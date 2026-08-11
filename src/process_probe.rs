use std::collections::HashMap;
#[cfg(windows)]
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::capture::{LocalSocket, TransportProtocol};
#[cfg(windows)]
use crate::windows_connection_probe;

const REQUEST_CHANNEL_CAPACITY: usize = 1_024;
const SNAPSHOT_REFRESH_INTERVAL: Duration = Duration::from_millis(250);

type SocketKey = (IpAddr, u16, TransportProtocol);
type ListenerQuery = Box<dyn FnMut() -> Result<Vec<ListenerSnapshot>, String> + Send + 'static>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ProbeRequestId(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProbeRequestOutcome {
    Queued(ProbeRequestId),
    InFlight(ProbeRequestId),
    Unavailable,
}

#[derive(Clone)]
struct ProbeRequest {
    id: ProbeRequestId,
    socket: LocalSocket,
    #[cfg_attr(not(windows), allow(dead_code))]
    peers: Vec<SocketAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProbeProcess {
    pub pid: u32,
    pub name: Option<Arc<str>>,
    pub path: Option<Arc<str>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProbeResult {
    Unique {
        request_id: ProbeRequestId,
        socket: LocalSocket,
        process: ProbeProcess,
    },
    NotFound {
        request_id: ProbeRequestId,
        socket: LocalSocket,
    },
    Ambiguous {
        request_id: ProbeRequestId,
        socket: LocalSocket,
        candidate_count: usize,
    },
    Unavailable {
        request_id: ProbeRequestId,
        socket: LocalSocket,
        error: Arc<str>,
    },
    #[cfg_attr(not(windows), allow(dead_code))]
    ConnectionMatches {
        request_id: ProbeRequestId,
        socket: LocalSocket,
        matches: Vec<ConnectionMatch>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConnectionMatch {
    pub peer: SocketAddr,
    pub process: ProbeProcess,
}

impl ProbeResult {
    fn request_id(&self) -> ProbeRequestId {
        match self {
            Self::Unique { request_id, .. }
            | Self::NotFound { request_id, .. }
            | Self::Ambiguous { request_id, .. }
            | Self::Unavailable { request_id, .. } => *request_id,
            Self::ConnectionMatches { request_id, .. } => *request_id,
        }
    }

    fn socket(&self) -> LocalSocket {
        match self {
            Self::Unique { socket, .. }
            | Self::NotFound { socket, .. }
            | Self::Ambiguous { socket, .. }
            | Self::Unavailable { socket, .. } => *socket,
            Self::ConnectionMatches { socket, .. } => *socket,
        }
    }
}

#[derive(Clone)]
struct ListenerSnapshot {
    socket: SocketAddr,
    protocol: TransportProtocol,
    process: ProbeProcess,
}

struct ProcessSnapshot {
    captured_at: Instant,
    listeners: Vec<ListenerSnapshot>,
    index: HashMap<SocketKey, HashMap<u32, ProbeProcess>>,
    #[cfg(windows)]
    connections: Option<Vec<windows_connection_probe::ConnectionRecord>>,
    #[cfg(windows)]
    connections_queried: bool,
}

pub(crate) struct ProcessProbe {
    request_tx: SyncSender<ProbeRequest>,
    result_rx: Receiver<ProbeResult>,
    in_flight: Arc<Mutex<HashMap<LocalSocket, ProbeRequestId>>>,
    next_request_id: AtomicU64,
    metrics: Arc<ProbeMetrics>,
}

#[derive(Default)]
struct ProbeMetrics {
    query_count: AtomicU64,
    query_duration_nanos: AtomicU64,
    last_query_duration_nanos: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ProbeDiagnosticsSnapshot {
    pub query_count: u64,
    pub query_duration: std::time::Duration,
    pub last_query_duration: std::time::Duration,
}

impl ProcessProbe {
    pub(crate) fn spawn() -> Self {
        Self::spawn_with_query(Box::new(query_listeners))
    }

    pub(crate) fn request(&self, socket: LocalSocket) -> ProbeRequestOutcome {
        self.request_for_peers(socket, Vec::new())
    }

    pub(crate) fn request_for_peers(
        &self,
        socket: LocalSocket,
        peers: Vec<SocketAddr>,
    ) -> ProbeRequestOutcome {
        let Ok(mut in_flight) = self.in_flight.lock() else {
            return ProbeRequestOutcome::Unavailable;
        };
        if let Some(&request_id) = in_flight.get(&socket) {
            return ProbeRequestOutcome::InFlight(request_id);
        }
        let request_id = ProbeRequestId(self.next_request_id.fetch_add(1, Ordering::Relaxed));
        in_flight.insert(socket, request_id);
        match self.request_tx.try_send(ProbeRequest {
            id: request_id,
            socket,
            peers,
        }) {
            Ok(()) => ProbeRequestOutcome::Queued(request_id),
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                in_flight.remove(&socket);
                ProbeRequestOutcome::Unavailable
            }
        }
    }

    pub(crate) fn drain_results(&self) -> Vec<ProbeResult> {
        let mut results = Vec::new();
        loop {
            match self.result_rx.try_recv() {
                Ok(result) => results.push(result),
                Err(TryRecvError::Empty) => return results,
                Err(TryRecvError::Disconnected) => {
                    let unavailable = self
                        .in_flight
                        .lock()
                        .map(|mut in_flight| {
                            in_flight
                                .drain()
                                .map(|(socket, request_id)| ProbeResult::Unavailable {
                                    request_id,
                                    socket,
                                    error: Arc::from("process probe worker disconnected"),
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    results.extend(unavailable);
                    return results;
                }
            }
        }
    }

    pub(crate) fn diagnostics_snapshot(&self) -> ProbeDiagnosticsSnapshot {
        ProbeDiagnosticsSnapshot {
            query_count: self.metrics.query_count.load(Ordering::Relaxed),
            query_duration: std::time::Duration::from_nanos(
                self.metrics.query_duration_nanos.load(Ordering::Relaxed),
            ),
            last_query_duration: std::time::Duration::from_nanos(
                self.metrics
                    .last_query_duration_nanos
                    .load(Ordering::Relaxed),
            ),
        }
    }

    #[cfg(test)]
    pub(crate) fn spawn_blocked_for_test(
        query_count: Arc<AtomicUsize>,
        release_rx: Receiver<()>,
    ) -> Self {
        Self::spawn_with_query(Box::new(move || {
            query_count.fetch_add(1, Ordering::Release);
            let _ = release_rx.recv();
            Ok(Vec::new())
        }))
    }

    #[cfg(test)]
    pub(crate) fn in_flight_count_for_test(&self) -> usize {
        self.in_flight
            .lock()
            .map(|in_flight| in_flight.len())
            .unwrap_or_default()
    }

    fn spawn_with_query(query: ListenerQuery) -> Self {
        Self::spawn_with_query_and_interval(query, SNAPSHOT_REFRESH_INTERVAL)
    }

    fn spawn_with_query_and_interval(
        query: ListenerQuery,
        snapshot_refresh_interval: Duration,
    ) -> Self {
        let (request_tx, request_rx) = mpsc::sync_channel(REQUEST_CHANNEL_CAPACITY);
        let (result_tx, result_rx) = mpsc::channel();
        let in_flight = Arc::new(Mutex::new(HashMap::new()));
        let worker_in_flight = in_flight.clone();
        let metrics = Arc::new(ProbeMetrics::default());
        let worker_metrics = metrics.clone();

        thread::Builder::new()
            .name("flowlens-process-probe".to_string())
            .spawn(move || {
                worker_loop(
                    request_rx,
                    result_tx,
                    worker_in_flight,
                    worker_metrics,
                    query,
                    snapshot_refresh_interval,
                )
            })
            .expect("process probe worker should spawn");

        Self {
            request_tx,
            result_rx,
            in_flight,
            next_request_id: AtomicU64::new(1),
            metrics,
        }
    }
}

/// Whether a request needs the Windows connection-endpoint probe: TCP with
/// at least one remote endpoint to match.
#[cfg(windows)]
fn requires_connection_probe(request: &ProbeRequest) -> bool {
    request.socket.protocol == TransportProtocol::Tcp && !request.peers.is_empty()
}

fn worker_loop(
    request_rx: Receiver<ProbeRequest>,
    result_tx: mpsc::Sender<ProbeResult>,
    in_flight: Arc<Mutex<HashMap<LocalSocket, ProbeRequestId>>>,
    metrics: Arc<ProbeMetrics>,
    mut query: ListenerQuery,
    snapshot_refresh_interval: Duration,
) {
    let mut snapshot: Option<ProcessSnapshot> = None;
    while let Ok(first) = request_rx.recv() {
        let mut sockets = vec![first];
        while let Ok(request) = request_rx.try_recv() {
            sockets.push(request);
        }

        let now = Instant::now();
        #[cfg(windows)]
        let needs_connections = sockets.iter().any(requires_connection_probe);
        let snapshot_result = match snapshot.as_ref() {
            Some(snapshot)
                if now.duration_since(snapshot.captured_at) < snapshot_refresh_interval && {
                    #[cfg(windows)]
                    {
                        !needs_connections || snapshot.connections_queried
                    }
                    #[cfg(not(windows))]
                    {
                        true
                    }
                } =>
            {
                Ok(snapshot)
            }
            _ => {
                let query_started = Instant::now();
                let refreshed = query().map(|listeners| {
                    #[cfg(windows)]
                    let connections = needs_connections
                        .then(|| windows_connection_probe::query().ok())
                        .flatten();
                    ProcessSnapshot {
                        captured_at: Instant::now(),
                        index: listener_index(&listeners),
                        listeners,
                        #[cfg(windows)]
                        connections,
                        #[cfg(windows)]
                        connections_queried: needs_connections,
                    }
                });
                let elapsed = query_started.elapsed();
                metrics.query_count.fetch_add(1, Ordering::Relaxed);
                metrics.query_duration_nanos.fetch_add(
                    elapsed.as_nanos().min(u128::from(u64::MAX)) as u64,
                    Ordering::Relaxed,
                );
                metrics.last_query_duration_nanos.store(
                    elapsed.as_nanos().min(u128::from(u64::MAX)) as u64,
                    Ordering::Relaxed,
                );
                match refreshed {
                    Ok(refreshed) => {
                        snapshot = Some(refreshed);
                        Ok(snapshot.as_ref().expect("snapshot was just stored"))
                    }
                    Err(error) => Err(error),
                }
            }
        };
        for result in resolve_snapshot_batch(&sockets, snapshot_result) {
            let socket = result.socket();
            let request_id = result.request_id();
            if let Ok(mut in_flight) = in_flight.lock()
                && in_flight.get(&socket) == Some(&request_id)
            {
                in_flight.remove(&socket);
            }
            if result_tx.send(result).is_err() {
                return;
            }
        }
    }
}

fn resolve_snapshot_batch(
    requests: &[ProbeRequest],
    snapshot: Result<&ProcessSnapshot, String>,
) -> Vec<ProbeResult> {
    let snapshot = match snapshot {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let error: Arc<str> = Arc::from(error);
            return requests
                .iter()
                .map(|request| ProbeResult::Unavailable {
                    request_id: request.id,
                    socket: request.socket,
                    error: error.clone(),
                })
                .collect();
        }
    };

    #[cfg(windows)]
    let connections = snapshot.connections.as_deref();
    resolve_requests(
        requests,
        &snapshot.listeners,
        &snapshot.index,
        #[cfg(windows)]
        connections,
    )
}

#[cfg(test)]
fn resolve_batch(
    requests: &[ProbeRequest],
    listeners: Result<Vec<ListenerSnapshot>, String>,
) -> Vec<ProbeResult> {
    let listeners = match listeners {
        Ok(listeners) => listeners,
        Err(error) => {
            let error: Arc<str> = Arc::from(error);
            return requests
                .iter()
                .map(|request| ProbeResult::Unavailable {
                    request_id: request.id,
                    socket: request.socket,
                    error: error.clone(),
                })
                .collect();
        }
    };

    #[cfg(windows)]
    let connections = if requests.iter().any(requires_connection_probe) {
        windows_connection_probe::query().ok()
    } else {
        None
    };
    let index = listener_index(&listeners);
    resolve_requests(
        requests,
        &listeners,
        &index,
        #[cfg(windows)]
        connections.as_deref(),
    )
}

#[cfg(not(windows))]
fn resolve_requests(
    requests: &[ProbeRequest],
    _listeners: &[ListenerSnapshot],
    index: &HashMap<SocketKey, HashMap<u32, ProbeProcess>>,
) -> Vec<ProbeResult> {
    requests
        .iter()
        .map(|request| resolve_socket(request.id, request.socket, index))
        .collect()
}

#[cfg(windows)]
fn resolve_requests(
    requests: &[ProbeRequest],
    listeners: &[ListenerSnapshot],
    index: &HashMap<SocketKey, HashMap<u32, ProbeProcess>>,
    connections: Option<&[windows_connection_probe::ConnectionRecord]>,
) -> Vec<ProbeResult> {
    requests
        .iter()
        .map(|request| {
            if requires_connection_probe(request)
                && let Some(connections) = connections
            {
                return resolve_connections(request, connections, listeners, index);
            }
            resolve_socket(request.id, request.socket, index)
        })
        .collect()
}

#[cfg(windows)]
fn resolve_connections(
    request: &ProbeRequest,
    connections: &[windows_connection_probe::ConnectionRecord],
    listeners: &[ListenerSnapshot],
    index: &HashMap<SocketKey, HashMap<u32, ProbeProcess>>,
) -> ProbeResult {
    let processes: HashMap<u32, ProbeProcess> = listeners
        .iter()
        .map(|listener| (listener.process.pid, listener.process.clone()))
        .collect();
    let mut has_endpoint_records = false;
    let matches: Vec<ConnectionMatch> = request
        .peers
        .iter()
        .filter_map(|peer| {
            let pids: HashSet<u32> = connections
                .iter()
                .filter(|connection| {
                    connection.local.ip() == request.socket.ip
                        && connection.local.port() == request.socket.port
                        && connection.protocol == request.socket.protocol
                        && connection.remote == Some(*peer)
                })
                .map(|connection| connection.pid)
                .collect();
            has_endpoint_records |= !pids.is_empty();
            (pids.len() == 1)
                .then(|| pids.into_iter().next().unwrap())
                .map(|pid| {
                    processes.get(&pid).cloned().unwrap_or(ProbeProcess {
                        pid,
                        name: None,
                        path: None,
                    })
                })
                .map(|process| ConnectionMatch {
                    peer: *peer,
                    process,
                })
        })
        .collect();
    if matches.is_empty() && !has_endpoint_records {
        return resolve_socket(request.id, request.socket, index);
    }
    ProbeResult::ConnectionMatches {
        request_id: request.id,
        socket: request.socket,
        matches,
    }
}

fn resolve_socket(
    request_id: ProbeRequestId,
    socket: LocalSocket,
    index: &HashMap<SocketKey, HashMap<u32, ProbeProcess>>,
) -> ProbeResult {
    let key = (socket.ip, socket.port, socket.protocol);
    let wildcard_key = (wildcard_for(socket.ip), socket.port, socket.protocol);
    let candidates = index.get(&key).or_else(|| index.get(&wildcard_key));

    match candidates.map(HashMap::len) {
        Some(1) => {
            let process = candidates
                .and_then(|candidates| candidates.values().next())
                .expect("one candidate exists")
                .clone();
            ProbeResult::Unique {
                request_id,
                socket,
                process,
            }
        }
        Some(candidate_count) => ProbeResult::Ambiguous {
            request_id,
            socket,
            candidate_count,
        },
        None => ProbeResult::NotFound { request_id, socket },
    }
}

fn listener_index(
    listeners: &[ListenerSnapshot],
) -> HashMap<SocketKey, HashMap<u32, ProbeProcess>> {
    let mut index: HashMap<SocketKey, HashMap<u32, ProbeProcess>> = HashMap::new();
    for listener in listeners {
        let ip = listener.socket.ip();
        let port = listener.socket.port();
        for key in socket_keys(ip, port, listener.protocol) {
            index
                .entry(key)
                .or_default()
                .entry(listener.process.pid)
                .or_insert_with(|| listener.process.clone());
        }
    }
    index
}

fn socket_keys(ip: IpAddr, port: u16, protocol: TransportProtocol) -> Vec<SocketKey> {
    let key = (ip, port, protocol);
    let IpAddr::V6(ipv6) = ip else {
        return vec![key];
    };
    match ipv6.to_ipv4_mapped() {
        Some(ipv4) => vec![key, (IpAddr::V4(ipv4), port, protocol)],
        None => vec![key],
    }
}

fn wildcard_for(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

fn query_listeners() -> Result<Vec<ListenerSnapshot>, String> {
    listeners::get_all()
        .map(|listeners| listeners.into_iter().map(ListenerSnapshot::from).collect())
        .map_err(|error| error.to_string())
}

impl From<listeners::Listener> for ListenerSnapshot {
    fn from(listener: listeners::Listener) -> Self {
        Self {
            socket: listener.socket,
            protocol: protocol_from_listener(listener.protocol),
            process: ProbeProcess::from(listener.process),
        }
    }
}

fn protocol_from_listener(protocol: listeners::Protocol) -> TransportProtocol {
    match protocol {
        listeners::Protocol::TCP => TransportProtocol::Tcp,
        listeners::Protocol::UDP => TransportProtocol::Udp,
    }
}

impl From<listeners::Process> for ProbeProcess {
    fn from(process: listeners::Process) -> Self {
        let name = executable_name(&process.path)
            .map(Arc::from)
            .or_else(|| (!process.name.is_empty()).then(|| Arc::from(process.name)));
        let path = (!process.path.is_empty()).then(|| Arc::from(process.path));
        Self {
            pid: process.pid,
            name,
            path,
        }
    }
}

fn executable_name(path: &str) -> Option<&str> {
    Path::new(path)
        .file_name()?
        .to_str()
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::mpsc;

    use super::*;

    fn socket(ip: IpAddr, port: u16, protocol: TransportProtocol) -> LocalSocket {
        LocalSocket { ip, port, protocol }
    }

    fn listener(ip: IpAddr, port: u16, protocol: TransportProtocol, pid: u32) -> ListenerSnapshot {
        ListenerSnapshot {
            socket: SocketAddr::new(ip, port),
            protocol,
            process: ProbeProcess {
                pid,
                name: Some(Arc::from(format!("proc-{pid}"))),
                path: Some(Arc::from(format!("/bin/proc-{pid}"))),
            },
        }
    }

    fn resolve_one(request: LocalSocket, listeners: Vec<ListenerSnapshot>) -> ProbeResult {
        resolve_batch(
            &[ProbeRequest {
                id: ProbeRequestId(1),
                socket: request,
                peers: Vec::new(),
            }],
            Ok(listeners),
        )
        .into_iter()
        .next()
        .unwrap()
    }

    #[test]
    fn spawn_starts_idle_worker() {
        let _probe = ProcessProbe::spawn();
    }

    #[test]
    fn exact_address_port_and_protocol_match_returns_unique_process() {
        let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let request = socket(local, 443, TransportProtocol::Tcp);

        let result = resolve_one(
            request,
            vec![
                listener(local, 443, TransportProtocol::Tcp, 7),
                listener(local, 443, TransportProtocol::Udp, 8),
                listener(local, 444, TransportProtocol::Tcp, 9),
            ],
        );

        assert_eq!(
            result,
            ProbeResult::Unique {
                request_id: ProbeRequestId(1),
                socket: request,
                process: ProbeProcess {
                    pid: 7,
                    name: Some(Arc::from("proc-7")),
                    path: Some(Arc::from("/bin/proc-7")),
                },
            }
        );
    }

    #[cfg(windows)]
    #[test]
    fn connection_endpoint_match_returns_the_connection_owner() {
        let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)), 443);
        let request = ProbeRequest {
            id: ProbeRequestId(1),
            socket: socket(local, 49_152, TransportProtocol::Tcp),
            peers: vec![peer],
        };
        let listeners = vec![listener(local, 49_152, TransportProtocol::Tcp, 7)];
        let result = resolve_connections(
            &request,
            &[windows_connection_probe::ConnectionRecord {
                local: SocketAddr::new(local, 49_152),
                remote: Some(peer),
                protocol: TransportProtocol::Tcp,
                pid: 7,
                state: Some(5),
            }],
            &listeners,
            &listener_index(&listeners),
        );

        assert_eq!(
            result,
            ProbeResult::ConnectionMatches {
                request_id: ProbeRequestId(1),
                socket: request.socket,
                matches: vec![ConnectionMatch {
                    peer,
                    process: ProbeProcess {
                        pid: 7,
                        name: Some(Arc::from("proc-7")),
                        path: Some(Arc::from("/bin/proc-7")),
                    },
                }],
            }
        );
    }

    #[cfg(windows)]
    #[test]
    fn missing_connection_endpoint_falls_back_to_unique_socket_owner() {
        let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let request = ProbeRequest {
            id: ProbeRequestId(1),
            socket: socket(local, 49_152, TransportProtocol::Tcp),
            peers: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
                443,
            )],
        };
        let listeners = vec![listener(local, 49_152, TransportProtocol::Tcp, 7)];

        assert_eq!(
            resolve_connections(&request, &[], &listeners, &listener_index(&listeners),),
            ProbeResult::Unique {
                request_id: request.id,
                socket: request.socket,
                process: ProbeProcess {
                    pid: 7,
                    name: Some(Arc::from("proc-7")),
                    path: Some(Arc::from("/bin/proc-7")),
                },
            }
        );
    }

    #[cfg(windows)]
    #[test]
    fn ambiguous_connection_endpoint_is_not_attributed() {
        let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)), 443);
        let request = ProbeRequest {
            id: ProbeRequestId(1),
            socket: socket(local, 49_152, TransportProtocol::Tcp),
            peers: vec![peer],
        };
        let connections = [7, 8]
            .into_iter()
            .map(|pid| windows_connection_probe::ConnectionRecord {
                local: SocketAddr::new(local, 49_152),
                remote: Some(peer),
                protocol: TransportProtocol::Tcp,
                pid,
                state: Some(5),
            })
            .collect::<Vec<_>>();
        let listeners = vec![
            listener(local, 49_152, TransportProtocol::Tcp, 7),
            listener(local, 49_152, TransportProtocol::Tcp, 8),
        ];
        let result = resolve_connections(
            &request,
            &connections,
            &listeners,
            &listener_index(&listeners),
        );

        assert_eq!(
            result,
            ProbeResult::ConnectionMatches {
                request_id: ProbeRequestId(1),
                socket: request.socket,
                matches: Vec::new(),
            }
        );
    }

    #[cfg(windows)]
    #[test]
    fn requires_connection_probe_requires_tcp_and_peers() {
        let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let tcp_with_peers = ProbeRequest {
            id: ProbeRequestId(1),
            socket: socket(local, 443, TransportProtocol::Tcp),
            peers: vec![SocketAddr::new(local, 50_000)],
        };
        let tcp_without_peers = ProbeRequest {
            id: ProbeRequestId(1),
            socket: socket(local, 443, TransportProtocol::Tcp),
            peers: Vec::new(),
        };
        let udp_with_peers = ProbeRequest {
            id: ProbeRequestId(1),
            socket: socket(local, 53, TransportProtocol::Udp),
            peers: vec![SocketAddr::new(local, 50_000)],
        };
        assert!(requires_connection_probe(&tcp_with_peers));
        assert!(!requires_connection_probe(&tcp_without_peers));
        assert!(!requires_connection_probe(&udp_with_peers));
    }

    #[test]
    fn wildcard_address_matches_concrete_request() {
        let request = socket(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            8080,
            TransportProtocol::Tcp,
        );

        let result = resolve_one(
            request,
            vec![listener(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                8080,
                TransportProtocol::Tcp,
                7,
            )],
        );

        assert!(matches!(
            result,
            ProbeResult::Unique {
                process: ProbeProcess { pid: 7, .. },
                ..
            }
        ));
    }

    #[test]
    fn exact_address_takes_priority_over_wildcard_address() {
        let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let request = socket(local, 8080, TransportProtocol::Tcp);

        let result = resolve_one(
            request,
            vec![
                listener(
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    8080,
                    TransportProtocol::Tcp,
                    7,
                ),
                listener(local, 8080, TransportProtocol::Tcp, 8),
            ],
        );

        assert!(matches!(
            result,
            ProbeResult::Unique {
                process: ProbeProcess { pid: 8, .. },
                ..
            }
        ));
    }

    #[test]
    fn duplicate_records_for_one_pid_are_unique() {
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let request = socket(local, 443, TransportProtocol::Tcp);

        let result = resolve_one(
            request,
            vec![
                listener(local, 443, TransportProtocol::Tcp, 7),
                listener(local, 443, TransportProtocol::Tcp, 7),
            ],
        );

        assert!(matches!(
            result,
            ProbeResult::Unique {
                process: ProbeProcess { pid: 7, .. },
                ..
            }
        ));
    }

    #[test]
    fn different_pids_for_one_socket_are_ambiguous() {
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let request = socket(local, 443, TransportProtocol::Tcp);

        let result = resolve_one(
            request,
            vec![
                listener(local, 443, TransportProtocol::Tcp, 7),
                listener(local, 443, TransportProtocol::Tcp, 8),
            ],
        );

        assert_eq!(
            result,
            ProbeResult::Ambiguous {
                request_id: ProbeRequestId(1),
                socket: request,
                candidate_count: 2,
            }
        );
    }

    #[test]
    fn ipv4_request_matches_ipv4_mapped_ipv6_listener() {
        let local = IpAddr::V4(Ipv4Addr::new(186, 241, 106, 205));
        let mapped = IpAddr::V6(Ipv4Addr::new(186, 241, 106, 205).to_ipv6_mapped());
        let request = socket(local, 51_102, TransportProtocol::Tcp);

        let result = resolve_one(
            request,
            vec![listener(mapped, 51_102, TransportProtocol::Tcp, 2_027_468)],
        );

        assert!(matches!(
            result,
            ProbeResult::Unique {
                process: ProbeProcess { pid: 2_027_468, .. },
                ..
            }
        ));
    }

    #[test]
    fn missing_socket_returns_not_found() {
        let request = socket(IpAddr::V6(Ipv6Addr::LOCALHOST), 443, TransportProtocol::Tcp);

        assert_eq!(
            resolve_one(request, Vec::new()),
            ProbeResult::NotFound {
                request_id: ProbeRequestId(1),
                socket: request,
            }
        );
    }

    #[test]
    fn query_failure_returns_unavailable_for_each_request() {
        let first = socket(IpAddr::V4(Ipv4Addr::LOCALHOST), 443, TransportProtocol::Tcp);
        let second = socket(IpAddr::V4(Ipv4Addr::LOCALHOST), 53, TransportProtocol::Udp);

        let result = resolve_batch(
            &[
                ProbeRequest {
                    id: ProbeRequestId(1),
                    socket: first,
                    peers: Vec::new(),
                },
                ProbeRequest {
                    id: ProbeRequestId(2),
                    socket: second,
                    peers: Vec::new(),
                },
            ],
            Err("listeners unavailable".to_string()),
        );

        assert_eq!(
            result,
            vec![
                ProbeResult::Unavailable {
                    request_id: ProbeRequestId(1),
                    socket: first,
                    error: Arc::from("listeners unavailable"),
                },
                ProbeResult::Unavailable {
                    request_id: ProbeRequestId(2),
                    socket: second,
                    error: Arc::from("listeners unavailable"),
                },
            ]
        );
    }

    #[test]
    fn repeated_request_for_in_flight_socket_is_deduplicated() {
        let (block_tx, block_rx) = mpsc::channel::<()>();
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let request = socket(local, 443, TransportProtocol::Tcp);
        let probe = ProcessProbe::spawn_with_query(Box::new(move || {
            block_rx.recv().unwrap();
            Ok(vec![listener(local, 443, TransportProtocol::Tcp, 7)])
        }));

        let first_request = match probe.request(request) {
            ProbeRequestOutcome::Queued(request_id) => request_id,
            outcome => panic!("unexpected first request outcome: {outcome:?}"),
        };
        assert_eq!(
            probe.request(request),
            ProbeRequestOutcome::InFlight(first_request)
        );

        block_tx.send(()).unwrap();
        let result = loop {
            let results = probe.drain_results();
            if let Some(result) = results.into_iter().next() {
                break result;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };

        assert!(matches!(result, ProbeResult::Unique { .. }));
        assert!(matches!(
            probe.request(request),
            ProbeRequestOutcome::Queued(_)
        ));
    }

    fn wait_for_result(probe: &ProcessProbe) -> ProbeResult {
        loop {
            if let Some(result) = probe.drain_results().into_iter().next() {
                return result;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn fresh_snapshot_is_reused_across_request_batches() {
        let query_count = Arc::new(AtomicUsize::new(0));
        let query_count_for_worker = query_count.clone();
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let request = socket(local, 443, TransportProtocol::Tcp);
        let probe = ProcessProbe::spawn_with_query_and_interval(
            Box::new(move || {
                query_count_for_worker.fetch_add(1, Ordering::Relaxed);
                Ok(vec![listener(local, 443, TransportProtocol::Tcp, 7)])
            }),
            Duration::from_millis(100),
        );

        assert!(matches!(
            probe.request(request),
            ProbeRequestOutcome::Queued(_)
        ));
        assert!(matches!(
            wait_for_result(&probe),
            ProbeResult::Unique { .. }
        ));
        assert!(matches!(
            probe.request(request),
            ProbeRequestOutcome::Queued(_)
        ));
        assert!(matches!(
            wait_for_result(&probe),
            ProbeResult::Unique { .. }
        ));

        assert_eq!(query_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn expired_snapshot_is_refreshed_for_a_later_request() {
        let query_count = Arc::new(AtomicUsize::new(0));
        let query_count_for_worker = query_count.clone();
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let request = socket(local, 443, TransportProtocol::Tcp);
        let probe = ProcessProbe::spawn_with_query_and_interval(
            Box::new(move || {
                query_count_for_worker.fetch_add(1, Ordering::Relaxed);
                Ok(vec![listener(local, 443, TransportProtocol::Tcp, 7)])
            }),
            Duration::from_millis(10),
        );

        assert!(matches!(
            probe.request(request),
            ProbeRequestOutcome::Queued(_)
        ));
        assert!(matches!(
            wait_for_result(&probe),
            ProbeResult::Unique { .. }
        ));
        std::thread::sleep(Duration::from_millis(25));
        assert!(matches!(
            probe.request(request),
            ProbeRequestOutcome::Queued(_)
        ));
        assert!(matches!(
            wait_for_result(&probe),
            ProbeResult::Unique { .. }
        ));

        assert_eq!(query_count.load(Ordering::Relaxed), 2);
    }
}
