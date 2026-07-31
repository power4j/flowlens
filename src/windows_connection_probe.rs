use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};

use crate::capture::TransportProtocol;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConnectionRecord {
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub protocol: TransportProtocol,
    pub pid: u32,
    pub state: Option<u32>,
}

pub(crate) fn query() -> Result<Vec<ConnectionRecord>, String> {
    let mut records = query_tcp(AF_INET)?;
    records.extend(query_tcp(AF_INET6)?);
    records.extend(query_udp(AF_INET)?);
    records.extend(query_udp(AF_INET6)?);
    Ok(records)
}

fn query_tcp(address_family: u32) -> Result<Vec<ConnectionRecord>, String> {
    let table = get_tcp_table(address_family)?;
    if address_family == AF_INET {
        parse_tcp4(&table)
    } else {
        parse_tcp6(&table)
    }
}

fn query_udp(address_family: u32) -> Result<Vec<ConnectionRecord>, String> {
    let table = get_udp_table(address_family)?;
    if address_family == AF_INET {
        parse_udp4(&table)
    } else {
        parse_udp6(&table)
    }
}

fn get_tcp_table(address_family: u32) -> Result<Vec<u8>, String> {
    let mut size = 0_u32;
    let status = unsafe {
        GetExtendedTcpTable(
            None,
            &raw mut size,
            false,
            address_family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if status != ERROR_INSUFFICIENT_BUFFER.0 {
        return Err(format!("GetExtendedTcpTable size query failed: {status}"));
    }
    get_tcp_table_with_size(address_family, size)
}

fn get_tcp_table_with_size(address_family: u32, size: u32) -> Result<Vec<u8>, String> {
    let mut table = Vec::<u8>::with_capacity(size as usize);
    let mut actual_size = size;
    let status = unsafe {
        GetExtendedTcpTable(
            Some(table.as_mut_ptr().cast()),
            &raw mut actual_size,
            false,
            address_family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if status != NO_ERROR.0 {
        return Err(format!("GetExtendedTcpTable failed: {status}"));
    }
    unsafe {
        table.set_len(actual_size as usize);
    }
    Ok(table)
}

fn get_udp_table(address_family: u32) -> Result<Vec<u8>, String> {
    let mut size = 0_u32;
    let status = unsafe {
        GetExtendedUdpTable(
            None,
            &raw mut size,
            false,
            address_family,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if status != ERROR_INSUFFICIENT_BUFFER.0 {
        return Err(format!("GetExtendedUdpTable size query failed: {status}"));
    }
    let mut table = Vec::<u8>::with_capacity(size as usize);
    let mut actual_size = size;
    let status = unsafe {
        GetExtendedUdpTable(
            Some(table.as_mut_ptr().cast()),
            &raw mut actual_size,
            false,
            address_family,
            UDP_TABLE_OWNER_PID,
            0,
        )
    };
    if status != NO_ERROR.0 {
        return Err(format!("GetExtendedUdpTable failed: {status}"));
    }
    unsafe {
        table.set_len(actual_size as usize);
    }
    Ok(table)
}

fn row_count(table: &[u8]) -> Result<usize, String> {
    if table.len() < size_of::<u32>() {
        return Err("connection table is truncated".to_string());
    }
    let count = unsafe { (table.as_ptr().cast::<u32>()).read_unaligned() };
    Ok(count as usize)
}

fn parse_tcp4(table: &[u8]) -> Result<Vec<ConnectionRecord>, String> {
    let count = row_count(table)?;
    let rows = rows::<MIB_TCPROW_OWNER_PID>(table, count)?;
    Ok(rows
        .into_iter()
        .map(|row| ConnectionRecord {
            local: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr))),
                u16::from_be(row.dwLocalPort as u16),
            ),
            remote: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwRemoteAddr))),
                u16::from_be(row.dwRemotePort as u16),
            )),
            protocol: TransportProtocol::Tcp,
            pid: row.dwOwningPid,
            state: Some(row.dwState),
        })
        .collect())
}

fn parse_tcp6(table: &[u8]) -> Result<Vec<ConnectionRecord>, String> {
    let count = row_count(table)?;
    let rows = rows::<MIB_TCP6ROW_OWNER_PID>(table, count)?;
    Ok(rows
        .into_iter()
        .map(|row| ConnectionRecord {
            local: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                u16::from_be(row.dwLocalPort as u16),
            ),
            remote: Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
                u16::from_be(row.dwRemotePort as u16),
            )),
            protocol: TransportProtocol::Tcp,
            pid: row.dwOwningPid,
            state: Some(row.dwState),
        })
        .collect())
}

fn parse_udp4(table: &[u8]) -> Result<Vec<ConnectionRecord>, String> {
    let count = row_count(table)?;
    let rows = rows::<MIB_UDPROW_OWNER_PID>(table, count)?;
    Ok(rows
        .into_iter()
        .map(|row| ConnectionRecord {
            local: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwLocalAddr))),
                u16::from_be(row.dwLocalPort as u16),
            ),
            remote: None,
            protocol: TransportProtocol::Udp,
            pid: row.dwOwningPid,
            state: None,
        })
        .collect())
}

fn parse_udp6(table: &[u8]) -> Result<Vec<ConnectionRecord>, String> {
    let count = row_count(table)?;
    let rows = rows::<MIB_UDP6ROW_OWNER_PID>(table, count)?;
    Ok(rows
        .into_iter()
        .map(|row| ConnectionRecord {
            local: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                u16::from_be(row.dwLocalPort as u16),
            ),
            remote: None,
            protocol: TransportProtocol::Udp,
            pid: row.dwOwningPid,
            state: None,
        })
        .collect())
}

fn rows<T: Copy>(table: &[u8], count: usize) -> Result<Vec<T>, String> {
    let row_size = size_of::<T>();
    let required = size_of::<u32>()
        .checked_add(
            row_size
                .checked_mul(count)
                .ok_or("connection table is too large")?,
        )
        .ok_or("connection table is too large")?;
    if table.len() < required {
        return Err("connection table rows are truncated".to_string());
    }
    let base = unsafe { table.as_ptr().add(size_of::<u32>()).cast::<T>() };
    Ok((0..count)
        .map(|index| unsafe { base.add(index).read_unaligned() })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_tcp_remote_endpoint() {
        let row = MIB_TCPROW_OWNER_PID {
            dwState: 5,
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: u32::from(u16::to_be(1234)),
            dwRemoteAddr: u32::from_ne_bytes([192, 0, 2, 1]),
            dwRemotePort: u32::from(u16::to_be(443)),
            dwOwningPid: 7,
        };
        let table = encode_rows(&row);
        let record = parse_tcp4(&table).unwrap().pop().unwrap();
        assert_eq!(record.local, "127.0.0.1:1234".parse().unwrap());
        assert_eq!(record.remote, Some("192.0.2.1:443".parse().unwrap()));
        assert_eq!(record.pid, 7);
    }

    #[test]
    #[ignore]
    fn live_query_reads_windows_connection_table() {
        let records = query().expect("Windows connection tables should be readable");
        assert!(!records.is_empty());
        assert!(records.iter().any(|record| record.remote.is_some()));
    }

    fn encode_rows<T: Copy>(row: &T) -> Vec<u8> {
        let mut table = vec![0_u8; size_of::<u32>() + size_of::<T>()];
        table[..size_of::<u32>()].copy_from_slice(&1_u32.to_ne_bytes());
        unsafe {
            table[size_of::<u32>()..]
                .as_mut_ptr()
                .cast::<T>()
                .write_unaligned(*row);
        }
        table
    }
}
