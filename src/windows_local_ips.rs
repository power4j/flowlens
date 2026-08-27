use std::mem::{MaybeUninit, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME,
    GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR_0_0, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
};

const AF_UNSPEC: u32 = 0;
const FLAGS: u32 = GAA_FLAG_SKIP_ANYCAST.0
    | GAA_FLAG_SKIP_DNS_SERVER.0
    | GAA_FLAG_SKIP_FRIENDLY_NAME.0
    | GAA_FLAG_SKIP_MULTICAST.0;

pub(crate) fn query() -> Result<Vec<IpAddr>, String> {
    let buffer = adapter_buffer()?;
    let mut addresses = Vec::new();
    let mut adapter = buffer.as_ptr().cast_mut().cast::<IP_ADAPTER_ADDRESSES_LH>();

    while !adapter.is_null() {
        let mut unicast = unsafe { (*adapter).FirstUnicastAddress };
        while !unicast.is_null() {
            let socket_address = unsafe { &(*unicast).Address };
            if let Some(address) = socket_address_to_ip(socket_address)
                && !address.is_unspecified()
            {
                addresses.push(address);
            }
            unicast = unsafe { (*unicast).Next };
        }
        adapter = unsafe { (*adapter).Next };
    }

    addresses.sort_unstable();
    addresses.dedup();
    Ok(addresses)
}

fn adapter_buffer() -> Result<Vec<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>, String> {
    let mut size = 0u32;
    let status = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC,
            windows::Win32::NetworkManagement::IpHelper::GET_ADAPTERS_ADDRESSES_FLAGS(FLAGS),
            None,
            None,
            &raw mut size,
        )
    };
    if status != ERROR_BUFFER_OVERFLOW.0 {
        return Err(format!("GetAdaptersAddresses(size) failed: {status}"));
    }

    let element_size = size_of::<IP_ADAPTER_ADDRESSES_LH>();
    for _ in 0..3 {
        let elements = (size as usize).div_ceil(element_size);
        let mut buffer = Vec::<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>::with_capacity(elements);
        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                windows::Win32::NetworkManagement::IpHelper::GET_ADAPTERS_ADDRESSES_FLAGS(FLAGS),
                None,
                Some(buffer.as_mut_ptr().cast()),
                &raw mut size,
            )
        };
        if status == NO_ERROR.0 {
            return Ok(buffer);
        }
        if status != ERROR_BUFFER_OVERFLOW.0 {
            return Err(format!("GetAdaptersAddresses(data) failed: {status}"));
        }
    }

    Err(format!(
        "GetAdaptersAddresses(data) failed: buffer changed during retries (required {size} bytes)"
    ))
}
fn socket_address_to_ip(address: &SOCKET_ADDRESS) -> Option<IpAddr> {
    let sockaddr = address.lpSockaddr;
    let length = usize::try_from(address.iSockaddrLength).ok()?;
    if sockaddr.is_null() {
        return None;
    }

    let family = unsafe { (*sockaddr).sa_family };
    if family == AF_INET && length >= size_of::<SOCKADDR_IN>() {
        let sockaddr = unsafe { &*sockaddr.cast::<SOCKADDR_IN>() };
        let bytes: IN_ADDR_0_0 = unsafe { sockaddr.sin_addr.S_un.S_un_b };
        return Some(IpAddr::V4(Ipv4Addr::new(
            bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4,
        )));
    }
    if family == AF_INET6 && length >= size_of::<SOCKADDR_IN6>() {
        let sockaddr = unsafe { &*sockaddr.cast::<SOCKADDR_IN6>() };
        let bytes = unsafe { sockaddr.sin6_addr.u.Byte };
        return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::addr_of_mut;
    use windows::Win32::Networking::WinSock::{IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR};

    #[test]
    fn parses_ipv4_socket_address() {
        let mut sockaddr = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_un_b: IN_ADDR_0_0 {
                        s_b1: 10,
                        s_b2: 11,
                        s_b3: 12,
                        s_b4: 31,
                    },
                },
            },
            ..Default::default()
        };
        let address = SOCKET_ADDRESS {
            lpSockaddr: addr_of_mut!(sockaddr).cast::<SOCKADDR>(),
            iSockaddrLength: size_of::<SOCKADDR_IN>() as i32,
        };

        assert_eq!(
            socket_address_to_ip(&address),
            Some("10.11.12.31".parse().unwrap())
        );
    }

    #[test]
    fn parses_ipv6_socket_address() {
        let mut sockaddr = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                },
            },
            ..Default::default()
        };
        let address = SOCKET_ADDRESS {
            lpSockaddr: addr_of_mut!(sockaddr).cast::<SOCKADDR>(),
            iSockaddrLength: size_of::<SOCKADDR_IN6>() as i32,
        };

        assert_eq!(socket_address_to_ip(&address), Some("::1".parse().unwrap()));
    }

    #[test]
    #[ignore = "requires the Windows network stack"]
    fn live_query_reads_windows_addresses() {
        let addresses = query().unwrap();
        println!("native local addresses: {addresses:?}");
        assert!(!addresses.is_empty());
    }
}
