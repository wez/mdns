pub use crate::mac_addr::*;
pub use if_addrs::{get_if_addrs, IfAddr, Ifv4Addr, Ifv6Addr, Interface};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};

/// Determine the local address of the system,
/// wrt. to the specified destination `ip` address.
pub fn local_address_for_destination(ip: IpAddr) -> std::io::Result<IpAddr> {
    let source_ip = match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };

    let socket = UdpSocket::bind((source_ip, 0))?;
    socket.connect((ip, 80))?;
    Ok(socket.local_addr()?.ip())
}

/// Determine the local address of the system.
/// This is wrt. to what is likely an external IP address.
pub fn local_address() -> std::io::Result<IpAddr> {
    local_address_for_destination(Ipv4Addr::new(8, 8, 8, 8).into())
}

pub fn interface_for_destination(ip: IpAddr) -> Option<Interface> {
    let addr = local_address_for_destination(ip).ok()?;
    let interfaces = if_addrs::get_if_addrs().ok()?;
    for iface in interfaces {
        if iface.addr.ip() == addr {
            return Some(iface);
        }
    }

    None
}
