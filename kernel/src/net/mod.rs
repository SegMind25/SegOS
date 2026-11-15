//! Networking: sockets of every family, and the TCP/IP stack.
//!
//! `iface.rs` (interfaces, Ethernet, ARP, routing, the network thread),
//! `ip.rs` (IPv4, ICMP), `tcp.rs`, `udp.rs`, `dhcp.rs`; `inet.rs` and
//! `netlink.rs` are the socket faces of AF_INET and AF_NETLINK; `unix.rs`
//! is AF_UNIX.

pub mod dhcp;
pub mod iface;
pub mod inet;
pub mod ip;
pub mod netlink;
pub mod socket;
pub mod tcp;
pub mod udp;
pub mod unix;

use crate::abi::{Errno, KResult};
use alloc::sync::Arc;
use socket::*;

/// An AF_INET socket.
pub fn inet_socket(ty: u32, protocol: u32) -> KResult<Arc<dyn Socket>> {
    match (ty, protocol) {
        (SOCK_STREAM, 0 | 6) => Ok(inet::TcpSocket::new()),
        (SOCK_DGRAM, 0 | 17) => Ok(udp::UdpSocket::new()),
        (SOCK_DGRAM, 1) => Ok(ip::IcmpSocket::new(false)),
        (SOCK_RAW, 1) => Ok(ip::IcmpSocket::new(true)),
        (SOCK_STREAM | SOCK_DGRAM | SOCK_RAW, _) => Err(Errno::EPROTONOSUPPORT),
        _ => Err(Errno::ESOCKTNOSUPPORT),
    }
}

/// An AF_NETLINK socket.
pub fn netlink_socket(ty: u32, protocol: u32) -> KResult<Arc<dyn Socket>> {
    netlink::new_socket(ty, protocol)
}

/// Brings networking up: `lo`, the cards the drivers found, DHCP.
pub fn init() {
    crate::drivers::virtio_net::init();
    iface::init();
}
