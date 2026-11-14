//! Networking: sockets of every family, and the TCP/IP stack.

pub mod socket;
pub mod unix;

use crate::abi::{Errno, KResult};
use alloc::sync::Arc;
use socket::Socket;

/// An AF_INET socket (the TCP/IP stack's).
pub fn inet_socket(_ty: u32, _protocol: u32) -> KResult<Arc<dyn Socket>> {
    Err(Errno::EAFNOSUPPORT)
}

/// An AF_NETLINK socket.
pub fn netlink_socket(_ty: u32, _protocol: u32) -> KResult<Arc<dyn Socket>> {
    Err(Errno::EAFNOSUPPORT)
}
