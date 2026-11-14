//! Sockets: the interface every address family implements, and the file
//! a socket descriptor refers to.
//!
//! `socket(2)` makes an object implementing [`Socket`] (AF_UNIX in
//! `net/unix.rs`, AF_INET in `net/inet.rs`, AF_NETLINK in
//! `net/netlink.rs`) and wraps it in a [`SocketFile`] inode, so `read`,
//! `write`, `poll`, `epoll` and `close` work on it like on any file. The
//! socket system calls (`syscall/net.rs`) reach the object through
//! [`socket_of`].
//!
//! Addresses travel as the raw `struct sockaddr_*` bytes a program passed;
//! each family parses its own. Blocking is the socket's business: a call
//! with `nonblock` set returns EAGAIN instead of waiting, a blocking wait
//! is interruptible (ERESTARTSYS on a signal), and every change of
//! readiness calls [`crate::fs::poll_notify`] so `poll`/`epoll` waiters
//! re-check.

use crate::abi::{Errno, KResult};
use crate::fs::{File, FileType, Inode};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Address families (`sys/socket.h`).
pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const AF_NETLINK: u16 = 16;

/// Socket types; SOCK_NONBLOCK and SOCK_CLOEXEC are flags or-ed in.
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;
pub const SOCK_SEQPACKET: u32 = 5;
pub const SOCK_NONBLOCK: u32 = 0o4000;
pub const SOCK_CLOEXEC: u32 = 0o2000000;

/// `send`/`recv` flags.
pub const MSG_OOB: u32 = 0x1;
pub const MSG_PEEK: u32 = 0x2;
pub const MSG_DONTWAIT: u32 = 0x40;
pub const MSG_TRUNC: u32 = 0x20;
pub const MSG_CTRUNC: u32 = 0x8;
pub const MSG_WAITALL: u32 = 0x100;
pub const MSG_NOSIGNAL: u32 = 0x4000;

/// Socket option levels.
pub const SOL_SOCKET: u32 = 1;
pub const IPPROTO_IP: u32 = 0;
pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_UDP: u32 = 17;

/// What one `recv` delivered.
#[derive(Default)]
pub struct Received {
    /// Bytes copied into the caller's buffer.
    pub len: usize,
    /// The datagram's full length when it was longer than the buffer
    /// (MSG_TRUNC); otherwise equal to `len`.
    pub full_len: usize,
    /// The sender's address (datagram sockets), raw sockaddr bytes.
    pub from: Option<Vec<u8>>,
    /// Descriptors passed with SCM_RIGHTS (AF_UNIX).
    pub rights: Vec<Arc<File>>,
    /// Credentials passed with SCM_CREDENTIALS: (pid, uid, gid).
    pub creds: Option<(u32, u32, u32)>,
}

pub trait Socket: Send + Sync {
    /// (family, type) as `socket()` created it.
    fn kind(&self) -> (u16, u32);

    fn bind(&self, addr: &[u8]) -> KResult<()>;
    fn listen(&self, _backlog: u32) -> KResult<()> {
        Err(Errno::EOPNOTSUPP)
    }
    /// A new connection, and the peer's address.
    fn accept(&self, _nonblock: bool) -> KResult<(Arc<dyn Socket>, Vec<u8>)> {
        Err(Errno::EOPNOTSUPP)
    }
    /// EINPROGRESS for a non-blocking connect still under way.
    fn connect(&self, addr: &[u8], nonblock: bool) -> KResult<()>;
    /// Sends `data` (to `to` on datagram sockets). EPIPE when the other
    /// side is gone (the caller raises SIGPIPE unless MSG_NOSIGNAL).
    fn send(
        &self,
        data: &[u8],
        to: Option<&[u8]>,
        flags: u32,
        nonblock: bool,
        rights: Vec<Arc<File>>,
    ) -> KResult<usize>;
    fn recv(&self, buf: &mut [u8], flags: u32, nonblock: bool) -> KResult<Received>;
    /// SHUT_RD = 0, SHUT_WR = 1, SHUT_RDWR = 2.
    fn shutdown(&self, how: u32) -> KResult<()>;
    fn local_addr(&self) -> KResult<Vec<u8>>;
    fn peer_addr(&self) -> KResult<Vec<u8>> {
        Err(Errno::ENOTCONN)
    }
    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> KResult<()>;
    fn get_option(&self, level: u32, name: u32) -> KResult<Vec<u8>>;
    /// POLLIN/POLLOUT/POLLHUP/POLLERR/POLLRDHUP as they hold now.
    fn poll(&self) -> u16;
    /// Bumped on every readiness change (for edge-triggered epoll).
    fn poll_generation(&self) -> u64 {
        0
    }
    /// Called when the last descriptor closes (the socket file is dropped).
    fn close(&self) {}
    /// For `ioctl(FIONREAD)`: bytes ready to read.
    fn bytes_ready(&self) -> usize {
        0
    }
    fn as_any(&self) -> &dyn core::any::Any;
}

/// The inode behind a socket descriptor.
pub struct SocketFile {
    pub sock: Arc<dyn Socket>,
    ino: u64,
}

impl SocketFile {
    pub fn inode(sock: Arc<dyn Socket>) -> Arc<dyn Inode> {
        Arc::new(SocketFile {
            sock,
            ino: crate::fs::new_ino(),
        })
    }
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        self.sock.close();
    }
}

impl Inode for SocketFile {
    fn file_type(&self) -> FileType {
        FileType::Socket
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        0o777
    }
    fn dev(&self) -> u64 {
        crate::fs::DEV_SOCKFS
    }
    fn seekable(&self) -> bool {
        false
    }
    fn read_stream(&self, buf: &mut [u8], nonblock: bool) -> KResult<usize> {
        self.sock.recv(buf, 0, nonblock).map(|r| r.len)
    }
    fn write_stream(&self, data: &[u8], nonblock: bool) -> KResult<usize> {
        self.sock.send(data, None, 0, nonblock, Vec::new())
    }
    fn poll(&self) -> u16 {
        self.sock.poll()
    }
    fn poll_generation(&self) -> u64 {
        self.sock.poll_generation()
    }
    fn anon_name(&self) -> Option<&'static str> {
        Some("socket")
    }
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// The socket behind a descriptor's inode (ENOTSOCK otherwise).
pub fn socket_of(inode: &Arc<dyn Inode>) -> KResult<Arc<dyn Socket>> {
    inode
        .as_any()
        .and_then(|a| a.downcast_ref::<SocketFile>())
        .map(|s| s.sock.clone())
        .ok_or(Errno::ENOTSOCK)
}

/// Reads a `u32` (an `int`) option value.
pub fn int_opt(value: &[u8]) -> KResult<u32> {
    value
        .get(..4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or(Errno::EINVAL)
}
