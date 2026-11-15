//! AF_INET sockets: the socket calls for TCP (stream) sockets, local port
//! allocation, and the socket options every AF_INET socket answers.

use super::iface;
use super::ip::parse_sockaddr;
use super::socket::*;
use super::tcp::{self, State, Tcb};
use crate::abi::{Errno, KResult};
use crate::fs::File;
use crate::sync::SpinLock;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

pub const SO_REUSEADDR: u32 = 2;
pub const SO_TYPE: u32 = 3;
pub const SO_ERROR: u32 = 4;
pub const SO_BROADCAST: u32 = 6;
pub const SO_SNDBUF: u32 = 7;
pub const SO_RCVBUF: u32 = 8;
pub const SO_KEEPALIVE: u32 = 9;
pub const SO_LINGER: u32 = 13;
pub const SO_REUSEPORT: u32 = 15;
pub const SO_RCVTIMEO: u32 = 20;
pub const SO_SNDTIMEO: u32 = 21;
pub const SO_ACCEPTCONN: u32 = 30;
pub const SO_PROTOCOL: u32 = 38;
pub const SO_DOMAIN: u32 = 39;
const TCP_NODELAY: u32 = 1;
const TCP_MAXSEG: u32 = 2;
const TCP_INFO: u32 = 11;

/// Local ports in use, per protocol.
pub struct Ports {
    map: SpinLock<BTreeMap<(u8, u16), (usize, bool)>>,
    next: AtomicU16,
}

static PORTS: Ports = Ports {
    map: SpinLock::new(BTreeMap::new()),
    next: AtomicU16::new(32768),
};

pub fn ports() -> &'static Ports {
    &PORTS
}

impl Ports {
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;

    /// Reserves `port` (0: an ephemeral one, 32768 to 60999 as Linux).
    pub fn bind(&self, proto: u8, port: u16, reuse: bool) -> KResult<u16> {
        let mut m = self.map.lock();
        if port == 0 {
            for _ in 0..28232 {
                let p = self.next.fetch_add(1, Ordering::Relaxed);
                if !(32768..61000).contains(&p) {
                    self.next.store(32769, Ordering::Relaxed);
                    continue;
                }
                if let alloc::collections::btree_map::Entry::Vacant(e) = m.entry((proto, p)) {
                    e.insert((1, reuse));
                    return Ok(p);
                }
            }
            return Err(Errno::EADDRINUSE);
        }
        match m.get_mut(&(proto, port)) {
            Some((n, r)) if reuse && *r => *n += 1,
            Some(_) => return Err(Errno::EADDRINUSE),
            None => {
                m.insert((proto, port), (1, reuse));
            }
        }
        Ok(port)
    }

    pub fn release(&self, proto: u8, port: u16) {
        let mut m = self.map.lock();
        if let Some((n, _)) = m.get_mut(&(proto, port)) {
            *n -= 1;
            if *n == 0 {
                m.remove(&(proto, port));
            }
        }
    }
}

fn int(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

/// Options with the same answer on every AF_INET socket.
pub fn common_option(level: u32, name: u32, kind: (u16, u32)) -> KResult<Vec<u8>> {
    match (level, name) {
        (SOL_SOCKET, SO_TYPE) => Ok(int(kind.1)),
        (SOL_SOCKET, SO_DOMAIN) => Ok(int(kind.0 as u32)),
        (SOL_SOCKET, SO_PROTOCOL) => Ok(int(match kind.1 {
            SOCK_STREAM => 6,
            SOCK_DGRAM => 17,
            _ => 1,
        })),
        (SOL_SOCKET, SO_ERROR | SO_ACCEPTCONN | SO_KEEPALIVE | SO_REUSEADDR | SO_BROADCAST) => {
            Ok(int(0))
        }
        (SOL_SOCKET, SO_SNDBUF) => Ok(int(tcp::SNDBUF as u32)),
        (SOL_SOCKET, SO_RCVBUF) => Ok(int(tcp::RCVBUF as u32)),
        (SOL_SOCKET, SO_LINGER) => Ok(vec![0; 8]),
        (SOL_SOCKET, SO_RCVTIMEO | SO_SNDTIMEO) => Ok(vec![0; 16]),
        (IPPROTO_IP, 1) => Ok(int(0)),     // IP_TOS
        (IPPROTO_IP, 2) => Ok(int(64)),    // IP_TTL
        (IPPROTO_IP, 10) => Ok(int(0)),    // IP_MTU_DISCOVER
        (IPPROTO_IP, 14) => Ok(int(1500)), // IP_MTU
        (IPPROTO_TCP, TCP_NODELAY) => Ok(int(0)),
        (IPPROTO_TCP, TCP_MAXSEG) => Ok(int(1460)),
        _ => Err(Errno::ENOPROTOOPT),
    }
}

enum TState {
    Fresh,
    Bound((u32, u16)),
    Conn { t: Arc<Tcb>, reported: bool },
    Listen(Arc<Tcb>),
}

pub struct TcpSocket {
    st: SpinLock<TState>,
    /// The local port this socket reserved (released on close).
    port: SpinLock<Option<u16>>,
    reuse: AtomicBool,
    opts: SpinLock<BTreeMap<(u32, u32), Vec<u8>>>,
}

impl TcpSocket {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Arc<dyn Socket> {
        Self::with(TState::Fresh)
    }

    fn with(st: TState) -> Arc<dyn Socket> {
        Arc::new(TcpSocket {
            st: SpinLock::new(st),
            port: SpinLock::new(None),
            reuse: AtomicBool::new(false),
            opts: SpinLock::new(BTreeMap::new()),
        })
    }

    fn tcb(&self) -> Option<Arc<Tcb>> {
        match &*self.st.lock() {
            TState::Conn { t, .. } => Some(t.clone()),
            _ => None,
        }
    }

    fn release_port(&self) {
        if let Some(p) = self.port.lock().take() {
            ports().release(Ports::TCP, p);
        }
    }
}

impl Socket for TcpSocket {
    fn kind(&self) -> (u16, u32) {
        (AF_INET, SOCK_STREAM)
    }

    fn bind(&self, addr: &[u8]) -> KResult<()> {
        let (ip, port) = parse_sockaddr(addr)?;
        if ip != 0 && !iface::is_local(ip) {
            return Err(Errno::EADDRNOTAVAIL);
        }
        let mut st = self.st.lock();
        if !matches!(*st, TState::Fresh) {
            return Err(Errno::EINVAL);
        }
        let port = ports().bind(Ports::TCP, port, self.reuse.load(Ordering::Relaxed))?;
        *self.port.lock() = Some(port);
        *st = TState::Bound((ip, port));
        Ok(())
    }

    fn listen(&self, backlog: u32) -> KResult<()> {
        let mut st = self.st.lock();
        let local = match &*st {
            TState::Fresh => {
                let p = ports().bind(Ports::TCP, 0, false)?;
                *self.port.lock() = Some(p);
                (0, p)
            }
            TState::Bound(l) => *l,
            TState::Listen(t) => {
                tcp::set_backlog(t, backlog as usize);
                return Ok(());
            }
            TState::Conn { .. } => return Err(Errno::EINVAL),
        };
        *st = TState::Listen(tcp::listen(local, backlog as usize));
        Ok(())
    }

    fn accept(&self, nonblock: bool) -> KResult<(Arc<dyn Socket>, Vec<u8>)> {
        let l = match &*self.st.lock() {
            TState::Listen(t) => t.clone(),
            _ => return Err(Errno::EINVAL),
        };
        let t = tcp::accept(&l, nonblock)?;
        let remote = t.c.lock().remote;
        Ok((
            Self::with(TState::Conn { t, reported: true }),
            iface::sockaddr_in(remote.0, remote.1),
        ))
    }

    fn connect(&self, addr: &[u8], nonblock: bool) -> KResult<()> {
        let existing = match &mut *self.st.lock() {
            TState::Conn { t, reported } => {
                let (state, _, _) = tcp::info(t);
                match state {
                    State::SynSent | State::SynRcvd if nonblock => return Err(Errno::EALREADY),
                    State::SynSent | State::SynRcvd => Some(t.clone()),
                    State::Closed => {
                        let e = t.c.lock().error.take();
                        return Err(e.unwrap_or(Errno::ECONNREFUSED));
                    }
                    _ if !*reported => {
                        *reported = true;
                        return Ok(());
                    }
                    _ => return Err(Errno::EISCONN),
                }
            }
            TState::Listen(_) => return Err(Errno::EINVAL),
            _ => None,
        };
        if let Some(t) = existing {
            return tcp::wait_connected(&t);
        }
        let (ip, port) = parse_sockaddr(addr)?;
        let ip = if ip == 0 { iface::LOOPBACK_IP } else { ip };
        let (_, _, src) = iface::route(ip)?;
        let mut st = self.st.lock();
        let local = match &*st {
            TState::Bound((lip, lport)) => (if *lip == 0 { src } else { *lip }, *lport),
            _ => {
                let mut p;
                loop {
                    p = ports().bind(Ports::TCP, 0, false)?;
                    if !tcp::in_use((src, p), (ip, port)) {
                        break;
                    }
                }
                *self.port.lock() = Some(p);
                (src, p)
            }
        };
        let t = tcp::connect(local, (ip, port))?;
        *st = TState::Conn {
            t: t.clone(),
            reported: !nonblock,
        };
        drop(st);
        if nonblock {
            return Err(Errno::EINPROGRESS);
        }
        let r = tcp::wait_connected(&t);
        if r.is_err() {
            *self.st.lock() = TState::Fresh;
            self.release_port();
        }
        r
    }

    fn send(
        &self,
        data: &[u8],
        _to: Option<&[u8]>,
        flags: u32,
        nonblock: bool,
        _rights: Vec<Arc<File>>,
    ) -> KResult<usize> {
        let t = self.tcb().ok_or(Errno::EPIPE)?;
        tcp::send(&t, data, nonblock || flags & MSG_DONTWAIT != 0)
    }

    fn recv(&self, buf: &mut [u8], flags: u32, nonblock: bool) -> KResult<Received> {
        let t = self.tcb().ok_or(Errno::ENOTCONN)?;
        let n = tcp::recv(
            &t,
            buf,
            flags & MSG_PEEK != 0,
            flags & MSG_WAITALL != 0,
            nonblock || flags & MSG_DONTWAIT != 0,
        )?;
        Ok(Received {
            len: n,
            full_len: n,
            ..Default::default()
        })
    }

    fn shutdown(&self, how: u32) -> KResult<()> {
        let t = self.tcb().ok_or(Errno::ENOTCONN)?;
        if how == 0 || how == 2 {
            tcp::shutdown_read(&t);
        }
        if how == 1 || how == 2 {
            tcp::shutdown_write(&t);
        }
        Ok(())
    }

    fn local_addr(&self) -> KResult<Vec<u8>> {
        let (ip, port) = match &*self.st.lock() {
            TState::Fresh => (0, 0),
            TState::Bound(l) => *l,
            TState::Conn { t, .. } | TState::Listen(t) => t.c.lock().local,
        };
        Ok(iface::sockaddr_in(ip, port))
    }

    fn peer_addr(&self) -> KResult<Vec<u8>> {
        let t = self.tcb().ok_or(Errno::ENOTCONN)?;
        let c = t.c.lock();
        if matches!(c.state, State::SynSent | State::Closed) {
            return Err(Errno::ENOTCONN);
        }
        Ok(iface::sockaddr_in(c.remote.0, c.remote.1))
    }

    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> KResult<()> {
        if level == SOL_SOCKET && (name == SO_REUSEADDR || name == SO_REUSEPORT) {
            self.reuse.store(int_opt(value)? != 0, Ordering::Relaxed);
        }
        self.opts.lock().insert((level, name), value.to_vec());
        Ok(())
    }

    fn get_option(&self, level: u32, name: u32) -> KResult<Vec<u8>> {
        match (level, name) {
            (SOL_SOCKET, SO_ERROR) => {
                let e = self.tcb().and_then(|t| t.c.lock().error.take());
                return Ok(int(e.map_or(0, |e| e.0 as u32)));
            }
            (SOL_SOCKET, SO_ACCEPTCONN) => {
                return Ok(int(matches!(*self.st.lock(), TState::Listen(_)) as u32));
            }
            (IPPROTO_TCP, TCP_INFO) => {
                let mut info = vec![0u8; 104];
                if let Some(t) = self.tcb() {
                    info[0] = match tcp::info(&t).0 {
                        State::Established => 1,
                        State::SynSent => 2,
                        State::CloseWait => 8,
                        _ => 7,
                    };
                }
                return Ok(info);
            }
            _ => {}
        }
        if let Some(v) = self.opts.lock().get(&(level, name)) {
            return Ok(v.clone());
        }
        common_option(level, name, self.kind())
    }

    fn poll(&self) -> u16 {
        use crate::fs::poll::*;
        match &*self.st.lock() {
            TState::Conn { t, .. } | TState::Listen(t) => tcp::poll(t),
            _ => POLLOUT | POLLHUP,
        }
    }

    fn poll_generation(&self) -> u64 {
        tcp::GENERATION.load(Ordering::Relaxed)
    }

    fn bytes_ready(&self) -> usize {
        self.tcb().map_or(0, |t| tcp::info(&t).1)
    }

    fn close(&self) {
        let st = core::mem::replace(&mut *self.st.lock(), TState::Fresh);
        match st {
            TState::Conn { t, .. } | TState::Listen(t) => tcp::close(&t),
            _ => {}
        }
        self.release_port();
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
