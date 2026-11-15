//! UDP: datagram sockets.

use super::iface::{self, Iface};
use super::inet::{self, Ports};
use super::ip::{self, PROTO_UDP, parse_sockaddr};
use super::socket::*;
use crate::abi::{Errno, KResult};
use crate::fs::File;
use crate::sync::SpinLock;
use crate::task::wait::WaitQueue;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static SOCKETS: SpinLock<Vec<Weak<UdpSocket>>> = SpinLock::new(Vec::new());
static GENERATION: AtomicU64 = AtomicU64::new(0);
/// Datagrams queued per socket before new ones are dropped.
const INBOX: usize = 256;

/// (sender, bytes).
type Datagram = ((u32, u16), Vec<u8>);

#[derive(Default)]
struct Ends {
    local: Option<(u32, u16)>,
    peer: Option<(u32, u16)>,
}

pub struct UdpSocket {
    ends: SpinLock<Ends>,
    inbox: SpinLock<VecDeque<Datagram>>,
    wait: WaitQueue,
    reuse: AtomicBool,
    rd_shut: AtomicBool,
}

impl UdpSocket {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Arc<dyn Socket> {
        let s = Arc::new(UdpSocket {
            ends: SpinLock::new(Ends::default()),
            inbox: SpinLock::new(VecDeque::new()),
            wait: WaitQueue::new(),
            reuse: AtomicBool::new(false),
            rd_shut: AtomicBool::new(false),
        });
        s.register();
        s
    }

    fn register(self: &Arc<Self>) {
        let mut l = SOCKETS.lock();
        l.retain(|w| w.strong_count() > 0);
        l.push(Arc::downgrade(self));
    }

    /// Binds to an ephemeral port if not bound yet.
    fn ensure_bound(&self) -> KResult<(u32, u16)> {
        if let Some(l) = self.ends.lock().local {
            return Ok(l);
        }
        let port = inet::ports().bind(Ports::UDP, 0, false)?;
        self.ends.lock().local = Some((0, port));
        Ok((0, port))
    }

    fn deliver(&self, from: (u32, u16), data: &[u8]) {
        if self.rd_shut.load(Ordering::Relaxed) {
            return;
        }
        let mut q = self.inbox.lock();
        if q.len() < INBOX {
            q.push_back((from, data.to_vec()));
        }
        drop(q);
        GENERATION.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
        crate::fs::poll_notify();
    }
}

/// Sends one datagram from `src` to `dst`.
pub fn send_datagram(src: (u32, u16), dst: (u32, u16), data: &[u8]) -> KResult<()> {
    let len = 8 + data.len();
    let mut d = Vec::with_capacity(len);
    d.extend_from_slice(&src.1.to_be_bytes());
    d.extend_from_slice(&dst.1.to_be_bytes());
    d.extend_from_slice(&(len as u16).to_be_bytes());
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(data);
    let mut c = ip::checksum(&d, ip::pseudo(src.0, dst.0, PROTO_UDP, len));
    if c == 0 {
        c = 0xffff;
    }
    d[6..8].copy_from_slice(&c.to_be_bytes());
    ip::output(src.0, dst.0, PROTO_UDP, &d)
}

pub fn input(f: &Arc<Iface>, src: u32, dst: u32, body: &[u8]) {
    if body.len() < 8 {
        return;
    }
    let sport = u16::from_be_bytes([body[0], body[1]]);
    let dport = u16::from_be_bytes([body[2], body[3]]);
    let len = (u16::from_be_bytes([body[4], body[5]]) as usize).clamp(8, body.len());
    let data = &body[8..len];
    if dport == 68 && super::dhcp::input(f, data) {
        return;
    }
    let broadcast = !iface::is_local(dst);
    let socks: Vec<Arc<UdpSocket>> = SOCKETS.lock().iter().filter_map(|w| w.upgrade()).collect();
    for s in socks {
        let e = s.ends.lock();
        let Some(local) = e.local else { continue };
        let matches = local.1 == dport
            && (local.0 == 0 || local.0 == dst || broadcast)
            && e.peer.is_none_or(|p| p == (src, sport));
        drop(e);
        if matches {
            s.deliver((src, sport), data);
            if !broadcast {
                return;
            }
        }
    }
}

impl Socket for UdpSocket {
    fn kind(&self) -> (u16, u32) {
        (AF_INET, SOCK_DGRAM)
    }

    fn bind(&self, addr: &[u8]) -> KResult<()> {
        let (ip, port) = parse_sockaddr(addr)?;
        if ip != 0 && !iface::is_local(ip) && ip != u32::MAX {
            return Err(Errno::EADDRNOTAVAIL);
        }
        let mut e = self.ends.lock();
        if e.local.is_some() {
            return Err(Errno::EINVAL);
        }
        let port = inet::ports().bind(Ports::UDP, port, self.reuse.load(Ordering::Relaxed))?;
        e.local = Some((ip, port));
        Ok(())
    }

    fn connect(&self, addr: &[u8], _nonblock: bool) -> KResult<()> {
        if addr.len() >= 2 && u16::from_le_bytes([addr[0], addr[1]]) == 0 {
            self.ends.lock().peer = None; // AF_UNSPEC: disconnect
            return Ok(());
        }
        let (ip, port) = parse_sockaddr(addr)?;
        let ip = if ip == 0 { iface::LOOPBACK_IP } else { ip };
        self.ensure_bound()?;
        let (_, _, src) = iface::route(ip)?;
        let mut e = self.ends.lock();
        if let Some(l) = e.local.as_mut()
            && l.0 == 0
        {
            l.0 = src;
        }
        e.peer = Some((ip, port));
        Ok(())
    }

    fn send(
        &self,
        data: &[u8],
        to: Option<&[u8]>,
        _flags: u32,
        _nonblock: bool,
        _rights: Vec<Arc<File>>,
    ) -> KResult<usize> {
        let dst = match to {
            Some(a) => parse_sockaddr(a)?,
            None => self.ends.lock().peer.ok_or(Errno::EDESTADDRREQ)?,
        };
        let dst = (
            if dst.0 == 0 {
                iface::LOOPBACK_IP
            } else {
                dst.0
            },
            dst.1,
        );
        let local = self.ensure_bound()?;
        let (_, _, src) = iface::route(dst.0)?;
        let src_ip = if local.0 != 0 && local.0 != u32::MAX {
            local.0
        } else {
            src
        };
        if data.len() > 1472 {
            return Err(Errno::EMSGSIZE);
        }
        send_datagram((src_ip, local.1), dst, data)?;
        Ok(data.len())
    }

    fn recv(&self, buf: &mut [u8], flags: u32, nonblock: bool) -> KResult<Received> {
        loop {
            {
                let mut q = self.inbox.lock();
                let item = if flags & MSG_PEEK != 0 {
                    q.front().cloned()
                } else {
                    q.pop_front()
                };
                if let Some((from, d)) = item {
                    let n = d.len().min(buf.len());
                    buf[..n].copy_from_slice(&d[..n]);
                    return Ok(Received {
                        len: n,
                        full_len: d.len(),
                        from: Some(iface::sockaddr_in(from.0, from.1)),
                        ..Default::default()
                    });
                }
            }
            if self.rd_shut.load(Ordering::Relaxed) {
                return Ok(Received::default());
            }
            if nonblock || flags & MSG_DONTWAIT != 0 {
                return Err(Errno::EAGAIN);
            }
            self.wait.wait_interruptible(|| {
                !self.inbox.lock().is_empty() || self.rd_shut.load(Ordering::Relaxed)
            })?;
        }
    }

    fn shutdown(&self, how: u32) -> KResult<()> {
        if self.ends.lock().peer.is_none() {
            return Err(Errno::ENOTCONN);
        }
        if how != 1 {
            self.rd_shut.store(true, Ordering::Relaxed);
            self.wait.wake_all();
            crate::fs::poll_notify();
        }
        Ok(())
    }

    fn local_addr(&self) -> KResult<Vec<u8>> {
        let l = self.ends.lock().local.unwrap_or((0, 0));
        Ok(iface::sockaddr_in(l.0, l.1))
    }

    fn peer_addr(&self) -> KResult<Vec<u8>> {
        let p = self.ends.lock().peer.ok_or(Errno::ENOTCONN)?;
        Ok(iface::sockaddr_in(p.0, p.1))
    }

    fn set_option(&self, level: u32, name: u32, value: &[u8]) -> KResult<()> {
        if level == SOL_SOCKET && (name == inet::SO_REUSEADDR || name == inet::SO_REUSEPORT) {
            self.reuse.store(int_opt(value)? != 0, Ordering::Relaxed);
        }
        Ok(())
    }

    fn get_option(&self, level: u32, name: u32) -> KResult<Vec<u8>> {
        if level == SOL_SOCKET && name == inet::SO_REUSEADDR {
            return Ok((self.reuse.load(Ordering::Relaxed) as u32)
                .to_le_bytes()
                .to_vec());
        }
        inet::common_option(level, name, self.kind())
    }

    fn poll(&self) -> u16 {
        use crate::fs::poll::*;
        let readable = !self.inbox.lock().is_empty() || self.rd_shut.load(Ordering::Relaxed);
        POLLOUT | if readable { POLLIN } else { 0 }
    }

    fn poll_generation(&self) -> u64 {
        GENERATION.load(Ordering::Relaxed)
    }

    fn bytes_ready(&self) -> usize {
        self.inbox.lock().front().map_or(0, |(_, d)| d.len())
    }

    fn close(&self) {
        if let Some((_, port)) = self.ends.lock().local.take() {
            inet::ports().release(Ports::UDP, port);
        }
        SOCKETS
            .lock()
            .retain(|w| w.upgrade().is_some_and(|s| !core::ptr::eq(&*s, self)));
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
