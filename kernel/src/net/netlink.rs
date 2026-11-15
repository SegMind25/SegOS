//! AF_NETLINK, NETLINK_ROUTE: what `ip`, glibc's `getifaddrs` and
//! `getaddrinfo` ask the kernel about interfaces, addresses and routes.
//! Dumps of links, addresses and routes; adding and removing addresses,
//! the default route, and setting links up or down. Other netlink
//! protocols (uevents) can be opened and never report anything.

use super::iface::{self, Iface};
use super::socket::*;
use crate::abi::{Errno, KResult};
use crate::fs::File;
use crate::sync::SpinLock;
use crate::task::wait::WaitQueue;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_MULTI: u16 = 2;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_SETLINK: u16 = 19;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;

static NEXT_PID: AtomicU32 = AtomicU32::new(0x8000_0000);
static GENERATION: AtomicU64 = AtomicU64::new(0);

pub struct NetlinkSocket {
    ty: u32,
    protocol: u32,
    pid: AtomicU32,
    inbox: SpinLock<VecDeque<Vec<u8>>>,
    wait: WaitQueue,
}

pub fn new_socket(ty: u32, protocol: u32) -> KResult<Arc<dyn Socket>> {
    if ty != SOCK_RAW && ty != SOCK_DGRAM {
        return Err(Errno::ESOCKTNOSUPPORT);
    }
    if protocol != 0 && protocol != 15 {
        return Err(Errno::EPROTONOSUPPORT);
    }
    Ok(Arc::new(NetlinkSocket {
        ty,
        protocol,
        pid: AtomicU32::new(0),
        inbox: SpinLock::new(VecDeque::new()),
        wait: WaitQueue::new(),
    }))
}

fn attr(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend_from_slice(&((4 + data.len()) as u16).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// One message: header, then `body`.
fn msg(ty: u16, flags: u16, seq: u32, pid: u32, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + body.len());
    m.extend_from_slice(&((16 + body.len()) as u32).to_le_bytes());
    m.extend_from_slice(&ty.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&seq.to_le_bytes());
    m.extend_from_slice(&pid.to_le_bytes());
    m.extend_from_slice(body);
    while !m.len().is_multiple_of(4) {
        m.push(0);
    }
    m
}

fn link(f: &Iface) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(&(if f.is_loopback() { 772u16 } else { 1 }).to_le_bytes());
    b.extend_from_slice(&f.index.to_le_bytes());
    b.extend_from_slice(&iface::flags(f).to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    attr(&mut b, 3, &cstr(&f.name)); // IFLA_IFNAME
    attr(&mut b, 1, &f.mac); // IFLA_ADDRESS
    attr(&mut b, 2, &if f.is_loopback() { [0; 6] } else { [0xff; 6] });
    attr(
        &mut b,
        4,
        &(if f.is_loopback() { 65536u32 } else { f.mtu }).to_le_bytes(),
    );
    attr(&mut b, 13, &1000u32.to_le_bytes()); // IFLA_TXQLEN
    let up = f.up.load(Ordering::Relaxed);
    let oper = if f.is_loopback() {
        0
    } else if up {
        6
    } else {
        2
    };
    attr(&mut b, 16, &[oper]); // IFLA_OPERSTATE
    attr(&mut b, 17, &[0]); // IFLA_LINKMODE
    let mut stats = [0u32; 23];
    stats[0] = f.rx_packets.load(Ordering::Relaxed) as u32;
    stats[1] = f.tx_packets.load(Ordering::Relaxed) as u32;
    stats[2] = f.rx_bytes.load(Ordering::Relaxed) as u32;
    stats[3] = f.tx_bytes.load(Ordering::Relaxed) as u32;
    let sb: Vec<u8> = stats.iter().flat_map(|s| s.to_le_bytes()).collect();
    attr(&mut b, 7, &sb); // IFLA_STATS
    b
}

fn addr(f: &Iface, ip: u32, prefix: u8) -> Vec<u8> {
    let mut b = alloc::vec![2, prefix, 0x80, if f.is_loopback() { 254 } else { 0 }];
    b.extend_from_slice(&f.index.to_le_bytes());
    attr(&mut b, 1, &ip.to_be_bytes()); // IFA_ADDRESS
    attr(&mut b, 2, &ip.to_be_bytes()); // IFA_LOCAL
    if !f.is_loopback() {
        attr(&mut b, 4, &(ip | !iface::mask(prefix)).to_be_bytes()); // IFA_BROADCAST
    }
    attr(&mut b, 3, &cstr(&f.name)); // IFA_LABEL
    b
}

fn route(dst: u32, len: u8, gw: Option<u32>, src: Option<u32>, oif: u32) -> Vec<u8> {
    let scope = if gw.is_some() { 0 } else { 253 };
    let proto = if gw.is_some() { 16 } else { 2 };
    let mut b = alloc::vec![2, len, 0, 0, 254, proto, scope, 1];
    b.extend_from_slice(&0u32.to_le_bytes());
    attr(&mut b, 15, &254u32.to_le_bytes()); // RTA_TABLE
    if len > 0 {
        attr(&mut b, 1, &dst.to_be_bytes()); // RTA_DST
    }
    if let Some(s) = src {
        attr(&mut b, 7, &s.to_be_bytes()); // RTA_PREFSRC
    }
    if let Some(g) = gw {
        attr(&mut b, 5, &g.to_be_bytes()); // RTA_GATEWAY
    }
    attr(&mut b, 4, &oif.to_le_bytes()); // RTA_OIF
    b
}

/// The attributes after a fixed header of `skip` bytes: (type, data).
fn attrs(body: &[u8], skip: usize) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut i = skip;
    while i + 4 <= body.len() {
        let l = u16::from_le_bytes([body[i], body[i + 1]]) as usize;
        let t = u16::from_le_bytes([body[i + 2], body[i + 3]]) & 0x3fff;
        if l < 4 || i + l > body.len() {
            break;
        }
        out.push((t, &body[i + 4..i + l]));
        i += (l + 3) & !3;
    }
    out
}

fn ip_attr(a: &[(u16, &[u8])], t: u16) -> Option<u32> {
    a.iter()
        .find(|(k, _)| *k == t)
        .and_then(|(_, v)| v.get(..4))
        .map(|v| u32::from_be_bytes(v.try_into().unwrap()))
}

impl NetlinkSocket {
    fn my_pid(&self) -> u32 {
        let p = self.pid.load(Ordering::Relaxed);
        if p != 0 {
            return p;
        }
        let new = NEXT_PID.fetch_add(1, Ordering::Relaxed);
        match self
            .pid
            .compare_exchange(0, new, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => new,
            Err(p) => p,
        }
    }

    fn queue(&self, d: Vec<u8>) {
        self.inbox.lock().push_back(d);
        GENERATION.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
        crate::fs::poll_notify();
    }

    /// Queues `msgs` as datagrams of at most ~4 KiB each.
    fn queue_all(&self, msgs: Vec<Vec<u8>>) {
        let mut d = Vec::new();
        for m in msgs {
            if !d.is_empty() && d.len() + m.len() > 3800 {
                self.queue(core::mem::take(&mut d));
            }
            d.extend_from_slice(&m);
        }
        if !d.is_empty() {
            self.queue(d);
        }
    }

    fn handle(&self, m: &[u8]) {
        let ty = u16::from_le_bytes([m[4], m[5]]);
        let flags = u16::from_le_bytes([m[6], m[7]]);
        let seq = u32::from_le_bytes(m[8..12].try_into().unwrap());
        let pid = self.my_pid();
        let body = &m[16..];
        let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
        let family = body.first().copied().unwrap_or(0);
        let mut out = Vec::new();
        let mut result: KResult<()> = Ok(());
        match ty {
            RTM_GETLINK => {
                let want = body
                    .get(4..8)
                    .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
                for f in iface::all() {
                    if dump || want == 0 || f.index == want {
                        out.push(msg(
                            RTM_NEWLINK,
                            if dump { NLM_F_MULTI } else { 0 },
                            seq,
                            pid,
                            &link(&f),
                        ));
                    }
                }
                if !dump && out.is_empty() {
                    result = Err(Errno::ENODEV);
                }
            }
            RTM_GETADDR if family == 0 || family == 2 => {
                for f in iface::all() {
                    if let Some((ip, p)) = *f.addr.lock() {
                        out.push(msg(RTM_NEWADDR, NLM_F_MULTI, seq, pid, &addr(&f, ip, p)));
                    }
                }
            }
            RTM_GETROUTE if family == 0 || family == 2 => {
                for f in iface::all().into_iter().filter(|f| !f.is_loopback()) {
                    let Some((ip, p)) = *f.addr.lock() else {
                        continue;
                    };
                    if let Some(gw) = *f.gateway.lock() {
                        out.push(msg(
                            RTM_NEWROUTE,
                            NLM_F_MULTI,
                            seq,
                            pid,
                            &route(0, 0, Some(gw), None, f.index),
                        ));
                    }
                    let net = ip & iface::mask(p);
                    out.push(msg(
                        RTM_NEWROUTE,
                        NLM_F_MULTI,
                        seq,
                        pid,
                        &route(net, p, None, Some(ip), f.index),
                    ));
                }
            }
            RTM_GETADDR | RTM_GETROUTE => {}
            RTM_NEWLINK | RTM_SETLINK => {
                let idx = body
                    .get(4..8)
                    .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
                let fl = body
                    .get(8..12)
                    .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
                let change = body
                    .get(12..16)
                    .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
                match iface::by_index(idx) {
                    Some(f) => {
                        if change & iface::IFF_UP != 0 || change == 0 {
                            f.up.store(fl & iface::IFF_UP != 0, Ordering::Relaxed);
                        }
                    }
                    None => result = Err(Errno::ENODEV),
                }
            }
            RTM_NEWADDR | RTM_DELADDR => {
                let prefix = body.get(1).copied().unwrap_or(32);
                let idx = body
                    .get(4..8)
                    .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
                let a = attrs(body, 8);
                let ip = ip_attr(&a, 2).or_else(|| ip_attr(&a, 1));
                match (iface::by_index(idx), ip) {
                    (Some(f), Some(ip)) if ty == RTM_NEWADDR => *f.addr.lock() = Some((ip, prefix)),
                    (Some(f), Some(ip)) => {
                        let mut cur = f.addr.lock();
                        if cur.is_some_and(|(c, _)| c == ip) {
                            *cur = None;
                        } else {
                            result = Err(Errno::EADDRNOTAVAIL);
                        }
                    }
                    _ => result = Err(Errno::EINVAL),
                }
            }
            RTM_NEWROUTE | RTM_DELROUTE => {
                let a = attrs(body, 12);
                let gw = ip_attr(&a, 5);
                let oif = a
                    .iter()
                    .find(|(k, _)| *k == 4)
                    .and_then(|(_, v)| v.get(..4))
                    .map(|v| u32::from_le_bytes(v.try_into().unwrap()));
                let dst_len = body.get(1).copied().unwrap_or(0);
                if dst_len == 0 {
                    let f = oif.and_then(iface::by_index).or_else(|| {
                        iface::all().into_iter().find(|f| {
                            gw.is_some_and(|g| {
                                f.addr.lock().is_some_and(|(ip, p)| {
                                    ip & iface::mask(p) == g & iface::mask(p)
                                })
                            })
                        })
                    });
                    match f {
                        Some(f) => *f.gateway.lock() = if ty == RTM_NEWROUTE { gw } else { None },
                        None => result = Err(Errno::ENETUNREACH),
                    }
                }
            }
            _ => result = Err(Errno::EOPNOTSUPP),
        }
        if dump && result.is_ok() {
            out.push(msg(NLMSG_DONE, NLM_F_MULTI, seq, pid, &0i32.to_le_bytes()));
        } else if result.is_err() || flags & NLM_F_ACK != 0 {
            let code = result.err().map_or(0, |e| -e.0);
            let mut b = code.to_le_bytes().to_vec();
            b.extend_from_slice(&m[..16]);
            out.push(msg(NLMSG_ERROR, 0, seq, pid, &b));
        }
        self.queue_all(out);
    }
}

impl Socket for NetlinkSocket {
    fn kind(&self) -> (u16, u32) {
        (AF_NETLINK, self.ty)
    }

    fn bind(&self, a: &[u8]) -> KResult<()> {
        if a.len() < 12 {
            return Err(Errno::EINVAL);
        }
        let want = u32::from_le_bytes(a[4..8].try_into().unwrap());
        if want != 0 {
            self.pid.store(want, Ordering::Relaxed);
        } else {
            self.my_pid();
        }
        Ok(())
    }

    fn connect(&self, _addr: &[u8], _nonblock: bool) -> KResult<()> {
        Ok(())
    }

    fn send(
        &self,
        data: &[u8],
        _to: Option<&[u8]>,
        _flags: u32,
        _nonblock: bool,
        _rights: Vec<Arc<File>>,
    ) -> KResult<usize> {
        if self.protocol != 0 {
            return Ok(data.len());
        }
        let mut i = 0;
        while i + 16 <= data.len() {
            let len = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
            if len < 16 || i + len > data.len() {
                break;
            }
            self.handle(&data[i..i + len]);
            i += (len + 3) & !3;
        }
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
                if let Some(d) = item {
                    let n = d.len().min(buf.len());
                    buf[..n].copy_from_slice(&d[..n]);
                    let mut from = alloc::vec![0u8; 12];
                    from[0..2].copy_from_slice(&AF_NETLINK.to_le_bytes());
                    return Ok(Received {
                        len: n,
                        full_len: d.len(),
                        from: Some(from),
                        ..Default::default()
                    });
                }
            }
            if nonblock || flags & MSG_DONTWAIT != 0 {
                return Err(Errno::EAGAIN);
            }
            self.wait
                .wait_interruptible(|| !self.inbox.lock().is_empty())?;
        }
    }

    fn shutdown(&self, _how: u32) -> KResult<()> {
        Ok(())
    }

    fn local_addr(&self) -> KResult<Vec<u8>> {
        let mut a = alloc::vec![0u8; 12];
        a[0..2].copy_from_slice(&AF_NETLINK.to_le_bytes());
        a[4..8].copy_from_slice(&self.my_pid().to_le_bytes());
        Ok(a)
    }

    fn set_option(&self, _level: u32, _name: u32, _value: &[u8]) -> KResult<()> {
        Ok(())
    }

    fn get_option(&self, level: u32, name: u32) -> KResult<Vec<u8>> {
        match (level, name) {
            (SOL_SOCKET, 7 | 8) => Ok(212992u32.to_le_bytes().to_vec()),
            (SOL_SOCKET, 3) => Ok(self.ty.to_le_bytes().to_vec()),
            (SOL_SOCKET, 4) => Ok(0u32.to_le_bytes().to_vec()),
            _ => Err(Errno::ENOPROTOOPT),
        }
    }

    fn poll(&self) -> u16 {
        use crate::fs::poll::*;
        POLLOUT
            | if self.inbox.lock().is_empty() {
                0
            } else {
                POLLIN
            }
    }

    fn poll_generation(&self) -> u64 {
        GENERATION.load(Ordering::Relaxed)
    }

    fn bytes_ready(&self) -> usize {
        self.inbox.lock().front().map_or(0, |d| d.len())
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
