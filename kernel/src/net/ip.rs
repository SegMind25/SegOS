//! IPv4 and ICMP: packet input and output, echo replies, and raw ICMP
//! sockets (`ping`).
//!
//! Fragments are not reassembled (dropped), and output sets "don't
//! fragment": TCP keeps segments within the MTU and UDP datagrams larger
//! than the MTU fail with EMSGSIZE.

use super::iface::{self, Iface};
use super::socket::*;
use crate::abi::{Errno, KResult};
use crate::fs::File;
use crate::sync::SpinLock;
use crate::task::wait::WaitQueue;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// The Internet checksum of `data`, continuing from `sum`.
pub fn checksum(data: &[u8], mut sum: u32) -> u16 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = chunks.remainder() {
        sum += (*b as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The TCP/UDP pseudo-header sum.
pub fn pseudo(src: u32, dst: u32, proto: u8, len: usize) -> u32 {
    (src >> 16) + (src & 0xffff) + (dst >> 16) + (dst & 0xffff) + proto as u32 + len as u32
}

static ID: AtomicU16 = AtomicU16::new(1);

/// Wraps `payload` in an IPv4 header and sends it.
pub fn output(src: u32, dst: u32, proto: u8, payload: &[u8]) -> KResult<()> {
    let len = 20 + payload.len();
    if len > 1500 {
        return Err(Errno::EMSGSIZE);
    }
    let mut p = Vec::with_capacity(len);
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&(len as u16).to_be_bytes());
    p.extend_from_slice(&ID.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    p.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    p.extend_from_slice(&[64, proto, 0, 0]);
    p.extend_from_slice(&src.to_be_bytes());
    p.extend_from_slice(&dst.to_be_bytes());
    let c = checksum(&p, 0);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(payload);
    iface::send_ip(dst, p)
}

/// A received IPv4 packet (header included).
pub fn input(f: &Arc<Iface>, p: &[u8]) {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return;
    }
    let ihl = (p[0] & 0xf) as usize * 4;
    let total = u16::from_be_bytes([p[2], p[3]]) as usize;
    if ihl < 20 || total < ihl || total > p.len() {
        return;
    }
    let p = &p[..total];
    let frag = u16::from_be_bytes([p[6], p[7]]);
    if frag & 0x3fff != 0 {
        return; // a fragment: not reassembled
    }
    let src = u32::from_be_bytes(p[12..16].try_into().unwrap());
    let dst = u32::from_be_bytes(p[16..20].try_into().unwrap());
    let ours = iface::is_local(dst)
        || dst == u32::MAX
        || f.addr
            .lock()
            .is_none_or(|(ip, pr)| dst == ip | !iface::mask(pr));
    if !ours {
        return;
    }
    let body = &p[ihl..];
    match p[9] {
        PROTO_ICMP => icmp_input(p, src, dst, body),
        PROTO_TCP => super::tcp::input(src, dst, body),
        PROTO_UDP => super::udp::input(f, src, dst, body),
        _ => {}
    }
}

fn icmp_input(packet: &[u8], src: u32, dst: u32, body: &[u8]) {
    if body.len() < 8 || checksum(body, 0) != 0 {
        return;
    }
    for s in RAW.lock().iter().filter_map(|w| w.upgrade()) {
        s.deliver(packet, src, body);
    }
    if body[0] == 8 && dst != u32::MAX {
        // Echo request: answer from the address it was sent to.
        let mut reply = body.to_vec();
        reply[0] = 0;
        reply[2..4].fill(0);
        let c = checksum(&reply, 0);
        reply[2..4].copy_from_slice(&c.to_be_bytes());
        let _ = output(dst, src, PROTO_ICMP, &reply);
    }
}

// ---- ICMP sockets: SOCK_RAW (with the IP header on receive) and the
// unprivileged SOCK_DGRAM kind (echo identifier = the socket's "port"). --

static RAW: SpinLock<Vec<Weak<IcmpSocket>>> = SpinLock::new(Vec::new());
static GENERATION: AtomicU64 = AtomicU64::new(0);
static NEXT_ID: AtomicU16 = AtomicU16::new(0x5e60);

pub struct IcmpSocket {
    raw: bool,
    ident: u16,
    inbox: SpinLock<VecDeque<(u32, Vec<u8>)>>,
    peer: SpinLock<Option<u32>>,
    wait: WaitQueue,
}

impl IcmpSocket {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(raw: bool) -> Arc<dyn Socket> {
        let s = Arc::new(IcmpSocket {
            raw,
            ident: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            inbox: SpinLock::new(VecDeque::new()),
            peer: SpinLock::new(None),
            wait: WaitQueue::new(),
        });
        let mut r = RAW.lock();
        r.retain(|w| w.strong_count() > 0);
        r.push(Arc::downgrade(&s));
        s
    }

    fn deliver(&self, packet: &[u8], src: u32, body: &[u8]) {
        let msg = if self.raw {
            packet.to_vec()
        } else {
            // Echo replies with our identifier only.
            if body[0] != 0 || u16::from_be_bytes([body[4], body[5]]) != self.ident {
                return;
            }
            body.to_vec()
        };
        let mut q = self.inbox.lock();
        if q.len() < 128 {
            q.push_back((src, msg));
        }
        drop(q);
        GENERATION.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
        crate::fs::poll_notify();
    }
}

pub fn parse_sockaddr(a: &[u8]) -> KResult<(u32, u16)> {
    if a.len() < 8 {
        return Err(Errno::EINVAL);
    }
    let fam = u16::from_le_bytes([a[0], a[1]]);
    if fam != AF_INET && !(fam == 0) {
        return Err(Errno::EAFNOSUPPORT);
    }
    Ok((
        u32::from_be_bytes(a[4..8].try_into().unwrap()),
        u16::from_be_bytes([a[2], a[3]]),
    ))
}

impl Socket for IcmpSocket {
    fn kind(&self) -> (u16, u32) {
        (AF_INET, if self.raw { SOCK_RAW } else { SOCK_DGRAM })
    }
    fn bind(&self, _addr: &[u8]) -> KResult<()> {
        Ok(())
    }
    fn connect(&self, addr: &[u8], _nonblock: bool) -> KResult<()> {
        *self.peer.lock() = Some(parse_sockaddr(addr)?.0);
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
            Some(a) => parse_sockaddr(a)?.0,
            None => self.peer.lock().ok_or(Errno::EDESTADDRREQ)?,
        };
        if data.len() < 8 {
            return Err(Errno::EINVAL);
        }
        let mut msg = data.to_vec();
        if !self.raw {
            msg[4..6].copy_from_slice(&self.ident.to_be_bytes());
            msg[2..4].fill(0);
            let c = checksum(&msg, 0);
            msg[2..4].copy_from_slice(&c.to_be_bytes());
        }
        let (_, _, src) = iface::route(dst)?;
        output(src, dst, PROTO_ICMP, &msg)?;
        Ok(data.len())
    }
    fn recv(&self, buf: &mut [u8], flags: u32, nonblock: bool) -> KResult<Received> {
        loop {
            {
                let mut q = self.inbox.lock();
                if let Some((src, msg)) = if flags & MSG_PEEK != 0 {
                    q.front().cloned()
                } else {
                    q.pop_front()
                } {
                    let n = msg.len().min(buf.len());
                    buf[..n].copy_from_slice(&msg[..n]);
                    return Ok(Received {
                        len: n,
                        full_len: msg.len(),
                        from: Some(iface::sockaddr_in(src, 0)),
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
        Ok(iface::sockaddr_in(0, if self.raw { 1 } else { self.ident }))
    }
    fn set_option(&self, _level: u32, _name: u32, _value: &[u8]) -> KResult<()> {
        Ok(())
    }
    fn get_option(&self, level: u32, name: u32) -> KResult<Vec<u8>> {
        super::inet::common_option(level, name, self.kind())
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
        self.inbox.lock().front().map_or(0, |(_, m)| m.len())
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
