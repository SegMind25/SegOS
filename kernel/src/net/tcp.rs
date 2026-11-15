//! TCP (RFC 9293): connections, listening, retransmission, flow control.
//!
//! Each connection is a [`Tcb`]: its state behind a spinlock, and a wait
//! queue for the threads reading, writing, connecting or accepting on it.
//! The network thread feeds it segments ([`input`]) and runs its timers
//! ([`tick`]); the socket calls (`inet.rs`) read and write its buffers.
//!
//! Kept simple where the networks SegOS runs on allow it: no window
//! scaling (64 KiB windows), no SACK, segments arriving out of order are
//! dropped (and the sender retransmits), go-back-N retransmission with an
//! exponential back-off, no congestion control, ACK on every segment.

use super::ip::{self, PROTO_TCP};
use crate::abi::{Errno, KResult};
use crate::sync::SpinLock;
use crate::task::wait::WaitQueue;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

pub const SNDBUF: usize = 256 * 1024;
pub const RCVBUF: usize = 256 * 1024;
const OUR_MSS: u16 = 1460;
const RTO_INITIAL: u64 = 400;
const RTO_MAX: u64 = 30_000;
const MAX_RETRIES: u32 = 12;
const TIME_WAIT_MS: u64 = 2_000;
const MS: u64 = 1_000_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
}

pub type Endpoint = (u32, u16);

pub struct Conn {
    pub state: State,
    pub local: Endpoint,
    pub remote: Endpoint,
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u32,
    rcv_nxt: u32,
    adv_wnd: u32,
    /// Bytes from `snd_una` on: sent but unacknowledged, then unsent.
    sndbuf: VecDeque<u8>,
    pub rcvbuf: VecDeque<u8>,
    /// The application shut down writing: send FIN after the data.
    fin_wanted: bool,
    fin_sent: bool,
    pub peer_fin: bool,
    pub rd_shut: bool,
    /// The error the next call reports (SO_ERROR).
    pub error: Option<Errno>,
    mss: u16,
    rto: u64,
    rtx_at: Option<u64>,
    retries: u32,
    time_wait_until: u64,
    // Listening sockets.
    backlog: VecDeque<Arc<Tcb>>,
    backlog_max: usize,
    parent: Weak<Tcb>,
    /// No socket refers to it any more (closed by the application).
    orphan: bool,
}

pub struct Tcb {
    pub c: SpinLock<Conn>,
    pub wait: WaitQueue,
}

type Key = (u32, u16, u32, u16);

static CONNS: SpinLock<BTreeMap<Key, Arc<Tcb>>> = SpinLock::new(BTreeMap::new());
static LISTENERS: SpinLock<Vec<Arc<Tcb>>> = SpinLock::new(Vec::new());
pub static GENERATION: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> u64 {
    crate::time::monotonic_ns() / MS
}

fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
fn le(a: u32, b: u32) -> bool {
    !lt(b, a)
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    crate::random::fill(&mut b);
    u32::from_le_bytes(b)
}

fn changed(t: &Tcb) {
    GENERATION.fetch_add(1, Ordering::Relaxed);
    t.wait.wake_all();
    crate::fs::poll_notify();
}

impl Conn {
    fn new(local: Endpoint, remote: Endpoint, state: State) -> Conn {
        let iss = random_u32();
        Conn {
            state,
            local,
            remote,
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 0,
            rcv_nxt: 0,
            adv_wnd: 0,
            sndbuf: VecDeque::new(),
            rcvbuf: VecDeque::new(),
            fin_wanted: false,
            fin_sent: false,
            peer_fin: false,
            rd_shut: false,
            error: None,
            mss: 536,
            rto: RTO_INITIAL,
            rtx_at: None,
            retries: 0,
            time_wait_until: 0,
            backlog: VecDeque::new(),
            backlog_max: 0,
            parent: Weak::new(),
            orphan: false,
        }
    }

    fn window(&self) -> u32 {
        (RCVBUF - self.rcvbuf.len().min(RCVBUF)).min(65535) as u32
    }

    /// Sends one segment.
    fn emit(&mut self, seq: u32, flags: u8, data: &[u8]) {
        let syn = flags & SYN != 0;
        let hlen = if syn { 24 } else { 20 };
        let mut s = Vec::with_capacity(hlen + data.len());
        s.extend_from_slice(&self.local.1.to_be_bytes());
        s.extend_from_slice(&self.remote.1.to_be_bytes());
        s.extend_from_slice(&seq.to_be_bytes());
        let ack = if flags & ACK != 0 { self.rcv_nxt } else { 0 };
        s.extend_from_slice(&ack.to_be_bytes());
        s.push(((hlen / 4) as u8) << 4);
        s.push(flags);
        let wnd = self.window();
        self.adv_wnd = wnd;
        s.extend_from_slice(&(wnd as u16).to_be_bytes());
        s.extend_from_slice(&[0, 0, 0, 0]);
        if syn {
            s.extend_from_slice(&[2, 4]);
            s.extend_from_slice(&OUR_MSS.to_be_bytes());
        }
        s.extend_from_slice(data);
        let c = ip::checksum(
            &s,
            ip::pseudo(self.local.0, self.remote.0, PROTO_TCP, s.len()),
        );
        s[16..18].copy_from_slice(&c.to_be_bytes());
        let _ = ip::output(self.local.0, self.remote.0, PROTO_TCP, &s);
    }

    fn send_ack(&mut self) {
        let seq = self.snd_nxt;
        self.emit(seq, ACK, &[]);
    }

    fn in_flight(&self) -> u32 {
        self.snd_nxt.wrapping_sub(self.snd_una)
    }

    fn arm(&mut self) {
        if self.rtx_at.is_none() {
            self.rtx_at = Some(now_ms() + self.rto);
        }
    }

    /// Sends what the window allows: data, then FIN when it is due.
    fn push(&mut self) {
        if !matches!(
            self.state,
            State::Established
                | State::CloseWait
                | State::FinWait1
                | State::LastAck
                | State::Closing
        ) {
            return;
        }
        loop {
            let sent = self.in_flight() as usize - (self.fin_sent as usize);
            let unsent = self.sndbuf.len().saturating_sub(sent);
            if unsent == 0 || self.fin_sent {
                break;
            }
            let room = (self.snd_wnd as usize).saturating_sub(sent);
            let n = unsent.min(room).min(self.mss as usize);
            if n == 0 {
                // Zero window: the retransmission timer probes.
                self.arm();
                break;
            }
            let data: Vec<u8> = self.sndbuf.range(sent..sent + n).copied().collect();
            let seq = self.snd_nxt;
            self.emit(seq, ACK | PSH, &data);
            self.snd_nxt = self.snd_nxt.wrapping_add(n as u32);
            self.arm();
        }
        let sent = self.in_flight() as usize - (self.fin_sent as usize);
        if self.fin_wanted && !self.fin_sent && sent == self.sndbuf.len() {
            let seq = self.snd_nxt;
            self.emit(seq, FIN | ACK, &[]);
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.fin_sent = true;
            self.state = match self.state {
                State::CloseWait => State::LastAck,
                State::Established => State::FinWait1,
                s => s,
            };
            self.arm();
        }
    }

    /// The retransmission timer fired: go back to the oldest unacked byte.
    fn retransmit(&mut self) {
        self.retries += 1;
        if self.retries > MAX_RETRIES || (self.state == State::SynSent && self.retries > 6) {
            self.error = Some(Errno::ETIMEDOUT);
            self.state = State::Closed;
            return;
        }
        self.rto = (self.rto * 2).min(RTO_MAX);
        self.rtx_at = None;
        match self.state {
            State::SynSent => {
                let iss = self.iss;
                self.emit(iss, SYN, &[]);
                self.arm();
            }
            State::SynRcvd => {
                let iss = self.iss;
                self.emit(iss, SYN | ACK, &[]);
                self.arm();
            }
            _ => {
                if self.in_flight() == 0 && !self.sndbuf.is_empty() {
                    // Window probe: one byte past the closed window.
                    let b = [self.sndbuf[0]];
                    let seq = self.snd_una;
                    self.emit(seq, ACK, &b);
                    self.snd_nxt = self.snd_una.wrapping_add(1);
                    self.arm();
                    return;
                }
                self.snd_nxt = self.snd_una;
                self.fin_sent = false;
                let wnd = self.snd_wnd.max(1);
                let saved = self.snd_wnd;
                self.snd_wnd = wnd;
                self.push();
                self.snd_wnd = saved;
            }
        }
    }
}

fn send_reset(src: Endpoint, dst: Endpoint, seq: u32, ack: Option<u32>) {
    let mut c = Conn::new(src, dst, State::Closed);
    match ack {
        Some(a) => {
            c.rcv_nxt = a;
            c.emit(seq, RST | ACK, &[]);
        }
        None => c.emit(seq, RST, &[]),
    }
}

fn remove(t: &Conn) {
    CONNS
        .lock()
        .remove(&(t.local.0, t.local.1, t.remote.0, t.remote.1));
}

/// Whether a connection on (local, remote) exists (for port choice).
pub fn in_use(local: Endpoint, remote: Endpoint) -> bool {
    CONNS
        .lock()
        .contains_key(&(local.0, local.1, remote.0, remote.1))
}

// ---- Application side ------------------------------------------------------

/// Starts connecting `local` to `remote` (sends the SYN).
pub fn connect(local: Endpoint, remote: Endpoint) -> KResult<Arc<Tcb>> {
    let key = (local.0, local.1, remote.0, remote.1);
    let t = Arc::new(Tcb {
        c: SpinLock::new(Conn::new(local, remote, State::SynSent)),
        wait: WaitQueue::new(),
    });
    {
        let mut conns = CONNS.lock();
        if conns.contains_key(&key) {
            return Err(Errno::EADDRINUSE);
        }
        conns.insert(key, t.clone());
    }
    let mut c = t.c.lock();
    let iss = c.iss;
    c.snd_nxt = iss.wrapping_add(1);
    c.emit(iss, SYN, &[]);
    c.arm();
    drop(c);
    Ok(t)
}

pub fn listen(local: Endpoint, backlog: usize) -> Arc<Tcb> {
    let mut c = Conn::new(local, (0, 0), State::Listen);
    c.backlog_max = backlog.max(1);
    let t = Arc::new(Tcb {
        c: SpinLock::new(c),
        wait: WaitQueue::new(),
    });
    LISTENERS.lock().push(t.clone());
    t
}

pub fn set_backlog(t: &Tcb, backlog: usize) {
    t.c.lock().backlog_max = backlog.max(1);
}

/// The next connection a listener accepted.
pub fn accept(t: &Tcb, nonblock: bool) -> KResult<Arc<Tcb>> {
    loop {
        if let Some(n) = t.c.lock().backlog.pop_front() {
            changed(t);
            return Ok(n);
        }
        if t.c.lock().state != State::Listen {
            return Err(Errno::EINVAL);
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        t.wait.wait_interruptible(|| {
            let c = t.c.lock();
            !c.backlog.is_empty() || c.state != State::Listen
        })?;
    }
}

/// Waits until a connection attempt has an outcome.
pub fn wait_connected(t: &Tcb) -> KResult<()> {
    t.wait
        .wait_interruptible(|| t.c.lock().state != State::SynSent)?;
    let mut c = t.c.lock();
    if let Some(e) = c.error.take() {
        return Err(e);
    }
    if c.state == State::Closed {
        return Err(Errno::ECONNREFUSED);
    }
    Ok(())
}

pub fn send(t: &Tcb, data: &[u8], nonblock: bool) -> KResult<usize> {
    if data.is_empty() {
        return Ok(0);
    }
    let mut done = 0;
    loop {
        {
            let mut c = t.c.lock();
            if let Some(e) = c.error.take() {
                return if done > 0 { Ok(done) } else { Err(e) };
            }
            match c.state {
                State::Established | State::CloseWait if !c.fin_wanted => {}
                State::SynSent | State::SynRcvd => {}
                _ => {
                    return if done > 0 {
                        Ok(done)
                    } else {
                        Err(Errno::EPIPE)
                    };
                }
            }
            let room = SNDBUF.saturating_sub(c.sndbuf.len());
            if room > 0 {
                let n = room.min(data.len() - done);
                c.sndbuf.extend(&data[done..done + n]);
                done += n;
                c.push();
                if done == data.len() {
                    return Ok(done);
                }
            }
        }
        if nonblock {
            return if done > 0 {
                Ok(done)
            } else {
                Err(Errno::EAGAIN)
            };
        }
        let r = t.wait.wait_interruptible(|| {
            let c = t.c.lock();
            c.sndbuf.len() < SNDBUF
                || c.error.is_some()
                || !matches!(
                    c.state,
                    State::Established | State::CloseWait | State::SynSent | State::SynRcvd
                )
        });
        if let Err(e) = r {
            return if done > 0 { Ok(done) } else { Err(e) };
        }
    }
}

/// Reads into `buf`. Ok(0) at end of stream.
pub fn recv(t: &Tcb, buf: &mut [u8], peek: bool, waitall: bool, nonblock: bool) -> KResult<usize> {
    let mut done = 0;
    loop {
        {
            let mut c = t.c.lock();
            let n = c.rcvbuf.len().min(buf.len() - done);
            if n > 0 {
                for (i, b) in c.rcvbuf.iter().take(n).enumerate() {
                    buf[done + i] = *b;
                }
                if !peek {
                    c.rcvbuf.drain(..n);
                    // Tell the peer when the window opened up again.
                    let w = c.window();
                    if w >= c.adv_wnd + 2 * c.mss as u32
                        || (c.adv_wnd < c.mss as u32 && w >= c.mss as u32)
                    {
                        c.send_ack();
                    }
                }
                done += n;
                if done == buf.len() || !waitall || peek {
                    return Ok(done);
                }
            }
            if c.peer_fin || c.rd_shut {
                return Ok(done);
            }
            if let Some(e) = c.error.take() {
                return if done > 0 { Ok(done) } else { Err(e) };
            }
            if matches!(c.state, State::Closed | State::Listen) {
                return Ok(done);
            }
            if c.state == State::SynSent && nonblock {
                return Err(Errno::EAGAIN);
            }
        }
        if nonblock {
            return if done > 0 {
                Ok(done)
            } else {
                Err(Errno::EAGAIN)
            };
        }
        let r = t.wait.wait_interruptible(|| {
            let c = t.c.lock();
            !c.rcvbuf.is_empty()
                || c.peer_fin
                || c.rd_shut
                || c.error.is_some()
                || c.state == State::Closed
        });
        if let Err(e) = r {
            return if done > 0 { Ok(done) } else { Err(e) };
        }
    }
}

/// SHUT_WR: FIN after the data.
pub fn shutdown_write(t: &Tcb) {
    let mut c = t.c.lock();
    match c.state {
        State::SynSent => {
            c.state = State::Closed;
            remove(&c);
        }
        State::Established | State::CloseWait | State::SynRcvd => {
            c.fin_wanted = true;
            c.push();
        }
        _ => {}
    }
    drop(c);
    changed(t);
}

pub fn shutdown_read(t: &Tcb) {
    let mut c = t.c.lock();
    c.rd_shut = true;
    c.rcvbuf.clear();
    drop(c);
    changed(t);
}

/// The application closed its last descriptor.
pub fn close(t: &Arc<Tcb>) {
    let mut c = t.c.lock();
    c.orphan = true;
    match c.state {
        State::Listen => {
            c.state = State::Closed;
            let pending: Vec<Arc<Tcb>> = c.backlog.drain(..).collect();
            drop(c);
            LISTENERS.lock().retain(|l| !Arc::ptr_eq(l, t));
            for p in pending {
                abort(&p);
            }
            changed(t);
            return;
        }
        State::SynSent | State::Closed => {
            c.state = State::Closed;
            remove(&c);
        }
        _ if !c.rcvbuf.is_empty() => {
            // Unread data: reset, as Linux does.
            drop(c);
            abort(t);
            return;
        }
        State::Established | State::CloseWait | State::SynRcvd => {
            c.fin_wanted = true;
            c.push();
        }
        _ => {}
    }
    drop(c);
    changed(t);
}

/// Resets the connection.
pub fn abort(t: &Tcb) {
    let mut c = t.c.lock();
    if !matches!(
        c.state,
        State::Closed | State::Listen | State::SynSent | State::TimeWait
    ) {
        let seq = c.snd_nxt;
        c.emit(seq, RST | ACK, &[]);
    }
    c.state = State::Closed;
    c.orphan = true;
    remove(&c);
    drop(c);
    changed(t);
}

pub fn poll(t: &Tcb) -> u16 {
    use crate::fs::poll::*;
    const POLLRDHUP: u16 = 0x2000;
    let c = t.c.lock();
    let mut r = 0;
    match c.state {
        State::Listen => {
            if !c.backlog.is_empty() {
                r |= POLLIN;
            }
        }
        State::SynSent | State::SynRcvd => {}
        _ => {
            if !c.rcvbuf.is_empty() || c.peer_fin || c.rd_shut {
                r |= POLLIN;
            }
            if c.peer_fin {
                r |= POLLRDHUP;
            }
            let writable =
                matches!(c.state, State::Established | State::CloseWait) && !c.fin_wanted;
            if writable && c.sndbuf.len() < SNDBUF {
                r |= POLLOUT;
            }
            if c.state == State::Closed || (c.peer_fin && c.fin_wanted) {
                r |= POLLHUP;
                if c.state == State::Closed {
                    r |= POLLIN | POLLOUT;
                }
            }
        }
    }
    if c.error.is_some() {
        r |= POLLERR;
    }
    r
}

pub fn info(t: &Tcb) -> (State, usize, usize) {
    let c = t.c.lock();
    (c.state, c.rcvbuf.len(), c.sndbuf.len())
}

// ---- Network side ------------------------------------------------------------

struct Seg<'a> {
    seq: u32,
    ack: u32,
    flags: u8,
    wnd: u32,
    mss: Option<u16>,
    data: &'a [u8],
}

fn parse(body: &[u8]) -> Option<(u16, u16, Seg<'_>)> {
    if body.len() < 20 {
        return None;
    }
    let off = (body[12] >> 4) as usize * 4;
    if off < 20 || off > body.len() {
        return None;
    }
    let mut mss = None;
    let mut i = 20;
    while i < off {
        match body[i] {
            0 => break,
            1 => i += 1,
            k => {
                let l = *body.get(i + 1)? as usize;
                if l < 2 {
                    break;
                }
                if k == 2 && l == 4 && i + 4 <= off {
                    mss = Some(u16::from_be_bytes([body[i + 2], body[i + 3]]));
                }
                i += l;
            }
        }
    }
    Some((
        u16::from_be_bytes([body[0], body[1]]),
        u16::from_be_bytes([body[2], body[3]]),
        Seg {
            seq: u32::from_be_bytes(body[4..8].try_into().unwrap()),
            ack: u32::from_be_bytes(body[8..12].try_into().unwrap()),
            flags: body[13],
            wnd: u16::from_be_bytes([body[14], body[15]]) as u32,
            mss,
            data: &body[off..],
        },
    ))
}

/// A TCP segment for this machine.
pub fn input(src: u32, dst: u32, body: &[u8]) {
    if ip::checksum(body, ip::pseudo(src, dst, PROTO_TCP, body.len())) != 0 {
        return;
    }
    let Some((sport, dport, seg)) = parse(body) else {
        return;
    };
    let conn = CONNS.lock().get(&(dst, dport, src, sport)).cloned();
    if let Some(t) = conn {
        arrives(&t, &seg);
        return;
    }
    let listener = LISTENERS
        .lock()
        .iter()
        .find(|l| {
            let c = l.c.lock();
            c.local.1 == dport && (c.local.0 == 0 || c.local.0 == dst)
        })
        .cloned();
    if let Some(l) = listener
        && seg.flags & (SYN | ACK | RST) == SYN
    {
        let lc = l.c.lock();
        let queued = lc.backlog.len();
        if queued >= lc.backlog_max {
            return;
        }
        let mut c = Conn::new((dst, dport), (src, sport), State::SynRcvd);
        c.rcv_nxt = seg.seq.wrapping_add(1);
        c.snd_wnd = seg.wnd;
        c.mss = seg.mss.unwrap_or(536).min(OUR_MSS);
        c.parent = Arc::downgrade(&l);
        let iss = c.iss;
        c.snd_nxt = iss.wrapping_add(1);
        c.emit(iss, SYN | ACK, &[]);
        c.arm();
        drop(lc);
        let t = Arc::new(Tcb {
            c: SpinLock::new(c),
            wait: WaitQueue::new(),
        });
        CONNS.lock().insert((dst, dport, src, sport), t);
        return;
    }
    if seg.flags & RST != 0 {
        return;
    }
    // Nobody here: reset.
    if seg.flags & ACK != 0 {
        send_reset((dst, dport), (src, sport), seg.ack, None);
    } else {
        let len =
            seg.data.len() as u32 + (seg.flags & SYN != 0) as u32 + (seg.flags & FIN != 0) as u32;
        send_reset(
            (dst, dport),
            (src, sport),
            0,
            Some(seg.seq.wrapping_add(len)),
        );
    }
}

fn arrives(t: &Arc<Tcb>, seg: &Seg) {
    let mut c = t.c.lock();
    let mut notify = false;
    let mut established_child = false;
    if c.state == State::SynSent {
        if seg.flags & ACK != 0 && seg.ack != c.iss.wrapping_add(1) {
            if seg.flags & RST == 0 {
                let local = c.local;
                let remote = c.remote;
                drop(c);
                send_reset(local, remote, seg.ack, None);
            }
            return;
        }
        if seg.flags & RST != 0 {
            if seg.flags & ACK != 0 {
                c.error = Some(Errno::ECONNREFUSED);
                c.state = State::Closed;
                remove(&c);
                drop(c);
                changed(t);
            }
            return;
        }
        if seg.flags & SYN != 0 {
            c.rcv_nxt = seg.seq.wrapping_add(1);
            c.mss = seg.mss.unwrap_or(536).min(OUR_MSS);
            c.snd_wnd = seg.wnd;
            if seg.flags & ACK != 0 {
                c.snd_una = seg.ack;
                c.state = State::Established;
                c.rtx_at = None;
                c.retries = 0;
                c.rto = RTO_INITIAL;
                c.send_ack();
                c.push();
            } else {
                c.state = State::SynRcvd;
                let iss = c.iss;
                c.emit(iss, SYN | ACK, &[]);
            }
            drop(c);
            changed(t);
        }
        return;
    }
    if c.state == State::Closed {
        return;
    }

    // Is the segment within the receive window?
    let mut data = seg.data;
    let mut seq = seg.seq;
    if lt(seq, c.rcv_nxt) {
        let old = c.rcv_nxt.wrapping_sub(seq) as usize;
        if old >= data.len() + (seg.flags & FIN != 0) as usize && seg.flags & RST == 0 {
            if !data.is_empty() || seg.flags & (FIN | SYN) != 0 {
                c.send_ack(); // a duplicate: re-acknowledge
            }
            if seg.flags & ACK == 0 {
                return;
            }
            data = &[];
            seq = c.rcv_nxt;
        } else {
            data = &data[old.min(data.len())..];
            seq = c.rcv_nxt;
        }
    }
    if seq != c.rcv_nxt && (!data.is_empty() || seg.flags & FIN != 0) {
        c.send_ack(); // out of order: dropped; the duplicate ACK asks again
        return;
    }
    if seg.flags & RST != 0 {
        if seq == c.rcv_nxt || seg.seq == c.rcv_nxt {
            if !matches!(c.state, State::TimeWait | State::LastAck | State::Closing) && !c.orphan {
                c.error = Some(if c.state == State::SynRcvd {
                    Errno::ECONNREFUSED
                } else {
                    Errno::ECONNRESET
                });
            }
            c.state = State::Closed;
            remove(&c);
            drop(c);
            changed(t);
        }
        return;
    }
    if seg.flags & SYN != 0 {
        c.send_ack();
        return;
    }
    if seg.flags & ACK == 0 {
        return;
    }

    // Acknowledgements.
    if c.state == State::SynRcvd {
        if lt(c.snd_una, seg.ack) && le(seg.ack, c.snd_nxt) {
            c.snd_una = seg.ack;
            c.state = State::Established;
            c.rtx_at = None;
            c.retries = 0;
            c.snd_wnd = seg.wnd;
            established_child = true;
        } else {
            let (l, r) = (c.local, c.remote);
            drop(c);
            send_reset(l, r, seg.ack, None);
            return;
        }
    } else if lt(c.snd_una, seg.ack) && le(seg.ack, c.snd_nxt) {
        let acked = seg.ack.wrapping_sub(c.snd_una) as usize;
        let fin_acked = c.fin_sent && seg.ack == c.snd_nxt;
        let bytes = acked - fin_acked as usize;
        let n = bytes.min(c.sndbuf.len());
        c.sndbuf.drain(..n);
        c.snd_una = seg.ack;
        c.retries = 0;
        c.rto = RTO_INITIAL;
        c.rtx_at = None;
        if c.in_flight() > 0 {
            c.arm();
        }
        notify = true;
        if fin_acked {
            match c.state {
                State::FinWait1 => c.state = State::FinWait2,
                State::Closing => {
                    c.state = State::TimeWait;
                    c.time_wait_until = now_ms() + TIME_WAIT_MS;
                }
                State::LastAck => {
                    c.state = State::Closed;
                    remove(&c);
                    drop(c);
                    changed(t);
                    return;
                }
                _ => {}
            }
        }
    } else if lt(c.snd_nxt, seg.ack) {
        c.send_ack();
        return;
    }
    if le(c.snd_una, seg.ack) {
        if seg.wnd > c.snd_wnd {
            notify = true;
        }
        c.snd_wnd = seg.wnd;
    }

    // Data.
    let mut need_ack = false;
    if !data.is_empty() {
        if matches!(
            c.state,
            State::Established | State::FinWait1 | State::FinWait2
        ) {
            let room = RCVBUF.saturating_sub(c.rcvbuf.len());
            let take = if c.rd_shut {
                data.len()
            } else {
                data.len().min(room)
            };
            if !c.rd_shut {
                c.rcvbuf.extend(&data[..take]);
            }
            c.rcv_nxt = c.rcv_nxt.wrapping_add(take as u32);
            if take < data.len() {
                // Did not fit: the rest (and any FIN) comes again.
                c.send_ack();
                drop(c);
                changed(t);
                return;
            }
            notify = true;
        }
        need_ack = true;
    }
    if seg.flags & FIN != 0
        && matches!(
            c.state,
            State::Established | State::FinWait1 | State::FinWait2 | State::SynRcvd
        )
    {
        c.rcv_nxt = c.rcv_nxt.wrapping_add(1);
        c.peer_fin = true;
        notify = true;
        need_ack = true;
        c.state = match c.state {
            State::Established | State::SynRcvd => State::CloseWait,
            State::FinWait1 if c.snd_una == c.snd_nxt => State::TimeWait,
            State::FinWait1 => State::Closing,
            State::FinWait2 => State::TimeWait,
            s => s,
        };
        if c.state == State::TimeWait {
            c.time_wait_until = now_ms() + TIME_WAIT_MS;
            c.rtx_at = None;
        }
    } else if seg.flags & FIN != 0 && c.state == State::TimeWait {
        need_ack = true;
    }
    if need_ack {
        c.send_ack();
    }
    c.push();
    let parent = c.parent.upgrade();
    drop(c);
    if established_child {
        match parent {
            Some(p) if p.c.lock().state == State::Listen => {
                p.c.lock().backlog.push_back(t.clone());
                changed(&p);
            }
            _ => abort(t),
        }
    }
    if notify || established_child {
        changed(t);
    }
}

/// Timers: retransmission, TIME_WAIT expiry, orphans' cleanup.
pub fn tick(now_ns: u64) {
    let now = now_ns / MS;
    let all: Vec<Arc<Tcb>> = CONNS.lock().values().cloned().collect();
    for t in all {
        let mut c = t.c.lock();
        let mut wake = false;
        if c.state == State::TimeWait && now >= c.time_wait_until {
            c.state = State::Closed;
            remove(&c);
            wake = true;
        } else if let Some(at) = c.rtx_at
            && now >= at
        {
            c.retransmit();
            if c.state == State::Closed {
                remove(&c);
                wake = true;
            }
        } else if c.orphan && c.state == State::FinWait2 && c.time_wait_until == 0 {
            // An orphan waiting for the peer's FIN gives up after a while.
            c.time_wait_until = now + 60_000;
            c.state = State::TimeWait;
        }
        drop(c);
        if wake {
            changed(&t);
        }
    }
}

/// `/proc/net/tcp`.
pub fn proc_tcp() -> alloc::string::String {
    use alloc::format;
    let mut s = alloc::string::String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
    );
    let st = |x: State| match x {
        State::Established => 1,
        State::SynSent => 2,
        State::SynRcvd => 3,
        State::FinWait1 => 4,
        State::FinWait2 => 5,
        State::TimeWait => 6,
        State::Closed => 7,
        State::CloseWait => 8,
        State::LastAck => 9,
        State::Listen => 10,
        State::Closing => 11,
    };
    let mut list: Vec<Arc<Tcb>> = LISTENERS.lock().clone();
    list.extend(CONNS.lock().values().cloned());
    for (i, t) in list.iter().enumerate() {
        let c = t.c.lock();
        s.push_str(&format!(
            "{:4}: {:08X}:{:04X} {:08X}:{:04X} {:02X} {:08X}:{:08X} 00:00000000 00000000     0        0 0\n",
            i,
            c.local.0.swap_bytes(),
            c.local.1,
            c.remote.0.swap_bytes(),
            c.remote.1,
            st(c.state),
            c.sndbuf.len(),
            c.rcvbuf.len()
        ));
    }
    s
}

/// The listener on `port` (for bind conflicts).
pub fn listening_on(port: u16) -> bool {
    LISTENERS.lock().iter().any(|l| l.c.lock().local.1 == port)
}
