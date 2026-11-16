//! Network interfaces, Ethernet, ARP, routing, and the network thread.
//!
//! Interfaces are `lo` (loopback, 127.0.0.1/8) and one `ethN` per network
//! card. Outgoing IPv4 packets go through [`send_ip`]: the route picks the
//! interface and next hop, ARP finds the next hop's Ethernet address
//! (queueing the packet until the answer comes), and the card sends the
//! frame. Packets for this machine itself go through the loopback queue.
//!
//! The network thread takes frames from the cards and the loopback queue
//! and hands them to IPv4 (`ip.rs`), and runs the timers (TCP
//! retransmission, ARP retries, DHCP). It sleeps on the card's receive
//! interrupt; every wait also ends after 10 ms for the timers.

use super::ip;
use crate::abi::{Errno, KResult};
use crate::drivers::msi::Irq;
use crate::sync::{Once, SpinLock};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// A network card.
pub trait NetDevice: Send + Sync {
    fn mac(&self) -> [u8; 6];
    /// Sends one Ethernet frame (without the FCS).
    fn send(&self, frame: &[u8]);
    /// The next received frame, if any.
    fn recv(&self) -> Option<Vec<u8>>;
    fn rx_pending(&self) -> bool;
    /// The receive interrupt, if the card has one.
    fn irq(&self) -> Option<&'static Irq>;
    fn name(&self) -> &str;
}

pub const ETH_IP: u16 = 0x0800;
pub const ETH_ARP: u16 = 0x0806;
pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];
pub const LOOPBACK_IP: u32 = 0x7f00_0001;

pub struct Iface {
    pub index: u32,
    pub name: String,
    pub mac: [u8; 6],
    pub dev: Option<Arc<dyn NetDevice>>,
    /// (address, prefix length).
    pub addr: SpinLock<Option<(u32, u8)>>,
    pub gateway: SpinLock<Option<u32>>,
    pub dns: SpinLock<Vec<u32>>,
    pub up: AtomicBool,
    pub rx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub mtu: u32,
}

impl Iface {
    pub fn is_loopback(&self) -> bool {
        self.dev.is_none()
    }

    pub fn ip(&self) -> Option<u32> {
        self.addr.lock().map(|(a, _)| a)
    }

    fn count_tx(&self, n: usize) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
}

static IFACES: SpinLock<Vec<Arc<Iface>>> = SpinLock::new(Vec::new());
/// What wakes the network thread: the first card's interrupt, or a
/// software one.
static WAKE: Once<&'static Irq> = Once::new();
/// IPv4 packets sent to this machine itself.
static LOOPBACK: SpinLock<VecDeque<Vec<u8>>> = SpinLock::new(VecDeque::new());

pub fn all() -> Vec<Arc<Iface>> {
    IFACES.lock().clone()
}

pub fn by_index(i: u32) -> Option<Arc<Iface>> {
    IFACES.lock().iter().find(|f| f.index == i).cloned()
}

pub fn by_name(n: &str) -> Option<Arc<Iface>> {
    IFACES.lock().iter().find(|f| f.name == n).cloned()
}

fn new_iface(name: String, dev: Option<Arc<dyn NetDevice>>) -> Arc<Iface> {
    let mut list = IFACES.lock();
    let f = Arc::new(Iface {
        index: list.len() as u32 + 1,
        name,
        mac: dev.as_ref().map_or([0; 6], |d| d.mac()),
        dev,
        addr: SpinLock::new(None),
        gateway: SpinLock::new(None),
        dns: SpinLock::new(Vec::new()),
        up: AtomicBool::new(false),
        rx_packets: AtomicU64::new(0),
        rx_bytes: AtomicU64::new(0),
        tx_packets: AtomicU64::new(0),
        tx_bytes: AtomicU64::new(0),
        mtu: 1500,
    });
    list.push(f.clone());
    f
}

/// `lo`, interface 1 as on Linux.
fn ensure_lo() {
    if by_name("lo").is_none() {
        let lo = new_iface("lo".into(), None);
        *lo.addr.lock() = Some((LOOPBACK_IP, 8));
        lo.up.store(true, Ordering::Relaxed);
    }
}

/// A network card found by a driver: interface `ethN`.
pub fn add_ethernet(dev: Arc<dyn NetDevice>) {
    ensure_lo();
    let n = IFACES.lock().iter().filter(|f| !f.is_loopback()).count();
    let mac = dev.mac();
    if let Some(irq) = dev.irq() {
        WAKE.call_once(|| irq);
    }
    let f = new_iface(format!("eth{n}"), Some(dev.clone()));
    f.up.store(true, Ordering::Relaxed);
    crate::info!(
        "net: {} ({}), {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        f.name,
        dev.name(),
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
}

pub fn wake() {
    if let Some(w) = WAKE.get() {
        w.notify();
    }
}

pub fn fmt_ip(a: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        a >> 24,
        (a >> 16) & 0xff,
        (a >> 8) & 0xff,
        a & 0xff
    )
}

pub fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix as u32)
    }
}

/// Whether `a` is one of this machine's addresses.
pub fn is_local(a: u32) -> bool {
    a >> 24 == 127 || IFACES.lock().iter().any(|f| f.ip() == Some(a))
}

/// Where a packet to `dst` goes: (interface, next hop, source address).
pub fn route(dst: u32) -> KResult<(Arc<Iface>, u32, u32)> {
    let list = all();
    let lo = list
        .iter()
        .find(|f| f.is_loopback())
        .cloned()
        .ok_or(Errno::ENETUNREACH)?;
    if dst >> 24 == 127 {
        return Ok((lo, dst, LOOPBACK_IP));
    }
    let eths = list
        .iter()
        .filter(|f| !f.is_loopback() && f.up.load(Ordering::Relaxed));
    let mut default = None;
    for f in eths {
        let Some((ip, prefix)) = *f.addr.lock() else {
            if dst == u32::MAX && default.is_none() {
                default = Some((f.clone(), dst, 0));
            }
            continue;
        };
        if dst == ip {
            return Ok((lo, dst, ip));
        }
        let m = mask(prefix);
        if dst == u32::MAX || dst & m == ip & m {
            return Ok((f.clone(), dst, ip));
        }
        if let Some(gw) = *f.gateway.lock()
            && default.is_none()
        {
            default = Some((f.clone(), gw, ip));
        }
    }
    default.ok_or(Errno::ENETUNREACH)
}

// ---- ARP ----------------------------------------------------------------

struct Pending {
    iface: u32,
    next_hop: u32,
    packet: Vec<u8>,
    since: u64,
    tries: u32,
}

static ARP: SpinLock<BTreeMap<u32, [u8; 6]>> = SpinLock::new(BTreeMap::new());
static WAITING: SpinLock<Vec<Pending>> = SpinLock::new(Vec::new());

fn eth_send(f: &Iface, dst: [u8; 6], ty: u16, payload: &[u8]) {
    let Some(dev) = &f.dev else { return };
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&f.mac);
    frame.extend_from_slice(&ty.to_be_bytes());
    frame.extend_from_slice(payload);
    if frame.len() < 60 {
        frame.resize(60, 0);
    }
    f.count_tx(frame.len());
    dev.send(&frame);
}

fn arp_packet(f: &Iface, op: u16, target_mac: [u8; 6], target_ip: u32) -> Vec<u8> {
    let mut p = Vec::with_capacity(28);
    p.extend_from_slice(&1u16.to_be_bytes()); // Ethernet
    p.extend_from_slice(&ETH_IP.to_be_bytes());
    p.extend_from_slice(&[6, 4]);
    p.extend_from_slice(&op.to_be_bytes());
    p.extend_from_slice(&f.mac);
    p.extend_from_slice(&f.ip().unwrap_or(0).to_be_bytes());
    p.extend_from_slice(&target_mac);
    p.extend_from_slice(&target_ip.to_be_bytes());
    p
}

fn arp_request(f: &Iface, ip: u32) {
    let p = arp_packet(f, 1, [0; 6], ip);
    eth_send(f, BROADCAST_MAC, ETH_ARP, &p);
}

fn arp_input(f: &Arc<Iface>, p: &[u8]) {
    if p.len() < 28 || p[0..2] != [0, 1] || p[2..4] != ETH_IP.to_be_bytes() {
        return;
    }
    let op = u16::from_be_bytes([p[6], p[7]]);
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&p[8..14]);
    let sender_ip = u32::from_be_bytes(p[14..18].try_into().unwrap());
    let target_ip = u32::from_be_bytes(p[24..28].try_into().unwrap());
    if sender_ip != 0 {
        ARP.lock().insert(sender_ip, sender_mac);
        flush_waiting(sender_ip, sender_mac);
    }
    if op == 1 && f.ip() == Some(target_ip) {
        let reply = arp_packet(f, 2, sender_mac, sender_ip);
        eth_send(f, sender_mac, ETH_ARP, &reply);
    }
}

fn flush_waiting(ip: u32, mac: [u8; 6]) {
    let ready: Vec<Pending> = {
        let mut w = WAITING.lock();
        let (ready, rest) = core::mem::take(&mut *w)
            .into_iter()
            .partition(|p| p.next_hop == ip);
        *w = rest;
        ready
    };
    for p in ready {
        if let Some(f) = by_index(p.iface) {
            eth_send(&f, mac, ETH_IP, &p.packet);
        }
    }
}

fn arp_tick(now: u64) {
    let mut retry = Vec::new();
    WAITING.lock().retain_mut(|p| {
        if now.saturating_sub(p.since) < 1_000_000_000 {
            return true;
        }
        p.tries += 1;
        p.since = now;
        retry.push((p.iface, p.next_hop));
        p.tries < 3
    });
    for (i, ip) in retry {
        if let Some(f) = by_index(i) {
            arp_request(&f, ip);
        }
    }
}

/// Sends a complete IPv4 packet to `dst`.
pub fn send_ip(dst: u32, packet: Vec<u8>) -> KResult<()> {
    let (f, next_hop, _) = route(dst)?;
    if f.is_loopback() {
        f.count_tx(packet.len());
        f.rx_packets.fetch_add(1, Ordering::Relaxed);
        f.rx_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
        LOOPBACK.lock().push_back(packet);
        wake();
        return Ok(());
    }
    let broadcast = next_hop == u32::MAX
        || f.addr
            .lock()
            .is_some_and(|(ip, p)| p < 31 && next_hop == ip | !mask(p));
    if broadcast {
        eth_send(&f, BROADCAST_MAC, ETH_IP, &packet);
        return Ok(());
    }
    let known = ARP.lock().get(&next_hop).copied();
    match known {
        Some(mac) => eth_send(&f, mac, ETH_IP, &packet),
        None => {
            let first = !WAITING.lock().iter().any(|p| p.next_hop == next_hop);
            let mut w = WAITING.lock();
            if w.len() < 256 {
                w.push(Pending {
                    iface: f.index,
                    next_hop,
                    packet,
                    since: crate::time::monotonic_ns(),
                    tries: 0,
                });
            }
            drop(w);
            if first {
                arp_request(&f, next_hop);
            }
        }
    }
    Ok(())
}

/// Sends a raw Ethernet broadcast (DHCP before the interface has an address).
pub fn send_broadcast(f: &Iface, packet: &[u8]) {
    eth_send(f, BROADCAST_MAC, ETH_IP, packet);
}

fn eth_input(f: &Arc<Iface>, frame: &[u8]) {
    if frame.len() < 14 {
        return;
    }
    f.rx_packets.fetch_add(1, Ordering::Relaxed);
    f.rx_bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
    let dst = &frame[0..6];
    if dst != f.mac && dst != BROADCAST_MAC && dst[0] & 1 == 0 {
        return;
    }
    match u16::from_be_bytes([frame[12], frame[13]]) {
        ETH_ARP => arp_input(f, &frame[14..]),
        ETH_IP => ip::input(f, &frame[14..]),
        _ => {}
    }
}

// ---- The network thread -------------------------------------------------

static STARTED: AtomicBool = AtomicBool::new(false);

/// Creates `lo` and starts the network thread (after the drivers ran).
pub fn init() {
    ensure_lo();
    WAKE.call_once(|| crate::drivers::msi::soft().expect("no interrupt vectors left"));
    if STARTED.swap(true, Ordering::Relaxed) {
        return;
    }
    let dhcp = true;
    for f in all().into_iter().filter(|f| !f.is_loopback()) {
        if dhcp {
            super::dhcp::start(&f);
        }
    }
    crate::task::spawn_named("net", run);
}

fn run() {
    let wake = *WAKE.get().unwrap();
    loop {
        let mut work = true;
        while work {
            work = false;
            for f in all() {
                if let Some(dev) = &f.dev {
                    for _ in 0..64 {
                        let Some(frame) = dev.recv() else { break };
                        eth_input(&f, &frame);
                        work = true;
                    }
                }
            }
            for _ in 0..64 {
                let Some(p) = LOOPBACK.lock().pop_front() else {
                    break;
                };
                if let Some(lo) = by_name("lo") {
                    ip::input(&lo, &p);
                }
                work = true;
            }
        }
        let now = crate::time::monotonic_ns();
        arp_tick(now);
        super::tcp::tick(now);
        super::dhcp::tick(now);
        wake.wait(
            || {
                !LOOPBACK.lock().is_empty()
                    || all()
                        .iter()
                        .any(|f| f.dev.as_ref().is_some_and(|d| d.rx_pending()))
            },
            10,
        );
    }
}

// ---- Interface ioctls (SIOCGIF*) and /proc/net ----------------------------

const SIOCGIFNAME: u32 = 0x8910;
const SIOCGIFCONF: u32 = 0x8912;
const SIOCGIFFLAGS: u32 = 0x8913;
const SIOCSIFFLAGS: u32 = 0x8914;
const SIOCGIFADDR: u32 = 0x8915;
const SIOCGIFBRDADDR: u32 = 0x8919;
const SIOCGIFNETMASK: u32 = 0x891b;
const SIOCGIFMTU: u32 = 0x8921;
const SIOCGIFHWADDR: u32 = 0x8927;
const SIOCGIFINDEX: u32 = 0x8933;
const SIOCGIFTXQLEN: u32 = 0x8942;

pub const IFF_UP: u32 = 0x1;
pub const IFF_BROADCAST: u32 = 0x2;
pub const IFF_LOOPBACK: u32 = 0x8;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_MULTICAST: u32 = 0x1000;
pub const IFF_LOWER_UP: u32 = 0x10000;

pub fn flags(f: &Iface) -> u32 {
    let up = if f.up.load(Ordering::Relaxed) {
        IFF_UP | IFF_RUNNING | IFF_LOWER_UP
    } else {
        0
    };
    up | if f.is_loopback() {
        IFF_LOOPBACK
    } else {
        IFF_BROADCAST | IFF_MULTICAST
    }
}

pub fn sockaddr_in(ip: u32, port: u16) -> Vec<u8> {
    let mut a = alloc::vec![0u8; 16];
    a[0..2].copy_from_slice(&2u16.to_le_bytes());
    a[2..4].copy_from_slice(&port.to_be_bytes());
    a[4..8].copy_from_slice(&ip.to_be_bytes());
    a
}

/// ioctls on any AF_INET socket that ask about interfaces.
pub fn ioctl(req: u32, arg: u64, mm: &crate::mm::vm::AddressSpace) -> KResult<u64> {
    if req == SIOCGIFCONF {
        let len: i32 = mm.read(arg)?;
        let buf: u64 = mm.read(arg + 8)?;
        let mut out = Vec::new();
        for f in all() {
            let Some(ip) = f.ip() else { continue };
            let mut r = [0u8; 40];
            let n = f.name.len().min(15);
            r[..n].copy_from_slice(&f.name.as_bytes()[..n]);
            r[16..32].copy_from_slice(&sockaddr_in(ip, 0));
            out.extend_from_slice(&r);
        }
        let n = if buf == 0 {
            out.len()
        } else {
            out.len().min(len.max(0) as usize / 40 * 40)
        };
        if buf != 0 {
            mm.copy_to(buf, &out[..n])?;
        }
        mm.write(arg, &(n as i32))?;
        return Ok(0);
    }
    let mut r = [0u8; 40];
    mm.copy_from(arg, &mut r)?;
    let f = if req == SIOCGIFNAME {
        let idx = u32::from_le_bytes(r[16..20].try_into().unwrap());
        by_index(idx).ok_or(Errno::ENODEV)?
    } else {
        let end = r[..16].iter().position(|&b| b == 0).unwrap_or(16);
        let name = core::str::from_utf8(&r[..end]).map_err(|_| Errno::ENODEV)?;
        by_name(name).ok_or(Errno::ENODEV)?
    };
    let addr = *f.addr.lock();
    match req {
        SIOCGIFNAME => {
            r[..16].fill(0);
            r[..f.name.len()].copy_from_slice(f.name.as_bytes());
        }
        SIOCGIFFLAGS => r[16..18].copy_from_slice(&(flags(&f) as u16).to_le_bytes()),
        SIOCSIFFLAGS => {
            let fl = u16::from_le_bytes([r[16], r[17]]) as u32;
            f.up.store(fl & IFF_UP != 0, Ordering::Relaxed);
            return Ok(0);
        }
        SIOCGIFADDR | SIOCGIFNETMASK | SIOCGIFBRDADDR => {
            let (ip, p) = addr.ok_or(Errno::EADDRNOTAVAIL)?;
            let v = match req {
                SIOCGIFADDR => ip,
                SIOCGIFNETMASK => mask(p),
                _ => ip | !mask(p),
            };
            r[16..32].copy_from_slice(&sockaddr_in(v, 0));
        }
        SIOCGIFMTU => r[16..20].copy_from_slice(&(f.mtu as i32).to_le_bytes()),
        SIOCGIFHWADDR => {
            let ty: u16 = if f.is_loopback() { 772 } else { 1 };
            r[16..18].copy_from_slice(&ty.to_le_bytes());
            r[18..24].copy_from_slice(&f.mac);
        }
        SIOCGIFINDEX => r[16..20].copy_from_slice(&f.index.to_le_bytes()),
        SIOCGIFTXQLEN => r[16..20].copy_from_slice(&1000i32.to_le_bytes()),
        _ => return Err(Errno::ENOTTY),
    }
    mm.copy_to(arg, &r)?;
    Ok(0)
}

/// `/proc/net/dev`.
pub fn proc_dev() -> String {
    let mut s = String::from(
        "Inter-|   Receive                                                |  Transmit\n \
         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
    );
    for f in all() {
        s.push_str(&format!(
            "{:>6}: {:>7} {:>7}    0    0    0     0          0         0 {:>8} {:>7}    0    0    0     0       0          0\n",
            f.name,
            f.rx_bytes.load(Ordering::Relaxed),
            f.rx_packets.load(Ordering::Relaxed),
            f.tx_bytes.load(Ordering::Relaxed),
            f.tx_packets.load(Ordering::Relaxed)
        ));
    }
    s
}

/// `/proc/net/route` (addresses in the kernel's byte order, as Linux).
pub fn proc_route() -> String {
    let mut s = String::from(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
    );
    for f in all().into_iter().filter(|f| !f.is_loopback()) {
        let Some((ip, p)) = *f.addr.lock() else {
            continue;
        };
        if let Some(gw) = *f.gateway.lock() {
            s.push_str(&format!(
                "{}\t00000000\t{:08X}\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
                f.name,
                gw.swap_bytes()
            ));
        }
        s.push_str(&format!(
            "{}\t{:08X}\t00000000\t0001\t0\t0\t0\t{:08X}\t0\t0\t0\n",
            f.name,
            (ip & mask(p)).swap_bytes(),
            mask(p).swap_bytes()
        ));
    }
    s
}

/// `/proc/net/pnp`: what DHCP learnt, in resolv.conf syntax (as Linux's
/// kernel IP autoconfiguration; `/etc/resolv.conf` links to it).
pub fn proc_pnp() -> String {
    let mut s = String::new();
    for f in all() {
        for d in f.dns.lock().iter() {
            s.push_str(&format!("nameserver {}\n", fmt_ip(*d)));
        }
    }
    s
}
