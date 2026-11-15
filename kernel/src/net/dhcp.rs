//! A DHCP client (RFC 2131) for each Ethernet interface, run by the
//! network thread: discover, request, bound. What the server says (address,
//! router, DNS servers) configures the interface; `/proc/net/pnp` shows the
//! DNS servers.

use super::iface::{self, Iface};
use crate::sync::SpinLock;
use alloc::sync::Arc;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Discover,
    Request { server: u32, offered: u32 },
    Bound,
}

struct Client {
    iface: Arc<Iface>,
    xid: u32,
    phase: Phase,
    next_send: u64,
    tries: u32,
}

static CLIENTS: SpinLock<Vec<Client>> = SpinLock::new(Vec::new());

pub fn start(f: &Arc<Iface>) {
    let mut x = [0u8; 4];
    crate::random::fill(&mut x);
    CLIENTS.lock().push(Client {
        iface: f.clone(),
        xid: u32::from_le_bytes(x),
        phase: Phase::Discover,
        next_send: 0,
        tries: 0,
    });
}

fn message(c: &Client) -> Vec<u8> {
    let mut m = alloc::vec![0u8; 240];
    m[0] = 1; // BOOTREQUEST
    m[1] = 1; // Ethernet
    m[2] = 6;
    m[4..8].copy_from_slice(&c.xid.to_be_bytes());
    m[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // answer by broadcast
    m[28..34].copy_from_slice(&c.iface.mac);
    m[236..240].copy_from_slice(&[99, 130, 83, 99]);
    match c.phase {
        Phase::Discover => m.extend_from_slice(&[53, 1, 1]),
        Phase::Request { server, offered } => {
            m.extend_from_slice(&[53, 1, 3, 50, 4]);
            m.extend_from_slice(&offered.to_be_bytes());
            m.extend_from_slice(&[54, 4]);
            m.extend_from_slice(&server.to_be_bytes());
        }
        Phase::Bound => {}
    }
    m.extend_from_slice(&[55, 4, 1, 3, 6, 15]); // mask, router, DNS, domain
    m.extend_from_slice(&[12, 5]);
    m.extend_from_slice(b"segos");
    m.push(255);
    m
}

/// Sends what is due.
pub fn tick(now: u64) {
    let mut out = Vec::new();
    for c in CLIENTS.lock().iter_mut() {
        if c.phase == Phase::Bound || now < c.next_send {
            continue;
        }
        if c.tries >= 4 {
            c.phase = Phase::Discover;
        }
        c.tries += 1;
        c.next_send = now + (1u64 << c.tries.min(3)) * 1_000_000_000;
        out.push(message(c));
    }
    for m in out {
        let _ = super::udp::send_datagram((0, 68), (u32::MAX, 67), &m);
    }
}

fn option(opts: &[u8], code: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => i += 1,
            255 => break,
            k => {
                let l = *opts.get(i + 1)? as usize;
                let v = opts.get(i + 2..i + 2 + l)?;
                if k == code {
                    return Some(v);
                }
                i += 2 + l;
            }
        }
    }
    None
}

fn ip4(v: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(v.get(..4)?.try_into().ok()?))
}

/// A datagram to port 68; true if it was a reply to one of our clients.
pub fn input(f: &Arc<Iface>, m: &[u8]) -> bool {
    if m.len() < 240 || m[0] != 2 || m[236..240] != [99, 130, 83, 99] {
        return false;
    }
    let xid = u32::from_be_bytes(m[4..8].try_into().unwrap());
    let mut list = CLIENTS.lock();
    let Some(c) = list
        .iter_mut()
        .find(|c| c.xid == xid && Arc::ptr_eq(&c.iface, f))
    else {
        return false;
    };
    let opts = &m[240..];
    let yiaddr = u32::from_be_bytes(m[16..20].try_into().unwrap());
    let ty = option(opts, 53)
        .and_then(|v| v.first().copied())
        .unwrap_or(0);
    match (c.phase, ty) {
        (Phase::Discover, 2) => {
            let server = option(opts, 54).and_then(ip4).unwrap_or(0);
            c.phase = Phase::Request {
                server,
                offered: yiaddr,
            };
            c.tries = 0;
            c.next_send = 0;
            drop(list);
            tick(crate::time::monotonic_ns());
        }
        (Phase::Request { .. }, 5) => {
            let mask = option(opts, 1).and_then(ip4).unwrap_or(0xffff_ff00);
            let prefix = mask.leading_ones() as u8;
            let router = option(opts, 3).and_then(ip4);
            let dns: Vec<u32> = option(opts, 6)
                .map(|v| v.chunks_exact(4).filter_map(ip4).collect())
                .unwrap_or_default();
            *f.addr.lock() = Some((yiaddr, prefix));
            *f.gateway.lock() = router;
            *f.dns.lock() = dns;
            c.phase = Phase::Bound;
            crate::info!(
                "net: {} is {}/{}{} (DHCP)",
                f.name,
                iface::fmt_ip(yiaddr),
                prefix,
                router.map_or(alloc::string::String::new(), |r| alloc::format!(
                    " via {}",
                    iface::fmt_ip(r)
                ))
            );
        }
        (Phase::Request { .. }, 6) => {
            c.phase = Phase::Discover; // NAK: start over
            c.tries = 0;
            c.next_send = 0;
        }
        _ => {}
    }
    true
}
