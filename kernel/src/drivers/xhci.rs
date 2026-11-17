//! USB: the xHCI host controller (every PC since about 2012; QEMU's
//! `qemu-xhci`) and HID boot-protocol keyboards and mice on its root
//! ports.
//!
//! The controller is taken from the firmware (USB legacy support),
//! reset, and given a device context array, a command ring and one event
//! ring. Each connected port is reset; its device gets a slot and an
//! address, its descriptors are read, and a HID interface in the boot
//! protocol gets its interrupt IN endpoint configured. A kernel thread
//! keeps a transfer queued on each such endpoint and handles the reports:
//! keys become set-1 scan codes for the PS/2 keyboard's path (evdev and
//! the console), mouse reports go to the evdev mouse. No interrupts: the
//! event ring is polled. No hubs, no other device classes yet.

use super::pci::{self, Bar};
use crate::mm::{frame, paging, phys_to_virt};
use crate::sync::SpinLock;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};

// TRB types.
const NORMAL: u32 = 1;
const SETUP: u32 = 2;
const DATA: u32 = 3;
const STATUS: u32 = 4;
const LINK: u32 = 6;
const ENABLE_SLOT: u32 = 9;
const ADDRESS_DEVICE: u32 = 11;
const CONFIGURE_ENDPOINT: u32 = 12;
const TRANSFER_EVENT: u32 = 32;
const COMMAND_COMPLETION: u32 = 33;

const SUCCESS: u32 = 1;
const SHORT_PACKET: u32 = 13;

/// A ring of TRBs in one page (the last is a link back to the start).
struct Ring {
    phys: u64,
    index: usize,
    cycle: u32,
}

const RING_TRBS: usize = 256;

impl Ring {
    fn new() -> Option<Ring> {
        let phys = frame::alloc_zeroed()?;
        let r = Ring {
            phys,
            index: 0,
            cycle: 1,
        };
        // The link TRB, with Toggle Cycle.
        r.store(RING_TRBS - 1, phys, 0, LINK << 10 | 1 << 1);
        Some(r)
    }

    fn store(&self, i: usize, param: u64, status: u32, control: u32) {
        let t = unsafe { (phys_to_virt(self.phys) as *mut u32).add(i * 4) };
        unsafe {
            write_volatile(t, param as u32);
            write_volatile(t.add(1), (param >> 32) as u32);
            write_volatile(t.add(2), status);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            write_volatile(t.add(3), control);
        }
    }

    /// Queues a TRB (the cycle bit is added); returns its address.
    fn push(&mut self, param: u64, status: u32, control: u32) -> u64 {
        let at = self.phys + self.index as u64 * 16;
        self.store(self.index, param, status, control | self.cycle);
        self.index += 1;
        if self.index == RING_TRBS - 1 {
            // Hand the link TRB over with the current cycle, then toggle.
            self.store(
                RING_TRBS - 1,
                self.phys,
                0,
                LINK << 10 | 1 << 1 | self.cycle,
            );
            self.index = 0;
            self.cycle ^= 1;
        }
        at
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Keyboard,
    Mouse,
}

/// A HID device in the boot protocol, with its interrupt IN endpoint.
struct Hid {
    slot: u32,
    dci: u32,
    kind: Kind,
    ring: Ring,
    buf: u64,
    mps: u32,
    /// The last keyboard report (modifiers and keys), or mouse buttons.
    last: [u8; 8],
}

struct Xhci {
    op: u64,
    db: u64,
    rt: u64,
    ctx64: bool,
    ports: u32,
    dcbaa: u64,
    cmd: Ring,
    events: u64,
    ev_index: usize,
    ev_cycle: u32,
    ep0: Vec<(u32, Ring)>,
    hids: Vec<Hid>,
}

static XHCI: SpinLock<Option<Xhci>> = SpinLock::new(None);

fn r32(a: u64) -> u32 {
    unsafe { read_volatile(a as *const u32) }
}
fn w32(a: u64, v: u32) {
    unsafe { write_volatile(a as *mut u32, v) }
}
fn w64(a: u64, v: u64) {
    w32(a, v as u32);
    w32(a + 4, (v >> 32) as u32);
}

fn wait_for(mut cond: impl FnMut() -> bool, ms: u32) -> bool {
    for _ in 0..ms {
        if cond() {
            return true;
        }
        crate::time::sleep_ms(1);
    }
    cond()
}

/// An event TRB: (param, status, control).
type Event = (u64, u32, u32);

impl Xhci {
    fn ctx_size(&self) -> usize {
        if self.ctx64 { 64 } else { 32 }
    }

    /// The next event, if one is waiting.
    fn next_event(&mut self) -> Option<Event> {
        let t = unsafe { (phys_to_virt(self.events) as *const u32).add(self.ev_index * 4) };
        let control = unsafe { read_volatile(t.add(3)) };
        if control & 1 != self.ev_cycle {
            return None;
        }
        let ev = unsafe {
            (
                read_volatile(t) as u64 | (read_volatile(t.add(1)) as u64) << 32,
                read_volatile(t.add(2)),
                control,
            )
        };
        self.ev_index += 1;
        if self.ev_index == RING_TRBS {
            self.ev_index = 0;
            self.ev_cycle ^= 1;
        }
        // Tell the controller how far we read (and clear Event Handler Busy).
        w64(
            self.rt + 0x20 + 0x18,
            (self.events + self.ev_index as u64 * 16) | 1 << 3,
        );
        Some(ev)
    }

    /// Waits for an event of `kind` (others are handled meanwhile).
    fn wait_event(&mut self, kind: u32, ms: u32) -> Option<Event> {
        for _ in 0..ms * 4 {
            while let Some(ev) = self.next_event() {
                if (ev.2 >> 10) & 0x3f == kind {
                    return Some(ev);
                }
                self.handle(ev);
            }
            crate::time::sleep_ns(250_000);
        }
        None
    }

    fn command(&mut self, param: u64, control: u32) -> Option<Event> {
        self.cmd.push(param, 0, control);
        w32(self.db, 0);
        let ev = self.wait_event(COMMAND_COMPLETION, 500)?;
        (ev.1 >> 24 == SUCCESS).then_some(ev)
    }

    /// A control transfer on slot `slot`'s endpoint 0; returns the bytes
    /// read (IN) into a fresh page.
    fn control(&mut self, slot: u32, setup: [u8; 8], len: u16) -> Option<Vec<u8>> {
        let input = setup[0] & 0x80 != 0;
        let buf = frame::alloc_zeroed()?;
        let ring = &mut self.ep0.iter_mut().find(|(s, _)| *s == slot)?.1;
        let trt = if len == 0 {
            0
        } else if input {
            3
        } else {
            2
        };
        ring.push(
            u64::from_le_bytes(setup),
            8,
            SETUP << 10 | 1 << 6 | trt << 16,
        );
        if len > 0 {
            ring.push(buf, len as u32, DATA << 10 | (input as u32) << 16);
        }
        let status_in = len == 0 || !input;
        ring.push(0, 0, STATUS << 10 | 1 << 5 | (status_in as u32) << 16);
        w32(self.db + slot as u64 * 4, 1);
        let ev = self.wait_event(TRANSFER_EVENT, 1000);
        let out = ev.and_then(|ev| {
            let code = ev.1 >> 24;
            (code == SUCCESS || code == SHORT_PACKET).then(|| {
                let mut v = alloc::vec![0u8; len as usize];
                unsafe {
                    core::ptr::copy_nonoverlapping(phys_to_virt(buf), v.as_mut_ptr(), len as usize)
                };
                v
            })
        });
        frame::free(buf);
        out
    }

    /// Resets port `p` (1-based) and sets up the device on it.
    fn attach(&mut self, p: u32) {
        let portsc = self.op + 0x400 + 0x10 * (p as u64 - 1);
        let sc = r32(portsc);
        if sc & 1 == 0 {
            return;
        }
        // Keep power on; leave the change bits alone; ask for a reset.
        w32(portsc, (sc & 0x0e00_c3e0) | 1 << 9 | 1 << 4);
        if !wait_for(|| r32(portsc) & 1 << 21 != 0, 200) {
            return;
        }
        let sc = r32(portsc);
        w32(portsc, (sc & 0x0e00_c3e0) | 1 << 9 | 0x7f << 17);
        if sc & 1 << 1 == 0 {
            return;
        }
        let speed = (sc >> 10) & 0xf;
        let Some(ev) = self.command(0, ENABLE_SLOT << 10) else {
            return;
        };
        let slot = ev.2 >> 24;
        let (Some(ring), Some(out), Some(input)) =
            (Ring::new(), frame::alloc_zeroed(), frame::alloc_zeroed())
        else {
            return;
        };
        unsafe {
            write_volatile(
                (phys_to_virt(self.dcbaa) as *mut u64).add(slot as usize),
                out,
            )
        };
        let cs = self.ctx_size();
        let ictx = phys_to_virt(input) as *mut u32;
        let mps0 = match speed {
            1 | 2 => 8,
            3 => 64,
            _ => 512,
        };
        unsafe {
            write_volatile(ictx.add(1), 0b11); // add slot and EP0
            let slotc = ictx.add(cs / 4);
            write_volatile(slotc, 1 << 27 | speed << 20);
            write_volatile(slotc.add(1), p << 16);
            let ep0 = ictx.add(2 * cs / 4);
            write_volatile(ep0.add(1), mps0 << 16 | 4 << 3 | 3 << 1);
            write_volatile(ep0.add(2), ring.phys as u32 | 1);
            write_volatile(ep0.add(3), (ring.phys >> 32) as u32);
            write_volatile(ep0.add(4), 8);
        }
        self.ep0.push((slot, ring));
        if self
            .command(input, ADDRESS_DEVICE << 10 | slot << 24)
            .is_none()
        {
            return;
        }
        let get = |ty: u16, len: u16| [0x80, 6, 0, ty as u8, 0, 0, len as u8, (len >> 8) as u8];
        let Some(head) = self.control(slot, get(2, 9), 9) else {
            return;
        };
        let total = u16::from_le_bytes([head[2], head[3]]).min(1024);
        let Some(conf) = self.control(slot, get(2, total), total) else {
            return;
        };
        // The first HID boot interface and its interrupt IN endpoint.
        let mut i = 0;
        let mut iface = None;
        let mut found = None;
        while i + 2 <= conf.len() {
            let (len, ty) = (conf[i] as usize, conf[i + 1]);
            if len < 2 {
                break;
            }
            match ty {
                4 if i + 9 <= conf.len() => {
                    iface =
                        (conf[i + 5] == 3 && conf[i + 6] == 1 && (1..=2).contains(&conf[i + 7]))
                            .then_some((conf[i + 2], conf[i + 7]));
                }
                5 if i + 7 <= conf.len() && found.is_none() => {
                    if let Some((num, proto)) = iface
                        && conf[i + 2] & 0x80 != 0
                        && conf[i + 3] & 3 == 3
                    {
                        let mps = u16::from_le_bytes([conf[i + 4], conf[i + 5]]) as u32 & 0x7ff;
                        found = Some((num, proto, conf[i + 2] & 0xf, mps, conf[i + 6]));
                    }
                }
                _ => {}
            }
            i += len;
        }
        let Some((num, proto, epnum, mps, interval)) = found else {
            return;
        };
        let value = conf[5];
        self.control(slot, [0, 9, value, 0, 0, 0, 0, 0], 0);
        self.control(slot, [0x21, 0x0b, 0, 0, num, 0, 0, 0], 0); // SET_PROTOCOL boot
        self.control(slot, [0x21, 0x0a, 0, 0, num, 0, 0, 0], 0); // SET_IDLE
        let dci = epnum as u32 * 2 + 1;
        let (Some(ring), Some(buf)) = (Ring::new(), frame::alloc_zeroed()) else {
            return;
        };
        // Interval as a power of two of 125 µs units.
        let exp = match speed {
            1 | 2 => (31 - ((interval.max(1) as u32) * 8).leading_zeros()).clamp(3, 10),
            _ => (interval.clamp(1, 16) - 1) as u32,
        };
        unsafe {
            core::ptr::write_bytes(ictx as *mut u8, 0, 4096);
            write_volatile(ictx.add(1), 1 | 1 << dci);
            let slotc = ictx.add(cs / 4);
            write_volatile(slotc, dci << 27 | speed << 20);
            write_volatile(slotc.add(1), p << 16);
            let ep = ictx.add((dci as usize + 1) * cs / 4);
            write_volatile(ep, exp << 16);
            write_volatile(ep.add(1), mps << 16 | 7 << 3 | 3 << 1);
            write_volatile(ep.add(2), ring.phys as u32 | 1);
            write_volatile(ep.add(3), (ring.phys >> 32) as u32);
            write_volatile(ep.add(4), mps << 16 | mps);
        }
        if self
            .command(input, CONFIGURE_ENDPOINT << 10 | slot << 24)
            .is_none()
        {
            return;
        }
        let kind = if proto == 1 {
            Kind::Keyboard
        } else {
            Kind::Mouse
        };
        crate::info!(
            "usb: port {p}: {} (slot {slot}, endpoint {epnum})",
            if kind == Kind::Keyboard {
                "keyboard"
            } else {
                "mouse"
            }
        );
        let mut hid = Hid {
            slot,
            dci,
            kind,
            ring,
            buf,
            mps: mps.min(64),
            last: [0; 8],
        };
        self.queue(&mut hid);
        self.hids.push(hid);
    }

    fn queue(&self, h: &mut Hid) {
        h.ring.push(h.buf, h.mps, NORMAL << 10 | 1 << 5 | 1 << 2);
        w32(self.db + h.slot as u64 * 4, h.dci);
    }

    /// An event outside a wait: HID reports.
    fn handle(&mut self, ev: Event) {
        if (ev.2 >> 10) & 0x3f != TRANSFER_EVENT {
            return;
        }
        let (slot, dci) = (ev.2 >> 24, (ev.2 >> 16) & 0x1f);
        let Some(i) = self
            .hids
            .iter()
            .position(|h| h.slot == slot && h.dci == dci)
        else {
            return;
        };
        let mut h = self.hids.swap_remove(i);
        let code = ev.1 >> 24;
        if code == SUCCESS || code == SHORT_PACKET {
            let n = (h.mps - (ev.1 & 0xff_ffff).min(h.mps)) as usize;
            let mut report = [0u8; 8];
            unsafe {
                core::ptr::copy_nonoverlapping(phys_to_virt(h.buf), report.as_mut_ptr(), n.min(8))
            };
            match h.kind {
                Kind::Keyboard => keyboard_report(&mut h.last, &report),
                Kind::Mouse => {
                    let buttons = report[0] & 7;
                    let changed = buttons ^ h.last[0];
                    h.last[0] = buttons;
                    let (dx, dy) = (report[1] as i8 as i32, report[2] as i8 as i32);
                    let wheel = if n > 3 { report[3] as i8 as i32 } else { 0 };
                    crate::input::mouse(dx, -dy, -wheel, buttons, changed);
                }
            }
        }
        self.queue(&mut h);
        self.hids.push(h);
    }
}

/// HID usage (0x04..=0x64) -> set-1 scan code (0xE000 | code: behind 0xE0).
const USAGE: [u16; 0x65] = {
    let mut t = [0u16; 0x65];
    let letters = [
        0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18,
        0x19, 0x10, 0x13, 0x1f, 0x14, 0x16, 0x2f, 0x11, 0x2d, 0x15, 0x2c,
    ];
    let mut i = 0;
    while i < 26 {
        t[4 + i] = letters[i];
        i += 1;
    }
    let mut d = 0;
    while d < 10 {
        t[0x1e + d] = 2 + d as u16; // 1..9, 0
        d += 1;
    }
    let rest: [(usize, u16); 52] = [
        (0x28, 0x1c),
        (0x29, 0x01),
        (0x2a, 0x0e),
        (0x2b, 0x0f),
        (0x2c, 0x39),
        (0x2d, 0x0c),
        (0x2e, 0x0d),
        (0x2f, 0x1a),
        (0x30, 0x1b),
        (0x31, 0x2b),
        (0x32, 0x2b),
        (0x33, 0x27),
        (0x34, 0x28),
        (0x35, 0x29),
        (0x36, 0x33),
        (0x37, 0x34),
        (0x38, 0x35),
        (0x39, 0x3a),
        (0x3a, 0x3b),
        (0x3b, 0x3c),
        (0x3c, 0x3d),
        (0x3d, 0x3e),
        (0x3e, 0x3f),
        (0x3f, 0x40),
        (0x40, 0x41),
        (0x41, 0x42),
        (0x42, 0x43),
        (0x43, 0x44),
        (0x44, 0x57),
        (0x45, 0x58),
        (0x47, 0x46),
        (0x49, 0xe052),
        (0x4a, 0xe047),
        (0x4b, 0xe049),
        (0x4c, 0xe053),
        (0x4d, 0xe04f),
        (0x4e, 0xe051),
        (0x4f, 0xe04d),
        (0x50, 0xe04b),
        (0x51, 0xe050),
        (0x52, 0xe048),
        (0x53, 0x45),
        (0x54, 0xe035),
        (0x55, 0x37),
        (0x56, 0x4a),
        (0x57, 0x4e),
        (0x58, 0xe01c),
        (0x59, 0x4f),
        (0x5a, 0x50),
        (0x5b, 0x51),
        (0x62, 0x52),
        (0x64, 0x56),
    ];
    let mut r = 0;
    while r < rest.len() {
        t[rest[r].0] = rest[r].1;
        r += 1;
    }
    t[0x5c] = 0x4b;
    t[0x5d] = 0x4c;
    t[0x5e] = 0x4d;
    t[0x5f] = 0x47;
    t[0x60] = 0x48;
    t[0x61] = 0x49;
    t[0x63] = 0x53;
    t
};

/// Modifier bits (LCtrl, LShift, LAlt, LGUI, RCtrl, RShift, RAlt, RGUI).
const MODIFIERS: [u16; 8] = [0x1d, 0x2a, 0x38, 0xe05b, 0xe01d, 0x36, 0xe038, 0xe05c];

fn send(code: u16, down: bool) {
    if code & 0xe000 == 0xe000 {
        super::ps2kbd::scancode(0xe0);
    }
    let b = (code & 0x7f) as u8;
    super::ps2kbd::scancode(if down { b } else { b | 0x80 });
}

/// A boot keyboard report: modifiers and up to six keys held. Keys
/// released first, then pressed, as scan codes.
fn keyboard_report(last: &mut [u8; 8], r: &[u8; 8]) {
    if r[2] == 1 {
        return; // phantom state (too many keys)
    }
    for (bit, &code) in MODIFIERS.iter().enumerate() {
        let (was, is) = (last[0] >> bit & 1, r[0] >> bit & 1);
        if was != is {
            send(code, is == 1);
        }
    }
    for &k in &last[2..8] {
        if k >= 4 && (k as usize) < USAGE.len() && !r[2..8].contains(&k) && USAGE[k as usize] != 0 {
            send(USAGE[k as usize], false);
        }
    }
    for &k in &r[2..8] {
        if k >= 4
            && (k as usize) < USAGE.len()
            && !last[2..8].contains(&k)
            && USAGE[k as usize] != 0
        {
            send(USAGE[k as usize], true);
        }
    }
    *last = *r;
}

fn init_controller(d: &pci::Device) -> Option<Xhci> {
    let Some(Bar::Memory { addr, size }) = d.bar(0) else {
        return None;
    };
    d.enable();
    let base = paging::map_device(addr, size.max(0x10000)).ok()?;
    let caplen = r32(base) & 0xff;
    let hcs1 = r32(base + 4);
    let hcs2 = r32(base + 8);
    let hcc1 = r32(base + 0x10);
    let op = base + caplen as u64;
    // Take the controller from the firmware (USB legacy support).
    let mut cap = ((hcc1 >> 16) as u64) << 2;
    while cap != 0 {
        let c = base + cap;
        let v = r32(c);
        if v & 0xff == 1 {
            w32(c, v | 1 << 24);
            wait_for(|| r32(c) & 1 << 16 == 0, 1000);
            break;
        }
        let next = ((v >> 8) & 0xff) as u64;
        cap = if next == 0 { 0 } else { cap + (next << 2) };
    }
    // Stop, then reset.
    w32(op, r32(op) & !1);
    wait_for(|| r32(op + 4) & 1 != 0, 100);
    w32(op, 1 << 1);
    if !wait_for(|| r32(op) & 1 << 1 == 0 && r32(op + 4) & 1 << 11 == 0, 1000) {
        return None;
    }
    let slots = (hcs1 & 0xff).min(32);
    let mut x = Xhci {
        op,
        db: base + (r32(base + 0x14) & !3) as u64,
        rt: base + (r32(base + 0x18) & !0x1f) as u64,
        ctx64: hcc1 & 1 << 2 != 0,
        ports: hcs1 >> 24,
        dcbaa: frame::alloc_zeroed()?,
        cmd: Ring::new()?,
        events: frame::alloc_zeroed()?,
        ev_index: 0,
        ev_cycle: 1,
        ep0: Vec::new(),
        hids: Vec::new(),
    };
    w32(op + 0x38, slots);
    // Scratchpad buffers, if the controller wants any.
    let scratch = ((hcs2 >> 21) & 0x1f) << 5 | (hcs2 >> 27);
    if scratch > 0 {
        let array = frame::alloc_zeroed()?;
        for i in 0..scratch.min(512) as usize {
            let page = frame::alloc_zeroed()?;
            unsafe { write_volatile((phys_to_virt(array) as *mut u64).add(i), page) };
        }
        unsafe { write_volatile(phys_to_virt(x.dcbaa) as *mut u64, array) };
    }
    w64(op + 0x30, x.dcbaa);
    w64(op + 0x18, x.cmd.phys | 1);
    // One event ring segment.
    let erst = frame::alloc_zeroed()?;
    unsafe {
        let e = phys_to_virt(erst) as *mut u32;
        write_volatile(e, x.events as u32);
        write_volatile(e.add(1), (x.events >> 32) as u32);
        write_volatile(e.add(2), RING_TRBS as u32);
    }
    let ir = x.rt + 0x20;
    w32(ir + 0x08, 1);
    w64(ir + 0x18, x.events);
    w64(ir + 0x10, erst);
    w32(op, 1); // run
    if !wait_for(|| r32(op + 4) & 1 == 0, 100) {
        return None;
    }
    crate::time::sleep_ms(50);
    for p in 1..=x.ports {
        x.attach(p);
    }
    Some(x)
}

/// Sets up the first xHCI controller (PCI class 0C, subclass 03, 0x30)
/// and its keyboards and mice; then keeps polling for their reports.
pub fn init() {
    for d in pci::devices() {
        if d.class != 0x0c || d.subclass != 0x03 || d.prog_if != 0x30 {
            continue;
        }
        let Some(x) = init_controller(&d) else {
            crate::warn!(
                "usb: {:04x}:{:04x}: the controller did not start",
                d.vendor,
                d.device
            );
            continue;
        };
        let devices = x.hids.len();
        crate::info!(
            "usb: xHCI {:04x}:{:04x}, {} ports, {devices} HID device(s)",
            d.vendor,
            d.device,
            x.ports
        );
        if devices == 0 {
            return;
        }
        *XHCI.lock() = Some(x);
        crate::task::spawn(|| {
            loop {
                crate::time::sleep_ms(4);
                if let Some(x) = XHCI.lock().as_mut() {
                    while let Some(ev) = x.next_event() {
                        x.handle(ev);
                    }
                }
            }
        });
        return;
    }
}
