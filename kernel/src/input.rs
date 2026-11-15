//! evdev: `/dev/input/eventN`, Linux's input event interface, which
//! libinput, Wayland compositors and X read.
//!
//! event0 is the PS/2 keyboard (Linux key codes), event1 the PS/2 mouse
//! (relative motion, three buttons, wheel). Every open file gets its own
//! queue of `struct input_event`s; a grab (EVIOCGRAB) keeps events for the
//! grabbing file only. While a program has the keyboard (the terminal in
//! K_OFF mode, or a grab), key presses do not reach the console.

use crate::abi::{Errno, KResult};
use crate::fs::{FileType, Inode, new_ino, poll};
use crate::mm::vm::AddressSpace;
use crate::sync::SpinLock;
use crate::task::wait::WaitQueue;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const EV_SYN: u16 = 0;
pub const EV_KEY: u16 = 1;
pub const EV_REL: u16 = 2;
pub const EV_REP: u16 = 0x14;
pub const BTN_LEFT: u16 = 0x110;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Keyboard,
    Mouse,
}

pub struct EvDev {
    index: u32,
    kind: Kind,
    name: &'static str,
    readers: SpinLock<Vec<Weak<Reader>>>,
    grab: SpinLock<Option<Weak<Reader>>>,
    keys: SpinLock<[u8; 96]>,
}

static KEYBOARD: EvDev = EvDev::new(0, Kind::Keyboard, "AT Translated Set 2 keyboard");
static MOUSE: EvDev = EvDev::new(1, Kind::Mouse, "ImPS/2 Generic Wheel Mouse");
static GENERATION: AtomicU64 = AtomicU64::new(0);
/// A program reads the keyboard itself (the console gets no keys).
pub static KEYBOARD_TAKEN: AtomicBool = AtomicBool::new(false);

impl EvDev {
    const fn new(index: u32, kind: Kind, name: &'static str) -> Self {
        EvDev {
            index,
            kind,
            name,
            readers: SpinLock::new(Vec::new()),
            grab: SpinLock::new(None),
            keys: SpinLock::new([0; 96]),
        }
    }

    fn emit(&self, events: &[(u16, u16, i32)]) {
        let ns = crate::time::realtime_ns();
        let mono = crate::time::monotonic_ns();
        let grab = self.grab.lock().as_ref().and_then(|w| w.upgrade());
        let readers: Vec<Arc<Reader>> = match grab {
            Some(g) => alloc::vec![g],
            None => self
                .readers
                .lock()
                .iter()
                .filter_map(|w| w.upgrade())
                .collect(),
        };
        for r in readers {
            let t = if r.monotonic.load(Ordering::Relaxed) {
                mono
            } else {
                ns
            };
            let mut q = r.queue.lock();
            for &(ty, code, value) in events {
                if q.len() >= 4096 {
                    q.pop_front();
                }
                let mut e = [0u8; 24];
                e[0..8].copy_from_slice(&((t / 1_000_000_000) as i64).to_le_bytes());
                e[8..16].copy_from_slice(&((t % 1_000_000_000 / 1000) as i64).to_le_bytes());
                e[16..18].copy_from_slice(&ty.to_le_bytes());
                e[18..20].copy_from_slice(&code.to_le_bytes());
                e[20..24].copy_from_slice(&value.to_le_bytes());
                q.push_back(e);
            }
            drop(q);
            r.wait.wake_all();
        }
        GENERATION.fetch_add(1, Ordering::Relaxed);
        crate::fs::poll_notify();
    }

    /// Bits of the capability `ev` (EVIOCGBIT).
    fn bits(&self, ev: u32) -> Vec<u8> {
        let mut b = alloc::vec![0u8; 96];
        let mut set = |n: u16| b[n as usize / 8] |= 1 << (n % 8);
        match (self.kind, ev) {
            (Kind::Keyboard, 0) => [EV_SYN, EV_KEY, EV_REP].iter().for_each(|&e| set(e)),
            (Kind::Mouse, 0) => [EV_SYN, EV_KEY, EV_REL].iter().for_each(|&e| set(e)),
            (Kind::Keyboard, 1) => {
                (1..=88).chain(96..=111).chain(125..=127).for_each(&mut set);
            }
            (Kind::Mouse, 1) => (BTN_LEFT..BTN_LEFT + 3).for_each(&mut set),
            (Kind::Mouse, 2) => [0, 1, 8].iter().for_each(|&r| set(r)), // REL_X, REL_Y, REL_WHEEL
            _ => {}
        }
        b
    }
}

/// A key went down or up (`code` a Linux key code).
pub fn key(code: u16, down: bool) {
    let repeat = {
        let mut k = KEYBOARD.keys.lock();
        let (i, m) = (code as usize / 8, 1u8 << (code % 8));
        if i >= k.len() {
            return;
        }
        let was = k[i] & m != 0;
        if down {
            k[i] |= m;
        } else {
            k[i] &= !m;
        }
        was && down
    };
    let value = if repeat { 2 } else { down as i32 };
    KEYBOARD.emit(&[(EV_KEY, code, value), (EV_SYN, 0, 0)]);
}

/// The mouse moved (`dy` up positive, as PS/2 reports it) or its buttons
/// changed.
pub fn mouse(dx: i32, dy: i32, wheel: i32, buttons: u8, changed: u8) {
    let mut ev = Vec::new();
    for b in 0..3u16 {
        if changed & (1 << b) != 0 {
            let code = BTN_LEFT + [0, 1, 2][b as usize];
            ev.push((EV_KEY, code, (buttons >> b & 1) as i32));
        }
    }
    if dx != 0 {
        ev.push((EV_REL, 0, dx));
    }
    if dy != 0 {
        ev.push((EV_REL, 1, -dy));
    }
    if wheel != 0 {
        ev.push((EV_REL, 8, -wheel));
    }
    if !ev.is_empty() {
        ev.push((EV_SYN, 0, 0));
        MOUSE.emit(&ev);
    }
}

/// Whether the console should get key presses.
pub fn console_gets_keys() -> bool {
    !KEYBOARD_TAKEN.load(Ordering::Relaxed)
        && KEYBOARD
            .grab
            .lock()
            .as_ref()
            .is_none_or(|w| w.strong_count() == 0)
}

/// The device node `/dev/input/eventN`.
pub struct Node {
    dev: &'static EvDev,
    ino: u64,
}

pub fn nodes() -> [(alloc::string::String, Arc<dyn Inode>); 2] {
    [&KEYBOARD, &MOUSE].map(|d| {
        (
            alloc::format!("event{}", d.index),
            Arc::new(Node {
                dev: d,
                ino: new_ino(),
            }) as Arc<dyn Inode>,
        )
    })
}

/// (name, major:minor, kind) of each device, for /sys.
pub fn devices() -> [(u32, &'static str, bool); 2] {
    [(0, KEYBOARD.name, true), (1, MOUSE.name, false)]
}

impl Inode for Node {
    fn file_type(&self) -> FileType {
        FileType::CharDevice
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        0o660
    }
    fn rdev(&self) -> u64 {
        crate::fs::dev::makedev(13, 64 + self.dev.index)
    }
    fn seekable(&self) -> bool {
        false
    }
    fn open_fifo(&self, _flags: u32) -> Option<Arc<dyn Inode>> {
        let r = Arc::new(Reader {
            dev: self.dev,
            ino: self.ino,
            queue: SpinLock::new(VecDeque::new()),
            wait: WaitQueue::new(),
            monotonic: AtomicBool::new(false),
        });
        let mut l = self.dev.readers.lock();
        l.retain(|w| w.strong_count() > 0);
        l.push(Arc::downgrade(&r));
        Some(r)
    }
}

/// One open file of an event device.
pub struct Reader {
    dev: &'static EvDev,
    ino: u64,
    queue: SpinLock<VecDeque<[u8; 24]>>,
    wait: WaitQueue,
    monotonic: AtomicBool,
}

impl Drop for Reader {
    fn drop(&mut self) {
        let mut g = self.dev.grab.lock();
        if g.as_ref().is_some_and(|w| w.strong_count() == 0) {
            *g = None;
        }
    }
}

fn put_str(mm: &AddressSpace, arg: u64, size: usize, s: &[u8]) -> KResult<u64> {
    let mut v = s.to_vec();
    v.push(0);
    let n = v.len().min(size);
    mm.copy_to(arg, &v[..n])?;
    Ok(n as u64)
}

impl Inode for Reader {
    fn file_type(&self) -> FileType {
        FileType::CharDevice
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        0o660
    }
    fn rdev(&self) -> u64 {
        crate::fs::dev::makedev(13, 64 + self.dev.index)
    }
    fn seekable(&self) -> bool {
        false
    }
    fn read_stream(&self, buf: &mut [u8], nonblock: bool) -> KResult<usize> {
        if buf.len() < 24 {
            return Err(Errno::EINVAL);
        }
        loop {
            {
                let mut q = self.queue.lock();
                let mut n = 0;
                while n + 24 <= buf.len() {
                    let Some(e) = q.pop_front() else { break };
                    buf[n..n + 24].copy_from_slice(&e);
                    n += 24;
                }
                if n > 0 {
                    return Ok(n);
                }
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            self.wait
                .wait_interruptible(|| !self.queue.lock().is_empty())?;
        }
    }
    fn write_stream(&self, data: &[u8], _nonblock: bool) -> KResult<usize> {
        Ok(data.len()) // LED and repeat events: ignored
    }
    fn poll(&self) -> u16 {
        poll::POLLOUT
            | if self.queue.lock().is_empty() {
                0
            } else {
                poll::POLLIN
            }
    }
    fn poll_generation(&self) -> u64 {
        GENERATION.load(Ordering::Relaxed)
    }
    fn ioctl(&self, req: u32, arg: u64, mm: &AddressSpace) -> KResult<u64> {
        if (req >> 8) & 0xff != b'E' as u32 {
            return Err(Errno::ENOTTY);
        }
        let nr = req & 0xff;
        let size = ((req >> 16) & 0x3fff) as usize;
        let d = self.dev;
        match nr {
            0x01 => mm.write(arg, &0x0001_0001i32).map(|()| 0), // EVIOCGVERSION
            0x02 => {
                // EVIOCGID: bus i8042, vendor, product, version.
                let id: [u16; 4] = [
                    0x11,
                    1,
                    if d.kind == Kind::Keyboard { 1 } else { 2 },
                    0xab41,
                ];
                mm.write(arg, &id).map(|()| 0)
            }
            0x03 if req >> 30 == 2 => mm.write(arg, &[250u32, 33]).map(|()| 0), // EVIOCGREP
            0x03 => Ok(0),                                                      // EVIOCSREP
            0x06 => put_str(mm, arg, size, d.name.as_bytes()),
            0x07 => put_str(
                mm,
                arg,
                size,
                if d.kind == Kind::Keyboard {
                    b"isa0060/serio0/input0"
                } else {
                    b"isa0060/serio1/input0"
                },
            ),
            0x08 => Err(Errno::ENOENT), // EVIOCGUNIQ: none
            0x09 => {
                // EVIOCGPROP: INPUT_PROP_POINTER for the mouse.
                let p = [if d.kind == Kind::Mouse { 1u8 } else { 0 }];
                let n = size.min(1);
                mm.copy_to(arg, &p[..n])?;
                Ok(n as u64)
            }
            0x18 => {
                let k = *d.keys.lock();
                let n = size.min(k.len());
                mm.copy_to(arg, &k[..n])?;
                Ok(n as u64)
            }
            0x19..=0x1b => {
                let z = alloc::vec![0u8; size.min(64)];
                mm.copy_to(arg, &z)?;
                Ok(z.len() as u64)
            }
            0x20..=0x3f => {
                let b = d.bits(nr - 0x20);
                let n = size.min(b.len());
                mm.copy_to(arg, &b[..n])?;
                Ok(n as u64)
            }
            0x40..=0x7f => Err(Errno::EINVAL), // no absolute axes
            0x90 => {
                // EVIOCGRAB
                let on: i32 = arg as i32;
                let mut g = d.grab.lock();
                let mine = self
                    .dev
                    .readers
                    .lock()
                    .iter()
                    .find(|w| w.upgrade().is_some_and(|r| core::ptr::eq(&*r, self)))
                    .cloned();
                if on != 0 {
                    if g.as_ref().is_some_and(|w| w.strong_count() > 0) {
                        return Err(Errno::EBUSY);
                    }
                    *g = mine;
                } else {
                    *g = None;
                }
                Ok(0)
            }
            0x91 => Ok(0), // EVIOCREVOKE
            0xa0 => {
                let id: i32 = mm.read(arg)?;
                self.monotonic.store(id == 1, Ordering::Relaxed);
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    }
}
