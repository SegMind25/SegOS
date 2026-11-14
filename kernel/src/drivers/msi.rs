//! MSI-X: devices interrupting the CPU with a message instead of a wire.
//!
//! A driver takes a vector here, points one of its device's MSI-X table
//! entries at this CPU's local APIC with that vector, and then sleeps in
//! [`Irq::wait`] instead of polling: the interrupt wakes it. Every wait
//! also re-checks on a short timer, so a lost interrupt costs a few
//! milliseconds, never a hang.

use super::pci::{Bar, Device};
use crate::task::wait::WaitQueue;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Vectors handed out to devices: 0x40..0x40 + COUNT.
pub const FIRST_VECTOR: u8 = 0x40;
const COUNT: usize = 64;

pub struct Irq {
    queue: WaitQueue,
    count: AtomicU64,
}

#[allow(clippy::declare_interior_mutable_const)]
const NEW: Irq = Irq {
    queue: WaitQueue::new(),
    count: AtomicU64::new(0),
};
static IRQS: [Irq; COUNT] = [NEW; COUNT];
static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Called from the interrupt handler for vectors in our range.
pub fn irq(vector: u8) {
    if let Some(i) = IRQS.get((vector - FIRST_VECTOR) as usize) {
        i.count.fetch_add(1, Ordering::Release);
        i.queue.wake_all();
    }
    crate::hal::apic::eoi();
}

pub fn is_ours(vector: u64) -> bool {
    (FIRST_VECTOR as u64..FIRST_VECTOR as u64 + COUNT as u64).contains(&vector)
}

impl Irq {
    /// Sleeps until `done()` holds; re-checks every 10 ms and gives up
    /// (returns false) after `timeout_ms`.
    pub fn wait(&self, mut done: impl FnMut() -> bool, timeout_ms: u64) -> bool {
        let give_up = crate::time::monotonic_ns() + timeout_ms * 1_000_000;
        loop {
            if done() {
                return true;
            }
            let now = crate::time::monotonic_ns();
            if now >= give_up {
                return false;
            }
            let recheck = (now + 10_000_000).min(give_up);
            let _timer = crate::time::wake_at(recheck);
            let seen = self.count.load(Ordering::Acquire);
            self.queue.wait_until(|| {
                self.count.load(Ordering::Acquire) != seen || crate::time::monotonic_ns() >= recheck
            });
        }
    }
}

/// Enables MSI-X entry `entry` of `dev` to send a fresh vector to this
/// CPU. Returns the interrupt to wait on, or None (no MSI-X, or none left).
pub fn enable(dev: &Device, entry: u16) -> Option<&'static Irq> {
    let cap = *dev.capabilities(0x11).first()?;
    let control = dev.addr.read16(cap + 2);
    if entry > control & 0x7ff {
        return None;
    }
    let table = dev.addr.read32(cap + 4);
    let Bar::Memory { addr, size } = dev.bar((table & 7) as u8)? else {
        return None;
    };
    let offset = (table & !7) as u64;
    if offset + (entry as u64 + 1) * 16 > size {
        return None;
    }
    let index = NEXT.fetch_add(1, Ordering::Relaxed);
    if index >= COUNT {
        return None;
    }
    let vector = FIRST_VECTOR + index as u8;
    let base = crate::mm::paging::map_device(addr + offset + entry as u64 * 16, 16).ok()?;
    let apic_id = crate::hal::apic::id();
    unsafe {
        let e = base as *mut u32;
        e.write_volatile(0xfee0_0000 | apic_id << 12); // message address
        e.add(1).write_volatile(0);
        e.add(2).write_volatile(vector as u32); // message data: the vector
        e.add(3).write_volatile(0); // unmasked
    }
    // MSI-X on, function mask off; legacy INTx stays disabled.
    dev.addr.write16(cap + 2, (control | 1 << 15) & !(1 << 14));
    Some(&IRQS[index])
}
