//! virtio over PCI (the "modern" 1.0 interface): finding the device's
//! configuration structures, feature negotiation, and split virtqueues.

use super::dma::{DmaPage, Mmio};
use super::pci;
use core::sync::atomic::{Ordering, fence};

const STATUS_ACK: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
pub const F_VERSION_1: u64 = 1 << 32;

pub struct Transport {
    pub pci: pci::Device,
    common: Mmio,
    notify: Mmio,
    notify_mult: u32,
    pub device_cfg: Mmio,
    pub isr: Mmio,
}

impl Transport {
    /// Finds the virtio capabilities of a PCI function.
    pub fn new(pci: pci::Device) -> Option<Self> {
        pci.enable();
        let (mut common, mut notify, mut device, mut isr, mut mult) = (None, None, None, None, 0);
        for cap in pci.capabilities(0x09) {
            let cfg_type = pci.read8(cap + 3);
            if !(1..=4).contains(&cfg_type) {
                continue; // 5: PCI configuration access, not needed
            }
            let bar = pci.read8(cap + 4);
            let offset = pci.read32(cap + 8) as u64;
            let Some(base) = bar_base(&pci, bar) else {
                continue;
            };
            let m = Mmio(base + offset);
            match cfg_type {
                1 => common = Some(m),
                2 => {
                    notify = Some(m);
                    mult = pci.read32(cap + 16);
                }
                3 => isr = Some(m),
                4 => device = Some(m),
                _ => {}
            }
        }
        Some(Self {
            pci,
            common: common?,
            notify: notify?,
            notify_mult: mult,
            device_cfg: device.unwrap_or(Mmio(0)),
            isr: isr.unwrap_or(Mmio(0)),
        })
    }

    /// Reset, then negotiate `wanted` features (VERSION_1 always).
    pub fn negotiate(&self, wanted: u64) -> Option<u64> {
        let c = self.common;
        c.w8(20, 0);
        while c.r8(20) != 0 {
            core::hint::spin_loop();
        }
        c.w8(20, STATUS_ACK | STATUS_DRIVER);
        c.w32(0, 0);
        let lo = c.r32(4) as u64;
        c.w32(0, 1);
        let hi = c.r32(4) as u64;
        let offered = hi << 32 | lo;
        let features = offered & (wanted | F_VERSION_1);
        if features & F_VERSION_1 == 0 {
            return None;
        }
        c.w32(8, 0);
        c.w32(12, features as u32);
        c.w32(8, 1);
        c.w32(12, (features >> 32) as u32);
        c.w8(20, STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK);
        (c.r8(20) & STATUS_FEATURES_OK != 0).then_some(features)
    }

    pub fn driver_ok(&self) {
        let c = self.common;
        c.w8(20, c.r8(20) | STATUS_DRIVER_OK);
    }

    /// Sets up queue `index`, with an MSI-X vector or none (0xffff).
    pub fn queue(&self, index: u16, msix: u16) -> Option<Queue> {
        let c = self.common;
        c.w16(22, index);
        let max = c.r16(24);
        if max == 0 {
            return None;
        }
        let size = max.min(128);
        c.w16(24, size);
        c.w16(26, msix);
        let q = Queue::new(size);
        c.w64(32, q.desc.phys);
        c.w64(40, q.avail.phys);
        c.w64(48, q.used.phys);
        let off = c.r16(30) as u64;
        c.w16(28, 1);
        Some(Queue {
            notify: Mmio(self.notify.0 + off * self.notify_mult as u64),
            index,
            ..q
        })
    }

    /// Points the configuration-change interrupt at an MSI-X vector.
    pub fn set_config_msix(&self, v: u16) {
        self.common.w16(16, v);
    }
}

/// Each BAR is mapped once, however many capabilities point into it.
fn bar_base(pci: &pci::Device, bar: u8) -> Option<u64> {
    use crate::sync::SpinLock;
    use alloc::vec::Vec;
    type BarKey = (u8, u8, u8, u8);
    static MAPPED: SpinLock<Vec<(BarKey, u64)>> = SpinLock::new(Vec::new());
    let key = (pci.bus, pci.dev, pci.func, bar);
    if let Some(&(_, v)) = MAPPED.lock().iter().find(|(k, _)| *k == key) {
        return Some(v);
    }
    let v = pci.map_bar(bar)?;
    MAPPED.lock().push((key, v));
    Some(v)
}

/// A split virtqueue: descriptor table, available ring, used ring, each
/// in its own page (queue size at most 128).
pub struct Queue {
    desc: DmaPage,
    avail: DmaPage,
    used: DmaPage,
    pub size: u16,
    free: alloc::vec::Vec<u16>,
    last_used: u16,
    notify: Mmio,
    index: u16,
}

pub const DESC_NEXT: u16 = 1;
pub const DESC_WRITE: u16 = 2;

impl Queue {
    fn new(size: u16) -> Self {
        Self {
            desc: DmaPage::new(),
            avail: DmaPage::new(),
            used: DmaPage::new(),
            size,
            free: (0..size).rev().collect(),
            last_used: 0,
            notify: Mmio(0),
            index: 0,
        }
    }

    pub fn free_count(&self) -> usize {
        self.free.len()
    }

    /// Queues a chain of buffers (physical address, length, device writes
    /// it); returns the head descriptor's index.
    pub fn submit(&mut self, bufs: &[(u64, u32, bool)]) -> Option<u16> {
        if self.free.len() < bufs.len() {
            return None;
        }
        let ids: alloc::vec::Vec<u16> = (0..bufs.len()).map(|_| self.free.pop().unwrap()).collect();
        for (i, &(addr, len, write)) in bufs.iter().enumerate() {
            let d = ids[i] as usize * 16;
            let mut flags = if write { DESC_WRITE } else { 0 };
            let next = if i + 1 < bufs.len() {
                flags |= DESC_NEXT;
                ids[i + 1]
            } else {
                0
            };
            self.desc.write::<u64>(d, addr);
            self.desc.write::<u32>(d + 8, len);
            self.desc.write::<u16>(d + 12, flags);
            self.desc.write::<u16>(d + 14, next);
        }
        let idx = self.avail.read::<u16>(2);
        self.avail
            .write::<u16>(4 + 2 * (idx % self.size) as usize, ids[0]);
        fence(Ordering::SeqCst);
        self.avail.write::<u16>(2, idx.wrapping_add(1));
        fence(Ordering::SeqCst);
        Some(ids[0])
    }

    pub fn kick(&self) {
        self.notify.w16(0, self.index);
    }

    /// A completed chain: (head index, bytes written by the device).
    pub fn pop_used(&mut self) -> Option<(u16, u32)> {
        fence(Ordering::SeqCst);
        if self.used.read::<u16>(2) == self.last_used {
            return None;
        }
        let e = 4 + 8 * (self.last_used % self.size) as usize;
        let id = self.used.read::<u32>(e) as u16;
        let len = self.used.read::<u32>(e + 4);
        self.last_used = self.last_used.wrapping_add(1);
        // Return the chain's descriptors to the free list.
        let mut d = id;
        loop {
            self.free.push(d);
            let flags = self.desc.read::<u16>(d as usize * 16 + 12);
            if flags & DESC_NEXT == 0 {
                break;
            }
            d = self.desc.read::<u16>(d as usize * 16 + 14);
        }
        Some((id, len))
    }
}
