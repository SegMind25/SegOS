//! PCI: finding devices, their registers (BARs) and capabilities.
//!
//! Configuration space is read through the legacy ports 0xCF8/0xCFC, which
//! every PC chipset and QEMU's q35 provide and which reach the standard
//! 256-byte header where BARs and the MSI/MSI-X and virtio capabilities
//! live. Memory BARs are mapped uncached into a kernel window.

use crate::hal::x86;
use crate::sync::SpinLock;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

const ADDR: u16 = 0xcf8;
const DATA: u16 = 0xcfc;

#[derive(Clone, Copy, Debug)]
pub struct Device {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
}

fn addr(b: u8, d: u8, f: u8, off: u8) -> u32 {
    0x8000_0000 | (b as u32) << 16 | (d as u32) << 11 | (f as u32) << 8 | (off as u32 & 0xfc)
}

static CONFIG: SpinLock<()> = SpinLock::new(());

impl Device {
    pub fn read32(&self, off: u8) -> u32 {
        let _g = CONFIG.lock();
        unsafe {
            x86::outl(ADDR, addr(self.bus, self.dev, self.func, off));
            x86::inl(DATA)
        }
    }

    pub fn write32(&self, off: u8, v: u32) {
        let _g = CONFIG.lock();
        unsafe {
            x86::outl(ADDR, addr(self.bus, self.dev, self.func, off));
            x86::outl(DATA, v);
        }
    }

    pub fn read16(&self, off: u8) -> u16 {
        (self.read32(off & !3) >> ((off & 2) * 8)) as u16
    }

    pub fn write16(&self, off: u8, v: u16) {
        let shift = (off & 2) * 8;
        let old = self.read32(off & !3);
        self.write32(off & !3, (old & !(0xffff << shift)) | (v as u32) << shift);
    }

    pub fn read8(&self, off: u8) -> u8 {
        (self.read32(off & !3) >> ((off & 3) * 8)) as u8
    }

    /// Memory space, I/O space and bus mastering (DMA) on; legacy INTx off.
    pub fn enable(&self) {
        let cmd = self.read16(4);
        self.write16(4, cmd | 0x7 | 0x400);
    }

    /// BAR `i`: (physical address, size, is memory). 64-bit BARs use two
    /// slots.
    pub fn bar(&self, i: u8) -> Option<(u64, u64, bool)> {
        let off = 0x10 + 4 * i;
        let lo = self.read32(off);
        if lo & 1 == 1 {
            self.write32(off, u32::MAX);
            let size = (!(self.read32(off) & !3)).wrapping_add(1) & 0xffff;
            self.write32(off, lo);
            return Some(((lo & !3) as u64, size as u64, false));
        }
        let is64 = (lo >> 1) & 3 == 2;
        let hi = if is64 { self.read32(off + 4) } else { 0 };
        self.write32(off, u32::MAX);
        let size_lo = self.read32(off) & !0xf;
        self.write32(off, lo);
        let mut size = (!size_lo).wrapping_add(1) as u64;
        if is64 {
            self.write32(off + 4, u32::MAX);
            let size_hi = self.read32(off + 4);
            self.write32(off + 4, hi);
            size = (!((size_hi as u64) << 32 | size_lo as u64)).wrapping_add(1);
        }
        let base = (hi as u64) << 32 | (lo & !0xf) as u64;
        (base != 0 && size != 0).then_some((base, size, true))
    }

    /// Maps memory BAR `i` (uncached) and returns its kernel address.
    pub fn map_bar(&self, i: u8) -> Option<u64> {
        let (base, size, mem) = self.bar(i)?;
        if !mem {
            return None;
        }
        Some(map_mmio(base, size))
    }

    /// Offsets of the capabilities with ID `id`.
    pub fn capabilities(&self, id: u8) -> Vec<u8> {
        let mut out = Vec::new();
        if self.read16(6) & 0x10 == 0 {
            return out;
        }
        let mut p = self.read8(0x34) & !3;
        for _ in 0..48 {
            if p == 0 {
                break;
            }
            if self.read8(p) == id {
                out.push(p);
            }
            p = self.read8(p + 1) & !3;
        }
        out
    }
}

/// Window for device registers (after the APICs).
static NEXT_MMIO: AtomicU64 = AtomicU64::new(0xffff_e000_1000_0000);

/// Maps `size` bytes of device memory at `phys`; returns the kernel address.
pub fn map_mmio(phys: u64, size: u64) -> u64 {
    let start = phys & !0xfff;
    let pages = (phys + size).div_ceil(4096) - start / 4096;
    let virt = NEXT_MMIO.fetch_add(pages * 4096 + 4096, Ordering::Relaxed);
    crate::mm::paging::map_mmio(virt, start, pages).expect("cannot map device memory");
    virt + (phys - start)
}

static DEVICES: SpinLock<Vec<Device>> = SpinLock::new(Vec::new());

pub fn devices() -> Vec<Device> {
    DEVICES.lock().clone()
}

/// Lists every PCI function.
pub fn init() {
    let mut found = Vec::new();
    for bus in 0..=255u8 {
        for dev in 0..32u8 {
            for func in 0..8u8 {
                let probe = Device {
                    bus,
                    dev,
                    func,
                    vendor: 0,
                    device: 0,
                    class: 0,
                    subclass: 0,
                    prog_if: 0,
                };
                let id = probe.read32(0);
                if id & 0xffff == 0xffff {
                    if func == 0 {
                        break;
                    }
                    continue;
                }
                let class = probe.read32(8);
                found.push(Device {
                    vendor: id as u16,
                    device: (id >> 16) as u16,
                    class: (class >> 24) as u8,
                    subclass: (class >> 16) as u8,
                    prog_if: (class >> 8) as u8,
                    ..probe
                });
                if func == 0 && probe.read8(0x0e) & 0x80 == 0 {
                    break; // single-function device
                }
            }
        }
    }
    crate::info!("pci: {} functions", found.len());
    for d in &found {
        crate::debug!(
            "  {:02x}:{:02x}.{} {:04x}:{:04x} class {:02x}.{:02x}.{:02x}",
            d.bus,
            d.dev,
            d.func,
            d.vendor,
            d.device,
            d.class,
            d.subclass,
            d.prog_if
        );
    }
    *DEVICES.lock() = found;
}
