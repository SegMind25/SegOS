//! PCI: finding devices and reading their configuration.
//!
//! Configuration space through the legacy I/O ports 0xcf8/0xcfc (every PC
//! has them; it covers the first 256 bytes of each function, all a
//! virtio, NVMe or AHCI driver needs). PCIe's memory-mapped ECAM comes
//! when a driver needs the extended space.

use crate::hal::x86;
use crate::sync::SpinLock;
use alloc::vec::Vec;

static CONFIG_LOCK: SpinLock<()> = SpinLock::new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
}

impl Address {
    fn port_address(&self, off: u8) -> u32 {
        1 << 31
            | (self.bus as u32) << 16
            | (self.dev as u32) << 11
            | (self.func as u32) << 8
            | (off as u32 & 0xfc)
    }

    pub fn read32(&self, off: u8) -> u32 {
        let _g = CONFIG_LOCK.lock();
        unsafe {
            x86::outl(0xcf8, self.port_address(off));
            x86::inl(0xcfc)
        }
    }

    pub fn write32(&self, off: u8, v: u32) {
        let _g = CONFIG_LOCK.lock();
        unsafe {
            x86::outl(0xcf8, self.port_address(off));
            x86::outl(0xcfc, v);
        }
    }

    pub fn read16(&self, off: u8) -> u16 {
        (self.read32(off) >> ((off & 2) * 8)) as u16
    }

    pub fn read8(&self, off: u8) -> u8 {
        (self.read32(off) >> ((off & 3) * 8)) as u8
    }

    pub fn write16(&self, off: u8, v: u16) {
        let shift = (off & 2) * 8;
        let old = self.read32(off);
        self.write32(off, (old & !(0xffff << shift)) | (v as u32) << shift);
    }
}

#[derive(Clone, Debug)]
pub struct Device {
    pub addr: Address,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
}

/// A base address register, decoded.
#[derive(Clone, Copy, Debug)]
pub enum Bar {
    Memory { addr: u64, size: u64 },
    Io { port: u16, size: u32 },
}

impl Device {
    /// Lets the device read and write memory (DMA) and decode its BARs.
    pub fn enable(&self) {
        let cmd = self.addr.read16(0x04);
        // I/O space, memory space, bus master; INTx off (we poll or use MSI).
        self.addr.write16(0x04, cmd | 0b111 | 1 << 10);
    }

    /// BAR `n` (0..=5), with its size probed (memory decoding is turned off
    /// meanwhile, as the specification asks).
    pub fn bar(&self, n: u8) -> Option<Bar> {
        let off = 0x10 + 4 * n;
        let lo = self.addr.read32(off);
        if lo == 0 {
            return None;
        }
        let cmd = self.addr.read16(0x04);
        self.addr.write16(0x04, cmd & !0b11);
        let bar = if lo & 1 == 1 {
            self.addr.write32(off, !0);
            let size = !(self.addr.read32(off) & !0x3) + 1;
            self.addr.write32(off, lo);
            Some(Bar::Io {
                port: (lo & !0x3) as u16,
                size: size & 0xffff,
            })
        } else {
            let is64 = (lo >> 1) & 0x3 == 2;
            let hi = if is64 { self.addr.read32(off + 4) } else { 0 };
            self.addr.write32(off, !0);
            let mut mask = (self.addr.read32(off) & !0xf) as u64;
            if is64 {
                self.addr.write32(off + 4, !0);
                mask |= (self.addr.read32(off + 4) as u64) << 32;
                self.addr.write32(off + 4, hi);
            } else {
                mask |= 0xffff_ffff_0000_0000;
            }
            self.addr.write32(off, lo);
            let addr = (lo & !0xf) as u64 | (hi as u64) << 32;
            Some(Bar::Memory {
                addr,
                size: !mask + 1,
            })
        };
        self.addr.write16(0x04, cmd);
        bar
    }

    /// Offsets of the capabilities with ID `id` in the capability list.
    pub fn capabilities(&self, id: u8) -> Vec<u8> {
        let mut out = Vec::new();
        if self.addr.read16(0x06) & 1 << 4 == 0 {
            return out;
        }
        let mut p = self.addr.read8(0x34) & !3;
        let mut guard = 0;
        while p != 0 && guard < 48 {
            if self.addr.read8(p) == id {
                out.push(p);
            }
            p = self.addr.read8(p + 1) & !3;
            guard += 1;
        }
        out
    }
}

static DEVICES: SpinLock<Vec<Device>> = SpinLock::new(Vec::new());

fn probe(addr: Address) -> Option<Device> {
    let id = addr.read32(0);
    if id & 0xffff == 0xffff {
        return None;
    }
    let class = addr.read32(0x08);
    Some(Device {
        addr,
        vendor: id as u16,
        device: (id >> 16) as u16,
        class: (class >> 24) as u8,
        subclass: (class >> 16) as u8,
        prog_if: (class >> 8) as u8,
    })
}

/// Scans every bus, device and function.
pub fn init() {
    let mut found = Vec::new();
    for bus in 0..=255u8 {
        for dev in 0..32u8 {
            let Some(d0) = probe(Address { bus, dev, func: 0 }) else {
                continue;
            };
            let multi = d0.addr.read8(0x0e) & 0x80 != 0;
            found.push(d0);
            if multi {
                for func in 1..8 {
                    if let Some(d) = probe(Address { bus, dev, func }) {
                        found.push(d);
                    }
                }
            }
        }
    }
    for d in &found {
        crate::debug!(
            "pci: {:02x}:{:02x}.{} {:04x}:{:04x} class {:02x}{:02x}{:02x}",
            d.addr.bus,
            d.addr.dev,
            d.addr.func,
            d.vendor,
            d.device,
            d.class,
            d.subclass,
            d.prog_if
        );
    }
    crate::info!("pci: {} functions", found.len());
    *DEVICES.lock() = found;
}

pub fn devices() -> Vec<Device> {
    DEVICES.lock().clone()
}
