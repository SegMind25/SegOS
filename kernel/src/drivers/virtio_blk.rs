//! virtio-blk: the disk QEMU and other hypervisors give a virtual machine.
//!
//! Virtio 1.x over PCI ("modern" interface: configuration structures found
//! through vendor capabilities, in memory BARs). One split virtqueue, one
//! request at a time, completion polled. Data goes through bounce pages
//! the device can reach by physical address. Interrupts (MSI-X) and
//! several requests in flight come with the page cache's write-back.

use super::pci::{self, Bar};
use crate::abi::{Errno, KResult};
use crate::block::{self, BlockDevice, SECTOR_SIZE};
use crate::mm::{PAGE_SIZE, frame, paging, phys_to_virt};
use crate::sync::Mutex;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, Ordering, fence};

const VENDOR: u16 = 0x1af4;
/// Modern device ID (0x1040 + type 2), and the transitional one.
const DEVICE_IDS: [u16; 2] = [0x1042, 0x1001];

const QUEUE_SIZE: u16 = 64;
/// Most data pages one request carries (128 KiB).
const MAX_PAGES: usize = 32;

// Status bits.
const ACKNOWLEDGE: u8 = 1;
const DRIVER: u8 = 2;
const DRIVER_OK: u8 = 4;
const FEATURES_OK: u8 = 8;
const FAILED: u8 = 128;

// Feature bits.
const F_RO: u64 = 1 << 5;
const F_FLUSH: u64 = 1 << 9;
const F_VERSION_1: u64 = 1 << 32;

// Request types.
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;

// Descriptor flags.
const D_NEXT: u16 = 1;
const D_WRITE: u16 = 2;

/// Linux's major for virtio disks varies; 254 is what it usually gets.
const MAJOR: u32 = 254;
static NEXT_DISK: AtomicU32 = AtomicU32::new(0);

/// Common configuration structure offsets (virtio 1.2, 4.1.4.3).
mod common {
    pub const DEVICE_FEATURE_SELECT: usize = 0;
    pub const DEVICE_FEATURE: usize = 4;
    pub const DRIVER_FEATURE_SELECT: usize = 8;
    pub const DRIVER_FEATURE: usize = 12;
    pub const DEVICE_STATUS: usize = 20;
    pub const QUEUE_SELECT: usize = 22;
    pub const QUEUE_SIZE: usize = 24;
    pub const QUEUE_MSIX_VECTOR: usize = 26;
    pub const QUEUE_ENABLE: usize = 28;
    pub const QUEUE_NOTIFY_OFF: usize = 30;
    pub const QUEUE_DESC: usize = 32;
    pub const QUEUE_DRIVER: usize = 40;
    pub const QUEUE_DEVICE: usize = 48;
}

#[derive(Clone, Copy)]
struct Mmio(u64);

impl Mmio {
    fn r8(self, off: usize) -> u8 {
        unsafe { read_volatile((self.0 + off as u64) as *const u8) }
    }
    fn r16(self, off: usize) -> u16 {
        unsafe { read_volatile((self.0 + off as u64) as *const u16) }
    }
    fn r32(self, off: usize) -> u32 {
        unsafe { read_volatile((self.0 + off as u64) as *const u32) }
    }
    fn w8(self, off: usize, v: u8) {
        unsafe { write_volatile((self.0 + off as u64) as *mut u8, v) }
    }
    fn w16(self, off: usize, v: u16) {
        unsafe { write_volatile((self.0 + off as u64) as *mut u16, v) }
    }
    fn w32(self, off: usize, v: u32) {
        unsafe { write_volatile((self.0 + off as u64) as *mut u32, v) }
    }
    fn w64(self, off: usize, v: u64) {
        self.w32(off, v as u32);
        self.w32(off + 4, (v >> 32) as u32);
    }
}

/// The virtqueue and the request's own pages; behind the device's mutex.
struct Queue {
    /// One page: descriptors at 0, available ring at 1024, used ring at 2048.
    ring: u64,
    /// Header (16 bytes) at 0, status byte at 16.
    req: u64,
    data: [u64; MAX_PAGES],
    notify: Mmio,
    last_used: u16,
    /// The queue's MSI-X interrupt; None means polling.
    irq: Option<&'static super::msi::Irq>,
}

impl Queue {
    fn desc(&self, i: usize, addr: u64, len: u32, flags: u16, next: u16) {
        let d = phys_to_virt(self.ring + i as u64 * 16);
        unsafe {
            write_volatile(d.cast::<u64>(), addr);
            write_volatile(d.add(8).cast::<u32>(), len);
            write_volatile(d.add(12).cast::<u16>(), flags);
            write_volatile(d.add(14).cast::<u16>(), next);
        }
    }

    /// Submits the chain starting at descriptor 0 and waits for it.
    fn submit_and_wait(&mut self) -> KResult<()> {
        let avail = phys_to_virt(self.ring + 1024);
        let used = phys_to_virt(self.ring + 2048);
        unsafe {
            let idx = read_volatile(avail.add(2).cast::<u16>());
            write_volatile(
                avail.add(4 + 2 * (idx % QUEUE_SIZE) as usize).cast::<u16>(),
                0,
            );
            fence(Ordering::SeqCst);
            write_volatile(avail.add(2).cast::<u16>(), idx.wrapping_add(1));
            fence(Ordering::SeqCst);
        }
        self.notify.w16(0, 0);
        if let Some(irq) = self.irq {
            let last = self.last_used;
            let done = || unsafe { read_volatile(used.add(2).cast::<u16>()) } != last;
            if !irq.wait(done, 30_000) {
                return Err(Errno::EIO);
            }
            self.last_used = unsafe { read_volatile(used.add(2).cast::<u16>()) };
        }
        let mut spins: u64 = 0;
        while self.irq.is_none() {
            let used_idx = unsafe { read_volatile(used.add(2).cast::<u16>()) };
            if used_idx != self.last_used {
                self.last_used = used_idx;
                break;
            }
            spins += 1;
            if spins.is_multiple_of(1024) {
                crate::task::yield_now();
            }
            if spins > 200_000_000 {
                return Err(Errno::EIO);
            }
            core::hint::spin_loop();
        }
        fence(Ordering::SeqCst);
        let status = unsafe { read_volatile(phys_to_virt(self.req + 16)) };
        if status == 0 { Ok(()) } else { Err(Errno::EIO) }
    }

    /// One request: header, `pages` data pages (`len` bytes in all), status.
    fn request(&mut self, ty: u32, sector: u64, len: usize, device_writes: bool) -> KResult<()> {
        let hdr = phys_to_virt(self.req);
        unsafe {
            write_volatile(hdr.cast::<u32>(), ty);
            write_volatile(hdr.add(4).cast::<u32>(), 0);
            write_volatile(hdr.add(8).cast::<u64>(), sector);
            write_volatile(hdr.add(16), 0xff);
        }
        self.desc(0, self.req, 16, D_NEXT, 1);
        let pages = len.div_ceil(PAGE_SIZE as usize);
        let mut left = len;
        for p in 0..pages {
            let chunk = left.min(PAGE_SIZE as usize);
            let flags = D_NEXT | if device_writes { D_WRITE } else { 0 };
            self.desc(1 + p, self.data[p], chunk as u32, flags, 2 + p as u16);
            left -= chunk;
        }
        self.desc(1 + pages, self.req + 16, 1, D_WRITE, 0);
        self.submit_and_wait()
    }
}

pub struct VirtioBlk {
    name: String,
    sectors: u64,
    read_only: bool,
    can_flush: bool,
    rdev: u64,
    queue: Mutex<Queue>,
}

impl BlockDevice for VirtioBlk {
    fn name(&self) -> &str {
        &self.name
    }
    fn sector_count(&self) -> u64 {
        self.sectors
    }
    fn read_only(&self) -> bool {
        self.read_only
    }
    fn rdev(&self) -> u64 {
        self.rdev
    }

    fn read_sectors(&self, lba: u64, buf: &mut [u8]) -> KResult<()> {
        check(self, lba, buf.len())?;
        let mut q = self.queue.lock();
        for (i, chunk) in buf.chunks_mut(MAX_PAGES * PAGE_SIZE as usize).enumerate() {
            let sector = lba + (i * MAX_PAGES * PAGE_SIZE as usize / SECTOR_SIZE) as u64;
            q.request(T_IN, sector, chunk.len(), true)?;
            for (p, part) in chunk.chunks_mut(PAGE_SIZE as usize).enumerate() {
                let src = phys_to_virt(q.data[p]);
                unsafe { core::ptr::copy_nonoverlapping(src, part.as_mut_ptr(), part.len()) };
            }
        }
        Ok(())
    }

    fn write_sectors(&self, lba: u64, data: &[u8]) -> KResult<()> {
        if self.read_only {
            return Err(Errno::EROFS);
        }
        check(self, lba, data.len())?;
        let mut q = self.queue.lock();
        for (i, chunk) in data.chunks(MAX_PAGES * PAGE_SIZE as usize).enumerate() {
            let sector = lba + (i * MAX_PAGES * PAGE_SIZE as usize / SECTOR_SIZE) as u64;
            for (p, part) in chunk.chunks(PAGE_SIZE as usize).enumerate() {
                let dst = phys_to_virt(q.data[p]);
                unsafe { core::ptr::copy_nonoverlapping(part.as_ptr(), dst, part.len()) };
            }
            q.request(T_OUT, sector, chunk.len(), false)?;
        }
        Ok(())
    }

    fn flush(&self) -> KResult<()> {
        if !self.can_flush {
            return Ok(());
        }
        let mut q = self.queue.lock();
        // Header and status only.
        let hdr = phys_to_virt(q.req);
        unsafe {
            write_volatile(hdr.cast::<u32>(), T_FLUSH);
            write_volatile(hdr.add(8).cast::<u64>(), 0);
            write_volatile(hdr.add(16), 0xff);
        }
        let req = q.req;
        q.desc(0, req, 16, D_NEXT, 1);
        q.desc(1, req + 16, 1, D_WRITE, 0);
        q.submit_and_wait()
    }
}

fn check(dev: &VirtioBlk, lba: u64, len: usize) -> KResult<()> {
    if len == 0
        || !len.is_multiple_of(SECTOR_SIZE)
        || lba + (len / SECTOR_SIZE) as u64 > dev.sectors
    {
        return Err(Errno::EIO);
    }
    Ok(())
}

/// Where each configuration structure is: (BAR, offset, length), and the
/// notify offset multiplier.
struct Caps {
    common: (u8, u32),
    notify: (u8, u32, u32),
    device: (u8, u32),
}

fn find_caps(d: &pci::Device) -> Option<Caps> {
    let (mut common, mut notify, mut device) = (None, None, None);
    for off in d.capabilities(0x09) {
        let a = d.addr;
        let cfg_type = a.read8(off + 3);
        let bar = a.read8(off + 4);
        let offset = a.read32(off + 8);
        match cfg_type {
            1 if common.is_none() => common = Some((bar, offset)),
            2 if notify.is_none() => notify = Some((bar, offset, a.read32(off + 16))),
            4 if device.is_none() => device = Some((bar, offset)),
            _ => {}
        }
    }
    Some(Caps {
        common: common?,
        notify: notify?,
        device: device?,
    })
}

fn map_bar(d: &pci::Device, n: u8, cache: &mut Vec<(u8, u64)>) -> Option<u64> {
    if let Some(&(_, v)) = cache.iter().find(|(b, _)| *b == n) {
        return Some(v);
    }
    let Bar::Memory { addr, size } = d.bar(n)? else {
        return None;
    };
    let virt = paging::map_device(addr, size).ok()?;
    cache.push((n, virt));
    Some(virt)
}

fn setup(d: &pci::Device) -> Result<VirtioBlk, &'static str> {
    let caps = find_caps(d).ok_or("no virtio 1.x capabilities (legacy-only device)")?;
    d.enable();
    let mut bars = Vec::new();
    let common =
        Mmio(map_bar(d, caps.common.0, &mut bars).ok_or("bad BAR")? + caps.common.1 as u64);
    let notify_base = map_bar(d, caps.notify.0, &mut bars).ok_or("bad BAR")? + caps.notify.1 as u64;
    let devcfg =
        Mmio(map_bar(d, caps.device.0, &mut bars).ok_or("bad BAR")? + caps.device.1 as u64);

    common.w8(common::DEVICE_STATUS, 0);
    while common.r8(common::DEVICE_STATUS) != 0 {
        core::hint::spin_loop();
    }
    common.w8(common::DEVICE_STATUS, ACKNOWLEDGE | DRIVER);

    let mut offered = 0u64;
    for sel in 0..2 {
        common.w32(common::DEVICE_FEATURE_SELECT, sel);
        offered |= (common.r32(common::DEVICE_FEATURE) as u64) << (32 * sel);
    }
    if offered & F_VERSION_1 == 0 {
        common.w8(common::DEVICE_STATUS, FAILED);
        return Err("device does not offer VIRTIO_F_VERSION_1");
    }
    let wanted = offered & (F_VERSION_1 | F_RO | F_FLUSH);
    for sel in 0..2 {
        common.w32(common::DRIVER_FEATURE_SELECT, sel);
        common.w32(common::DRIVER_FEATURE, (wanted >> (32 * sel)) as u32);
    }
    common.w8(common::DEVICE_STATUS, ACKNOWLEDGE | DRIVER | FEATURES_OK);
    if common.r8(common::DEVICE_STATUS) & FEATURES_OK == 0 {
        common.w8(common::DEVICE_STATUS, FAILED);
        return Err("features not accepted");
    }

    common.w16(common::QUEUE_SELECT, 0);
    let max = common.r16(common::QUEUE_SIZE);
    if max < QUEUE_SIZE {
        common.w8(common::DEVICE_STATUS, FAILED);
        return Err("queue too small");
    }
    let ring = frame::alloc_zeroed().ok_or("out of memory")?;
    let req = frame::alloc_zeroed().ok_or("out of memory")?;
    let mut data = [0u64; MAX_PAGES];
    for p in data.iter_mut() {
        *p = frame::alloc_zeroed().ok_or("out of memory")?;
    }
    common.w16(common::QUEUE_SIZE, QUEUE_SIZE);
    // Completion interrupts through MSI-X entry 0 when the device has it.
    let mut irq = super::msi::enable(d, 0);
    common.w16(
        common::QUEUE_MSIX_VECTOR,
        if irq.is_some() { 0 } else { 0xffff },
    );
    if irq.is_some() && common.r16(common::QUEUE_MSIX_VECTOR) != 0 {
        irq = None; // the device refused the vector
        common.w16(common::QUEUE_MSIX_VECTOR, 0xffff);
    }
    common.w64(common::QUEUE_DESC, ring);
    common.w64(common::QUEUE_DRIVER, ring + 1024);
    common.w64(common::QUEUE_DEVICE, ring + 2048);
    let notify_off = common.r16(common::QUEUE_NOTIFY_OFF) as u64;
    common.w16(common::QUEUE_ENABLE, 1);
    common.w8(
        common::DEVICE_STATUS,
        ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK,
    );

    let capacity = devcfg.r32(0) as u64 | (devcfg.r32(4) as u64) << 32;
    let n = NEXT_DISK.fetch_add(1, Ordering::Relaxed);
    Ok(VirtioBlk {
        name: format!("vd{}", (b'a' + n as u8) as char),
        sectors: capacity,
        read_only: wanted & F_RO != 0,
        can_flush: wanted & F_FLUSH != 0,
        rdev: crate::fs::dev::makedev(MAJOR, n * 16),
        queue: Mutex::new(Queue {
            ring,
            req,
            data,
            notify: Mmio(notify_base + notify_off * caps.notify.2 as u64),
            last_used: 0,
            irq,
        }),
    })
}

/// Finds every virtio block device and registers it.
pub fn init() {
    for d in pci::devices() {
        if d.vendor != VENDOR || !DEVICE_IDS.contains(&d.device) {
            continue;
        }
        // Transitional devices are block devices only if their subsystem says so.
        if d.device == 0x1001 || d.addr.read16(0x2e) == 2 || d.device == 0x1042 {
            match setup(&d) {
                Ok(dev) => {
                    let minor = (dev.rdev & 0xff) as u32;
                    block::register_disk(Arc::new(dev), MAJOR, minor);
                }
                Err(e) => crate::warn!("virtio-blk at {:?}: {e}", d.addr),
            }
        }
    }
}
