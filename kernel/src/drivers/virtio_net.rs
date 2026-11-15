//! virtio-net: the network card QEMU and other hypervisors give a virtual
//! machine (virtio 1.x over PCI, the same transport as virtio-blk).
//!
//! Two split virtqueues: receive (0), every descriptor a page the device
//! fills with a 12-byte `virtio_net_hdr` and one Ethernet frame, and
//! transmit (1). No offloads are negotiated, so the header is all zeros
//! and the stack computes every checksum. Received frames raise MSI-X
//! entry 0; the network thread sleeps on it.

use super::pci;
use super::virtio_blk::{
    ACKNOWLEDGE, DRIVER, DRIVER_OK, F_VERSION_1, FAILED, FEATURES_OK, Mmio, common, find_caps,
    map_bar,
};
use crate::mm::{frame, phys_to_virt};
use crate::net::iface::NetDevice;
use crate::sync::SpinLock;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

const VENDOR: u16 = 0x1af4;
const QUEUE_SIZE: u16 = 64;
const HDR: usize = 12;
const F_MAC: u64 = 1 << 5;
const D_WRITE: u16 = 2;

/// One virtqueue in one page: descriptors at 0, available ring at 1024,
/// used ring at 2048; `bufs[i]` is descriptor i's page.
struct Ring {
    ring: u64,
    bufs: Vec<u64>,
    notify: Mmio,
    last_used: u16,
    avail_idx: u16,
    /// Transmit: descriptors free for new frames.
    free: Vec<u16>,
}

impl Ring {
    fn new(notify: Mmio) -> Option<Self> {
        let ring = frame::alloc_zeroed()?;
        let mut bufs = Vec::new();
        for _ in 0..QUEUE_SIZE {
            bufs.push(frame::alloc_zeroed()?);
        }
        Some(Ring {
            ring,
            bufs,
            notify,
            last_used: 0,
            avail_idx: 0,
            free: (0..QUEUE_SIZE).collect(),
        })
    }

    fn desc(&self, i: u16, len: u32, flags: u16) {
        let d = phys_to_virt(self.ring + i as u64 * 16);
        unsafe {
            write_volatile(d.cast::<u64>(), self.bufs[i as usize]);
            write_volatile(d.add(8).cast::<u32>(), len);
            write_volatile(d.add(12).cast::<u16>(), flags);
            write_volatile(d.add(14).cast::<u16>(), 0);
        }
    }

    /// Makes descriptor `i` available (the caller kicks).
    fn offer(&mut self, i: u16) {
        let avail = phys_to_virt(self.ring + 1024);
        unsafe {
            write_volatile(
                avail
                    .add(4 + 2 * (self.avail_idx % QUEUE_SIZE) as usize)
                    .cast::<u16>(),
                i,
            );
            fence(Ordering::SeqCst);
            self.avail_idx = self.avail_idx.wrapping_add(1);
            write_volatile(avail.add(2).cast::<u16>(), self.avail_idx);
            fence(Ordering::SeqCst);
        }
    }

    fn kick(&self) {
        self.notify.w16(0, 0);
    }

    /// The next used descriptor: (index, bytes the device wrote).
    fn pop(&mut self) -> Option<(u16, u32)> {
        let used = phys_to_virt(self.ring + 2048);
        let idx = unsafe { read_volatile(used.add(2).cast::<u16>()) };
        if idx == self.last_used {
            return None;
        }
        fence(Ordering::SeqCst);
        let e = unsafe { used.add(4 + 8 * (self.last_used % QUEUE_SIZE) as usize) };
        let id = unsafe { read_volatile(e.cast::<u32>()) } as u16;
        let len = unsafe { read_volatile(e.add(4).cast::<u32>()) };
        self.last_used = self.last_used.wrapping_add(1);
        Some((id, len))
    }

    fn pending(&self) -> bool {
        let used = phys_to_virt(self.ring + 2048);
        unsafe { read_volatile(used.add(2).cast::<u16>()) != self.last_used }
    }
}

pub struct VirtioNet {
    mac: [u8; 6],
    rx: SpinLock<Ring>,
    tx: SpinLock<Ring>,
    irq: Option<&'static super::msi::Irq>,
}

impl NetDevice for VirtioNet {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn send(&self, frame: &[u8]) {
        if frame.len() > 4096 - HDR {
            return;
        }
        let mut tx = self.tx.lock();
        while let Some((id, _)) = tx.pop() {
            tx.free.push(id);
        }
        let Some(i) = tx.free.pop() else {
            return; // the device is behind: drop, as a full queue would
        };
        let buf = phys_to_virt(tx.bufs[i as usize]);
        unsafe {
            core::ptr::write_bytes(buf, 0, HDR);
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buf.add(HDR), frame.len());
        }
        tx.desc(i, (HDR + frame.len()) as u32, 0);
        tx.offer(i);
        tx.kick();
    }

    fn recv(&self) -> Option<Vec<u8>> {
        let mut rx = self.rx.lock();
        let (id, len) = rx.pop()?;
        let len = (len as usize).clamp(HDR, 4096);
        let buf = phys_to_virt(rx.bufs[id as usize]);
        let frame = unsafe { core::slice::from_raw_parts(buf.add(HDR), len - HDR) }.to_vec();
        rx.desc(id, 4096, D_WRITE);
        rx.offer(id);
        rx.kick();
        Some(frame)
    }

    fn rx_pending(&self) -> bool {
        self.rx.lock().pending()
    }

    fn irq(&self) -> Option<&'static super::msi::Irq> {
        self.irq
    }

    fn name(&self) -> &str {
        "virtio-net"
    }
}

fn setup(d: &pci::Device) -> Result<VirtioNet, &'static str> {
    let caps = find_caps(d).ok_or("no virtio 1.x capabilities")?;
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
        return Err("no VIRTIO_F_VERSION_1");
    }
    let wanted = offered & (F_VERSION_1 | F_MAC);
    for sel in 0..2 {
        common.w32(common::DRIVER_FEATURE_SELECT, sel);
        common.w32(common::DRIVER_FEATURE, (wanted >> (32 * sel)) as u32);
    }
    common.w8(common::DEVICE_STATUS, ACKNOWLEDGE | DRIVER | FEATURES_OK);
    if common.r8(common::DEVICE_STATUS) & FEATURES_OK == 0 {
        common.w8(common::DEVICE_STATUS, FAILED);
        return Err("features not accepted");
    }
    let mut mac = [0u8; 6];
    if wanted & F_MAC != 0 {
        for (i, b) in mac.iter_mut().enumerate() {
            *b = devcfg.r8(i);
        }
    } else {
        crate::random::fill(&mut mac);
        mac[0] = (mac[0] & 0xfe) | 0x02; // unicast, locally administered
    }
    common.w16(common::MSIX_CONFIG, 0xffff);

    let mut irq = super::msi::enable(d, 0);
    let mut rings = Vec::new();
    for q in 0..2u16 {
        common.w16(common::QUEUE_SELECT, q);
        if common.r16(common::QUEUE_SIZE) < QUEUE_SIZE {
            common.w8(common::DEVICE_STATUS, FAILED);
            return Err("queue too small");
        }
        common.w16(common::QUEUE_SIZE, QUEUE_SIZE);
        let vector = if q == 0 && irq.is_some() { 0 } else { 0xffff };
        common.w16(common::QUEUE_MSIX_VECTOR, vector);
        if q == 0 && irq.is_some() && common.r16(common::QUEUE_MSIX_VECTOR) != 0 {
            irq = None;
            common.w16(common::QUEUE_MSIX_VECTOR, 0xffff);
        }
        let notify_off = common.r16(common::QUEUE_NOTIFY_OFF) as u64;
        let ring = Ring::new(Mmio(notify_base + notify_off * caps.notify.2 as u64))
            .ok_or("out of memory")?;
        common.w64(common::QUEUE_DESC, ring.ring);
        common.w64(common::QUEUE_DRIVER, ring.ring + 1024);
        common.w64(common::QUEUE_DEVICE, ring.ring + 2048);
        common.w16(common::QUEUE_ENABLE, 1);
        rings.push(ring);
    }
    common.w8(
        common::DEVICE_STATUS,
        ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK,
    );
    let tx = rings.pop().unwrap();
    let mut rx = rings.pop().unwrap();
    for i in 0..QUEUE_SIZE {
        rx.desc(i, 4096, D_WRITE);
        rx.offer(i);
    }
    rx.free.clear();
    rx.kick();
    Ok(VirtioNet {
        mac,
        rx: SpinLock::new(rx),
        tx: SpinLock::new(tx),
        irq,
    })
}

/// Finds virtio network cards and gives them to the network stack.
pub fn init() {
    for d in pci::devices() {
        let net = d.vendor == VENDOR
            && (d.device == 0x1041 || (d.device == 0x1000 && d.addr.read16(0x2e) == 1));
        if !net {
            continue;
        }
        match setup(&d) {
            Ok(dev) => crate::net::iface::add_ethernet(Arc::new(dev)),
            Err(e) => crate::warn!("virtio-net at {:?}: {e}", d.addr),
        }
    }
}
