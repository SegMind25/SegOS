//! virtio-gpu: 2D scanout on QEMU's virtio-gpu PCI device.
//!
//! Virtio 1.x over PCI (the modern interface), with split virtqueues:
//! control (0) for resource commands and cursor (1), which we leave idle.
//! A dumb buffer is exported as a 2D resource whose backing is the buffer's
//! own physical frames; showing it creates the resource once, sets it as the
//! scanout and flushes its rectangle. Commands are one at a time, completed
//! by polling the used ring.
//!
//! This complements `drm.rs`: when a virtio-gpu device is present its
//! scanout replaces the firmware framebuffer; otherwise the firmware path
//! is used. No 3D (virgl) or hardware cursor commands yet.

use super::pci;
use super::virtio_blk::{self, Mmio, common};
use crate::abi::{Errno, KResult};
use crate::mm::{PAGE_SIZE, frame, phys_to_virt};
use crate::sync::Mutex;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, Ordering, fence};

/// Modern virtio GPU is device type 16 (0x1040 + 16); 0x1001 is the
/// transitional device id, checked by its subsystem id below.
const VENDOR: u16 = 0x1af4;
const DEVICE_IDS: [u16; 2] = [0x1050, 0x1001];
const SUBSYSTEM_GPU: u16 = 16;
const QUEUE_SIZE: u16 = 64;
const CONTROL_QUEUE: u16 = 0;

// Feature bits.
const F_VERSION_1: u64 = 1 << 32;

// Control commands (`enum virtio_gpu_ctrl_type`).
const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const CMD_RESOURCE_UNREF: u32 = 0x0102;
const CMD_SET_SCANOUT: u32 = 0x0103;
const CMD_RESOURCE_FLUSH: u32 = 0x0104;
const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;

// Responses (`enum virtio_gpu_ctrl_type`).
const RESP_OK_NODATA: u32 = 0x1100;
const RESP_OK_DISPLAY_INFO: u32 = 0x1101;

/// `VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM`: XRGB8888 dumb buffers in memory.
const FORMAT_XRGB8888: u32 = 2;

// Descriptor flags.
const D_NEXT: u16 = 1;
const D_WRITE: u16 = 2;

// Maximum frames we can attach in one command: 8 pages of 256 entries.
const MAX_FRAMES: usize = 8 * 256;

// ---- Command encoding (kept separate so it can be unit-tested) ----------

fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// `struct virtio_gpu_ctrl_hdr`.
fn header(ty: u32) -> [u8; 16] {
    let mut h = [0u8; 16];
    put_u32(&mut h, 0, ty);
    h
}

/// `struct virtio_gpu_resource_create_2d`.
fn create_2d(id: u32, width: u32, height: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..16].copy_from_slice(&header(CMD_RESOURCE_CREATE_2D));
    put_u32(&mut b, 16, id);
    put_u32(&mut b, 20, FORMAT_XRGB8888);
    put_u32(&mut b, 24, width);
    put_u32(&mut b, 28, height);
    b
}

/// `struct virtio_gpu_resource_attach_backing` (mem entries follow).
fn attach_backing(id: u32, entries: u32) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[..16].copy_from_slice(&header(CMD_RESOURCE_ATTACH_BACKING));
    put_u32(&mut b, 16, id);
    put_u32(&mut b, 20, entries);
    b
}

/// `struct virtio_gpu_set_scanout`.
fn set_scanout(id: u32, width: u32, height: u32) -> [u8; 40] {
    let mut b = [0u8; 40];
    b[..16].copy_from_slice(&header(CMD_SET_SCANOUT));
    // rect = { x = 0, y = 0, width, height } at offset 16.
    put_u32(&mut b, 24, width);
    put_u32(&mut b, 28, height);
    put_u32(&mut b, 32, 0); // scanout_id
    put_u32(&mut b, 36, id); // resource_id
    b
}

/// `struct virtio_gpu_resource_flush`.
fn flush(id: u32, width: u32, height: u32) -> [u8; 40] {
    let mut b = [0u8; 40];
    b[..16].copy_from_slice(&header(CMD_RESOURCE_FLUSH));
    put_u32(&mut b, 24, width);
    put_u32(&mut b, 28, height);
    put_u32(&mut b, 32, id); // resource_id
    b
}

/// Writes one `struct virtio_gpu_mem_entry` at `off`.
fn mem_entry(b: &mut [u8], off: usize, addr: u64, len: u32) {
    put_u64(b, off, addr);
    put_u32(b, off + 8, len);
}

// ---- The control virtqueue ---------------------------------------------

struct Queue {
    /// One page: descriptors at 0, available ring at 1024, used at 2048.
    ring: u64,
    /// A page for the command and one for the response header.
    cmd: u64,
    resp: u64,
    /// Eight pages of `struct virtio_gpu_mem_entry` (2048 entries).
    data: Vec<u64>,
    notify: Mmio,
    last_used: u16,
    /// Mode from GET_DISPLAY_INFO (scanout 0).
    width: u32,
    height: u32,
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

    /// Submits the descriptor chain starting at 0 and waits for the used
    /// ring; returns the response header's `type`.
    fn submit(&mut self, n: usize) -> KResult<u32> {
        if n == 0 || n > QUEUE_SIZE as usize {
            return Err(Errno::EINVAL);
        }
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
        self.notify.w16(0, CONTROL_QUEUE);

        let mut spins: u64 = 0;
        loop {
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
                return Err(Errno::ETIMEDOUT);
            }
            core::hint::spin_loop();
        }
        fence(Ordering::SeqCst);
        Ok(unsafe { read_volatile(phys_to_virt(self.resp).cast::<u32>()) })
    }

    fn response(&mut self, n: usize) -> KResult<()> {
        match self.submit(n)? {
            RESP_OK_NODATA | RESP_OK_DISPLAY_INFO => Ok(()),
            _ => Err(Errno::EIO),
        }
    }

    /// Runs a header-only command, reusing the response page.
    fn command(&mut self, cmd: &[u8]) -> KResult<()> {
        unsafe { core::ptr::copy_nonoverlapping(cmd.as_ptr(), phys_to_virt(self.cmd), cmd.len()) };
        self.desc(0, self.cmd, cmd.len() as u32, D_NEXT, 1);
        self.desc(1, self.resp, 16, D_WRITE, 0);
        self.response(2)
    }

    /// Creates a 2D resource and attaches `frames` as its backing pages.
    fn create_resource(&mut self, id: u32, width: u32, height: u32, frames: &[u64]) -> KResult<()> {
        if frames.is_empty() || frames.len() > MAX_FRAMES {
            return Err(Errno::EINVAL);
        }
        // 1. RESOURCE_CREATE_2D.
        let create = create_2d(id, width, height);
        self.command(&create)?;

        // 2. RESOURCE_ATTACH_BACKING with one descriptor per data page.
        let attach = attach_backing(id, frames.len() as u32);
        unsafe {
            core::ptr::copy_nonoverlapping(attach.as_ptr(), phys_to_virt(self.cmd), attach.len())
        };
        self.desc(0, self.cmd, attach.len() as u32, D_NEXT, 1);

        let pages = frames.len().div_ceil(256);
        for (p, &page) in self.data.iter().enumerate().take(pages) {
            let entries = unsafe { core::slice::from_raw_parts_mut(phys_to_virt(page), 4096) };
            for (i, &f) in frames.iter().skip(p * 256).take(256).enumerate() {
                mem_entry(entries, i * 16, f, PAGE_SIZE as u32);
            }
            let len = (frames.len() - p * 256).min(256) * 16;
            let next = (p + 2) as u16;
            self.desc(p + 1, page, len as u32, D_NEXT, next);
        }
        self.desc(pages + 1, self.resp, 16, D_WRITE, 0);
        self.response(pages + 2)
    }
}

/// The GPU device, shared through `drm.rs`. `resources` maps the first
/// physical frame of a buffer to its resource id; `created` tracks which
/// ids already exist in the device.
pub(crate) struct Gpu {
    ctrl: Mutex<Queue>,
    resources: Mutex<BTreeMap<u64, u32>>,
    created: Mutex<BTreeSet<u32>>,
    next_id: AtomicU32,
}

impl Gpu {
    /// Shows a dumb buffer on scanout 0. `key` identifies the buffer and
    /// `frames` are its physical pages, attached once as the resource's
    /// backing memory.
    pub(crate) fn present(&self, key: u64, width: u32, height: u32, frames: &[u64]) -> KResult<()> {
        let id = {
            let mut r = self.resources.lock();
            match r.get(&key) {
                Some(&id) => id,
                None => {
                    let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                    r.insert(key, id);
                    id
                }
            }
        };
        let mut q = self.ctrl.lock();
        let fresh = !self.created.lock().contains(&id);
        if fresh {
            q.create_resource(id, width, height, frames)?;
            self.created.lock().insert(id);
        }
        q.command(&set_scanout(id, width, height))?;
        q.command(&flush(id, width, height))
    }
}

/// Finds a virtio-gpu device, initialises its control queue and registers
/// it as the scanout backend in `drm.rs`. Does nothing if there is none.
pub fn init() {
    for d in pci::devices() {
        if d.vendor != VENDOR || !DEVICE_IDS.contains(&d.device) {
            continue;
        }
        if d.device == 0x1001 && d.addr.read16(0x2e) != SUBSYSTEM_GPU {
            continue;
        }
        match setup(&d) {
            Ok(gpu) => {
                crate::info!("virtio-gpu: {}x{} scanout", gpu.width(), gpu.height());
                crate::drm::register_gpu(gpu);
            }
            Err(e) => crate::warn!("virtio-gpu at {:?}: {e}", d.addr),
        }
    }
}

impl Gpu {
    fn width(&self) -> u32 {
        self.ctrl.lock().width
    }
    fn height(&self) -> u32 {
        self.ctrl.lock().height
    }
}

fn setup(d: &pci::Device) -> Result<Gpu, &'static str> {
    let caps = virtio_blk::find_caps(d).ok_or("no virtio 1.x capabilities")?;
    d.enable();
    let mut bars = Vec::new();
    let common = Mmio(
        virtio_blk::map_bar(d, caps.common.0, &mut bars).ok_or("bad BAR")? + caps.common.1 as u64,
    );
    let notify_base =
        virtio_blk::map_bar(d, caps.notify.0, &mut bars).ok_or("bad BAR")? + caps.notify.1 as u64;

    common.w8(common::DEVICE_STATUS, 0);
    while common.r8(common::DEVICE_STATUS) != 0 {
        core::hint::spin_loop();
    }
    common.w8(
        common::DEVICE_STATUS,
        virtio_blk::ACKNOWLEDGE | virtio_blk::DRIVER,
    );

    let mut offered = 0u64;
    for sel in 0..2 {
        common.w32(common::DEVICE_FEATURE_SELECT, sel);
        offered |= (common.r32(common::DEVICE_FEATURE) as u64) << (32 * sel);
    }
    if offered & F_VERSION_1 == 0 {
        common.w8(common::DEVICE_STATUS, virtio_blk::FAILED);
        return Err("device does not offer VIRTIO_F_VERSION_1");
    }
    // No VIRGL: 2D scanout only, so the only driver feature is VERSION_1.
    for sel in 0..2 {
        common.w32(common::DRIVER_FEATURE_SELECT, sel);
        common.w32(common::DRIVER_FEATURE, (F_VERSION_1 >> (32 * sel)) as u32);
    }
    common.w8(
        common::DEVICE_STATUS,
        virtio_blk::ACKNOWLEDGE | virtio_blk::DRIVER | virtio_blk::FEATURES_OK,
    );
    if common.r8(common::DEVICE_STATUS) & virtio_blk::FEATURES_OK == 0 {
        common.w8(common::DEVICE_STATUS, virtio_blk::FAILED);
        return Err("features not accepted");
    }

    // Queue 0 is the control queue; queue 1 (cursor) is left disabled.
    common.w16(common::QUEUE_SELECT, CONTROL_QUEUE);
    if common.r16(common::QUEUE_SIZE) < QUEUE_SIZE {
        common.w8(common::DEVICE_STATUS, virtio_blk::FAILED);
        return Err("control queue too small");
    }
    let ring = frame::alloc_zeroed().ok_or("out of memory")?;
    let cmd = frame::alloc_zeroed().ok_or("out of memory")?;
    let resp = frame::alloc_zeroed().ok_or("out of memory")?;
    let mut data = Vec::with_capacity(8);
    for _ in 0..8 {
        data.push(frame::alloc_zeroed().ok_or("out of memory")?);
    }
    common.w16(common::QUEUE_SIZE, QUEUE_SIZE);
    common.w16(common::QUEUE_MSIX_VECTOR, 0xffff); // poll
    common.w64(common::QUEUE_DESC, ring);
    common.w64(common::QUEUE_DRIVER, ring + 1024);
    common.w64(common::QUEUE_DEVICE, ring + 2048);
    let notify_off = common.r16(common::QUEUE_NOTIFY_OFF) as u64;
    common.w16(common::QUEUE_ENABLE, 1);
    common.w8(
        common::DEVICE_STATUS,
        virtio_blk::ACKNOWLEDGE
            | virtio_blk::DRIVER
            | virtio_blk::FEATURES_OK
            | virtio_blk::DRIVER_OK,
    );

    // GET_DISPLAY_INFO on the control queue to learn the mode.
    let mut queue = Queue {
        ring,
        cmd,
        resp,
        data,
        notify: Mmio(notify_base + notify_off * caps.notify.2 as u64),
        last_used: 0,
        width: 0,
        height: 0,
    };
    let info = header(0x0100); // VIRTIO_GPU_CMD_GET_DISPLAY_INFO
    queue
        .command(&info)
        .map_err(|_| "GET_DISPLAY_INFO failed")?;
    // `struct virtio_gpu_resp_display_info`: hdr (16), then pmodes[0].r
    // = { x @16, y @20, width @24, height @28 }.
    let response = phys_to_virt(queue.resp);
    let width = unsafe { read_volatile(response.add(24).cast::<u32>()) };
    let height = unsafe { read_volatile(response.add(28).cast::<u32>()) };
    queue.width = width;
    queue.height = height;

    Ok(Gpu {
        ctrl: Mutex::new(queue),
        resources: Mutex::new(BTreeMap::new()),
        created: Mutex::new(BTreeSet::new()),
        next_id: AtomicU32::new(1),
    })
}

#[cfg(feature = "ktest")]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn create_2d_layout() {
        let c = create_2d(7, 1280, 800);
        assert_eq!(&c[..4], &0x0101u32.to_le_bytes());
        assert_eq!(&c[16..20], &7u32.to_le_bytes());
        assert_eq!(&c[20..24], &FORMAT_XRGB8888.to_le_bytes());
        assert_eq!(&c[24..28], &1280u32.to_le_bytes());
        assert_eq!(&c[28..32], &800u32.to_le_bytes());
    }

    pub(crate) fn set_scanout_layout() {
        let s = set_scanout(3, 640, 480);
        assert_eq!(&s[..4], &0x0103u32.to_le_bytes());
        assert_eq!(&s[16..20], &0u32.to_le_bytes()); // x
        assert_eq!(&s[20..24], &0u32.to_le_bytes()); // y
        assert_eq!(&s[24..28], &640u32.to_le_bytes());
        assert_eq!(&s[28..32], &480u32.to_le_bytes());
        assert_eq!(&s[32..36], &0u32.to_le_bytes()); // scanout_id
        assert_eq!(&s[36..40], &3u32.to_le_bytes()); // resource_id
    }

    pub(crate) fn flush_and_attach_layout() {
        let f = flush(9, 100, 200);
        assert_eq!(&f[..4], &0x0104u32.to_le_bytes());
        assert_eq!(&f[32..36], &9u32.to_le_bytes());
        let a = attach_backing(9, 4);
        assert_eq!(&a[..4], &0x0106u32.to_le_bytes());
        assert_eq!(&a[16..20], &9u32.to_le_bytes());
        assert_eq!(&a[20..24], &4u32.to_le_bytes());
    }

    pub(crate) fn mem_entry_layout() {
        let mut b = [0u8; 32];
        mem_entry(&mut b, 0, 0x1234_5678_9abc_def0, 4096);
        assert_eq!(&b[..8], &0x1234_5678_9abc_def0u64.to_le_bytes());
        assert_eq!(&b[8..12], &4096u32.to_le_bytes());
    }
}
