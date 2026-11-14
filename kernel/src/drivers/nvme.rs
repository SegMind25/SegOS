//! NVMe: PCI Express solid-state disks.
//!
//! One admin queue pair and one I/O queue pair per controller, one command
//! at a time, completion polled (the I/O completion queue is created with
//! interrupts off). Data goes through bounce pages described by PRP
//! entries (a PRP list page past two pages). Each active namespace with
//! 512- or 4096-byte blocks and no metadata becomes a disk, `nvme0n1`, …;
//! on 4096-byte namespaces the 512-byte sector interface is translated,
//! with read-modify-write of partial blocks.

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

/// Linux's "blkext" major, where NVMe namespaces live.
const MAJOR: u32 = 259;
static NEXT_DISK: AtomicU32 = AtomicU32::new(0);
static NEXT_CTRL: AtomicU32 = AtomicU32::new(0);

/// Most data pages one command carries (128 KiB).
const MAX_PAGES: usize = 32;
const ADMIN_QUEUE_SIZE: u16 = 16;
const IO_QUEUE_SIZE: u16 = 64;
const PAGE: usize = PAGE_SIZE as usize;
/// How long one command may take before it counts as failed.
const COMMAND_TIMEOUT_MS: u64 = 30_000;

// Controller registers.
const REG_CAP: usize = 0x00;
const REG_VS: usize = 0x08;
const REG_INTMS: usize = 0x0c;
const REG_CC: usize = 0x14;
const REG_CSTS: usize = 0x1c;
const REG_AQA: usize = 0x24;
const REG_ASQ: usize = 0x28;
const REG_ACQ: usize = 0x30;
const DOORBELLS: usize = 0x1000;

const CC_EN: u32 = 1;
/// I/O submission entries of 64 bytes, completion entries of 16.
const CC_IOSQES: u32 = 6 << 16;
const CC_IOCQES: u32 = 4 << 20;
const CSTS_RDY: u32 = 1;
const CSTS_CFS: u32 = 2;

// Admin opcodes.
const ADMIN_CREATE_SQ: u8 = 0x01;
const ADMIN_CREATE_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;

// NVM opcodes.
const IO_FLUSH: u8 = 0x00;
const IO_WRITE: u8 = 0x01;
const IO_READ: u8 = 0x02;

#[derive(Clone, Copy)]
struct Mmio(u64);

impl Mmio {
    fn r32(self, off: usize) -> u32 {
        unsafe { read_volatile((self.0 + off as u64) as *const u32) }
    }
    fn r64(self, off: usize) -> u64 {
        self.r32(off) as u64 | (self.r32(off + 4) as u64) << 32
    }
    fn w32(self, off: usize, v: u32) {
        unsafe { write_volatile((self.0 + off as u64) as *mut u32, v) }
    }
    fn w64(self, off: usize, v: u64) {
        self.w32(off, v as u32);
        self.w32(off + 4, (v >> 32) as u32);
    }
}

/// Polls `done` until it holds or `timeout_ms` passes, yielding the CPU
/// now and then.
fn poll(timeout_ms: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = crate::time::uptime_ms() + timeout_ms;
    let mut spins: u64 = 0;
    loop {
        if done() {
            return true;
        }
        spins += 1;
        if spins.is_multiple_of(1024) {
            if crate::time::uptime_ms() > deadline {
                return done();
            }
            crate::task::yield_now();
        }
        core::hint::spin_loop();
    }
}

/// A submission queue and its completion queue.
struct QueuePair {
    regs: Mmio,
    sq: u64,
    cq: u64,
    size: u16,
    sq_tail: u16,
    cq_head: u16,
    phase: bool,
    sq_doorbell: usize,
    cq_doorbell: usize,
    next_cid: u16,
    /// MSI-X interrupt of its completion queue; None means polling.
    irq: Option<&'static super::msi::Irq>,
}

impl QueuePair {
    fn new(regs: Mmio, qid: usize, size: u16, stride: usize) -> Option<QueuePair> {
        Some(QueuePair {
            regs,
            sq: frame::alloc_zeroed()?,
            cq: frame::alloc_zeroed()?,
            size,
            sq_tail: 0,
            cq_head: 0,
            irq: None,
            phase: true,
            sq_doorbell: DOORBELLS + 2 * qid * stride,
            cq_doorbell: DOORBELLS + (2 * qid + 1) * stride,
            next_cid: 0,
        })
    }

    /// Submits one command (dwords 0..16, CID filled in) and waits for its
    /// completion; returns completion dword 0.
    fn run(&mut self, mut cmd: [u32; 16]) -> KResult<u32> {
        let regs = self.regs;
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        cmd[0] = (cmd[0] & 0xffff) | (cid as u32) << 16;
        let slot = phys_to_virt(self.sq + self.sq_tail as u64 * 64).cast::<u32>();
        for (i, &dw) in cmd.iter().enumerate() {
            unsafe { write_volatile(slot.add(i), dw) };
        }
        self.sq_tail = (self.sq_tail + 1) % self.size;
        fence(Ordering::SeqCst);
        regs.w32(self.sq_doorbell, self.sq_tail as u32);

        let entry = phys_to_virt(self.cq + self.cq_head as u64 * 16).cast::<u32>();
        let phase = self.phase;
        let done = || {
            let dw3 = unsafe { read_volatile(entry.add(3)) };
            (dw3 >> 16) & 1 == phase as u32
        };
        let arrived = match self.irq {
            Some(irq) => irq.wait(done, COMMAND_TIMEOUT_MS),
            None => poll(COMMAND_TIMEOUT_MS, done),
        };
        if !arrived {
            crate::warn!("nvme: command {:#x} timed out", cmd[0] & 0xff);
            return Err(Errno::EIO);
        }
        fence(Ordering::SeqCst);
        let dw0 = unsafe { read_volatile(entry) };
        let dw3 = unsafe { read_volatile(entry.add(3)) };
        self.cq_head += 1;
        if self.cq_head == self.size {
            self.cq_head = 0;
            self.phase = !self.phase;
        }
        regs.w32(self.cq_doorbell, self.cq_head as u32);
        let status = (dw3 >> 17) & 0x7fff;
        if dw3 & 0xffff != cid as u32 || status != 0 {
            crate::warn!(
                "nvme: command {:#x} failed: status {status:#x}",
                cmd[0] & 0xff
            );
            return Err(Errno::EIO);
        }
        Ok(dw0)
    }
}

/// Everything behind the controller's mutex: queues and bounce pages.
struct Queues {
    admin: QueuePair,
    io: QueuePair,
    /// Bounce pages, and a PRP list naming `data[1..]`.
    data: [u64; MAX_PAGES],
    prp_list: u64,
}

impl Queues {
    /// Points PRP1/PRP2 of `cmd` at `bytes` of bounce memory starting with
    /// page `first` (only page 0 may start a transfer over two pages).
    fn prps(&self, cmd: &mut [u32; 16], first: usize, bytes: usize) {
        let prp1 = self.data[first];
        let prp2 = match bytes.div_ceil(PAGE) {
            0 | 1 => 0,
            2 => self.data[first + 1],
            _ => {
                debug_assert_eq!(first, 0);
                self.prp_list
            }
        };
        cmd[6] = prp1 as u32;
        cmd[7] = (prp1 >> 32) as u32;
        cmd[8] = prp2 as u32;
        cmd[9] = (prp2 >> 32) as u32;
    }

    fn rw(
        &mut self,
        op: u8,
        nsid: u32,
        slba: u64,
        blocks: u32,
        first: usize,
        bytes: usize,
    ) -> KResult<()> {
        let mut cmd = [0u32; 16];
        cmd[0] = op as u32;
        cmd[1] = nsid;
        self.prps(&mut cmd, first, bytes);
        cmd[10] = slba as u32;
        cmd[11] = (slba >> 32) as u32;
        cmd[12] = blocks - 1;
        self.io.run(cmd).map(|_| ())
    }

    fn identify(&mut self, cns: u32, nsid: u32) -> KResult<*const u8> {
        let mut cmd = [0u32; 16];
        cmd[0] = ADMIN_IDENTIFY as u32;
        cmd[1] = nsid;
        self.prps(&mut cmd, 0, PAGE);
        cmd[10] = cns;
        self.admin.run(cmd)?;
        Ok(phys_to_virt(self.data[0]))
    }

    fn copy_out(&self, off: usize, dst: &mut [u8]) {
        let mut done = 0;
        while done < dst.len() {
            let pos = off + done;
            let n = (PAGE - pos % PAGE).min(dst.len() - done);
            let src = unsafe { phys_to_virt(self.data[pos / PAGE]).add(pos % PAGE) };
            unsafe { core::ptr::copy_nonoverlapping(src, dst[done..].as_mut_ptr(), n) };
            done += n;
        }
    }

    fn copy_in(&self, off: usize, src: &[u8]) {
        let mut done = 0;
        while done < src.len() {
            let pos = off + done;
            let n = (PAGE - pos % PAGE).min(src.len() - done);
            let dst = unsafe { phys_to_virt(self.data[pos / PAGE]).add(pos % PAGE) };
            unsafe { core::ptr::copy_nonoverlapping(src[done..].as_ptr(), dst, n) };
            done += n;
        }
    }
}

struct Controller {
    regs: Mmio,
    /// Most bytes in one command (bounce pages and the controller's MDTS).
    max_bytes: usize,
    queues: Mutex<Queues>,
}

/// One namespace: a disk.
pub struct Namespace {
    ctrl: Arc<Controller>,
    nsid: u32,
    name: String,
    /// log2 of the block size: 9 or 12.
    block_shift: u32,
    /// Size in 512-byte sectors.
    sectors: u64,
    rdev: u64,
}

impl Namespace {
    fn check(&self, lba: u64, len: usize) -> KResult<()> {
        if len == 0
            || !len.is_multiple_of(SECTOR_SIZE)
            || lba + (len / SECTOR_SIZE) as u64 > self.sectors
        {
            return Err(Errno::EIO);
        }
        Ok(())
    }

    /// Splits the byte range `[off, off + len)` into commands: calls `f`
    /// with the block-aligned range `[start, end)` each covers and the part
    /// `[seg, seg_end)` of the request inside it.
    fn segments(
        &self,
        off: u64,
        len: usize,
        mut f: impl FnMut(u64, u64, u64, u64) -> KResult<()>,
    ) -> KResult<()> {
        let bs = 1u64 << self.block_shift;
        let end_all = off + len as u64;
        let mut pos = off;
        while pos < end_all {
            let start = pos & !(bs - 1);
            let end = (end_all.next_multiple_of(bs)).min(start + self.ctrl.max_bytes as u64);
            let seg_end = end.min(end_all);
            f(start, end, pos, seg_end)?;
            pos = seg_end;
        }
        Ok(())
    }
}

impl BlockDevice for Namespace {
    fn name(&self) -> &str {
        &self.name
    }
    fn sector_count(&self) -> u64 {
        self.sectors
    }
    fn rdev(&self) -> u64 {
        self.rdev
    }

    fn read_sectors(&self, lba: u64, buf: &mut [u8]) -> KResult<()> {
        self.check(lba, buf.len())?;
        let shift = self.block_shift;
        let base = lba * SECTOR_SIZE as u64;
        let mut q = self.ctrl.queues.lock();
        self.segments(base, buf.len(), |start, end, seg, seg_end| {
            let bytes = (end - start) as usize;
            q.rw(
                IO_READ,
                self.nsid,
                start >> shift,
                (bytes >> shift) as u32,
                0,
                bytes,
            )?;
            let dst = &mut buf[(seg - base) as usize..(seg_end - base) as usize];
            q.copy_out((seg - start) as usize, dst);
            Ok(())
        })
    }

    fn write_sectors(&self, lba: u64, data: &[u8]) -> KResult<()> {
        self.check(lba, data.len())?;
        let shift = self.block_shift;
        let bs = 1u64 << shift;
        let base = lba * SECTOR_SIZE as u64;
        let mut q = self.ctrl.queues.lock();
        self.segments(base, data.len(), |start, end, seg, seg_end| {
            // Partial blocks at either end: read them first (4 KiB blocks
            // only, and then a block is exactly one bounce page).
            if seg > start {
                q.rw(IO_READ, self.nsid, start >> shift, 1, 0, bs as usize)?;
            }
            let last = end - bs;
            if seg_end < end && !(seg > start && last == start) {
                let page = ((last - start) as usize) / PAGE;
                q.rw(IO_READ, self.nsid, last >> shift, 1, page, bs as usize)?;
            }
            q.copy_in(
                (seg - start) as usize,
                &data[(seg - base) as usize..(seg_end - base) as usize],
            );
            let bytes = (end - start) as usize;
            q.rw(
                IO_WRITE,
                self.nsid,
                start >> shift,
                (bytes >> shift) as u32,
                0,
                bytes,
            )
        })
    }

    fn flush(&self) -> KResult<()> {
        let mut q = self.ctrl.queues.lock();
        let mut cmd = [0u32; 16];
        cmd[0] = IO_FLUSH as u32;
        cmd[1] = self.nsid;
        q.io.run(cmd).map(|_| ())
    }
}

fn read_u64(p: *const u8, off: usize) -> u64 {
    unsafe { core::ptr::read_unaligned(p.add(off).cast::<u64>()) }
}
fn read_u32(p: *const u8, off: usize) -> u32 {
    unsafe { core::ptr::read_unaligned(p.add(off).cast::<u32>()) }
}

fn setup(d: &pci::Device) -> Result<(), &'static str> {
    let Some(Bar::Memory { addr, size }) = d.bar(0) else {
        return Err("BAR0 is not a memory BAR");
    };
    d.enable();
    let regs = Mmio(paging::map_device(addr, size.max(0x2000)).map_err(|_| "cannot map BAR0")?);

    let cap = regs.r64(REG_CAP);
    let mqes = (cap & 0xffff) as u16 + 1;
    let timeout_ms = ((cap >> 24) & 0xff).max(1) * 500;
    let stride = 4usize << ((cap >> 32) & 0xf);
    if (cap >> 37) & 1 == 0 {
        return Err("controller lacks the NVM command set");
    }
    if (cap >> 48) & 0xf != 0 {
        return Err("controller does not support 4 KiB pages");
    }
    let vs = regs.r32(REG_VS);

    // Reset: disable and wait for not-ready.
    if regs.r32(REG_CC) & CC_EN != 0 {
        poll(timeout_ms, || regs.r32(REG_CSTS) & CSTS_RDY != 0);
        regs.w32(REG_CC, 0);
    }
    if !poll(timeout_ms, || regs.r32(REG_CSTS) & CSTS_RDY == 0) {
        return Err("controller did not reset");
    }

    let admin_size = ADMIN_QUEUE_SIZE.min(mqes);
    let io_size = IO_QUEUE_SIZE.min(mqes);
    let oom = "out of memory";
    let admin = QueuePair::new(regs, 0, admin_size, stride).ok_or(oom)?;
    let io = QueuePair::new(regs, 1, io_size, stride).ok_or(oom)?;
    let mut data = [0u64; MAX_PAGES];
    for p in data.iter_mut() {
        *p = frame::alloc_zeroed().ok_or(oom)?;
    }
    let prp_list = frame::alloc_zeroed().ok_or(oom)?;
    for (i, &p) in data[1..].iter().enumerate() {
        unsafe { write_volatile(phys_to_virt(prp_list).cast::<u64>().add(i), p) };
    }

    regs.w32(REG_INTMS, !0);
    regs.w32(
        REG_AQA,
        (admin_size as u32 - 1) << 16 | (admin_size as u32 - 1),
    );
    regs.w64(REG_ASQ, admin.sq);
    regs.w64(REG_ACQ, admin.cq);
    regs.w32(REG_CC, CC_EN | CC_IOSQES | CC_IOCQES);
    if !poll(timeout_ms, || {
        regs.r32(REG_CSTS) & (CSTS_RDY | CSTS_CFS) != 0
    }) || regs.r32(REG_CSTS) & CSTS_CFS != 0
    {
        return Err("controller did not become ready");
    }

    let mut q = Queues {
        admin,
        io,
        data,
        prp_list,
    };

    // Identify Controller.
    let id = q.identify(1, 0).map_err(|_| "Identify Controller failed")?;
    let mut model = [0u8; 40];
    unsafe { core::ptr::copy_nonoverlapping(id.add(24), model.as_mut_ptr(), 40) };
    let mdts = unsafe { *id.add(77) };
    let nn = read_u32(id, 516);
    let mut max_bytes = MAX_PAGES * PAGE;
    if mdts != 0 && mdts < 16 {
        max_bytes = max_bytes.min(PAGE << mdts);
    }

    // The I/O queue pair. Its completions interrupt through MSI-X entry 1
    // when the controller has it; otherwise they are polled.
    let irq = super::msi::enable(d, 1);
    let mut cmd = [0u32; 16];
    cmd[0] = ADMIN_CREATE_CQ as u32;
    cmd[6] = q.io.cq as u32;
    cmd[7] = (q.io.cq >> 32) as u32;
    cmd[10] = (io_size as u32 - 1) << 16 | 1;
    // Physically contiguous; IEN and vector 1 with MSI-X.
    cmd[11] = if irq.is_some() { 1 << 16 | 0b11 } else { 1 };
    q.admin
        .run(cmd)
        .map_err(|_| "cannot create I/O completion queue")?;
    q.io.irq = irq;
    let mut cmd = [0u32; 16];
    cmd[0] = ADMIN_CREATE_SQ as u32;
    cmd[6] = q.io.sq as u32;
    cmd[7] = (q.io.sq >> 32) as u32;
    cmd[10] = (io_size as u32 - 1) << 16 | 1;
    cmd[11] = 1 << 16 | 1; // completion queue 1, physically contiguous
    q.admin
        .run(cmd)
        .map_err(|_| "cannot create I/O submission queue")?;

    // Active namespaces (CNS 2, NVMe 1.1+), or every ID up to NN.
    let mut nsids = Vec::new();
    if vs >= 0x1_0100
        && let Ok(list) = q.identify(2, 0)
    {
        for i in 0..1024 {
            match read_u32(list, i * 4) {
                0 => break,
                n => nsids.push(n),
            }
        }
    } else {
        nsids.extend(1..=nn.min(1024));
    }

    let ctrl_index = NEXT_CTRL.fetch_add(1, Ordering::Relaxed);
    let model = core::str::from_utf8(&model).unwrap_or("?").trim_end();
    crate::info!(
        "nvme{ctrl_index}: {model}, NVMe {}.{}, {} namespace(s)",
        vs >> 16,
        (vs >> 8) & 0xff,
        nsids.len()
    );

    let mut found = Vec::new();
    for nsid in nsids {
        let Ok(ns) = q.identify(0, nsid) else {
            continue;
        };
        let nsze = read_u64(ns, 0);
        let flbas = unsafe { *ns.add(26) };
        let format = (flbas & 0xf) as usize | ((flbas as usize >> 5) & 3) << 4;
        if nsze == 0 || format >= 64 {
            continue;
        }
        let lbaf = read_u32(ns, 128 + 4 * format);
        let ms = lbaf & 0xffff;
        let lbads = (lbaf >> 16) & 0xff;
        if ms != 0 || (lbads != 9 && lbads != 12) {
            crate::warn!(
                "nvme{ctrl_index}n{nsid}: unsupported format ({} byte blocks, {ms} metadata)",
                1u64 << lbads
            );
            continue;
        }
        found.push((nsid, nsze, lbads));
    }

    let ctrl = Arc::new(Controller {
        regs,
        max_bytes,
        queues: Mutex::new(q),
    });
    for (nsid, nsze, lbads) in found {
        let n = NEXT_DISK.fetch_add(1, Ordering::Relaxed);
        let disk = Namespace {
            ctrl: ctrl.clone(),
            nsid,
            name: format!("nvme{ctrl_index}n{nsid}"),
            block_shift: lbads,
            sectors: nsze << (lbads - 9),
            rdev: crate::fs::dev::makedev(MAJOR, n * 16),
        };
        if lbads != 9 {
            crate::info!("{}: {} byte blocks", disk.name, 1u32 << lbads);
        }
        block::register_disk(Arc::new(disk), MAJOR, n * 16);
    }
    Ok(())
}

/// Finds every NVMe controller and registers its namespaces.
pub fn init() {
    for d in pci::devices() {
        if d.class == 0x01
            && d.subclass == 0x08
            && d.prog_if == 0x02
            && let Err(e) = setup(&d)
        {
            crate::warn!("nvme at {:?}: {e}", d.addr);
        }
    }
}
