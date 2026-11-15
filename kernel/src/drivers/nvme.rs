//! NVMe: PCIe SSDs (most new PCs), polled, one I/O queue.

use super::dma::{DmaPage, Mmio, poll};
use crate::abi::{Errno, KResult};
use crate::block::BlockDevice;
use crate::sync::Mutex;
use alloc::string::String;
use alloc::sync::Arc;

const QSIZE: u16 = 32;

struct Queues {
    regs: Mmio,
    stride: u64,
    asq: DmaPage,
    acq: DmaPage,
    iosq: DmaPage,
    iocq: DmaPage,
    data: DmaPage,
    /// (sq tail, cq head, cq phase) for admin (0) and I/O (1).
    sq_tail: [u16; 2],
    cq_head: [u16; 2],
    phase: [bool; 2],
    cid: u16,
}

pub struct NvmeDisk {
    name: String,
    sectors: u64,
    sector_size: u32,
    q: Mutex<Queues>,
}

impl Queues {
    /// Submits a command on queue `qid` (0 admin, 1 I/O) and waits.
    fn submit(&mut self, qid: usize, mut cmd: [u32; 16]) -> KResult<[u32; 4]> {
        self.cid = self.cid.wrapping_add(1);
        cmd[0] |= (self.cid as u32) << 16;
        let (sq, cq) = if qid == 0 {
            (&self.asq, &self.acq)
        } else {
            (&self.iosq, &self.iocq)
        };
        let slot = self.sq_tail[qid] as usize;
        for (i, w) in cmd.iter().enumerate() {
            sq.write::<u32>(slot * 64 + i * 4, *w);
        }
        self.sq_tail[qid] = (self.sq_tail[qid] + 1) % QSIZE;
        let db = 0x1000 + (2 * qid as u64) * self.stride;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.regs.w32(db, self.sq_tail[qid] as u32);
        let head = self.cq_head[qid] as usize;
        let phase = self.phase[qid];
        let ok = poll(10_000, || {
            (cq.read::<u32>(head * 16 + 12) >> 16) & 1 == phase as u32
        });
        if !ok {
            return Err(Errno::EIO);
        }
        let entry: [u32; 4] = core::array::from_fn(|i| cq.read::<u32>(head * 16 + i * 4));
        self.cq_head[qid] = (self.cq_head[qid] + 1) % QSIZE;
        if self.cq_head[qid] == 0 {
            self.phase[qid] = !self.phase[qid];
        }
        self.regs.w32(
            0x1000 + (2 * qid as u64 + 1) * self.stride,
            self.cq_head[qid] as u32,
        );
        if (entry[3] >> 17) & 0x7ff != 0 {
            return Err(Errno::EIO);
        }
        Ok(entry)
    }
}

pub fn probe(pci: super::pci::Device, n: usize) -> Option<Arc<dyn BlockDevice>> {
    pci.enable();
    let regs = Mmio(pci.map_bar(0)?);
    let cap = regs.r64(0);
    let stride = 4u64 << ((cap >> 32) & 0xf);
    regs.w32(0x14, 0); // disable
    if !poll(2000, || regs.r32(0x1c) & 1 == 0) {
        return None;
    }
    let mut q = Queues {
        regs,
        stride,
        asq: DmaPage::new(),
        acq: DmaPage::new(),
        iosq: DmaPage::new(),
        iocq: DmaPage::new(),
        data: DmaPage::new(),
        sq_tail: [0; 2],
        cq_head: [0; 2],
        phase: [true; 2],
        cid: 0,
    };
    regs.w32(0x24, (QSIZE as u32 - 1) | (QSIZE as u32 - 1) << 16);
    regs.w64(0x28, q.asq.phys);
    regs.w64(0x30, q.acq.phys);
    // Enable: NVM command set, 4 KiB pages, 64-byte SQ and 16-byte CQ entries.
    regs.w32(0x14, 1 | 6 << 16 | 4 << 20);
    if !poll(5000, || regs.r32(0x1c) & 1 == 1) {
        return None;
    }
    // Identify namespace 1.
    let mut cmd = [0u32; 16];
    cmd[0] = 0x06;
    cmd[1] = 1;
    cmd[6] = q.data.phys as u32;
    cmd[7] = (q.data.phys >> 32) as u32;
    cmd[10] = 0;
    q.submit(0, cmd).ok()?;
    let nsze = q.data.read::<u64>(0);
    let flbas = q.data.read::<u8>(26) & 0xf;
    let lbaf = q.data.read::<u32>(128 + 4 * flbas as usize);
    let sector_size = 1u32 << ((lbaf >> 16) & 0xff);
    // I/O completion queue 1, then submission queue 1 (polled, no IRQ).
    let mut c = [0u32; 16];
    c[0] = 0x05;
    c[6] = q.iocq.phys as u32;
    c[7] = (q.iocq.phys >> 32) as u32;
    c[10] = 1 | (QSIZE as u32 - 1) << 16;
    c[11] = 1;
    q.submit(0, c).ok()?;
    let mut s = [0u32; 16];
    s[0] = 0x01;
    s[6] = q.iosq.phys as u32;
    s[7] = (q.iosq.phys >> 32) as u32;
    s[10] = 1 | (QSIZE as u32 - 1) << 16;
    s[11] = 1 | 1 << 16;
    q.submit(0, s).ok()?;
    let name = alloc::format!("nvme{n}n1");
    let sectors = nsze * (sector_size as u64 / 512);
    crate::info!(
        "nvme: {name}, {} MiB, {sector_size}-byte sectors",
        sectors / 2048
    );
    Some(Arc::new(NvmeDisk {
        name,
        sectors,
        sector_size,
        q: Mutex::new(q),
    }))
}

impl NvmeDisk {
    fn io(&self, write: bool, sector: u64, buf: &mut [u8]) -> KResult<()> {
        let mut q = self.q.lock();
        let per = self.sector_size as u64 / 512;
        if !sector.is_multiple_of(per)
            || !(buf.len() as u64).is_multiple_of(self.sector_size as u64)
        {
            return Err(Errno::EINVAL);
        }
        if write {
            q.data.bytes()[..buf.len()].copy_from_slice(buf);
        }
        let lba = sector / per;
        let n = buf.len() as u64 / self.sector_size as u64;
        let mut c = [0u32; 16];
        c[0] = if write { 0x01 } else { 0x02 };
        c[1] = 1;
        c[6] = q.data.phys as u32;
        c[7] = (q.data.phys >> 32) as u32;
        c[10] = lba as u32;
        c[11] = (lba >> 32) as u32;
        c[12] = (n - 1) as u32;
        q.submit(1, c)?;
        if !write {
            buf.copy_from_slice(&q.data.bytes()[..buf.len()]);
        }
        Ok(())
    }
}

impl BlockDevice for NvmeDisk {
    fn name(&self) -> &str {
        &self.name
    }
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> KResult<()> {
        for (i, chunk) in buf.chunks_mut(4096).enumerate() {
            self.io(false, sector + i as u64 * 8, chunk)?;
        }
        Ok(())
    }
    fn write(&self, sector: u64, buf: &[u8]) -> KResult<()> {
        for (i, chunk) in buf.chunks(4096).enumerate() {
            let mut tmp = alloc::vec::Vec::from(chunk);
            self.io(true, sector + i as u64 * 8, &mut tmp)?;
        }
        Ok(())
    }
}
