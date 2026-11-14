//! AHCI: SATA disks behind a standard SATA host controller.
//!
//! Every implemented port with an ATA disk attached (link up, signature
//! 0x101) becomes a disk, `sda`, `sdb`, … Each port gets one page holding
//! its command list, received-FIS area and the single command table we
//! use: one command at a time (slot 0), completion polled, data through
//! bounce pages, one PRDT entry per page. ATAPI drives and port
//! multipliers are skipped.

use super::pci::{self, Bar};
use crate::abi::{Errno, KResult};
use crate::block::{self, BlockDevice, SECTOR_SIZE};
use crate::mm::{PAGE_SIZE, frame, paging, phys_to_virt};
use crate::sync::Mutex;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU32, Ordering, fence};

/// Linux's SCSI disk major (SATA disks go through libata's SCSI layer).
const MAJOR: u32 = 8;
static NEXT_DISK: AtomicU32 = AtomicU32::new(0);

/// Most data pages one command carries (128 KiB, 256 sectors).
const MAX_PAGES: usize = 32;
const PAGE: usize = PAGE_SIZE as usize;
const COMMAND_TIMEOUT_MS: u64 = 30_000;

// HBA registers.
const HBA_CAP: usize = 0x00;
const HBA_GHC: usize = 0x04;
const HBA_IS: usize = 0x08;
const HBA_PI: usize = 0x0c;
const HBA_VS: usize = 0x10;
const HBA_CAP2: usize = 0x24;
const HBA_BOHC: usize = 0x28;

const CAP_S64A: u32 = 1 << 31;
const GHC_AE: u32 = 1 << 31;
const GHC_IE: u32 = 1 << 1;
const CAP2_BOH: u32 = 1;
const BOHC_BOS: u32 = 1;
const BOHC_OOS: u32 = 2;

// Port registers (offsets inside a port's 0x80 bytes).
const PX_CLB: usize = 0x00;
const PX_FB: usize = 0x08;
const PX_IS: usize = 0x10;
const PX_IE: usize = 0x14;
const PX_CMD: usize = 0x18;
const PX_TFD: usize = 0x20;
const PX_SIG: usize = 0x24;
const PX_SSTS: usize = 0x28;
const PX_SERR: usize = 0x30;
const PX_CI: usize = 0x38;

const CMD_ST: u32 = 1 << 0;
const CMD_SUD: u32 = 1 << 1;
const CMD_POD: u32 = 1 << 2;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;

const IS_TFES: u32 = 1 << 30;
const TFD_ERR: u32 = 1 << 0;
const TFD_DRQ: u32 = 1 << 3;
const TFD_BSY: u32 = 1 << 7;

const SIG_ATA: u32 = 0x0000_0101;

// Layout of a port's page.
const CMD_LIST: u64 = 0;
const RECEIVED_FIS: u64 = 1024;
const CMD_TABLE: u64 = 2048;

// ATA commands.
const ATA_IDENTIFY: u8 = 0xec;
const ATA_READ_DMA: u8 = 0xc8;
const ATA_WRITE_DMA: u8 = 0xca;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_FLUSH_CACHE: u8 = 0xe7;
const ATA_FLUSH_CACHE_EXT: u8 = 0xea;

#[derive(Clone, Copy)]
struct Mmio(u64);

impl Mmio {
    fn r32(self, off: usize) -> u32 {
        unsafe { read_volatile((self.0 + off as u64) as *const u32) }
    }
    fn w32(self, off: usize, v: u32) {
        unsafe { write_volatile((self.0 + off as u64) as *mut u32, v) }
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

/// One port's registers and memory; behind the disk's mutex.
struct Port {
    regs: Mmio,
    /// Command list, received FIS and command table (see the layout above).
    mem: u64,
    data: [u64; MAX_PAGES],
}

impl Port {
    /// Stops the command engine and FIS receive.
    fn stop(&self) -> bool {
        let r = self.regs;
        r.w32(PX_CMD, r.r32(PX_CMD) & !CMD_ST);
        let ok = poll(500, || r.r32(PX_CMD) & CMD_CR == 0);
        r.w32(PX_CMD, r.r32(PX_CMD) & !CMD_FRE);
        ok & poll(500, || r.r32(PX_CMD) & CMD_FR == 0)
    }

    /// Points the port at our memory and starts FIS receive and commands.
    fn start(&self) -> bool {
        let r = self.regs;
        let clb = self.mem + CMD_LIST;
        let fb = self.mem + RECEIVED_FIS;
        r.w32(PX_CLB, clb as u32);
        r.w32(PX_CLB + 4, (clb >> 32) as u32);
        r.w32(PX_FB, fb as u32);
        r.w32(PX_FB + 4, (fb >> 32) as u32);
        r.w32(PX_SERR, !0);
        r.w32(PX_IS, !0);
        r.w32(PX_IE, 0);
        r.w32(PX_CMD, r.r32(PX_CMD) | CMD_FRE | CMD_SUD | CMD_POD);
        if !poll(500, || r.r32(PX_CMD) & CMD_FR != 0) {
            // Some HBAs only show FR once a FIS arrived; carry on.
        }
        if !poll(1000, || r.r32(PX_TFD) & (TFD_BSY | TFD_DRQ) == 0) {
            return false;
        }
        r.w32(PX_CMD, r.r32(PX_CMD) | CMD_ST);
        true
    }

    /// Issues one command in slot 0: `cmd` with `lba`/`count`, moving
    /// `bytes` of bounce memory (to the device if `write`).
    fn command(&mut self, cmd: u8, lba: u64, count: u16, bytes: usize, write: bool) -> KResult<()> {
        let r = self.regs;
        let pages = bytes.div_ceil(PAGE);
        // Command header 0: FIS of 5 dwords, write flag, PRDT length.
        let hdr = phys_to_virt(self.mem + CMD_LIST).cast::<u32>();
        let table = self.mem + CMD_TABLE;
        unsafe {
            write_volatile(
                hdr,
                5 | if write { 1 << 6 } else { 0 } | (pages as u32) << 16,
            );
            write_volatile(hdr.add(1), 0);
            write_volatile(hdr.add(2), table as u32);
            write_volatile(hdr.add(3), (table >> 32) as u32);
        }
        // Register FIS, host to device.
        let fis = phys_to_virt(table);
        let lba48 = matches!(
            cmd,
            ATA_READ_DMA_EXT | ATA_WRITE_DMA_EXT | ATA_FLUSH_CACHE_EXT
        );
        let device = if lba48 {
            0x40
        } else if cmd == ATA_IDENTIFY || cmd == ATA_FLUSH_CACHE {
            0
        } else {
            0x40 | ((lba >> 24) & 0xf) as u8
        };
        let bytes_fis: [u8; 20] = [
            0x27,
            0x80,
            cmd,
            0,
            lba as u8,
            (lba >> 8) as u8,
            (lba >> 16) as u8,
            device,
            (lba >> 24) as u8,
            (lba >> 32) as u8,
            (lba >> 40) as u8,
            0,
            count as u8,
            (count >> 8) as u8,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        for (i, &b) in bytes_fis.iter().enumerate() {
            unsafe { write_volatile(fis.add(i), b) };
        }
        // One PRDT entry per page.
        let prdt = unsafe { fis.add(0x80) }.cast::<u32>();
        let mut left = bytes;
        for p in 0..pages {
            let chunk = left.min(PAGE);
            let addr = self.data[p];
            unsafe {
                write_volatile(prdt.add(4 * p), addr as u32);
                write_volatile(prdt.add(4 * p + 1), (addr >> 32) as u32);
                write_volatile(prdt.add(4 * p + 2), 0);
                write_volatile(prdt.add(4 * p + 3), chunk as u32 - 1);
            }
            left -= chunk;
        }
        fence(Ordering::SeqCst);

        if !poll(COMMAND_TIMEOUT_MS, || {
            r.r32(PX_TFD) & (TFD_BSY | TFD_DRQ) == 0
        }) {
            self.recover();
            return Err(Errno::EIO);
        }
        r.w32(PX_IS, !0);
        r.w32(PX_CI, 1);
        let mut failed = false;
        let done = poll(COMMAND_TIMEOUT_MS, || {
            if r.r32(PX_IS) & IS_TFES != 0 {
                failed = true;
                return true;
            }
            r.r32(PX_CI) & 1 == 0
        });
        fence(Ordering::SeqCst);
        if !done || failed || r.r32(PX_TFD) & TFD_ERR != 0 {
            crate::warn!(
                "ahci: command {cmd:#x} at {lba} failed (TFD {:#x}, IS {:#x}{})",
                r.r32(PX_TFD),
                r.r32(PX_IS),
                if done { "" } else { ", timed out" }
            );
            self.recover();
            return Err(Errno::EIO);
        }
        Ok(())
    }

    /// Restarts the port after an error.
    fn recover(&self) {
        self.stop();
        self.start();
    }
}

pub struct AhciDisk {
    name: String,
    sectors: u64,
    lba48: bool,
    minor: u32,
    rdev: u64,
    port: Mutex<Port>,
}

impl AhciDisk {
    fn check(&self, lba: u64, len: usize) -> KResult<()> {
        if len == 0
            || !len.is_multiple_of(SECTOR_SIZE)
            || lba + (len / SECTOR_SIZE) as u64 > self.sectors
        {
            return Err(Errno::EIO);
        }
        Ok(())
    }

    fn rw(&self, port: &mut Port, lba: u64, bytes: usize, write: bool) -> KResult<()> {
        let count = (bytes / SECTOR_SIZE) as u16; // at most 256
        let cmd = match (self.lba48, write) {
            (true, false) => ATA_READ_DMA_EXT,
            (true, true) => ATA_WRITE_DMA_EXT,
            // LBA28: a count of 0 means 256 sectors.
            (false, false) => ATA_READ_DMA,
            (false, true) => ATA_WRITE_DMA,
        };
        port.command(cmd, lba, count, bytes, write)
    }
}

impl BlockDevice for AhciDisk {
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
        let mut port = self.port.lock();
        for (i, chunk) in buf.chunks_mut(MAX_PAGES * PAGE).enumerate() {
            let sector = lba + (i * MAX_PAGES * PAGE / SECTOR_SIZE) as u64;
            self.rw(&mut port, sector, chunk.len(), false)?;
            for (p, part) in chunk.chunks_mut(PAGE).enumerate() {
                let src = phys_to_virt(port.data[p]);
                unsafe { core::ptr::copy_nonoverlapping(src, part.as_mut_ptr(), part.len()) };
            }
        }
        Ok(())
    }

    fn write_sectors(&self, lba: u64, data: &[u8]) -> KResult<()> {
        self.check(lba, data.len())?;
        let mut port = self.port.lock();
        for (i, chunk) in data.chunks(MAX_PAGES * PAGE).enumerate() {
            let sector = lba + (i * MAX_PAGES * PAGE / SECTOR_SIZE) as u64;
            for (p, part) in chunk.chunks(PAGE).enumerate() {
                let dst = phys_to_virt(port.data[p]);
                unsafe { core::ptr::copy_nonoverlapping(part.as_ptr(), dst, part.len()) };
            }
            self.rw(&mut port, sector, chunk.len(), true)?;
        }
        Ok(())
    }

    fn flush(&self) -> KResult<()> {
        let cmd = if self.lba48 {
            ATA_FLUSH_CACHE_EXT
        } else {
            ATA_FLUSH_CACHE
        };
        self.port.lock().command(cmd, 0, 0, 0, false)
    }
}

/// An IDENTIFY DEVICE word.
fn word(id: *const u8, n: usize) -> u16 {
    unsafe { core::ptr::read_unaligned(id.add(2 * n).cast::<u16>()) }
}

/// Sets up port `i` and identifies its disk.
fn setup_port(abar: Mmio, i: usize, dma_limit: u64) -> Result<AhciDisk, &'static str> {
    let regs = Mmio(abar.0 + 0x100 + 0x80 * i as u64);
    let alloc = || {
        if dma_limit == 0 {
            frame::alloc_zeroed()
        } else {
            frame::alloc_below(dma_limit)
        }
    };
    let oom = "out of memory";
    let mem = alloc().ok_or(oom)?;
    let mut data = [0u64; MAX_PAGES];
    for p in data.iter_mut() {
        *p = alloc().ok_or(oom)?;
    }
    let mut port = Port { regs, mem, data };
    if !port.stop() {
        return Err("port engine does not stop");
    }
    if !port.start() {
        return Err("device stays busy");
    }

    port.command(ATA_IDENTIFY, 0, 0, 512, false)
        .map_err(|_| "IDENTIFY DEVICE failed")?;
    let id = phys_to_virt(port.data[0]) as *const u8;
    if word(id, 49) & 1 << 9 == 0 {
        return Err("disk without LBA addressing");
    }
    // Logical sectors larger than 512 bytes (word 106 bit 12): unsupported.
    let w106 = word(id, 106);
    if w106 & 0xc000 == 0x4000 && w106 & 1 << 12 != 0 {
        let words = word(id, 117) as u32 | (word(id, 118) as u32) << 16;
        if words != 256 {
            return Err("logical sectors are not 512 bytes");
        }
    }
    let lba48 = word(id, 83) & 1 << 10 != 0;
    let sectors = if lba48 {
        (0..4).fold(0u64, |acc, k| acc | (word(id, 100 + k) as u64) << (16 * k))
    } else {
        word(id, 60) as u64 | (word(id, 61) as u64) << 16
    };
    if sectors == 0 {
        return Err("disk reports no sectors");
    }
    let mut model = [0u8; 40];
    for k in 0..20 {
        let w = word(id, 27 + k);
        model[2 * k] = (w >> 8) as u8;
        model[2 * k + 1] = w as u8;
    }
    let model = core::str::from_utf8(&model).unwrap_or("?").trim();

    let n = NEXT_DISK.fetch_add(1, Ordering::Relaxed);
    let name = if n < 26 {
        format!("sd{}", (b'a' + n as u8) as char)
    } else {
        format!(
            "sd{}{}",
            (b'a' + (n / 26 - 1) as u8) as char,
            (b'a' + (n % 26) as u8) as char
        )
    };
    crate::info!(
        "ahci: port {i}: {name}: {model}{}",
        if lba48 { "" } else { " (LBA28)" }
    );
    Ok(AhciDisk {
        name,
        sectors,
        lba48,
        minor: n * 16,
        rdev: crate::fs::dev::makedev(MAJOR, n * 16),
        port: Mutex::new(port),
    })
}

fn setup(d: &pci::Device) -> Result<(), &'static str> {
    let Some(Bar::Memory { addr, size }) = d.bar(5) else {
        return Err("BAR5 (ABAR) is not a memory BAR");
    };
    d.enable();
    let abar = Mmio(paging::map_device(addr, size.max(0x1100)).map_err(|_| "cannot map ABAR")?);

    // Take the controller from the firmware if it still claims it.
    if abar.r32(HBA_CAP2) & CAP2_BOH != 0 {
        abar.w32(HBA_BOHC, abar.r32(HBA_BOHC) | BOHC_OOS);
        poll(2000, || abar.r32(HBA_BOHC) & BOHC_BOS == 0);
    }
    abar.w32(HBA_GHC, (abar.r32(HBA_GHC) | GHC_AE) & !GHC_IE);
    abar.w32(HBA_IS, !0);

    let cap = abar.r32(HBA_CAP);
    let dma_limit = if cap & CAP_S64A == 0 { 1u64 << 32 } else { 0 };
    let vs = abar.r32(HBA_VS);
    let pi = abar.r32(HBA_PI);
    crate::debug!(
        "ahci at {:?}: AHCI {}.{}, ports {pi:#x}",
        d.addr,
        vs >> 16,
        (vs >> 8) & 0xff
    );

    for i in 0..32 {
        if pi & 1 << i == 0 {
            continue;
        }
        let regs = Mmio(abar.0 + 0x100 + 0x80 * i as u64);
        let ssts = regs.r32(PX_SSTS);
        // Device present and communication established, interface active.
        if ssts & 0xf != 3 || (ssts >> 8) & 0xf != 1 {
            continue;
        }
        let sig = regs.r32(PX_SIG);
        if sig != SIG_ATA {
            crate::debug!("ahci: port {i}: signature {sig:#x}, skipped");
            continue;
        }
        match setup_port(abar, i, dma_limit) {
            Ok(disk) => {
                let minor = disk.minor;
                block::register_disk(Arc::new(disk), MAJOR, minor);
            }
            Err(e) => crate::warn!("ahci: port {i}: {e}"),
        }
    }
    Ok(())
}

/// Finds every AHCI controller and registers its SATA disks.
pub fn init() {
    for d in pci::devices() {
        if d.class == 0x01
            && d.subclass == 0x06
            && d.prog_if == 0x01
            && let Err(e) = setup(&d)
        {
            crate::warn!("ahci at {:?}: {e}", d.addr);
        }
    }
}
