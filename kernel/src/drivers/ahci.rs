//! AHCI: SATA disks (most PCs; QEMU's q35 boots from one).

use super::dma::{DmaPage, Mmio, poll};
use crate::abi::{Errno, KResult};
use crate::block::BlockDevice;
use crate::sync::Mutex;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

const SIG_ATA: u32 = 0x0000_0101;
const CMD_ST: u32 = 1 << 0;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;

struct Port {
    regs: Mmio,
    /// Command list (1 KiB) at 0, received FIS (256 B) at 0x400.
    list: DmaPage,
    /// Command table: FIS at 0, PRDT at 0x80.
    table: DmaPage,
    /// Data bounce page.
    data: DmaPage,
}

pub struct AhciDisk {
    name: String,
    sectors: u64,
    port: Mutex<Port>,
}

pub fn probe(pci: super::pci::Device, first_letter: &mut u8) -> Vec<Arc<dyn BlockDevice>> {
    let mut out = Vec::new();
    pci.enable();
    let Some(base) = pci.map_bar(5) else {
        return out;
    };
    let hba = Mmio(base);
    hba.w32(4, hba.r32(4) | 1 << 31); // AHCI mode
    let implemented = hba.r32(0x0c);
    for p in 0..32 {
        if implemented & (1 << p) == 0 {
            continue;
        }
        let regs = Mmio(base + 0x100 + p as u64 * 0x80);
        if regs.r32(0x28) & 0xf != 3 || regs.r32(0x24) != SIG_ATA {
            continue; // nothing attached, or not a disk (ATAPI...)
        }
        let port = Port {
            regs,
            list: DmaPage::new(),
            table: DmaPage::new(),
            data: DmaPage::new(),
        };
        // Stop, point at our memory, start.
        regs.w32(0x18, regs.r32(0x18) & !(CMD_ST | CMD_FRE));
        poll(500, || regs.r32(0x18) & (CMD_CR | CMD_FR) == 0);
        regs.w64(0x00, port.list.phys);
        regs.w64(0x08, port.list.phys + 0x400);
        regs.w32(0x30, u32::MAX); // SERR
        regs.w32(0x10, u32::MAX); // IS
        regs.w32(0x14, 0); // no interrupts: we poll
        regs.w32(0x18, regs.r32(0x18) | CMD_FRE);
        regs.w32(0x18, regs.r32(0x18) | CMD_ST);
        let disk = AhciDisk {
            name: String::new(),
            sectors: 0,
            port: Mutex::new(port),
        };
        let mut id = [0u8; 512];
        if disk.command(0xec, 0, &mut id, false).is_err() {
            continue;
        }
        let w = |i: usize| u16::from_le_bytes([id[i * 2], id[i * 2 + 1]]) as u64;
        let sectors = w(100) | w(101) << 16 | w(102) << 32 | w(103) << 48;
        let name = alloc::format!("sd{}", *first_letter as char);
        *first_letter += 1;
        crate::info!("ahci: {name} (port {p}), {} MiB", sectors / 2048);
        out.push(Arc::new(AhciDisk {
            name,
            sectors,
            ..disk
        }) as Arc<dyn BlockDevice>);
    }
    out
}

impl AhciDisk {
    /// One ATA command moving `buf` (at most a page).
    fn command(&self, cmd: u8, lba: u64, buf: &mut [u8], write: bool) -> KResult<()> {
        let p = self.port.lock();
        let count = (buf.len() / 512).max(1) as u16;
        // Command header 0: FIS length 5 dwords, write flag, one PRD.
        let flags = 5 | if write { 1 << 6 } else { 0 } | 1 << 16;
        p.list.write::<u32>(0, flags);
        p.list.write::<u32>(4, 0);
        p.list.write::<u64>(8, p.table.phys);
        p.table.zero();
        let fis = [
            0x27u8,
            0x80,
            cmd,
            0,
            lba as u8,
            (lba >> 8) as u8,
            (lba >> 16) as u8,
            0x40,
            (lba >> 24) as u8,
            (lba >> 32) as u8,
            (lba >> 40) as u8,
            0,
            count as u8,
            (count >> 8) as u8,
            0,
            0,
        ];
        p.table.bytes()[..16].copy_from_slice(&fis);
        p.table.write::<u64>(0x80, p.data.phys);
        p.table.write::<u32>(0x8c, buf.len() as u32 - 1);
        if write {
            p.data.bytes()[..buf.len()].copy_from_slice(buf);
        }
        let r = p.regs;
        if !poll(1000, || r.r32(0x20) & 0x88 == 0) {
            return Err(Errno::EIO);
        }
        r.w32(0x38, 1);
        let ok = poll(10_000, || {
            r.r32(0x38) & 1 == 0 || r.r32(0x10) & (1 << 30) != 0
        });
        if !ok || r.r32(0x20) & 1 != 0 || r.r32(0x10) & (1 << 30) != 0 {
            r.w32(0x10, u32::MAX);
            return Err(Errno::EIO);
        }
        if !write {
            buf.copy_from_slice(&p.data.bytes()[..buf.len()]);
        }
        Ok(())
    }
}

impl BlockDevice for AhciDisk {
    fn name(&self) -> &str {
        &self.name
    }
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> KResult<()> {
        for (i, chunk) in buf.chunks_mut(4096).enumerate() {
            self.command(0x25, sector + i as u64 * 8, chunk, false)?;
        }
        Ok(())
    }
    fn write(&self, sector: u64, buf: &[u8]) -> KResult<()> {
        for (i, chunk) in buf.chunks(4096).enumerate() {
            let mut tmp = Vec::from(chunk);
            self.command(0x35, sector + i as u64 * 8, &mut tmp, true)?;
        }
        Ok(())
    }
}
