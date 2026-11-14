//! Block devices: disks and their partitions.
//!
//! A driver (virtio-blk, later NVMe and AHCI) registers each disk it finds
//! as a [`BlockDevice`]; the partition table on it (GPT) adds one more
//! device per partition. Each gets a node in `/dev` (`vda`, `vda1`, …)
//! with Linux's device numbers, and file systems (ext4, FAT) read and
//! write through this interface, in 512-byte sectors.

pub mod cache;
pub mod gpt;

use crate::abi::{Errno, KResult};
use crate::fs::{self, FileType, Inode};
use crate::sync::SpinLock;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

pub const SECTOR_SIZE: usize = 512;

/// A disk or a partition, addressed in 512-byte sectors.
pub trait BlockDevice: Send + Sync {
    /// Name in `/dev`: `vda`, `vda1`, `nvme0n1`, …
    fn name(&self) -> &str;
    /// Size in 512-byte sectors.
    fn sector_count(&self) -> u64;
    /// Reads `buf.len() / 512` sectors starting at `lba`. `buf.len()` is a
    /// non-zero multiple of 512 and `lba + count` is within the device.
    fn read_sectors(&self, lba: u64, buf: &mut [u8]) -> KResult<()>;
    /// Writes `data.len() / 512` sectors starting at `lba` (same rules).
    fn write_sectors(&self, lba: u64, data: &[u8]) -> KResult<()>;
    /// Makes earlier writes durable (the disk's write cache flushed).
    fn flush(&self) -> KResult<()> {
        Ok(())
    }
    /// Whether writes are refused (read-only media).
    fn read_only(&self) -> bool {
        false
    }
    /// Linux device number (`st_rdev` of its node).
    fn rdev(&self) -> u64;

    fn size_bytes(&self) -> u64 {
        self.sector_count() * SECTOR_SIZE as u64
    }
}

/// Reads `buf.len()` bytes at byte offset `off`, any alignment (bounce
/// buffer for the partial sectors at either end).
pub fn read_bytes(dev: &dyn BlockDevice, off: u64, buf: &mut [u8]) -> KResult<()> {
    if buf.is_empty() {
        return Ok(());
    }
    if off + buf.len() as u64 > dev.size_bytes() {
        return Err(Errno::EIO);
    }
    let s = SECTOR_SIZE as u64;
    if off.is_multiple_of(s) && buf.len().is_multiple_of(SECTOR_SIZE) {
        return dev.read_sectors(off / s, buf);
    }
    let first = off / s;
    let last = (off + buf.len() as u64).div_ceil(s);
    let mut tmp = vec![0u8; ((last - first) * s) as usize];
    dev.read_sectors(first, &mut tmp)?;
    let start = (off - first * s) as usize;
    buf.copy_from_slice(&tmp[start..start + buf.len()]);
    Ok(())
}

/// Writes `data` at byte offset `off`, any alignment (read-modify-write of
/// the partial sectors).
pub fn write_bytes(dev: &dyn BlockDevice, off: u64, data: &[u8]) -> KResult<()> {
    if data.is_empty() {
        return Ok(());
    }
    if off + data.len() as u64 > dev.size_bytes() {
        return Err(Errno::EIO);
    }
    let s = SECTOR_SIZE as u64;
    if off.is_multiple_of(s) && data.len().is_multiple_of(SECTOR_SIZE) {
        return dev.write_sectors(off / s, data);
    }
    let first = off / s;
    let last = (off + data.len() as u64).div_ceil(s);
    let mut tmp = vec![0u8; ((last - first) * s) as usize];
    dev.read_sectors(first, &mut tmp)?;
    let start = (off - first * s) as usize;
    tmp[start..start + data.len()].copy_from_slice(data);
    dev.write_sectors(first, &tmp)
}

/// A slice of a disk: one partition.
pub struct Partition {
    name: String,
    disk: Arc<dyn BlockDevice>,
    start: u64,
    sectors: u64,
    rdev: u64,
}

impl BlockDevice for Partition {
    fn name(&self) -> &str {
        &self.name
    }
    fn sector_count(&self) -> u64 {
        self.sectors
    }
    fn read_sectors(&self, lba: u64, buf: &mut [u8]) -> KResult<()> {
        self.check(lba, buf.len())?;
        self.disk.read_sectors(self.start + lba, buf)
    }
    fn write_sectors(&self, lba: u64, data: &[u8]) -> KResult<()> {
        self.check(lba, data.len())?;
        self.disk.write_sectors(self.start + lba, data)
    }
    fn flush(&self) -> KResult<()> {
        self.disk.flush()
    }
    fn read_only(&self) -> bool {
        self.disk.read_only()
    }
    fn rdev(&self) -> u64 {
        self.rdev
    }
}

impl Partition {
    fn check(&self, lba: u64, len: usize) -> KResult<()> {
        let count = (len / SECTOR_SIZE) as u64;
        if !len.is_multiple_of(SECTOR_SIZE) || lba + count > self.sectors {
            return Err(Errno::EIO);
        }
        Ok(())
    }
}

static DEVICES: SpinLock<Vec<Arc<dyn BlockDevice>>> = SpinLock::new(Vec::new());

/// Adds a whole disk: its node in `/dev`, then its partitions.
/// `minor_base` is the disk's own minor; partition n gets `minor_base + n`
/// (Linux: 16 minors per virtio disk, 8 per SCSI/SATA disk).
pub fn register_disk(disk: Arc<dyn BlockDevice>, major: u32, minor_base: u32) {
    let disk: Arc<dyn BlockDevice> = Arc::new(cache::Cached::new(disk));
    crate::info!(
        "block: {} ({} MiB{})",
        disk.name(),
        disk.size_bytes() >> 20,
        if disk.read_only() { ", read-only" } else { "" }
    );
    add(disk.clone());
    let parts = match gpt::read(disk.as_ref()) {
        Ok(p) => p,
        Err(e) => {
            crate::debug!("block: {}: no GPT ({e:?})", disk.name());
            return;
        }
    };
    for p in parts {
        // Linux names partitions of disks ending in a digit with a "p".
        let sep = if disk.name().ends_with(|c: char| c.is_ascii_digit()) {
            "p"
        } else {
            ""
        };
        let part = Arc::new(Partition {
            name: alloc::format!("{}{}{}", disk.name(), sep, p.number),
            disk: disk.clone(),
            start: p.first_lba,
            sectors: p.last_lba - p.first_lba + 1,
            rdev: fs::dev::makedev(major, minor_base + p.number),
        });
        crate::info!(
            "block: {} ({} MiB, {})",
            part.name,
            part.size_bytes() >> 20,
            if p.name.is_empty() {
                "unnamed"
            } else {
                &p.name
            }
        );
        add(part);
    }
}

fn add(dev: Arc<dyn BlockDevice>) {
    let node: Arc<dyn Inode> = Arc::new(Node {
        dev: dev.clone(),
        ino: fs::new_ino(),
    });
    let _ = fs::dev_dir().insert(dev.name(), node);
    DEVICES.lock().push(dev);
}

/// Writes every disk's cached changes and flushes its write cache.
pub fn sync_all() {
    let disks: Vec<_> = DEVICES
        .lock()
        .iter()
        .filter(|d| !d.name().is_empty())
        .cloned()
        .collect();
    for d in disks {
        if let Err(e) = d.flush() {
            crate::warn!("block: {}: write-back failed ({e:?})", d.name());
        }
    }
}

/// Starts the thread that writes changes back every 5 seconds.
pub fn start_flusher() {
    crate::task::spawn_named("blockflush", || {
        loop {
            crate::time::sleep_ms(5000);
            crate::fs::pagecache::sync_all();
            sync_all();
        }
    });
}

/// A registered device by its `/dev` name.
pub fn find(name: &str) -> Option<Arc<dyn BlockDevice>> {
    DEVICES.lock().iter().find(|d| d.name() == name).cloned()
}

/// A registered device by device number (for `mount /dev/vda1`).
pub fn by_rdev(rdev: u64) -> Option<Arc<dyn BlockDevice>> {
    DEVICES.lock().iter().find(|d| d.rdev() == rdev).cloned()
}

pub fn all() -> Vec<Arc<dyn BlockDevice>> {
    DEVICES.lock().clone()
}

/// The `/dev` node of a block device: reads and writes go to the device.
struct Node {
    dev: Arc<dyn BlockDevice>,
    ino: u64,
}

impl Inode for Node {
    fn file_type(&self) -> FileType {
        FileType::BlockDevice
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        0o660
    }
    fn rdev(&self) -> u64 {
        self.dev.rdev()
    }
    fn dev(&self) -> u64 {
        fs::DEV_TMPFS
    }
    fn size(&self) -> u64 {
        0 // as Linux: st_size of a block device node is 0
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let size = self.dev.size_bytes();
        if off >= size {
            return Ok(0);
        }
        let n = buf.len().min((size - off) as usize);
        read_bytes(self.dev.as_ref(), off, &mut buf[..n])?;
        Ok(n)
    }
    fn write_at(&self, off: u64, data: &[u8]) -> KResult<usize> {
        if self.dev.read_only() {
            return Err(Errno::EROFS);
        }
        let size = self.dev.size_bytes();
        if off >= size {
            return Err(Errno::ENOSPC);
        }
        let n = data.len().min((size - off) as usize);
        write_bytes(self.dev.as_ref(), off, &data[..n])?;
        Ok(n)
    }
    fn truncate(&self, _len: u64) -> KResult<()> {
        Ok(()) // O_TRUNC on a device is ignored, as on Linux
    }
}

/// The device behind a `/dev` block node.
pub fn device_of(inode: &Arc<dyn Inode>) -> Option<Arc<dyn BlockDevice>> {
    if inode.file_type() != FileType::BlockDevice {
        return None;
    }
    by_rdev(inode.rdev())
}
