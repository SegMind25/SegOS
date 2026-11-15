//! Block devices: disks, their partitions (GPT, or MBR), and the `/dev`
//! nodes that expose them (`/dev/sda`, `/dev/sda1`, `/dev/vda`,
//! `/dev/nvme0n1p2`, ...).

use crate::abi::{Errno, KResult};
use crate::fs::{FileType, Inode, new_ino};
use crate::sync::SpinLock;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

/// A disk or partition, in 512-byte sectors. Reads and writes are whole
/// sectors (and whole native sectors for 4K-sector drives).
pub trait BlockDevice: Send + Sync {
    fn name(&self) -> &str;
    fn sectors(&self) -> u64;
    fn read(&self, sector: u64, buf: &mut [u8]) -> KResult<()>;
    fn write(&self, sector: u64, buf: &[u8]) -> KResult<()>;
    /// For partitions: (disk, first sector).
    fn whole(&self) -> Option<(Arc<dyn BlockDevice>, u64)> {
        None
    }
}

/// Reads `buf.len()` bytes at byte `off`, any alignment.
pub fn read_bytes(dev: &dyn BlockDevice, off: u64, buf: &mut [u8]) -> KResult<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let first = off / 512;
    let last = (off + buf.len() as u64 - 1) / 512;
    if last >= dev.sectors() {
        return Err(Errno::EIO);
    }
    if off.is_multiple_of(512) && buf.len().is_multiple_of(512) {
        return dev.read(first, buf);
    }
    let mut tmp = vec![0u8; ((last - first + 1) * 512) as usize];
    dev.read(first, &mut tmp)?;
    let start = (off % 512) as usize;
    buf.copy_from_slice(&tmp[start..start + buf.len()]);
    Ok(())
}

/// Writes `data` at byte `off`, any alignment (read-modify-write).
pub fn write_bytes(dev: &dyn BlockDevice, off: u64, data: &[u8]) -> KResult<()> {
    if data.is_empty() {
        return Ok(());
    }
    if off.is_multiple_of(512) && data.len().is_multiple_of(512) {
        return dev.write(off / 512, data);
    }
    let first = off / 512;
    let last = (off + data.len() as u64 - 1) / 512;
    let mut tmp = vec![0u8; ((last - first + 1) * 512) as usize];
    dev.read(first, &mut tmp)?;
    let start = (off % 512) as usize;
    tmp[start..start + data.len()].copy_from_slice(data);
    dev.write(first, &tmp)
}

pub struct Partition {
    name: String,
    disk: Arc<dyn BlockDevice>,
    start: u64,
    len: u64,
    /// GPT partition name (UTF-16 in the table), e.g. "segos-root".
    pub label: String,
}

impl BlockDevice for Partition {
    fn name(&self) -> &str {
        &self.name
    }
    fn sectors(&self) -> u64 {
        self.len
    }
    fn read(&self, sector: u64, buf: &mut [u8]) -> KResult<()> {
        if sector + (buf.len() as u64).div_ceil(512) > self.len {
            return Err(Errno::EIO);
        }
        self.disk.read(self.start + sector, buf)
    }
    fn write(&self, sector: u64, buf: &[u8]) -> KResult<()> {
        if sector + (buf.len() as u64).div_ceil(512) > self.len {
            return Err(Errno::EIO);
        }
        self.disk.write(self.start + sector, buf)
    }
    fn whole(&self) -> Option<(Arc<dyn BlockDevice>, u64)> {
        Some((self.disk.clone(), self.start))
    }
}

/// (start, length, name) of each partition.
fn partitions(disk: &dyn BlockDevice) -> Vec<(u64, u64, String)> {
    let mut out = Vec::new();
    let mut hdr = [0u8; 512];
    if disk.read(1, &mut hdr).is_ok() && &hdr[..8] == b"EFI PART" {
        let u32_at = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let u64_at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let (lba, count, size) = (
            u64_at(&hdr, 72),
            u32_at(&hdr, 80),
            u32_at(&hdr, 84) as usize,
        );
        if !(128..=4096).contains(&size) || count > 1024 {
            return out;
        }
        let bytes = count as usize * size;
        let mut table = vec![0u8; bytes.next_multiple_of(512)];
        if disk.read(lba, &mut table).is_err() {
            return out;
        }
        for e in table.chunks(size).take(count as usize) {
            if e[..16].iter().all(|&b| b == 0) {
                continue;
            }
            let (first, last) = (u64_at(e, 32), u64_at(e, 40));
            let name: Vec<u16> = e[56..128]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();
            if last >= first {
                out.push((first, last - first + 1, String::from_utf16_lossy(&name)));
            }
        }
        return out;
    }
    let mut mbr = [0u8; 512];
    if disk.read(0, &mut mbr).is_ok() && mbr[510] == 0x55 && mbr[511] == 0xaa {
        for i in 0..4 {
            let e = &mbr[446 + i * 16..462 + i * 16];
            let start = u32::from_le_bytes(e[8..12].try_into().unwrap()) as u64;
            let len = u32::from_le_bytes(e[12..16].try_into().unwrap()) as u64;
            if e[4] != 0 && e[4] != 0xee && len != 0 {
                out.push((start, len, String::new()));
            }
        }
    }
    out
}

struct Entry {
    dev: Arc<dyn BlockDevice>,
    label: String,
    rdev: u64,
}

static DEVICES: SpinLock<Vec<Entry>> = SpinLock::new(Vec::new());

/// Linux's device numbers: sd 8, nvme 259, virtio 254.
fn major_of(name: &str) -> u32 {
    if name.starts_with("sd") {
        8
    } else if name.starts_with("nvme") {
        259
    } else {
        254
    }
}

fn makedev(major: u32, minor: u32) -> u64 {
    let (ma, mi) = (major as u64, minor as u64);
    (mi & 0xff) | ((ma & 0xfff) << 8) | ((mi & !0xff) << 12) | ((ma & !0xfff) << 32)
}

/// Adds a disk and its partitions.
pub fn register(disk: Arc<dyn BlockDevice>) {
    let parts = partitions(&*disk);
    let base = disk.name().to_string();
    let mut list = DEVICES.lock();
    let major = major_of(&base);
    let disk_index = list
        .iter()
        .filter(|e| e.dev.whole().is_none() && major_of(e.dev.name()) == major)
        .count() as u32;
    let minor0 = disk_index * 16;
    list.push(Entry {
        dev: disk.clone(),
        label: String::new(),
        rdev: makedev(major, minor0),
    });
    for (i, (start, len, label)) in parts.into_iter().enumerate() {
        let sep = if base.ends_with(|c: char| c.is_ascii_digit()) {
            "p"
        } else {
            ""
        };
        let name = alloc::format!("{base}{sep}{}", i + 1);
        if !label.is_empty() {
            crate::info!("  {name}: {} MiB, \"{label}\"", len / 2048);
        }
        list.push(Entry {
            dev: Arc::new(Partition {
                name,
                disk: disk.clone(),
                start,
                len,
                label: label.clone(),
            }),
            label,
            rdev: makedev(major, minor0 + i as u32 + 1),
        });
    }
}

pub fn find(name: &str) -> Option<Arc<dyn BlockDevice>> {
    DEVICES
        .lock()
        .iter()
        .find(|e| e.dev.name() == name)
        .map(|e| e.dev.clone())
}

/// The partition whose GPT name is `label`.
pub fn find_label(label: &str) -> Option<Arc<dyn BlockDevice>> {
    DEVICES
        .lock()
        .iter()
        .find(|e| e.label == label)
        .map(|e| e.dev.clone())
}

/// Every block device: (device, its st_rdev).
pub fn all() -> Vec<(Arc<dyn BlockDevice>, u64)> {
    DEVICES
        .lock()
        .iter()
        .map(|e| (e.dev.clone(), e.rdev))
        .collect()
}

/// The device with number `rdev` (for mount by device file).
pub fn by_rdev(rdev: u64) -> Option<Arc<dyn BlockDevice>> {
    DEVICES
        .lock()
        .iter()
        .find(|e| e.rdev == rdev)
        .map(|e| e.dev.clone())
}

/// `/dev/sda` and friends: byte access to a block device.
pub struct BlockNode {
    ino: u64,
    pub dev: Arc<dyn BlockDevice>,
    rdev: u64,
}

impl BlockNode {
    pub fn create(dev: Arc<dyn BlockDevice>, rdev: u64) -> Arc<dyn Inode> {
        Arc::new(Self {
            ino: new_ino(),
            dev,
            rdev,
        })
    }
}

impl Inode for BlockNode {
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
        self.rdev
    }
    fn size(&self) -> u64 {
        self.dev.sectors() * 512
    }
    fn seekable(&self) -> bool {
        true
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let size = self.size();
        if off >= size {
            return Ok(0);
        }
        let n = buf.len().min((size - off) as usize).min(1 << 20);
        read_bytes(&*self.dev, off, &mut buf[..n])?;
        Ok(n)
    }
    fn write_at(&self, off: u64, data: &[u8]) -> KResult<usize> {
        let size = self.size();
        if off >= size {
            return Err(Errno::ENOSPC);
        }
        let n = data.len().min((size - off) as usize);
        write_bytes(&*self.dev, off, &data[..n])?;
        Ok(n)
    }
    fn truncate(&self, _len: u64) -> KResult<()> {
        Ok(())
    }
    fn ioctl(&self, req: u32, arg: u64, mm: &crate::mm::vm::AddressSpace) -> KResult<u64> {
        const BLKGETSIZE: u32 = 0x1260;
        const BLKSSZGET: u32 = 0x1268;
        const BLKGETSIZE64: u32 = 0x8008_1272;
        match req {
            BLKGETSIZE64 => mm.write(arg, &self.size()).map(|()| 0),
            BLKGETSIZE => mm.write(arg, &self.dev.sectors()).map(|()| 0),
            BLKSSZGET => mm.write(arg, &512i32).map(|()| 0),
            _ => Err(Errno::ENOTTY),
        }
    }
}
