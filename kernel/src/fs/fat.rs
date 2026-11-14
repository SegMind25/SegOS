//! FAT12, FAT16 and FAT32, read-write, with long file names: the format
//! of EFI system partitions and USB sticks.
//!
//! The whole file allocation table is kept in memory and written back
//! (to every copy) after each change. One lock serialises every
//! operation on a volume. FAT has no inode numbers, owners, permissions
//! or links: SegOS numbers each file as it is found, reports 0755
//! (0555 when read-only), and refuses links and symbolic links, as Linux
//! does.

use super::mount::FsInfo;
use super::{FileType, Inode, new_ino};
use crate::abi::{Errno, KResult, Stat};
use crate::block::{self, BlockDevice};
use crate::sync::{Mutex, Once, SpinLock};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LFN: u8 = 0x0f;
const DELETED: u8 = 0xe5;
pub const MSDOS_SUPER_MAGIC: u64 = 0x4d44;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Fat12,
    Fat16,
    Fat32,
}

/// Where a directory's entries are: FAT12/16's fixed root region, or a
/// cluster chain.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum DirLoc {
    FixedRoot,
    Chain(u32),
}

struct Inner {
    /// The first FAT, raw.
    fat: Vec<u8>,
    /// FAT sectors changed since the last flush.
    dirty: BTreeSet<u32>,
    /// Where to start looking for a free cluster.
    hint: u32,
}

pub struct FatFs {
    dev: Arc<dyn BlockDevice>,
    dev_id: u64,
    kind: Kind,
    bps: u64,
    cluster_size: u64,
    reserved: u64,
    nfats: u64,
    fat_sectors: u64,
    root_start: u64,
    root_entries: u64,
    data_start: u64,
    clusters: u32,
    root_cluster: u32,
    label: String,
    inner: Mutex<Inner>,
    /// Live nodes by the position of their directory entry, and by number.
    by_pos: SpinLock<BTreeMap<(DirLoc, u64), Weak<Node>>>,
    by_ino: SpinLock<BTreeMap<u64, Weak<Node>>>,
    root: Once<Arc<Node>>,
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

impl FatFs {
    pub fn mount(dev: Arc<dyn BlockDevice>, dev_id: u64) -> KResult<Arc<FatFs>> {
        let mut bs = vec![0u8; 512];
        block::read_bytes(dev.as_ref(), 0, &mut bs)?;
        if bs[510] != 0x55 || bs[511] != 0xaa {
            return Err(Errno::EINVAL);
        }
        let bps = le16(&bs, 11) as u64;
        let spc = bs[13] as u64;
        let reserved = le16(&bs, 14) as u64;
        let nfats = bs[16] as u64;
        let root_entries = le16(&bs, 17) as u64;
        let total = match le16(&bs, 19) {
            0 => le32(&bs, 32) as u64,
            n => n as u64,
        };
        let fat_sectors = match le16(&bs, 22) {
            0 => le32(&bs, 36) as u64,
            n => n as u64,
        };
        if !bps.is_power_of_two() || !(512..=4096).contains(&bps) || !spc.is_power_of_two() {
            return Err(Errno::EINVAL);
        }
        if nfats == 0 || reserved == 0 || fat_sectors == 0 || total == 0 {
            return Err(Errno::EINVAL);
        }
        let root_sectors = (root_entries * 32).div_ceil(bps);
        let root_start = reserved + nfats * fat_sectors;
        let data_start = root_start + root_sectors;
        if total <= data_start || total * bps > dev.size_bytes() {
            return Err(Errno::EINVAL);
        }
        let clusters = ((total - data_start) / spc) as u32;
        let kind = if clusters < 4085 {
            Kind::Fat12
        } else if clusters < 65525 {
            Kind::Fat16
        } else {
            Kind::Fat32
        };
        let (root_cluster, label_off) = if kind == Kind::Fat32 {
            (le32(&bs, 44), 71)
        } else {
            (0, 43)
        };
        let label = String::from_utf8_lossy(&bs[label_off..label_off + 11])
            .trim_end()
            .into();
        let mut fat = vec![0u8; (fat_sectors * bps) as usize];
        block::read_bytes(dev.as_ref(), reserved * bps, &mut fat)?;
        let fs = Arc::new(FatFs {
            dev,
            dev_id,
            kind,
            bps,
            cluster_size: spc * bps,
            reserved,
            nfats,
            fat_sectors,
            root_start,
            root_entries,
            data_start,
            clusters,
            root_cluster,
            label,
            inner: Mutex::new(Inner {
                fat,
                dirty: BTreeSet::new(),
                hint: 2,
            }),
            by_pos: SpinLock::new(BTreeMap::new()),
            by_ino: SpinLock::new(BTreeMap::new()),
            root: Once::new(),
        });
        if kind == Kind::Fat32 && !fs.dev.read_only() {
            // The FSInfo free count goes stale as we allocate: say "unknown".
            let fsinfo = le16(&bs, 48) as u64;
            if fsinfo != 0 && fsinfo != 0xffff {
                let _ = block::write_bytes(fs.dev.as_ref(), fsinfo * bps + 488, &[0xff; 4]);
            }
        }
        Ok(fs)
    }

    pub fn root(self: &Arc<Self>) -> Arc<dyn Inode> {
        self.root
            .call_once(|| {
                let first = if self.kind == Kind::Fat32 {
                    self.root_cluster
                } else {
                    0
                };
                let node = Arc::new(Node {
                    fs: self.clone(),
                    ino: new_ino(),
                    is_dir: true,
                    st: SpinLock::new(NodeState {
                        first,
                        size: 0,
                        attr: ATTR_DIRECTORY,
                        mtime: 0,
                        pos: None,
                        parent: Weak::new(),
                    }),
                });
                self.by_ino.lock().insert(node.ino, Arc::downgrade(&node));
                node
            })
            .clone()
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    fn eoc(&self) -> u32 {
        match self.kind {
            Kind::Fat12 => 0xfff,
            Kind::Fat16 => 0xffff,
            Kind::Fat32 => 0x0fff_ffff,
        }
    }

    fn is_end(&self, v: u32) -> bool {
        v < 2 || v > self.clusters + 1
    }

    fn get(&self, inner: &Inner, n: u32) -> u32 {
        let f = &inner.fat;
        match self.kind {
            Kind::Fat12 => {
                let o = (n + n / 2) as usize;
                let w = le16(f, o) as u32;
                if n & 1 == 1 { w >> 4 } else { w & 0xfff }
            }
            Kind::Fat16 => le16(f, 2 * n as usize) as u32,
            Kind::Fat32 => le32(f, 4 * n as usize) & 0x0fff_ffff,
        }
    }

    fn set(&self, inner: &mut Inner, n: u32, v: u32) {
        let (o, len) = match self.kind {
            Kind::Fat12 => {
                let o = (n + n / 2) as usize;
                let w = le16(&inner.fat, o);
                let w = if n & 1 == 1 {
                    (w & 0x000f) | ((v as u16) << 4)
                } else {
                    (w & 0xf000) | (v as u16 & 0xfff)
                };
                inner.fat[o..o + 2].copy_from_slice(&w.to_le_bytes());
                (o, 2)
            }
            Kind::Fat16 => {
                let o = 2 * n as usize;
                inner.fat[o..o + 2].copy_from_slice(&(v as u16).to_le_bytes());
                (o, 2)
            }
            Kind::Fat32 => {
                let o = 4 * n as usize;
                let old = le32(&inner.fat, o);
                let w = (old & 0xf000_0000) | (v & 0x0fff_ffff);
                inner.fat[o..o + 4].copy_from_slice(&w.to_le_bytes());
                (o, 4)
            }
        };
        inner.dirty.insert((o as u64 / self.bps) as u32);
        inner.dirty.insert(((o + len - 1) as u64 / self.bps) as u32);
    }

    /// Writes changed FAT sectors to every copy of the table.
    fn flush(&self, inner: &mut Inner) -> KResult<()> {
        for s in core::mem::take(&mut inner.dirty) {
            let range = (s as u64 * self.bps) as usize..((s as u64 + 1) * self.bps) as usize;
            for copy in 0..self.nfats {
                let at = (self.reserved + copy * self.fat_sectors + s as u64) * self.bps;
                block::write_bytes(self.dev.as_ref(), at, &inner.fat[range.clone()])?;
            }
        }
        Ok(())
    }

    fn chain(&self, inner: &Inner, first: u32) -> Vec<u32> {
        let mut out = Vec::new();
        let mut c = first;
        while !self.is_end(c) && out.len() <= self.clusters as usize {
            out.push(c);
            c = self.get(inner, c);
        }
        out
    }

    fn cluster_offset(&self, c: u32) -> u64 {
        (self.data_start * self.bps) + (c as u64 - 2) * self.cluster_size
    }

    /// A free cluster, marked as the end of a chain and linked after `prev`.
    fn alloc(&self, inner: &mut Inner, prev: Option<u32>, zero: bool) -> KResult<u32> {
        let total = self.clusters;
        let start = inner.hint.clamp(2, total + 1);
        let found = (start..total + 2)
            .chain(2..start)
            .find(|&c| self.get(inner, c) == 0)
            .ok_or(Errno::ENOSPC)?;
        let eoc = self.eoc();
        self.set(inner, found, eoc);
        if let Some(p) = prev {
            self.set(inner, p, found);
        }
        inner.hint = found + 1;
        if zero {
            let z = vec![0u8; self.cluster_size as usize];
            block::write_bytes(self.dev.as_ref(), self.cluster_offset(found), &z)?;
        }
        Ok(found)
    }

    fn free_chain(&self, inner: &mut Inner, first: u32) {
        for c in self.chain(inner, first) {
            self.set(inner, c, 0);
        }
    }

    fn free_clusters(&self) -> u64 {
        let inner = self.inner.lock();
        (2..self.clusters + 2)
            .filter(|&c| self.get(&inner, c) == 0)
            .count() as u64
    }

    // Directories as byte arrays of 32-byte entries.

    fn dir_len(&self, inner: &Inner, loc: DirLoc) -> u64 {
        match loc {
            DirLoc::FixedRoot => self.root_entries * 32,
            DirLoc::Chain(first) => self.chain(inner, first).len() as u64 * self.cluster_size,
        }
    }

    /// Device byte offset of byte `pos` of a directory.
    fn dir_offset(&self, inner: &Inner, loc: DirLoc, pos: u64) -> KResult<u64> {
        match loc {
            DirLoc::FixedRoot => {
                if pos >= self.root_entries * 32 {
                    return Err(Errno::EIO);
                }
                Ok(self.root_start * self.bps + pos)
            }
            DirLoc::Chain(first) => {
                let chain = self.chain(inner, first);
                let c = *chain
                    .get((pos / self.cluster_size) as usize)
                    .ok_or(Errno::EIO)?;
                Ok(self.cluster_offset(c) + pos % self.cluster_size)
            }
        }
    }

    fn dir_read(&self, inner: &Inner, loc: DirLoc) -> KResult<Vec<u8>> {
        match loc {
            DirLoc::FixedRoot => {
                let mut b = vec![0u8; (self.root_entries * 32) as usize];
                block::read_bytes(self.dev.as_ref(), self.root_start * self.bps, &mut b)?;
                Ok(b)
            }
            DirLoc::Chain(first) => {
                let chain = self.chain(inner, first);
                let cs = self.cluster_size as usize;
                let mut b = vec![0u8; chain.len() * cs];
                for (i, &c) in chain.iter().enumerate() {
                    block::read_bytes(
                        self.dev.as_ref(),
                        self.cluster_offset(c),
                        &mut b[i * cs..(i + 1) * cs],
                    )?;
                }
                Ok(b)
            }
        }
    }

    fn entry_write(&self, inner: &Inner, loc: DirLoc, pos: u64, e: &[u8; 32]) -> KResult<()> {
        let at = self.dir_offset(inner, loc, pos)?;
        block::write_bytes(self.dev.as_ref(), at, e)
    }

    fn entry_read(&self, inner: &Inner, loc: DirLoc, pos: u64) -> KResult<[u8; 32]> {
        let at = self.dir_offset(inner, loc, pos)?;
        let mut e = [0u8; 32];
        block::read_bytes(self.dev.as_ref(), at, &mut e)?;
        Ok(e)
    }

    fn list(&self, inner: &Inner, loc: DirLoc) -> KResult<Vec<RawEntry>> {
        let bytes = self.dir_read(inner, loc)?;
        let mut out = Vec::new();
        let mut lfn: Vec<u16> = Vec::new();
        let mut lfn_start = None;
        let mut lfn_sum = 0u8;
        for (i, e) in bytes.as_chunks::<32>().0.iter().enumerate() {
            let pos = i as u64 * 32;
            match e[0] {
                0 => break,
                DELETED => {
                    lfn.clear();
                    lfn_start = None;
                    continue;
                }
                _ => {}
            }
            let attr = e[11];
            if attr & 0x3f == ATTR_LFN {
                let ord = e[0];
                if ord & 0x40 != 0 {
                    lfn.clear();
                    lfn_start = Some(pos);
                    lfn_sum = e[13];
                }
                let mut part = Vec::with_capacity(13);
                for o in (1..11)
                    .step_by(2)
                    .chain((14..26).step_by(2))
                    .chain((28..32).step_by(2))
                {
                    part.push(le16(e, o));
                }
                // Parts come last-first: prepend.
                part.extend_from_slice(&lfn);
                lfn = part;
                continue;
            }
            if attr & ATTR_VOLUME_ID != 0 {
                lfn.clear();
                lfn_start = None;
                continue;
            }
            let short: [u8; 11] = e[0..11].try_into().unwrap();
            let long = if lfn_start.is_some() && checksum(&short) == lfn_sum {
                let units: Vec<u16> = lfn
                    .iter()
                    .copied()
                    .take_while(|&u| u != 0 && u != 0xffff)
                    .collect();
                Some(
                    char::decode_utf16(units)
                        .map(|c| c.unwrap_or('?'))
                        .collect::<String>(),
                )
            } else {
                None
            };
            let name = long.unwrap_or_else(|| short_to_name(&short, e[12]));
            let first = (le16(e, 20) as u32) << 16 | le16(e, 26) as u32;
            out.push(RawEntry {
                name,
                short,
                attr,
                first: if self.kind == Kind::Fat32 {
                    first
                } else {
                    first & 0xffff
                },
                size: le32(e, 28),
                mtime: fat_to_unix(le16(e, 24), le16(e, 22)),
                pos,
                start: lfn_start.unwrap_or(pos),
            });
            lfn.clear();
            lfn_start = None;
        }
        Ok(out)
    }

    /// Byte position of `n` consecutive free entries, growing a chained
    /// directory when needed.
    fn free_slots(&self, inner: &mut Inner, loc: DirLoc, n: u64) -> KResult<u64> {
        let bytes = self.dir_read(inner, loc)?;
        let (mut run, mut run_start) = (0u64, 0u64);
        for (i, e) in bytes.as_chunks::<32>().0.iter().enumerate() {
            let pos = i as u64 * 32;
            if e[0] == 0 {
                // Everything from here on is free.
                if run == 0 {
                    run_start = pos;
                }
                let left = bytes.len() as u64 - run_start;
                if left >= n * 32 {
                    return Ok(run_start);
                }
                run = 0;
                break;
            }
            if e[0] == DELETED {
                if run == 0 {
                    run_start = pos;
                }
                run += 1;
                if run == n {
                    return Ok(run_start);
                }
            } else {
                run = 0;
            }
        }
        let DirLoc::Chain(first) = loc else {
            return Err(Errno::ENOSPC);
        };
        // Grow: enough zeroed clusters after the current end.
        let len = bytes.len() as u64;
        let start = if run > 0 {
            run_start
        } else {
            self.first_free_tail(&bytes).unwrap_or(len)
        };
        let need = start + n * 32;
        let mut last = *self.chain(inner, first).last().ok_or(Errno::EIO)?;
        let mut have = len;
        while have < need {
            last = self.alloc(inner, Some(last), true)?;
            have += self.cluster_size;
        }
        Ok(start)
    }

    fn first_free_tail(&self, bytes: &[u8]) -> Option<u64> {
        bytes
            .as_chunks::<32>()
            .0
            .iter()
            .position(|e| e[0] == 0)
            .map(|i| i as u64 * 32)
    }

    /// Writes long-name entries and the short entry for `name` at the
    /// first free place; returns the short entry's position.
    #[allow(clippy::too_many_arguments)]
    fn add_entry(
        &self,
        inner: &mut Inner,
        loc: DirLoc,
        name: &str,
        attr: u8,
        first: u32,
        size: u32,
        mtime: u64,
    ) -> KResult<u64> {
        let existing = self.list(inner, loc)?;
        let short = make_short(name, &existing)?;
        let units: Vec<u16> = name.encode_utf16().collect();
        let needs_lfn = short_to_name(&short, 0) != name;
        let lfn_count = if needs_lfn {
            units.len().div_ceil(13) as u64
        } else {
            0
        };
        let start = self.free_slots(inner, loc, lfn_count + 1)?;
        let sum = checksum(&short);
        for k in 0..lfn_count {
            // Entries from the last part to the first.
            let ord = lfn_count - k;
            let mut e = [0u8; 32];
            e[0] = ord as u8 | if k == 0 { 0x40 } else { 0 };
            e[11] = ATTR_LFN;
            e[13] = sum;
            let base = (ord - 1) as usize * 13;
            let offs = (1..11)
                .step_by(2)
                .chain((14..26).step_by(2))
                .chain((28..32).step_by(2));
            for (j, o) in offs.enumerate() {
                let u = match base + j {
                    i if i < units.len() => units[i],
                    i if i == units.len() => 0,
                    _ => 0xffff,
                };
                e[o..o + 2].copy_from_slice(&u.to_le_bytes());
            }
            self.entry_write(inner, loc, start + k * 32, &e)?;
        }
        let pos = start + lfn_count * 32;
        let mut e = [0u8; 32];
        e[0..11].copy_from_slice(&short);
        e[11] = attr;
        fill_short(&mut e, first, size, mtime);
        self.entry_write(inner, loc, pos, &e)?;
        Ok(pos)
    }

    fn delete_entry(&self, inner: &Inner, loc: DirLoc, raw: &RawEntry) -> KResult<()> {
        let mut p = raw.start;
        while p <= raw.pos {
            let mut e = self.entry_read(inner, loc, p)?;
            e[0] = DELETED;
            self.entry_write(inner, loc, p, &e)?;
            p += 32;
        }
        Ok(())
    }

    /// The node for an entry, the same one while it lives.
    fn node(self: &Arc<Self>, parent: &Arc<Node>, loc: DirLoc, raw: &RawEntry) -> Arc<Node> {
        let key = (loc, raw.pos);
        if let Some(n) = self.by_pos.lock().get(&key).and_then(Weak::upgrade) {
            return n;
        }
        let node = Arc::new(Node {
            fs: self.clone(),
            ino: new_ino(),
            is_dir: raw.attr & ATTR_DIRECTORY != 0,
            st: SpinLock::new(NodeState {
                first: raw.first,
                size: raw.size,
                attr: raw.attr,
                mtime: raw.mtime,
                pos: Some(key),
                parent: Arc::downgrade(parent),
            }),
        });
        self.by_pos.lock().insert(key, Arc::downgrade(&node));
        self.by_ino.lock().insert(node.ino, Arc::downgrade(&node));
        node
    }
}

impl FsInfo for FatFs {
    fn magic(&self) -> u64 {
        MSDOS_SUPER_MAGIC
    }
    fn stats(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.cluster_size,
            self.clusters as u64,
            self.free_clusters(),
            0,
            0,
        )
    }
}

struct RawEntry {
    name: String,
    short: [u8; 11],
    attr: u8,
    first: u32,
    size: u32,
    mtime: u64,
    /// Position of the short entry, and of the first long-name entry.
    pos: u64,
    start: u64,
}

struct NodeState {
    first: u32,
    size: u32,
    attr: u8,
    mtime: u64,
    /// (directory, position) of its entry; None for the root and for a
    /// node taken out of its directory by a rename in progress.
    pos: Option<(DirLoc, u64)>,
    parent: Weak<Node>,
}

pub struct Node {
    fs: Arc<FatFs>,
    ino: u64,
    is_dir: bool,
    st: SpinLock<NodeState>,
}

impl Node {
    fn loc(&self) -> DirLoc {
        let first = self.st.lock().first;
        if first == 0 {
            DirLoc::FixedRoot
        } else {
            DirLoc::Chain(first)
        }
    }

    fn this(&self) -> Arc<Node> {
        self.fs
            .by_ino
            .lock()
            .get(&self.ino)
            .and_then(Weak::upgrade)
            .expect("live node")
    }

    /// Writes first cluster, size and time back into its entry.
    fn sync_entry(&self, inner: &Inner) -> KResult<()> {
        let (pos, first, size, mtime) = {
            let st = self.st.lock();
            (st.pos, st.first, st.size, st.mtime)
        };
        let Some((loc, p)) = pos else { return Ok(()) };
        let mut e = self.fs.entry_read(inner, loc, p)?;
        fill_short(&mut e, first, if self.is_dir { 0 } else { size }, mtime);
        self.fs.entry_write(inner, loc, p, &e)
    }

    fn find(&self, inner: &Inner, name: &str) -> KResult<RawEntry> {
        self.fs
            .list(inner, self.loc())?
            .into_iter()
            .find(|r| r.name.eq_ignore_ascii_case(name) && r.name != "." && r.name != "..")
            .ok_or(Errno::ENOENT)
    }

    fn check_writable(&self) -> KResult<()> {
        if self.fs.dev.read_only() {
            Err(Errno::EROFS)
        } else {
            Ok(())
        }
    }

    fn write_inner(&self, inner: &mut Inner, off: u64, data: &[u8]) -> KResult<usize> {
        let fs = &self.fs;
        let end = off + data.len() as u64;
        if end > u32::MAX as u64 {
            return Err(Errno::EFBIG);
        }
        let size = self.st.lock().size as u64;
        if off > size {
            // FAT has no holes: write the gap as zeros first.
            let zeros = vec![0u8; (off - size) as usize];
            self.write_inner(inner, size, &zeros)?;
        }
        let first = self.st.lock().first;
        let cs = fs.cluster_size;
        let need = end.div_ceil(cs) as usize;
        let mut chain = if first == 0 {
            Vec::new()
        } else {
            fs.chain(inner, first)
        };
        while chain.len() < need {
            let c = fs.alloc(inner, chain.last().copied(), false)?;
            if chain.is_empty() {
                self.st.lock().first = c;
            }
            chain.push(c);
        }
        let mut done = 0usize;
        while done < data.len() {
            let at = off + done as u64;
            let c = chain[(at / cs) as usize];
            let n = ((cs - at % cs) as usize).min(data.len() - done);
            block::write_bytes(
                fs.dev.as_ref(),
                fs.cluster_offset(c) + at % cs,
                &data[done..done + n],
            )?;
            done += n;
        }
        {
            let mut st = self.st.lock();
            st.size = st.size.max(end as u32);
            st.mtime = crate::time::realtime_ns() / 1_000_000_000;
        }
        fs.flush(inner)?;
        self.sync_entry(inner)?;
        Ok(data.len())
    }
}

impl Inode for Node {
    fn file_type(&self) -> FileType {
        if self.is_dir {
            FileType::Directory
        } else {
            FileType::Regular
        }
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        if self.st.lock().attr & ATTR_READ_ONLY != 0 {
            0o555
        } else {
            0o755
        }
    }
    fn set_perm(&self, _perm: u32) -> KResult<()> {
        Err(Errno::EPERM)
    }
    fn size(&self) -> u64 {
        if self.is_dir {
            let inner = self.fs.inner.lock();
            self.fs.dir_len(&inner, self.loc())
        } else {
            self.st.lock().size as u64
        }
    }
    fn dev(&self) -> u64 {
        self.fs.dev_id
    }
    fn mtime(&self) -> u64 {
        self.st.lock().mtime
    }
    fn set_mtime(&self, secs: u64) {
        self.st.lock().mtime = secs;
        let inner = self.fs.inner.lock();
        let _ = self.sync_entry(&inner);
    }
    fn nlink(&self) -> u64 {
        1
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        if self.is_dir {
            return Err(Errno::EISDIR);
        }
        let fs = &self.fs;
        let inner = fs.inner.lock();
        let (first, size) = {
            let st = self.st.lock();
            (st.first, st.size as u64)
        };
        if off >= size {
            return Ok(0);
        }
        let len = buf.len().min((size - off) as usize);
        let chain = fs.chain(&inner, first);
        let cs = fs.cluster_size;
        let mut done = 0usize;
        while done < len {
            let at = off + done as u64;
            let Some(&c) = chain.get((at / cs) as usize) else {
                break;
            };
            let n = ((cs - at % cs) as usize).min(len - done);
            block::read_bytes(
                fs.dev.as_ref(),
                fs.cluster_offset(c) + at % cs,
                &mut buf[done..done + n],
            )?;
            done += n;
        }
        Ok(done)
    }

    fn write_at(&self, off: u64, data: &[u8]) -> KResult<usize> {
        if self.is_dir {
            return Err(Errno::EISDIR);
        }
        self.check_writable()?;
        if data.is_empty() {
            return Ok(0);
        }
        let mut inner = self.fs.inner.lock();
        self.write_inner(&mut inner, off, data)
    }

    fn truncate(&self, len: u64) -> KResult<()> {
        if self.is_dir {
            return Err(Errno::EISDIR);
        }
        self.check_writable()?;
        if len > u32::MAX as u64 {
            return Err(Errno::EFBIG);
        }
        let fs = &self.fs;
        let mut inner = fs.inner.lock();
        let (first, size) = {
            let st = self.st.lock();
            (st.first, st.size as u64)
        };
        if len > size {
            let zeros = vec![0u8; (len - size) as usize];
            self.write_inner(&mut inner, size, &zeros)?;
            return Ok(());
        }
        let keep = len.div_ceil(fs.cluster_size) as usize;
        let chain = if first == 0 {
            Vec::new()
        } else {
            fs.chain(&inner, first)
        };
        if keep == 0 {
            if first != 0 {
                fs.free_chain(&mut inner, first);
            }
            self.st.lock().first = 0;
        } else if keep < chain.len() {
            fs.free_chain(&mut inner, chain[keep]);
            let eoc = fs.eoc();
            fs.set(&mut inner, chain[keep - 1], eoc);
        }
        {
            let mut st = self.st.lock();
            st.size = len as u32;
            st.mtime = crate::time::realtime_ns() / 1_000_000_000;
        }
        fs.flush(&mut inner)?;
        self.sync_entry(&inner)
    }

    fn lookup(&self, name: &str) -> KResult<Arc<dyn Inode>> {
        if !self.is_dir {
            return Err(Errno::ENOTDIR);
        }
        match name {
            "." => return Ok(self.this()),
            ".." => return Ok(self.parent().unwrap_or_else(|| self.this())),
            _ => {}
        }
        let raw = {
            let inner = self.fs.inner.lock();
            self.find(&inner, name)?
        };
        Ok(self.fs.node(&self.this(), self.loc(), &raw))
    }

    fn parent(&self) -> Option<Arc<dyn Inode>> {
        let p = self.st.lock().parent.upgrade();
        Some(match p {
            Some(p) => p,
            None => self.this(), // the root
        })
    }

    fn entries(&self) -> KResult<Vec<(String, Arc<dyn Inode>)>> {
        if !self.is_dir {
            return Err(Errno::ENOTDIR);
        }
        let raws = {
            let inner = self.fs.inner.lock();
            self.fs.list(&inner, self.loc())?
        };
        let me = self.this();
        let loc = self.loc();
        Ok(raws
            .into_iter()
            .filter(|r| r.name != "." && r.name != "..")
            .map(|r| {
                let n: Arc<dyn Inode> = self.fs.node(&me, loc, &r);
                (r.name, n)
            })
            .collect())
    }

    fn is_empty_dir(&self) -> bool {
        self.entries().map(|e| e.is_empty()).unwrap_or(false)
    }

    fn create(&self, name: &str, ty: FileType, _perm: u32) -> KResult<Arc<dyn Inode>> {
        if !self.is_dir {
            return Err(Errno::ENOTDIR);
        }
        self.check_writable()?;
        valid_name(name)?;
        let attr = match ty {
            FileType::Regular => ATTR_ARCHIVE,
            FileType::Directory => ATTR_DIRECTORY,
            _ => return Err(Errno::EPERM),
        };
        let fs = &self.fs;
        let mut inner = fs.inner.lock();
        if self.find(&inner, name).is_ok() {
            return Err(Errno::EEXIST);
        }
        let now = crate::time::realtime_ns() / 1_000_000_000;
        let loc = self.loc();
        let first = if ty == FileType::Directory {
            let c = fs.alloc(&mut inner, None, true)?;
            // "." and "..": the parent's cluster, 0 for the root.
            let parent_first = match loc {
                DirLoc::FixedRoot => 0,
                DirLoc::Chain(f) if f == fs.root_cluster && fs.kind == Kind::Fat32 => 0,
                DirLoc::Chain(f) => f,
            };
            for (i, (n, target)) in [(*b".          ", c), (*b"..         ", parent_first)]
                .iter()
                .enumerate()
            {
                let mut e = [0u8; 32];
                e[0..11].copy_from_slice(n);
                e[11] = ATTR_DIRECTORY;
                fill_short(&mut e, *target, 0, now);
                fs.entry_write(&inner, DirLoc::Chain(c), i as u64 * 32, &e)?;
            }
            c
        } else {
            0
        };
        let pos = fs.add_entry(&mut inner, loc, name, attr, first, 0, now)?;
        fs.flush(&mut inner)?;
        let raw = fs
            .list(&inner, loc)?
            .into_iter()
            .find(|r| r.pos == pos)
            .ok_or(Errno::EIO)?;
        drop(inner);
        Ok(fs.node(&self.this(), loc, &raw))
    }

    fn remove(&self, name: &str, dir: bool) -> KResult<()> {
        self.check_writable()?;
        let fs = &self.fs;
        let loc = self.loc();
        let raw = {
            let inner = fs.inner.lock();
            self.find(&inner, name)?
        };
        let is_dir = raw.attr & ATTR_DIRECTORY != 0;
        match (dir, is_dir) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            _ => {}
        }
        if is_dir {
            let node = fs.node(&self.this(), loc, &raw);
            if !node.is_empty_dir() {
                return Err(Errno::ENOTEMPTY);
            }
        }
        let mut inner = fs.inner.lock();
        fs.delete_entry(&inner, loc, &raw)?;
        if raw.first != 0 {
            fs.free_chain(&mut inner, raw.first);
        }
        fs.flush(&mut inner)?;
        if let Some(n) = fs
            .by_pos
            .lock()
            .remove(&(loc, raw.pos))
            .and_then(|w| w.upgrade())
        {
            let mut st = n.st.lock();
            st.pos = None;
            st.first = 0;
            st.size = 0;
        }
        Ok(())
    }

    fn take(&self, name: &str) -> KResult<Arc<dyn Inode>> {
        self.check_writable()?;
        let fs = &self.fs;
        let loc = self.loc();
        let inner = fs.inner.lock();
        let raw = self.find(&inner, name)?;
        let node = {
            drop(inner);
            fs.node(&self.this(), loc, &raw)
        };
        let inner = fs.inner.lock();
        fs.delete_entry(&inner, loc, &raw)?;
        fs.by_pos.lock().remove(&(loc, raw.pos));
        node.st.lock().pos = None;
        Ok(node)
    }

    fn insert(&self, name: &str, inode: Arc<dyn Inode>) -> KResult<()> {
        self.check_writable()?;
        if inode.dev() != self.fs.dev_id {
            return Err(Errno::EXDEV);
        }
        valid_name(name)?;
        let fs = &self.fs;
        let node = fs
            .by_ino
            .lock()
            .get(&inode.ino())
            .and_then(Weak::upgrade)
            .ok_or(Errno::EXDEV)?;
        let (linked, first, size, attr, mtime) = {
            let st = node.st.lock();
            (st.pos.is_some(), st.first, st.size, st.attr, st.mtime)
        };
        if linked {
            return Err(Errno::EPERM); // FAT has no hard links
        }
        let loc = self.loc();
        let mut inner = fs.inner.lock();
        if self.find(&inner, name).is_ok() {
            return Err(Errno::EEXIST);
        }
        let pos = fs.add_entry(&mut inner, loc, name, attr, first, size, mtime)?;
        if node.is_dir && first != 0 {
            // Its ".." now names this directory.
            let parent_first = match loc {
                DirLoc::FixedRoot => 0,
                DirLoc::Chain(f) if f == fs.root_cluster && fs.kind == Kind::Fat32 => 0,
                DirLoc::Chain(f) => f,
            };
            let mut e = fs.entry_read(&inner, DirLoc::Chain(first), 32)?;
            fill_short(&mut e, parent_first, 0, mtime);
            fs.entry_write(&inner, DirLoc::Chain(first), 32, &e)?;
        }
        fs.flush(&mut inner)?;
        {
            let mut st = node.st.lock();
            st.pos = Some((loc, pos));
            st.parent = Arc::downgrade(&self.this());
        }
        fs.by_pos.lock().insert((loc, pos), Arc::downgrade(&node));
        Ok(())
    }

    fn symlink(&self, _name: &str, _target: &str) -> KResult<()> {
        Err(Errno::EPERM)
    }

    fn stat(&self) -> Stat {
        let size = self.size();
        let t = self.mtime() as i64;
        let cs = self.fs.cluster_size;
        Stat {
            st_dev: self.dev(),
            st_ino: self.ino,
            st_nlink: 1,
            st_mode: self.file_type().mode_bits() | self.perm(),
            st_size: size as i64,
            st_blksize: cs as i64,
            st_blocks: (size.div_ceil(cs) * cs / 512) as i64,
            st_atime: t,
            st_mtime: t,
            st_ctime: t,
            ..Stat::default()
        }
    }
}

fn checksum(short: &[u8; 11]) -> u8 {
    short.iter().fold(0u8, |s, &c| {
        ((s & 1) << 7).wrapping_add(s >> 1).wrapping_add(c)
    })
}

/// "README  TXT" → "README.TXT", with the lowercase flags Windows sets.
fn short_to_name(short: &[u8; 11], ntres: u8) -> String {
    let mut base: String = short[0..8]
        .iter()
        .map(|&c| c as char)
        .collect::<String>()
        .trim_end()
        .into();
    let mut ext: String = short[8..11]
        .iter()
        .map(|&c| c as char)
        .collect::<String>()
        .trim_end()
        .into();
    if base.starts_with('\u{5}') {
        base.replace_range(0..1, "\u{e5}");
    }
    if ntres & 0x08 != 0 {
        base = base.to_ascii_lowercase();
    }
    if ntres & 0x10 != 0 {
        ext = ext.to_ascii_lowercase();
    }
    if ext.is_empty() {
        base
    } else {
        alloc::format!("{base}.{ext}")
    }
}

fn valid_name(name: &str) -> KResult<()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(Errno::EINVAL);
    }
    if name.encode_utf16().count() > 255 {
        return Err(Errno::ENAMETOOLONG);
    }
    if name
        .chars()
        .any(|c| (c as u32) < 0x20 || "\"*/:<>?\\|".contains(c))
    {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

fn short_char(c: char) -> Option<u8> {
    match c {
        'a'..='z' => Some(c.to_ascii_uppercase() as u8),
        'A'..='Z' | '0'..='9' => Some(c as u8),
        '!' | '#' | '$' | '%' | '&' | '\'' | '(' | ')' | '-' | '@' | '^' | '_' | '`' | '{'
        | '}' | '~' => Some(c as u8),
        _ => None,
    }
}

/// The 8.3 name for `name`: itself if it is a valid uppercase 8.3 name,
/// otherwise an unused "BASE~N.EXT" alias.
fn make_short(name: &str, existing: &[RawEntry]) -> KResult<[u8; 11]> {
    let (base, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i + 1..]),
        _ => (name, ""),
    };
    let clean =
        |s: &str, max: usize| -> Vec<u8> { s.chars().filter_map(short_char).take(max).collect() };
    let exact = base.len() <= 8
        && ext.len() <= 3
        && !base.is_empty()
        && base
            .chars()
            .chain(ext.chars())
            .all(|c| short_char(c) == Some(c as u8));
    let mut short = [b' '; 11];
    let e = clean(ext, 3);
    short[8..8 + e.len()].copy_from_slice(&e);
    if exact {
        short[..base.len()].copy_from_slice(base.as_bytes());
        return Ok(short);
    }
    let mut b = clean(base, 8);
    if b.is_empty() {
        b = b"FILE".to_vec();
    }
    for n in 1..1_000_000u32 {
        let tail = alloc::format!("~{n}");
        let keep = b.len().min(8 - tail.len());
        let mut s = short;
        s[..8].fill(b' ');
        s[..keep].copy_from_slice(&b[..keep]);
        s[keep..keep + tail.len()].copy_from_slice(tail.as_bytes());
        if !existing.iter().any(|r| r.short == s) {
            return Ok(s);
        }
    }
    Err(Errno::ENOSPC)
}

fn fill_short(e: &mut [u8; 32], first: u32, size: u32, mtime: u64) {
    let (date, time) = unix_to_fat(mtime);
    e[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
    e[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e[22..24].copy_from_slice(&time.to_le_bytes());
    e[24..26].copy_from_slice(&date.to_le_bytes());
    e[18..20].copy_from_slice(&date.to_le_bytes()); // access date
    if e[16] == 0 && e[17] == 0 {
        e[14..16].copy_from_slice(&time.to_le_bytes());
        e[16..18].copy_from_slice(&date.to_le_bytes());
    }
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

fn fat_to_unix(date: u16, time: u16) -> u64 {
    if date == 0 {
        return 0;
    }
    let (y, m, d) = (
        1980 + (date >> 9) as i64,
        ((date >> 5) & 15) as i64,
        (date & 31) as i64,
    );
    let days = days_from_civil(y, m.clamp(1, 12), d.clamp(1, 31));
    let secs = (time >> 11) as i64 * 3600 + ((time >> 5) & 63) as i64 * 60 + (time & 31) as i64 * 2;
    (days * 86_400 + secs).max(0) as u64
}

fn unix_to_fat(secs: u64) -> (u16, u16) {
    let secs = secs.max(315_532_800); // 1980-01-01, FAT's epoch
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let (y, m, d) = civil_from_days(days);
    let date = (((y - 1980).min(127) as u16) << 9) | ((m as u16) << 5) | d as u16;
    let time =
        ((rem / 3600) as u16) << 11 | (((rem / 60) % 60) as u16) << 5 | ((rem % 60) / 2) as u16;
    (date, time)
}
