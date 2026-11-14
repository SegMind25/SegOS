//! The VFS side: an ext4 inode as an [`Inode`].
//!
//! Locking: every change runs under the file system's big lock
//! ([`Ext4Fs::modify`]) and holds the state lock of each inode it changes.
//! Reads (file data, lookups) take only the state lock of the inode they
//! read: an inode's blocks only change, or are freed, under its own lock.

use super::dir::{self, DirEntry, DirMap};
use super::extent::{self, Tree};
use super::inode::{
    EXTENTS_FL, IBLOCK_LEN, INDEX_FL, INLINE_DATA_FL, RawInode, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT,
    S_IFREG,
};
use super::{
    Ext4Fs, FsState, INCOMPAT_EXTENTS, INCOMPAT_FILETYPE, INCOMPAT_INLINE_DATA,
    RO_COMPAT_DIR_NLINK, RO_COMPAT_LARGE_FILE, crc, le32, now, put32,
};
use crate::abi::{Errno, KResult, Stat};
use crate::fs::{FileType, Inode};
use crate::sync::{Mutex, Once};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

/// Longest symbolic link target read (Linux: PATH_MAX).
const SYMLINK_MAX: u64 = 4096;
/// Most bytes written to newly allocated blocks in one device request.
const ALLOC_CHUNK: u64 = 1 << 20;
/// Link count at which a directory's count stops (dir_nlink: then 1).
const LINK_MAX: u16 = 65000;
/// Directories this small are searched for free space in every block on
/// insertion; larger ones only in their last block.
const SMALL_DIR_BLOCKS: u64 = 16;

pub struct Ext4Inode {
    fs: Arc<Ext4Fs>,
    ino: u32,
    ty: FileType,
    /// The file type bits of i_mode (never change).
    fmt: u16,
    st: Mutex<IState>,
    /// The pipe of a FIFO, made on first open.
    fifo: Once<Arc<dyn Inode>>,
}

/// An inode's changing state.
struct IState {
    raw: RawInode,
    /// The extent list, read on first use (extent-mapped inodes).
    tree: Option<Tree>,
    /// A directory's entries, read on first use.
    dir: Option<DirMap>,
    /// Freed while still in use: no more I/O.
    deleted: bool,
}

fn valid_name(name: &str) -> KResult<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(Errno::EINVAL);
    }
    if name.len() > 255 {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(())
}

impl IState {
    fn inline(&self, fs: &Ext4Fs) -> bool {
        self.raw.has_inline_data() && fs.has_incompat(INCOMPAT_INLINE_DATA)
    }

    /// Whether i_block holds a block map (not a symlink target, device
    /// number or inline data).
    fn has_block_map(&self, fs: &Ext4Fs) -> bool {
        if self.inline(fs) {
            return false;
        }
        match self.raw.mode & S_IFMT {
            S_IFREG | S_IFDIR => true,
            S_IFLNK => !self.raw.is_fast_symlink(fs),
            _ => false,
        }
    }

    fn tree(&mut self, fs: &Ext4Fs) -> KResult<&mut Tree> {
        if self.tree.is_none() {
            self.tree = Some(extent::load(fs, &self.raw.iblock)?);
        }
        Ok(self.tree.as_mut().unwrap())
    }

    /// Maps file block `lblk`: (device block if mapped and initialised,
    /// run of blocks in the same state).
    fn map(&mut self, fs: &Ext4Fs, lblk: u64) -> KResult<(Option<u64>, u64)> {
        if self.raw.has_extents() {
            Ok(extent::lookup(&self.tree(fs)?.extents, lblk))
        } else {
            let (p, n) = self.raw.map_indirect(fs, lblk)?;
            Ok(((p != 0).then_some(p), n))
        }
    }

    /// The whole content of an inline-data inode: i_block, then the
    /// `system.data` attribute.
    fn inline_content(&self) -> KResult<Vec<u8>> {
        let mut v = self.raw.iblock.to_vec();
        v.extend_from_slice(self.raw.inline_xattr()?);
        Ok(v)
    }

    /// Reads data at `off`, clamped to the file size.
    fn read_data(&mut self, fs: &Ext4Fs, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let size = self.raw.size;
        if off >= size || buf.is_empty() || self.deleted {
            return Ok(0);
        }
        let n = buf.len().min((size - off).min(usize::MAX as u64) as usize);
        let buf = &mut buf[..n];
        if self.inline(fs) {
            let data = self.inline_content()?;
            for (i, b) in buf.iter_mut().enumerate() {
                *b = data.get(off as usize + i).copied().unwrap_or(0);
            }
            return Ok(n);
        }
        let bs = fs.block_size();
        let mut done = 0usize;
        while done < n {
            let pos = off + done as u64;
            let (p, run) = self.map(fs, pos / bs)?;
            let in_blk = pos % bs;
            let avail = run.max(1).saturating_mul(bs) - in_blk;
            let k = (n - done).min(avail.min(1 << 20) as usize);
            let dst = &mut buf[done..done + k];
            match p {
                None => dst.fill(0),
                Some(p) => fs.read_direct(p, in_blk, dst)?,
            }
            done += k;
        }
        Ok(n)
    }

    fn max_size(&self, fs: &Ext4Fs) -> u64 {
        let bs = fs.block_size();
        let by_map = if self.raw.has_extents() {
            ((1u64 << 32) - 1) * bs
        } else {
            let per = bs / 4;
            (12 + per + per * per + per * per * per) * bs
        };
        let by_blocks = if fs.huge_file() {
            u64::MAX
        } else {
            ((1u64 << 32) - 1) * 512
        };
        by_map.min(by_blocks).min(i64::MAX as u64)
    }

    /// Where to look for blocks for file block `lblk`: after the block of
    /// the one before, or in the inode's group.
    fn goal(&mut self, fs: &Ext4Fs, ino: u32, lblk: u64) -> KResult<u64> {
        if self.raw.has_extents() {
            let t = self.tree(fs)?;
            let i = t.extents.partition_point(|e| (e.lblk as u64) < lblk);
            if i > 0 {
                let e = t.extents[i - 1];
                return Ok(e.pblk + (lblk - e.lblk as u64).min(e.len as u64));
            }
            if let Some(e) = t.extents.first() {
                return Ok(e.pblk.saturating_sub(e.lblk as u64 - lblk));
            }
        } else if lblk > 0
            && let (p, _) = self.raw.map_indirect(fs, lblk - 1)?
            && p != 0
        {
            return Ok(p + 1);
        }
        Ok(fs.group_first_block(fs.inode_group(ino)))
    }

    /// Writes `data` at `off`, allocating blocks for holes. Updates size
    /// and times and writes the inode.
    fn write_data(
        &mut self,
        fs: &Ext4Fs,
        st: &mut FsState,
        ino: u32,
        off: u64,
        data: &[u8],
    ) -> KResult<usize> {
        if self.deleted {
            return Err(Errno::EIO);
        }
        if self.inline(fs) {
            self.uninline(fs, st, ino)?;
        }
        let end = off.checked_add(data.len() as u64).ok_or(Errno::EFBIG)?;
        if end > self.max_size(fs) {
            return Err(Errno::EFBIG);
        }
        let bs = fs.block_size();
        let extents = self.raw.has_extents();
        let mut tree_changed = false;
        let mut new_runs: Vec<(u64, u64, u64)> = Vec::new();
        let mut pos = off;
        let r = (|| -> KResult<()> {
            while pos < end {
                let lblk = pos / bs;
                let in_blk = pos % bs;
                // (device block, initialised, run); None: a hole of `run`.
                let (state, run) = if extents {
                    let t = self.tree(fs)?;
                    match extent::lookup_alloc(&t.extents, lblk) {
                        Some((p, init, run)) => (Some((p, init)), run),
                        None => (None, extent::lookup(&t.extents, lblk).1),
                    }
                } else {
                    let (p, run) = self.raw.map_indirect(fs, lblk)?;
                    ((p != 0).then_some((p, true)), run)
                };
                match state {
                    Some((p, true)) => {
                        let n = (run.saturating_mul(bs) - in_blk).min(end - pos);
                        let s = (pos - off) as usize;
                        fs.write_at(p, in_blk, &data[s..s + n as usize])?;
                        pos += n;
                    }
                    _ => {
                        // New blocks (or allocated, unwritten ones): whole
                        // blocks are written, zeros around the data.
                        let want = (end - lblk * bs)
                            .div_ceil(bs)
                            .min(run)
                            .min((ALLOC_CHUNK / bs).max(1));
                        let (p, n) = match state {
                            Some((p, false)) => (p, want),
                            _ => {
                                let goal = self.goal(fs, ino, lblk)?;
                                fs.alloc_blocks(st, goal, want)?
                            }
                        };
                        let mut buf = vec![0u8; (n * bs) as usize];
                        let span_start = lblk * bs;
                        let span_end = ((lblk + n) * bs).min(end);
                        let src = &data[(pos - off) as usize..(span_end - off) as usize];
                        let at = (pos - span_start) as usize;
                        buf[at..at + src.len()].copy_from_slice(src);
                        if let Err(e) = fs.write_at(p, 0, &buf) {
                            if state.is_none() {
                                let _ = fs.free_blocks(st, p, n);
                            }
                            return Err(e);
                        }
                        if extents {
                            extent::insert(&mut self.tree(fs)?.extents, lblk, n, p);
                            tree_changed = true;
                            if state.is_none() {
                                self.raw.add_blocks(fs, n as i64);
                                new_runs.push((lblk, n, p));
                            }
                        } else {
                            let mut meta = 0;
                            let mut mapped = 0;
                            let mut err = None;
                            for i in 0..n {
                                if let Err(e) =
                                    self.raw.set_indirect(fs, st, lblk + i, p + i, &mut meta)
                                {
                                    err = Some(e);
                                    break;
                                }
                                mapped += 1;
                            }
                            self.raw.add_blocks(fs, meta + mapped as i64);
                            if let Some(e) = err {
                                // Out of space for an indirect block: the
                                // unmapped data blocks go back.
                                let _ = fs.free_blocks(st, p + mapped, n - mapped);
                                pos = pos.max(((lblk + mapped) * bs).min(span_end));
                                return Err(e);
                            }
                        }
                        pos = span_end;
                    }
                }
            }
            Ok(())
        })();
        if tree_changed && let Err(e) = self.store_tree(fs, st, ino) {
            // No room for the tree: undo this call's allocations.
            for &(l, n, p) in &new_runs {
                extent::punch(&mut self.tree(fs)?.extents, l, l + n);
                let _ = fs.free_blocks(st, p, n);
                self.raw.add_blocks(fs, -(n as i64));
            }
            let _ = self.store_tree(fs, st, ino);
            fs.write_raw_inode(ino, &self.raw)?;
            return Err(e);
        }
        let written = pos - off;
        if written > 0 {
            if pos > self.raw.size {
                self.raw.size = pos;
                if pos > i32::MAX as u64 {
                    fs.set_ro_compat(st, RO_COMPAT_LARGE_FILE);
                }
            }
            self.touch();
            fs.write_raw_inode(ino, &self.raw)?;
        }
        match r {
            Err(e) if written == 0 => Err(e),
            _ => Ok(written as usize),
        }
    }

    fn store_tree(&mut self, fs: &Ext4Fs, st: &mut FsState, ino: u32) -> KResult<()> {
        let seed = self.raw.csum_seed(fs, ino);
        let goal = fs.group_first_block(fs.inode_group(ino));
        let mut iblock = self.raw.iblock;
        let tree = self.tree.as_mut().ok_or(Errno::EIO)?;
        let delta = extent::store(fs, st, tree, &mut iblock, seed, goal)?;
        self.raw.iblock = iblock;
        self.raw.add_blocks(fs, delta);
        Ok(())
    }

    fn touch(&mut self) {
        let (t, ns) = now();
        (self.raw.mtime, self.raw.mtime_nsec) = (t, ns);
        (self.raw.ctime, self.raw.ctime_nsec) = (t, ns);
    }

    fn touch_ctime(&mut self) {
        let (t, ns) = now();
        (self.raw.ctime, self.raw.ctime_nsec) = (t, ns);
    }

    /// Frees every block at or after file block `from`, and zeroes the
    /// rest of the block holding byte `size` if that is inside it.
    fn free_from(&mut self, fs: &Ext4Fs, st: &mut FsState, ino: u32, size: u64) -> KResult<()> {
        let bs = fs.block_size();
        let from = size.div_ceil(bs);
        if self.raw.has_extents() {
            let removed = extent::punch(&mut self.tree(fs)?.extents, from, u64::MAX);
            let mut freed = 0i64;
            for e in &removed {
                fs.free_blocks(st, e.pblk, e.len as u64)?;
                freed += e.len as i64;
            }
            self.raw.add_blocks(fs, -freed);
            if !removed.is_empty() {
                self.store_tree(fs, st, ino)?;
            }
        } else {
            let mut freed = Vec::new();
            self.raw.truncate_indirect(fs, from, &mut freed)?;
            let n = freed.len() as i64;
            fs.free_block_list(st, freed)?;
            self.raw.add_blocks(fs, -n);
        }
        if !size.is_multiple_of(bs)
            && let (Some(p), _) = self.map(fs, size / bs)?
        {
            let tail = (bs - size % bs) as usize;
            fs.write_at(p, size % bs, &vec![0u8; tail])?;
        }
        Ok(())
    }

    fn truncate(&mut self, fs: &Ext4Fs, st: &mut FsState, ino: u32, len: u64) -> KResult<()> {
        if self.deleted {
            return Err(Errno::EIO);
        }
        if self.inline(fs) {
            self.uninline(fs, st, ino)?;
        }
        if len > self.max_size(fs) {
            return Err(Errno::EFBIG);
        }
        if len < self.raw.size {
            self.free_from(fs, st, ino, len)?;
        }
        self.raw.size = len;
        if len > i32::MAX as u64 {
            fs.set_ro_compat(st, RO_COMPAT_LARGE_FILE);
        }
        self.touch();
        fs.write_raw_inode(ino, &self.raw)
    }

    /// Frees the inode and everything it holds (its last link is gone).
    fn delete(&mut self, fs: &Ext4Fs, st: &mut FsState, ino: u32) -> KResult<()> {
        if self.deleted {
            return Ok(());
        }
        if self.has_block_map(fs) {
            self.free_from(fs, st, ino, 0)?;
            if self.raw.has_extents() {
                extent::empty_root(&mut self.raw.iblock);
            }
        }
        if self.raw.file_acl != 0 {
            release_xattr_block(fs, st, self.raw.file_acl)?;
            self.raw.file_acl = 0;
            put32(&mut self.raw.bytes, 0x68, 0);
            super::put16(&mut self.raw.bytes, 0x76, 0);
        }
        let is_dir = self.raw.mode & S_IFMT == S_IFDIR;
        self.raw.links = 0;
        self.raw.size = 0;
        self.raw.blocks = 0;
        self.raw.dtime = now().0 as u32;
        self.touch_ctime();
        fs.write_raw_inode(ino, &self.raw)?;
        fs.free_inode(st, ino, is_dir)?;
        self.deleted = true;
        self.tree = None;
        self.dir = None;
        Ok(())
    }

    // Directories.

    fn dir_map(&mut self, fs: &Ext4Fs, ino: u32) -> KResult<&mut DirMap> {
        if self.dir.is_none() {
            let filetype = fs.has_incompat(INCOMPAT_FILETYPE);
            let bs = fs.block_size() as usize;
            let mut out = DirMap::new();
            if self.inline(fs) {
                let ib = self.raw.iblock;
                out.insert(
                    b".".to_vec(),
                    DirEntry {
                        ino,
                        lblk: u32::MAX,
                        off: 0,
                    },
                );
                out.insert(
                    b"..".to_vec(),
                    DirEntry {
                        ino: le32(&ib, 0),
                        lblk: u32::MAX,
                        off: 0,
                    },
                );
                dir::parse_block(&ib[4..IBLOCK_LEN], filetype, bs, u32::MAX, &mut out);
                let x = self.raw.inline_xattr()?.to_vec();
                dir::parse_block(&x, filetype, bs, u32::MAX, &mut out);
            } else if !self.deleted {
                let mut block = vec![0u8; bs];
                let nblocks = self.raw.size.div_ceil(bs as u64);
                for lblk in 0..nblocks {
                    let (p, _) = self.map(fs, lblk)?;
                    let Some(p) = p else { continue };
                    let len = (self.raw.size - lblk * bs as u64).min(bs as u64) as usize;
                    block[len..].fill(0);
                    fs.read_direct(p, 0, &mut block[..len])?;
                    dir::parse_block(&block[..len], filetype, bs, lblk as u32, &mut out);
                }
            }
            self.dir = Some(out);
        }
        Ok(self.dir.as_mut().unwrap())
    }

    /// A directory block: (device block, content).
    fn dir_block(&mut self, fs: &Ext4Fs, lblk: u64) -> KResult<(u64, Vec<u8>)> {
        let (p, _) = self.map(fs, lblk)?;
        let p = p.ok_or(Errno::EIO)?;
        let mut b = vec![0u8; fs.block_size() as usize];
        fs.read_direct(p, 0, &mut b)?;
        Ok((p, b))
    }

    /// Where the entries of a directory block end (before the checksum
    /// tail, if it has one).
    fn entries_end(fs: &Ext4Fs, b: &[u8]) -> usize {
        if fs.metadata_csum() && dir::has_tail(b) {
            b.len() - dir::TAIL_LEN
        } else {
            b.len()
        }
    }

    fn put_dir_block(&self, fs: &Ext4Fs, ino: u32, p: u64, b: &mut [u8]) -> KResult<()> {
        if fs.metadata_csum() && dir::has_tail(b) {
            dir::set_tail(b, self.raw.csum_seed(fs, ino));
        }
        fs.write_at(p, 0, b)
    }

    fn check_dir_writable(&mut self, fs: &Ext4Fs, st: &mut FsState, ino: u32) -> KResult<()> {
        if self.deleted {
            return Err(Errno::ENOENT);
        }
        if self.inline(fs) {
            self.uninline(fs, st, ino)?;
        }
        if self.raw.flags & INDEX_FL != 0 {
            self.deindex(fs, st, ino)?;
        }
        Ok(())
    }

    /// Moves the data of an inline-data inode out to blocks (as Linux does
    /// when inline data outgrows the inode): the file or directory then
    /// changes like any other. Refused (EROFS) if the inode keeps other
    /// extended attributes beside the data.
    fn uninline(&mut self, fs: &Ext4Fs, st: &mut FsState, ino: u32) -> KResult<()> {
        if !self.raw.only_data_xattr() {
            return Err(Errno::EROFS);
        }
        let is_dir = self.raw.mode & S_IFMT == S_IFDIR;
        let filetype = fs.has_incompat(INCOMPAT_FILETYPE);
        let mut entries: Vec<(Vec<u8>, u32, u8)> = Vec::new();
        let mut content = Vec::new();
        if is_dir {
            let map = self.dir_map(fs, ino)?.clone();
            let parent = map.get(&b".."[..]).map_or(ino, |e| e.ino);
            entries.push((b".".to_vec(), ino, 2));
            entries.push((b"..".to_vec(), parent, 2));
            for (name, e) in map.iter() {
                if name != b"." && name != b".." {
                    let ft = if filetype { child_ftype(fs, e.ino)? } else { 0 };
                    entries.push((name.clone(), e.ino, ft));
                }
            }
        } else {
            content = self.inline_content()?;
            content.truncate(self.raw.size as usize);
        }
        self.raw.flags &= !INLINE_DATA_FL;
        self.raw.clear_xattrs();
        self.raw.iblock = [0; IBLOCK_LEN];
        self.raw.size = 0;
        self.tree = None;
        self.dir = None;
        if fs.has_incompat(INCOMPAT_EXTENTS) {
            self.raw.flags |= EXTENTS_FL;
            extent::empty_root(&mut self.raw.iblock);
        }
        fs.write_raw_inode(ino, &self.raw)?;
        if is_dir {
            let bs = fs.block_size() as usize;
            let tail = fs.metadata_csum();
            let (mut blocks, locs) = dir::pack(&entries, bs, tail, filetype);
            let seed = self.raw.csum_seed(fs, ino);
            for (i, b) in blocks.iter_mut().enumerate() {
                if tail {
                    dir::set_tail(b, seed);
                }
                self.write_data(fs, st, ino, (i * bs) as u64, b)?;
            }
            let mut out = DirMap::new();
            for ((name, ino, _), (lblk, off)) in entries.into_iter().zip(locs) {
                out.insert(name, DirEntry { ino, lblk, off });
            }
            self.dir = Some(out);
        } else if !content.is_empty() {
            self.write_data(fs, st, ino, 0, &content)?;
        }
        Ok(())
    }

    /// Rewrites a hashed (htree) directory as a plain one: every entry
    /// packed into leaf blocks, the index gone.
    fn deindex(&mut self, fs: &Ext4Fs, st: &mut FsState, ino: u32) -> KResult<()> {
        let bs = fs.block_size() as usize;
        let filetype = fs.has_incompat(INCOMPAT_FILETYPE);
        let map = self.dir_map(fs, ino)?.clone();
        let mut entries: Vec<(Vec<u8>, u32, u8)> = Vec::with_capacity(map.len());
        let parent = map.get(&b".."[..]).map_or(ino, |e| e.ino);
        entries.push((b".".to_vec(), ino, 2));
        entries.push((b"..".to_vec(), parent, 2));
        for (name, e) in map.iter() {
            if name == b"." || name == b".." {
                continue;
            }
            let ft = if filetype { child_ftype(fs, e.ino)? } else { 0 };
            entries.push((name.clone(), e.ino, ft));
        }
        let tail = fs.metadata_csum();
        let (mut blocks, locs) = dir::pack(&entries, bs, tail, filetype);
        let seed = self.raw.csum_seed(fs, ino);
        let old_blocks = self.raw.size / bs as u64;
        for (i, b) in blocks.iter_mut().enumerate() {
            if tail {
                dir::set_tail(b, seed);
            }
            if (i as u64) < old_blocks {
                let (p, _) = self.dir_block(fs, i as u64)?;
                fs.write_at(p, 0, b)?;
            } else {
                self.write_data(fs, st, ino, i as u64 * bs as u64, b)?;
            }
        }
        let new_size = blocks.len() as u64 * bs as u64;
        if new_size < self.raw.size {
            self.free_from(fs, st, ino, new_size)?;
            self.raw.size = new_size;
        }
        self.raw.flags &= !INDEX_FL;
        let mut out = DirMap::new();
        for ((name, ino, _), (lblk, off)) in entries.into_iter().zip(locs) {
            out.insert(name, DirEntry { ino, lblk, off });
        }
        self.dir = Some(out);
        fs.write_raw_inode(ino, &self.raw)
    }

    /// Adds `name` → `child` (of directory entry type `ft`).
    fn dir_add(
        &mut self,
        fs: &Ext4Fs,
        st: &mut FsState,
        ino: u32,
        name: &[u8],
        child: u32,
        ft: u8,
    ) -> KResult<()> {
        self.check_dir_writable(fs, st, ino)?;
        if self.dir_map(fs, ino)?.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let filetype = fs.has_incompat(INCOMPAT_FILETYPE);
        let bs = fs.block_size();
        let nblocks = self.raw.size / bs;
        let first = if nblocks <= SMALL_DIR_BLOCKS {
            0
        } else {
            nblocks - 1
        };
        for lblk in first..nblocks {
            let (p, mut b) = self.dir_block(fs, lblk)?;
            let end = Self::entries_end(fs, &b);
            if let Some(off) = dir::try_insert(&mut b, end, name, child, ft, filetype) {
                self.put_dir_block(fs, ino, p, &mut b)?;
                self.dir_map(fs, ino)?.insert(
                    name.to_vec(),
                    DirEntry {
                        ino: child,
                        lblk: lblk as u32,
                        off: off as u32,
                    },
                );
                self.touch();
                return fs.write_raw_inode(ino, &self.raw);
            }
        }
        // A new block.
        let tail = fs.metadata_csum();
        let (mut blocks, _) = dir::pack(&[(name.to_vec(), child, ft)], bs as usize, tail, filetype);
        let b = &mut blocks[0];
        if tail {
            dir::set_tail(b, self.raw.csum_seed(fs, ino));
        }
        self.write_data(fs, st, ino, nblocks * bs, b)?;
        self.dir_map(fs, ino)?.insert(
            name.to_vec(),
            DirEntry {
                ino: child,
                lblk: nblocks as u32,
                off: 0,
            },
        );
        Ok(())
    }

    /// Takes `name` out of the directory: the inode it named.
    fn dir_remove(&mut self, fs: &Ext4Fs, st: &mut FsState, ino: u32, name: &[u8]) -> KResult<u32> {
        self.check_dir_writable(fs, st, ino)?;
        let e = *self.dir_map(fs, ino)?.get(name).ok_or(Errno::ENOENT)?;
        let filetype = fs.has_incompat(INCOMPAT_FILETYPE);
        let (p, mut b) = self.dir_block(fs, e.lblk as u64)?;
        let end = Self::entries_end(fs, &b);
        if !dir::remove_at(&mut b, end, e.off as usize, filetype) {
            return Err(Errno::EIO);
        }
        self.put_dir_block(fs, ino, p, &mut b)?;
        self.dir_map(fs, ino)?.remove(name);
        self.touch();
        fs.write_raw_inode(ino, &self.raw)?;
        Ok(e.ino)
    }

    /// Points the existing entry `name` at `child`.
    fn dir_set(
        &mut self,
        fs: &Ext4Fs,
        st: &mut FsState,
        ino: u32,
        name: &[u8],
        child: u32,
        ft: u8,
    ) -> KResult<()> {
        self.check_dir_writable(fs, st, ino)?;
        let e = *self.dir_map(fs, ino)?.get(name).ok_or(Errno::ENOENT)?;
        let filetype = fs.has_incompat(INCOMPAT_FILETYPE);
        let (p, mut b) = self.dir_block(fs, e.lblk as u64)?;
        dir::set_entry_ino(&mut b, e.off as usize, child, ft, filetype);
        self.put_dir_block(fs, ino, p, &mut b)?;
        self.dir_map(fs, ino)?
            .insert(name.to_vec(), DirEntry { ino: child, ..e });
        self.touch_ctime();
        fs.write_raw_inode(ino, &self.raw)
    }

    /// One more subdirectory ("..") links here.
    fn inc_dir_links(&mut self, fs: &Ext4Fs) -> KResult<()> {
        if self.raw.links >= LINK_MAX || self.raw.links == 1 {
            if fs.sb.ro_compat & RO_COMPAT_DIR_NLINK == 0 {
                return Err(Errno::EMLINK);
            }
            self.raw.links = 1;
        } else {
            self.raw.links += 1;
        }
        Ok(())
    }

    fn dec_dir_links(&mut self) {
        if self.raw.links > 2 {
            self.raw.links -= 1;
        }
    }
}

/// The directory entry type of inode `ino`, from its mode.
fn child_ftype(fs: &Ext4Fs, ino: u32) -> KResult<u8> {
    let raw = match fs.cached_inode(ino) {
        Some(i) => i.fmt,
        None => fs.read_raw_inode(ino)?.mode,
    };
    Ok(mode_ftype(raw))
}

fn mode_ftype(mode: u16) -> u8 {
    use super::inode::{S_IFBLK, S_IFCHR, S_IFSOCK};
    match mode & S_IFMT {
        S_IFREG => 1,
        S_IFDIR => 2,
        S_IFCHR => 3,
        S_IFBLK => 4,
        S_IFIFO => 5,
        S_IFSOCK => 6,
        S_IFLNK => 7,
        _ => 0,
    }
}

/// Drops one reference to an extended attribute block, freeing it with
/// the last.
fn release_xattr_block(fs: &Ext4Fs, st: &mut FsState, blk: u64) -> KResult<()> {
    let mut b = fs.block(blk)?.to_vec();
    if le32(&b, 0) != 0xea02_0000 {
        return Ok(()); // not an xattr block: leave it alone
    }
    let refs = le32(&b, 4);
    if refs <= 1 {
        return fs.free_blocks(st, blk, 1);
    }
    put32(&mut b, 4, refs - 1);
    if fs.metadata_csum() {
        put32(&mut b, 0x10, 0);
        let c = crc::crc32c(fs.seed, &blk.to_le_bytes());
        let c = crc::crc32c(c, &b);
        put32(&mut b, 0x10, c);
    }
    fs.write_at(blk, 0, &b)
}

impl Ext4Inode {
    pub(super) fn new(fs: Arc<Ext4Fs>, ino: u32, raw: RawInode) -> Self {
        Self {
            fs,
            ino,
            ty: raw.file_type().unwrap_or(FileType::Regular),
            fmt: raw.mode & S_IFMT,
            st: Mutex::new(IState {
                raw,
                tree: None,
                dir: None,
                deleted: false,
            }),
            fifo: Once::new(),
        }
    }

    fn is_dir(&self) -> KResult<()> {
        if self.ty == FileType::Directory {
            Ok(())
        } else {
            Err(Errno::ENOTDIR)
        }
    }

    /// Finishes an inode found on the orphan list at mount: deleted if
    /// it has no links, else its blocks past the end freed.
    pub(super) fn finish_orphan(&self) -> KResult<()> {
        let fs = &self.fs;
        fs.modify(|st| {
            let mut s = self.st.lock();
            if s.raw.links == 0 {
                s.dtime_clear();
                return s.delete(fs, st, self.ino);
            }
            if s.has_block_map(fs) {
                let size = s.raw.size;
                s.free_from(fs, st, self.ino, size)?;
            }
            s.raw.dtime = 0;
            fs.write_raw_inode(self.ino, &s.raw)
        })
    }

    /// Makes a new inode for `ty` in this directory (not yet named).
    fn new_inode(
        &self,
        st: &mut FsState,
        mode: u16,
        is_dir: bool,
        map: bool,
    ) -> KResult<Arc<Ext4Inode>> {
        let fs = &self.fs;
        let ino = fs.alloc_inode(st, fs.inode_group(self.ino), is_dir)?;
        let generation = (crate::time::realtime_ns() as u32) ^ ino.rotate_left(16);
        let mut raw = RawInode::new(fs, mode, generation);
        raw.links = if is_dir { 2 } else { 1 };
        if map && fs.has_incompat(INCOMPAT_EXTENTS) {
            raw.flags |= EXTENTS_FL;
            extent::empty_root(&mut raw.iblock);
        }
        if let Err(e) = fs.write_raw_inode(ino, &raw) {
            let _ = fs.free_inode(st, ino, is_dir);
            return Err(e);
        }
        // A stale in-memory inode of the same number (freed while open)
        // must not be found again.
        fs.inodes.lock().remove(&ino);
        Ok(fs.inode_from_raw(ino, raw))
    }
}

impl IState {
    fn dtime_clear(&mut self) {
        self.raw.dtime = 0;
    }
}

impl Inode for Ext4Inode {
    fn file_type(&self) -> FileType {
        self.ty
    }
    fn ino(&self) -> u64 {
        self.ino as u64
    }
    fn perm(&self) -> u32 {
        (self.st.lock().raw.mode & 0o7777) as u32
    }
    fn set_perm(&self, perm: u32) -> KResult<()> {
        self.fs.modify(|_| {
            let mut s = self.st.lock();
            if s.deleted {
                return Ok(());
            }
            s.raw.mode = (s.raw.mode & S_IFMT) | (perm & 0o7777) as u16;
            s.touch_ctime();
            self.fs.write_raw_inode(self.ino, &s.raw)
        })
    }
    fn size(&self) -> u64 {
        let s = self.st.lock();
        match self.ty {
            FileType::Regular if s.raw.is_socket() => 0,
            FileType::Regular | FileType::Directory | FileType::Symlink => s.raw.size,
            _ => 0,
        }
    }
    fn rdev(&self) -> u64 {
        match self.ty {
            FileType::CharDevice | FileType::BlockDevice => self.st.lock().raw.rdev(),
            _ => 0,
        }
    }
    fn dev(&self) -> u64 {
        self.fs.dev_id
    }
    fn mtime(&self) -> u64 {
        self.st.lock().raw.mtime.max(0) as u64
    }
    fn set_mtime(&self, secs: u64) {
        let _ = self.fs.modify(|_| {
            let mut s = self.st.lock();
            if s.deleted {
                return Ok(());
            }
            s.raw.mtime = secs as i64;
            s.raw.mtime_nsec = 0;
            s.touch_ctime();
            self.fs.write_raw_inode(self.ino, &s.raw)
        });
    }
    fn nlink(&self) -> u64 {
        self.st.lock().raw.links as u64
    }
    fn link_added(&self) {
        let _ = self.fs.modify(|_| {
            let mut s = self.st.lock();
            if s.deleted {
                return Ok(());
            }
            s.raw.links = s.raw.links.saturating_add(1);
            s.touch_ctime();
            self.fs.write_raw_inode(self.ino, &s.raw)
        });
    }
    fn link_removed(&self) {
        let _ = self.fs.modify(|st| {
            let mut s = self.st.lock();
            if s.deleted {
                return Ok(());
            }
            s.raw.links = s.raw.links.saturating_sub(1);
            if s.raw.links == 0 && self.ty != FileType::Directory {
                return s.delete(&self.fs, st, self.ino);
            }
            s.touch_ctime();
            self.fs.write_raw_inode(self.ino, &s.raw)
        });
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut s = self.st.lock();
        match self.ty {
            FileType::Regular if s.raw.is_socket() => Ok(0),
            FileType::Regular => s.read_data(&self.fs, off, buf),
            _ => Err(self.not_a_file()),
        }
    }
    fn write_at(&self, off: u64, data: &[u8]) -> KResult<usize> {
        if self.ty != FileType::Regular {
            return Err(self.not_a_file());
        }
        if data.is_empty() {
            return Ok(0);
        }
        self.fs.modify(|st| {
            let mut s = self.st.lock();
            if s.raw.is_socket() {
                return Err(Errno::EINVAL);
            }
            s.write_data(&self.fs, st, self.ino, off, data)
        })
    }
    fn truncate(&self, len: u64) -> KResult<()> {
        if self.ty != FileType::Regular {
            return Err(self.not_a_file());
        }
        self.fs.modify(|st| {
            let mut s = self.st.lock();
            if s.raw.size == len {
                return Ok(());
            }
            s.truncate(&self.fs, st, self.ino, len)
        })
    }
    fn open_fifo(&self, flags: u32) -> Option<Arc<dyn Inode>> {
        if self.ty != FileType::Fifo {
            return None;
        }
        let perm = self.perm();
        self.fifo
            .call_once(|| crate::fs::pipe::Fifo::create(perm))
            .open_fifo(flags)
    }

    fn readlink(&self) -> KResult<String> {
        if self.ty != FileType::Symlink {
            return Err(Errno::EINVAL);
        }
        let mut s = self.st.lock();
        let size = s.raw.size;
        if size > SYMLINK_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let target = if !s.inline(&self.fs) && s.raw.is_fast_symlink(&self.fs) {
            s.raw.iblock[..size as usize].to_vec()
        } else {
            let mut v = vec![0u8; size as usize];
            let n = s.read_data(&self.fs, 0, &mut v)?;
            v.truncate(n);
            v
        };
        Ok(String::from_utf8_lossy(&target).into_owned())
    }

    fn lookup(&self, name: &str) -> KResult<Arc<dyn Inode>> {
        self.is_dir()?;
        let ino = {
            let mut s = self.st.lock();
            let e = s.dir_map(&self.fs, self.ino)?.get(name.as_bytes()).copied();
            e.ok_or(Errno::ENOENT)?.ino
        };
        let inode: Arc<dyn Inode> = self.fs.inode(ino)?;
        Ok(inode)
    }
    fn parent(&self) -> Option<Arc<dyn Inode>> {
        if self.ty != FileType::Directory {
            return None;
        }
        self.lookup("..").ok()
    }
    fn create(&self, name: &str, ty: FileType, perm: u32) -> KResult<Arc<dyn Inode>> {
        self.is_dir()?;
        valid_name(name)?;
        let fs = &self.fs;
        let (fmt, is_dir, map) = match ty {
            FileType::Regular => (S_IFREG, false, true),
            FileType::Directory => (S_IFDIR, true, true),
            FileType::Fifo => (S_IFIFO, false, false),
            _ => return Err(Errno::EPERM),
        };
        let mode = fmt | (perm & 0o7777) as u16;
        fs.modify(|st| {
            let mut s = self.st.lock();
            s.check_dir_writable(fs, st, self.ino)?;
            if s.dir_map(fs, self.ino)?.contains_key(name.as_bytes()) {
                return Err(Errno::EEXIST);
            }
            // Check the link count can grow before allocating.
            if is_dir && s.raw.links >= LINK_MAX && fs.sb.ro_compat & RO_COMPAT_DIR_NLINK == 0 {
                return Err(Errno::EMLINK);
            }
            let child = self.new_inode(st, mode, is_dir, map)?;
            let r = (|| -> KResult<()> {
                if is_dir {
                    let mut c = child.st.lock();
                    let bs = fs.block_size() as usize;
                    let tail = fs.metadata_csum();
                    let filetype = fs.has_incompat(INCOMPAT_FILETYPE);
                    let entries = [
                        (b".".to_vec(), child.ino, 2u8),
                        (b"..".to_vec(), self.ino, 2u8),
                    ];
                    let (mut blocks, _) = dir::pack(&entries, bs, tail, filetype);
                    if tail {
                        dir::set_tail(&mut blocks[0], c.raw.csum_seed(fs, child.ino));
                    }
                    c.write_data(fs, st, child.ino, 0, &blocks[0])?;
                }
                s.dir_add(
                    fs,
                    st,
                    self.ino,
                    name.as_bytes(),
                    child.ino,
                    mode_ftype(mode),
                )?;
                if is_dir {
                    s.inc_dir_links(fs)?;
                    fs.write_raw_inode(self.ino, &s.raw)?;
                }
                Ok(())
            })();
            if let Err(e) = r {
                let mut c = child.st.lock();
                let _ = c.delete(fs, st, child.ino);
                return Err(e);
            }
            let inode: Arc<dyn Inode> = child;
            Ok(inode)
        })
    }
    fn symlink(&self, name: &str, target: &str) -> KResult<()> {
        self.is_dir()?;
        valid_name(name)?;
        let fs = &self.fs;
        let t = target.as_bytes();
        if t.is_empty() {
            return Err(Errno::ENOENT);
        }
        if t.len() as u64 >= fs.block_size().min(SYMLINK_MAX) {
            return Err(Errno::ENAMETOOLONG);
        }
        fs.modify(|st| {
            let mut s = self.st.lock();
            s.check_dir_writable(fs, st, self.ino)?;
            if s.dir_map(fs, self.ino)?.contains_key(name.as_bytes()) {
                return Err(Errno::EEXIST);
            }
            let fast = t.len() < IBLOCK_LEN;
            let child = self.new_inode(st, S_IFLNK | 0o777, false, !fast)?;
            let r = (|| -> KResult<()> {
                let mut c = child.st.lock();
                if fast {
                    c.raw.iblock = [0; IBLOCK_LEN];
                    c.raw.iblock[..t.len()].copy_from_slice(t);
                    c.raw.size = t.len() as u64;
                    fs.write_raw_inode(child.ino, &c.raw)?;
                } else {
                    c.write_data(fs, st, child.ino, 0, t)?;
                }
                drop(c);
                s.dir_add(fs, st, self.ino, name.as_bytes(), child.ino, 7)
            })();
            if let Err(e) = r {
                let mut c = child.st.lock();
                let _ = c.delete(fs, st, child.ino);
                return Err(e);
            }
            Ok(())
        })
    }
    fn insert(&self, name: &str, inode: Arc<dyn Inode>) -> KResult<()> {
        self.is_dir()?;
        valid_name(name)?;
        let fs = &self.fs;
        if inode.dev() != fs.dev_id {
            return Err(Errno::EXDEV);
        }
        let ino = u32::try_from(inode.ino()).map_err(|_| Errno::EXDEV)?;
        if ino == self.ino {
            return Err(Errno::EINVAL);
        }
        let child = fs.inode(ino)?;
        fs.modify(|st| {
            let mut s = self.st.lock();
            let (mode, deleted) = {
                let c = child.st.lock();
                (c.raw.mode, c.deleted)
            };
            if deleted {
                return Err(Errno::ENOENT);
            }
            let is_dir = mode & S_IFMT == S_IFDIR;
            if is_dir {
                s.inc_dir_links(fs)?;
            }
            if let Err(e) = s.dir_add(fs, st, self.ino, name.as_bytes(), ino, mode_ftype(mode)) {
                if is_dir {
                    s.dec_dir_links();
                }
                return Err(e);
            }
            if is_dir {
                fs.write_raw_inode(self.ino, &s.raw)?;
            }
            Ok(())
        })
    }
    fn remove(&self, name: &str, dir: bool) -> KResult<()> {
        self.is_dir()?;
        if name == "." {
            return Err(Errno::EINVAL);
        }
        if name == ".." {
            return Err(Errno::ENOTEMPTY);
        }
        let fs = &self.fs;
        fs.modify(|st| {
            let mut s = self.st.lock();
            // (An htree directory is rewritten first, before the child is
            // locked: the rewrite reads every child's type.)
            s.check_dir_writable(fs, st, self.ino)?;
            let ino = s
                .dir_map(fs, self.ino)?
                .get(name.as_bytes())
                .ok_or(Errno::ENOENT)?
                .ino;
            if ino == self.ino {
                return Err(Errno::EINVAL);
            }
            let child = fs.inode(ino)?;
            let mut c = child.st.lock();
            let is_dir = c.raw.mode & S_IFMT == S_IFDIR;
            match (dir, is_dir) {
                (true, false) => return Err(Errno::ENOTDIR),
                (false, true) => return Err(Errno::EISDIR),
                (true, true) => {
                    let m = c.dir_map(fs, ino)?;
                    if m.keys().any(|k| k != b"." && k != b"..") {
                        return Err(Errno::ENOTEMPTY);
                    }
                }
                _ => {}
            }
            s.dir_remove(fs, st, self.ino, name.as_bytes())?;
            if is_dir {
                s.dec_dir_links();
                fs.write_raw_inode(self.ino, &s.raw)?;
                c.delete(fs, st, ino)
            } else {
                c.raw.links = c.raw.links.saturating_sub(1);
                if c.raw.links == 0 {
                    c.delete(fs, st, ino)
                } else {
                    c.touch_ctime();
                    fs.write_raw_inode(ino, &c.raw)
                }
            }
        })
    }
    fn take(&self, name: &str) -> KResult<Arc<dyn Inode>> {
        self.is_dir()?;
        if name == "." || name == ".." {
            return Err(Errno::EINVAL);
        }
        let fs = &self.fs;
        let ino = fs.modify(|st| {
            let mut s = self.st.lock();
            let ino = s.dir_remove(fs, st, self.ino, name.as_bytes())?;
            if mode_ftype(child_mode(fs, ino)?) == 2 {
                s.dec_dir_links();
                fs.write_raw_inode(self.ino, &s.raw)?;
            }
            Ok(ino)
        })?;
        let inode: Arc<dyn Inode> = fs.inode(ino)?;
        Ok(inode)
    }
    fn set_parent(&self, parent: &Arc<dyn Inode>) {
        if self.ty != FileType::Directory || parent.dev() != self.fs.dev_id {
            return;
        }
        let pino = parent.ino() as u32;
        let fs = &self.fs;
        let r = fs.modify(|st| {
            let mut s = self.st.lock();
            s.dir_set(fs, st, self.ino, b"..", pino, 2)
        });
        if let Err(e) = r {
            crate::warn!("ext4: inode {}: cannot update \"..\": {e:?}", self.ino);
        }
    }
    fn entries(&self) -> KResult<Vec<(String, Arc<dyn Inode>)>> {
        self.is_dir()?;
        let list: Vec<(Vec<u8>, u32)> = {
            let mut s = self.st.lock();
            s.dir_map(&self.fs, self.ino)?
                .iter()
                .filter(|(n, _)| n.as_slice() != b"." && n.as_slice() != b"..")
                .map(|(n, e)| (n.clone(), e.ino))
                .collect()
        };
        let mut out: Vec<(String, Arc<dyn Inode>)> = Vec::with_capacity(list.len());
        for (name, ino) in list {
            let inode: Arc<dyn Inode> = self.fs.inode(ino)?;
            out.push((String::from_utf8_lossy(&name).into_owned(), inode));
        }
        Ok(out)
    }
    fn is_empty_dir(&self) -> bool {
        if self.ty != FileType::Directory {
            return false;
        }
        let mut s = self.st.lock();
        s.dir_map(&self.fs, self.ino)
            .map(|m| m.keys().all(|k| k == b"." || k == b".."))
            .unwrap_or(false)
    }
    fn writable_dir(&self) -> bool {
        self.fs.writable
    }

    fn stat(&self) -> Stat {
        let s = self.st.lock();
        let r = &s.raw;
        let size = match self.ty {
            FileType::Regular if r.is_socket() => 0,
            FileType::Regular | FileType::Directory | FileType::Symlink => r.size,
            _ => 0,
        };
        let rdev = match self.ty {
            FileType::CharDevice | FileType::BlockDevice => r.rdev(),
            _ => 0,
        };
        Stat {
            st_dev: self.fs.dev_id,
            st_ino: self.ino as u64,
            st_nlink: r.links as u64,
            st_mode: self.ty.mode_bits() | (r.mode & 0o7777) as u32,
            st_rdev: rdev,
            st_size: size as i64,
            st_blksize: self.fs.block_size() as i64,
            st_blocks: r.sectors(&self.fs) as i64,
            st_atime: r.atime,
            st_atime_nsec: r.atime_nsec as i64,
            st_mtime: r.mtime,
            st_mtime_nsec: r.mtime_nsec as i64,
            st_ctime: r.ctime,
            st_ctime_nsec: r.ctime_nsec as i64,
            ..Stat::default()
        }
    }
}

/// The mode of inode `ino`.
fn child_mode(fs: &Ext4Fs, ino: u32) -> KResult<u16> {
    match fs.cached_inode(ino) {
        Some(i) => Ok(i.fmt),
        None => Ok(fs.read_raw_inode(ino)?.mode),
    }
}
