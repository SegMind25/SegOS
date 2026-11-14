//! Block and inode allocation: the per-group bitmaps, the free counts in
//! the group descriptors and the superblock, and the uninitialised-group
//! flags of `uninit_bg`/`metadata_csum` file systems.

use super::{
    BG_BLOCK_UNINIT, BG_INODE_UNINIT, Ext4Fs, FsState, INCOMPAT_META_BG, crc, le16, put16,
};
use crate::abi::{Errno, KResult};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

fn bit(b: &[u8], i: usize) -> bool {
    b[i / 8] & (1 << (i % 8)) != 0
}

fn set_bit(b: &mut [u8], i: usize, v: bool) {
    if v {
        b[i / 8] |= 1 << (i % 8);
    } else {
        b[i / 8] &= !(1 << (i % 8));
    }
}

impl Ext4Fs {
    pub(super) fn group_first_block(&self, g: u64) -> u64 {
        self.sb.first_data_block as u64 + g * self.sb.blocks_per_group as u64
    }

    fn blocks_in_group(&self, g: u64) -> u64 {
        (self.sb.blocks_count - self.group_first_block(g)).min(self.sb.blocks_per_group as u64)
    }

    /// Blocks at the start of group `g` taken by the superblock backup and
    /// the group descriptor table (and its reserved growth).
    fn base_meta_blocks(&self, g: u64) -> u64 {
        let has_super = self.sb.group_has_super(g) as u64;
        let per_block = self.block_size() / self.sb.desc_size as u64;
        if !self.has_incompat(INCOMPAT_META_BG) || g < self.sb.first_meta_bg as u64 * per_block {
            if has_super == 0 {
                return 0;
            }
            let gdb = if self.has_incompat(INCOMPAT_META_BG) {
                self.sb.first_meta_bg as u64
            } else {
                self.gdb_count
            };
            1 + gdb + self.sb.reserved_gdt as u64
        } else {
            let idx = g % per_block;
            let gdb = (idx == 0 || idx == 1 || idx == per_block - 1) as u64;
            has_super + gdb
        }
    }

    /// The block bitmap of a group still marked BLOCK_UNINIT: its own
    /// metadata in use, the rest free.
    fn init_block_bitmap(&self, g: u64, d: &[u8]) -> Vec<u8> {
        let bs = self.block_size() as usize;
        let mut b = vec![0u8; bs];
        for i in 0..self.base_meta_blocks(g) as usize {
            set_bit(&mut b, i, true);
        }
        let first = self.group_first_block(g);
        let n = self.blocks_in_group(g);
        let mut mark = |blk: u64, count: u64| {
            for x in blk..blk + count {
                if x >= first && x < first + n {
                    set_bit(&mut b, (x - first) as usize, true);
                }
            }
        };
        mark(self.desc_field(d, 0x0, 0x20), 1);
        mark(self.desc_field(d, 0x4, 0x24), 1);
        let itable_blocks =
            (self.sb.inodes_per_group as u64 * self.sb.inode_size as u64).div_ceil(bs as u64);
        mark(self.desc_field(d, 0x8, 0x28), itable_blocks);
        for i in n as usize..bs * 8 {
            set_bit(&mut b, i, true);
        }
        b
    }

    /// The block bitmap of group `g`: (descriptor, bitmap block, bitmap).
    fn load_block_bitmap(&self, g: u64) -> KResult<(Vec<u8>, u64, Vec<u8>)> {
        let d = self.group_desc(g)?;
        let blk = self.desc_field(&d, 0x0, 0x20);
        let bitmap = if self.group_csum() && le16(&d, 0x12) & BG_BLOCK_UNINIT != 0 {
            self.init_block_bitmap(g, &d)
        } else {
            self.block(blk)?.to_vec()
        };
        Ok((d, blk, bitmap))
    }

    /// Writes a group's block bitmap and descriptor (with `free` blocks
    /// free), with checksums.
    fn store_block_bitmap(
        &self,
        g: u64,
        mut d: Vec<u8>,
        blk: u64,
        bitmap: &[u8],
        free: u64,
    ) -> KResult<()> {
        self.write_at(blk, 0, bitmap)?;
        self.set_desc_field16(&mut d, 0xc, 0x2c, free);
        let flags = le16(&d, 0x12) & !BG_BLOCK_UNINIT;
        put16(&mut d, 0x12, flags);
        if self.metadata_csum() {
            let n = self.sb.blocks_per_group as usize / 8;
            let c = crc::crc32c(self.seed, &bitmap[..n]);
            put16(&mut d, 0x18, c as u16);
            if self.sb.desc_size >= 64 {
                put16(&mut d, 0x38, (c >> 16) as u16);
            }
        }
        self.put_group_desc(g, &mut d)
    }

    fn load_inode_bitmap(&self, g: u64) -> KResult<(Vec<u8>, u64, Vec<u8>)> {
        let d = self.group_desc(g)?;
        let blk = self.desc_field(&d, 0x4, 0x24);
        let bitmap = if self.group_csum() && le16(&d, 0x12) & BG_INODE_UNINIT != 0 {
            let bs = self.block_size() as usize;
            let mut b = vec![0u8; bs];
            for i in self.sb.inodes_per_group as usize..bs * 8 {
                set_bit(&mut b, i, true);
            }
            b
        } else {
            self.block(blk)?.to_vec()
        };
        Ok((d, blk, bitmap))
    }

    fn store_inode_bitmap(&self, g: u64, mut d: Vec<u8>, blk: u64, bitmap: &[u8]) -> KResult<()> {
        self.write_at(blk, 0, bitmap)?;
        let flags = le16(&d, 0x12) & !BG_INODE_UNINIT;
        put16(&mut d, 0x12, flags);
        if self.metadata_csum() {
            let n = self.sb.inodes_per_group as usize / 8;
            let c = crc::crc32c(self.seed, &bitmap[..n]);
            put16(&mut d, 0x1a, c as u16);
            if self.sb.desc_size >= 64 {
                put16(&mut d, 0x3a, (c >> 16) as u16);
            }
        }
        self.put_group_desc(g, &mut d)
    }

    /// Allocates up to `max` consecutive blocks, as near `goal` (at or
    /// after it) as possible: (first block, count).
    pub(super) fn alloc_blocks(
        &self,
        st: &mut FsState,
        goal: u64,
        max: u64,
    ) -> KResult<(u64, u64)> {
        if self.free_blocks.load(Ordering::Relaxed) == 0 {
            return Err(Errno::ENOSPC);
        }
        let first = self.sb.first_data_block as u64;
        let goal = if goal < first || goal >= self.sb.blocks_count {
            self.group_first_block(st.last_group)
        } else {
            goal
        };
        let g0 = (goal - first) / self.sb.blocks_per_group as u64;
        let max = max.clamp(1, self.sb.blocks_per_group as u64);
        for i in 0..=self.group_count {
            let g = (g0 + i) % self.group_count;
            let d = self.group_desc(g)?;
            let free = self.desc_field16(&d, 0xc, 0x2c);
            if free == 0 {
                continue;
            }
            let (d, blk, mut bitmap) = self.load_block_bitmap(g)?;
            let n = self.blocks_in_group(g) as usize;
            let start = if i == 0 {
                (goal - self.group_first_block(g)) as usize
            } else {
                0
            };
            let Some(s) = (start..n).find(|&b| !bit(&bitmap, b)) else {
                continue;
            };
            let mut count = 0usize;
            while s + count < n && (count as u64) < max && !bit(&bitmap, s + count) {
                set_bit(&mut bitmap, s + count, true);
                count += 1;
            }
            self.store_block_bitmap(g, d, blk, &bitmap, free.saturating_sub(count as u64))?;
            self.free_blocks.fetch_sub(count as u64, Ordering::Relaxed);
            st.sb_dirty = true;
            st.last_group = g;
            return Ok((self.group_first_block(g) + s as u64, count as u64));
        }
        Err(Errno::ENOSPC)
    }

    /// Frees blocks `start..start + count` (may span groups).
    pub(super) fn free_blocks(&self, st: &mut FsState, start: u64, count: u64) -> KResult<()> {
        let first = self.sb.first_data_block as u64;
        let mut b = start;
        let end = start + count;
        if start < first || end > self.sb.blocks_count {
            return Err(Errno::EIO);
        }
        while b < end {
            let g = (b - first) / self.sb.blocks_per_group as u64;
            let gstart = self.group_first_block(g);
            let gend = (gstart + self.blocks_in_group(g)).min(end);
            let (d, blk, mut bitmap) = self.load_block_bitmap(g)?;
            let mut freed = 0;
            for x in b..gend {
                let i = (x - gstart) as usize;
                if bit(&bitmap, i) {
                    set_bit(&mut bitmap, i, false);
                    freed += 1;
                } else {
                    crate::warn!("ext4: freeing free block {x}");
                }
            }
            let free = self.desc_field16(&d, 0xc, 0x2c) + freed;
            self.store_block_bitmap(g, d, blk, &bitmap, free)?;
            self.free_blocks.fetch_add(freed, Ordering::Relaxed);
            st.sb_dirty = true;
            b = gend;
        }
        Ok(())
    }

    /// Frees a list of blocks, coalescing runs.
    pub(super) fn free_block_list(&self, st: &mut FsState, mut blocks: Vec<u64>) -> KResult<()> {
        blocks.sort_unstable();
        let mut i = 0;
        while i < blocks.len() {
            let s = blocks[i];
            let mut n = 1;
            while i + (n as usize) < blocks.len() && blocks[i + n as usize] == s + n {
                n += 1;
            }
            self.free_blocks(st, s, n)?;
            i += n as usize;
        }
        Ok(())
    }

    /// Allocates an inode, preferably in group `pref`.
    pub(super) fn alloc_inode(&self, st: &mut FsState, pref: u64, dir: bool) -> KResult<u32> {
        if self.free_inodes.load(Ordering::Relaxed) == 0 {
            return Err(Errno::ENOSPC);
        }
        let ipg = self.sb.inodes_per_group as u64;
        for i in 0..self.group_count {
            let g = (pref + i) % self.group_count;
            let d = self.group_desc(g)?;
            let free = self.desc_field16(&d, 0xe, 0x2e);
            if free == 0 {
                continue;
            }
            let (mut d, blk, mut bitmap) = self.load_inode_bitmap(g)?;
            let low = if g == 0 {
                self.sb.first_ino as usize - 1
            } else {
                0
            };
            let Some(idx) = (low..ipg as usize).find(|&b| !bit(&bitmap, b)) else {
                continue;
            };
            if g * ipg + idx as u64 + 1 > self.sb.inodes_count as u64 {
                continue;
            }
            // Linux initialises the block bitmap of a group whose inodes
            // come into use.
            if self.group_csum() && le16(&d, 0x12) & BG_BLOCK_UNINIT != 0 {
                let (bd, bblk, bbitmap) = self.load_block_bitmap(g)?;
                let bfree = self.desc_field16(&bd, 0xc, 0x2c);
                self.store_block_bitmap(g, bd, bblk, &bbitmap, bfree)?;
                d = self.group_desc(g)?;
            }
            set_bit(&mut bitmap, idx, true);
            self.set_desc_field16(&mut d, 0xe, 0x2e, free - 1);
            if dir {
                let dirs = self.desc_field16(&d, 0x10, 0x30) + 1;
                self.set_desc_field16(&mut d, 0x10, 0x30, dirs);
            }
            if self.group_csum() {
                let unused = self.desc_field16(&d, 0x1c, 0x32);
                if idx as u64 >= ipg - unused.min(ipg) {
                    self.set_desc_field16(&mut d, 0x1c, 0x32, ipg - idx as u64 - 1);
                }
            }
            self.store_inode_bitmap(g, d, blk, &bitmap)?;
            self.free_inodes.fetch_sub(1, Ordering::Relaxed);
            st.sb_dirty = true;
            return Ok((g * ipg + idx as u64 + 1) as u32);
        }
        Err(Errno::ENOSPC)
    }

    pub(super) fn free_inode(&self, st: &mut FsState, ino: u32, dir: bool) -> KResult<()> {
        let ipg = self.sb.inodes_per_group as u64;
        let g = (ino as u64 - 1) / ipg;
        let idx = ((ino as u64 - 1) % ipg) as usize;
        let (mut d, blk, mut bitmap) = self.load_inode_bitmap(g)?;
        if !bit(&bitmap, idx) {
            crate::warn!("ext4: freeing free inode {ino}");
            return Ok(());
        }
        set_bit(&mut bitmap, idx, false);
        let free = self.desc_field16(&d, 0xe, 0x2e) + 1;
        self.set_desc_field16(&mut d, 0xe, 0x2e, free);
        if dir {
            let dirs = self.desc_field16(&d, 0x10, 0x30).saturating_sub(1);
            self.set_desc_field16(&mut d, 0x10, 0x30, dirs);
        }
        self.store_inode_bitmap(g, d, blk, &bitmap)?;
        self.free_inodes.fetch_add(1, Ordering::Relaxed);
        st.sb_dirty = true;
        Ok(())
    }

    /// The group an inode is in (new blocks for it are looked for there).
    pub(super) fn inode_group(&self, ino: u32) -> u64 {
        (ino as u64 - 1) / self.sb.inodes_per_group as u64
    }
}
