//! The block cache: recently used 4 KiB blocks of each disk, kept in
//! memory, and writes held back (write-back) until a sync, an eviction,
//! or the periodic flush every few seconds.
//!
//! It sits under the partitions, so every file system on a disk shares
//! one cache. File systems read and write through it without knowing.

use super::{BlockDevice, SECTOR_SIZE};
use crate::abi::KResult;
use crate::sync::Mutex;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

const BLOCK: usize = 4096;
const SECTORS_PER_BLOCK: u64 = (BLOCK / SECTOR_SIZE) as u64;
/// Blocks kept per disk (16 MiB).
const CAPACITY: usize = 4096;
/// Most blocks read or written in one device request.
const MAX_RUN: usize = 32;

struct Entry {
    data: Box<[u8]>,
    dirty: bool,
    used: u64,
}

struct State {
    blocks: BTreeMap<u64, Entry>,
    clock: u64,
    /// Writes reached the disk since its last cache flush.
    unflushed: bool,
}

pub struct Cached {
    disk: Arc<dyn BlockDevice>,
    state: Mutex<State>,
}

impl Cached {
    pub fn new(disk: Arc<dyn BlockDevice>) -> Self {
        Self {
            disk,
            state: Mutex::new(State {
                blocks: BTreeMap::new(),
                clock: 0,
                unflushed: false,
            }),
        }
    }

    /// Sectors in block `b` (the last block of a disk may be partial).
    fn block_sectors(&self, b: u64) -> u64 {
        SECTORS_PER_BLOCK.min(self.disk.sector_count() - b * SECTORS_PER_BLOCK)
    }

    /// Reads blocks `first..first + count` from the disk in as few requests
    /// as possible and caches them.
    fn fill(&self, st: &mut State, first: u64, count: u64) -> KResult<()> {
        let mut b = first;
        while b < first + count {
            if st.blocks.contains_key(&b) {
                b += 1;
                continue;
            }
            let mut run = 1;
            while b + run < first + count
                && run < MAX_RUN as u64
                && !st.blocks.contains_key(&(b + run))
            {
                run += 1;
            }
            let last_sectors = self.block_sectors(b + run - 1);
            let sectors = (run - 1) * SECTORS_PER_BLOCK + last_sectors;
            let mut buf = vec![0u8; sectors as usize * SECTOR_SIZE];
            self.disk.read_sectors(b * SECTORS_PER_BLOCK, &mut buf)?;
            for i in 0..run {
                let start = i as usize * BLOCK;
                let end = (start + BLOCK).min(buf.len());
                let mut data = vec![0u8; BLOCK].into_boxed_slice();
                data[..end - start].copy_from_slice(&buf[start..end]);
                st.clock += 1;
                st.blocks.insert(
                    b + i,
                    Entry {
                        data,
                        dirty: false,
                        used: st.clock,
                    },
                );
            }
            b += run;
        }
        Ok(())
    }

    /// Writes every dirty block, merging neighbours into one request.
    fn write_back(&self, st: &mut State) -> KResult<()> {
        let dirty: Vec<u64> = st
            .blocks
            .iter()
            .filter(|(_, e)| e.dirty)
            .map(|(&b, _)| b)
            .collect();
        let mut i = 0;
        while i < dirty.len() {
            let mut run = 1;
            while i + run < dirty.len() && dirty[i + run] == dirty[i] + run as u64 && run < MAX_RUN
            {
                run += 1;
            }
            let first = dirty[i];
            let last_sectors = self.block_sectors(first + run as u64 - 1);
            let sectors = (run as u64 - 1) * SECTORS_PER_BLOCK + last_sectors;
            let mut buf = vec![0u8; sectors as usize * SECTOR_SIZE];
            for k in 0..run {
                let start = k * BLOCK;
                let end = (start + BLOCK).min(buf.len());
                buf[start..end]
                    .copy_from_slice(&st.blocks[&(first + k as u64)].data[..end - start]);
            }
            self.disk.write_sectors(first * SECTORS_PER_BLOCK, &buf)?;
            st.unflushed = true;
            for k in 0..run {
                st.blocks.get_mut(&(first + k as u64)).unwrap().dirty = false;
            }
            i += run;
        }
        Ok(())
    }

    /// Drops the least recently used blocks above the capacity.
    fn evict(&self, st: &mut State) -> KResult<()> {
        if st.blocks.len() <= CAPACITY {
            return Ok(());
        }
        if st.blocks.values().any(|e| e.dirty) {
            self.write_back(st)?;
        }
        let mut ages: Vec<(u64, u64)> = st.blocks.iter().map(|(&b, e)| (e.used, b)).collect();
        ages.sort_unstable();
        let excess = st.blocks.len() - CAPACITY * 3 / 4;
        for &(_, b) in ages.iter().take(excess) {
            st.blocks.remove(&b);
        }
        Ok(())
    }
}

impl BlockDevice for Cached {
    fn name(&self) -> &str {
        self.disk.name()
    }
    fn sector_count(&self) -> u64 {
        self.disk.sector_count()
    }
    fn read_only(&self) -> bool {
        self.disk.read_only()
    }
    fn rdev(&self) -> u64 {
        self.disk.rdev()
    }

    fn read_sectors(&self, lba: u64, buf: &mut [u8]) -> KResult<()> {
        let mut st = self.state.lock();
        let first = lba / SECTORS_PER_BLOCK;
        let last = (lba + (buf.len() / SECTOR_SIZE) as u64 - 1) / SECTORS_PER_BLOCK;
        self.fill(&mut st, first, last - first + 1)?;
        let mut done = 0;
        let mut sector = lba;
        while done < buf.len() {
            let b = sector / SECTORS_PER_BLOCK;
            let off = (sector % SECTORS_PER_BLOCK) as usize * SECTOR_SIZE;
            let n = (BLOCK - off).min(buf.len() - done);
            st.clock += 1;
            let clock = st.clock;
            let e = st.blocks.get_mut(&b).unwrap();
            e.used = clock;
            buf[done..done + n].copy_from_slice(&e.data[off..off + n]);
            done += n;
            sector += (n / SECTOR_SIZE) as u64;
        }
        self.evict(&mut st)
    }

    fn write_sectors(&self, lba: u64, data: &[u8]) -> KResult<()> {
        if self.disk.read_only() {
            return Err(crate::abi::Errno::EROFS);
        }
        let mut st = self.state.lock();
        let mut done = 0;
        let mut sector = lba;
        while done < data.len() {
            let b = sector / SECTORS_PER_BLOCK;
            let off = (sector % SECTORS_PER_BLOCK) as usize * SECTOR_SIZE;
            let n = (BLOCK - off).min(data.len() - done);
            let whole = off == 0 && n as u64 == self.block_sectors(b) * SECTOR_SIZE as u64;
            if whole {
                st.blocks.entry(b).or_insert_with(|| Entry {
                    data: vec![0u8; BLOCK].into_boxed_slice(),
                    dirty: false,
                    used: 0,
                });
            } else if !st.blocks.contains_key(&b) {
                self.fill(&mut st, b, 1)?;
            }
            st.clock += 1;
            let clock = st.clock;
            let e = st.blocks.get_mut(&b).unwrap();
            e.data[off..off + n].copy_from_slice(&data[done..done + n]);
            e.dirty = true;
            e.used = clock;
            done += n;
            sector += (n / SECTOR_SIZE) as u64;
        }
        self.evict(&mut st)
    }

    fn flush(&self) -> KResult<()> {
        let mut st = self.state.lock();
        self.write_back(&mut st)?;
        if !core::mem::take(&mut st.unflushed) {
            return Ok(());
        }
        drop(st);
        self.disk.flush()
    }
}
