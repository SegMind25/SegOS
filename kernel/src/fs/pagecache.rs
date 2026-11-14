//! The page cache for shared file mappings.
//!
//! When a file is mapped `MAP_SHARED`, its pages are loaded into frames
//! that every mapping of it uses directly: a store through one mapping is
//! seen by every other mapping and by `read`, and `write` updates the
//! cached pages as well as the file. Changed pages are written back to
//! the file system on `msync`, `munmap`, `fsync`, `sync` and by the
//! periodic flush; a cache whose pages no mapping uses any more is then
//! dropped. Files that are not shared-mapped are read and written straight
//! through their file system (and the block cache under it).

use super::Inode;
use crate::abi::KResult;
use crate::mm::{PAGE_SIZE, frame, phys_to_virt};
use crate::sync::SpinLock;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

pub struct Cache {
    inode: Arc<dyn Inode>,
    /// Page index → frame (the cache holds one reference to each).
    pages: SpinLock<BTreeMap<u64, u64>>,
}

static CACHES: SpinLock<Vec<Arc<Cache>>> = SpinLock::new(Vec::new());

fn same(a: &Arc<dyn Inode>, b: &Arc<dyn Inode>) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// The cache of `inode`, if it is shared-mapped.
pub fn lookup(inode: &Arc<dyn Inode>) -> Option<Arc<Cache>> {
    CACHES
        .lock()
        .iter()
        .find(|c| same(&c.inode, inode))
        .cloned()
}

/// The cache of `inode`, created if needed.
pub fn get(inode: &Arc<dyn Inode>) -> Arc<Cache> {
    let mut caches = CACHES.lock();
    if let Some(c) = caches.iter().find(|c| same(&c.inode, inode)) {
        return c.clone();
    }
    let c = Arc::new(Cache {
        inode: inode.clone(),
        pages: SpinLock::new(BTreeMap::new()),
    });
    caches.push(c.clone());
    c
}

impl Cache {
    /// The frame holding page `idx`, read from the file the first time
    /// (zeros past the end of the file).
    pub fn page(&self, idx: u64) -> KResult<u64> {
        if let Some(&p) = self.pages.lock().get(&idx) {
            return Ok(p);
        }
        let phys = frame::alloc_zeroed().ok_or(crate::abi::Errno::ENOMEM)?;
        let buf =
            unsafe { core::slice::from_raw_parts_mut(phys_to_virt(phys), PAGE_SIZE as usize) };
        let mut got = 0;
        while got < buf.len() {
            match self
                .inode
                .read_at(idx * PAGE_SIZE + got as u64, &mut buf[got..])
            {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) => {
                    frame::free(phys);
                    return Err(e);
                }
            }
        }
        let mut pages = self.pages.lock();
        if let Some(&p) = pages.get(&idx) {
            frame::free(phys); // another thread loaded it meanwhile
            return Ok(p);
        }
        pages.insert(idx, phys);
        Ok(phys)
    }

    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let size = self.inode.size();
        if off >= size {
            return Ok(0);
        }
        let len = buf.len().min((size - off) as usize);
        let mut done = 0;
        while done < len {
            let at = off + done as u64;
            let phys = self.page(at / PAGE_SIZE)?;
            let o = (at % PAGE_SIZE) as usize;
            let n = (PAGE_SIZE as usize - o).min(len - done);
            let src = unsafe { core::slice::from_raw_parts(phys_to_virt(phys).add(o), n) };
            buf[done..done + n].copy_from_slice(src);
            done += n;
        }
        Ok(done)
    }

    /// Updates the cached pages `data` covers (pages not cached will be
    /// read from the file, which already has the data).
    fn update(&self, off: u64, data: &[u8]) {
        let pages = self.pages.lock();
        let mut done = 0;
        while done < data.len() {
            let at = off + done as u64;
            let o = (at % PAGE_SIZE) as usize;
            let n = (PAGE_SIZE as usize - o).min(data.len() - done);
            if let Some(&phys) = pages.get(&(at / PAGE_SIZE)) {
                let dst = unsafe { core::slice::from_raw_parts_mut(phys_to_virt(phys).add(o), n) };
                dst.copy_from_slice(&data[done..done + n]);
            }
            done += n;
        }
    }

    /// Writes every cached page (up to the file's size) to the file.
    pub fn write_back(&self) -> KResult<()> {
        let size = self.inode.size();
        let pages: Vec<(u64, u64)> = self.pages.lock().iter().map(|(&i, &p)| (i, p)).collect();
        for (idx, phys) in pages {
            let off = idx * PAGE_SIZE;
            if off >= size {
                continue;
            }
            let n = (size - off).min(PAGE_SIZE) as usize;
            let data = unsafe { core::slice::from_raw_parts(phys_to_virt(phys), n) };
            self.inode.write_at(off, data)?;
        }
        Ok(())
    }

    /// Whether some mapping still uses one of its pages.
    fn mapped(&self) -> bool {
        self.pages.lock().values().any(|&p| frame::ref_count(p) > 1)
    }
}

/// Reads through the cache when the file is shared-mapped.
pub fn read_at(inode: &Arc<dyn Inode>, off: u64, buf: &mut [u8]) -> KResult<usize> {
    match lookup(inode) {
        Some(c) => c.read(off, buf),
        None => inode.read_at(off, buf),
    }
}

/// Writes to the file, and to its cached pages when it is shared-mapped.
pub fn write_at(inode: &Arc<dyn Inode>, off: u64, data: &[u8]) -> KResult<usize> {
    let n = inode.write_at(off, data)?;
    if let Some(c) = lookup(inode) {
        c.update(off, &data[..n]);
    }
    Ok(n)
}

/// Writes back `inode`'s cached pages.
pub fn sync_inode(inode: &Arc<dyn Inode>) -> KResult<()> {
    match lookup(inode) {
        Some(c) => c.write_back(),
        None => Ok(()),
    }
}

/// Writes back every cache, and drops those no mapping uses any more.
pub fn sync_all() {
    let caches: Vec<Arc<Cache>> = CACHES.lock().clone();
    for c in caches {
        if let Err(e) = c.write_back() {
            crate::warn!("page cache: write-back failed ({e:?})");
            continue;
        }
        if !c.mapped() {
            CACHES.lock().retain(|o| !Arc::ptr_eq(o, &c));
            for (_, p) in core::mem::take(&mut *c.pages.lock()) {
                frame::free(p);
            }
        }
    }
}
