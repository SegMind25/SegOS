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
//!
//! Private file mappings (shared libraries) fault their pages in from
//! here too, copy-on-write: every process running a library shares one
//! copy of its code.

use super::Inode;
use crate::abi::KResult;
use crate::mm::{PAGE_SIZE, frame, phys_to_virt};
use crate::sync::SpinLock;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

pub struct Cache {
    inode: Arc<dyn Inode>,
    /// Page index → frame (the cache holds one reference to each).
    pages: SpinLock<BTreeMap<u64, u64>>,
    /// Dropped by [`sync_all`] (its frames are gone): users of an old
    /// reference to it go to the inode's current cache instead.
    dead: AtomicBool,
    /// Some writable shared mapping showed the pages: they may differ
    /// from the file. (Private mappings copy a page before writing it, and
    /// `write` updates the file too, so only these need writing back.)
    writable: AtomicBool,
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
        dead: AtomicBool::new(false),
        writable: AtomicBool::new(false),
    });
    caches.push(c.clone());
    c
}

impl Cache {
    /// The frame holding page `idx`, read from the file the first time
    /// (zeros past the end of the file), with a reference taken for the
    /// caller: it maps the frame or lets go with `frame::free`. (Taken
    /// under the lock, so that [`sync_all`] cannot free the frame first.)
    pub fn page(&self, idx: u64) -> KResult<u64> {
        {
            let pages = self.pages.lock();
            if self.dead.load(Ordering::Relaxed) {
                drop(pages);
                return get(&self.inode).page(idx);
            }
            if let Some(&p) = pages.get(&idx) {
                frame::get(p);
                return Ok(p);
            }
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
        if self.dead.load(Ordering::Relaxed) {
            drop(pages);
            frame::free(phys);
            return get(&self.inode).page(idx);
        }
        if let Some(&p) = pages.get(&idx) {
            frame::free(phys); // another thread loaded it meanwhile
            frame::get(p);
            return Ok(p);
        }
        pages.insert(idx, phys);
        frame::get(phys);
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
            frame::free(phys);
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

    /// Notes that a writable shared mapping shows the pages.
    pub fn mark_writable(&self) {
        self.writable.store(true, Ordering::Relaxed);
    }

    /// Writes every cached page (up to the file's size) to the file, if a
    /// writable shared mapping may have changed them.
    pub fn write_back(&self) -> KResult<()> {
        if !self.writable.load(Ordering::Relaxed) {
            return Ok(());
        }
        let size = self.inode.size();
        // References of our own: the frames stay while being written.
        let pages: Vec<(u64, u64)> = self
            .pages
            .lock()
            .iter()
            .map(|(&i, &p)| {
                frame::get(p);
                (i, p)
            })
            .collect();
        let mut result = Ok(());
        for &(idx, phys) in &pages {
            let off = idx * PAGE_SIZE;
            if off >= size || result.is_err() {
                continue;
            }
            let n = (size - off).min(PAGE_SIZE) as usize;
            let data = unsafe { core::slice::from_raw_parts(phys_to_virt(phys), n) };
            result = self.inode.write_at(off, data).map(|_| ());
        }
        for (_, p) in pages {
            frame::free(p);
        }
        result
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
        // Dropped only if no mapping (and no `page` caller) holds a page,
        // decided under the cache's lock: `page` takes its references
        // under it too.
        let mut caches = CACHES.lock();
        let mut pages = c.pages.lock();
        if pages.values().all(|&p| frame::ref_count(p) <= 1) && !c.dead.load(Ordering::Relaxed) {
            c.dead.store(true, Ordering::Relaxed);
            caches.retain(|o| !Arc::ptr_eq(o, &c));
            for (_, p) in core::mem::take(&mut *pages) {
                frame::free(p);
            }
        }
    }
}
