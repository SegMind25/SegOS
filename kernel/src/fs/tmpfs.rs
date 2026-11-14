//! tmpfs: files and directories that live in kernel memory. The root file
//! system in Phase 2 (filled from the initramfs) and later `/tmp`.

use super::{FileType, Inode, new_ino};
use crate::abi::{Errno, KResult};
use crate::sync::{Mutex, SpinLock};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Largest tmpfs file (a guard against a runaway write eating all memory).
const MAX_FILE: u64 = 1 << 30;

fn now() -> u64 {
    crate::time::realtime_ns() / crate::time::NS_PER_SEC
}

pub struct Dir {
    ino: u64,
    perm: AtomicU32,
    mtime: AtomicU64,
    entries: SpinLock<BTreeMap<String, Arc<dyn Inode>>>,
    /// The containing directory; the root's own (dangling) Weak means
    /// "this is the root".
    parent: Weak<dyn Inode>,
    me: Weak<Dir>,
}

impl Dir {
    pub fn new_root(perm: u32) -> Arc<dyn Inode> {
        Arc::new_cyclic(|me: &Weak<Dir>| Dir {
            ino: new_ino(),
            perm: AtomicU32::new(perm),
            mtime: AtomicU64::new(now()),
            entries: SpinLock::new(BTreeMap::new()),
            parent: Weak::<Dir>::new(),
            me: me.clone(),
        })
    }

    fn touch(&self) {
        self.mtime.store(now(), Ordering::Relaxed);
    }
}

impl Inode for Dir {
    fn file_type(&self) -> FileType {
        FileType::Directory
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        self.perm.load(Ordering::Relaxed)
    }
    fn size(&self) -> u64 {
        4096
    }
    fn mtime(&self) -> u64 {
        self.mtime.load(Ordering::Relaxed)
    }

    fn lookup(&self, name: &str) -> KResult<Arc<dyn Inode>> {
        self.entries.lock().get(name).cloned().ok_or(Errno::ENOENT)
    }

    fn parent(&self) -> Option<Arc<dyn Inode>> {
        self.parent.upgrade().or_else(|| {
            // The root is its own parent.
            self.me.upgrade().map(|d| d as Arc<dyn Inode>)
        })
    }

    fn create(&self, name: &str, ty: FileType, perm: u32) -> KResult<Arc<dyn Inode>> {
        if name == "." || name == ".." {
            return Err(Errno::EEXIST);
        }
        let mut entries = self.entries.lock();
        if entries.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let inode: Arc<dyn Inode> = match ty {
            FileType::Regular => Arc::new(File {
                ino: new_ino(),
                perm: AtomicU32::new(perm),
                mtime: AtomicU64::new(now()),
                data: Mutex::new(Vec::new()),
            }),
            FileType::Directory => {
                let parent: Weak<dyn Inode> = self.me.clone();
                Arc::new_cyclic(|me: &Weak<Dir>| Dir {
                    ino: new_ino(),
                    perm: AtomicU32::new(perm),
                    mtime: AtomicU64::new(now()),
                    entries: SpinLock::new(BTreeMap::new()),
                    parent,
                    me: me.clone(),
                })
            }
            FileType::CharDevice => return Err(Errno::EPERM),
        };
        entries.insert(name.to_string(), inode.clone());
        drop(entries);
        self.touch();
        Ok(inode)
    }

    fn insert(&self, name: &str, inode: Arc<dyn Inode>) -> KResult<()> {
        let mut entries = self.entries.lock();
        if entries.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        entries.insert(name.to_string(), inode);
        Ok(())
    }

    fn remove(&self, name: &str, dir: bool) -> KResult<()> {
        if name == "." {
            return Err(Errno::EINVAL);
        }
        if name == ".." {
            return Err(Errno::ENOTEMPTY);
        }
        let mut entries = self.entries.lock();
        let inode = entries.get(name).ok_or(Errno::ENOENT)?;
        let is_dir = inode.file_type() == FileType::Directory;
        match (dir, is_dir) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            (true, true) if !inode.is_empty_dir() => return Err(Errno::ENOTEMPTY),
            _ => {}
        }
        entries.remove(name);
        drop(entries);
        self.touch();
        Ok(())
    }

    fn entries(&self) -> KResult<Vec<(String, Arc<dyn Inode>)>> {
        Ok(self
            .entries
            .lock()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    fn is_empty_dir(&self) -> bool {
        self.entries.lock().is_empty()
    }
}

pub struct File {
    ino: u64,
    perm: AtomicU32,
    mtime: AtomicU64,
    data: Mutex<Vec<u8>>,
}

impl Inode for File {
    fn file_type(&self) -> FileType {
        FileType::Regular
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        self.perm.load(Ordering::Relaxed)
    }
    fn size(&self) -> u64 {
        self.data.lock().len() as u64
    }
    fn mtime(&self) -> u64 {
        self.mtime.load(Ordering::Relaxed)
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = self.data.lock();
        let Ok(off) = usize::try_from(off) else {
            return Ok(0);
        };
        if off >= data.len() {
            return Ok(0);
        }
        let n = buf.len().min(data.len() - off);
        buf[..n].copy_from_slice(&data[off..off + n]);
        Ok(n)
    }

    fn write_at(&self, off: u64, src: &[u8]) -> KResult<usize> {
        let end = off.checked_add(src.len() as u64).ok_or(Errno::EFBIG)?;
        if end > MAX_FILE {
            return Err(Errno::EFBIG);
        }
        let mut data = self.data.lock();
        let (off, end) = (off as usize, end as usize);
        let cur = data.len();
        if cur < end {
            data.try_reserve(end - cur).map_err(|_| Errno::ENOSPC)?;
            data.resize(end, 0);
        }
        data[off..end].copy_from_slice(src);
        drop(data);
        self.mtime.store(now(), Ordering::Relaxed);
        Ok(src.len())
    }

    fn truncate(&self, len: u64) -> KResult<()> {
        if len > MAX_FILE {
            return Err(Errno::EFBIG);
        }
        let mut data = self.data.lock();
        let len = len as usize;
        let cur = data.len();
        if len > cur {
            data.try_reserve(len - cur).map_err(|_| Errno::ENOSPC)?;
        }
        data.resize(len, 0);
        if len < data.capacity() / 2 {
            data.shrink_to_fit();
        }
        drop(data);
        self.mtime.store(now(), Ordering::Relaxed);
        Ok(())
    }
}
