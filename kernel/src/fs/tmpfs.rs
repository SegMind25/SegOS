//! tmpfs: files, directories and symbolic links that live in kernel
//! memory. The root file system (filled from the initramfs) and `/tmp`.

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

/// What every tmpfs inode has.
struct Meta {
    ino: u64,
    perm: AtomicU32,
    mtime: AtomicU64,
    nlink: AtomicU32,
}

impl Meta {
    fn new(perm: u32) -> Self {
        Self {
            ino: new_ino(),
            perm: AtomicU32::new(perm & 0o7777),
            mtime: AtomicU64::new(now()),
            nlink: AtomicU32::new(1),
        }
    }

    fn touch(&self) {
        self.mtime.store(now(), Ordering::Relaxed);
    }
}

macro_rules! meta_methods {
    () => {
        fn ino(&self) -> u64 {
            self.meta.ino
        }
        fn perm(&self) -> u32 {
            self.meta.perm.load(Ordering::Relaxed)
        }
        fn set_perm(&self, perm: u32) -> KResult<()> {
            self.meta.perm.store(perm & 0o7777, Ordering::Relaxed);
            Ok(())
        }
        fn mtime(&self) -> u64 {
            self.meta.mtime.load(Ordering::Relaxed)
        }
        fn set_mtime(&self, secs: u64) {
            self.meta.mtime.store(secs, Ordering::Relaxed);
        }
        fn link_added(&self) {
            self.meta.nlink.fetch_add(1, Ordering::Relaxed);
        }
        fn link_removed(&self) {
            self.meta.nlink.fetch_sub(1, Ordering::Relaxed);
        }
    };
}

pub struct Dir {
    meta: Meta,
    entries: SpinLock<BTreeMap<String, Arc<dyn Inode>>>,
    /// The containing directory; the root's dangling Weak means "this is
    /// the root".
    parent: SpinLock<Weak<dyn Inode>>,
    me: Weak<Dir>,
}

impl Dir {
    pub fn new_root(perm: u32) -> Arc<dyn Inode> {
        Arc::new_cyclic(|me: &Weak<Dir>| Dir {
            meta: Meta::new(perm),
            entries: SpinLock::new(BTreeMap::new()),
            parent: SpinLock::new(Weak::<Dir>::new()),
            me: me.clone(),
        })
    }

    fn new_child(&self, perm: u32) -> Arc<dyn Inode> {
        let parent: Weak<dyn Inode> = self.me.clone();
        Arc::new_cyclic(|me: &Weak<Dir>| Dir {
            meta: Meta::new(perm),
            entries: SpinLock::new(BTreeMap::new()),
            parent: SpinLock::new(parent),
            me: me.clone(),
        })
    }

    fn check_name(name: &str) -> KResult<()> {
        if name == "." || name == ".." || name.is_empty() {
            return Err(Errno::EEXIST);
        }
        Ok(())
    }
}

impl Inode for Dir {
    meta_methods!();

    fn file_type(&self) -> FileType {
        FileType::Directory
    }
    fn size(&self) -> u64 {
        4096
    }
    fn nlink(&self) -> u64 {
        let subdirs = self
            .entries
            .lock()
            .values()
            .filter(|i| i.file_type() == FileType::Directory)
            .count();
        2 + subdirs as u64
    }

    fn lookup(&self, name: &str) -> KResult<Arc<dyn Inode>> {
        self.entries.lock().get(name).cloned().ok_or(Errno::ENOENT)
    }

    fn parent(&self) -> Option<Arc<dyn Inode>> {
        self.parent.lock().upgrade().or_else(|| {
            // The root is its own parent.
            self.me.upgrade().map(|d| d as Arc<dyn Inode>)
        })
    }

    fn set_parent(&self, parent: &Arc<dyn Inode>) {
        *self.parent.lock() = Arc::downgrade(parent);
    }

    fn create(&self, name: &str, ty: FileType, perm: u32) -> KResult<Arc<dyn Inode>> {
        Self::check_name(name)?;
        let mut entries = self.entries.lock();
        if entries.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let inode: Arc<dyn Inode> = match ty {
            FileType::Regular => Arc::new(File {
                meta: Meta::new(perm),
                data: Mutex::new(Vec::new()),
            }),
            FileType::Directory => self.new_child(perm),
            FileType::Fifo => super::pipe::Fifo::create(perm),
            FileType::CharDevice | FileType::Symlink | FileType::BlockDevice => {
                return Err(Errno::EPERM);
            }
        };
        entries.insert(name.to_string(), inode.clone());
        drop(entries);
        self.meta.touch();
        Ok(inode)
    }

    fn symlink(&self, name: &str, target: &str) -> KResult<()> {
        Self::check_name(name)?;
        let mut entries = self.entries.lock();
        if entries.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        entries.insert(
            name.to_string(),
            Arc::new(Symlink {
                meta: Meta::new(0o777),
                target: target.to_string(),
            }),
        );
        drop(entries);
        self.meta.touch();
        Ok(())
    }

    fn insert(&self, name: &str, inode: Arc<dyn Inode>) -> KResult<()> {
        Self::check_name(name)?;
        let mut entries = self.entries.lock();
        if entries.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        entries.insert(name.to_string(), inode);
        drop(entries);
        self.meta.touch();
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
        let inode = entries.remove(name).unwrap();
        drop(entries);
        inode.link_removed();
        self.meta.touch();
        Ok(())
    }

    fn take(&self, name: &str) -> KResult<Arc<dyn Inode>> {
        let inode = self.entries.lock().remove(name).ok_or(Errno::ENOENT)?;
        self.meta.touch();
        Ok(inode)
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
    meta: Meta,
    data: Mutex<Vec<u8>>,
}

impl Inode for File {
    meta_methods!();

    fn file_type(&self) -> FileType {
        FileType::Regular
    }
    fn size(&self) -> u64 {
        self.data.lock().len() as u64
    }
    fn nlink(&self) -> u64 {
        self.meta.nlink.load(Ordering::Relaxed) as u64
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
        self.meta.touch();
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
        self.meta.touch();
        Ok(())
    }
}

pub struct Symlink {
    meta: Meta,
    target: String,
}

impl Inode for Symlink {
    meta_methods!();

    fn file_type(&self) -> FileType {
        FileType::Symlink
    }
    fn size(&self) -> u64 {
        self.target.len() as u64
    }
    fn readlink(&self) -> KResult<String> {
        Ok(self.target.clone())
    }
}
