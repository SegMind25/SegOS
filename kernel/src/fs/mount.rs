//! The mount table: file systems attached on top of directories.
//!
//! A mount covers a directory (the mount point) with the root of another
//! file system. Path lookup crosses down into the mounted root when it
//! reaches a mount point, and back up to the mount point on "..".
//! Inodes are told apart by (st_dev, st_ino), as on Linux.
//!
//! Every process has a mount namespace with its own table (see
//! `proc::ns::MntNs`); calls made without a current process — booting, for
//! instance — use the initial namespace.

use super::{FileType, Inode};
use crate::abi::{Errno, KResult};
use crate::proc::ns::{MntNs, current_mnt};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// What `statfs` reports about a mounted file system.
pub trait FsInfo: Send + Sync {
    fn magic(&self) -> u64;
    /// (block size, blocks, free blocks, inodes, free inodes)
    fn stats(&self) -> (u64, u64, u64, u64, u64);
    /// Whether the file system can only be read (unsupported features,
    /// read-only media).
    fn read_only(&self) -> bool {
        false
    }
}

/// A mounted file system: its root, and statfs info for disk file systems.
pub type Mounted = (Arc<dyn Inode>, Option<Arc<dyn FsInfo>>);

pub struct Mount {
    pub id: u64,
    /// The covered directory.
    pub point: Arc<dyn Inode>,
    /// Root of the mounted file system.
    pub root: Arc<dyn Inode>,
    pub source: String,
    pub fstype: String,
    /// Absolute path of the mount point when mounted.
    pub path: String,
    pub read_only: bool,
    pub info: Option<Arc<dyn FsInfo>>,
}

/// Mount ids are unique across namespaces, as Linux's are.
static NEXT_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

fn same(a: &Arc<dyn Inode>, b: &Arc<dyn Inode>) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// If `inode` is a mount point, the root mounted on it (the latest of
/// stacked mounts); otherwise `inode` itself.
pub fn cross_down(inode: Arc<dyn Inode>) -> Arc<dyn Inode> {
    if inode.file_type() != FileType::Directory {
        return inode;
    }
    let ns = current_mnt();
    let mounts = ns.mounts.lock();
    let mut cur = inode;
    for _ in 0..16 {
        match mounts.iter().rev().find(|m| same(&m.point, &cur)) {
            Some(m) => cur = m.root.clone(),
            None => break,
        }
    }
    cur
}

/// If `inode` is the root of a mounted file system, the directory it
/// covers (repeatedly, for stacked mounts); otherwise `inode` itself.
pub fn cross_up(inode: Arc<dyn Inode>) -> Arc<dyn Inode> {
    let ns = current_mnt();
    let mounts = ns.mounts.lock();
    let mut cur = inode;
    for _ in 0..16 {
        match mounts.iter().rev().find(|m| same(&m.root, &cur)) {
            Some(m) => cur = m.point.clone(),
            None => break,
        }
    }
    cur
}

/// The mount whose root is `inode`, in the caller's namespace.
pub fn mount_at(inode: &Arc<dyn Inode>) -> Option<Arc<Mount>> {
    let ns = current_mnt();
    ns.mounts
        .lock()
        .iter()
        .rev()
        .find(|m| same(&m.root, inode))
        .cloned()
}

/// The innermost mount `inode` belongs to (by st_dev), for statfs.
pub fn mount_of_dev(dev: u64) -> Option<Arc<Mount>> {
    let ns = current_mnt();
    ns.mounts
        .lock()
        .iter()
        .rev()
        .find(|m| m.root.dev() == dev)
        .cloned()
}

pub fn add(
    point: Arc<dyn Inode>,
    root: Arc<dyn Inode>,
    source: &str,
    fstype: &str,
    path: &str,
    read_only: bool,
    info: Option<Arc<dyn FsInfo>>,
) -> KResult<()> {
    if point.file_type() != FileType::Directory || root.file_type() != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    let ns = current_mnt();
    ns.mounts.lock().push(Arc::new(Mount {
        id: NEXT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
        point,
        root,
        source: source.into(),
        fstype: fstype.into(),
        path: path.into(),
        read_only,
        info,
    }));
    Ok(())
}

/// Detaches the mount whose root is `root`; EBUSY if another mount sits
/// inside it.
pub fn remove(root: &Arc<dyn Inode>) -> KResult<Arc<Mount>> {
    let ns = current_mnt();
    let mut mounts = ns.mounts.lock();
    let i = mounts
        .iter()
        .rposition(|m| same(&m.root, root))
        .ok_or(Errno::EINVAL)?;
    let m = mounts[i].clone();
    let busy = mounts.iter().any(|o| {
        o.id != m.id
            && o.path.starts_with(&m.path)
            && o.path.len() > m.path.len()
            && (m.path == "/" || o.path.as_bytes().get(m.path.len()) == Some(&b'/'))
    });
    if busy {
        return Err(Errno::EBUSY);
    }
    mounts.remove(i);
    Ok(m)
}

/// Moves the mount whose root is `root` onto `point` (`mount --move`).
pub fn move_to(root: &Arc<dyn Inode>, point: Arc<dyn Inode>, path: &str) -> KResult<()> {
    let ns = current_mnt();
    let mut mounts = ns.mounts.lock();
    let i = mounts
        .iter()
        .rposition(|m| same(&m.root, root))
        .ok_or(Errno::EINVAL)?;
    let m = mounts.remove(i);
    mounts.push(Arc::new(Mount {
        id: m.id,
        point,
        root: m.root.clone(),
        source: m.source.clone(),
        fstype: m.fstype.clone(),
        path: path.into(),
        read_only: m.read_only,
        info: m.info.clone(),
    }));
    Ok(())
}

pub fn set_read_only(root: &Arc<dyn Inode>, ro: bool) -> KResult<()> {
    let ns = current_mnt();
    let mut mounts = ns.mounts.lock();
    let i = mounts
        .iter()
        .rposition(|m| same(&m.root, root))
        .ok_or(Errno::EINVAL)?;
    let m = &mounts[i];
    let new = Arc::new(Mount {
        id: m.id,
        point: m.point.clone(),
        root: m.root.clone(),
        source: m.source.clone(),
        fstype: m.fstype.clone(),
        path: m.path.clone(),
        read_only: ro,
        info: m.info.clone(),
    });
    mounts[i] = new;
    Ok(())
}

/// Whether the file system with this st_dev is mounted read-only.
pub fn is_read_only(dev: u64) -> bool {
    let ns = current_mnt();
    ns.mounts
        .lock()
        .iter()
        .rev()
        .find(|m| m.root.dev() == dev)
        .is_some_and(|m| m.read_only)
}

/// The caller's mount table, for `/proc/mounts`.
pub fn all() -> Vec<Arc<Mount>> {
    let ns = current_mnt();
    ns.mounts.lock().clone()
}

/// A particular process's mount table, for `/proc/<pid>/mounts`.
pub fn all_in(ns: &Arc<MntNs>) -> Vec<Arc<Mount>> {
    ns.mounts.lock().clone()
}
