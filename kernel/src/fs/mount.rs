//! The mount table: which file system's root covers which directory.
//!
//! Path lookup calls [`cross`] on every directory it steps into, so a
//! mounted file system's root replaces the directory it was mounted on,
//! and [`up`] for "..", so stepping out of a mounted root lands in the
//! directory above the mount point. Inodes are told apart by
//! (`dev`, `ino`), as each file system numbers its own inodes.

use super::{FileType, Inode};
use crate::abi::{Errno, KResult};
use crate::sync::SpinLock;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

pub struct Mount {
    pub id: u32,
    /// The directory it covers; None for the root file system.
    pub point: Option<Arc<dyn Inode>>,
    pub root: Arc<dyn Inode>,
    pub source: String,
    pub fstype: String,
    pub path: String,
    pub readonly: bool,
}

static MOUNTS: SpinLock<Vec<Arc<Mount>>> = SpinLock::new(Vec::new());
/// Mounts with a mount point (a fast path for lookups when there are none).
static COVERED: AtomicUsize = AtomicUsize::new(0);
static NEXT_ID: AtomicUsize = AtomicUsize::new(20);

/// Whether `a` and `b` are the same inode.
pub fn same(a: &Arc<dyn Inode>, b: &Arc<dyn Inode>) -> bool {
    a.ino() == b.ino() && a.dev() == b.dev()
}

/// What a lookup that reaches `inode` really gets: the root of whatever
/// is mounted on it (the latest mount, if stacked), else `inode` itself.
pub fn cross(inode: Arc<dyn Inode>) -> Arc<dyn Inode> {
    if COVERED.load(Ordering::Relaxed) == 0 || inode.file_type() != FileType::Directory {
        return inode;
    }
    let mounts = MOUNTS.lock();
    let mut cur = inode;
    'again: for _ in 0..16 {
        for m in mounts.iter().rev() {
            if let Some(p) = &m.point
                && same(p, &cur)
            {
                cur = m.root.clone();
                continue 'again;
            }
        }
        break;
    }
    cur
}

/// The mount whose root is `inode`, if any.
pub fn mount_of_root(inode: &Arc<dyn Inode>) -> Option<Arc<Mount>> {
    MOUNTS
        .lock()
        .iter()
        .rev()
        .find(|m| same(&m.root, inode))
        .cloned()
}

/// The directory ".." of `dir` leads to, across mount points. The root
/// directory is its own parent.
pub fn up(dir: &Arc<dyn Inode>) -> Arc<dyn Inode> {
    let root = super::root();
    if same(dir, &root) {
        return root;
    }
    let mut cur = dir.clone();
    // Out of a mounted root: continue from the directory it covers.
    while let Some(m) = mount_of_root(&cur) {
        match &m.point {
            Some(p) => cur = p.clone(),
            None => return cur,
        }
        if same(&cur, &root) {
            return root;
        }
    }
    let parent = cur.parent().unwrap_or_else(|| cur.clone());
    cross(parent)
}

/// The name of `child` inside `dir` (for getcwd and /proc/*/cwd).
fn name_in(dir: &Arc<dyn Inode>, child: &Arc<dyn Inode>) -> Option<String> {
    if let Some(n) = dir.name_of(child) {
        return Some(n);
    }
    dir.entries()
        .ok()?
        .into_iter()
        .find(|(_, i)| same(&cross(i.clone()), child) || same(i, child))
        .map(|(n, _)| n)
}

/// The absolute path of `inode`, found by walking ".." to the root.
pub fn path_of(inode: &Arc<dyn Inode>) -> String {
    let root = super::root();
    let mut parts = Vec::new();
    let mut cur = inode.clone();
    for _ in 0..256 {
        if same(&cur, &root) {
            break;
        }
        // The name to look for: a mounted root goes by its mount point's.
        let mut named = cur.clone();
        while let Some(m) = mount_of_root(&named) {
            match &m.point {
                Some(p) => named = p.clone(),
                None => break,
            }
        }
        let parent = up(&cur);
        if same(&parent, &cur) {
            break;
        }
        match name_in(&parent, &named) {
            Some(n) => parts.push(n),
            None => break,
        }
        cur = parent;
    }
    let mut out = String::new();
    for p in parts.iter().rev() {
        out.push('/');
        out.push_str(p);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// Mounts `root` (a file system's root directory) on the directory `point`.
pub fn mount(
    point: Option<Arc<dyn Inode>>,
    root: Arc<dyn Inode>,
    source: &str,
    fstype: &str,
    readonly: bool,
) -> KResult<()> {
    if let Some(p) = &point
        && p.file_type() != FileType::Directory
    {
        return Err(Errno::ENOTDIR);
    }
    let path = point.as_ref().map_or_else(|| String::from("/"), path_of);
    let m = Arc::new(Mount {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed) as u32,
        point: point.clone(),
        root,
        source: source.into(),
        fstype: fstype.into(),
        path,
        readonly,
    });
    let mut mounts = MOUNTS.lock();
    if point.is_none() {
        mounts.retain(|m| m.point.is_some());
        mounts.insert(0, m);
    } else {
        mounts.push(m);
        COVERED.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

/// Unmounts the file system whose root is `root`. EBUSY if something is
/// mounted below it.
pub fn umount(root: &Arc<dyn Inode>) -> KResult<()> {
    let mut mounts = MOUNTS.lock();
    let i = mounts
        .iter()
        .rposition(|m| m.point.is_some() && same(&m.root, root))
        .ok_or(Errno::EINVAL)?;
    let dev = mounts[i].root.dev();
    if mounts
        .iter()
        .any(|m| m.point.as_ref().is_some_and(|p| p.dev() == dev) && m.root.dev() != dev)
    {
        return Err(Errno::EBUSY);
    }
    mounts.remove(i);
    COVERED.fetch_sub(1, Ordering::Relaxed);
    Ok(())
}

pub fn all() -> Vec<Arc<Mount>> {
    MOUNTS.lock().clone()
}

/// The mount holding `inode` (the one whose root has its `dev`).
pub fn mount_for(inode: &Arc<dyn Inode>) -> Option<Arc<Mount>> {
    let dev = inode.dev();
    MOUNTS
        .lock()
        .iter()
        .rev()
        .find(|m| m.root.dev() == dev)
        .cloned()
}

/// `/proc/mounts`.
pub fn proc_mounts() -> String {
    let mut s = String::new();
    for m in all() {
        let opts = match m.fstype.as_str() {
            "proc" | "sysfs" => "rw,nosuid,nodev,noexec,relatime",
            "devtmpfs" => "rw,nosuid,relatime,mode=755",
            _ if m.readonly => "ro,relatime",
            _ => "rw,relatime",
        };
        s.push_str(&format!(
            "{} {} {} {} 0 0\n",
            m.source, m.path, m.fstype, opts
        ));
    }
    s
}

/// `/proc/self/mountinfo`.
pub fn proc_mountinfo() -> String {
    let mut s = String::new();
    let mounts = all();
    for m in &mounts {
        let parent = m
            .point
            .as_ref()
            .and_then(|p| mounts.iter().rev().find(|o| o.root.dev() == p.dev()))
            .map_or(m.id, |o| o.id);
        let dev = m.root.dev();
        s.push_str(&format!(
            "{} {} {}:{} / {} {} - {} {} {}\n",
            m.id,
            parent,
            dev >> 8,
            dev & 0xff,
            m.path,
            if m.readonly {
                "ro,relatime"
            } else {
                "rw,relatime"
            },
            m.fstype,
            m.source,
            if m.readonly { "ro" } else { "rw" }
        ));
    }
    s
}
