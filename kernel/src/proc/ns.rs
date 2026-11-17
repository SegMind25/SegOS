//! User and PID namespaces (`clone`/`unshare` with CLONE_NEWUSER and
//! CLONE_NEWPID), as browser sandboxes use them.
//!
//! Every process runs as root (kernel uid and gid 0). A user namespace
//! only changes how ids look from inside it: through its `uid_map` and
//! `gid_map` (written once, through `/proc/<pid>/`), an unmapped id shows
//! as the overflow id 65534. The kernel keeps global ids; a PID namespace
//! hands out its own numbers (1 for its first process, the namespace's
//! init and reaper of its orphans) for the processes and threads in it
//! and in the namespaces below it. When its init exits, the rest of the
//! namespace is killed and no process can be created in it any more.

use crate::abi::{Errno, KResult};
use crate::sync::SpinLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The overflow uid and gid (`/proc/sys/kernel/overflowuid`).
pub const OVERFLOW_ID: u32 = 65534;
/// Linux allows 32 levels of nesting below the initial namespaces.
const MAX_LEVEL: u32 = 32;
/// `/proc/<pid>/ns/*` inode numbers of the initial namespaces (Linux's
/// PROC_USER_INIT_INO and PROC_PID_INIT_INO).
const USER_INIT_INO: u64 = 0xeffffffd;
const PID_INIT_INO: u64 = 0xeffffffc;
/// Later namespaces are numbered from here on, as Linux's are.
static NEXT_INO: AtomicU64 = AtomicU64::new(0xf000_0000);

fn new_ino() -> u64 {
    NEXT_INO.fetch_add(1, Ordering::Relaxed)
}

/// One line of an id map: ids `first..first + count` inside are kernel
/// ids `lower..lower + count`.
#[derive(Clone, Copy)]
struct Extent {
    first: u32,
    lower: u32,
    count: u32,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Ids {
    Uid,
    Gid,
}

pub struct UserNs {
    pub level: u32,
    pub parent: Option<Arc<UserNs>>,
    pub ino: u64,
    uid_map: SpinLock<Option<Vec<Extent>>>,
    gid_map: SpinLock<Option<Vec<Extent>>>,
    /// `/proc/<pid>/setgroups`: "allow" (true) or "deny".
    setgroups: AtomicBool,
}

static INIT_USER: SpinLock<Option<Arc<UserNs>>> = SpinLock::new(None);
static INIT_PID: SpinLock<Option<Arc<PidNs>>> = SpinLock::new(None);

impl UserNs {
    pub fn initial() -> Arc<UserNs> {
        INIT_USER
            .lock()
            .get_or_insert_with(|| {
                let all = alloc::vec![Extent {
                    first: 0,
                    lower: 0,
                    count: u32::MAX,
                }];
                Arc::new(UserNs {
                    level: 0,
                    parent: None,
                    ino: USER_INIT_INO,
                    uid_map: SpinLock::new(Some(all.clone())),
                    gid_map: SpinLock::new(Some(all)),
                    setgroups: AtomicBool::new(true),
                })
            })
            .clone()
    }

    /// A new namespace below `parent`, with no ids mapped yet.
    pub fn new(parent: &Arc<UserNs>) -> KResult<Arc<UserNs>> {
        if parent.level >= MAX_LEVEL {
            return Err(Errno::ENOSPC);
        }
        Ok(Arc::new(UserNs {
            level: parent.level + 1,
            parent: Some(parent.clone()),
            ino: new_ino(),
            uid_map: SpinLock::new(None),
            gid_map: SpinLock::new(None),
            setgroups: AtomicBool::new(parent.setgroups.load(Ordering::Relaxed)),
        }))
    }

    fn map(&self, which: Ids) -> &SpinLock<Option<Vec<Extent>>> {
        match which {
            Ids::Uid => &self.uid_map,
            Ids::Gid => &self.gid_map,
        }
    }

    /// The id that kernel id `kid` is in this namespace, if it is mapped.
    pub fn inside(&self, which: Ids, kid: u32) -> Option<u32> {
        let map = self.map(which).lock();
        map.as_ref()?.iter().find_map(|e| {
            (kid >= e.lower && kid - e.lower < e.count).then(|| e.first + (kid - e.lower))
        })
    }

    /// `kid` as seen from here, or the overflow id.
    pub fn view(&self, which: Ids, kid: u32) -> u32 {
        self.inside(which, kid).unwrap_or(OVERFLOW_ID)
    }

    /// The kernel id that `id` in this namespace stands for.
    pub fn to_kernel(&self, which: Ids, id: u32) -> Option<u32> {
        if id == u32::MAX {
            return None;
        }
        let map = self.map(which).lock();
        map.as_ref()?.iter().find_map(|e| {
            (id >= e.first && id - e.first < e.count).then(|| e.lower + (id - e.first))
        })
    }

    /// Whether `ns` is this namespace or one below it (where a process of
    /// this one, root, has every capability).
    pub fn is_ancestor_of(self: &Arc<Self>, ns: &Arc<UserNs>) -> bool {
        let mut n = Some(ns.clone());
        while let Some(x) = n {
            if Arc::ptr_eq(&x, self) {
                return true;
            }
            n = x.parent.clone();
        }
        false
    }

    /// `setgroups(2)` is allowed once the gid map is written, unless
    /// "deny" was written to `setgroups`.
    pub fn may_setgroups(&self) -> bool {
        self.gid_map.lock().is_some() && self.setgroups.load(Ordering::Relaxed)
    }

    /// `/proc/<pid>/uid_map` (or gid_map) as a process of `reader` reads
    /// it: lower ids are shown in the parent's view when the reader is
    /// inside, in the reader's own otherwise.
    pub fn show_map(self: &Arc<Self>, which: Ids, reader: &Arc<UserNs>) -> String {
        let lower_ns = if Arc::ptr_eq(self, reader) {
            self.parent.clone().unwrap_or_else(|| self.clone())
        } else {
            reader.clone()
        };
        let mut s = String::new();
        let Some(map) = self.map(which).lock().clone() else {
            return s;
        };
        for e in map {
            if let Some(lower) = lower_ns.inside(which, e.lower) {
                let _ = writeln!(s, "{:>10} {:>10} {:>10}", e.first, lower, e.count);
            }
        }
        s
    }

    /// A write of `data` to this namespace's `uid_map` or `gid_map` by a
    /// process in `writer`.
    pub fn write_map(
        self: &Arc<Self>,
        which: Ids,
        off: u64,
        data: &[u8],
        writer: &Arc<UserNs>,
    ) -> KResult<usize> {
        let Some(parent) = self.parent.clone() else {
            return Err(Errno::EPERM);
        };
        if off != 0 || data.len() >= 4096 {
            return Err(Errno::EINVAL);
        }
        // Only from inside the namespace or from its parent.
        if !Arc::ptr_eq(writer, self) && !Arc::ptr_eq(writer, &parent) {
            return Err(Errno::EPERM);
        }
        let text = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
        let mut extents: Vec<Extent> = Vec::new();
        for line in text.split('\n') {
            if line.trim().is_empty() {
                continue;
            }
            let mut f = line.split_ascii_whitespace().map(|w| w.parse::<u32>());
            let (Some(Ok(first)), Some(Ok(lower)), Some(Ok(count)), None) =
                (f.next(), f.next(), f.next(), f.next())
            else {
                return Err(Errno::EINVAL);
            };
            if count == 0
                || first.checked_add(count).is_none()
                || lower.checked_add(count).is_none()
                || extents.len() >= 340
            {
                return Err(Errno::EINVAL);
            }
            if extents.iter().any(|e| {
                ranges_meet(e.first, e.count, first, count)
                    || ranges_meet(e.lower, e.count, lower, count)
            }) {
                return Err(Errno::EINVAL);
            }
            extents.push(Extent {
                first,
                lower,
                count,
            });
        }
        if extents.is_empty() {
            return Err(Errno::EINVAL);
        }
        // Writing a map needs privilege over the parent namespace, unless
        // it maps just the writer's own id (and, for groups, setgroups is
        // denied).
        let own = extents.len() == 1
            && extents[0].count == 1
            && parent.to_kernel(which, extents[0].lower) == Some(0)
            && (which == Ids::Uid || !self.setgroups.load(Ordering::Relaxed));
        if !own && !writer.is_ancestor_of(&parent) {
            return Err(Errno::EPERM);
        }
        // Lower ids are the parent's: store them as kernel ids.
        for e in &mut extents {
            let lo = parent.to_kernel(which, e.lower).ok_or(Errno::EPERM)?;
            let hi = parent
                .to_kernel(which, e.lower + (e.count - 1))
                .ok_or(Errno::EPERM)?;
            if hi.wrapping_sub(lo) != e.count - 1 {
                return Err(Errno::EPERM);
            }
            e.lower = lo;
        }
        let mut map = self.map(which).lock();
        if map.is_some() {
            return Err(Errno::EPERM);
        }
        *map = Some(extents);
        Ok(data.len())
    }

    pub fn show_setgroups(&self) -> String {
        String::from(if self.setgroups.load(Ordering::Relaxed) {
            "allow\n"
        } else {
            "deny\n"
        })
    }

    pub fn write_setgroups(
        self: &Arc<Self>,
        off: u64,
        data: &[u8],
        writer: &Arc<UserNs>,
    ) -> KResult<usize> {
        if off != 0 {
            return Err(Errno::EINVAL);
        }
        if !writer.is_ancestor_of(self) {
            return Err(Errno::EPERM);
        }
        let word = core::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
        match word.strip_suffix('\n').unwrap_or(word) {
            "allow" => {
                if !self.setgroups.load(Ordering::Relaxed) {
                    return Err(Errno::EPERM);
                }
            }
            "deny" => {
                if self.gid_map.lock().is_some() {
                    return Err(Errno::EPERM);
                }
                self.setgroups.store(false, Ordering::Relaxed);
            }
            _ => return Err(Errno::EINVAL),
        }
        Ok(data.len())
    }
}

/// Whether `a..a+n` and `b..b+m` share an id.
fn ranges_meet(a: u32, n: u32, b: u32, m: u32) -> bool {
    (a as u64) < b as u64 + m as u64 && (b as u64) < a as u64 + n as u64
}

pub struct PidNs {
    pub level: u32,
    pub parent: Option<Arc<PidNs>>,
    pub ino: u64,
    inner: SpinLock<PidNsInner>,
}

#[derive(Default)]
struct PidNsInner {
    next: u32,
    /// Number here -> kernel id, and back.
    up: BTreeMap<u32, u32>,
    down: BTreeMap<u32, u32>,
    /// The kernel pid of the namespace's init (0 until it exists).
    reaper: u32,
    /// Its init has exited.
    dead: bool,
}

impl PidNs {
    pub fn initial() -> Arc<PidNs> {
        INIT_PID
            .lock()
            .get_or_insert_with(|| {
                Arc::new(PidNs {
                    level: 0,
                    parent: None,
                    ino: PID_INIT_INO,
                    inner: SpinLock::new(PidNsInner::default()),
                })
            })
            .clone()
    }

    pub fn new(parent: &Arc<PidNs>) -> KResult<Arc<PidNs>> {
        if parent.level >= MAX_LEVEL {
            return Err(Errno::ENOSPC);
        }
        Ok(Arc::new(PidNs {
            level: parent.level + 1,
            parent: Some(parent.clone()),
            ino: new_ino(),
            inner: SpinLock::new(PidNsInner {
                next: 1,
                ..Default::default()
            }),
        }))
    }

    /// What kernel id `kid` is numbered here (0: not in this namespace).
    pub fn nr(&self, kid: u32) -> u32 {
        if self.level == 0 {
            return kid;
        }
        self.inner.lock().down.get(&kid).copied().unwrap_or(0)
    }

    /// The kernel id numbered `nr` here.
    pub fn kid(&self, nr: u32) -> Option<u32> {
        if self.level == 0 {
            return Some(nr);
        }
        self.inner.lock().up.get(&nr).copied()
    }

    /// The kernel pid of this namespace's init (1 for the initial one).
    pub fn reaper(&self) -> u32 {
        if self.level == 0 {
            return 1;
        }
        self.inner.lock().reaper
    }

    /// Gives kernel id `kid` a number here and in every namespace above
    /// (up to the initial one, whose numbers are the kernel's); returns
    /// the number here. ENOMEM once the namespace's init has exited.
    pub fn attach(self: &Arc<Self>, kid: u32) -> KResult<u32> {
        let mut done: Vec<Arc<PidNs>> = Vec::new();
        let mut n = Some(self.clone());
        let mut mine = kid;
        while let Some(ns) = n {
            if ns.level == 0 {
                break;
            }
            {
                let mut g = ns.inner.lock();
                if g.dead {
                    drop(g);
                    for d in &done {
                        d.forget_one(kid);
                    }
                    return Err(Errno::ENOMEM);
                }
                let nr = g.next;
                g.next += 1;
                g.up.insert(nr, kid);
                g.down.insert(kid, nr);
                if nr == 1 {
                    g.reaper = kid;
                }
                if Arc::ptr_eq(&ns, self) {
                    mine = nr;
                }
            }
            n = ns.parent.clone();
            done.push(ns);
        }
        Ok(mine)
    }

    fn forget_one(&self, kid: u32) {
        let mut g = self.inner.lock();
        if let Some(nr) = g.down.remove(&kid) {
            g.up.remove(&nr);
        }
    }

    /// Kernel id `kid` is gone: drop its numbers here and above.
    pub fn detach(self: &Arc<Self>, kid: u32) {
        let mut n = Some(self.clone());
        while let Some(ns) = n {
            if ns.level == 0 {
                break;
            }
            ns.forget_one(kid);
            n = ns.parent.clone();
        }
    }

    /// Its init has exited: no new processes; returns the kernel pids
    /// still numbered here (to be killed).
    pub fn shut_down(&self) -> Vec<u32> {
        let mut g = self.inner.lock();
        g.dead = true;
        g.down.keys().copied().collect()
    }

    /// Whether this namespace is `ns` or one of its ancestors.
    pub fn contains(self: &Arc<Self>, ns: &Arc<PidNs>) -> bool {
        let mut n = Some(ns.clone());
        while let Some(x) = n {
            if Arc::ptr_eq(&x, self) {
                return true;
            }
            n = x.parent.clone();
        }
        false
    }
}
