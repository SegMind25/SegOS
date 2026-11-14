//! Futexes: the kernel half of every user-space lock, condition variable
//! and `pthread_join`.
//!
//! A waiter is queued under a key naming the futex word: the address
//! space and address for private memory, or the physical address for
//! `MAP_SHARED` pages (the same word in two processes is one futex). The
//! waiter queues itself *before* it reads the word, so a waker that
//! changes the word and then wakes cannot miss it; a waiter that leaves
//! (wrong value, timeout, signal) after being dequeued by a waker counts
//! as woken. Wakers dequeue at most the number of waiters asked for,
//! matching bitsets, and requeue moves waiters to another key.

use crate::abi::{Errno, KResult, Timespec};
use crate::mm::vm::AddressSpace;
use crate::mm::{PAGE_SIZE, paging, phys_to_virt};
use crate::sync::SpinLock;
use crate::task::wait::WaitQueue;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Operations (the low bits of `op`).
pub mod ops {
    pub const FUTEX_WAIT: u32 = 0;
    pub const FUTEX_WAKE: u32 = 1;
    pub const FUTEX_REQUEUE: u32 = 3;
    pub const FUTEX_CMP_REQUEUE: u32 = 4;
    pub const FUTEX_WAKE_OP: u32 = 5;
    pub const FUTEX_LOCK_PI: u32 = 6;
    pub const FUTEX_UNLOCK_PI: u32 = 7;
    pub const FUTEX_TRYLOCK_PI: u32 = 8;
    pub const FUTEX_WAIT_BITSET: u32 = 9;
    pub const FUTEX_WAKE_BITSET: u32 = 10;
    pub const FUTEX_PRIVATE_FLAG: u32 = 128;
    pub const FUTEX_CLOCK_REALTIME: u32 = 256;
    pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xffff_ffff;
}
use ops::*;

/// Robust futex word bits.
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Key {
    /// (address space, user address).
    Private(usize, u64),
    /// Physical address of a word in a shared page.
    Shared(u64),
}

struct Waiter {
    woken: AtomicBool,
    bitset: u32,
    queue: WaitQueue,
    /// Changed (by requeue) only with `TABLE` held.
    key: SpinLock<Key>,
}

static TABLE: SpinLock<BTreeMap<Key, VecDeque<Arc<Waiter>>>> = SpinLock::new(BTreeMap::new());

fn key(mm: &AddressSpace, addr: u64, private: bool) -> KResult<Key> {
    if !addr.is_multiple_of(4) {
        return Err(Errno::EINVAL);
    }
    if !private {
        // Fault the page in, then see whether it is shared memory.
        let _: u32 = mm.read(addr)?;
        if let Some(e) = paging::user_entry(mm.pml4(), addr & !(PAGE_SIZE - 1))
            && e & paging::flags::SHARED != 0
        {
            return Ok(Key::Shared(paging::entry_phys(e) + addr % PAGE_SIZE));
        }
    }
    Ok(Key::Private(mm as *const AddressSpace as usize, addr))
}

/// Takes `w` off its queue; false if a waker already did (it was woken).
fn dequeue(w: &Arc<Waiter>) -> bool {
    let mut t = TABLE.lock();
    let k = *w.key.lock();
    let Some(q) = t.get_mut(&k) else {
        return false;
    };
    let found = match q.iter().position(|x| Arc::ptr_eq(x, w)) {
        Some(i) => {
            q.remove(i);
            true
        }
        None => false,
    };
    if q.is_empty() {
        t.remove(&k);
    }
    found
}

/// Wakes up to `n` waiters on `k` whose bitset matches (at least one, as
/// Linux does for n <= 0). Returns how many woke.
fn wake_key(k: Key, n: i32, bitset: u32) -> u64 {
    let mut t = TABLE.lock();
    let Some(q) = t.get_mut(&k) else {
        return 0;
    };
    let mut woken = 0u64;
    let mut i = 0;
    while i < q.len() {
        if q[i].bitset & bitset == 0 {
            i += 1;
            continue;
        }
        let w = q.remove(i).unwrap();
        w.woken.store(true, Ordering::Release);
        w.queue.wake_all();
        woken += 1;
        if woken as i64 >= n as i64 {
            break;
        }
    }
    if q.is_empty() {
        t.remove(&k);
    }
    woken
}

/// Wakes up to `n` waiters on the word at `addr` (thread exit's
/// `clear_child_tid`, robust lists).
pub fn wake_address(mm: &AddressSpace, addr: u64, n: i32) {
    if let Ok(k) = key(mm, addr, false) {
        wake_key(k, n, FUTEX_BITSET_MATCH_ANY);
    }
}

/// A deadline on the monotonic clock, from a user timespec.
fn deadline(mm: &AddressSpace, ts: u64, absolute: bool, realtime: bool) -> KResult<Option<u64>> {
    if ts == 0 {
        return Ok(None);
    }
    let t: Timespec = mm.read(ts)?;
    if t.tv_sec < 0 || !(0..1_000_000_000).contains(&t.tv_nsec) {
        return Err(Errno::EINVAL);
    }
    let ns = (t.tv_sec as u64)
        .saturating_mul(crate::time::NS_PER_SEC)
        .saturating_add(t.tv_nsec as u64);
    let now = crate::time::monotonic_ns();
    Ok(Some(if !absolute {
        now.saturating_add(ns)
    } else if realtime {
        let offset = crate::time::realtime_ns().saturating_sub(now);
        ns.saturating_sub(offset)
    } else {
        ns
    }))
}

fn wait(
    mm: &AddressSpace,
    addr: u64,
    val: u32,
    bitset: u32,
    private: bool,
    deadline: Option<u64>,
) -> KResult<u64> {
    if bitset == 0 {
        return Err(Errno::EINVAL);
    }
    let k = key(mm, addr, private)?;
    let w = Arc::new(Waiter {
        woken: AtomicBool::new(false),
        bitset,
        queue: WaitQueue::new(),
        key: SpinLock::new(k),
    });
    TABLE.lock().entry(k).or_default().push_back(w.clone());
    let result = match mm.read::<u32>(addr) {
        Err(e) => Err(e),
        Ok(cur) if cur != val => Err(Errno::EAGAIN),
        Ok(_) => {
            let _timer = deadline.map(crate::time::wake_at);
            let timed_out = || deadline.is_some_and(|d| crate::time::monotonic_ns() >= d);
            match w
                .queue
                .wait_interruptible(|| w.woken.load(Ordering::Acquire) || timed_out())
            {
                Ok(()) if w.woken.load(Ordering::Acquire) => Ok(()),
                Ok(()) => Err(Errno::ETIMEDOUT),
                // A timed wait is not restarted (its time would start
                // over); an untimed one is, after a handler with SA_RESTART.
                Err(_) if deadline.is_some() => Err(Errno::EINTR),
                Err(e) => Err(e),
            }
        }
    };
    match result {
        Ok(()) => Ok(0),
        Err(e) => {
            if dequeue(&w) {
                Err(e)
            } else {
                Ok(0) // a waker took us meanwhile: that wake-up was ours
            }
        }
    }
}

/// Wakes `nr_wake` waiters of `k1` and moves up to `nr_requeue` of the
/// rest to `k2`. Returns woken + moved.
fn requeue(k1: Key, k2: Key, nr_wake: i32, nr_requeue: i32) -> u64 {
    let woken = wake_key(k1, nr_wake, FUTEX_BITSET_MATCH_ANY);
    if k1 == k2 || nr_requeue <= 0 {
        return woken;
    }
    let mut t = TABLE.lock();
    let Some(mut q1) = t.remove(&k1) else {
        return woken;
    };
    let n = (nr_requeue as usize).min(q1.len());
    let moved: VecDeque<_> = q1.drain(..n).collect();
    if !q1.is_empty() {
        t.insert(k1, q1);
    }
    let q2 = t.entry(k2).or_default();
    for w in moved {
        *w.key.lock() = k2;
        q2.push_back(w);
    }
    woken + n as u64
}

/// An atomic read-modify-write of the user word at `addr` (FUTEX_WAKE_OP).
/// Returns the old value.
fn atomic_update(mm: &AddressSpace, addr: u64, f: impl Fn(u32) -> u32) -> KResult<u32> {
    if !addr.is_multiple_of(4) {
        return Err(Errno::EINVAL);
    }
    let page = addr & !(PAGE_SIZE - 1);
    let writable = |e: u64| {
        e & paging::flags::WRITABLE != 0
            && e & paging::flags::USER != 0
            && e & paging::flags::COW == 0
    };
    let entry = match paging::user_entry(mm.pml4(), page) {
        Some(e) if writable(e) => e,
        _ => {
            if !mm.handle_fault(addr, true, false) {
                return Err(Errno::EFAULT);
            }
            paging::user_entry(mm.pml4(), page)
                .filter(|&e| writable(e))
                .ok_or(Errno::EFAULT)?
        }
    };
    let ptr = unsafe { phys_to_virt(paging::entry_phys(entry)).add((addr % PAGE_SIZE) as usize) };
    let word = unsafe { &*(ptr as *const AtomicU32) };
    let mut old = word.load(Ordering::SeqCst);
    loop {
        match word.compare_exchange(old, f(old), Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Ok(old),
            Err(cur) => old = cur,
        }
    }
}

fn sign_extend12(v: u32) -> i32 {
    ((v << 20) as i32) >> 20
}

fn wake_op(mm: &AddressSpace, k1: Key, addr2: u64, private: bool, a: [u64; 6]) -> KResult<u64> {
    let (nr_wake, nr_wake2, val3) = (a[2] as i32, a[3] as i32, a[5] as u32);
    let mut op = (val3 >> 28) & 0xf;
    let cmp = (val3 >> 24) & 0xf;
    let mut oparg = sign_extend12((val3 >> 12) & 0xfff) as u32;
    let cmparg = sign_extend12(val3 & 0xfff);
    if op & 8 != 0 {
        oparg = 1u32.wrapping_shl(oparg & 31);
        op &= 7;
    }
    if op > 4 || cmp > 5 {
        return Err(Errno::ENOSYS);
    }
    let k2 = key(mm, addr2, private)?;
    let old = atomic_update(mm, addr2, |old| match op {
        0 => oparg,
        1 => old.wrapping_add(oparg),
        2 => old | oparg,
        3 => old & !oparg,
        _ => old ^ oparg,
    })? as i32;
    let mut woken = wake_key(k1, nr_wake, FUTEX_BITSET_MATCH_ANY);
    let hit = match cmp {
        0 => old == cmparg,
        1 => old != cmparg,
        2 => old < cmparg,
        3 => old <= cmparg,
        4 => old > cmparg,
        _ => old >= cmparg,
    };
    if hit {
        woken += wake_key(k2, nr_wake2, FUTEX_BITSET_MATCH_ANY);
    }
    Ok(woken)
}

/// `futex(uaddr, op, val, timeout/val2, uaddr2, val3)`.
pub fn futex(mm: &AddressSpace, a: [u64; 6]) -> KResult<u64> {
    let (addr, op_full, val) = (a[0], a[1] as u32, a[2] as u32);
    let private = op_full & FUTEX_PRIVATE_FLAG != 0;
    let realtime = op_full & FUTEX_CLOCK_REALTIME != 0;
    let op = op_full & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    if realtime && op != FUTEX_WAIT && op != FUTEX_WAIT_BITSET {
        return Err(Errno::ENOSYS);
    }
    match op {
        FUTEX_WAIT => {
            let d = deadline(mm, a[3], false, false)?;
            wait(mm, addr, val, FUTEX_BITSET_MATCH_ANY, private, d)
        }
        FUTEX_WAIT_BITSET => {
            let d = deadline(mm, a[3], true, realtime)?;
            wait(mm, addr, val, a[5] as u32, private, d)
        }
        FUTEX_WAKE => Ok(wake_key(
            key(mm, addr, private)?,
            val as i32,
            FUTEX_BITSET_MATCH_ANY,
        )),
        FUTEX_WAKE_BITSET => {
            let bitset = a[5] as u32;
            if bitset == 0 {
                return Err(Errno::EINVAL);
            }
            Ok(wake_key(key(mm, addr, private)?, val as i32, bitset))
        }
        FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
            let (nr_wake, nr_requeue) = (val as i32, a[3] as i32);
            if nr_wake < 0 || nr_requeue < 0 {
                return Err(Errno::EINVAL);
            }
            let k1 = key(mm, addr, private)?;
            let k2 = key(mm, a[4], private)?;
            if op == FUTEX_CMP_REQUEUE {
                let cur: u32 = mm.read(addr)?;
                if cur != a[5] as u32 {
                    return Err(Errno::EAGAIN);
                }
            }
            Ok(requeue(k1, k2, nr_wake, nr_requeue))
        }
        FUTEX_WAKE_OP => {
            let k1 = key(mm, addr, private)?;
            wake_op(mm, k1, a[4], private, a)
        }
        FUTEX_LOCK_PI | FUTEX_UNLOCK_PI | FUTEX_TRYLOCK_PI => Err(Errno::ENOSYS),
        _ => Err(Errno::ENOSYS),
    }
}

/// Marks one robust futex of a dying thread: if `tid` owns it, set
/// OWNER_DIED (keeping WAITERS) and wake a waiter.
fn handle_death(mm: &AddressSpace, addr: u64, tid: u32, pending_op: bool) {
    let mut wake = false;
    let r = atomic_update(mm, addr, |v| {
        if v & FUTEX_TID_MASK == tid {
            (v & FUTEX_WAITERS) | FUTEX_OWNER_DIED
        } else {
            v
        }
    });
    if let Ok(old) = r {
        if old & FUTEX_TID_MASK == tid {
            wake = old & FUTEX_WAITERS != 0;
        } else if pending_op && old == 0 {
            // Released but not yet woken: wake someone to retry.
            wake = true;
        }
    }
    if wake {
        wake_address(mm, addr, 1);
    }
}

/// Walks the robust list (`set_robust_list`) of a dying thread.
pub fn exit_robust_list(mm: &AddressSpace, head: u64, tid: u32) {
    if head == 0 {
        return;
    }
    // struct robust_list_head { next; long futex_offset; list_op_pending; }
    let Ok(mut entry) = mm.read::<u64>(head) else {
        return;
    };
    let Ok(offset) = mm.read::<i64>(head + 8) else {
        return;
    };
    let pending = mm.read::<u64>(head + 16).unwrap_or(0) & !1;
    let mut limit = 2048;
    while entry & !1 != head && entry != 0 && limit > 0 {
        let e = entry & !1;
        // Read the next pointer before the futex can be released.
        let next = mm.read::<u64>(e);
        if e != pending {
            handle_death(mm, e.wrapping_add(offset as u64), tid, false);
        }
        match next {
            Ok(n) => entry = n,
            Err(_) => return,
        }
        limit -= 1;
    }
    if pending != 0 {
        handle_death(mm, pending.wrapping_add(offset as u64), tid, true);
    }
}
