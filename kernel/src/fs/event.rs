//! Event file descriptors: `eventfd`, `timerfd`, `signalfd`, `epoll` and
//! `inotify`.
//!
//! Each is an anonymous inode that `read`, `write`, `poll` and `epoll`
//! work on like any other file. Blocking reads sleep on the object's own
//! wait queue; every change also calls [`poll_notify`] so `poll`, `select`
//! and `epoll_wait` look again.
//!
//! epoll keeps no callbacks on the files it watches: `epoll_wait` asks
//! each watched file's `poll` (an epoll in an epoll asks its own list), and
//! sleeps on the global poll notification. Edge-triggered entries report
//! when readiness appears or when the file's [`Inode::poll_generation`]
//! moved since the last report.

use super::{File, FileType, Inode, POLL_EVENTS, POLL_WAIT, new_ino, poll, poll_notify};
use crate::abi::{Errno, KResult};
use crate::sync::{Once, SpinLock};
use crate::task::wait::WaitQueue;
use crate::time::{self, NS_PER_SEC};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

/// What every anonymous inode shares.
macro_rules! anon_inode {
    ($name:literal) => {
        // Linux's anonymous inodes have no type bits; a FIFO behaves the
        // same for lseek (ESPIPE) and mmap (ENODEV).
        fn file_type(&self) -> FileType {
            FileType::Fifo
        }
        fn ino(&self) -> u64 {
            self.ino
        }
        fn dev(&self) -> u64 {
            DEV_ANON
        }
        fn perm(&self) -> u32 {
            0o600
        }
        fn seekable(&self) -> bool {
            false
        }
        fn read_at(&self, _off: u64, _buf: &mut [u8]) -> KResult<usize> {
            Err(Errno::EINVAL)
        }
        fn write_at(&self, _off: u64, _data: &[u8]) -> KResult<usize> {
            Err(Errno::EINVAL)
        }
        fn anon_name(&self) -> Option<&'static str> {
            Some($name)
        }
        fn as_any(&self) -> Option<&dyn Any> {
            Some(self)
        }
    };
}

/// `st_dev` of anonymous inodes (Linux's anon_inodefs is an unnamed
/// device too).
pub const DEV_ANON: u64 = 0xe;

// ---------------------------------------------------------------- eventfd

pub const EFD_SEMAPHORE: u32 = 1;

/// A 64-bit counter: writes add, reads take it (or 1, as a semaphore).
pub struct EventFd {
    ino: u64,
    count: SpinLock<u64>,
    semaphore: bool,
    wait: WaitQueue,
    generation: AtomicU64,
}

impl EventFd {
    pub fn create(initial: u32, flags: u32) -> Arc<dyn Inode> {
        Arc::new(Self {
            ino: new_ino(),
            count: SpinLock::new(initial as u64),
            semaphore: flags & EFD_SEMAPHORE != 0,
            wait: WaitQueue::new(),
            generation: AtomicU64::new(0),
        })
    }

    fn changed(&self) {
        self.generation.fetch_add(1, Ordering::Release);
        self.wait.wake_all();
        poll_notify();
    }
}

const EFD_MAX: u64 = u64::MAX - 1;

impl Inode for EventFd {
    anon_inode!("[eventfd]");

    fn read_stream(&self, buf: &mut [u8], nonblock: bool) -> KResult<usize> {
        if buf.len() < 8 {
            return Err(Errno::EINVAL);
        }
        loop {
            {
                let mut c = self.count.lock();
                if *c > 0 {
                    let v = if self.semaphore { 1 } else { *c };
                    *c -= v;
                    drop(c);
                    buf[..8].copy_from_slice(&v.to_le_bytes());
                    self.changed();
                    return Ok(8);
                }
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            self.wait.wait_interruptible(|| *self.count.lock() > 0)?;
        }
    }

    fn write_stream(&self, data: &[u8], nonblock: bool) -> KResult<usize> {
        if data.len() < 8 {
            return Err(Errno::EINVAL);
        }
        let v = u64::from_le_bytes(data[..8].try_into().unwrap());
        if v == u64::MAX {
            return Err(Errno::EINVAL);
        }
        loop {
            {
                let mut c = self.count.lock();
                if EFD_MAX - *c >= v {
                    *c += v;
                    drop(c);
                    self.changed();
                    return Ok(8);
                }
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            self.wait
                .wait_interruptible(|| EFD_MAX - *self.count.lock() >= v)?;
        }
    }

    fn poll(&self) -> u16 {
        let c = *self.count.lock();
        let mut r = 0;
        if c > 0 {
            r |= poll::POLLIN;
        }
        if c < EFD_MAX {
            r |= poll::POLLOUT;
        }
        r
    }

    fn poll_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

// ---------------------------------------------------------------- timerfd

pub const CLOCK_REALTIME: u32 = 0;
pub const CLOCK_MONOTONIC: u32 = 1;
pub const CLOCK_BOOTTIME: u32 = 7;
pub const TFD_TIMER_ABSTIME: u32 = 1;
pub const TFD_TIMER_CANCEL_ON_SET: u32 = 2;

#[derive(Default)]
struct TimerState {
    /// Next expiry (monotonic ns), if armed.
    next: Option<u64>,
    interval: u64,
    /// Expirations not yet read.
    expirations: u64,
}

impl TimerState {
    /// Counts the expirations up to `now`. Returns whether there were new
    /// ones.
    fn update(&mut self, now: u64) -> bool {
        let Some(d) = self.next else {
            return false;
        };
        if now < d {
            return false;
        }
        match (now - d).checked_div(self.interval) {
            Some(q) => {
                let n = q + 1;
                self.expirations = self.expirations.saturating_add(n);
                self.next = Some(d + n * self.interval);
            }
            None => {
                self.expirations = self.expirations.saturating_add(1);
                self.next = None;
            }
        }
        true
    }
}

pub struct TimerFd {
    ino: u64,
    realtime: bool,
    state: SpinLock<TimerState>,
    wait: WaitQueue,
    generation: AtomicU64,
}

/// Armed timers, for the thread that wakes pollers when they expire.
static TIMERS: SpinLock<Vec<Weak<TimerFd>>> = SpinLock::new(Vec::new());
/// Bumped (and the daemon woken) when a timer is set.
static TIMERS_CHANGED: AtomicU64 = AtomicU64::new(0);
static DAEMON_WAIT: WaitQueue = WaitQueue::new();
static DAEMON: Once<()> = Once::new();

/// The timer thread: sleeps until the earliest armed timer expires, then
/// counts its expirations and wakes whoever polls or reads it.
fn timer_daemon() {
    loop {
        let seen = TIMERS_CHANGED.load(Ordering::Acquire);
        let now = time::monotonic_ns();
        let mut earliest: Option<u64> = None;
        let mut fired = Vec::new();
        {
            let mut timers = TIMERS.lock();
            timers.retain(|w| w.strong_count() > 0);
            for w in timers.iter() {
                let Some(t) = w.upgrade() else { continue };
                let mut st = t.state.lock();
                if st.update(now) {
                    fired.push(t.clone());
                }
                if let Some(d) = st.next {
                    earliest = Some(earliest.map_or(d, |e: u64| e.min(d)));
                }
            }
        }
        for t in &fired {
            t.changed();
        }
        drop(fired);
        let _timer = earliest.map(time::wake_at);
        DAEMON_WAIT.wait_until(|| {
            TIMERS_CHANGED.load(Ordering::Acquire) != seen
                || earliest.is_some_and(|e| time::monotonic_ns() >= e)
        });
    }
}

/// (it_interval, it_value) in ns.
pub type ITimerSpec = (u64, u64);

impl TimerFd {
    pub fn create(clock: u32) -> KResult<Arc<TimerFd>> {
        if !matches!(clock, CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME) {
            return Err(Errno::EINVAL);
        }
        DAEMON.call_once(|| {
            crate::task::spawn_named("timerfd", timer_daemon);
        });
        let t = Arc::new(Self {
            ino: new_ino(),
            realtime: clock == CLOCK_REALTIME,
            state: SpinLock::new(TimerState::default()),
            wait: WaitQueue::new(),
            generation: AtomicU64::new(0),
        });
        TIMERS.lock().push(Arc::downgrade(&t));
        Ok(t)
    }

    fn changed(&self) {
        self.generation.fetch_add(1, Ordering::Release);
        self.wait.wake_all();
        poll_notify();
    }

    /// The time left and the interval.
    pub fn get(&self) -> ITimerSpec {
        let now = time::monotonic_ns();
        let mut st = self.state.lock();
        st.update(now);
        (
            st.interval,
            st.next.map_or(0, |d| d.saturating_sub(now).max(1)),
        )
    }

    /// `timerfd_settime`: returns the old setting.
    pub fn set(&self, flags: u32, interval: u64, value: u64) -> ITimerSpec {
        let old = self.get();
        let now = time::monotonic_ns();
        {
            let mut st = self.state.lock();
            st.expirations = 0;
            st.interval = interval;
            st.next = if value == 0 {
                None
            } else if flags & TFD_TIMER_ABSTIME == 0 {
                Some(now.saturating_add(value))
            } else if self.realtime {
                let offset = time::realtime_ns().saturating_sub(now);
                Some(value.saturating_sub(offset))
            } else {
                Some(value)
            };
        }
        TIMERS_CHANGED.fetch_add(1, Ordering::Release);
        DAEMON_WAIT.wake_all();
        self.changed();
        old
    }
}

impl Inode for TimerFd {
    anon_inode!("[timerfd]");

    fn read_stream(&self, buf: &mut [u8], nonblock: bool) -> KResult<usize> {
        if buf.len() < 8 {
            return Err(Errno::EINVAL);
        }
        loop {
            let next = {
                let mut st = self.state.lock();
                st.update(time::monotonic_ns());
                if st.expirations > 0 {
                    let n = core::mem::take(&mut st.expirations);
                    buf[..8].copy_from_slice(&n.to_le_bytes());
                    return Ok(8);
                }
                st.next
            };
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            let generation_now = self.generation.load(Ordering::Acquire);
            let _timer = next.map(time::wake_at);
            self.wait.wait_interruptible(|| {
                self.generation.load(Ordering::Acquire) != generation_now
                    || next.is_some_and(|d| time::monotonic_ns() >= d)
            })?;
        }
    }

    fn write_stream(&self, _data: &[u8], _nonblock: bool) -> KResult<usize> {
        Err(Errno::EINVAL)
    }

    fn poll(&self) -> u16 {
        let mut st = self.state.lock();
        st.update(time::monotonic_ns());
        if st.expirations > 0 { poll::POLLIN } else { 0 }
    }

    fn poll_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

/// A timespec pair (struct itimerspec) as (interval ns, value ns).
pub fn ns_of_timespec(sec: i64, nsec: i64) -> KResult<u64> {
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(Errno::EINVAL);
    }
    Ok((sec as u64)
        .saturating_mul(NS_PER_SEC)
        .saturating_add(nsec as u64))
}

// --------------------------------------------------------------- signalfd

/// Reads the calling thread's pending signals in `mask` as
/// `struct signalfd_siginfo` records.
pub struct SignalFd {
    ino: u64,
    pub mask: AtomicU64,
}

impl SignalFd {
    pub fn create(mask: u64) -> Arc<dyn Inode> {
        Arc::new(Self {
            ino: new_ino(),
            mask: AtomicU64::new(mask),
        })
    }

    fn mask(&self) -> u64 {
        self.mask.load(Ordering::Relaxed) & !crate::proc::signal::UNBLOCKABLE
    }
}

fn siginfo_record(sig: i32, info: &crate::proc::signal::SigInfo) -> [u8; 128] {
    let mut b = [0u8; 128];
    b[0..4].copy_from_slice(&(sig as u32).to_le_bytes()); // ssi_signo
    b[8..12].copy_from_slice(&info.code.to_le_bytes()); // ssi_code
    b[12..16].copy_from_slice(&(info.a as u32).to_le_bytes()); // ssi_pid
    b[16..20].copy_from_slice(&((info.a >> 32) as u32).to_le_bytes()); // ssi_uid
    b[40..44].copy_from_slice(&(info.b as i32).to_le_bytes()); // ssi_status
    b[72..80].copy_from_slice(&info.a.to_le_bytes()); // ssi_addr
    b
}

impl Inode for SignalFd {
    anon_inode!("[signalfd]");

    fn read_stream(&self, buf: &mut [u8], nonblock: bool) -> KResult<usize> {
        if buf.len() < 128 {
            return Err(Errno::EINVAL);
        }
        let task = crate::task::current();
        let u = task.user().ok_or(Errno::EINVAL)?;
        loop {
            let mut n = 0;
            while n + 128 <= buf.len() {
                let Some((sig, info)) = u.dequeue_signal(self.mask()) else {
                    break;
                };
                buf[n..n + 128].copy_from_slice(&siginfo_record(sig, &info));
                n += 128;
            }
            if n > 0 {
                return Ok(n);
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            let seen = POLL_EVENTS.load(Ordering::Acquire);
            POLL_WAIT.wait_interruptible(|| {
                POLL_EVENTS.load(Ordering::Acquire) != seen
                    || u.pending_signals() & self.mask() != 0
            })?;
        }
    }

    fn write_stream(&self, _data: &[u8], _nonblock: bool) -> KResult<usize> {
        Err(Errno::EINVAL)
    }

    fn poll(&self) -> u16 {
        let task = crate::task::current();
        match task.user() {
            Some(u) if u.pending_signals() & self.mask() != 0 => poll::POLLIN,
            _ => 0,
        }
    }
}

// ------------------------------------------------------------------ epoll

pub mod ev {
    pub const EPOLLIN: u32 = 0x001;
    pub const EPOLLPRI: u32 = 0x002;
    pub const EPOLLOUT: u32 = 0x004;
    pub const EPOLLERR: u32 = 0x008;
    pub const EPOLLHUP: u32 = 0x010;
    pub const EPOLLRDNORM: u32 = 0x040;
    pub const EPOLLWRNORM: u32 = 0x100;
    pub const EPOLLRDHUP: u32 = 0x2000;
    pub const EPOLLEXCLUSIVE: u32 = 1 << 28;
    pub const EPOLLWAKEUP: u32 = 1 << 29;
    pub const EPOLLONESHOT: u32 = 1 << 30;
    pub const EPOLLET: u32 = 1 << 31;
}
use ev::*;

struct Interest {
    file: Weak<File>,
    fd: i32,
    events: u32,
    data: u64,
    /// A one-shot entry that has reported: silent until EPOLL_CTL_MOD.
    disarmed: bool,
    /// Edge-triggered: what was ready and the file's generation at the
    /// last look.
    last_ready: u32,
    last_gen: u64,
}

/// What `file` reports, in epoll bits, among `events` (errors and hang-ups
/// always).
fn readiness(file: &File, events: u32) -> u32 {
    let p = file.inode.poll() as u32;
    let mut r = p & (EPOLLIN | EPOLLPRI | EPOLLOUT | EPOLLERR | EPOLLHUP);
    if r & EPOLLIN != 0 {
        r |= EPOLLRDNORM;
    }
    if r & EPOLLOUT != 0 {
        r |= EPOLLWRNORM;
    }
    if r & EPOLLHUP != 0 {
        r |= EPOLLRDHUP;
    }
    r & (events | EPOLLERR | EPOLLHUP)
}

pub struct Epoll {
    ino: u64,
    /// In the order they were added.
    items: SpinLock<Vec<Interest>>,
}

pub const EPOLL_CTL_ADD: u32 = 1;
pub const EPOLL_CTL_DEL: u32 = 2;
pub const EPOLL_CTL_MOD: u32 = 3;

impl Epoll {
    pub fn create() -> Arc<dyn Inode> {
        Arc::new(Self {
            ino: new_ino(),
            items: SpinLock::new(Vec::new()),
        })
    }

    /// Whether this epoll watches `target` (an epoll), directly or through
    /// nested epolls.
    fn reaches(&self, target: &Epoll, depth: usize) -> bool {
        if core::ptr::eq(self, target) {
            return true;
        }
        if depth > 5 {
            return true;
        }
        let files: Vec<_> = self
            .items
            .lock()
            .iter()
            .filter_map(|i| i.file.upgrade())
            .collect();
        files.iter().any(|f| {
            f.inode
                .as_any()
                .and_then(|a| a.downcast_ref::<Epoll>())
                .is_some_and(|e| e.reaches(target, depth + 1))
        })
    }

    pub fn ctl(&self, op: u32, fd: i32, file: &Arc<File>, events: u32, data: u64) -> KResult<()> {
        if matches!(
            file.inode.file_type(),
            FileType::Regular | FileType::Directory
        ) {
            return Err(Errno::EPERM);
        }
        if let Some(e) = file.inode.as_any().and_then(|a| a.downcast_ref::<Epoll>()) {
            if core::ptr::eq(e, self) {
                return Err(Errno::EINVAL);
            }
            if op == EPOLL_CTL_ADD && e.reaches(self, 0) {
                return Err(Errno::ELOOP);
            }
        }
        let mut items = self.items.lock();
        items.retain(|i| i.file.strong_count() > 0);
        let pos = items
            .iter()
            .position(|i| i.fd == fd && core::ptr::eq(i.file.as_ptr(), Arc::as_ptr(file)));
        match op {
            EPOLL_CTL_ADD => {
                if pos.is_some() {
                    return Err(Errno::EEXIST);
                }
                items.push(Interest {
                    file: Arc::downgrade(file),
                    fd,
                    events,
                    data,
                    disarmed: false,
                    last_ready: 0,
                    last_gen: file.inode.poll_generation().wrapping_sub(1),
                });
            }
            EPOLL_CTL_DEL => {
                items.remove(pos.ok_or(Errno::ENOENT)?);
            }
            EPOLL_CTL_MOD => {
                let i = &mut items[pos.ok_or(Errno::ENOENT)?];
                if i.events & EPOLLEXCLUSIVE != 0 {
                    return Err(Errno::EINVAL);
                }
                i.events = events;
                i.data = data;
                i.disarmed = false;
                i.last_ready = 0;
                i.last_gen = file.inode.poll_generation().wrapping_sub(1);
            }
            _ => return Err(Errno::EINVAL),
        }
        drop(items);
        // A waiter may now have something to report.
        poll_notify();
        Ok(())
    }

    /// Up to `max` ready entries as (events, data), consuming edge and
    /// one-shot state.
    pub fn collect(&self, max: usize) -> Vec<(u32, u64)> {
        // The files are polled without the list lock held: a nested epoll
        // polls its own list.
        let snapshot: Vec<(usize, Arc<File>, u32)> = {
            let mut items = self.items.lock();
            items.retain(|i| i.file.strong_count() > 0);
            items
                .iter()
                .enumerate()
                .filter(|(_, i)| !i.disarmed)
                .filter_map(|(n, i)| i.file.upgrade().map(|f| (n, f, i.events)))
                .collect()
        };
        let polled: Vec<(usize, Arc<File>, u32, u64)> = snapshot
            .into_iter()
            .map(|(n, f, events)| {
                let generation_now = f.inode.poll_generation();
                let r = readiness(&f, events);
                (n, f, r, generation_now)
            })
            .collect();
        let mut out = Vec::new();
        let mut items = self.items.lock();
        for (n, f, r, generation_now) in polled {
            if out.len() >= max {
                break;
            }
            // The list may have changed meanwhile: find the entry again.
            let Some(i) = items
                .get_mut(n)
                .filter(|i| core::ptr::eq(i.file.as_ptr(), Arc::as_ptr(&f)) && !i.disarmed)
            else {
                continue;
            };
            if i.events & EPOLLET != 0 {
                let fresh =
                    r & !i.last_ready != 0 || (generation_now != 0 && generation_now != i.last_gen);
                i.last_ready = r;
                if r == 0 || !fresh {
                    continue;
                }
                i.last_gen = generation_now;
            } else if r == 0 {
                continue;
            }
            if i.events & EPOLLONESHOT != 0 {
                i.disarmed = true;
            }
            out.push((r, i.data));
        }
        out
    }

    /// Whether some entry is ready (for polling the epoll itself).
    fn any_ready(&self) -> bool {
        let snapshot: Vec<(Arc<File>, u32)> = self
            .items
            .lock()
            .iter()
            .filter(|i| !i.disarmed)
            .filter_map(|i| i.file.upgrade().map(|f| (f, i.events)))
            .collect();
        snapshot.iter().any(|(f, e)| readiness(f, *e) != 0)
    }
}

impl Inode for Epoll {
    anon_inode!("[eventpoll]");

    fn poll(&self) -> u16 {
        if self.any_ready() { poll::POLLIN } else { 0 }
    }
}

// ---------------------------------------------------------------- inotify

/// inotify event bits (linux/inotify.h).
pub mod in_mask {
    pub const IN_ACCESS: u32 = 0x1;
    pub const IN_MODIFY: u32 = 0x2;
    pub const IN_ATTRIB: u32 = 0x4;
    pub const IN_CLOSE_WRITE: u32 = 0x8;
    pub const IN_CLOSE_NOWRITE: u32 = 0x10;
    pub const IN_OPEN: u32 = 0x20;
    pub const IN_MOVED_FROM: u32 = 0x40;
    pub const IN_MOVED_TO: u32 = 0x80;
    pub const IN_CREATE: u32 = 0x100;
    pub const IN_DELETE: u32 = 0x200;
    pub const IN_DELETE_SELF: u32 = 0x400;
    pub const IN_MOVE_SELF: u32 = 0x800;
    pub const IN_Q_OVERFLOW: u32 = 0x4000;
    pub const IN_IGNORED: u32 = 0x8000;
    pub const IN_ONLYDIR: u32 = 0x0100_0000;
    pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;
    pub const IN_EXCL_UNLINK: u32 = 0x0400_0000;
    pub const IN_MASK_CREATE: u32 = 0x1000_0000;
    pub const IN_MASK_ADD: u32 = 0x2000_0000;
    pub const IN_ISDIR: u32 = 0x4000_0000;
    pub const IN_ONESHOT: u32 = 0x8000_0000;
    pub const IN_ALL_EVENTS: u32 = 0xfff;
}
use in_mask::*;

/// Events an instance queues at most (Linux's max_queued_events).
const INOTIFY_MAX_EVENTS: usize = 16384;

struct Watch {
    wd: i32,
    /// The watched inode, by (device, inode number).
    key: (u64, u64),
    mask: u32,
}

struct InotifyEvent {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: alloc::string::String,
}

impl InotifyEvent {
    /// `struct inotify_event` and its name, NUL-padded to 16 bytes.
    fn len(&self) -> usize {
        16 + Self::name_len(&self.name)
    }
    fn name_len(name: &str) -> usize {
        if name.is_empty() {
            0
        } else {
            (name.len() + 1).next_multiple_of(16)
        }
    }
}

#[derive(Default)]
struct InotifyState {
    watches: Vec<Watch>,
    queue: alloc::collections::VecDeque<InotifyEvent>,
    next_wd: i32,
}

/// `inotify_init1`: watches on files and directories; events queue up
/// for `read`, which returns whole `struct inotify_event`s.
pub struct Inotify {
    ino: u64,
    state: SpinLock<InotifyState>,
    wait: WaitQueue,
    generation: AtomicU64,
}

/// Every live instance, and how many watches they have in all (the file
/// system calls skip the work while there are none).
static INSTANCES: SpinLock<Vec<Weak<Inotify>>> = SpinLock::new(Vec::new());
static WATCHES: AtomicU64 = AtomicU64::new(0);

impl Inotify {
    pub fn create() -> Arc<dyn Inode> {
        let me = Arc::new(Self {
            ino: new_ino(),
            state: SpinLock::new(InotifyState {
                next_wd: 1,
                ..Default::default()
            }),
            wait: WaitQueue::new(),
            generation: AtomicU64::new(0),
        });
        let mut all = INSTANCES.lock();
        all.retain(|w| w.strong_count() > 0);
        all.push(Arc::downgrade(&me));
        me
    }

    /// `inotify_add_watch` on `target`: returns the watch descriptor.
    pub fn add_watch(&self, target: &Arc<dyn Inode>, mask: u32) -> KResult<i32> {
        if mask & IN_MASK_ADD != 0 && mask & IN_MASK_CREATE != 0 {
            return Err(Errno::EINVAL);
        }
        if mask & IN_ALL_EVENTS == 0 {
            return Err(Errno::EINVAL);
        }
        if mask & IN_ONLYDIR != 0 && target.file_type() != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        let key = (target.dev(), target.ino());
        let keep = mask & (IN_ALL_EVENTS | IN_EXCL_UNLINK | IN_ONESHOT);
        let mut st = self.state.lock();
        if let Some(w) = st.watches.iter_mut().find(|w| w.key == key) {
            if mask & IN_MASK_CREATE != 0 {
                return Err(Errno::EEXIST);
            }
            w.mask = if mask & IN_MASK_ADD != 0 {
                w.mask | keep
            } else {
                keep
            };
            return Ok(w.wd);
        }
        let wd = st.next_wd;
        st.next_wd += 1;
        st.watches.push(Watch {
            wd,
            key,
            mask: keep,
        });
        WATCHES.fetch_add(1, Ordering::Relaxed);
        Ok(wd)
    }

    /// `inotify_rm_watch`: the watch goes, with an IN_IGNORED event.
    pub fn rm_watch(&self, wd: i32) -> KResult<()> {
        let mut st = self.state.lock();
        let i = st
            .watches
            .iter()
            .position(|w| w.wd == wd)
            .ok_or(Errno::EINVAL)?;
        st.watches.remove(i);
        WATCHES.fetch_sub(1, Ordering::Relaxed);
        Self::queue(&mut st, wd, IN_IGNORED, 0, "");
        drop(st);
        self.changed();
        Ok(())
    }

    fn queue(st: &mut InotifyState, wd: i32, mask: u32, cookie: u32, name: &str) {
        // An event like the last one queued is merged into it, as Linux does.
        if let Some(last) = st.queue.back()
            && last.wd == wd
            && last.mask == mask
            && last.cookie == cookie
            && last.name == name
        {
            return;
        }
        if st.queue.len() >= INOTIFY_MAX_EVENTS {
            if st.queue.back().is_none_or(|e| e.mask != IN_Q_OVERFLOW) {
                st.queue.push_back(InotifyEvent {
                    wd: -1,
                    mask: IN_Q_OVERFLOW,
                    cookie: 0,
                    name: alloc::string::String::new(),
                });
            }
            return;
        }
        st.queue.push_back(InotifyEvent {
            wd,
            mask,
            cookie,
            name: name.into(),
        });
    }

    /// Queues `mask` for the watch on `key`, if it wants it. `self_gone`:
    /// the watched inode was deleted, which ends the watch.
    fn deliver(&self, key: (u64, u64), mask: u32, cookie: u32, name: &str, self_gone: bool) {
        let mut st = self.state.lock();
        let Some(i) = st.watches.iter().position(|w| w.key == key) else {
            return;
        };
        let (wd, wmask) = (st.watches[i].wd, st.watches[i].mask);
        let mut queued = false;
        if wmask & mask & IN_ALL_EVENTS != 0 {
            Self::queue(&mut st, wd, mask, cookie, name);
            queued = true;
        }
        if self_gone || (queued && wmask & IN_ONESHOT != 0) {
            st.watches.remove(i);
            WATCHES.fetch_sub(1, Ordering::Relaxed);
            Self::queue(&mut st, wd, IN_IGNORED, 0, "");
            queued = true;
        }
        drop(st);
        if queued {
            self.changed();
        }
    }

    fn changed(&self) {
        self.generation.fetch_add(1, Ordering::Release);
        self.wait.wake_all();
        poll_notify();
    }

    fn pending_bytes(&self) -> usize {
        self.state.lock().queue.iter().map(|e| e.len()).sum()
    }
}

/// Reports `mask` about `inode` to the watches on it, and (with `name`)
/// to the watches on the directory `dir` it is in: what the file system
/// calls use. `cookie` ties IN_MOVED_FROM to IN_MOVED_TO. `self_gone`:
/// `inode` was deleted (its watches end).
pub fn notify(
    inode: Option<&Arc<dyn Inode>>,
    dir: Option<(&Arc<dyn Inode>, &str)>,
    mask: u32,
    cookie: u32,
    self_gone: bool,
) {
    if WATCHES.load(Ordering::Relaxed) == 0 {
        return;
    }
    let isdir = inode.is_some_and(|i| i.file_type() == FileType::Directory);
    let mask = if isdir { mask | IN_ISDIR } else { mask };
    let all: Vec<Arc<Inotify>> = INSTANCES
        .lock()
        .iter()
        .filter_map(|w| w.upgrade())
        .collect();
    for ino in all {
        if let Some((d, name)) = dir {
            ino.deliver((d.dev(), d.ino()), mask, cookie, name, false);
        }
        if let Some(i) = inode {
            ino.deliver((i.dev(), i.ino()), mask, cookie, "", self_gone);
        }
    }
}

/// Reports `mask` (IN_CREATE, IN_DELETE, IN_MOVED_*) about the entry
/// `name` of `dir` to the watches on `dir` only.
pub fn notify_entry(dir: &Arc<dyn Inode>, name: &str, is_dir: bool, mask: u32, cookie: u32) {
    if WATCHES.load(Ordering::Relaxed) == 0 {
        return;
    }
    let mask = if is_dir { mask | IN_ISDIR } else { mask };
    let all: Vec<Arc<Inotify>> = INSTANCES
        .lock()
        .iter()
        .filter_map(|w| w.upgrade())
        .collect();
    for ino in all {
        ino.deliver((dir.dev(), dir.ino()), mask, cookie, name, false);
    }
}

/// Whether any inotify watch exists (callers skip finding names if not).
pub fn watching() -> bool {
    WATCHES.load(Ordering::Relaxed) != 0
}

/// A fresh cookie for a rename's pair of events.
pub fn move_cookie() -> u32 {
    static NEXT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

impl Drop for Inotify {
    fn drop(&mut self) {
        let n = self.state.get_mut().watches.len() as u64;
        WATCHES.fetch_sub(n, Ordering::Relaxed);
    }
}

impl Inode for Inotify {
    anon_inode!("inotify");

    fn read_stream(&self, buf: &mut [u8], nonblock: bool) -> KResult<usize> {
        loop {
            {
                let mut st = self.state.lock();
                if let Some(first) = st.queue.front() {
                    if first.len() > buf.len() {
                        return Err(Errno::EINVAL);
                    }
                    let mut at = 0;
                    while let Some(e) = st.queue.front() {
                        let len = e.len();
                        if at + len > buf.len() {
                            break;
                        }
                        let e = st.queue.pop_front().unwrap();
                        let name_len = InotifyEvent::name_len(&e.name);
                        buf[at..at + 4].copy_from_slice(&e.wd.to_le_bytes());
                        buf[at + 4..at + 8].copy_from_slice(&e.mask.to_le_bytes());
                        buf[at + 8..at + 12].copy_from_slice(&e.cookie.to_le_bytes());
                        buf[at + 12..at + 16].copy_from_slice(&(name_len as u32).to_le_bytes());
                        let name = &mut buf[at + 16..at + len];
                        name.fill(0);
                        name[..e.name.len()].copy_from_slice(e.name.as_bytes());
                        at += len;
                    }
                    drop(st);
                    self.changed();
                    return Ok(at);
                }
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            self.wait
                .wait_interruptible(|| !self.state.lock().queue.is_empty())?;
        }
    }

    fn write_stream(&self, _data: &[u8], _nonblock: bool) -> KResult<usize> {
        Err(Errno::EINVAL)
    }

    fn poll(&self) -> u16 {
        if self.state.lock().queue.is_empty() {
            0
        } else {
            poll::POLLIN
        }
    }

    fn poll_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn ioctl(&self, req: u32, arg: u64, mm: &crate::mm::vm::AddressSpace) -> KResult<u64> {
        const FIONREAD: u32 = 0x541b;
        match req {
            FIONREAD => {
                mm.write(arg, &(self.pending_bytes() as i32))?;
                Ok(0)
            }
            _ => Err(Errno::ENOTTY),
        }
    }
}
