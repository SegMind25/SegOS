//! `/proc`: generated files describing the system and its processes, in
//! Linux's formats (programs such as `ps`, `free` and `uptime` parse them).
//!
//! Files are generated afresh on every read, so they always describe the
//! present. `/proc/self` points at the reading process; BusyBox runs its
//! applets by executing `/proc/self/exe`.

use super::{FileType, Inode, path_of};
use crate::abi::{Errno, KResult};
use crate::proc::{self, Process, RunState};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::Ordering;

/// Inode numbers: fixed per object, so `stat` and `getcwd` see the same
/// inode every time.
const INO_BASE: u64 = 0xf000_0000_0000_0000;

fn ino_of(pid: u32, item: u64) -> u64 {
    INO_BASE | (pid as u64) << 16 | item
}

type Gen = Box<dyn Fn() -> Vec<u8> + Send + Sync>;

/// A read-only file whose contents `gen` produces.
struct GenFile {
    ino: u64,
    generate: Gen,
    parent: Weak<dyn Inode>,
}

impl Inode for GenFile {
    fn file_type(&self) -> FileType {
        FileType::Regular
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn dev(&self) -> u64 {
        super::DEV_PROC
    }
    fn perm(&self) -> u32 {
        0o444
    }
    fn parent(&self) -> Option<Arc<dyn Inode>> {
        self.parent.upgrade()
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = (self.generate)();
        let off = (off as usize).min(data.len());
        let n = buf.len().min(data.len() - off);
        buf[..n].copy_from_slice(&data[off..off + n]);
        Ok(n)
    }
    fn write_at(&self, _off: u64, _data: &[u8]) -> KResult<usize> {
        Err(Errno::EACCES)
    }
    fn truncate(&self, _len: u64) -> KResult<()> {
        Err(Errno::EACCES)
    }
}

/// A symbolic link whose target `target` computes.
struct Link {
    ino: u64,
    target: Box<dyn Fn() -> KResult<String> + Send + Sync>,
    /// For `/proc/<pid>/fd/<n>`: the open file itself, which a lookup
    /// through the link reaches whatever its name (a memfd, a deleted
    /// file), as Linux's "magic links" do.
    inode: Option<Arc<dyn Inode>>,
}

impl Inode for Link {
    fn file_type(&self) -> FileType {
        FileType::Symlink
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn dev(&self) -> u64 {
        super::DEV_PROC
    }
    fn perm(&self) -> u32 {
        0o777
    }
    fn readlink(&self) -> KResult<String> {
        (self.target)()
    }
    fn magic_target(&self) -> Option<Arc<dyn Inode>> {
        self.inode.clone()
    }
}

type Entries = Vec<(String, Arc<dyn Inode>)>;
type Lister = Box<dyn Fn(&Arc<dyn Inode>) -> Entries + Send + Sync>;

/// A directory whose entries `list` produces (given the directory itself).
struct GenDir {
    ino: u64,
    parent: Weak<dyn Inode>,
    me: Weak<GenDir>,
    list: Lister,
}

impl GenDir {
    fn create(
        ino: u64,
        parent: Weak<dyn Inode>,
        list: impl Fn(&Arc<dyn Inode>) -> Vec<(String, Arc<dyn Inode>)> + Send + Sync + 'static,
    ) -> Arc<dyn Inode> {
        Arc::new_cyclic(|me: &Weak<GenDir>| GenDir {
            ino,
            parent,
            me: me.clone(),
            list: Box::new(list),
        })
    }

    fn me(&self) -> Arc<dyn Inode> {
        self.me.upgrade().unwrap()
    }
}

impl Inode for GenDir {
    fn file_type(&self) -> FileType {
        FileType::Directory
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn dev(&self) -> u64 {
        super::DEV_PROC
    }
    fn perm(&self) -> u32 {
        0o555
    }
    fn parent(&self) -> Option<Arc<dyn Inode>> {
        self.parent.upgrade()
    }
    fn lookup(&self, name: &str) -> KResult<Arc<dyn Inode>> {
        (self.list)(&self.me())
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, i)| i)
            .ok_or(Errno::ENOENT)
    }
    fn entries(&self) -> KResult<Vec<(String, Arc<dyn Inode>)>> {
        Ok((self.list)(&self.me()))
    }
    fn create(&self, _name: &str, _ty: FileType, _perm: u32) -> KResult<Arc<dyn Inode>> {
        Err(Errno::EACCES)
    }
    fn remove(&self, _name: &str, _dir: bool) -> KResult<()> {
        Err(Errno::EACCES)
    }
    fn writable_dir(&self) -> bool {
        false
    }
}

fn file(
    ino: u64,
    parent: &Arc<dyn Inode>,
    generate: impl Fn() -> String + Send + Sync + 'static,
) -> Arc<dyn Inode> {
    Arc::new(GenFile {
        ino,
        generate: Box::new(move || generate().into_bytes()),
        parent: Arc::downgrade(parent),
    })
}

fn link(ino: u64, target: impl Fn() -> KResult<String> + Send + Sync + 'static) -> Arc<dyn Inode> {
    Arc::new(Link {
        ino,
        target: Box::new(target),
        inode: None,
    })
}

/// `/proc`, a child of `root`.
pub fn root(root: &Arc<dyn Inode>) -> Arc<dyn Inode> {
    GenDir::create(INO_BASE | 1, Arc::downgrade(root), |me| {
        let mut v: Vec<(String, Arc<dyn Inode>)> = alloc::vec![
            (
                "self".into(),
                link(INO_BASE | 2, || {
                    let t = crate::task::current();
                    t.user()
                        .map(|u| u.process.pid.to_string())
                        .ok_or(Errno::ENOENT)
                })
            ),
            ("meminfo".into(), file(INO_BASE | 3, me, meminfo)),
            ("uptime".into(), file(INO_BASE | 4, me, uptime)),
            ("loadavg".into(), file(INO_BASE | 5, me, loadavg)),
            ("mounts".into(), file(INO_BASE | 6, me, mounts)),
            ("cpuinfo".into(), file(INO_BASE | 7, me, cpuinfo)),
            ("version".into(), file(INO_BASE | 8, me, version)),
            (
                "filesystems".into(),
                file(INO_BASE | 9, me, || {
                    "nodev\ttmpfs\nnodev\tproc\nnodev\tdevtmpfs\n".into()
                })
            ),
            ("stat".into(), file(INO_BASE | 10, me, stat)),
            ("cmdline".into(), file(INO_BASE | 11, me, || "\n".into())),
            (
                "net".into(),
                GenDir::create(INO_BASE | 12, Arc::downgrade(me), |net| {
                    alloc::vec![
                        (
                            "dev".into(),
                            file(INO_BASE | 13, net, crate::net::iface::proc_dev)
                        ),
                        (
                            "route".into(),
                            file(INO_BASE | 14, net, crate::net::iface::proc_route)
                        ),
                        (
                            "tcp".into(),
                            file(INO_BASE | 15, net, crate::net::tcp::proc_tcp)
                        ),
                        (
                            "pnp".into(),
                            file(INO_BASE | 16, net, crate::net::iface::proc_pnp)
                        ),
                    ]
                })
            ),
        ];
        for p in proc::all() {
            let pid = p.pid;
            v.push((pid.to_string(), pid_dir(pid, me)));
        }
        v
    })
}

fn meminfo() -> String {
    let total = crate::mm::frame::total_count() * 4;
    let free = crate::mm::frame::free_count() * 4;
    format!(
        "MemTotal:       {total:8} kB\nMemFree:        {free:8} kB\nMemAvailable:   {free:8} kB\n\
         Buffers:               0 kB\nCached:                0 kB\nSwapCached:            0 kB\n\
         Active:                0 kB\nInactive:              0 kB\nSwapTotal:             0 kB\n\
         SwapFree:              0 kB\nShmem:                 0 kB\n"
    )
}

fn uptime() -> String {
    let ms = crate::time::monotonic_ns() / 1_000_000;
    let idle = ms * crate::hal::percpu::count() as u64;
    format!(
        "{}.{:02} {}.{:02}\n",
        ms / 1000,
        ms % 1000 / 10,
        idle / 1000,
        idle % 1000 / 10
    )
}

fn loadavg() -> String {
    let all = proc::all();
    let last = all.last().map_or(0, |p| p.pid);
    format!("0.00 0.00 0.00 1/{} {last}\n", all.len())
}

fn mounts() -> String {
    let mounts = super::mount::all();
    let mut s = String::new();
    if !mounts.iter().any(|m| m.path == "/") {
        s.push_str("rootfs / rootfs rw 0 0\nproc /proc proc rw,nosuid,nodev,noexec 0 0\n");
    }
    for m in mounts {
        s.push_str(&format!(
            "{} {} {} {} 0 0\n",
            m.source,
            m.path,
            m.fstype,
            if m.read_only { "ro" } else { "rw" }
        ));
    }
    s
}

fn version() -> String {
    format!(
        "Linux version 6.6.0-segos-{v} (SegOS {v}, a kernel written in Rust that speaks Linux) #1 SegOS {v}\n",
        v = crate::VERSION
    )
}

fn cpu_brand() -> String {
    let mut b = Vec::new();
    for leaf in 0x8000_0002u32..=0x8000_0004 {
        let (a, bx, c, d) = crate::hal::x86::cpuid(leaf, 0);
        for r in [a, bx, c, d] {
            b.extend_from_slice(&r.to_le_bytes());
        }
    }
    String::from_utf8_lossy(&b)
        .trim_matches(char::from(0))
        .trim()
        .to_string()
}

fn cpuinfo() -> String {
    let (_, b, c, d) = crate::hal::x86::cpuid(0, 0);
    let mut vendor = Vec::new();
    for r in [b, d, c] {
        vendor.extend_from_slice(&r.to_le_bytes());
    }
    let vendor = String::from_utf8_lossy(&vendor).into_owned();
    let mhz = crate::time::tsc_hz() / 1_000_000;
    let mut s = String::new();
    for cpu in 0..crate::hal::percpu::count() {
        let _ = write!(
            s,
            "processor\t: {cpu}\nvendor_id\t: {vendor}\nmodel name\t: {}\ncpu MHz\t\t: {mhz}.000\n\
             cpu cores\t: {}\nflags\t\t: fpu tsc msr pae cx8 apic sep cmov pat clflush mmx fxsr sse sse2 syscall nx lm\n\n",
            cpu_brand(),
            crate::hal::percpu::count()
        );
    }
    s
}

fn stat() -> String {
    let jiffies = crate::time::monotonic_ns() / 10_000_000;
    let boot = (crate::time::realtime_ns() - crate::time::monotonic_ns()) / crate::time::NS_PER_SEC;
    let mut s = format!("cpu  0 0 0 {jiffies} 0 0 0 0 0 0\n");
    for cpu in 0..crate::hal::percpu::count() {
        let _ = writeln!(s, "cpu{cpu} 0 0 0 {jiffies} 0 0 0 0 0 0");
    }
    let _ = write!(
        s,
        "intr 0\nctxt 0\nbtime {boot}\nprocesses {}\nprocs_running 1\nprocs_blocked 0\n",
        proc::all().len()
    );
    s
}

fn process(pid: u32) -> KResult<Arc<Process>> {
    proc::lookup(pid).ok_or(Errno::ESRCH)
}

fn state_char(p: &Process) -> char {
    match p.state() {
        RunState::Zombie(_) => 'Z',
        RunState::Stopped { .. } => 'T',
        RunState::Running => match p.thread().map(|t| t.state()) {
            Some(crate::task::State::Running) | Some(crate::task::State::Ready) => 'R',
            _ => 'S',
        },
    }
}

fn pid_stat(p: &Process) -> String {
    let start = p.start_ns / 10_000_000;
    let tty = if p.has_ctty.load(Ordering::Relaxed) {
        0x501
    } else {
        0
    };
    let vsize: u64 = p
        .thread()
        .and_then(|t| t.user().map(|u| u.mm()))
        .map_or(0, |mm| mm.regions().iter().map(|v| v.end - v.start).sum());
    format!(
        "{} ({}) {} {} {} {} {tty} -1 4194304 0 0 0 0 0 0 0 0 20 0 {threads} 0 {start} {vsize} 0 \
         18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        p.pid,
        p.name.lock().as_str(),
        state_char(p),
        p.ppid.load(Ordering::Relaxed),
        p.pgid(),
        p.sid(),
        threads = p.thread_count().max(1),
    )
}

fn pid_status(p: &Process) -> String {
    let state = match state_char(p) {
        'R' => "R (running)",
        'T' => "T (stopped)",
        'Z' => "Z (zombie)",
        _ => "S (sleeping)",
    };
    // The main (oldest) thread's restrictions.
    let (nnp, seccomp) = p
        .threads()
        .first()
        .and_then(|t| {
            t.user().map(|u| {
                (
                    u.no_new_privs.load(Ordering::Relaxed) as u32,
                    u.seccomp_mode.load(Ordering::Relaxed),
                )
            })
        })
        .unwrap_or((0, 0));
    format!(
        "Name:\t{}\nUmask:\t{:04o}\nState:\t{state}\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{}\n\
         Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nThreads:\t{}\n\
         NoNewPrivs:\t{nnp}\nSeccomp:\t{seccomp}\n",
        p.name.lock().as_str(),
        p.umask.load(Ordering::Relaxed),
        p.ppid.load(Ordering::Relaxed),
        p.thread_count().max(1),
        pid = p.pid,
    )
}

/// `/proc/<pid>/maps`: the address space's regions, as Linux prints them.
fn pid_maps(p: &Process) -> String {
    use crate::abi::mman::{PROT_EXEC, PROT_READ, PROT_WRITE};
    use crate::mm::vm::Kind;
    let Some(mm) = p.threads().iter().find_map(|t| t.user().map(|u| u.mm())) else {
        return String::new();
    };
    let mut out = String::new();
    for v in mm.regions() {
        let bit = |b: u32, c: char| if v.prot & b != 0 { c } else { '-' };
        let (off, ino, name) = match (&v.file, v.kind) {
            (Some((f, off)), _) => (
                *off,
                f.ino(),
                v.path.as_deref().map(String::from).unwrap_or_default(),
            ),
            (None, Kind::Heap) => (0, 0, "[heap]".into()),
            (None, Kind::Stack) => (0, 0, "[stack]".into()),
            _ => (0, 0, String::new()),
        };
        let line = format!(
            "{:08x}-{:08x} {}{}{}{} {off:08x} 00:00 {ino}",
            v.start,
            v.end,
            bit(PROT_READ, 'r'),
            bit(PROT_WRITE, 'w'),
            bit(PROT_EXEC, 'x'),
            if v.kind == Kind::Shared { 's' } else { 'p' },
        );
        if name.is_empty() {
            out.push_str(&line);
        } else {
            out.push_str(&format!("{line:<72} {name}"));
        }
        out.push('\n');
    }
    out
}

/// What `/proc/<pid>/fd/<n>` points to.
fn fd_target(f: &super::File) -> String {
    if let Some(name) = f.inode.anon_name() {
        return format!("anon_inode:{name}");
    }
    match f.inode.file_type() {
        FileType::Fifo => format!("pipe:[{}]", f.inode.ino()),
        FileType::CharDevice => {
            let rdev = f.inode.rdev();
            match rdev {
                0x501 => "/dev/console".into(),
                0x500 => "/dev/tty".into(),
                0x103 => "/dev/null".into(),
                _ => format!("/dev/char/{}:{}", (rdev >> 8) & 0xfff, rdev & 0xff),
            }
        }
        _ => f
            .path()
            .map(|p| String::from(&*p))
            .unwrap_or_else(|| path_of(&f.inode)),
    }
}

fn pid_dir(pid: u32, parent: &Arc<dyn Inode>) -> Arc<dyn Inode> {
    GenDir::create(ino_of(pid, 1), Arc::downgrade(parent), move |me| {
        let with =
            |f: fn(&Process) -> String| move || process(pid).map(|p| f(&p)).unwrap_or_default();
        alloc::vec![
            ("stat".into(), file(ino_of(pid, 2), me, with(pid_stat))),
            ("status".into(), file(ino_of(pid, 3), me, with(pid_status))),
            (
                "cmdline".into(),
                file(
                    ino_of(pid, 4),
                    me,
                    with(|p| {
                        let mut s = String::new();
                        for a in p.cmdline.lock().iter() {
                            s.push_str(a);
                            s.push('\0');
                        }
                        s
                    })
                )
            ),
            (
                "comm".into(),
                file(
                    ino_of(pid, 5),
                    me,
                    with(|p| format!("{}\n", p.name.lock().as_str()))
                )
            ),
            (
                "exe".into(),
                link(ino_of(pid, 6), move || Ok(process(pid)?.exe.lock().clone()))
            ),
            (
                "cwd".into(),
                link(ino_of(pid, 7), move || Ok(path_of(
                    &process(pid)?.cwd.lock().clone()
                )))
            ),
            ("fd".into(), fd_dir(pid, me)),
            ("task".into(), task_dir(pid, me)),
            ("maps".into(), file(ino_of(pid, 0x10), me, with(pid_maps))),
        ]
    })
}

/// The tids of `p`'s live threads.
fn tids(p: &Process) -> Vec<u32> {
    p.threads()
        .iter()
        .filter_map(|t| t.user().map(|u| u.tid))
        .collect()
}

/// `/proc/<pid>/task`: a directory per thread.
fn task_dir(pid: u32, parent: &Arc<dyn Inode>) -> Arc<dyn Inode> {
    GenDir::create(ino_of(pid, 9), Arc::downgrade(parent), move |me| {
        let Ok(p) = process(pid) else {
            return Vec::new();
        };
        tids(&p)
            .into_iter()
            .map(|tid| (tid.to_string(), thread_dir(pid, tid, me)))
            .collect()
    })
}

/// `/proc/<pid>/task/<tid>`: the thread's stat, status and comm (the
/// process's, with the thread's id).
fn thread_dir(pid: u32, tid: u32, parent: &Arc<dyn Inode>) -> Arc<dyn Inode> {
    GenDir::create(ino_of(tid, 10), Arc::downgrade(parent), move |me| {
        let alive = move || {
            process(pid)
                .ok()
                .filter(|p| tids(p).contains(&tid) || tid == pid)
        };
        let replace_pid = move |text: String| {
            // The first field of stat, and the Pid: line of status.
            if let Some(rest) = text.strip_prefix(&format!("{pid} (")) {
                format!("{tid} ({rest}")
            } else {
                text.replace(&format!("\nPid:\t{pid}\n"), &format!("\nPid:\t{tid}\n"))
            }
        };
        alloc::vec![
            (
                "stat".into(),
                file(ino_of(tid, 11), me, move || alive()
                    .map(|p| replace_pid(pid_stat(&p)))
                    .unwrap_or_default())
            ),
            (
                "status".into(),
                file(ino_of(tid, 12), me, move || alive()
                    .map(|p| replace_pid(pid_status(&p)))
                    .unwrap_or_default())
            ),
            (
                "syscall".into(),
                file(ino_of(tid, 14), me, move || {
                    let Some(t) = crate::proc::find_thread(tid) else {
                        return String::new();
                    };
                    let Some(u) = t.user() else {
                        return String::new();
                    };
                    let v: Vec<u64> = u.syscall.iter().map(|s| s.load(Ordering::Relaxed)).collect();
                    // Linux: "running" in user mode, else the number and
                    // arguments.
                    if v[0] == 0 {
                        "running\n".into()
                    } else {
                        format!("{} {:#x} {:#x} {:#x}\n", v[0] - 1, v[1], v[2], v[3])
                    }
                })
            ),
            (
                "comm".into(),
                file(ino_of(tid, 13), me, move || alive()
                    .map(|p| {
                        let own = crate::proc::find_thread(tid)
                            .and_then(|t| t.user().and_then(|u| u.comm.lock().clone()));
                        format!("{}\n", own.unwrap_or_else(|| p.name.lock().clone()))
                    })
                    .unwrap_or_default())
            ),
        ]
    })
}

fn fd_dir(pid: u32, parent: &Arc<dyn Inode>) -> Arc<dyn Inode> {
    GenDir::create(ino_of(pid, 8), Arc::downgrade(parent), move |_| {
        let Ok(p) = process(pid) else {
            return Vec::new();
        };
        let fds = p.files.lock().list();
        fds.into_iter()
            .map(|(fd, f)| {
                let target = fd_target(&f);
                let l: Arc<dyn Inode> = Arc::new(Link {
                    ino: ino_of(pid, 0x100 + fd as u64),
                    target: Box::new(move || Ok(target.clone())),
                    inode: Some(f.inode.clone()),
                });
                (fd.to_string(), l)
            })
            .collect()
    })
}
