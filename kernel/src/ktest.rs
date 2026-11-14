//! In-kernel tests: `cargo xtask test` boots the kernel with the `ktest`
//! feature in QEMU; it runs these and exits QEMU with a success/failure code.
//! A failing test panics, and the panic handler reports failure.

use crate::abi::mman::{PROT_READ, PROT_WRITE};
use crate::abi::{Errno, open};
use crate::fs::{self, FileType};
use crate::hal::cpu::{QemuExit, exit_qemu};
use crate::mm;
use crate::mm::vm::{AddressSpace, Kind};
use crate::{hal::percpu, proc, sync::Mutex, task, time};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bootinfo::BootInfo;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const TESTS: &[(&str, fn())] = &[
    ("breakpoint exception returns", breakpoint_returns),
    ("frames: alloc, zeroed, free", frames_alloc_free),
    ("frames: distinct", frames_distinct),
    ("paging: map, translate, unmap", paging_map_unmap),
    ("heap: Box and String", heap_box_string),
    ("heap: large Vec grows the heap", heap_grows),
    ("heap: many small allocations are reused", heap_reuse),
    ("timer: uptime advances while sleeping", timer_advances),
    ("smp: every CPU is online and ticking", smp_online),
    ("sched: threads run on several CPUs", threads_spread),
    (
        "sched: more spinning threads than CPUs (preemption)",
        preemption,
    ),
    (
        "sync: Mutex keeps an exact count under contention",
        mutex_count,
    ),
    (
        "sched: 200 short threads start, exit and are freed",
        thread_churn,
    ),
    ("time: TSC clock is monotonic and calibrated", tsc_clock),
    ("vm: regions, demand paging, mprotect, munmap", vm_regions),
    (
        "vm: user copies fault in pages and reject bad ranges",
        vm_copies,
    ),
    ("fs: tmpfs create, write, read, remove", tmpfs_basics),
    ("fs: path lookup and normalisation", path_lookup),
    ("fs: the initramfs is unpacked", initramfs_present),
    (
        "user: raw exit_group(42) from a hand-made ELF",
        user_exit_code,
    ),
    ("user: a null write is SIGSEGV, ud2 is SIGILL", user_faults),
    (
        "user: /init (musl hello world) prints and exits 0",
        user_hello,
    ),
    (
        "user: conformance tests print what Linux printed",
        user_conformance,
    ),
    (
        "user: a process's memory is freed when it exits",
        user_memory_freed,
    ),
];

pub fn run(boot: &'static BootInfo) -> ! {
    crate::load_initramfs(boot);
    kprintln!("running {} kernel tests", TESTS.len());
    for (name, test) in TESTS {
        crate::console::print(format_args!("test {name} ... "));
        test();
        kprintln!("ok");
    }
    kprintln!("all {} tests passed", TESTS.len());
    exit_qemu(QemuExit::Success)
}

fn breakpoint_returns() {
    let before = crate::ktest_hooks::breakpoints();
    crate::hal::x86::breakpoint();
    assert_eq!(crate::ktest_hooks::breakpoints(), before + 1);
}

fn frames_alloc_free() {
    let free = mm::frame::free_count();
    let phys = mm::frame::alloc_zeroed().expect("out of frames");
    assert_eq!(phys % mm::PAGE_SIZE, 0);
    let page = unsafe { core::slice::from_raw_parts(mm::phys_to_virt(phys), 4096) };
    assert!(page.iter().all(|&b| b == 0));
    assert_eq!(mm::frame::free_count(), free - 1);
    mm::frame::free(phys);
    assert_eq!(mm::frame::free_count(), free);
}

fn frames_distinct() {
    let frames: Vec<u64> = (0..64)
        .map(|_| mm::frame::alloc_zeroed().unwrap())
        .collect();
    let mut sorted = frames.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), frames.len());
    frames.into_iter().for_each(mm::frame::free);
}

fn paging_map_unmap() {
    const VIRT: u64 = 0xffff_d000_0000_0000;
    let free = mm::frame::free_count();
    mm::paging::map_new(VIRT, 1).unwrap();
    assert!(mm::paging::translate(VIRT).is_some());
    unsafe {
        (VIRT as *mut u64).write_volatile(0x5e605);
        assert_eq!((VIRT as *const u64).read_volatile(), 0x5e605);
    }
    assert!(matches!(
        mm::paging::map_new(VIRT, 1),
        Err(mm::paging::MapError::AlreadyMapped)
    ));
    mm::paging::unmap(VIRT);
    assert!(mm::paging::translate(VIRT).is_none());
    // Intermediate page tables stay allocated; only the data frame returns.
    assert!(mm::frame::free_count() >= free - 3);
}

fn heap_box_string() {
    let b = Box::new(41u64);
    assert_eq!(*b + 1, 42);
    let mut s = String::from("Seg");
    s.push_str("OS");
    assert_eq!(s, "SegOS");
}

fn heap_grows() {
    let (_, before) = mm::heap::stats();
    let v: Vec<u8> = alloc::vec![7; 8 << 20]; // 8 MiB > initial 4 MiB heap
    assert!(v.iter().all(|&b| b == 7));
    let (_, after) = mm::heap::stats();
    assert!(after > before);
}

fn heap_reuse() {
    let (used_before, _) = mm::heap::stats();
    for i in 0..10_000u64 {
        let b = Box::new(i);
        assert_eq!(*b, i);
    }
    assert_eq!(mm::heap::stats().0, used_before);
}

fn timer_advances() {
    let start = time::uptime_ms();
    time::sleep_ms(100);
    let elapsed = time::uptime_ms() - start;
    assert!(elapsed >= 100, "slept {elapsed} ms");
}

fn smp_online() {
    let expected = crate::hal::smp::cpu_count_from_acpi();
    assert_eq!(percpu::count(), expected);
    let before = percpu::ticks();
    time::sleep_ms(50);
    for ((cpu, a), (_, b)) in before.iter().zip(percpu::ticks()) {
        assert!(b > *a, "CPU {cpu} timer is not ticking");
    }
}

fn threads_spread() {
    let cpus_seen = Arc::new(AtomicU64::new(0));
    let threads: Vec<_> = (0..percpu::count() * 4)
        .map(|_| {
            let seen = cpus_seen.clone();
            task::spawn(move || {
                for _ in 0..20 {
                    seen.fetch_or(1 << percpu::this_cpu().index, Ordering::Relaxed);
                    spin_for_ms(2);
                }
            })
        })
        .collect();
    threads.iter().for_each(|t| t.join());
    let used = cpus_seen.load(Ordering::Relaxed).count_ones() as usize;
    if percpu::count() > 1 {
        assert!(used > 1, "all threads ran on one CPU");
    }
}

/// n spinning threads, more than CPUs, each waiting (without yielding) until
/// all have started: only possible if the timer preempts them.
fn preemption() {
    let n = percpu::count() + 2;
    let started = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..n)
        .map(|_| {
            let started = started.clone();
            task::spawn(move || {
                started.fetch_add(1, Ordering::SeqCst);
                while started.load(Ordering::SeqCst) < n {
                    core::hint::spin_loop();
                }
            })
        })
        .collect();
    threads.iter().for_each(|t| t.join());
    assert_eq!(started.load(Ordering::SeqCst), n);
}

fn mutex_count() {
    const THREADS: u64 = 8;
    const ROUNDS: u64 = 500;
    let counter = Arc::new(Mutex::new(0u64));
    let threads: Vec<_> = (0..THREADS)
        .map(|_| {
            let counter = counter.clone();
            task::spawn(move || {
                for i in 0..ROUNDS {
                    let mut c = counter.lock();
                    let v = *c;
                    if i % 50 == 0 {
                        task::yield_now(); // hold the lock across a switch
                    }
                    *c = v + 1;
                }
            })
        })
        .collect();
    threads.iter().for_each(|t| t.join());
    assert_eq!(*counter.lock(), THREADS * ROUNDS);
}

fn thread_churn() {
    let free = mm::frame::free_count();
    let done = Arc::new(AtomicUsize::new(0));
    for _ in 0..10 {
        let batch: Vec<_> = (0..20)
            .map(|_| {
                let done = done.clone();
                task::spawn(move || {
                    done.fetch_add(1, Ordering::Relaxed);
                })
            })
            .collect();
        batch.iter().for_each(|t| t.join());
    }
    assert_eq!(done.load(Ordering::Relaxed), 200);
    // Let other CPUs finish switching away from the last ones.
    time::sleep_ms(20);
    // Stacks (16 frames each) are returned; page-table pages may remain.
    let lost = free.saturating_sub(mm::frame::free_count());
    assert!(lost < 64, "{lost} frames not returned");
}

fn spin_for_ms(ms: u64) {
    let until = time::uptime_ms() + ms;
    while time::uptime_ms() < until {
        core::hint::spin_loop();
    }
}

fn tsc_clock() {
    assert!(time::tsc_hz() > 1_000_000, "TSC not calibrated");
    let a = time::monotonic_ns();
    time::sleep_ms(30);
    let b = time::monotonic_ns();
    let ms = (b - a) / 1_000_000;
    assert!((30..1000).contains(&ms), "slept 30 ms, clock says {ms} ms");
    // The RTC said something after 2023.
    assert!(time::realtime_ns() / time::NS_PER_SEC > 1_700_000_000);
}

fn vm_regions() {
    let free = mm::frame::free_count();
    {
        let mm = AddressSpace::new().unwrap();
        mm.map(0x40_0000, 0x4000, PROT_READ | PROT_WRITE, Kind::Anon, false)
            .unwrap();
        assert_eq!(
            mm.map(0x40_1000, 0x1000, PROT_READ, Kind::Anon, false),
            Err(Errno::EEXIST)
        );
        // Nothing is mapped until touched.
        assert!(mm::paging::user_entry(mm.pml4(), 0x40_0000).is_none());
        assert!(mm.handle_fault(0x40_0123, true, false));
        assert!(mm::paging::user_entry(mm.pml4(), 0x40_0000).is_some());
        assert!(
            !mm.handle_fault(0x50_0000, false, false),
            "outside every region"
        );
        assert!(!mm.handle_fault(0x40_0000, false, true), "not executable");
        // Split by mprotect: the middle page becomes read-only.
        mm.protect(0x40_1000, 0x1000, PROT_READ).unwrap();
        assert_eq!(mm.regions().len(), 3);
        assert!(!mm.handle_fault(0x40_1000, true, false));
        assert!(mm.handle_fault(0x40_1000, false, false));
        // munmap the middle; the outer pages stay.
        mm.unmap(0x40_1000, 0x1000).unwrap();
        assert_eq!(mm.regions().len(), 2);
        assert!(!mm.handle_fault(0x40_1000, false, false));
        assert!(mm.handle_fault(0x40_3fff, true, false));
        assert_eq!(mm.find_free(0x1000).unwrap() + 0x1000, mm::vm::MMAP_END);
        // brk grows a heap region and shrinks it again.
        mm.init_brk(0x60_0000);
        assert_eq!(mm.brk(0x60_2000), 0x60_2000);
        assert!(mm.handle_fault(0x60_1000, true, false));
        assert_eq!(mm.brk(0x60_0000), 0x60_0000);
        assert!(!mm.handle_fault(0x60_1000, false, false));
        assert_eq!(mm.brk(0x10), 0x60_0000, "below the start: unchanged");
    }
    // Every page and table of the address space is freed with it.
    assert_eq!(mm::frame::free_count(), free);
}

fn vm_copies() {
    let mm = AddressSpace::new().unwrap();
    mm.map(0x40_0000, 0x3000, PROT_READ | PROT_WRITE, Kind::Anon, false)
        .unwrap();
    mm.map(0x50_0000, 0x1000, PROT_READ, Kind::Anon, false)
        .unwrap();
    // Across a page boundary.
    let data: Vec<u8> = (0..6000u32).map(|i| i as u8).collect();
    mm.copy_to(0x40_0f00, &data).unwrap();
    let mut back = alloc::vec![0u8; 6000];
    mm.copy_from(0x40_0f00, &mut back).unwrap();
    assert_eq!(back, data);
    assert_eq!(mm.copy_to(0x50_0000, b"x"), Err(Errno::EFAULT), "read-only");
    assert_eq!(mm.copy_to(0x3f_ffff, b"xy"), Err(Errno::EFAULT), "unmapped");
    let mut b = [0u8; 8];
    assert_eq!(mm.copy_from(u64::MAX - 3, &mut b), Err(Errno::EFAULT));
    assert_eq!(
        mm.copy_from(0xffff_8000_0000_0000, &mut b),
        Err(Errno::EFAULT)
    );
    mm.copy_to(0x40_2ffa, b"hello\0").unwrap();
    assert_eq!(mm.read_cstr(0x40_2ffa, 100).unwrap(), "hello");
    mm.copy_to(0x40_2ff0, &[b'a'; 16]).unwrap();
    assert!(mm.read_cstr(0x40_2ff0, 100).is_err(), "runs off the region");
}

fn tmpfs_basics() {
    let dir = fs::tmpfs::Dir::new_root(0o755);
    let f = dir.create("f", FileType::Regular, 0o644).unwrap();
    assert_eq!(f.write_at(3, b"abc").unwrap(), 3);
    assert_eq!(f.size(), 6);
    let mut buf = [9u8; 8];
    assert_eq!(f.read_at(0, &mut buf).unwrap(), 6);
    assert_eq!(&buf[..6], b"\0\0\0abc");
    assert_eq!(f.read_at(100, &mut buf).unwrap(), 0);
    f.truncate(2).unwrap();
    assert_eq!(f.size(), 2);
    assert!(matches!(
        dir.create("f", FileType::Regular, 0o644),
        Err(Errno::EEXIST)
    ));
    let sub = dir.create("sub", FileType::Directory, 0o755).unwrap();
    sub.create("x", FileType::Regular, 0o600).unwrap();
    assert_eq!(dir.remove("sub", true), Err(Errno::ENOTEMPTY));
    assert_eq!(dir.remove("f", true), Err(Errno::ENOTDIR));
    assert_eq!(dir.remove("sub", false), Err(Errno::EISDIR));
    sub.remove("x", false).unwrap();
    dir.remove("sub", true).unwrap();
    assert_eq!(dir.entries().unwrap().len(), 1);
    assert_eq!(sub.parent().unwrap().ino(), dir.ino());
}

fn path_lookup() {
    let root = fs::root();
    let dev = fs::lookup(&root, "/dev").unwrap();
    assert_eq!(dev.file_type(), FileType::Directory);
    let null = fs::lookup(&dev, "../dev/./null").unwrap();
    assert_eq!(null.file_type(), FileType::CharDevice);
    assert_eq!(null.rdev(), 0x103, "makedev(1, 3)");
    assert_eq!(fs::lookup(&root, "/dev/null/").err(), Some(Errno::ENOTDIR));
    assert_eq!(fs::lookup(&root, "/nope").err(), Some(Errno::ENOENT));
    assert_eq!(fs::lookup(&root, "").err(), Some(Errno::ENOENT));
    assert_eq!(fs::lookup(&root, "/..").unwrap().ino(), root.ino());
    let (d, name) = fs::lookup_parent(&root, "/dev//console/").unwrap();
    assert_eq!((d.ino(), name.as_str()), (dev.ino(), "console"));
    assert_eq!(fs::normalize("/a/b", "../c/./d//"), "/a/c/d");
    assert_eq!(fs::normalize("/a", "/x/.."), "/");
    assert_eq!(fs::normalize("/", "../../.."), "/");
}

fn initramfs_present() {
    let init = fs::lookup(&fs::root(), "/init").expect("no /init in the initramfs");
    assert_eq!(init.file_type(), FileType::Regular);
    assert_eq!(init.perm() & 0o111, 0o111);
    let mut magic = [0u8; 4];
    init.read_at(0, &mut magic).unwrap();
    assert_eq!(&magic, b"\x7fELF");
    assert!(fs::lookup(&fs::root(), "/tests").is_ok());
}

/// A minimal static ELF executable around `code`, loaded at 0x400000.
fn tiny_elf(code: &[u8]) -> Vec<u8> {
    const BASE: u64 = 0x40_0000;
    let total = (64 + 56 + code.len()) as u64;
    let mut e = Vec::new();
    e.extend_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
    e.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    e.extend_from_slice(&62u16.to_le_bytes()); // x86-64
    e.extend_from_slice(&1u32.to_le_bytes());
    e.extend_from_slice(&(BASE + 120).to_le_bytes()); // entry
    e.extend_from_slice(&64u64.to_le_bytes()); // phoff
    e.extend_from_slice(&0u64.to_le_bytes()); // shoff
    e.extend_from_slice(&0u32.to_le_bytes());
    for v in [64u16, 56, 1, 0, 0, 0] {
        e.extend_from_slice(&v.to_le_bytes());
    }
    e.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    e.extend_from_slice(&5u32.to_le_bytes()); // R X
    for v in [0, BASE, BASE, total, total, 0x1000] {
        e.extend_from_slice(&v.to_le_bytes());
    }
    e.extend_from_slice(code);
    e
}

/// Runs `path` with stdout and stderr captured; returns (wait status,
/// output).
fn run_captured(path: &str, argv: &[&str]) -> (i32, Vec<u8>) {
    let root = fs::root();
    let tmp = fs::lookup(&root, "/tmp").unwrap();
    let name = alloc::format!("ktest-{}.out", NEXT_CAPTURE.fetch_add(1, Ordering::Relaxed));
    let out = tmp.create(&name, FileType::Regular, 0o600).unwrap();
    let null = fs::lookup(&root, "/dev/null").unwrap();
    let stdin = fs::File::new(null, open::O_RDONLY);
    let stdout = fs::File::new(out.clone(), open::O_WRONLY);
    let t = proc::spawn(
        path,
        argv,
        &["HOME=/", "PATH=/bin"],
        [stdin, stdout.clone(), stdout],
    )
    .unwrap_or_else(|e| panic!("cannot start {path}: {e:?}"));
    t.join();
    let status = t.user().unwrap().process.exit_status().unwrap();
    let mut data = alloc::vec![0u8; out.size() as usize];
    out.read_at(0, &mut data).unwrap();
    tmp.remove(&name, false).unwrap();
    (status, data)
}

static NEXT_CAPTURE: AtomicUsize = AtomicUsize::new(0);

fn install(path: &str, bytes: &[u8]) {
    let (dir, name) = fs::lookup_parent(&fs::root(), path).unwrap();
    let _ = dir.remove(&name, false);
    let f = dir.create(&name, FileType::Regular, 0o755).unwrap();
    f.write_at(0, bytes).unwrap();
}

fn user_exit_code() {
    // mov edi, 42; mov eax, 231 (exit_group); syscall
    install(
        "/tmp/exit42",
        &tiny_elf(&[0xbf, 42, 0, 0, 0, 0xb8, 231, 0, 0, 0, 0x0f, 0x05]),
    );
    let (status, out) = run_captured("/tmp/exit42", &["exit42"]);
    assert_eq!(status, 42 << 8);
    assert!(out.is_empty());
}

fn user_faults() {
    // mov qword ptr [0], 1
    install(
        "/tmp/nullwrite",
        &tiny_elf(&[0x48, 0xc7, 0x04, 0x25, 0, 0, 0, 0, 1, 0, 0, 0]),
    );
    assert_eq!(run_captured("/tmp/nullwrite", &["nullwrite"]).0, 11);
    install("/tmp/ud2", &tiny_elf(&[0x0f, 0x0b]));
    assert_eq!(run_captured("/tmp/ud2", &["ud2"]).0, 4);
}

fn user_hello() {
    let (status, out) = run_captured("/init", &["/init"]);
    assert_eq!(String::from_utf8_lossy(&out), "Hello, world!\n");
    assert_eq!(status, 0);
}

fn user_conformance() {
    let tests = fs::lookup(&fs::root(), "/tests").unwrap();
    let mut ran = 0;
    for (name, inode) in tests.entries().unwrap() {
        if name.ends_with(".expected") || inode.file_type() != FileType::Regular {
            continue;
        }
        let expected = fs::lookup(&tests, &alloc::format!("{name}.expected"))
            .unwrap_or_else(|_| panic!("/tests/{name} has no .expected"));
        let mut want = alloc::vec![0u8; expected.size() as usize];
        expected.read_at(0, &mut want).unwrap();
        let path = alloc::format!("/tests/{name}");
        let (status, got) = run_captured(&path, &[&path]);
        if got != want {
            let (g, w) = (
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(&want),
            );
            for (i, (a, b)) in g.lines().zip(w.lines()).enumerate() {
                if a != b {
                    kprintln!(
                        "\n  line {}: got      {a}\n  line {}: expected {b}",
                        i + 1,
                        i + 1
                    );
                }
            }
            panic!(
                "{path}: output differs from Linux ({} lines, expected {})",
                g.lines().count(),
                w.lines().count()
            );
        }
        assert_eq!(status, 0, "{path} exit status");
        ran += 1;
    }
    assert!(ran > 0, "no conformance tests in /tests");
}

fn user_memory_freed() {
    // Warm up (heap growth, capture file names), then measure.
    run_captured("/init", &["/init"]);
    time::sleep_ms(20);
    let free = mm::frame::free_count();
    for _ in 0..5 {
        assert_eq!(run_captured("/init", &["/init"]).0, 0);
    }
    time::sleep_ms(20);
    let lost = free.saturating_sub(mm::frame::free_count());
    // Kernel stacks' page tables may stay; process memory must not.
    assert!(lost < 16, "{lost} frames not returned after 5 runs");
}
