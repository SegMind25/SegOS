# SegOS: a from-scratch operating system in Rust (plan)

Status: **Phase 5 done**. SegOS boots on UEFI with its own bootloader,
segboot, finds its disks (virtio, NVMe, SATA; interrupt-driven), mounts a
read-write ext4 root from disk, and runs **unmodified, dynamically linked
Linux programs**: Ubuntu's bash, GNU coreutils, Python 3.13 (threads
included) and gcc, which compiles a C program on SegOS that then runs.
Threads, futexes, epoll, eventfd, timerfd and signalfd are in. Ten
conformance tests print byte for byte what they print on Linux; 26 kernel
tests pass in QEMU on 4 CPUs (debug and release); CI types commands into
the shell, bash, python3 and gcc over the serial port. No third-party
crates. Next: Phase 8, desktop applications.

## 1. The goal, stated precisely

"Run every application" decides the whole design. The applications people
use (Steam, Firefox, Chromium, Discord, Blender, LibreOffice, Wine/Proton for
Windows games) exist as **Linux x86-64 binaries**. Nobody will port them to a
new OS. So the new kernel must be **binary-compatible with Linux**: it loads
the same ELF files, answers the same system calls with the same numbers,
structures and error codes, and provides the same `/proc`, `/sys` and `/dev`
files those programs read.

That is the approach of gVisor, Asterinas, Kerla and Maestro, and of
FreeBSD's and Windows' (WSL1) Linux layers. It is the only realistic route
to "every application" for a new kernel.

Windows programs then come for free in the same way they do today: Wine and
Proton are Linux programs.

Non-goals (at least for the first years): running Linux kernel modules,
NVIDIA's proprietary driver, Secure Boot signed by Microsoft, legacy BIOS
boot (every PC since about 2012 has UEFI), 32-bit-only hardware,
architectures other than x86-64 (aarch64 later).

## 2. Architecture

```
 ┌──────────────────────────────────────────────────────────────┐
 │ Unmodified Linux apps: bash, coreutils, Mesa, Firefox, Steam │
 │ Wine/Proton, SegLinux's Rust compositor and shell            │
 ├──────────────────────────────────────────────────────────────┤
 │ glibc / musl (unmodified)                                    │
 ╞══════════════════════ syscall boundary (Linux ABI) ══════════╡
 │ segkernel (Rust, no_std)                                     │
 │  linux-abi: syscall table, errno, struct layouts, ioctls     │
 │  process:  tasks, threads, signals, futex, ptrace, cgroups*  │
 │  mm:       paging, mmap, COW fork, page cache, swap*         │
 │  vfs:      dentries, mounts, ext4, tmpfs, procfs, sysfs, dev │
 │  net:      sockets, unix, TCP/IP (smoltcp first), netlink    │
 │  drivers:  virtio, NVMe, AHCI, xHCI/USB HID, e1000, DRM/KMS  │
 │  sched:    SMP, per-CPU run queues, preemption               │
 ├──────────────────────────────────────────────────────────────┤
 │ segkernel-hal: x86-64 only (the one place for `unsafe` asm)  │
 │  GDT/IDT, APIC/x2APIC, HPET/TSC, ACPI, PCI(e), IOMMU*        │
 ╞══════════════════════════════════════════════════════════════╡
 │ segboot: our own UEFI bootloader (bootinfo protocol)         │
 └──────────────────────────────────────────────────────────────┘
        * later phases
```

Design decisions:

- **Monolithic kernel with a small unsafe core** ("framekernel", as in
  Asterinas). All `unsafe` code lives in `segkernel-hal` and a few audited
  modules; everything else is `#![forbid(unsafe_code)]`. This keeps Linux-like
  performance (no IPC per syscall, which a microkernel would pay on every
  `read()` from a game) while getting most of Rust's safety.
- **Linux ABI is the native ABI**, not an emulation layer. There is no
  second "own" syscall interface to maintain.
- **Drivers expose Linux's userspace interfaces**: DRM/KMS ioctls, evdev
  (`/dev/input/event*`), ALSA. Then Mesa, libinput, PipeWire and SegLinux's
  existing Smithay compositor work without changes.
- **Own bootloader, segboot** (UEFI only). It was Limine during Phases 0
  and 1; segboot replaced it so that every line of code SegOS runs is in
  this repository. It loads the kernel ELF, builds the first page tables,
  passes a memory map, the framebuffer and the ACPI RSDP in a small
  `BootInfo` structure (the `bootinfo` crate), and jumps to the kernel. The
  kernel starts the other CPUs itself from the ACPI MADT.
- **No third-party crates.** The kernel, segboot and xtask depend only on
  Rust's `core`, `alloc` and `std` (xtask). Things a crate would give us
  (x86 structures, page tables, the heap allocator, the console font, the
  FAT32 and GPT writers) are written here, small and fitted to SegOS. A
  crate is only worth adding if writing it would cost months (TCP/IP may
  be one; that is decided in Phase 6).
- **Toolchain**: stable Rust pinned in `rust-toolchain.toml`, built-in target
  `x86_64-unknown-none`, built with `cargo xtask` (build, run in QEMU, test).

## 3. Repository layout (target)

Today the kernel is one `kernel` crate with `hal/`, `mm/`, `task/`,
`proc/`, `fs/` and `syscall/` modules; they move into the crates below as
they grow.

```
Cargo.toml              workspace
rust-toolchain.toml
xtask/                  cargo xtask build|run|test|image; GPT, FAT32, cpio writers
boot/                   segboot, the UEFI bootloader
bootinfo/               the boot protocol shared by segboot and the kernel
kernel/
  hal/                  x86-64: boot entry, interrupts, paging, APIC, ACPI
  mm/                   frame allocator, page tables, VMAs, page cache
  sched/                tasks, SMP scheduler, timers
  vfs/                  VFS + tmpfs, devfs, procfs, sysfs, ext4, fat32
  net/                  socket layer, unix sockets, TCP/IP
  linux-abi/            syscall dispatch, every syscall in its own module
  drivers/              virtio-*, nvme, ahci, xhci, hid, e1000, gpu
  kernel/               the binary that ties it together
userland/
  hello/                the Phase 2 demo, /init today (C, built with musl-gcc)
  init/                 segos-init, PID 1, later
  tests/                syscall conformance tests (run on Linux AND SegOS)
docs/
```

The rootfs is not written from scratch: it uses unmodified binaries
(BusyBox/musl first, then a glibc-based distribution root such as Artix or
Alpine) so every phase is measured against real software.

## 4. Roadmap

Each phase ends with a demo that must work in QEMU and in CI.

| Phase | What gets built | Done when | Rough effort* |
|---|---|---|---|
| 0. Bring-up | Workspace, xtask, own UEFI bootloader (segboot), serial + framebuffer console, GDT/IDT, exceptions, physical frame allocator, kernel heap, paging | Kernel prints "SegOS" in QEMU, panics show a backtrace, CI boots it | 2–4 weeks |
| 1. Multitasking | APIC timer, kernel threads, preemptive scheduler, SMP bring-up, spinlocks/mutexes | 4 CPUs run kernel threads in parallel | 1–2 months |
| 2. First user process | Ring 3, `syscall`/`sysret`, ELF loader, address spaces, initramfs (cpio), tmpfs, ~40 syscalls (`read`, `write`, `mmap`, `brk`, `exit`, …) | A static musl "hello world" built on Linux runs unmodified | 1–2 months |
| 3. A shell | `fork` with copy-on-write, `execve`, `wait4`, pipes, signals, TTY + line discipline, `ioctl(TCGETS…)`, devfs, procfs basics | BusyBox `sh` runs; `ls \| grep \| wc` works | 2–3 months |
| 4. Real storage | PCI, virtio-blk, NVMe, AHCI, page cache, ext4 (read, then write), fat32 for the EFI partition | Boots from a disk with a full rootfs | 2–3 months |
| 5. glibc and dynamic linking | `ld-linux.so`, threads (`clone` flags, TLS, `futex`, `set_robust_list`), `epoll`, `eventfd`, `timerfd`, `signalfd`, `poll/select`, `/proc/self/*` | Unmodified Debian/Artix userland: bash, coreutils, python3, gcc compiling a program | 3–4 months |
| 6. Networking | virtio-net, e1000, TCP/IP (smoltcp, later own), unix sockets incl. `SCM_RIGHTS`, netlink (route, uevent) | `curl https://…` and `ssh` work | 2–3 months |
| 7. Graphics and input | DRM/KMS on virtio-gpu (then simple-framebuffer, then AMD/Intel), evdev, xHCI + USB HID, `memfd`, dma-buf | SegLinux's Rust compositor and shell run unchanged on SegOS | 4–6 months |
| 8. Desktop apps | Sound (virtio-snd, Intel HDA → ALSA interface), `inotify`, `fanotify`, seccomp, namespaces (for Flatpak/Chromium sandbox), `io_uring` subset | Firefox, Chromium, LibreOffice, Discord run | 6+ months |
| 9. Games | Mesa radv/iris on real AMD/Intel GPUs (amdgpu-compatible DRM is the largest single task), `ptrace`, cgroups v2 subset, Wine/Proton | Steam installs; a Proton game runs | 1 year+ |
| 10. Release | Installer (reuse SegLinux Setup's design), updates, real-hardware testing, power management (ACPI S3, cpufreq) | Installable ISO | ongoing |

\* For one or two experienced developers. Honest expectation: a shell in
3–6 months, a desktop with a browser in 2–3 years, Steam games longer. GPU
drivers for real hardware are the hardest part, as they were for every other
new OS.

## 5. How compatibility is measured

- **Syscall conformance suite** (`userland/tests`): small programs whose
  output is recorded on real Linux and compared on SegOS. Plus imported
  suites: LTP (Linux Test Project), gVisor's syscall tests, musl's libc-test.
- **Syscall coverage table** generated from the source: implemented /
  partial / `ENOSYS` for all ~360 x86-64 syscalls, published in `docs/`.
- **Application ladder** run in CI nightly: BusyBox → bash → coreutils →
  python → gcc → curl → weston → SegLinux compositor → Firefox → Steam.
- **`strace` on Linux** to find which syscalls an application needs before
  working on it.

## 6. What SegLinux keeps

Deleting the tree is not throwing it away; the userland pieces come back on
top of SegOS once Phase 7 is reached, because they are Linux programs:

- `seglinux-compositor` (Smithay) and `seglinux-shell` — the desktop.
- `seglinux-installer` / `seglinux-setup` — the installer design.
- `seglinux-pe`, `segrun` — Windows program support via Wine.
- `docs/gaming.md`, tuning knowledge — scheduler and latency targets.

They stay available in git history (`git show fededbe:crates/...`, the
SegLinux 1.0.0 tree) and can be
restored into `userland/` when needed.

## 7. Risks

| Risk | Mitigation |
|---|---|
| Scope is enormous | Strict phase gates; every phase ends in a working demo; never start a phase before the previous one passes CI |
| Linux ABI has many undocumented behaviours | Compare against real Linux with the conformance suite; read Linux source for semantics (not copying code: GPL) |
| GPU drivers | Start with virtio-gpu and simple-framebuffer; AMD first on real hardware because its documentation and Mesa driver are open |
| Licensing | Kernel code original under MIT/Apache-2.0; no code copied from Linux (GPL-2.0); rootfs binaries keep their own licences |
| `unsafe` bugs | Confine to `hal` and audited modules, `#![forbid(unsafe_code)]` elsewhere, Miri for pure logic, KASAN-like checks in debug builds |

## 8. Phase 2, as built

The demo: a static "hello world" built with musl on Linux, copied
unchanged into SegOS's initramfs, runs as `/init` and its output appears on
the console. What it took:

- **Address spaces** (`mm/vm.rs`): a page table per process, sharing the
  kernel half (all its top-level entries are created at boot). Regions
  record what each part of the lower half is; pages are mapped on first
  touch. The kernel copies to and from user memory through the direct map
  after checking the regions, so a bad pointer is `EFAULT`, never a kernel
  fault. PROT_NONE pages are kept present but kernel-only.
- **Ring 3** (`hal/syscall.rs`, `hal/user.rs`): `syscall` entry with
  `swapgs` and a per-thread kernel stack, one `iretq` exit shared with
  interrupts; FS/GS base and `fxsave` state switched with the thread.
- **ELF loader** (`proc/elf.rs`): `ET_EXEC` and static-PIE, the Linux
  initial stack with the auxiliary vector.
- **initramfs**: segboot loads `\boot\initramfs` (newc cpio, written by
  xtask); the kernel unpacks it into tmpfs. `/dev` has null, zero, full,
  random, urandom, tty and console.
- **79 system call numbers** (`syscall/`): files and directories, memory,
  identity, time, limits, signal bookkeeping (delivery is Phase 3).
- **Tests**: 24 in-kernel tests, including hand-made ELF programs that
  fault (SIGSEGV, SIGILL) without hurting the kernel, `/init` with its
  output captured, and `userland/tests/basics.c` (about 90 checks) whose
  output must match what it prints on Linux; xtask checks that on the build
  machine's Linux first.

## 9. Phase 3, as built

The demo: BusyBox `sh` runs and `ls | grep | wc` works. The BusyBox is
Ubuntu's `busybox-static` package (statically linked with glibc), copied
unchanged into the initramfs with a symbolic link per applet. What it took:

- **Copy-on-write `fork`** (`mm/vm.rs`, `mm/frame.rs`): every frame has a
  reference count; `fork` shares all pages read-only with a software COW
  bit, and the first write copies (or, for the last holder, just takes
  the page back). Kernel writes to user memory break COW first.
- **Processes** (`proc/`): a process table, parent and children, zombies
  and `wait4`/`waitid`, orphans handed to init, process groups and
  sessions, `clone` for processes (`fork`, `vfork`, `posix_spawn`'s
  `CLONE_VM | CLONE_VFORK`), `execve` with `#!` scripts. New threads
  start from a saved register frame, so `fork` children, `exec` and
  `/init` share one path into user mode.
- **Signals** (`proc/signal.rs`): delivery on every return to user mode,
  Linux's exact `rt_sigframe` (siginfo, ucontext, FPU state), `rt_sigreturn`,
  SA_RESTART, SA_RESETHAND, SA_NODEFER, alternate stacks, `sigsuspend`,
  default actions including stop and continue (and `WUNTRACED`), faults
  in user mode as SIGSEGV/SIGILL/SIGFPE to the program's handler.
  Blocking waits are interruptible: a signal kicks the sleeper, which
  returns `ERESTARTSYS`, turned into a restart or EINTR on the way out.
- **Files** (`fs/`): symbolic links (followed in lookups, 40 at most),
  canonical paths, `rename`, hard links, `chmod`, timestamps, FIFOs,
  pipes with PIPE_BUF atomicity and SIGPIPE, `poll`/`ppoll`/`select`/
  `pselect6`, `/proc` (`self`, `<pid>/{stat,status,cmdline,comm,exe,cwd,fd}`,
  `meminfo`, `uptime`, `mounts`, `cpuinfo`, `version`, `stat`), one
  `st_dev` per file system.
- **A terminal** (`tty.rs`, `drivers/`, `hal/ioapic.rs`): the I/O APIC
  routes the PS/2 keyboard and serial interrupts; the line discipline
  does canonical editing, echo, raw mode with VMIN/VTIME, `^C`/`^\`/`^Z`
  to the foreground group, termios, window size and the controlling
  terminal. The screen console understands the VT100/ANSI sequences line
  editors and `vi` use.
- **140 system call numbers**, `reboot` (ACPI power off from `\_S5_`, or
  a reset), `sysinfo`, `prctl`, a minimal `futex`.
- **Tests**: `userland/tests/process.c` and `shell.sh` join `basics.c`,
  each checked on Linux by xtask before SegOS runs it; and `cargo xtask
  test` ends by booting SegOS, typing commands into the shell over the
  serial port, checking their output and powering the machine off.

Two bugs found on the way, both now covered by tests: Phase 2's `TCGETS`
wrote 60 bytes (the C library's termios) where the kernel's struct is 36,
which would have corrupted a glibc program's stack; and naming a process
after its resolved executable instead of the path it was started by,
which stops BusyBox (it checks for "exe") from naming its applets.

## 10. Phase 4, as built

The demo: SegOS boots from a disk holding a full root file system. When a
partition has ext4 with `/init` on it, the kernel mounts it on `/` (as
Linux does with `root=`), adds `/dev`, `/proc` and a tmpfs `/tmp`, and
starts `/init` from the disk; the initramfs is only the fallback. `cargo
xtask` builds that disk (GPT, ext4 made by e2fsprogs' `mke2fs` from the
same tree as the initramfs) and every test run boots from it.

- **PCI** (`drivers/pci.rs`): every bus, device and function through the
  configuration ports; BARs sized and mapped uncached into a device
  window; bus mastering. (ECAM and MSI-X come with interrupt-driven I/O.)
- **Drivers**, polled, one request at a time, data through bounce pages:
  **virtio-blk** (virtio 1.x over PCI), **NVMe** (admin and one I/O queue
  pair, PRP lists, 512-byte and 4 KiB LBA namespaces), **AHCI** (SATA,
  READ/WRITE DMA EXT, FLUSH CACHE EXT).
- **Block layer** (`block/`): one interface for disks and partitions,
  `/dev` nodes with Linux's device numbers (`vda1`, `nvme0n1p1`, `sda1`),
  **GPT** partitions, and a **write-back block cache** under every disk
  (4 KiB blocks, LRU, merged writes), flushed by `sync`, `fsync`,
  `umount`, power-off and every 5 seconds.
- **File systems**: **ext2/3/4** (`fs/ext4/`): extents, indirect maps,
  64-bit, flex_bg, meta_bg, htree directories read linearly, inline
  data, fast and slow symlinks, devices and FIFOs; checked file by file
  against 21 `mke2fs` images. And **read-write**: block and inode
  allocation (bitmaps, group and superblock counts, uninitialised
  groups), extent trees grown and split, indirect maps, truncate, hard
  and symbolic links, rename, `chmod`, timestamps, checksums under
  `metadata_csum` or `gdt_csum`, the orphan list, and **jbd2 journal
  replay** at mount. Writes go in place with the journal kept empty, and
  leave a file system Linux's `e2fsck -fn` passes. A file system with a
  feature the writer does not handle mounts read-only. **FAT12/16/32**
  (`fs/fat.rs`), read-write with long names, checked with `fsck.fat` and
  `mtools`.
- **Mounts** (`fs/mount.rs`): a mount table crossed by path lookup in
  both directions, `mount` (tmpfs, proc, devtmpfs, ext2/3/4, vfat, bind,
  `--move`, read-only remount), `umount2`, `/proc/mounts`, `statfs`/`df`
  from the mounted file system, EXDEV across file systems, EROFS and
  EEXIST as Linux orders them.
- **Page cache** (`fs/pagecache.rs`): real **`MAP_SHARED`** file mappings.
  Pages are shared by every mapping, `read` and `write`, kept shared by
  `fork`, and written back on `msync`, `munmap`, `fsync`, `sync` and by
  the periodic flush. Shared anonymous memory is shared across `fork`.
- **Tests**: `userland/tests/mapping.c` (shared mappings, fork, msync,
  coherence), recorded on Linux like the others; the kernel tests and the
  serial-port shell session now run on the ext4 root.

## 11. Phase 5, as built

The demo: Ubuntu's own bash, coreutils, Python and gcc, dynamically
linked against glibc and unmodified, run on SegOS from its ext4 root; gcc
compiles and links a program there, and it runs. `cargo xtask` copies the
packages (and every library `ldd` finds) from the build machine onto the
root disk; they are guest software on the test disk, not part of SegOS.

- **Dynamic linking** (`proc/elf.rs`, `proc/exec.rs`): the program's
  `PT_INTERP` (`ld-linux-x86-64.so.2`) is loaded below the mmap area and
  started with `AT_BASE`/`AT_ENTRY`/`AT_PHDR`; glibc's loader does the rest.
- **Threads** (`proc/`): a process is a thread group; `clone` with
  `CLONE_THREAD` and the flags glibc and musl pass, TLS, set/clear tid,
  robust lists, `exit` per thread and `exit_group`, `execve` from a
  threaded process, process- and thread-directed signals (`tgkill`),
  `rt_sigtimedwait`, `/proc/<pid>/task`.
- **futex** (`proc/futex.rs`): wait/wake with exact counts, bitsets,
  requeue, WAKE_OP, absolute and relative timeouts, shared futexes keyed
  by physical page (PI later).
- **Event descriptors** (`fs/event.rs`): epoll (level, edge, one-shot,
  nested), eventfd, timerfd, signalfd, and inotify descriptors that never
  report (yet).
- **Interrupt-driven disks** (`drivers/msi.rs`): virtio-blk and NVMe
  complete through MSI-X; waiting threads sleep. Python starts in 1.4 s
  instead of 3.3 s.
- **Smaller**: `statx`, extended-attribute calls answering as a file
  system without attributes, sockets refused as on a Linux without
  networking, a minimal `/sys` (CPU counts), `getcpu`.
- **Tests**: `userland/tests/threads.c` (86 checks) and `events.c` (129),
  recorded on Linux; the shell session runs bash, GNU `seq`, python3 (an
  8-thread pool) and gcc.

## 12. Phase 6, as built

The demo: on SegOS, Ubuntu's `curl` downloads over HTTPS from a server on
another machine (certificate verified, 4 MiB with a matching md5) and
`ssh` logs in to it with a key and runs a command. In CI the other
machine is the build machine: `cargo xtask test` starts a Python HTTPS
server and an unprivileged sshd there, which SegOS reaches through QEMU's
user network (10.0.2.2, `segos-host` in `/etc/hosts`).

- **virtio-net** (`drivers/virtio_net.rs`): receive and transmit
  virtqueues, a page per frame, no offloads; received frames raise MSI-X.
- **The stack** (`net/`), written for SegOS: interfaces `lo` and `ethN`,
  Ethernet and ARP (queueing until the answer), routing (subnet, default
  gateway, local addresses through loopback), IPv4 without fragments,
  ICMP (echo replies; raw and ping sockets), UDP, and TCP: three-way
  handshake both ways, listen backlog, retransmission with back-off,
  flow control with 64 KiB windows, zero-window probes, half-close,
  RST, TIME_WAIT. A network thread runs input and the timers.
- **DHCP** client at boot; `/proc/net/pnp` lists the DNS servers and
  `/etc/resolv.conf` links to it, as with Linux's kernel autoconfig.
- **Sockets**: AF_INET stream, datagram and ICMP; options (`SO_ERROR`
  for non-blocking connect, `TCP_NODELAY`, `SO_REUSEADDR`, ...);
  `SIOCGIF*` ioctls; NETLINK_ROUTE dumps of links, addresses and routes,
  and changes to them (`ip addr add`, `ip route add default`, `ip link
  set up`); `sendmmsg`/`recvmmsg` for glibc's resolver; `/proc/net/dev`,
  `route`, `tcp`.
- **Smaller**: `close_range`, `alarm`/`setitimer`/`getitimer` (ping's
  interval timer).
- **Tests**: `userland/tests/inet.c` (TCP and UDP over loopback, 63
  checks, recorded on Linux); the shell session checks DHCP, `ping`,
  `curl` over HTTPS and `ssh`.

Not yet: IPv6, IP fragments, window scaling and SACK, congestion
control, an e1000 driver for real PCs.

## 13. Phase 7, as built

The demo: Ubuntu's unmodified weston 13 (DRM backend, pixman renderer)
runs on SegOS with kiosk and desktop shells; `weston-simple-shm` draws in
it; keyboard and mouse work through libinput. `cargo xtask test` checks
it on QEMU's screen (QMP screendumps): the client's picture, Esc
reaching the client, and the console back after weston exits.

- **DRM/KMS** (`drm.rs`), as Linux's simpledrm: `/dev/dri/card0` on the
  firmware framebuffer, one CRTC, primary plane, encoder and connector;
  dumb buffers mapped with `mmap`, ADDFB/ADDFB2, SETCRTC, PAGE_FLIP with
  events, DIRTYFB. The console steps aside while a program shows a
  picture. `userland/drm/drmtest.c` checks it pixel by pixel.
- **Input** (`input.rs`): evdev `/dev/input/event0` (keyboard, Linux key
  codes) and `event1` (a new PS/2 mouse driver with wheel), the evdev
  ioctls, EVIOCGRAB; terminal KD/VT ioctls (graphics mode, keyboard off).
- **What weston, libudev and libinput needed**: `/sys` laid out as udev
  expects (class and dev links, `uevent`, `subsystem`), the udev database
  in `/run/udev/data`, tmpfs on `/run`, `memfd_create` with seals,
  `mremap` (grow, shrink, move; wl_shm pools), `flock`, `fallocate`,
  `O_PATH` on symbolic links, `statx` mount ids, SYSFS_MAGIC.

Not yet: GPU acceleration (virtio-gpu, then AMD/Intel), atomic KMS,
hardware cursors, USB (xHCI) keyboards and mice, dma-buf.

## 14. Next concrete steps (Phase 8: desktop applications)

The demo: Firefox and Chromium run on the Wayland desktop.

1. **GPU**: virtio-gpu with 3D (virgl) or a Mesa software path (llvmpipe)
   over shared memory; atomic KMS.
2. **What browsers need**: seccomp-BPF, `inotify`, user, PID, network and
   mount namespaces, `/dev/shm`, fontconfig, a D-Bus session bus, `chroot`
   and CLONE_FS (all done, below).

   *Done so far.* Firefox renders a page headless (a screenshot), and
   the shell session has a step that runs it on weston (it runs where
   Firefox can be downloaded). **User and PID namespaces**
   (`proc/ns.rs`): `clone` and `unshare` with CLONE_NEWUSER and
   CLONE_NEWPID; `/proc/<pid>/uid_map`, `gid_map` and `setgroups`, with
   Linux's rules for who may write what, from inside or from the parent;
   ids, file owners, `chown` and the setuid family as the namespace sees
   them (65534 when unmapped); `/proc/<pid>/ns/{user,pid,pid_for_children}`.
   A PID namespace numbers its processes and threads from 1; its init
   reaps its orphans, ignores default-action signals (but SIGKILL and
   SIGSTOP from above), and takes the namespace with it when it exits
   (then `fork` there is ENOMEM). getpid, getppid, gettid, wait,
   kill/tkill/tgkill, process groups and sessions, SIGCHLD and the
   `set_tid_address`/`CLONE_*SETTID` values are translated.
   `userland/tests/namespaces.c` prints the same on Linux, as root or
   not, and on SegOS. **Mount namespaces** (`proc/ns.rs`, `fs/mount.rs`):
   `clone` and `unshare` with CLONE_NEWNS give the caller a private copy
   of the mount table, so mounts and unmounts there do not affect other
   namespaces (CLONE_NEWNS with CLONE_FS or CLONE_THREAD is EINVAL, as on
   Linux); `/proc/<pid>/ns/mnt`, the caller's `/proc/mounts` and
   `/proc/<pid>/mounts` show the right table. `tests/namespaces` mounts a
   tmpfs in one namespace and checks it is invisible in the parent's. Not
   yet: UTS, IPC and cgroup namespaces (EINVAL), `setns`, `/proc` mounted
   per PID namespace, capabilities (everything is root). **`/dev/shm`**, **fontconfig**
   and **D-Bus**: the shell session creates POSIX shared memory from
   Python, `fc-match` finds DejaVu Sans, and `dbus-run-session` starts
   Ubuntu's `dbus-daemon`, which answers `dbus-send`. **Network
   namespaces** (CLONE_NEWNET): AF_INET there reaches nothing
   (ENETUNREACH), abstract AF_UNIX names are the namespace's own.
   **`chroot`** and **CLONE_FS** (root, working directory and umask
   shared), and `/proc/<pid>/fdinfo`, whose lookups fail with ESRCH once
   the process is gone: Chromium's way to chroot its sandbox into an
   empty directory, which `tests/namespaces` repeats.
3. **Sound** (done): an Intel HD Audio driver (`drivers/hda.rs`:
   CORB/RIRB, codecs set up for playback, one output stream with a
   buffer descriptor list) behind Linux's ALSA interface (`sound.rs`:
   `/dev/snd/controlC0` and `pcmC0D0p`; hw_params refinement,
   sw_params, prepare/start/drain/drop, WRITEI_FRAMES, status, SYNC_PTR,
   poll). Ubuntu's `aplay` plays through libasound unchanged; QEMU
   records the card's output and `cargo xtask test` measures the 440 Hz
   tone in it. Not yet: capture, mmap transfers, mixer controls,
   interrupts (the position is followed by a kernel thread), dmix (no
   SysV shared memory).
4. **USB**: xHCI with HID keyboards and mice, for real PCs.
