//! segkernel: the SegOS kernel.
//!
//! Boot order: serial → logger → CPU tables → memory → screen console →
//! timer and the other CPUs → the initramfs → `/init`, the first program.
//! See docs/plan.md for where this is going.

#![no_std]
#![no_main]
// Phase 0 defines interfaces (user segments, unmap, …) that later phases use.
#![allow(dead_code)]

extern crate alloc;

mod abi;
mod block;
#[macro_use]
mod console;
mod drivers;
mod font;
mod fs;
mod hal;
#[macro_use]
mod klog;
#[cfg(feature = "ktest")]
mod ktest;
mod ktest_hooks;
mod mm;
mod proc;
mod random;
mod sync;
mod syscall;
mod task;
mod time;
mod tty;

use bootinfo::BootInfo;
use core::panic::PanicInfo;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Entry point, jumped to by segboot (our UEFI bootloader) on the bootstrap
/// CPU, interrupts off, on a boot stack. See the `bootinfo` crate.
#[unsafe(no_mangle)]
extern "sysv64" fn kmain(boot: &'static BootInfo) -> ! {
    hal::serial::init();
    kprintln!("SegOS {VERSION}");
    if boot.magic != bootinfo::MAGIC || boot.version != bootinfo::VERSION {
        panic!(
            "not started by segboot (boot protocol {:#x} v{})",
            boot.magic, boot.version
        );
    }

    hal::init();
    info!("cpu: GDT, TSS and IDT loaded");

    mm::init(boot.memory_map(), boot.hhdm_offset);
    info!(
        "kernel: loaded at phys {:#x}, virt {:#x}",
        boot.kernel_phys_base, boot.kernel_virt_base
    );

    // Screen console last: the boot log above is on serial already if
    // anything before this point fails.
    console::init(&boot.framebuffer);
    if boot.framebuffer.address != 0 {
        // The banner is on serial already; the screen starts empty.
        console::print_screen(format_args!("SegOS {VERSION}\n"));
        info!(
            "console: {}x{} framebuffer",
            boot.framebuffer.width, boot.framebuffer.height
        );
    }

    // This CPU's timer and data, the other CPUs, the scheduler.
    hal::apic::init_bsp();
    hal::percpu::init(0, hal::apic::id(), hal::gdt::bsp_tss());
    task::sched::init_cpu();
    hal::smp::start_aps(boot.rsdp);
    // The AP trampoline was the last user of segboot's identity map.
    mm::paging::remove_identity_map();
    hal::acpi::set_rsdp(boot.rsdp);
    // Keyboard and serial input, through the I/O APIC to this CPU.
    drivers::init(boot.rsdp);

    #[cfg(feature = "ktest")]
    task::spawn_named("ktest", move || ktest::run(boot));
    #[cfg(not(feature = "ktest"))]
    task::spawn_named("init", move || kernel_init(boot));

    // The boot context becomes this CPU's idle task.
    task::sched::idle_loop()
}

/// Unpacks the initramfs into the root file system.
fn load_initramfs(boot: &BootInfo) {
    let archive = boot.initramfs();
    if archive.is_empty() {
        warn!("no initramfs: there is no program to run");
        return;
    }
    match fs::cpio::unpack(archive) {
        Ok(s) => info!(
            "initramfs: {} files ({} KiB), {} directories, {} links",
            s.files,
            s.bytes / 1024,
            s.dirs,
            s.links
        ),
        Err(e) => error!("initramfs: not a valid newc cpio archive ({e:?})"),
    }
}

/// First kernel thread: fills the root file system and starts `/init`,
/// the first program, as process 1.
#[cfg(not(feature = "ktest"))]
fn kernel_init(boot: &'static BootInfo) {
    let (used, size) = mm::heap::stats();
    info!(
        "ready: {} CPUs, {} MiB free, heap {used}/{size} bytes",
        hal::percpu::count(),
        mm::frame::free_count() * mm::PAGE_SIZE / (1024 * 1024)
    );
    drivers::pci::init();
    drivers::virtio_blk::init();
    drivers::nvme::init();
    drivers::ahci::init();
    block::start_flusher();
    match fs::disk::mount_root() {
        Some(dev) => info!("root: {dev} (ext4, read-only)"),
        None => load_initramfs(boot),
    }
    let started = proc::console_stdio().and_then(|stdio| {
        proc::spawn(
            "/init",
            &["/init"],
            &[
                "HOME=/root",
                "TERM=linux",
                "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
            ],
            stdio,
            true,
        )
    });
    let init = match started {
        Ok(t) => t,
        Err(e) => {
            error!("cannot start /init: {e:?}");
            return;
        }
    };
    info!("started /init (pid 1)");
    init.join();
    let status = init.user().unwrap().process.exit_status().unwrap_or(0);
    if status & 0x7f == 0 {
        info!("/init exited with status {}", (status >> 8) & 0xff);
    } else {
        warn!("/init was killed by signal {}", status & 0x7f);
    }
    info!("init has exited; nothing left to run");
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    hal::x86::disable_interrupts();
    console::print_panic(format_args!("\nKERNEL PANIC: {}\n", info));
    console::print_panic(format_args!(
        "backtrace (llvm-addr2line -e segkernel <addr>):\n"
    ));
    hal::cpu::backtrace(|depth, addr| {
        console::print_panic(format_args!("  #{depth:<2} {addr:#018x}\n"));
    });
    if cfg!(feature = "ktest") {
        hal::cpu::exit_qemu(hal::cpu::QemuExit::Failure);
    }
    hal::cpu::halt_forever()
}
