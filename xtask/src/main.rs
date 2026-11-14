//! `cargo xtask`: builds segboot, the kernel and the userland programs,
//! writes a bootable GPT disk image, runs it in QEMU.
//!
//! Only the Rust standard library is used: the GPT, FAT32 and cpio writers
//! are in `gpt.rs`, `fat.rs` and `cpio.rs`. The userland programs are
//! ordinary Linux programs, built with musl-gcc exactly as a Linux user
//! would build them. Running needs qemu-system-x86_64 and OVMF.

mod cpio;
mod fat;
mod gpt;
mod userland;

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

const USAGE: &str = "\
usage: cargo xtask <command> [options]

commands:
  build     build segboot and the kernel
  image     build and write a bootable disk image (target/segos.img)
  run       build the image and boot it in QEMU (serial on this terminal)
  test      check the userland tests on this Linux machine, boot the kernel
            test suite in QEMU, then boot SegOS and type commands into its
            shell over the serial port; fail if anything fails

options:
  --release        optimised build
  --headless       no QEMU window (run)
  --kernel <ELF>   put this kernel in the image instead of building segkernel

environment:
  OVMF      path to OVMF.fd (default /usr/share/ovmf/OVMF.fd)
  MUSL_GCC  the musl C compiler (default musl-gcc)
  BUSYBOX   a statically linked x86-64 busybox (default: Ubuntu's
            busybox-static, downloaded with apt-get into target/busybox)

The image is a GPT disk with one FAT32 EFI system partition holding
segboot, the kernel and the initramfs (userland/ built with musl); write it
to a USB stick with e.g. `dd if=target/segos.img of=/dev/sdX bs=4M`.
";

/// isa-debug-exit maps the kernel's success code 0x10 to (0x10 << 1) | 1.
const QEMU_TEST_SUCCESS: i32 = 33;
const TEST_TIMEOUT: Duration = Duration::from_secs(300);

/// Disk layout: 1 MiB before the ESP (GPT, alignment), 64 MiB ESP, 1 MiB
/// after it (backup GPT).
const ESP_FIRST_LBA: u64 = 2048;
const ESP_SECTORS: u64 = 64 * 1024 * 1024 / gpt::SECTOR;
const DISK_SECTORS: u64 = ESP_FIRST_LBA + ESP_SECTORS + 2048;

struct Opts {
    release: bool,
    headless: bool,
    kernel: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let result = parse_opts(&args[1..]).and_then(|opts| match cmd.as_str() {
        "build" => build_all(&opts, false).map(|_| ()),
        "image" => image(&opts, false).map(|img| println!("{}", img.display())),
        "run" => image(&opts, false).and_then(|img| run(&img, &opts)),
        "test" => userland::build()
            .and_then(|u| userland::check_on_host(&u))
            .and_then(|()| image(&opts, true))
            .and_then(|img| test(&img))
            .and_then(|()| image(&opts, false))
            .and_then(|img| shell_session(&img)),
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut opts = Opts {
        release: false,
        headless: false,
        kernel: None,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--release" => opts.release = true,
            "--headless" => opts.headless = true,
            "--kernel" => {
                let p = it.next().ok_or("--kernel needs a path")?;
                opts.kernel = Some(PathBuf::from(p));
            }
            other => return Err(format!("unknown option `{other}`\n\n{USAGE}")),
        }
    }
    Ok(opts)
}

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn status(cmd: &mut Command) -> Result<(), String> {
    let s = cmd
        .status()
        .map_err(|e| format!("cannot run {:?}: {e}", cmd.get_program()))?;
    if s.success() {
        Ok(())
    } else {
        Err(format!("{cmd:?} failed: {s}"))
    }
}

fn cargo() -> Command {
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.current_dir(root());
    cmd
}

fn profile(opts: &Opts) -> &'static str {
    if opts.release { "release" } else { "debug" }
}

fn build_bootloader(opts: &Opts) -> Result<PathBuf, String> {
    let mut cmd = cargo();
    cmd.args([
        "build",
        "--package",
        "segboot",
        "--target",
        "x86_64-unknown-uefi",
    ]);
    if opts.release {
        cmd.arg("--release");
    }
    status(&mut cmd)?;
    Ok(root()
        .join("target/x86_64-unknown-uefi")
        .join(profile(opts))
        .join("segboot.efi"))
}

fn build_kernel(opts: &Opts, ktest: bool) -> Result<PathBuf, String> {
    if let Some(k) = &opts.kernel {
        return Ok(k.clone());
    }
    let mut cmd = cargo();
    cmd.args([
        "build",
        "--package",
        "segkernel",
        "--target",
        "x86_64-unknown-none",
    ]);
    if opts.release {
        cmd.arg("--release");
    }
    if ktest {
        // Separate target dir: switching features must not rebuild the normal kernel.
        cmd.args(["--features", "ktest", "--target-dir", "target/ktest"]);
    }
    status(&mut cmd)?;
    let dir = if ktest { "target/ktest" } else { "target" };
    Ok(root()
        .join(dir)
        .join("x86_64-unknown-none")
        .join(profile(opts))
        .join("segkernel"))
}

/// Builds segboot and the kernel; returns (bootloader, kernel).
fn build_all(opts: &Opts, ktest: bool) -> Result<(PathBuf, PathBuf), String> {
    Ok((build_bootloader(opts)?, build_kernel(opts, ktest)?))
}

fn random_bytes<const N: usize>() -> [u8; N] {
    // RandomState is seeded from the OS's random source.
    let mut out = [0u8; N];
    for chunk in out.chunks_mut(8) {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(0);
        chunk.copy_from_slice(&h.finish().to_le_bytes()[..chunk.len()]);
    }
    out
}

fn read(p: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(p).map_err(|e| format!("cannot read {}: {e}", p.display()))
}

fn image(opts: &Opts, ktest: bool) -> Result<PathBuf, String> {
    let (bootloader, kernel) = build_all(opts, ktest)?;
    let initramfs = userland::initramfs(&userland::build()?)?;
    let files = [
        ("EFI/BOOT/BOOTX64.EFI", read(&bootloader)?),
        ("boot/segkernel", read(&kernel)?),
        ("boot/initramfs", initramfs),
    ];
    let name = if ktest { "segos-test.img" } else { "segos.img" };
    let path = root().join("target").join(name);
    let disk = disk_image(&files)?;
    std::fs::write(&path, disk).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path)
}

/// A GPT disk with one EFI system partition holding `files`.
fn disk_image(files: &[(&str, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let sector = gpt::SECTOR as usize;
    let mut disk = vec![0u8; DISK_SECTORS as usize * sector];
    let esp = ESP_FIRST_LBA as usize * sector..(ESP_FIRST_LBA + ESP_SECTORS) as usize * sector;
    let volume_id = u32::from_le_bytes(random_bytes());
    fat::format(&mut disk[esp], ESP_FIRST_LBA as u32, volume_id, files)?;
    gpt::write(
        &mut disk,
        gpt::random_guid(random_bytes()),
        &[gpt::Partition {
            type_guid: gpt::ESP_TYPE,
            guid: gpt::random_guid(random_bytes()),
            first_lba: ESP_FIRST_LBA,
            last_lba: ESP_FIRST_LBA + ESP_SECTORS - 1,
            name: "EFI System Partition",
        }],
    )?;
    Ok(disk)
}

fn qemu(img: &Path) -> Command {
    let mut cmd = Command::new("qemu-system-x86_64");
    let ovmf = std::env::var("OVMF").unwrap_or_else(|_| "/usr/share/ovmf/OVMF.fd".into());
    cmd.args(["-M", "q35", "-m", "512M", "-smp", "4", "-no-reboot"])
        .args(["-serial", "stdio"])
        .args(["-bios", &ovmf])
        .arg("-drive")
        .arg(format!("format=raw,file={}", img.display()));
    // Usable KVM only: CI runners often have /dev/kvm without permission.
    if std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
    {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    }
    cmd
}

fn run(img: &Path, opts: &Opts) -> Result<(), String> {
    let mut cmd = qemu(img);
    if opts.headless {
        cmd.args(["-display", "none"]);
    }
    status(&mut cmd)
}

fn test(img: &Path) -> Result<(), String> {
    let mut child = qemu(img)
        .args(["-display", "none"])
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
        .spawn()
        .map_err(|e| format!("cannot start QEMU: {e}"))?;
    let start = std::time::Instant::now();
    loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            return match s.code() {
                Some(QEMU_TEST_SUCCESS) => Ok(()),
                code => Err(format!("kernel tests failed (QEMU exit code {code:?})")),
            };
        }
        if start.elapsed() > TEST_TIMEOUT {
            let _ = child.kill();
            return Err(format!("kernel tests timed out after {TEST_TIMEOUT:?}"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Boots the normal image, waits for BusyBox's prompt on the serial port,
/// types commands as a user would and checks what they print, then powers
/// the machine off from the shell.
fn shell_session(img: &Path) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    let mut child = qemu(img)
        .args(["-display", "none"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot start QEMU: {e}"))?;
    let output = Arc::new(Mutex::new(Vec::<u8>::new()));
    let mut stdout = child.stdout.take().unwrap();
    let sink = output.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 {
                break;
            }
            sink.lock().unwrap().extend_from_slice(&buf[..n]);
        }
    });
    let mut stdin = child.stdin.take().unwrap();
    let text = || String::from_utf8_lossy(&output.lock().unwrap()).into_owned();
    let fail = |what: String, child: &mut std::process::Child| {
        let _ = child.kill();
        let log = text();
        let tail: String = log
            .chars()
            .rev()
            .take(3000)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        Err(format!(
            "shell session: {what}\n--- serial output (end) ---\n{tail}"
        ))
    };
    let wait_for = |needle: &str, from: usize, secs: u64| -> Option<usize> {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(secs) {
            let t = text();
            if let Some(i) = t.get(from..).and_then(|s| s.find(needle)) {
                return Some(from + i + needle.len());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        None
    };
    const PROMPT: &str = "root@segos:~# ";
    let Some(mut at) = wait_for(PROMPT, 0, 120) else {
        return fail("no shell prompt within 120 s".into(), &mut child);
    };
    println!("xtask: shell session: prompt after boot");
    // (command, what its output must contain). Expected text never appears
    // in the command itself, so the echo cannot satisfy the check.
    let steps: [(&str, &str); 6] = [
        ("echo SEGOS-$((6 * 7))-OK", "SEGOS-42-OK"),
        (
            "ls /tests | grep expected | wc -l | sed 's/^/COUNT=/'",
            "COUNT=3",
        ),
        ("hello | tr a-z A-Z", "HELLO, WORLD!"),
        ("cat /proc/self/comm | tr a-z A-Z", "CAT"),
        (
            "(sleep 0.2; echo late) & wait; echo JOBS-$?-DONE",
            "JOBS-0-DONE",
        ),
        (
            "cd /tmp && mkdir t && cd t && touch a b && ls | wc -l | sed 's/^/FILES=/'",
            "FILES=2",
        ),
    ];
    for (cmd, want) in steps {
        let _ = stdin.write_all(format!("{cmd}\n").as_bytes());
        let _ = stdin.flush();
        let Some(end) = wait_for(want, at, 30) else {
            return fail(format!("`{cmd}` did not print `{want}`"), &mut child);
        };
        at = end;
        println!("xtask: shell session: `{cmd}` -> {want}");
    }
    let _ = stdin.write_all(b"poweroff -f\n");
    let _ = stdin.flush();
    let start = std::time::Instant::now();
    loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            if s.success() {
                println!("xtask: shell session: `poweroff -f` turned the machine off");
                return Ok(());
            }
            return fail(format!("QEMU ended with {s} after poweroff"), &mut child);
        }
        if start.elapsed() > Duration::from_secs(30) {
            return fail(
                "`poweroff -f` did not turn the machine off".into(),
                &mut child,
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
