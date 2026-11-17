//! `cargo xtask`: builds segboot, the kernel and the userland programs,
//! writes a bootable GPT disk image, runs it in QEMU.
//!
//! Only the Rust standard library is used: the GPT, FAT32 and cpio writers
//! are in `gpt.rs`, `fat.rs` and `cpio.rs`. The userland programs are
//! ordinary Linux programs, built with musl-gcc exactly as a Linux user
//! would build them. Running needs qemu-system-x86_64 and OVMF.

mod cpio;
mod fat;
mod firefox;
mod glibc;
mod gpt;
mod nettest;
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
  SEGOS_REUSE_ROOTFS  keep target/rootfs.img from the last build (kernel work)
  SEGOS_NO_FIREFOX    leave Firefox off the root disk

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
    let u = userland::build()?;
    if std::env::var_os("SEGOS_REUSE_ROOTFS").is_none()
        || !root().join("target/rootfs.img").exists()
    {
        root_disk(&u)?;
    }
    let initramfs = userland::initramfs(&u)?;
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

/// Linux file system data partition type 0FC63DAF-8483-4772-8E79-3D69D8477DE4.
const LINUX_FS_TYPE: [u8; 16] = [
    0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4,
];
const ROOT_FIRST_LBA: u64 = 2048;

/// `target/rootfs.img`: a GPT disk with one ext4 partition holding the full
/// root file system (the same tree as the initramfs). The ext4 is made by
/// e2fsprogs' mke2fs, so SegOS's reader is checked against the real format.
fn root_disk(u: &userland::Userland) -> Result<PathBuf, String> {
    let target = root().join("target");
    let tree = target.join("rootfs");
    userland::tree(u, &tree)?;
    let firefox_libs = firefox::add(&tree)?;
    let copied = glibc::add(&tree, &firefox_libs)?;
    nettest::prepare(&tree)?;
    if copied > 0 {
        eprintln!("xtask: root disk: {copied} files of Ubuntu's glibc userland");
    }
    // Room for the files, ext4's own structures, and some to spare.
    let mib = (glibc::tree_size(&tree) / (1 << 20)) * 5 / 4 + 96;
    let root_sectors = mib * 1024 * 1024 / gpt::SECTOR;
    let part = target.join("rootfs.ext4");
    let _ = std::fs::remove_file(&part);
    status(
        Command::new("mke2fs")
            .args(["-q", "-F", "-t", "ext4", "-L", "segos-root", "-d"])
            .arg(&tree)
            .arg(&part)
            .arg(format!("{}k", root_sectors * gpt::SECTOR / 1024)),
    )?;
    let fs = read(&part)?;
    let sector = gpt::SECTOR as usize;
    let mut disk = vec![0u8; (ROOT_FIRST_LBA + root_sectors + 2048) as usize * sector];
    let start = ROOT_FIRST_LBA as usize * sector;
    disk[start..start + fs.len()].copy_from_slice(&fs);
    gpt::write(
        &mut disk,
        gpt::random_guid(random_bytes()),
        &[gpt::Partition {
            type_guid: LINUX_FS_TYPE,
            guid: gpt::random_guid(random_bytes()),
            first_lba: ROOT_FIRST_LBA,
            last_lba: ROOT_FIRST_LBA + root_sectors - 1,
            name: "SegOS root",
        }],
    )?;
    let path = target.join("rootfs.img");
    std::fs::write(&path, disk).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    let _ = std::fs::remove_file(&part);
    Ok(path)
}

fn qemu(img: &Path) -> Command {
    let mut cmd = Command::new("qemu-system-x86_64");
    let ovmf = std::env::var("OVMF").unwrap_or_else(|_| "/usr/share/ovmf/OVMF.fd".into());
    // No PS/2 controller (as on most new PCs): keys and the mouse come
    // through USB.
    cmd.args(["-M", "q35,i8042=off", "-m", "2G", "-smp", "4", "-no-reboot"])
        .args(["-serial", "stdio"])
        .args(["-bios", &ovmf])
        .arg("-drive")
        .arg(format!("format=raw,file={}", img.display()))
        // A virtio network card on QEMU's user network (NAT; DHCP; the
        // build machine is 10.0.2.2).
        // No option ROM: the firmware would try to boot from the network.
        .args(["-netdev", "user,id=net0"])
        .args(["-device", "virtio-net-pci,netdev=net0,romfile="]);
    // An HD Audio card whose output QEMU records (the shell session
    // checks what `aplay` played).
    let wav = root().join("target/audio.wav");
    let _ = std::fs::remove_file(&wav);
    cmd.arg("-audiodev")
        .arg(format!(
            "wav,id=snd0,path={},out.frequency=48000,out.channels=2,out.format=s16",
            wav.display()
        ))
        .args([
            "-device",
            "ich9-intel-hda",
            "-device",
            "hda-output,audiodev=snd0",
        ]);
    // A USB controller with a keyboard and a mouse (the shell session
    // types on the keyboard through QMP).
    cmd.args(["-device", "qemu-xhci,id=xhci"])
        .args(["-device", "usb-kbd,bus=xhci.0,id=ukbd"])
        .args(["-device", "usb-mouse,bus=xhci.0,id=umouse"]);
    // A QMP socket, for screendumps of what SegOS shows.
    let qmp = qmp_socket();
    let _ = std::fs::remove_file(&qmp);
    cmd.arg("-qmp")
        .arg(format!("unix:{},server,nowait", qmp.display()));
    let rootfs = root().join("target/rootfs.img");
    if rootfs.exists() {
        cmd.arg("-drive")
            .arg(format!(
                "format=raw,if=none,id=root,file={}",
                rootfs.display()
            ))
            .args(["-device", "virtio-blk-pci,drive=root"]);
    }
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

fn qmp_socket() -> PathBuf {
    root().join("target/qmp.sock")
}

/// Runs one QMP command (a JSON object) and waits for its answer.
fn qmp(command: &str) -> Result<(), String> {
    use std::io::{BufRead, BufReader, Write};
    let err = |e: std::io::Error| format!("QMP: {e}");
    let sock = std::os::unix::net::UnixStream::connect(qmp_socket()).map_err(err)?;
    sock.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(err)?;
    let mut w = sock.try_clone().map_err(err)?;
    let mut r = BufReader::new(sock);
    // Reads until the answer to the last command (skipping events).
    let answer = |r: &mut BufReader<std::os::unix::net::UnixStream>| -> Result<String, String> {
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).map_err(err)? == 0 {
                return Err("QMP: QEMU closed the socket".into());
            }
            if line.contains("\"return\"") || line.contains("\"QMP\"") {
                return Ok(line);
            }
            if line.contains("\"error\"") {
                return Err(format!("QMP: {}", line.trim()));
            }
        }
    };
    answer(&mut r)?; // the greeting
    w.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")
        .map_err(err)?;
    answer(&mut r)?;
    w.write_all(format!("{command}\n").as_bytes())
        .map_err(err)?;
    answer(&mut r)?;
    Ok(())
}

/// Asks QEMU over QMP to write what the screen shows to `file` (a PPM).
fn screendump(file: &Path) -> Result<(), String> {
    let _ = std::fs::remove_file(file);
    let path = file
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    qmp(&format!(
        "{{\"execute\":\"screendump\",\"arguments\":{{\"filename\":\"{path}\"}}}}"
    ))
}

/// A binary PPM (P6, maxval 255): (width, height, RGB bytes).
fn parse_ppm(data: &[u8]) -> Result<(usize, usize, &[u8]), String> {
    let mut at = 0;
    let mut fields = Vec::new();
    while fields.len() < 4 {
        while at < data.len() && (data[at].is_ascii_whitespace() || data[at] == b'#') {
            if data[at] == b'#' {
                while at < data.len() && data[at] != b'\n' {
                    at += 1;
                }
            } else {
                at += 1;
            }
        }
        let start = at;
        while at < data.len() && !data[at].is_ascii_whitespace() {
            at += 1;
        }
        if start == at {
            return Err("truncated PPM header".into());
        }
        fields.push(String::from_utf8_lossy(&data[start..at]).into_owned());
    }
    at += 1; // the one whitespace byte before the pixels
    let num = |s: &str| {
        s.parse::<usize>()
            .map_err(|_| format!("bad PPM field `{s}`"))
    };
    if fields[0] != "P6" || num(&fields[3])? != 255 {
        return Err(format!("not a P6 PPM with maxval 255: {fields:?}"));
    }
    let (w, h) = (num(&fields[1])?, num(&fields[2])?);
    let pixels = data
        .get(at..at + w * h * 3)
        .ok_or("PPM shorter than its size")?;
    Ok((w, h, pixels))
}

/// A QMP screendump: (width, height) and the colour at each of `at`
/// (x and y as fractions of the size).
/// The shell session played one second of a 440 Hz tone: QEMU's
/// recording must hold it (about 48000 loud frames whose zero crossings
/// give 440 Hz).
fn check_tone() -> Result<(), String> {
    let data = read(&root().join("target/audio.wav"))?;
    let Some(at) = data.windows(4).position(|w| w == b"data") else {
        return Err("audio.wav: no data chunk".into());
    };
    let samples: Vec<i16> = data[at + 8..]
        .chunks_exact(4)
        .map(|f| i16::from_le_bytes([f[0], f[1]]))
        .collect();
    let loud: Vec<usize> = (0..samples.len())
        .filter(|&i| samples[i].unsigned_abs() > 2000)
        .collect();
    let (Some(&first), Some(&last)) = (loud.first(), loud.last()) else {
        return Err(format!(
            "audio.wav: {} frames, all silent: the tone did not play",
            samples.len()
        ));
    };
    let tone = &samples[first..=last];
    let crossings = tone.windows(2).filter(|w| (w[0] < 0) != (w[1] < 0)).count();
    let secs = tone.len() as f64 / 48000.0;
    let hz = crossings as f64 / 2.0 / secs;
    println!(
        "xtask: sound: QEMU recorded {:.2} s of tone at {hz:.0} Hz ({} frames in all)",
        secs,
        samples.len()
    );
    if !(0.9..=1.1).contains(&secs) || !(430.0..=450.0).contains(&hz) {
        return Err(format!(
            "sound: expected 1 s of 440 Hz, recorded {secs:.2} s at {hz:.0} Hz"
        ));
    }
    Ok(())
}

fn screen(at: &[(f64, f64)]) -> Result<(usize, usize, Vec<&'static str>), String> {
    let file = root().join("target/screen.ppm");
    screendump(&file)?;
    let data = read(&file)?;
    let (w, h, px) = parse_ppm(&data)?;
    let colours = at
        .iter()
        .map(|&(fx, fy)| {
            let (x, y) = ((w as f64 * fx) as usize, (h as f64 * fy) as usize);
            let i = (y * w + x) * 3;
            match [px[i], px[i + 1], px[i + 2]] {
                [r, g, b] if r > 200 && g < 50 && b < 50 => "red",
                [r, g, b] if g > 200 && r < 50 && b < 50 => "green",
                [r, g, b] if b > 200 && r < 50 && g < 50 => "blue",
                _ => "other",
            }
        })
        .collect();
    Ok((w, h, colours))
}

/// A QMP screendump's (width, height), number of distinct colours, and
/// the share of the screen the commonest colour covers.
fn screen_colours() -> Result<(usize, usize, usize, f64), String> {
    let file = root().join("target/screen.ppm");
    screendump(&file)?;
    let data = read(&file)?;
    let (w, h, px) = parse_ppm(&data)?;
    let mut counts = std::collections::HashMap::<[u8; 3], usize>::new();
    for p in px.chunks_exact(3) {
        *counts.entry([p[0], p[1], p[2]]).or_default() += 1;
    }
    let top = counts.values().copied().max().unwrap_or(0);
    Ok((w, h, counts.len(), top as f64 / (w * h).max(1) as f64))
}

/// Types `text` on the keyboard (the machine's only one is USB), key by key.
fn type_usb(text: &str) -> Result<(), String> {
    for c in text.chars() {
        let (key, shift) = match c {
            'a'..='z' | '0'..='9' => (c.to_string(), false),
            'A'..='Z' => (c.to_ascii_lowercase().to_string(), true),
            ' ' => ("spc".into(), false),
            '-' => ("minus".into(), false),
            '\n' => ("ret".into(), false),
            '$' => ("4".into(), true),
            '(' => ("9".into(), true),
            ')' => ("0".into(), true),
            '*' => ("8".into(), true),
            _ => return Err(format!("cannot type {c:?}")),
        };
        let q = |k: &str| format!("{{\"type\":\"qcode\",\"data\":\"{k}\"}}");
        let keys = if shift {
            format!("{},{}", q("shift"), q(&key))
        } else {
            q(&key)
        };
        qmp(&format!(
            "{{\"execute\":\"send-key\",\"arguments\":{{\"keys\":[{keys}]}}}}"
        ))?;
        std::thread::sleep(Duration::from_millis(60));
    }
    Ok(())
}

/// Presses and releases a key (a QEMU "qcode", e.g. "esc") over QMP.
fn send_key(qcode: &str) -> Result<(), String> {
    qmp(&format!(
        "{{\"execute\":\"send-key\",\"arguments\":{{\"keys\":[{{\"type\":\"qcode\",\"data\":\"{qcode}\"}}]}}}}"
    ))
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
    let mut steps: Vec<(&str, &str)> = vec![
        ("echo SEGOS-$((6 * 7))-OK", "SEGOS-42-OK"),
        (
            "ls /tests | grep expected | wc -l | sed 's/^/COUNT=/'",
            "COUNT=10",
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
    // Phase 5: Ubuntu's glibc programs, dynamically linked, unmodified
    // (when the build machine could provide them; see glibc.rs).
    let rootfs = root().join("target/rootfs/usr/bin");
    if rootfs.join("bash").exists() {
        steps.push((
            "bash -c 'a=(x y z); echo \"BASH-${#a[@]}-$((2**10))\"'",
            "BASH-3-1024",
        ));
        // GNU coreutils (BusyBox's applets would answer to bare names).
        steps.push(("/usr/bin/seq -s: 1 3", "1:2:3"));
    }
    if rootfs.join("python3").exists() {
        steps.push((
            "python3 -c 'import json; print(\"PY-\" + json.dumps(sorted({3: 1, 1: 2})))'",
            "PY-[1, 3]",
        ));
        steps.push((
            "python3 -c 'import threading as t, concurrent.futures as f; e = f.ThreadPoolExecutor(8); print(\"THREADS-\" + str(sum(e.map(lambda x: x * x, range(100)))))'",
            "THREADS-328350",
        ));
    }
    let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
    // Phase 6: networking, against servers on the build machine.
    let servers =
        if rootfs.join("curl").exists() && rootfs.join("ssh").exists() && nettest::available() {
            Some(nettest::start()?)
        } else {
            None
        };
    if let Some(s) = &servers {
        steps.push((
            "ip -4 addr show dev eth0 | grep -o 'inet [0-9.]*/[0-9]*' | tr a-z A-Z",
            "INET 10.0.2.15/24",
        ));
        steps.push((
            "ping -c 1 -W 5 10.0.2.2 | grep -c 'bytes from' | sed 's/^/PINGS=/'",
            "PINGS=1",
        ));
        steps.push((
            leak(format!(
                "curl -sS --cacert /etc/segos-test/ca.pem https://segos-host:{}/hello.txt | tr a-z A-Z",
                nettest::HTTPS_PORT
            )),
            "HTTPS OVER SEGOS TCP",
        ));
        steps.push((
            leak(format!(
                "curl -sS --cacert /etc/segos-test/ca.pem https://segos-host:{}/big.bin | md5sum",
                nettest::HTTPS_PORT
            )),
            leak(s.big_md5.clone()),
        ));
        steps.push((
            leak(format!(
                "ssh -q -i /root/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -p {} {}@10.0.2.2 'echo SSH-$((40+2))'",
                nettest::SSH_PORT,
                s.user
            )),
            "SSH-42",
        ));
    }
    if rootfs.join("gcc").exists() {
        steps.push((
            "cd /tmp && printf 'int main(void){return 7*6;}' > g.c && gcc -O2 -o g g.c; ./g; echo GCC-$?",
            "GCC-42",
        ));
    }
    // Phase 8: POSIX shared memory in /dev/shm, fontconfig, and a D-Bus
    // session bus answering a call.
    if rootfs.join("dbus-daemon").exists() {
        steps.push((
            "python3 -c \"from multiprocessing import shared_memory as s; m=s.SharedMemory(create=True,size=4096); m.buf[0]=42; n=s.SharedMemory(m.name); print('SHM-'+str(n.buf[0])); n.close(); m.close(); m.unlink()\"",
            "SHM-42",
        ));
        steps.push((
            "fc-match -f 'FONT-%{family}-%{fontformat}\\n' sans",
            "FONT-DejaVu Sans-TrueType",
        ));
        steps.push((
            "dbus-run-session -- dbus-send --session --print-reply --dest=org.freedesktop.DBus / org.freedesktop.DBus.ListNames 2>&1 | grep -c '\"org.freedesktop.DBus\"' | sed 's/^/DBUS-NAMES=/'",
            "DBUS-NAMES=1",
        ));
    }
    // Phase 8: sound. A 440 Hz tone, one second, through ALSA's hw
    // device (libasound, the HD Audio driver); QEMU records it.
    let played_tone = rootfs.join("aplay").exists();
    if played_tone {
        steps.push((
            "python3 -c \"import wave,struct,math; w=wave.open('/tmp/tone.wav','wb'); w.setnchannels(2); w.setsampwidth(2); w.setframerate(48000); w.writeframes(b''.join(struct.pack('<hh',v,v) for v in (int(12000*math.sin(2*math.pi*440*i/48000)) for i in range(48000)))); w.close()\" && aplay -q -D hw:0,0 /tmp/tone.wav; echo APLAY-$?",
            "APLAY-0",
        ));
    }
    // Phase 8: Firefox, headless, renders a page to a PNG; Ubuntu's
    // python3 reads the colours back (see pngcheck.py). Slow without KVM.
    let firefox = root()
        .join("target/rootfs/opt/firefox/firefox-bin")
        .exists();
    let mut slow: Vec<(&str, &str)> = Vec::new();
    if firefox {
        slow.push((
            leak(format!(
                "HOME=/root MOZ_CRASHREPORTER_DISABLE=1 firefox --headless --screenshot /tmp/ff.png file://{dir}/page.html > /tmp/ff.log 2>&1; python3 {dir}/pngcheck.py /tmp/ff.png",
                dir = firefox::TEST_DIR
            )),
            "top=red middle=red bottom=blue",
        ));
    }
    let steps = steps.into_iter().map(|(c, w)| (c, w, 120));
    for (cmd, want, secs) in steps.chain(slow.into_iter().map(|(c, w)| (c, w, 900))) {
        let _ = stdin.write_all(format!("{cmd}\n").as_bytes());
        let _ = stdin.flush();
        let Some(end) = wait_for(want, at, secs) else {
            return fail(format!("`{cmd}` did not print `{want}`"), &mut child);
        };
        at = end;
        println!("xtask: shell session: `{cmd}` -> {want}");
    }
    // Phase 7: a KMS program shows a red|blue frame (SETCRTC), then flips
    // to a green one (PAGE_FLIP); QEMU's screen is checked in both states,
    // and once more after it ends, when the console has the screen back.
    let send = |cmd: &str| {
        let mut w = &stdin;
        let _ = w.write_all(format!("{cmd}\n").as_bytes());
        let _ = w.flush();
    };
    // Phase 8: USB. A command typed on the USB keyboard (xHCI, HID boot
    // protocol) reaches the shell; the USB mouse's motion reaches evdev.
    if let Err(e) = type_usb("echo USB-$((6*7))\n") {
        return fail(format!("usb: {e}"), &mut child);
    }
    let Some(end) = wait_for("USB-42", at, 60) else {
        return fail(
            "usb: the line typed on the USB keyboard did not run".into(),
            &mut child,
        );
    };
    at = end;
    println!("xtask: shell session: USB keyboard: `echo USB-$((6*7))` -> USB-42");
    send(
        "(dd if=/dev/input/event1 bs=24 count=1 2>/dev/null | wc -c | sed 's/^/MOUSE-BYTES=/') & sleep 1; echo MOVE-$((3+3))",
    );
    let Some(end) = wait_for("MOVE-6", at, 30) else {
        return fail("usb: the mouse reader did not start".into(), &mut child);
    };
    at = end;
    if let Err(e) = qmp(
        "{\"execute\":\"input-send-event\",\"arguments\":{\"events\":[{\"type\":\"rel\",\"data\":{\"axis\":\"x\",\"value\":20}}]}}",
    ) {
        return fail(format!("usb: {e}"), &mut child);
    }
    let Some(end) = wait_for("MOUSE-BYTES=24", at, 30) else {
        return fail("usb: no evdev event from the USB mouse".into(), &mut child);
    };
    at = end;
    println!("xtask: shell session: USB mouse: motion -> one evdev event (24 bytes)");
    let check_screen = |what: &str, want: &[&str], child: &mut std::process::Child| {
        // The kernel copies to the screen at once; give QEMU's display a moment.
        std::thread::sleep(Duration::from_millis(500));
        let points = [(0.25, 0.5), (0.5, 0.5), (0.75, 0.5)];
        match screen(&points) {
            Ok((w, h, got)) if got == want => {
                println!("xtask: shell session: {what}: {w}x{h} screen is {got:?}");
                Ok(())
            }
            Ok((w, h, got)) => fail(
                format!(
                    "{what}: the {w}x{h} screen is {got:?} (left, centre, right), not {want:?}"
                ),
                child,
            ),
            Err(e) => fail(format!("{what}: screendump: {e}"), child),
        }
    };
    let cmd = "drmtest --pause &";
    send(cmd);
    let Some(end) = wait_for("DRMTEST-SHOWN", at, 60) else {
        return fail(format!("`{cmd}` did not print `DRMTEST-SHOWN`"), &mut child);
    };
    let log = text();
    for line in log[at..end].lines() {
        if let Some(i) = line.find("drm: ").or_else(|| line.find("evdev: ")) {
            println!("xtask: shell session:   {}", line[i..].trim_end());
        }
    }
    at = end;
    println!("xtask: shell session: `{cmd}` -> DRMTEST-SHOWN");
    // The centre column is the first of the right half.
    check_screen("SETCRTC", &["red", "blue", "blue"], &mut child)?;
    let cmd = "kill -USR1 %1";
    send(cmd);
    let Some(end) = wait_for("DRMTEST-OK ", at, 60) else {
        return fail(format!("`{cmd}` did not print `DRMTEST-OK`"), &mut child);
    };
    let log = text();
    for line in log[at..end].lines() {
        if let Some(i) = line.find("drm: ") {
            println!("xtask: shell session:   {}", line[i..].trim_end());
        }
    }
    at = end;
    let size: String = log[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    println!("xtask: shell session: `{cmd}` -> DRMTEST-OK {size}");
    check_screen("PAGE_FLIP", &["green", "green", "green"], &mut child)?;
    let cmd = "kill %1; wait; echo KILLED-$((40 + 2))";
    send(cmd);
    if wait_for("KILLED-42", at, 60).is_none() {
        return fail(format!("`{cmd}` did not print `KILLED-42`"), &mut child);
    }
    println!("xtask: shell session: `{cmd}` -> KILLED-42");
    check_screen("console", &["other", "other", "other"], &mut child)?;
    // Phase 7 demo: Ubuntu's Wayland compositor on /dev/dri/card0 and
    // evdev, and a client drawing into it: the screen must show the
    // client's pattern, a key press (Esc) must reach the client, and the
    // console must come back when weston ends.
    if rootfs.join("weston").exists() {
        // Types `cmd`; returns where `want` ends in the output after `from`.
        let step =
            |cmd: &str, want: &str, from: usize, secs: u64, child: &mut std::process::Child| {
                send(cmd);
                match wait_for(want, from, secs) {
                    Some(end) => {
                        println!("xtask: shell session: `{cmd}` -> {want}");
                        Ok(end)
                    }
                    None => fail(format!("`{cmd}` did not print `{want}`"), child).map(|()| from),
                }
            };
        at = step(
            "XDG_RUNTIME_DIR=/run/user/0 LIBSEAT_BACKEND=noop weston --backend=drm --renderer=pixman --shell=kiosk --log=/tmp/weston.log & WESTON=$!; echo WESTON-$((1+1))",
            "WESTON-2",
            at,
            30,
            &mut child,
        )?;
        at = step(
            "for i in $(seq 240); do W=$(ls /run/user/0 | grep -v lock); [ -n \"$W\" ] && break; sleep 0.5; done; echo SOCKET-$W",
            "SOCKET-wayland-",
            at,
            150,
            &mut child,
        )?;
        at = step(
            "XDG_RUNTIME_DIR=/run/user/0 WAYLAND_DISPLAY=$W weston-simple-shm & echo CLIENT-$((1+2))",
            "CLIENT-3",
            at,
            30,
            &mut child,
        )?;
        // The client fills the screen (kiosk shell) with a many-coloured
        // pattern; the console and an empty desktop have few colours.
        let start = std::time::Instant::now();
        loop {
            match screen_colours() {
                Ok((w, h, distinct, top)) if distinct >= 500 && top < 0.5 => {
                    println!(
                        "xtask: shell session: weston: the {w}x{h} screen shows the client ({distinct} colours, the commonest on {:.0}%)",
                        top * 100.0
                    );
                    break;
                }
                Ok((w, h, distinct, top)) if start.elapsed() > Duration::from_secs(120) => {
                    return fail(
                        format!(
                            "weston: the {w}x{h} screen has {distinct} colours, the commonest on {:.0}%: no client",
                            top * 100.0
                        ),
                        &mut child,
                    );
                }
                Ok(_) => std::thread::sleep(Duration::from_secs(1)),
                Err(e) => return fail(format!("weston: screendump: {e}"), &mut child),
            }
        }
        // Esc, through the PS/2 keyboard, evdev, libinput and weston:
        // weston-simple-shm quits on it.
        if let Err(e) = send_key("esc") {
            return fail(format!("weston: send-key: {e}"), &mut child);
        }
        let Some(end) = wait_for("simple-shm exiting", at, 60) else {
            return fail(
                "weston: weston-simple-shm did not quit on Esc".into(),
                &mut child,
            );
        };
        at = end;
        println!("xtask: shell session: weston: Esc -> simple-shm exiting");
        // weston (seat "noop") leaves the console's keyboard on, so the Esc
        // reached BusyBox's shell too, which takes it with the next 15
        // characters typed as an escape sequence when they come together
        // (slow machines). Type a marker until the shell answers it.
        let mut synced = false;
        for _ in 0..5 {
            send("echo SYNC-$((8*8))");
            if let Some(end) = wait_for("SYNC-64", at, 20) {
                at = end;
                synced = true;
                break;
            }
        }
        if !synced {
            return fail(
                "weston: the shell did not answer after Esc".into(),
                &mut child,
            );
        }
        // Phase 8 demo: Firefox as a Wayland client of weston, showing the
        // test page (red on top, blue below) full screen.
        if firefox {
            at = step(
                &format!(
                    "XDG_RUNTIME_DIR=/run/user/0 WAYLAND_DISPLAY=$W MOZ_ENABLE_WAYLAND=1 HOME=/root MOZ_CRASHREPORTER_DISABLE=1 firefox --kiosk file://{}/page.html > /tmp/ffw.log 2>&1 & FF=$!; echo FIREFOX-$((2+2))",
                    firefox::TEST_DIR
                ),
                "FIREFOX-4",
                at,
                30,
                &mut child,
            )?;
            let start = std::time::Instant::now();
            loop {
                match screen(&[(0.5, 0.3), (0.5, 0.85)]) {
                    Ok((w, h, got)) if got == ["red", "blue"] => {
                        println!(
                            "xtask: shell session: weston: Firefox shows the page on the {w}x{h} screen ({:.0} s)",
                            start.elapsed().as_secs_f64()
                        );
                        break;
                    }
                    Ok((w, h, got)) if start.elapsed() > Duration::from_secs(900) => {
                        let _ = step(
                            "tail -20 /tmp/ffw.log; echo FFLOG-$((5+5))",
                            "FFLOG-10",
                            at,
                            20,
                            &mut child,
                        );
                        return fail(
                            format!(
                                "weston: the {w}x{h} screen is {got:?} (top, bottom), not Firefox's page"
                            ),
                            &mut child,
                        );
                    }
                    Ok(_) => std::thread::sleep(Duration::from_secs(2)),
                    Err(e) => return fail(format!("weston: screendump: {e}"), &mut child),
                }
            }
            at = step(
                "kill $FF; wait $FF; echo FIREFOX-ENDED-$((3+4))",
                "FIREFOX-ENDED-7",
                at,
                60,
                &mut child,
            )?;
        }
        step(
            "kill $WESTON; wait; grep -c 'caught signal 15' /tmp/weston.log | sed 's/^/WESTON-SIGNALS=/'",
            "WESTON-SIGNALS=1",
            at,
            60,
            &mut child,
        )?;
        match screen_colours() {
            Ok((w, h, distinct, top)) if distinct < 16 && top > 0.8 => {
                println!(
                    "xtask: shell session: weston ended: the {w}x{h} screen is the console again"
                );
            }
            Ok((w, h, distinct, top)) => {
                return fail(
                    format!(
                        "weston ended: the {w}x{h} screen has {distinct} colours, the commonest on {:.0}%: not the console",
                        top * 100.0
                    ),
                    &mut child,
                );
            }
            Err(e) => return fail(format!("weston ended: screendump: {e}"), &mut child),
        }
    }
    let _ = stdin.write_all(b"poweroff -f\n");
    let _ = stdin.flush();
    let start = std::time::Instant::now();
    loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            if s.success() {
                println!("xtask: shell session: `poweroff -f` turned the machine off");
                if played_tone {
                    return check_tone();
                }
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
