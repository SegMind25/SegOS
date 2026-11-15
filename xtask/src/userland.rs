//! The initramfs: what SegOS runs.
//!
//! - `userland/rootfs/`: files copied as they are (`/init`, `/etc`).
//! - BusyBox: Ubuntu's statically linked `busybox-static`, unmodified, with
//!   a symbolic link for each of its applets (`/bin/sh`, `/bin/ls`, ...).
//! - `userland/hello/hello.c`: the Phase 2 demo, `/usr/bin/hello`.
//! - `userland/tests/`: conformance tests. `NAME.c` programs (built with
//!   musl-gcc) and `NAME.sh` scripts (run by BusyBox's sh), each with a
//!   `NAME.expected` file holding exactly what it prints on Linux.

use crate::cpio;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Program {
    /// Where it goes in the initramfs ("usr/bin/hello", "tests/basics").
    pub path: String,
    /// The built program (or the script).
    pub file: PathBuf,
    /// For tests: the output it must print, recorded on Linux.
    pub expected: Option<PathBuf>,
    /// A shell script (run by sh) rather than an executable.
    pub script: bool,
}

pub struct Userland {
    pub programs: Vec<Program>,
    pub busybox: PathBuf,
}

fn root() -> PathBuf {
    crate::root()
}

fn read(p: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(p).map_err(|e| format!("cannot read {}: {e}", p.display()))
}

fn musl_gcc() -> String {
    std::env::var("MUSL_GCC").unwrap_or_else(|_| "musl-gcc".into())
}

fn compile(c: &Path, out: &Path) -> Result<(), String> {
    let cc = musl_gcc();
    let mut cmd = Command::new(&cc);
    cmd.args(["-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(out)
        .arg(c);
    match cmd.status() {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("{cc} failed on {}: {s}", c.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(format!(
            "`{cc}` not found. The userland programs are built for Linux \
             with musl: install musl-tools (Debian/Ubuntu) or musl (Arch, \
             Fedora), or set MUSL_GCC"
        )),
        Err(e) => Err(format!("cannot run {cc}: {e}")),
    }
}

/// Whether `bytes` is a static x86-64 ELF executable (no PT_INTERP).
fn is_static_elf(bytes: &[u8]) -> bool {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 {
        return false;
    }
    let u16_at = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]) as usize;
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let (size, count) = (u16_at(54), u16_at(56));
    (0..count).all(|i| {
        let o = phoff + i * size;
        bytes
            .get(o..o + 4)
            .is_some_and(|t| u32::from_le_bytes(t.try_into().unwrap()) != 3)
    })
}

/// A statically linked BusyBox: `$BUSYBOX`, or Ubuntu's `busybox-static`
/// package, downloaded once with apt into target/busybox.
fn busybox() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("BUSYBOX") {
        let p = PathBuf::from(p);
        if !is_static_elf(&read(&p)?) {
            return Err(format!(
                "{} is not a statically linked x86-64 BusyBox",
                p.display()
            ));
        }
        return Ok(p);
    }
    let dir = root().join("target/busybox");
    let bin = dir.join("busybox");
    if bin.exists() {
        return Ok(bin);
    }
    let dl = dir.join("download");
    let _ = std::fs::remove_dir_all(&dl);
    std::fs::create_dir_all(&dl).map_err(|e| format!("cannot create {}: {e}", dl.display()))?;
    println!("xtask: downloading Ubuntu's busybox-static with apt-get");
    let fail = |what: &str| {
        format!(
            "cannot get BusyBox ({what}). On Debian or Ubuntu, apt-get must \
             work; elsewhere set BUSYBOX to a statically linked x86-64 busybox"
        )
    };
    let ok = Command::new("apt-get")
        .args(["download", "busybox-static"])
        .current_dir(&dl)
        .status()
        .map_err(|_| fail("apt-get not found"))?
        .success();
    if !ok {
        return Err(fail("apt-get download busybox-static failed"));
    }
    let deb = std::fs::read_dir(&dl)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "deb"))
        .ok_or_else(|| fail("no .deb downloaded"))?;
    let unpacked = dl.join("unpacked");
    let ok = Command::new("dpkg-deb")
        .arg("-x")
        .arg(&deb)
        .arg(&unpacked)
        .status()
        .map_err(|_| fail("dpkg-deb not found"))?
        .success();
    let found = ["usr/bin/busybox", "bin/busybox"]
        .iter()
        .map(|p| unpacked.join(p))
        .find(|p| p.exists());
    let Some(src) = found.filter(|_| ok) else {
        return Err(fail("the package has no busybox binary"));
    };
    if !is_static_elf(&read(&src)?) {
        return Err(fail("the package's busybox is not statically linked"));
    }
    std::fs::copy(&src, &bin).map_err(|e| format!("cannot copy busybox: {e}"))?;
    let name = deb.file_name().unwrap().to_string_lossy().into_owned();
    std::fs::write(dir.join("SOURCE"), format!("{name}\n")).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&dl);
    Ok(bin)
}

/// Where BusyBox installs each applet ("bin/ls", "usr/bin/wc", ...), as
/// `busybox --list-full` says; run on this machine when it can be.
fn applets(busybox: &Path) -> Vec<String> {
    let out = if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        Command::new(busybox).arg("--list-full").output().ok()
    } else {
        None
    };
    match out {
        Some(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(|l| l.trim().trim_start_matches('/').to_string())
            .filter(|l| !l.is_empty() && l.contains('/'))
            .collect(),
        _ => [
            "sh", "ash", "ls", "cat", "echo", "grep", "wc", "sort", "head", "tail", "cp", "mv",
            "rm", "mkdir", "rmdir", "ln", "ps", "kill", "sleep", "pwd", "true", "false", "test",
            "[", "env", "uname", "date", "find", "sed", "awk", "vi", "more", "less", "clear",
            "free", "uptime", "mount", "poweroff", "reboot", "stat", "touch", "tr", "cut", "tee",
            "readlink", "printf", "id", "whoami", "dmesg", "hexdump", "xargs", "seq",
        ]
        .iter()
        .map(|a| format!("bin/{a}"))
        .collect(),
    }
}

/// Builds the C programs and collects the tests and BusyBox.
pub fn build() -> Result<Userland, String> {
    let src = root().join("userland");
    let out = root().join("target/userland");
    std::fs::create_dir_all(&out).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    let mut programs = Vec::new();
    let hello = out.join("hello");
    compile(&src.join("hello/hello.c"), &hello)?;
    programs.push(Program {
        path: "usr/bin/hello".into(),
        file: hello,
        expected: None,
        script: false,
    });
    let tests = src.join("tests");
    let mut names: Vec<_> = std::fs::read_dir(&tests)
        .map_err(|e| format!("cannot read {}: {e}", tests.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "c" || x == "sh"))
        .collect();
    names.sort();
    for t in names {
        let name = t.file_stem().unwrap().to_string_lossy().into_owned();
        let expected = t.with_extension("expected");
        if !expected.exists() {
            return Err(format!("{} has no {}", t.display(), expected.display()));
        }
        let script = t.extension().is_some_and(|x| x == "sh");
        let file = if script {
            t.clone()
        } else {
            let bin = out.join(format!("tests-{name}"));
            compile(&t, &bin)?;
            bin
        };
        programs.push(Program {
            path: format!("tests/{name}{}", if script { ".sh" } else { "" }),
            file,
            expected: Some(expected),
            script,
        });
    }
    Ok(Userland {
        programs,
        busybox: busybox()?,
    })
}

/// Copies `userland/rootfs` into `entries`, keeping permissions and links.
fn add_tree(
    dir: &Path,
    prefix: &str,
    entries: &mut Vec<cpio::Entry>,
    dirs: &mut Vec<String>,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut list: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .collect();
    list.sort_by_key(|e| e.file_name());
    for e in list {
        let name = e.file_name().to_string_lossy().into_owned();
        if name == ".keep" {
            continue;
        }
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let meta = std::fs::symlink_metadata(e.path()).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(e.path()).map_err(|e| e.to_string())?;
            entries.push(cpio::Entry {
                path,
                mode: cpio::MODE_SYMLINK | 0o777,
                data: target.to_string_lossy().into_owned().into_bytes(),
            });
        } else if meta.is_dir() {
            dirs.push(path.clone());
            add_tree(&e.path(), &path, entries, dirs)?;
        } else {
            entries.push(cpio::Entry {
                path,
                mode: cpio::MODE_FILE | (meta.permissions().mode() & 0o7777),
                data: read(&e.path())?,
            });
        }
    }
    Ok(())
}

/// The initramfs (a newc cpio archive).
pub fn initramfs(u: &Userland) -> Result<Vec<u8>, String> {
    let (entries, dirs) = tree(u)?;
    let dirs: Vec<&str> = dirs.iter().map(|s| s.as_str()).collect();
    Ok(cpio::write(&entries, &dirs))
}

/// Writes the root file system tree (what the initramfs holds) into
/// `dir`, for `mke2fs -d`. Returns its size in bytes.
pub fn stage(u: &Userland, dir: &Path) -> Result<u64, String> {
    use std::os::unix::fs::PermissionsExt;
    let err = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|e| err(dir, e))?;
    }
    std::fs::create_dir_all(dir).map_err(|e| err(dir, e))?;
    let (entries, dirs) = tree(u)?;
    for d in &dirs {
        let p = dir.join(d);
        std::fs::create_dir_all(&p).map_err(|e| err(&p, e))?;
    }
    let mut bytes = 0;
    for e in &entries {
        let p = dir.join(&e.path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| err(parent, e))?;
        }
        if e.mode & 0o170_000 == cpio::MODE_SYMLINK {
            let target = String::from_utf8_lossy(&e.data).into_owned();
            std::os::unix::fs::symlink(target, &p).map_err(|er| err(&p, er))?;
        } else {
            std::fs::write(&p, &e.data).map_err(|er| err(&p, er))?;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(e.mode & 0o7777))
                .map_err(|er| err(&p, er))?;
            bytes += e.data.len() as u64;
        }
    }
    Ok(bytes)
}

/// Every file and directory of the root file system.
fn tree(u: &Userland) -> Result<(Vec<cpio::Entry>, Vec<String>), String> {
    let mut entries = Vec::new();
    let mut dirs: Vec<String> = [
        "dev", "proc", "sys", "run", "tmp", "root", "home", "mnt", "var", "sbin", "usr/sbin",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    add_tree(&root().join("userland/rootfs"), "", &mut entries, &mut dirs)?;
    entries.push(cpio::Entry {
        path: "bin/busybox".into(),
        mode: cpio::MODE_FILE | 0o755,
        data: read(&u.busybox)?,
    });
    for applet in applets(&u.busybox) {
        if applet == "bin/busybox" || entries.iter().any(|e| e.path == applet) {
            continue;
        }
        entries.push(cpio::Entry {
            path: applet,
            mode: cpio::MODE_SYMLINK | 0o777,
            data: b"/bin/busybox".to_vec(),
        });
    }
    for p in &u.programs {
        entries.push(cpio::Entry {
            path: p.path.clone(),
            mode: cpio::MODE_FILE | if p.script { 0o644 } else { 0o755 },
            data: read(&p.file)?,
        });
        if let Some(e) = &p.expected {
            let base = p.path.trim_end_matches(".sh");
            entries.push(cpio::Entry {
                path: format!("{base}.expected"),
                mode: cpio::MODE_FILE | 0o644,
                data: read(e)?,
            });
        }
    }
    Ok((entries, dirs))
}

/// Runs every test on this machine, if it is x86-64 Linux, and checks it
/// prints exactly its `.expected` file: the expectations must be real Linux
/// behaviour, not what SegOS happens to do. Scripts run with the same
/// BusyBox SegOS gets, its applets first on PATH.
pub fn check_on_host(u: &Userland) -> Result<(), String> {
    if !(cfg!(target_os = "linux") && cfg!(target_arch = "x86_64")) {
        println!("xtask: not on x86-64 Linux, skipping the host run of the userland tests");
        return Ok(());
    }
    let dir = root().join("target/userland/host-run");
    let bin = root().join("target/userland/host-bin");
    let _ = std::fs::remove_dir_all(&bin);
    std::fs::create_dir_all(&bin).map_err(|e| e.to_string())?;
    let bb = std::fs::canonicalize(&u.busybox).map_err(|e| e.to_string())?;
    for applet in applets(&u.busybox) {
        let name = applet.rsplit('/').next().unwrap();
        let _ = std::os::unix::fs::symlink(&bb, bin.join(name));
    }
    for p in u.programs.iter().filter(|p| p.expected.is_some()) {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let mut cmd = if p.script {
            let mut c = Command::new(&bb);
            c.arg("sh")
                .arg(std::fs::canonicalize(&p.file).map_err(|e| e.to_string())?);
            c
        } else {
            Command::new(&p.file)
        };
        let out = cmd
            .current_dir(&dir)
            .env_clear()
            .env("PATH", &bin)
            .env("HOME", "/")
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("cannot run {}: {e}", p.file.display()))?;
        let expected = read(p.expected.as_ref().unwrap())?;
        if !out.status.success() || out.stdout != expected {
            return Err(format!(
                "{} does not behave as its .expected file says on this Linux \
                 machine ({}). It printed:\n{}{}",
                p.path,
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        println!("xtask: {} passes on Linux", p.path);
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
