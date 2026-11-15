//! Firefox on the root disk: Mozilla's own Linux x86-64 build (Ubuntu's
//! firefox package is only a stub that installs a snap).
//!
//! The pinned release is downloaded once with curl into
//! `target/firefox/`, checked against its SHA-256 and unpacked there;
//! every image copies it to `/opt/firefox` with `/usr/bin/firefox`
//! pointing at it. The shared libraries it loads from the system (GTK 3,
//! its X11 and Wayland libraries, ALSA, D-Bus, ...) are found with `ldd`
//! and copied by the glibc layer, together with what GTK reads at run time
//! (its packages are listed in `glibc.rs`).
//!
//! Without the network (or with `SEGOS_NO_FIREFOX=1`) the disk is built
//! without Firefox, and the shell session skips its steps.

use crate::root;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const VERSION: &str = "159.0.1";
/// From the release's SHA256SUMS file.
const SHA256: &str = "469ce17120018e1c95411d254cf3c5f8db2dd1768a7acde5a2a089b00072ac65";

fn url() -> String {
    format!(
        "https://ftp.mozilla.org/pub/firefox/releases/{VERSION}/linux-x86_64/en-US/firefox-{VERSION}.tar.xz"
    )
}

fn sha256(file: &Path) -> Option<String> {
    let out = Command::new("sha256sum").arg(file).output().ok()?;
    out.status.success().then(|| {
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string()
    })
}

/// The unpacked release (`target/firefox/<version>/firefox`), downloading
/// and unpacking it first if needed.
fn unpacked() -> Result<PathBuf, String> {
    let dir = root().join("target/firefox");
    let out = dir.join(VERSION);
    let ff = out.join("firefox");
    if ff.join("firefox-bin").exists() {
        return Ok(ff);
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tarball = dir.join(format!("firefox-{VERSION}.tar.xz"));
    if sha256(&tarball).as_deref() != Some(SHA256) {
        let part = dir.join(format!("firefox-{VERSION}.tar.xz.part"));
        eprintln!("xtask: downloading Firefox {VERSION} from {}", url());
        let ok = Command::new("curl")
            .args(["-fsSL", "--retry", "3", "-o"])
            .arg(&part)
            .arg(url())
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            let _ = std::fs::remove_file(&part);
            return Err(format!("cannot download {}", url()));
        }
        let got = sha256(&part);
        if got.as_deref() != Some(SHA256) {
            let _ = std::fs::remove_file(&part);
            return Err(format!(
                "{}: SHA-256 {got:?}, expected {SHA256}",
                tarball.display()
            ));
        }
        std::fs::rename(&part, &tarball).map_err(|e| format!("{}: {e}", tarball.display()))?;
    }
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    crate::status(
        Command::new("tar")
            .arg("-xJf")
            .arg(&tarball)
            .arg("-C")
            .arg(&out),
    )?;
    Ok(ff)
}

/// Shared libraries (host paths) that the ELF files under `dir` load from
/// outside it.
fn system_libraries(dir: &Path) -> Vec<String> {
    let mut libs = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let Ok(meta) = p.symlink_metadata() else {
                continue;
            };
            if meta.is_dir() {
                todo.push(p);
                continue;
            }
            if !meta.is_file() || !crate::glibc::is_elf(&p) {
                continue;
            }
            let Ok(out) = Command::new("ldd")
                .arg(&p)
                .env("LD_LIBRARY_PATH", dir)
                .output()
            else {
                continue;
            };
            for l in String::from_utf8_lossy(&out.stdout).lines() {
                let Some((_, rest)) = l.split_once("=> ") else {
                    continue;
                };
                let Some(lib) = rest.split_whitespace().next() else {
                    continue;
                };
                if lib.starts_with('/') && !Path::new(lib).starts_with(dir) {
                    libs.push(lib.to_string());
                }
            }
        }
    }
    libs.sort();
    libs.dedup();
    libs
}

/// Puts Firefox into `tree`. Returns the host libraries it needs, for the
/// glibc layer to copy (empty when Firefox is left out).
pub fn add(tree: &Path) -> Result<Vec<String>, String> {
    if std::env::var_os("SEGOS_NO_FIREFOX").is_some()
        || std::env::var_os("SEGOS_NO_GLIBC").is_some()
    {
        return Ok(Vec::new());
    }
    let ff = match unpacked() {
        Ok(ff) => ff,
        Err(e) => {
            eprintln!("xtask: {e}; the root disk will not have Firefox");
            return Ok(Vec::new());
        }
    };
    let opt = tree.join("opt");
    std::fs::create_dir_all(&opt).map_err(|e| format!("{}: {e}", opt.display()))?;
    crate::status(Command::new("cp").arg("-a").arg(&ff).arg(&opt))?;
    let bin = tree.join("usr/bin");
    std::fs::create_dir_all(&bin).map_err(|e| format!("{}: {e}", bin.display()))?;
    let link = bin.join("firefox");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink("/opt/firefox/firefox", &link)
        .map_err(|e| format!("{}: {e}", link.display()))?;
    // The shell session's test page and the checker of its screenshot.
    let test = tree.join(TEST_DIR.trim_start_matches('/'));
    std::fs::create_dir_all(&test).map_err(|e| format!("{}: {e}", test.display()))?;
    for (name, data) in [
        ("page.html", PAGE),
        ("pngcheck.py", include_str!("pngcheck.py")),
    ] {
        std::fs::write(test.join(name), data).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(system_libraries(&ff))
}

/// Where the test page and `pngcheck.py` are in SegOS.
pub const TEST_DIR: &str = "/usr/share/segos-test/firefox";

/// The test page: red on top, a blue block below (the shell session
/// checks the colours in Firefox's screenshot and on the screen).
const PAGE: &str = "<!DOCTYPE html>\n<html><head><title>SegOS</title></head>\n\
<body style=\"margin:0; background:#ff0000\">\n\
<div style=\"position:fixed; left:0; right:0; top:60%; bottom:0; background:#0000ff\"></div>\n\
</body></html>\n";
