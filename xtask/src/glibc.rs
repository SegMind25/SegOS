//! The glibc layer of the root disk: unmodified Ubuntu packages (bash,
//! coreutils, python3, gcc and binutils, with every shared library they
//! load), copied from the machine that builds SegOS.
//!
//! They are Ubuntu's own binaries, dynamically linked against glibc and
//! started by `/lib64/ld-linux-x86-64.so.2`: the Phase 5 demo is that they
//! run on SegOS as they are. The build machine must be Debian or Ubuntu
//! with the packages installed (GitHub's ubuntu-24.04 runners are); a
//! missing package is skipped with a warning, and `SEGOS_NO_GLIBC=1`
//! leaves the layer out.

use std::collections::BTreeSet;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Packages copied whole (minus documentation).
const PACKAGES: &[&str] = &[
    "bash",
    "coreutils",
    "grep",
    "sed",
    "findutils",
    "diffutils",
    "libc6",
    "python3-minimal",
    "python3.12-minimal",
    "libpython3.12-minimal",
    "libpython3.12-stdlib",
    "gcc",
    "gcc-13",
    "gcc-13-x86-64-linux-gnu",
    "cpp-13-x86-64-linux-gnu",
    "binutils",
    "binutils-x86-64-linux-gnu",
    "libc6-dev",
    "libgcc-13-dev",
    "linux-libc-dev",
    // Phase 6: networking.
    "curl",
    "libcurl4t64",
    "wget",
    "netcat-openbsd",
    "ca-certificates",
    "netbase",
];

/// Files no package lists (generated at install time) but programs need.
const EXTRA: &[&str] = &["/etc/ssl/certs/ca-certificates.crt"];

/// Paths not worth the space.
fn skipped(p: &str) -> bool {
    [
        "/usr/share/doc",
        "/usr/share/man",
        "/usr/share/info",
        "/usr/share/locale",
        "/usr/share/lintian",
    ]
    .iter()
    .any(|s| p.starts_with(s))
}

/// Where a host path goes in SegOS's tree: everything under /usr (the
/// tree keeps BusyBox in /bin and /sbin; /lib and /lib64 point into /usr).
fn dest(p: &str) -> String {
    for (from, to) in [
        ("/bin/", "/usr/bin/"),
        ("/sbin/", "/usr/sbin/"),
        ("/lib/", "/usr/lib/"),
        ("/lib64/", "/usr/lib64/"),
    ] {
        if let Some(rest) = p.strip_prefix(from) {
            return format!("{to}{rest}");
        }
    }
    p.to_string()
}

fn package_files(pkg: &str) -> Option<Vec<String>> {
    let out = Command::new("dpkg").args(["-L", pkg]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_string)
            .collect(),
    )
}

/// Shared libraries `file` loads, as `ldd` resolves them on the host.
fn libraries(file: &Path) -> Vec<String> {
    let Ok(out) = Command::new("ldd").arg(file).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let path = match l.split_once("=> ") {
                Some((_, rest)) => rest.split_whitespace().next()?,
                None => l.split_whitespace().next()?,
            };
            path.starts_with('/').then(|| path.to_string())
        })
        .collect()
}

fn is_elf(p: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 4];
    std::fs::File::open(p)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && &magic == b"\x7fELF"
}

/// Copies one host path (file or symbolic link) into the tree.
fn copy(host: &str, tree: &Path) -> Result<(), String> {
    let src = Path::new(host);
    let Ok(meta) = std::fs::symlink_metadata(src) else {
        return Ok(());
    };
    // Directories, and links to directories (merged-/usr's /bin, /lib).
    if meta.is_dir() || src.is_dir() {
        return Ok(());
    }
    let to = tree.join(dest(host).trim_start_matches('/'));
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    // Ubuntu's file replaces a BusyBox applet of the same name.
    if std::fs::symlink_metadata(&to).is_ok() {
        let _ = std::fs::remove_file(&to);
    }
    if meta.file_type().is_symlink() {
        let mut target = std::fs::read_link(src).map_err(|e| format!("{host}: {e}"))?;
        // Absolute links (Debian's /etc/alternatives) point straight at
        // the file they end at.
        if target.is_absolute()
            && let Ok(real) = std::fs::canonicalize(src)
        {
            target = PathBuf::from(dest(&real.display().to_string()));
        }
        symlink(&target, &to).map_err(|e| format!("{}: {e}", to.display()))?;
    } else {
        std::fs::copy(src, &to).map_err(|e| format!("{host}: {e}"))?;
        std::fs::set_permissions(
            &to,
            std::fs::Permissions::from_mode(meta.permissions().mode() & 0o7777),
        )
        .map_err(|e| format!("{}: {e}", to.display()))?;
    }
    Ok(())
}

/// Adds the glibc layer to `tree`. Returns how many files were copied.
pub fn add(tree: &Path) -> Result<usize, String> {
    if std::env::var_os("SEGOS_NO_GLIBC").is_some() {
        return Ok(0);
    }
    let mut files: BTreeSet<String> = BTreeSet::new();
    for pkg in PACKAGES {
        match package_files(pkg) {
            Some(list) => files.extend(list.into_iter().filter(|p| !skipped(p))),
            None => {
                eprintln!("xtask: package {pkg} is not installed; the glibc layer will lack it")
            }
        }
    }
    files.extend(EXTRA.iter().map(|s| s.to_string()));
    if files.is_empty() {
        eprintln!("xtask: no glibc packages found (not Debian/Ubuntu?): root disk without them");
        return Ok(0);
    }
    // Files absolute symbolic links end at.
    let ends: Vec<String> = files
        .iter()
        .filter(|f| std::fs::read_link(f).is_ok_and(|t| t.is_absolute()))
        .filter_map(|f| std::fs::canonicalize(f).ok())
        .map(|p| p.display().to_string())
        .collect();
    // ...and the whole package each comes from (python3 may resolve to
    // another Python version than the one listed).
    for end in &ends {
        let owner = Command::new("dpkg").args(["-S", end]).output().ok();
        let pkg = owner.filter(|o| o.status.success()).and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split(':')
                .next()
                .map(str::to_string)
        });
        if let Some(list) = pkg.and_then(|p| package_files(&p)) {
            files.extend(list.into_iter().filter(|p| !skipped(p)));
        }
        // A Python's standard library comes in packages named after it.
        if let Some(ver) = end.strip_prefix("/usr/bin/python3.") {
            for p in [
                format!("libpython3.{ver}-minimal"),
                format!("libpython3.{ver}-stdlib"),
            ] {
                if let Some(list) = package_files(&p) {
                    files.extend(list.into_iter().filter(|p| !skipped(p)));
                }
            }
        }
    }
    files.extend(ends);
    // Shared libraries of every program and library, until nothing new.
    let mut todo: Vec<String> = files.iter().cloned().collect();
    while let Some(f) = todo.pop() {
        let p = PathBuf::from(&f);
        if !p.is_file() || !is_elf(&p) {
            continue;
        }
        for lib in libraries(&p) {
            // Also the file a library symlink points to.
            let real = std::fs::canonicalize(&lib)
                .map(|r| r.display().to_string())
                .unwrap_or(lib.clone());
            for l in [lib, real] {
                if files.insert(l.clone()) {
                    todo.push(l);
                }
            }
        }
    }
    for f in &files {
        copy(f, tree)?;
    }
    // /lib and /lib64 lead into /usr, as on a merged-/usr Ubuntu; the
    // dynamic linker's well-known path among them.
    for (link, target) in [("lib", "usr/lib"), ("lib64", "usr/lib64")] {
        let p = tree.join(link);
        if std::fs::symlink_metadata(&p).is_err() {
            symlink(target, &p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
    }
    Ok(files.len())
}

/// Bytes the files under `dir` take.
pub fn tree_size(dir: &Path) -> u64 {
    let mut total = 0;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    for e in entries.flatten() {
        let Ok(meta) = e.path().symlink_metadata() else {
            continue;
        };
        if meta.is_dir() {
            total += tree_size(&e.path());
        } else {
            total += meta.len();
        }
    }
    total
}
