//! The Phase 6 demo's other end: an HTTPS server and an OpenSSH server on
//! the build machine, which SegOS reaches through QEMU's user network (the
//! build machine is 10.0.2.2 from inside; /etc/hosts calls it
//! `segos-host`).
//!
//! [`prepare`] makes a throwaway certificate and SSH keys in
//! `target/net-test` and puts what the guest needs on the root disk: the
//! certificate (`/etc/segos-test/ca.pem`, so `curl` verifies the server)
//! and the client key (`/root/.ssh/id_ed25519`). [`start`] runs the two
//! servers on 127.0.0.1 until the returned guard is dropped. Both need
//! python3, openssl and OpenSSH (client and server) on the build machine;
//! without them the network steps of the shell session are skipped.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const HTTPS_PORT: u16 = 18443;
pub const SSH_PORT: u16 = 12222;
const BIG: usize = 4 << 20;

fn dir() -> PathBuf {
    super::root().join("target/net-test")
}

fn have(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {cmd}")])
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn sshd() -> Option<&'static str> {
    ["/usr/sbin/sshd", "/usr/bin/sshd"]
        .into_iter()
        .find(|p| Path::new(p).exists())
}

fn run(cmd: &mut Command) -> Result<(), String> {
    let o = cmd
        .output()
        .map_err(|e| format!("cannot run {:?}: {e}", cmd.get_program()))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{cmd:?} failed: {}",
            String::from_utf8_lossy(&o.stderr)
        ))
    }
}

fn write(p: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    std::fs::write(p, data).map_err(|e| format!("{}: {e}", p.display()))?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("{}: {e}", p.display()))
}

/// Whether the build machine can run the demo's servers.
pub fn available() -> bool {
    have("python3") && have("openssl") && have("ssh-keygen") && sshd().is_some()
}

/// Makes the certificate, the keys and the files to serve, and copies the
/// guest's part into `tree` (the root file system being built).
pub fn prepare(tree: &Path) -> Result<bool, String> {
    if !available() {
        eprintln!("xtask: no python3, openssl or OpenSSH server here: skipping the network demo");
        return Ok(false);
    }
    let d = dir();
    std::fs::create_dir_all(d.join("www")).map_err(|e| e.to_string())?;
    if !d.join("cert.pem").exists() {
        run(Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-days",
                "3650",
                "-subj",
                "/CN=segos-host",
                "-addext",
                "subjectAltName=DNS:segos-host,IP:10.0.2.2",
            ])
            .arg("-keyout")
            .arg(d.join("key.pem"))
            .arg("-out")
            .arg(d.join("cert.pem")))?;
    }
    for key in ["hostkey", "id"] {
        if !d.join(key).exists() {
            run(Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(d.join(key)))?;
        }
    }
    let public = std::fs::read(d.join("id.pub")).map_err(|e| e.to_string())?;
    write(&d.join("authorized_keys"), &public, 0o600)?;
    write(&d.join("www/hello.txt"), b"https over segos tcp\n", 0o644)?;
    // Pseudo-random bytes (xorshift), so the transfer is not compressible.
    let mut x: u64 = 0x5e60_5eed;
    let big: Vec<u8> = (0..BIG)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    write(&d.join("www/big.bin"), &big, 0o644)?;
    let cert = std::fs::read(d.join("cert.pem")).map_err(|e| e.to_string())?;
    write(&tree.join("etc/segos-test/ca.pem"), &cert, 0o644)?;
    let id = std::fs::read(d.join("id")).map_err(|e| e.to_string())?;
    write(&tree.join("root/.ssh/id_ed25519"), &id, 0o600)?;
    std::fs::set_permissions(
        tree.join("root/.ssh"),
        std::fs::Permissions::from_mode(0o700),
    )
    .map_err(|e| e.to_string())?;
    Ok(true)
}

/// The running servers; dropping it stops them.
pub struct Servers {
    children: Vec<Child>,
    /// The user SegOS logs in as over SSH.
    pub user: String,
    /// md5 of `big.bin`, as `md5sum` prints it.
    pub big_md5: String,
}

impl Drop for Servers {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn wait_port(port: u16) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

const SERVER: &str = r#"
import http.server, ssl, sys, os
os.chdir(sys.argv[1])
class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[2])), Quiet)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[3], sys.argv[4])
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
"#;

/// Starts the HTTPS server and sshd (after [`prepare`]).
pub fn start() -> Result<Servers, String> {
    let d = dir();
    let user = std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty())
        .or_else(|| {
            let o = Command::new("id").arg("-un").output().ok()?;
            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .ok_or("cannot tell who runs xtask")?;
    let md5 = Command::new("md5sum")
        .arg(d.join("www/big.bin"))
        .output()
        .map_err(|e| format!("cannot run md5sum: {e}"))?;
    let big_md5 = String::from_utf8_lossy(&md5.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();
    let mut s = Servers {
        children: Vec::new(),
        user,
        big_md5,
    };
    s.children.push(
        Command::new("python3")
            .args(["-c", SERVER])
            .arg(d.join("www"))
            .arg(HTTPS_PORT.to_string())
            .arg(d.join("cert.pem"))
            .arg(d.join("key.pem"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot start the HTTPS server: {e}"))?,
    );
    // sshd insists on its privilege separation directory, even unprivileged.
    let _ = std::fs::create_dir_all("/run/sshd");
    // Its own configuration: the system's may not be readable unprivileged.
    let config = format!(
        "Port {SSH_PORT}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
         StrictModes no\nUsePAM no\nPidFile none\nPasswordAuthentication no\n\
         KbdInteractiveAuthentication no\nPermitRootLogin yes\n",
        d.join("hostkey").display(),
        d.join("authorized_keys").display()
    );
    write(&d.join("sshd_config"), config.as_bytes(), 0o600)?;
    let log = std::fs::File::create(d.join("sshd.log")).map_err(|e| e.to_string())?;
    s.children.push(
        Command::new(sshd().unwrap())
            .args(["-D", "-e", "-f"])
            .arg(d.join("sshd_config"))
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .map_err(|e| format!("cannot start sshd: {e}"))?,
    );
    if !wait_port(HTTPS_PORT) {
        return Err("the HTTPS server did not start".into());
    }
    if !wait_port(SSH_PORT) {
        let log = std::fs::read_to_string(d.join("sshd.log")).unwrap_or_default();
        return Err(format!("sshd did not start:\n{log}"));
    }
    Ok(s)
}
