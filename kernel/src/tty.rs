//! The console terminal and its line discipline.
//!
//! Keyboard and serial input arrive here (from their interrupt handlers)
//! as bytes. In canonical mode (the default) the terminal collects a line
//! with editing (erase, kill, word erase), echoes it, and hands it to
//! `read` when Enter is pressed; `^D` ends input. In raw mode (what line
//! editors such as BusyBox's use) bytes go straight to `read`. `^C`, `^\`
//! and `^Z` send SIGINT, SIGQUIT and SIGTSTP to the foreground process
//! group. Settings are Linux's `struct termios`, changed with `ioctl`.

use crate::abi::{Errno, KResult, Winsize};
use crate::fs::poll;
use crate::mm::vm::AddressSpace;
use crate::proc::{self, signal, signo};
use crate::sync::SpinLock;
use crate::task::wait::WaitQueue;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

// c_iflag
const ISTRIP: u32 = 0o40;
const INLCR: u32 = 0o100;
const IGNCR: u32 = 0o200;
const ICRNL: u32 = 0o400;
// c_lflag
const ISIG: u32 = 0o1;
const ICANON: u32 = 0o2;
const ECHO: u32 = 0o10;
const ECHOE: u32 = 0o20;
const ECHOK: u32 = 0o40;
const ECHONL: u32 = 0o100;
const NOFLSH: u32 = 0o200;
const ECHOCTL: u32 = 0o1000;
const IEXTEN: u32 = 0o100000;
// c_cc indices
const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VTIME: usize = 5;
const VMIN: usize = 6;
const VSUSP: usize = 10;
const VEOL: usize = 11;
const VWERASE: usize = 14;
const VEOL2: usize = 16;

/// The kernel's `struct termios` (what TCGETS/TCSETS transfer: 36 bytes;
/// C libraries convert to their own larger struct).
#[derive(Clone, Copy)]
struct Termios {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    line: u8,
    cc: [u8; 19],
}

const TERMIOS_SIZE: usize = 36;

impl Termios {
    /// Linux's console defaults (`stty -a`: icrnl ixon opost onlcr, 38400
    /// cs8 cread hupcl, isig icanon echo echoe echok iexten echoctl echoke).
    const fn default() -> Self {
        Self {
            iflag: 0o2400, // ICRNL | IXON
            oflag: 0o5,    // OPOST | ONLCR
            cflag: 0o2277, // B38400 | CS8 | CREAD | HUPCL
            lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | 0o4000 | IEXTEN,
            line: 0,
            // INTR QUIT ERASE KILL EOF TIME MIN SWTC START STOP SUSP EOL
            // REPRINT DISCARD WERASE LNEXT EOL2
            cc: [
                3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0,
            ],
        }
    }

    fn to_bytes(self) -> [u8; TERMIOS_SIZE] {
        let mut b = [0u8; TERMIOS_SIZE];
        for (i, w) in [self.iflag, self.oflag, self.cflag, self.lflag]
            .iter()
            .enumerate()
        {
            b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        b[16] = self.line;
        b[17..36].copy_from_slice(&self.cc);
        b
    }

    fn from_bytes(b: &[u8; TERMIOS_SIZE]) -> Self {
        let w = |i: usize| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
        let mut cc = [0u8; 19];
        cc.copy_from_slice(&b[17..36]);
        Self {
            iflag: w(0),
            oflag: w(1),
            cflag: w(2),
            lflag: w(3),
            line: b[16],
            cc,
        }
    }
}

struct Input {
    /// The line being edited (canonical mode).
    edit: Vec<u8>,
    /// Completed lines waiting for `read`; an empty one is an end of file.
    lines: VecDeque<Vec<u8>>,
    /// Bytes for `read` in raw mode.
    raw: VecDeque<u8>,
}

const MAX_INPUT: usize = 4096;

pub struct Tty {
    termios: SpinLock<Termios>,
    input: SpinLock<Input>,
    read_wait: WaitQueue,
    /// Foreground process group and owning session (0: none).
    fg_pgrp: AtomicU32,
    session: AtomicU32,
    winsize: SpinLock<Winsize>,
}

static CONSOLE: Tty = Tty {
    termios: SpinLock::new(Termios::default()),
    input: SpinLock::new(Input {
        edit: Vec::new(),
        lines: VecDeque::new(),
        raw: VecDeque::new(),
    }),
    read_wait: WaitQueue::new(),
    fg_pgrp: AtomicU32::new(0),
    session: AtomicU32::new(0),
    winsize: SpinLock::new(Winsize {
        rows: 25,
        cols: 80,
        xpixel: 0,
        ypixel: 0,
    }),
};

/// The system console: the screen and keyboard, and the serial port.
pub fn console() -> &'static Tty {
    &CONSOLE
}

/// Sets the window size from the screen console's character grid.
pub fn init() {
    let (cols, rows) = crate::console::size();
    let mut w = CONSOLE.winsize.lock();
    w.cols = cols as u16;
    w.rows = rows as u16;
}

fn echo(bytes: &[u8]) {
    crate::console::write_bytes(bytes);
}

/// How a byte echoes: control characters as `^X` with ECHOCTL.
fn echo_char(t: &Termios, b: u8) {
    if t.lflag & ECHO == 0 {
        return;
    }
    if t.lflag & ECHOCTL != 0 && (b < 0x20 && b != b'\n' && b != b'\t' || b == 0x7f) {
        echo(&[b'^', b ^ 0x40]);
    } else {
        echo(&[b]);
    }
}

/// Erases one character on the screen (`\b \b`, twice for `^X` forms).
fn echo_erase(t: &Termios, b: u8) {
    if t.lflag & ECHO == 0 || t.lflag & ECHOE == 0 {
        return;
    }
    let width = if t.lflag & ECHOCTL != 0 && (b < 0x20 && b != b'\t' || b == 0x7f) {
        2
    } else {
        1
    };
    for _ in 0..width {
        echo(b"\x08 \x08");
    }
}

impl Tty {
    /// Bytes typed (keyboard) or received (serial). Called from interrupt
    /// handlers.
    pub fn input_bytes(&self, bytes: &[u8]) {
        for &b in bytes {
            self.input_byte(b);
        }
        self.read_wait.wake_all();
        crate::fs::poll_notify();
    }

    fn signal_fg(&self, sig: i32) {
        let pg = self.fg_pgrp.load(Ordering::Relaxed);
        if pg != 0 {
            let _ = signal::send_to_group(pg, sig, signal::SigInfo::kernel());
        }
    }

    fn input_byte(&self, mut b: u8) {
        let t = *self.termios.lock();
        if t.iflag & ISTRIP != 0 {
            b &= 0x7f;
        }
        if b == b'\r' {
            if t.iflag & IGNCR != 0 {
                return;
            }
            if t.iflag & ICRNL != 0 {
                b = b'\n';
            }
        } else if b == b'\n' && t.iflag & INLCR != 0 {
            b = b'\r';
        }
        if t.lflag & ISIG != 0 {
            let sig = if b == t.cc[VINTR] {
                Some(signo::SIGINT)
            } else if b == t.cc[VQUIT] {
                Some(signo::SIGQUIT)
            } else if b == t.cc[VSUSP] {
                Some(signo::SIGTSTP)
            } else {
                None
            };
            if let Some(sig) = sig {
                if t.lflag & NOFLSH == 0 {
                    let mut i = self.input.lock();
                    i.edit.clear();
                    i.lines.clear();
                    i.raw.clear();
                }
                echo_char(&t, b);
                if t.lflag & ECHO != 0 {
                    echo(b"\n");
                }
                self.signal_fg(sig);
                return;
            }
        }
        let mut i = self.input.lock();
        if t.lflag & ICANON == 0 {
            if i.raw.len() < MAX_INPUT {
                i.raw.push_back(b);
            }
            drop(i);
            echo_char(&t, b);
            return;
        }
        let cc = &t.cc;
        if b == cc[VERASE] || b == 0x08 {
            // One character, UTF-8 continuation bytes included.
            while let Some(c) = i.edit.pop() {
                if c & 0xc0 != 0x80 {
                    echo_erase(&t, c);
                    break;
                }
            }
        } else if b == cc[VWERASE] && t.lflag & IEXTEN != 0 {
            while i.edit.last() == Some(&b' ') {
                let c = i.edit.pop().unwrap();
                echo_erase(&t, c);
            }
            while let Some(&c) = i.edit.last() {
                if c == b' ' {
                    break;
                }
                i.edit.pop();
                echo_erase(&t, c);
            }
        } else if b == cc[VKILL] {
            while let Some(c) = i.edit.pop() {
                echo_erase(&t, c);
            }
            if t.lflag & ECHOK != 0 && t.lflag & ECHOE == 0 {
                echo(b"\n");
            }
        } else if b == cc[VEOF] && cc[VEOF] != 0 {
            let line = core::mem::take(&mut i.edit);
            i.lines.push_back(line);
        } else if b == b'\n' || (b == cc[VEOL] && b != 0) || (b == cc[VEOL2] && b != 0) {
            let mut line = core::mem::take(&mut i.edit);
            line.push(b);
            i.lines.push_back(line);
            drop(i);
            if t.lflag & (ECHO | ECHONL) != 0 {
                echo(b"\n");
            }
        } else if i.edit.len() < MAX_INPUT - 1 {
            i.edit.push(b);
            drop(i);
            echo_char(&t, b);
        }
    }

    fn readable(&self) -> bool {
        let i = self.input.lock();
        !i.lines.is_empty() || !i.raw.is_empty()
    }

    pub fn read(&self, out: &mut [u8], nonblock: bool) -> KResult<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let t = *self.termios.lock();
        let canonical = t.lflag & ICANON != 0;
        let (vmin, vtime) = (t.cc[VMIN], t.cc[VTIME]);
        let deadline = (!canonical && vmin == 0 && vtime > 0)
            .then(|| crate::time::monotonic_ns() + vtime as u64 * 100_000_000);
        let _timer = deadline.map(crate::time::wake_at);
        loop {
            {
                let mut i = self.input.lock();
                // A line typed before switching to raw mode is read first.
                if let Some(line) = i.lines.front_mut() {
                    if line.is_empty() {
                        i.lines.pop_front();
                        return Ok(0); // ^D: end of file
                    }
                    let n = out.len().min(line.len());
                    out[..n].copy_from_slice(&line[..n]);
                    line.drain(..n);
                    if line.is_empty() {
                        i.lines.pop_front();
                    }
                    return Ok(n);
                }
                if !i.raw.is_empty() {
                    let n = out.len().min(i.raw.len());
                    for (o, b) in out.iter_mut().zip(i.raw.drain(..n)) {
                        *o = b;
                    }
                    return Ok(n);
                }
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            if !canonical && vmin == 0 {
                match deadline {
                    None => return Ok(0),
                    Some(d) if crate::time::monotonic_ns() >= d => return Ok(0),
                    _ => {}
                }
            }
            self.read_wait.wait_interruptible(|| {
                self.readable() || deadline.is_some_and(|d| crate::time::monotonic_ns() >= d)
            })?;
        }
    }

    pub fn write(&self, data: &[u8]) -> KResult<usize> {
        crate::console::write_bytes(data);
        Ok(data.len())
    }

    pub fn poll(&self) -> u16 {
        if self.readable() {
            poll::POLLIN | poll::POLLOUT
        } else {
            poll::POLLOUT
        }
    }

    /// Makes this terminal the controlling terminal of `p`'s session.
    pub fn make_controlling(&self, p: &proc::Process) {
        self.session.store(p.sid(), Ordering::Relaxed);
        self.fg_pgrp.store(p.pgid(), Ordering::Relaxed);
        p.has_ctty.store(true, Ordering::Relaxed);
    }

    /// On open: a session leader without a terminal gets this one, unless
    /// O_NOCTTY.
    pub fn opened(&self, flags: u32) {
        if flags & crate::abi::open::O_NOCTTY != 0 {
            return;
        }
        let t = crate::task::current();
        if let Some(u) = t.user() {
            let p = &u.process;
            if p.sid() == p.pid
                && !p.has_ctty.load(Ordering::Relaxed)
                && self.session.load(Ordering::Relaxed) == 0
            {
                self.make_controlling(p);
            }
        }
    }

    pub fn ioctl(&self, req: u32, arg: u64, mm: &AddressSpace) -> KResult<u64> {
        use crate::abi::ioctl::*;
        const TCSBRK: u32 = 0x5409;
        const TCXONC: u32 = 0x540a;
        const TCFLSH: u32 = 0x540b;
        const TIOCSCTTY: u32 = 0x540e;
        const FIONREAD: u32 = 0x541b;
        const TIOCNOTTY: u32 = 0x5422;
        const TIOCGSID: u32 = 0x5429;
        const KDGKBTYPE: u32 = 0x4b33;
        let me = crate::task::current();
        let process = me.user().map(|u| u.process.clone());
        match req {
            TCGETS => {
                mm.copy_to(arg, &self.termios.lock().to_bytes())?;
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF => {
                let mut b = [0u8; TERMIOS_SIZE];
                mm.copy_from(arg, &mut b)?;
                let new = Termios::from_bytes(&b);
                let old = core::mem::replace(&mut *self.termios.lock(), new);
                let mut i = self.input.lock();
                if req == TCSETSF {
                    i.edit.clear();
                    i.lines.clear();
                    i.raw.clear();
                } else if old.lflag & ICANON != 0 && new.lflag & ICANON == 0 {
                    // Leaving canonical mode: a half-typed line becomes input.
                    let edit = core::mem::take(&mut i.edit);
                    i.raw.extend(edit);
                }
                drop(i);
                self.read_wait.wake_all();
                Ok(0)
            }
            TIOCGWINSZ => {
                mm.write(arg, &*self.winsize.lock())?;
                Ok(0)
            }
            TIOCSWINSZ => {
                let w: Winsize = mm.read(arg)?;
                *self.winsize.lock() = w;
                self.signal_fg(signo::SIGWINCH);
                Ok(0)
            }
            TIOCGPGRP => {
                mm.write(arg, &(self.fg_pgrp.load(Ordering::Relaxed) as i32))?;
                Ok(0)
            }
            TIOCSPGRP => {
                let pg: i32 = mm.read(arg)?;
                if pg <= 0 {
                    return Err(Errno::EINVAL);
                }
                if let Some(p) = &process
                    && p.sid() != self.session.load(Ordering::Relaxed)
                {
                    return Err(Errno::ENOTTY);
                }
                self.fg_pgrp.store(pg as u32, Ordering::Relaxed);
                Ok(0)
            }
            TIOCGSID => {
                let sid = self.session.load(Ordering::Relaxed);
                if sid == 0 {
                    return Err(Errno::ENOTTY);
                }
                mm.write(arg, &(sid as i32))?;
                Ok(0)
            }
            TIOCSCTTY => {
                let p = process.ok_or(Errno::EPERM)?;
                if p.sid() != p.pid {
                    return Err(Errno::EPERM);
                }
                self.make_controlling(&p);
                Ok(0)
            }
            TIOCNOTTY => {
                if let Some(p) = process {
                    p.has_ctty.store(false, Ordering::Relaxed);
                }
                Ok(0)
            }
            FIONREAD => {
                let i = self.input.lock();
                let n = i.lines.front().map_or(0, |l| l.len()) + i.raw.len();
                drop(i);
                mm.write(arg, &(n as i32))?;
                Ok(0)
            }
            TCFLSH => {
                if arg != 1 {
                    // TCIFLUSH or TCIOFLUSH
                    let mut i = self.input.lock();
                    i.edit.clear();
                    i.lines.clear();
                    i.raw.clear();
                }
                Ok(0)
            }
            TCSBRK | TCXONC => Ok(0),
            KDGKBTYPE => {
                mm.write(arg, &2u8)?; // KB_101: a PC keyboard
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    }
}
