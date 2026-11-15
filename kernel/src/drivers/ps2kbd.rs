//! PS/2 keyboard, through the i8042 controller (also what firmware emulates
//! for USB keyboards on many PCs, and what QEMU provides).
//!
//! The controller translates the keyboard's codes to scan code set 1:
//! one byte per key press, the same byte with bit 7 set on release, and
//! 0xE0 before the keys added with the 101-key keyboard. Keys become the
//! bytes a terminal sends (US layout): letters and symbols, control
//! characters with Ctrl, an ESC prefix with Alt, and escape sequences for
//! the cursor and editing keys.

use crate::hal::x86;
use crate::sync::SpinLock;

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const COMMAND: u16 = 0x64;

fn wait_write() {
    for _ in 0..100_000 {
        if unsafe { x86::inb(STATUS) } & 2 == 0 {
            return;
        }
    }
}

fn command(c: u8) {
    wait_write();
    unsafe { x86::outb(COMMAND, c) };
}

/// Enables keyboard interrupts on the controller. False if there is none.
pub fn init() -> bool {
    if unsafe { x86::inb(STATUS) } == 0xff {
        return false;
    }
    command(0xad); // disable the keyboard port while we set up
    command(0xa7); // and the mouse port
    for _ in 0..64 {
        if unsafe { x86::inb(STATUS) } & 1 == 0 {
            break;
        }
        unsafe { x86::inb(DATA) };
    }
    command(0x20); // read the configuration byte
    let mut config = 0;
    for _ in 0..100_000 {
        if unsafe { x86::inb(STATUS) } & 1 != 0 {
            config = unsafe { x86::inb(DATA) };
            break;
        }
    }
    // Keyboard interrupt on, mouse interrupt off, translation to set 1 on.
    config = (config | 0x01 | 0x40) & !0x02;
    command(0x60);
    wait_write();
    unsafe { x86::outb(DATA, config) };
    if mouse_init() {
        // Mouse interrupt and clock on too.
        config = (config | 0x02) & !0x20;
        command(0x60);
        wait_write();
        unsafe { x86::outb(DATA, config) };
        MOUSE_PRESENT.store(true, core::sync::atomic::Ordering::Relaxed);
    }
    command(0xae); // enable the keyboard port
    true
}

struct Keys {
    shift: bool,
    ctrl: bool,
    alt: bool,
    caps: bool,
    extended: bool,
}

static KEYS: SpinLock<Keys> = SpinLock::new(Keys {
    shift: false,
    ctrl: false,
    alt: false,
    caps: false,
    extended: false,
});

/// Set 1 codes 0x00-0x39: (unshifted, shifted).
const MAP: &[(u8, u8); 58] = &[
    (0, 0),
    (0x1b, 0x1b), // Esc
    (b'1', b'!'),
    (b'2', b'@'),
    (b'3', b'#'),
    (b'4', b'$'),
    (b'5', b'%'),
    (b'6', b'^'),
    (b'7', b'&'),
    (b'8', b'*'),
    (b'9', b'('),
    (b'0', b')'),
    (b'-', b'_'),
    (b'=', b'+'),
    (0x7f, 0x7f), // Backspace sends DEL, as Linux's console does
    (b'\t', b'\t'),
    (b'q', b'Q'),
    (b'w', b'W'),
    (b'e', b'E'),
    (b'r', b'R'),
    (b't', b'T'),
    (b'y', b'Y'),
    (b'u', b'U'),
    (b'i', b'I'),
    (b'o', b'O'),
    (b'p', b'P'),
    (b'[', b'{'),
    (b']', b'}'),
    (b'\r', b'\r'), // Enter
    (0, 0),         // Left Ctrl
    (b'a', b'A'),
    (b's', b'S'),
    (b'd', b'D'),
    (b'f', b'F'),
    (b'g', b'G'),
    (b'h', b'H'),
    (b'j', b'J'),
    (b'k', b'K'),
    (b'l', b'L'),
    (b';', b':'),
    (b'\'', b'"'),
    (b'`', b'~'),
    (0, 0), // Left Shift
    (b'\\', b'|'),
    (b'z', b'Z'),
    (b'x', b'X'),
    (b'c', b'C'),
    (b'v', b'V'),
    (b'b', b'B'),
    (b'n', b'N'),
    (b'm', b'M'),
    (b',', b'<'),
    (b'.', b'>'),
    (b'/', b'?'),
    (0, 0), // Right Shift
    (b'*', b'*'),
    (0, 0), // Left Alt
    (b' ', b' '),
];

/// What one scan code means.
enum Key {
    Nothing,
    /// A fixed byte sequence (cursor and editing keys).
    Seq(&'static [u8]),
    /// A character key: (unshifted, shifted).
    Char(u8, u8),
}

fn translate(k: &mut Keys, code: u8) -> Key {
    let extended = core::mem::take(&mut k.extended);
    let release = code & 0x80 != 0;
    let key = code & 0x7f;
    match key {
        0x2a | 0x36 => k.shift = !release,
        0x1d => k.ctrl = !release,
        0x38 => k.alt = !release,
        0x3a if !release => k.caps = !k.caps,
        _ => {}
    }
    if release {
        return Key::Nothing;
    }
    if extended {
        return match key {
            0x48 => Key::Seq(b"\x1b[A"),
            0x50 => Key::Seq(b"\x1b[B"),
            0x4d => Key::Seq(b"\x1b[C"),
            0x4b => Key::Seq(b"\x1b[D"),
            0x47 => Key::Seq(b"\x1b[H"),
            0x4f => Key::Seq(b"\x1b[F"),
            0x49 => Key::Seq(b"\x1b[5~"),
            0x51 => Key::Seq(b"\x1b[6~"),
            0x52 => Key::Seq(b"\x1b[2~"),
            0x53 => Key::Seq(b"\x1b[3~"),
            0x1c => Key::Seq(b"\r"), // keypad Enter
            0x35 => Key::Seq(b"/"),  // keypad /
            _ => Key::Nothing,
        };
    }
    match MAP.get(key as usize) {
        Some(&(lower, upper)) if lower != 0 => Key::Char(lower, upper),
        _ => Key::Nothing,
    }
}

/// The byte Ctrl turns `b` into.
fn control(b: u8) -> u8 {
    match b {
        b'a'..=b'z' | b'A'..=b'Z' => b & 0x1f,
        b'@' | b' ' | b'2' => 0,
        b'[' | b'3' => 0x1b,
        b'\\' | b'4' => 0x1c,
        b']' | b'5' => 0x1d,
        b'^' | b'6' => 0x1e,
        b'_' | b'-' | b'/' => 0x1f,
        b'?' | b'8' => 0x7f,
        b => b,
    }
}

/// Keyboard interrupt: reads the scan code, reports the key to evdev
/// and types it on the console (unless a program has the keyboard).
pub fn irq() {
    let code = unsafe { x86::inb(DATA) };
    let mut out = [0u8; 8];
    let (n, ev) = {
        let mut k = KEYS.lock();
        if code == 0xe0 {
            k.extended = true;
            return;
        }
        let ev = linux_key(code & 0x7f, k.extended).map(|c| (c, code & 0x80 == 0));
        let n = match translate(&mut k, code) {
            Key::Nothing => 0,
            Key::Seq(seq) => {
                out[..seq.len()].copy_from_slice(seq);
                seq.len()
            }
            Key::Char(lower, upper) => {
                let letter = lower.is_ascii_lowercase();
                let mut b = if k.shift ^ (k.caps && letter) {
                    upper
                } else {
                    lower
                };
                if k.ctrl {
                    b = control(b);
                }
                let mut n = 0;
                if k.alt {
                    out[0] = 0x1b;
                    n = 1;
                }
                out[n] = b;
                n + 1
            }
        };
        (n, ev)
    };
    if let Some((c, down)) = ev {
        crate::input::key(c, down);
    }
    if n > 0 && crate::input::console_gets_keys() {
        crate::tty::console().input_bytes(&out[..n]);
    }
}

/// The Linux key code of a set-1 scan code (the same numbers, except for
/// the keys behind the 0xE0 prefix).
fn linux_key(code: u8, extended: bool) -> Option<u16> {
    if !extended {
        return (1..=0x58).contains(&code).then_some(code as u16);
    }
    Some(match code {
        0x1c => 96,  // KP enter
        0x1d => 97,  // right ctrl
        0x35 => 98,  // KP /
        0x37 => 99,  // print screen
        0x38 => 100, // right alt
        0x47 => 102, // home
        0x48 => 103, // up
        0x49 => 104, // page up
        0x4b => 105, // left
        0x4d => 106, // right
        0x4f => 107, // end
        0x50 => 108, // down
        0x51 => 109, // page down
        0x52 => 110, // insert
        0x53 => 111, // delete
        0x5b => 125, // left meta
        0x5c => 126, // right meta
        0x5d => 127, // menu
        _ => return None,
    })
}

// ---- The PS/2 mouse (the controller's second port) --------------------------

struct Mouse {
    packet: [u8; 4],
    have: usize,
    size: usize,
    buttons: u8,
}

static MOUSE: SpinLock<Mouse> = SpinLock::new(Mouse {
    packet: [0; 4],
    have: 0,
    size: 3,
    buttons: 0,
});

fn read_data() -> Option<u8> {
    for _ in 0..100_000 {
        if unsafe { x86::inb(STATUS) } & 1 != 0 {
            return Some(unsafe { x86::inb(DATA) });
        }
    }
    None
}

/// Sends a byte to the mouse; true if it acknowledged.
fn mouse_send(b: u8) -> bool {
    command(0xd4);
    wait_write();
    unsafe { x86::outb(DATA, b) };
    read_data() == Some(0xfa)
}

/// Sets the mouse up (defaults, wheel if it has one, streaming). Called
/// by [`init`] before interrupts are routed.
fn mouse_init() -> bool {
    command(0xa8); // enable the mouse port
    if !mouse_send(0xf6) {
        return false;
    }
    // The IntelliMouse knock (sample rates 200, 100, 80) turns the wheel on.
    for rate in [200u8, 100, 80] {
        mouse_send(0xf3);
        mouse_send(rate);
    }
    mouse_send(0xf2);
    let id = read_data().unwrap_or(0);
    MOUSE.lock().size = if id == 3 { 4 } else { 3 };
    mouse_send(0xf4)
}

/// Mouse interrupt: one byte of a 3- or 4-byte movement packet.
pub fn mouse_irq() {
    let b = unsafe { x86::inb(DATA) };
    let mut m = MOUSE.lock();
    if m.have == 0 && b & 0x08 == 0 {
        return; // not the first byte of a packet: resynchronise
    }
    let i = m.have;
    m.packet[i] = b;
    m.have += 1;
    if m.have < m.size {
        return;
    }
    m.have = 0;
    let p = m.packet;
    if p[0] & 0xc0 != 0 {
        return; // overflow
    }
    let dx = p[1] as i32 - (((p[0] as i32) << 4) & 0x100);
    let dy = p[2] as i32 - (((p[0] as i32) << 3) & 0x100);
    let wheel = if m.size == 4 {
        (p[3] << 4) as i8 as i32 >> 4
    } else {
        0
    };
    let buttons = p[0] & 7;
    let changed = buttons ^ m.buttons;
    m.buttons = buttons;
    drop(m);
    crate::input::mouse(dx, dy, wheel, buttons, changed);
}

pub static MOUSE_PRESENT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
