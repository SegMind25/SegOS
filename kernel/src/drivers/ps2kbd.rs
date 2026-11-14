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

/// Keyboard interrupt: reads the scan code and types it.
pub fn irq() {
    let code = unsafe { x86::inb(DATA) };
    let mut out = [0u8; 8];
    let n = {
        let mut k = KEYS.lock();
        if code == 0xe0 {
            k.extended = true;
            return;
        }
        match translate(&mut k, code) {
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
        }
    };
    if n > 0 {
        crate::tty::console().input_bytes(&out[..n]);
    }
}
