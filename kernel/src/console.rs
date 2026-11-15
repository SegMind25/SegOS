//! Text console on the boot framebuffer, drawn with SegOS's own font.
//!
//! It understands the part of the VT100/ANSI escape language that line
//! editors and full-screen programs use (cursor movement, erasing, colours,
//! insert and delete), so BusyBox's shell and `vi` work on the screen as
//! they do on a serial terminal.

use crate::font;
use crate::hal::serial;
use crate::sync::SpinLock;
use alloc::vec::Vec;
use bootinfo::{Framebuffer, PixelFormat};
use core::fmt::{self, Write};

const CELL_W: usize = font::WIDTH;
const CELL_H: usize = font::HEIGHT;
const FG: u32 = 0x00e6_e6e6;
const BG: u32 = 0x0010_1418;
/// The 16 ANSI colours (0x00RRGGBB): black, red, green, yellow, blue,
/// magenta, cyan, white, then the bright ones.
const PALETTE: [u32; 16] = [
    0x10_1418, 0xcd_3131, 0x0d_bc79, 0xe5_e510, 0x24_72c8, 0xbc_3fbc, 0x11_a8cd, 0xe5_e5e5,
    0x66_6666, 0xf1_4c4c, 0x23_d18b, 0xf5_f543, 0x3b_8eea, 0xd6_70d6, 0x29_b8db, 0xff_ffff,
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Parse {
    Normal,
    Escape,
    /// Inside `ESC [`: parameters so far, and whether it is `ESC [ ?`.
    Csi,
}

pub struct Console {
    base: *mut u32,
    pitch: usize, // in pixels
    width: usize,
    height: usize,
    cols: usize,
    rows: usize,
    col: usize,
    row: usize,
    fg: u32,
    bg: u32,
    /// Colours as set by SGR, before reverse video and byte-order swap.
    fg_rgb: u32,
    bg_rgb: u32,
    bold: bool,
    reverse: bool,
    rgb: bool,
    parse: Parse,
    params: [u16; 8],
    nparams: usize,
    private: bool,
    saved: (usize, usize),
    cursor_shown: bool,
    cursor_visible: bool,
}

// The framebuffer pointer is only used under the console mutex.
unsafe impl Send for Console {}

static CONSOLE: SpinLock<Option<Console>> = SpinLock::new(None);
/// Answers to terminal queries (cursor position), typed back as input.
static REPLY: SpinLock<Vec<u8>> = SpinLock::new(Vec::new());

pub fn init(fb: &Framebuffer) {
    if fb.address == 0 || fb.bpp != 32 {
        crate::warn!("console: no usable framebuffer, serial only");
        return;
    }
    let (width, height) = (fb.width as usize, fb.height as usize);
    let rgb = fb.format == PixelFormat::Rgbx;
    let mut console = Console {
        base: crate::mm::phys_to_virt(fb.address).cast(),
        pitch: fb.pitch as usize / 4,
        width,
        height,
        cols: width / CELL_W,
        rows: height / CELL_H,
        col: 0,
        row: 0,
        fg: convert(FG, rgb),
        bg: convert(BG, rgb),
        fg_rgb: FG,
        bg_rgb: BG,
        bold: false,
        reverse: false,
        rgb,
        parse: Parse::Normal,
        params: [0; 8],
        nparams: 0,
        private: false,
        saved: (0, 0),
        cursor_shown: false,
        cursor_visible: true,
    };
    console.clear();
    *CONSOLE.lock() = Some(console);
}

/// 0x00RRGGBB to the framebuffer's byte order.
fn convert(rgb: u32, swap: bool) -> u32 {
    if swap {
        (rgb & 0xff) << 16 | (rgb & 0xff00) | (rgb >> 16) & 0xff
    } else {
        rgb
    }
}

impl Console {
    fn pixel(&mut self, x: usize, y: usize, color: u32) {
        unsafe { self.base.add(y * self.pitch + x).write_volatile(color) }
    }

    fn fill(&mut self, x0: usize, y0: usize, w: usize, h: usize, color: u32) {
        for y in y0..(y0 + h).min(self.height) {
            for x in x0..(x0 + w).min(self.width) {
                self.pixel(x, y, color);
            }
        }
    }

    fn clear(&mut self) {
        self.fill(0, 0, self.width, self.height, self.bg);
    }

    /// Recomputes the drawing colours from the SGR state.
    fn update_colors(&mut self) {
        let mut fg = self.fg_rgb;
        if self.bold
            && let Some(i) = PALETTE[..8].iter().position(|&c| c == fg)
        {
            fg = PALETTE[i + 8];
        }
        let (f, b) = if self.reverse {
            (self.bg_rgb, fg)
        } else {
            (fg, self.bg_rgb)
        };
        self.fg = convert(f, self.rgb);
        self.bg = convert(b, self.rgb);
    }

    fn glyph(&mut self, c: char) {
        let rows = font::glyph(c);
        let (x0, y0) = (self.col * CELL_W, self.row * CELL_H);
        for (dy, bits) in rows.iter().enumerate() {
            for dx in 0..CELL_W {
                let color = if bits & (0x80 >> dx) != 0 {
                    self.fg
                } else {
                    self.bg
                };
                self.pixel(x0 + dx, y0 + dy, color);
            }
        }
    }

    /// Erases cells `[from, to)` of text row `row`.
    fn erase(&mut self, row: usize, from: usize, to: usize) {
        let to = to.min(self.cols);
        if from < to {
            self.fill(
                from * CELL_W,
                row * CELL_H,
                (to - from) * CELL_W,
                CELL_H,
                self.bg,
            );
        }
    }

    fn scroll_up(&mut self) {
        let row_px = CELL_H * self.pitch;
        let total = self.rows * row_px;
        unsafe { core::ptr::copy(self.base.add(row_px), self.base, total - row_px) };
        let last = self.rows - 1;
        self.erase(last, 0, self.cols);
    }

    fn line_feed(&mut self) {
        self.row += 1;
        if self.row >= self.rows {
            self.scroll_up();
            self.row = self.rows - 1;
        }
    }

    fn newline(&mut self) {
        self.col = 0;
        self.line_feed();
    }

    /// Shows or hides the underline cursor (XOR, so drawing twice undoes it).
    fn toggle_cursor(&mut self) {
        let (x0, y0) = (
            self.col.min(self.cols - 1) * CELL_W,
            self.row * CELL_H + CELL_H - 2,
        );
        let mask = convert(FG ^ BG, self.rgb);
        for y in y0..y0 + 2 {
            for x in x0..x0 + CELL_W {
                let p = unsafe { self.base.add(y * self.pitch + x) };
                unsafe { p.write_volatile(p.read_volatile() ^ mask) };
            }
        }
        self.cursor_shown = !self.cursor_shown;
    }

    fn hide_cursor(&mut self) {
        if self.cursor_shown {
            self.toggle_cursor();
        }
    }

    fn show_cursor(&mut self) {
        if self.cursor_visible && !self.cursor_shown {
            self.toggle_cursor();
        }
    }

    /// Shifts the cells right of the cursor by `n` (positive: right, for
    /// insert; negative: left, for delete), within the row.
    fn shift_row(&mut self, n: isize) {
        let y0 = self.row * CELL_H;
        let start = self.col * CELL_W;
        let end = self.cols * CELL_W;
        let shift = n.unsigned_abs() * CELL_W;
        for y in y0..y0 + CELL_H {
            let line = unsafe { self.base.add(y * self.pitch) };
            unsafe {
                if n > 0 && start + shift < end {
                    core::ptr::copy(
                        line.add(start),
                        line.add(start + shift),
                        end - start - shift,
                    );
                } else if n < 0 && start + shift < end {
                    core::ptr::copy(
                        line.add(start + shift),
                        line.add(start),
                        end - start - shift,
                    );
                }
            }
        }
        if n > 0 {
            let to = (self.col + n as usize).min(self.cols);
            self.erase(self.row, self.col, to);
        } else {
            let from = self.cols.saturating_sub(n.unsigned_abs()).max(self.col);
            self.erase(self.row, from, self.cols);
        }
    }

    fn param(&self, i: usize, default: u16) -> usize {
        let v = if i < self.nparams { self.params[i] } else { 0 };
        (if v == 0 { default } else { v }) as usize
    }

    fn sgr(&mut self) {
        let n = self.nparams.max(1);
        for i in 0..n {
            let p = if i < self.nparams { self.params[i] } else { 0 };
            match p {
                0 => {
                    self.fg_rgb = FG;
                    self.bg_rgb = BG;
                    self.bold = false;
                    self.reverse = false;
                }
                1 => self.bold = true,
                22 => self.bold = false,
                7 => self.reverse = true,
                27 => self.reverse = false,
                30..=37 => self.fg_rgb = PALETTE[p as usize - 30],
                39 => self.fg_rgb = FG,
                40..=47 => self.bg_rgb = PALETTE[p as usize - 40],
                49 => self.bg_rgb = BG,
                90..=97 => self.fg_rgb = PALETTE[p as usize - 90 + 8],
                100..=107 => self.bg_rgb = PALETTE[p as usize - 100 + 8],
                _ => {}
            }
        }
        self.update_colors();
    }

    /// A complete `ESC [ ... final` sequence.
    fn csi(&mut self, fin: char) {
        let (rows, cols) = (self.rows, self.cols);
        match fin {
            'A' => self.row = self.row.saturating_sub(self.param(0, 1)),
            'B' => self.row = (self.row + self.param(0, 1)).min(rows - 1),
            'C' => self.col = (self.col + self.param(0, 1)).min(cols - 1),
            'D' => self.col = self.col.min(cols - 1).saturating_sub(self.param(0, 1)),
            'E' => {
                self.row = (self.row + self.param(0, 1)).min(rows - 1);
                self.col = 0;
            }
            'F' => {
                self.row = self.row.saturating_sub(self.param(0, 1));
                self.col = 0;
            }
            'G' => self.col = (self.param(0, 1) - 1).min(cols - 1),
            'd' => self.row = (self.param(0, 1) - 1).min(rows - 1),
            'H' | 'f' => {
                self.row = (self.param(0, 1) - 1).min(rows - 1);
                self.col = (self.param(1, 1) - 1).min(cols - 1);
            }
            'J' => match self.param(0, 0) {
                0 => {
                    self.erase(self.row, self.col, cols);
                    for r in self.row + 1..rows {
                        self.erase(r, 0, cols);
                    }
                }
                1 => {
                    for r in 0..self.row {
                        self.erase(r, 0, cols);
                    }
                    self.erase(self.row, 0, self.col + 1);
                }
                _ => self.clear(),
            },
            'K' => match self.param(0, 0) {
                0 => self.erase(self.row, self.col, cols),
                1 => self.erase(self.row, 0, self.col + 1),
                _ => self.erase(self.row, 0, cols),
            },
            'X' => {
                let n = self.param(0, 1);
                self.erase(self.row, self.col, self.col + n);
            }
            'P' => self.shift_row(-(self.param(0, 1) as isize)),
            '@' => self.shift_row(self.param(0, 1) as isize),
            'm' => self.sgr(),
            'n' if self.param(0, 0) == 6 => {
                // Cursor position report: typed back as terminal input.
                let reply = alloc::format!("\x1b[{};{}R", self.row + 1, self.col + 1);
                REPLY.lock().extend_from_slice(reply.as_bytes());
            }
            's' => self.saved = (self.row, self.col),
            'u' => (self.row, self.col) = self.saved,
            'h' | 'l' if self.private && self.param(0, 0) == 25 => {
                self.cursor_visible = fin == 'h';
            }
            _ => {}
        }
    }

    fn put(&mut self, c: char) {
        match self.parse {
            Parse::Normal => match c {
                '\n' => self.newline(),
                '\r' => self.col = 0,
                '\x08' => self.col = self.col.min(self.cols - 1).saturating_sub(1),
                '\t' => self.col = ((self.col / 8 + 1) * 8).min(self.cols - 1),
                '\x1b' => self.parse = Parse::Escape,
                c if (c as u32) < 0x20 || c == '\x7f' => {}
                c => {
                    if self.col >= self.cols {
                        self.newline();
                    }
                    self.glyph(c);
                    self.col += 1;
                }
            },
            Parse::Escape => {
                self.parse = Parse::Normal;
                match c {
                    '[' => {
                        self.parse = Parse::Csi;
                        self.params = [0; 8];
                        self.nparams = 0;
                        self.private = false;
                    }
                    '7' => self.saved = (self.row, self.col),
                    '8' => (self.row, self.col) = self.saved,
                    'M' => self.row = self.row.saturating_sub(1),
                    'D' => self.line_feed(),
                    'E' => self.newline(),
                    'c' => {
                        self.fg_rgb = FG;
                        self.bg_rgb = BG;
                        self.bold = false;
                        self.reverse = false;
                        self.update_colors();
                        self.clear();
                        (self.row, self.col) = (0, 0);
                    }
                    _ => {}
                }
            }
            Parse::Csi => match c {
                '0'..='9' => {
                    if self.nparams == 0 {
                        self.nparams = 1;
                    }
                    let p = &mut self.params[self.nparams - 1];
                    *p = p.saturating_mul(10).saturating_add(c as u16 - b'0' as u16);
                }
                ';' => {
                    if self.nparams == 0 {
                        self.nparams = 1;
                    }
                    if self.nparams < self.params.len() {
                        self.nparams += 1;
                    }
                }
                '?' | '>' | '=' => self.private = true,
                c if ('\x40'..='\x7e').contains(&c) => {
                    self.parse = Parse::Normal;
                    self.csi(c);
                }
                _ => self.parse = Parse::Normal,
            },
        }
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.hide_cursor();
        for c in s.chars() {
            self.put(c);
        }
        self.show_cursor();
        Ok(())
    }
}

/// Prints to serial and, once it exists, the screen.
pub fn print(args: fmt::Arguments) {
    crate::hal::x86::without_interrupts(|| {
        let _ = serial::SERIAL.lock().write_fmt(args);
        if let Some(console) = CONSOLE.lock().as_mut() {
            let _ = console.write_fmt(args);
        }
    });
}

/// Writes raw bytes (a program's output) to serial and the screen.
/// Invalid UTF-8 shows as U+FFFD on the screen; serial gets the bytes.
pub fn write_bytes(data: &[u8]) {
    crate::hal::x86::without_interrupts(|| {
        {
            let mut serial = serial::SERIAL.lock();
            for &b in data {
                if b == b'\n' {
                    serial.write_byte(b'\r');
                }
                serial.write_byte(b);
            }
        }
        if let Some(console) = CONSOLE.lock().as_mut() {
            for chunk in data.utf8_chunks() {
                let _ = console.write_str(chunk.valid());
                if !chunk.invalid().is_empty() {
                    let _ = console.write_str("\u{fffd}");
                }
            }
        }
    });
    // Answers to queries go back as input, outside the console lock (the
    // terminal echoes, which writes to the console).
    let reply = core::mem::take(&mut *REPLY.lock());
    if !reply.is_empty() {
        crate::tty::console().input_bytes(&reply);
    }
}

/// Text columns and rows of the console (80x25 on serial only).
pub fn size() -> (usize, usize) {
    CONSOLE
        .lock()
        .as_ref()
        .map_or((80, 25), |c| (c.cols, c.rows))
}

/// Prints to the screen only (for what serial already has).
pub fn print_screen(args: fmt::Arguments) {
    crate::hal::x86::without_interrupts(|| {
        if let Some(console) = CONSOLE.lock().as_mut() {
            let _ = console.write_fmt(args);
        }
    });
}

/// For the panic handler: never blocks on a lock.
pub fn print_panic(args: fmt::Arguments) {
    serial::write_unlocked(args);
    if let Some(mut guard) = CONSOLE.try_lock()
        && let Some(console) = guard.as_mut()
    {
        console.fg = convert(0x00ff_6060, console.rgb);
        let _ = console.write_fmt(args);
    }
}

#[macro_export]
macro_rules! kprintln {
    () => { $crate::console::print(format_args!("\n")) };
    ($($arg:tt)*) => { $crate::console::print(format_args!("{}\n", format_args!($($arg)*))) };
}

/// The screen console while a program owns the screen (DRM, or the
/// terminal in KD_GRAPHICS mode): parked here, so nothing draws.
static PARKED: SpinLock<Option<Console>> = SpinLock::new(None);

/// Hands the screen to a program (`true`) or back to the console, which
/// then starts on a clean screen.
pub fn set_graphics(on: bool) {
    crate::hal::x86::without_interrupts(|| {
        if on {
            if let Some(c) = CONSOLE.lock().take() {
                *PARKED.lock() = Some(c);
            }
        } else if let Some(mut c) = PARKED.lock().take() {
            c.clear();
            c.col = 0;
            c.row = 0;
            *CONSOLE.lock() = Some(c);
        }
    });
}
