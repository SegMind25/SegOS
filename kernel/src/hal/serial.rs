//! 16550 UART on COM1: the first output that works and the last that fails.

use super::x86;
use crate::sync::SpinLock;
use core::fmt;

const COM1: u16 = 0x3f8;

pub struct Serial {
    base: u16,
}

impl Serial {
    const fn new(base: u16) -> Self {
        Self { base }
    }

    fn out(&self, offset: u16, value: u8) {
        unsafe { x86::outb(self.base + offset, value) }
    }

    fn input(&self, offset: u16) -> u8 {
        unsafe { x86::inb(self.base + offset) }
    }

    fn init(&mut self) {
        {
            self.out(1, 0x00); // no interrupts
            self.out(3, 0x80); // DLAB on
            self.out(0, 0x01); // divisor 1: 115200 baud
            self.out(1, 0x00);
            self.out(3, 0x03); // 8N1, DLAB off
            self.out(2, 0xc7); // FIFO on, cleared, 14-byte threshold
            self.out(4, 0x0b); // DTR, RTS, OUT2
        }
    }

    pub fn write_byte(&mut self, byte: u8) {
        {
            while self.input(5) & 0x20 == 0 {
                core::hint::spin_loop();
            }
            self.out(0, byte);
        }
    }
}

impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
        Ok(())
    }
}

pub static SERIAL: SpinLock<Serial> = SpinLock::new(Serial::new(COM1));

pub fn init() {
    SERIAL.lock().init();
}

/// Writes without waiting for the lock: used by the panic handler, where the
/// lock may be held by the code that panicked.
pub fn write_unlocked(args: fmt::Arguments) {
    let mut serial = Serial::new(COM1);
    let _ = fmt::Write::write_fmt(&mut serial, args);
}

/// Interrupts when bytes arrive (they go to the console terminal).
pub fn enable_rx_interrupt() {
    let s = SERIAL.lock();
    // Drain anything that arrived before.
    while s.input(5) & 1 != 0 {
        s.input(0);
    }
    s.out(1, 0x01);
}

/// Serial interrupt: hands received bytes to the console terminal.
pub fn irq() {
    let mut buf = [0u8; 64];
    let mut n = 0;
    {
        let s = SERIAL.lock();
        while n < buf.len() && s.input(5) & 1 != 0 {
            buf[n] = s.input(0);
            n += 1;
        }
    }
    if n > 0 {
        crate::tty::console().input_bytes(&buf[..n]);
    }
}
