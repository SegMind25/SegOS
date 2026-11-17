//! Intel High Definition Audio: the controller in every PC since 2004
//! (and QEMU's `intel-hda`/`ich9-intel-hda`), with its codecs.
//!
//! The controller is reset, its command ring (CORB) and response ring
//! (RIRB) set up, and every codec's audio function group configured for
//! playback: widgets powered up, amplifiers unmuted, output pins enabled
//! (with EAPD), and every output converter (DAC) listening to stream 1.
//! One output stream plays a cyclic buffer described by a buffer
//! descriptor list; `sound.rs` puts ALSA's PCM interface on top of it.
//! The position is read from the stream's LPIB register (no interrupts).

use super::pci::{self, Bar};
use crate::mm::{PAGE_SIZE, frame, paging, phys_to_virt};
use crate::sync::SpinLock;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};

const GCAP: u64 = 0x00;
const GCTL: u64 = 0x08;
const STATESTS: u64 = 0x0e;
const CORBLBASE: u64 = 0x40;
const CORBUBASE: u64 = 0x44;
const CORBWP: u64 = 0x48;
const CORBRP: u64 = 0x4a;
const CORBCTL: u64 = 0x4c;
const CORBSIZE: u64 = 0x4e;
const RIRBLBASE: u64 = 0x50;
const RIRBUBASE: u64 = 0x54;
const RIRBWP: u64 = 0x58;
const RINTCNT: u64 = 0x5a;
const RIRBCTL: u64 = 0x5c;
const RIRBSIZE: u64 = 0x5e;

// Stream descriptor registers (from the descriptor's base).
const SD_CTL: u64 = 0x00;
const SD_LPIB: u64 = 0x04;
const SD_CBL: u64 = 0x08;
const SD_LVI: u64 = 0x0c;
const SD_FMT: u64 = 0x12;
const SD_BDPL: u64 = 0x18;
const SD_BDPU: u64 = 0x1c;

/// The stream tag the DACs listen to.
const STREAM_TAG: u32 = 1;
/// 48 kHz, 16 bits, 2 channels.
pub const FORMAT: u16 = 0x0011;
/// The most buffer descriptors a list may hold.
pub const MAX_PAGES: usize = 256;

pub struct Hda {
    mmio: u64,
    corb: u64,
    rirb: u64,
    corb_wp: u16,
    rirb_rp: u16,
    /// The output stream descriptor's register base.
    sd: u64,
    bdl: u64,
    /// The pages of the cyclic buffer, and its length in bytes.
    pages: Vec<u64>,
    len: usize,
    /// (codec address, DAC node ids).
    dacs: Vec<(u32, u32)>,
    pub vendor: u32,
    pub base: u64,
}

static HDA: SpinLock<Option<Hda>> = SpinLock::new(None);

pub fn present() -> bool {
    HDA.lock().is_some()
}

/// Runs `f` on the controller, if there is one.
pub fn with<R>(f: impl FnOnce(&mut Hda) -> R) -> Option<R> {
    HDA.lock().as_mut().map(f)
}

fn wait_for(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..1000 {
        if cond() {
            return true;
        }
        crate::time::sleep_ms(1);
    }
    false
}

impl Hda {
    fn r8(&self, off: u64) -> u8 {
        unsafe { read_volatile((self.mmio + off) as *const u8) }
    }
    fn r16(&self, off: u64) -> u16 {
        unsafe { read_volatile((self.mmio + off) as *const u16) }
    }
    fn r32(&self, off: u64) -> u32 {
        unsafe { read_volatile((self.mmio + off) as *const u32) }
    }
    fn w8(&self, off: u64, v: u8) {
        unsafe { write_volatile((self.mmio + off) as *mut u8, v) }
    }
    fn w16(&self, off: u64, v: u16) {
        unsafe { write_volatile((self.mmio + off) as *mut u16, v) }
    }
    fn w32(&self, off: u64, v: u32) {
        unsafe { write_volatile((self.mmio + off) as *mut u32, v) }
    }

    /// Sends a verb to a codec and returns its response.
    fn verb(&mut self, cad: u32, nid: u32, verb: u32) -> Option<u32> {
        let cmd = cad << 28 | nid << 20 | verb;
        self.corb_wp = (self.corb_wp + 1) % 256;
        unsafe {
            write_volatile(
                (phys_to_virt(self.corb) as *mut u32).add(self.corb_wp as usize),
                cmd,
            )
        };
        self.w16(CORBWP, self.corb_wp);
        let want = (self.rirb_rp + 1) % 256;
        let mmio = self.mmio;
        let ok =
            wait_for(|| unsafe { read_volatile((mmio + RIRBWP) as *const u16) } & 0xff == want);
        if !ok {
            return None;
        }
        self.rirb_rp = want;
        let resp =
            unsafe { read_volatile((phys_to_virt(self.rirb) as *const u64).add(want as usize)) };
        Some(resp as u32)
    }

    fn param(&mut self, cad: u32, nid: u32, p: u32) -> u32 {
        self.verb(cad, nid, 0xf00 << 8 | p).unwrap_or(0)
    }

    /// Sets up one codec's audio function groups for playback.
    fn configure_codec(&mut self, cad: u32) {
        if self.vendor == 0 {
            self.vendor = self.param(cad, 0, 0x00);
        }
        let groups = self.param(cad, 0, 0x04);
        let (first, count) = ((groups >> 16) & 0xff, groups & 0xff);
        for fg in first..first + count {
            if self.param(cad, fg, 0x05) & 0xff != 1 {
                continue; // not an audio function group
            }
            self.verb(cad, fg, 0x705 << 8); // D0
            let nodes = self.param(cad, fg, 0x04);
            let (start, n) = ((nodes >> 16) & 0xff, nodes & 0xff);
            for nid in start..start + n {
                let caps = self.param(cad, nid, 0x09);
                let ty = (caps >> 20) & 0xf;
                self.verb(cad, nid, 0x705 << 8);
                // Output amplifier: unmuted, at its 0 dB step.
                if caps & 1 << 2 != 0 {
                    let amp = self.param(cad, nid, 0x12);
                    let gain = amp & 0x7f;
                    self.verb(cad, nid, 0x3 << 16 | 0xb000 | gain);
                }
                // Input amplifiers (mixers): every input unmuted.
                if caps & 1 << 1 != 0 && ty == 2 {
                    let inputs = self.param(cad, nid, 0x0e) & 0x7f;
                    for i in 0..inputs.min(16) {
                        self.verb(cad, nid, 0x3 << 16 | 0x7000 | i << 8);
                    }
                }
                match ty {
                    0 => {
                        // An output converter: stream 1, channel 0.
                        self.verb(cad, nid, 0x706 << 8 | STREAM_TAG << 4);
                        self.verb(cad, nid, 0x2 << 16 | FORMAT as u32);
                        self.dacs.push((cad, nid));
                    }
                    4 => {
                        let pin = self.param(cad, nid, 0x0c);
                        if pin & 1 << 4 != 0 {
                            // Output enabled (and headphone drive if able).
                            let hp = if pin & 1 << 3 != 0 { 0x80 } else { 0 };
                            self.verb(cad, nid, 0x707 << 8 | 0x40 | hp);
                            if pin & 1 << 16 != 0 {
                                self.verb(cad, nid, 0x70c << 8 | 0x02);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Stops the stream and gives it a cyclic buffer of `len` bytes
    /// (zeroed); returns false if that is too long.
    pub fn setup(&mut self, len: usize) -> bool {
        if len == 0 || len > MAX_PAGES * PAGE_SIZE as usize {
            return false;
        }
        self.stop();
        let ctl = self.sd + SD_CTL;
        self.w8(ctl, self.r8(ctl) | 1);
        let mmio = self.mmio;
        wait_for(|| unsafe { read_volatile((mmio + ctl) as *const u8) } & 1 != 0);
        self.w8(ctl, self.r8(ctl) & !1);
        wait_for(|| unsafe { read_volatile((mmio + ctl) as *const u8) } & 1 == 0);
        let pages = len.div_ceil(PAGE_SIZE as usize);
        while self.pages.len() < pages {
            match frame::alloc_zeroed() {
                Some(p) => self.pages.push(p),
                None => return false,
            }
        }
        for &p in &self.pages {
            unsafe { core::ptr::write_bytes(phys_to_virt(p), 0, PAGE_SIZE as usize) };
        }
        let bdl = phys_to_virt(self.bdl) as *mut u32;
        for i in 0..pages {
            let chunk = (len - i * PAGE_SIZE as usize).min(PAGE_SIZE as usize);
            let p = self.pages[i];
            unsafe {
                write_volatile(bdl.add(i * 4), p as u32);
                write_volatile(bdl.add(i * 4 + 1), (p >> 32) as u32);
                write_volatile(bdl.add(i * 4 + 2), chunk as u32);
                write_volatile(bdl.add(i * 4 + 3), 0);
            }
        }
        // A list holds at least two entries: split a single page in two.
        let entries = if pages == 1 {
            let half = (len / 2) & !3;
            unsafe {
                write_volatile(bdl.add(2), half as u32);
                write_volatile(bdl.add(4), self.pages[0] as u32 + half as u32);
                write_volatile(bdl.add(5), (self.pages[0] >> 32) as u32);
                write_volatile(bdl.add(6), (len - half) as u32);
                write_volatile(bdl.add(7), 0);
            }
            2
        } else {
            pages
        };
        self.len = len;
        self.w32(self.sd + SD_BDPL, self.bdl as u32);
        self.w32(self.sd + SD_BDPU, (self.bdl >> 32) as u32);
        self.w32(self.sd + SD_CBL, len as u32);
        self.w16(self.sd + SD_LVI, (entries - 1) as u16);
        self.w16(self.sd + SD_FMT, FORMAT);
        // Stream tag in bits 20..24 of the 24-bit control register.
        self.w8(ctl + 2, (STREAM_TAG << 4) as u8);
        true
    }

    /// Copies `data` into the cyclic buffer at byte `off`.
    pub fn write(&mut self, mut off: usize, data: &[u8]) {
        let mut done = 0;
        while done < data.len() {
            off %= self.len;
            let page = off / PAGE_SIZE as usize;
            let within = off % PAGE_SIZE as usize;
            let n = (data.len() - done)
                .min(PAGE_SIZE as usize - within)
                .min(self.len - off);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data[done..].as_ptr(),
                    phys_to_virt(self.pages[page]).add(within),
                    n,
                )
            };
            done += n;
            off += n;
        }
    }

    /// Zeroes `len` bytes of the cyclic buffer from byte `off`.
    pub fn silence(&mut self, off: usize, len: usize) {
        let zeros = [0u8; 512];
        let mut left = len.min(self.len);
        let mut at = off;
        while left > 0 {
            let n = left.min(zeros.len());
            self.write(at, &zeros[..n]);
            at += n;
            left -= n;
        }
    }

    pub fn start(&mut self) {
        let ctl = self.sd + SD_CTL;
        self.w8(ctl, self.r8(ctl) | 1 << 1);
    }

    pub fn stop(&mut self) {
        let ctl = self.sd + SD_CTL;
        self.w8(ctl, self.r8(ctl) & !(1 << 1));
    }

    /// Where the controller is in the cyclic buffer (bytes).
    pub fn position(&self) -> usize {
        self.r32(self.sd + SD_LPIB) as usize % self.len.max(1)
    }
}

fn init_controller(d: &pci::Device) -> Option<Hda> {
    let Some(Bar::Memory { addr, size }) = d.bar(0) else {
        return None;
    };
    d.enable();
    let mmio = paging::map_device(addr, size.max(0x4000)).ok()?;
    let mut h = Hda {
        mmio,
        corb: frame::alloc_zeroed()?,
        rirb: frame::alloc_zeroed()?,
        corb_wp: 0,
        rirb_rp: 0,
        sd: 0,
        bdl: frame::alloc_zeroed()?,
        pages: Vec::new(),
        len: 0,
        dacs: Vec::new(),
        vendor: 0,
        base: addr,
    };
    // Reset: CRST low, then high; codecs announce themselves in STATESTS.
    h.w32(GCTL, h.r32(GCTL) & !1);
    if !wait_for(|| unsafe { read_volatile((mmio + GCTL) as *const u32) } & 1 == 0) {
        return None;
    }
    h.w32(GCTL, h.r32(GCTL) | 1);
    if !wait_for(|| unsafe { read_volatile((mmio + GCTL) as *const u32) } & 1 == 1) {
        return None;
    }
    crate::time::sleep_ms(2);
    let gcap = h.r16(GCAP) as u64;
    let (iss, oss) = ((gcap >> 8) & 0xf, (gcap >> 12) & 0xf);
    if oss == 0 {
        return None;
    }
    h.sd = 0x80 + iss * 0x20;
    // CORB and RIRB: 256 entries each.
    h.w8(CORBCTL, 0);
    h.w8(RIRBCTL, 0);
    h.w8(CORBSIZE, 0x2);
    h.w8(RIRBSIZE, 0x2);
    h.w32(CORBLBASE, h.corb as u32);
    h.w32(CORBUBASE, (h.corb >> 32) as u32);
    h.w32(RIRBLBASE, h.rirb as u32);
    h.w32(RIRBUBASE, (h.rirb >> 32) as u32);
    h.w16(CORBRP, 1 << 15);
    wait_for(|| unsafe { read_volatile((mmio + CORBRP) as *const u16) } & 1 << 15 != 0);
    h.w16(CORBRP, 0);
    wait_for(|| unsafe { read_volatile((mmio + CORBRP) as *const u16) } & 1 << 15 == 0);
    h.w16(CORBWP, 0);
    h.w16(RIRBWP, 1 << 15);
    h.w16(RINTCNT, 1);
    h.w8(CORBCTL, 1 << 1);
    h.w8(RIRBCTL, 1 << 1);
    let codecs = h.r16(STATESTS);
    for cad in 0..15 {
        if codecs & 1 << cad != 0 {
            h.configure_codec(cad);
        }
    }
    if h.dacs.is_empty() {
        return None;
    }
    Some(h)
}

/// Finds the first HD Audio controller (PCI class 04, subclass 03).
pub fn init() {
    for d in pci::devices() {
        if d.class != 0x04 || d.subclass != 0x03 {
            continue;
        }
        match init_controller(&d) {
            Some(h) => {
                crate::info!(
                    "hda: {:04x}:{:04x} at {:#x}, codec {:08x}, {} DAC(s)",
                    d.vendor,
                    d.device,
                    h.base,
                    h.vendor,
                    h.dacs.len()
                );
                *HDA.lock() = Some(h);
                return;
            }
            None => crate::warn!("hda: {:04x}:{:04x}: no usable codec", d.vendor, d.device),
        }
    }
}
