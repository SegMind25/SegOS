//! DRM/KMS on the framebuffer the firmware set up: `/dev/dri/card0`, as
//! Linux's simpledrm offers it, for Wayland compositors and other KMS
//! programs.
//!
//! One CRTC, one primary plane, one encoder and one connected connector
//! with one mode (the firmware's resolution). Programs draw into dumb
//! buffers (ordinary memory they `mmap`), wrap them in framebuffers, and
//! show one with SETCRTC or PAGE_FLIP; the kernel then copies it to the
//! screen (and again on DIRTYFB). Page flips complete at once and send
//! their event. While a program shows its own picture the text console
//! stays off the screen; when its last file closes, the console returns.
//! Atomic modesetting (properties, blobs and the ATOMIC ioctl) is offered
//! alongside the legacy ioctls; there is no GPU rendering or PRIME.

use crate::abi::{Errno, KResult};
use crate::fs::{FileType, Inode, new_ino, poll};
use crate::mm::vm::AddressSpace;
use crate::mm::{PAGE_SIZE, frame, phys_to_virt};
use crate::sync::{Once, SpinLock};
use crate::task::wait::WaitQueue;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const CRTC: u32 = 0x20;
const ENCODER: u32 = 0x21;
const CONNECTOR: u32 = 0x22;
const PLANE: u32 = 0x23;
const PROP_TYPE: u32 = 0x30;
const PROP_DPMS: u32 = 0x31;
// Atomic properties (DRM_MODE_PROP_* flags in get_property).
const PROP_ACTIVE: u32 = 0x32;
const PROP_MODE_ID: u32 = 0x33;
const PROP_CRTC_ID: u32 = 0x34;
const PROP_FB_ID: u32 = 0x35;
const PROP_SRC_X: u32 = 0x36;
const PROP_SRC_Y: u32 = 0x37;
const PROP_SRC_W: u32 = 0x38;
const PROP_SRC_H: u32 = 0x39;
const PROP_CRTC_X: u32 = 0x3a;
const PROP_CRTC_Y: u32 = 0x3b;
const PROP_CRTC_W: u32 = 0x3c;
const PROP_CRTC_H: u32 = 0x3d;
// DRM_MODE_PROP_* type bits and the hidden-from-legacy atomic bit.
const PROP_RANGE: u32 = 1 << 1;
const PROP_ENUM: u32 = 1 << 3;
const PROP_BLOB: u32 = 1 << 4;
const PROP_OBJECT: u32 = 1 << 6;
const PROP_IMMUTABLE: u32 = 1 << 2;
const PROP_ATOMIC: u32 = 0x8000_0000;
// DRM_MODE_ATOMIC_* flags.
const ATOMIC_TEST_ONLY: u32 = 0x100;
const ATOMIC_NONBLOCK: u32 = 0x200;
const ATOMIC_ALLOW_MODESET: u32 = 0x400;
const PAGE_FLIP_EVENT: u32 = 0x01;
const OBJ_CRTC: u32 = 0xcccc_cccc;
const OBJ_CONNECTOR: u32 = 0xc0c0_c0c0;
const OBJ_PLANE: u32 = 0xeeee_eeee;
const XR24: u32 = 0x3432_5258;
const AR24: u32 = 0x3432_5241;

struct Screen {
    base: u64,
    width: u32,
    height: u32,
    /// Bytes per line.
    pitch: u32,
    /// The firmware's pixels are R, G, B (not B, G, R) in memory.
    rgb: bool,
}

static SCREEN: Once<Screen> = Once::new();
static NEXT_ID: AtomicU32 = AtomicU32::new(0x100);
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// A dumb buffer: pages the program draws into.
struct Buffer {
    width: u32,
    height: u32,
    pitch: u32,
    frames: Vec<u64>,
}

impl Drop for Buffer {
    fn drop(&mut self) {
        for &f in &self.frames {
            frame::free(f);
        }
    }
}

struct Fb {
    buffer: Arc<Buffer>,
    width: u32,
    height: u32,
    pitch: u32,
    offset: u32,
    format: u32,
}

/// What the screen shows: (file id, framebuffer).
static SCANOUT: SpinLock<Option<(u64, Arc<Fb>)>> = SpinLock::new(None);
static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

pub fn init(fb: &bootinfo::Framebuffer) {
    if fb.address == 0 || fb.bpp != 32 {
        return;
    }
    SCREEN.call_once(|| Screen {
        base: fb.address,
        width: fb.width,
        height: fb.height,
        pitch: fb.pitch,
        rgb: fb.format == bootinfo::PixelFormat::Rgbx,
    });
    crate::info!(
        "drm: card0, {}x{} on the firmware framebuffer",
        fb.width,
        fb.height
    );
}

pub fn present() -> bool {
    SCREEN.get().is_some()
}

/// Copies `fb` to the screen.
fn show(fb: &Fb) {
    let Some(s) = SCREEN.get() else { return };
    let w = fb.width.min(s.width) as usize;
    let h = fb.height.min(s.height) as usize;
    let mut row = vec![0u8; w * 4];
    for y in 0..h {
        let mut off = fb.offset as usize + y * fb.pitch as usize;
        let mut done = 0;
        while done < row.len() {
            let page = off / PAGE_SIZE as usize;
            let in_page = off % PAGE_SIZE as usize;
            let n = (PAGE_SIZE as usize - in_page).min(row.len() - done);
            let Some(&phys) = fb.buffer.frames.get(page) else {
                return;
            };
            let src = unsafe { core::slice::from_raw_parts(phys_to_virt(phys).add(in_page), n) };
            row[done..done + n].copy_from_slice(src);
            done += n;
            off += n;
        }
        if s.rgb {
            for p in row.chunks_exact_mut(4) {
                p.swap(0, 2);
            }
        }
        let dst = phys_to_virt(s.base + (y * s.pitch as usize) as u64);
        unsafe { core::ptr::copy_nonoverlapping(row.as_ptr(), dst, row.len()) };
    }
}

fn set_scanout(file: u64, fb: Option<Arc<Fb>>) {
    let mut sc = SCANOUT.lock();
    match fb {
        Some(fb) => {
            crate::console::set_graphics(true);
            show(&fb);
            *sc = Some((file, fb));
        }
        None => {
            if sc.take().is_some() {
                crate::console::set_graphics(false);
            }
        }
    }
}

/// `/dev/dri/card0`.
pub struct CardNode {
    ino: u64,
}

pub fn node() -> Arc<dyn Inode> {
    Arc::new(CardNode { ino: new_ino() })
}

impl Inode for CardNode {
    fn file_type(&self) -> FileType {
        FileType::CharDevice
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        0o666
    }
    fn rdev(&self) -> u64 {
        crate::fs::dev::makedev(226, 0)
    }
    fn seekable(&self) -> bool {
        false
    }
    fn open_fifo(&self, _flags: u32) -> Option<Arc<dyn Inode>> {
        Some(Arc::new(DrmFile {
            id: NEXT_FILE.fetch_add(1, Ordering::Relaxed),
            ino: self.ino,
            st: SpinLock::new(State::default()),
            events: SpinLock::new(VecDeque::new()),
            wait: WaitQueue::new(),
        }))
    }
}

#[derive(Default)]
struct State {
    buffers: BTreeMap<u32, Arc<Buffer>>,
    fbs: BTreeMap<u32, Arc<Fb>>,
    /// Blob properties (notably MODE_ID), keyed by their object id.
    blobs: BTreeMap<u32, Vec<u8>>,
    next_handle: u32,
    universal: bool,
    /// The current atomic state of the CRTC, connector and primary plane.
    crtc_active: bool,
    crtc_mode: u32,
    connector_crtc: u32,
    plane_fb: u32,
    plane_crtc: u32,
}

/// One open file of the card: its buffers, framebuffers and events.
pub struct DrmFile {
    id: u64,
    ino: u64,
    st: SpinLock<State>,
    events: SpinLock<VecDeque<[u8; 32]>>,
    wait: WaitQueue,
}

impl Drop for DrmFile {
    fn drop(&mut self) {
        let mine = SCANOUT.lock().as_ref().is_some_and(|(f, _)| *f == self.id);
        if mine {
            set_scanout(self.id, None);
        }
    }
}

fn mode_info(s: &Screen) -> [u8; 68] {
    let mut m = [0u8; 68];
    let (w, h) = (s.width as u16, s.height as u16);
    let (ht, vt) = (w + 48, h + 9);
    let clock = ht as u32 * vt as u32 * 60 / 1000;
    m[0..4].copy_from_slice(&clock.to_le_bytes());
    for (i, v) in [w, w + 16, w + 32, ht, 0, h, h + 3, h + 6, vt, 0]
        .iter()
        .enumerate()
    {
        m[4 + i * 2..6 + i * 2].copy_from_slice(&v.to_le_bytes());
    }
    m[24..28].copy_from_slice(&60u32.to_le_bytes());
    m[28..32].copy_from_slice(&0xau32.to_le_bytes()); // -hsync, -vsync
    m[32..36].copy_from_slice(&0x48u32.to_le_bytes()); // preferred | driver
    let name = alloc::format!("{w}x{h}");
    m[36..36 + name.len()].copy_from_slice(name.as_bytes());
    m
}

fn r32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn r64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn w32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// Copies `ids` to the user array at `ptr` if it has room for them all
/// (`cap` entries); returns how many there are, as the ioctls report.
fn put_ids(mm: &AddressSpace, ptr: u64, cap: u32, ids: &[u32]) -> KResult<u32> {
    if ptr != 0 && cap as usize >= ids.len() {
        let b: Vec<u8> = ids.iter().flat_map(|i| i.to_le_bytes()).collect();
        mm.copy_to(ptr, &b)?;
    }
    Ok(ids.len() as u32)
}

fn put_u64s(mm: &AddressSpace, ptr: u64, cap: u32, v: &[u64]) -> KResult<u32> {
    if ptr != 0 && cap as usize >= v.len() {
        let b: Vec<u8> = v.iter().flat_map(|i| i.to_le_bytes()).collect();
        mm.copy_to(ptr, &b)?;
    }
    Ok(v.len() as u32)
}

/// What `GETPROPERTY` reports about a property.
struct PropMeta {
    name: &'static str,
    flags: u32,
    values: &'static [u64],
    enums: &'static [(u64, &'static str)],
}

fn prop_meta(id: u32) -> KResult<PropMeta> {
    Ok(match id {
        PROP_TYPE => PropMeta {
            name: "type",
            flags: PROP_ENUM | PROP_IMMUTABLE,
            values: &[],
            enums: &[(0, "Overlay"), (1, "Primary"), (2, "Cursor")],
        },
        PROP_DPMS => PropMeta {
            name: "DPMS",
            flags: PROP_ENUM,
            values: &[],
            enums: &[(0, "On"), (1, "Standby"), (2, "Suspend"), (3, "Off")],
        },
        PROP_ACTIVE => PropMeta {
            name: "ACTIVE",
            flags: PROP_RANGE | PROP_ATOMIC,
            values: &[0, 1],
            enums: &[],
        },
        PROP_MODE_ID => PropMeta {
            name: "MODE_ID",
            flags: PROP_BLOB | PROP_ATOMIC,
            values: &[],
            enums: &[],
        },
        PROP_CRTC_ID => PropMeta {
            name: "CRTC_ID",
            flags: PROP_OBJECT | PROP_ATOMIC,
            values: &[],
            enums: &[],
        },
        PROP_FB_ID => PropMeta {
            name: "FB_ID",
            flags: PROP_OBJECT | PROP_ATOMIC,
            values: &[],
            enums: &[],
        },
        PROP_SRC_X | PROP_SRC_Y | PROP_CRTC_X | PROP_CRTC_Y => PropMeta {
            name: match id {
                PROP_SRC_X => "SRC_X",
                PROP_SRC_Y => "SRC_Y",
                PROP_CRTC_X => "CRTC_X",
                _ => "CRTC_Y",
            },
            flags: PROP_RANGE | PROP_ATOMIC,
            values: &[0, 16384],
            enums: &[],
        },
        PROP_SRC_W | PROP_SRC_H | PROP_CRTC_W | PROP_CRTC_H => PropMeta {
            name: match id {
                PROP_SRC_W => "SRC_W",
                PROP_SRC_H => "SRC_H",
                PROP_CRTC_W => "CRTC_W",
                _ => "CRTC_H",
            },
            flags: PROP_RANGE | PROP_ATOMIC,
            // Widths and heights are 16.16 fixed point.
            values: &[0, (16384u64) << 16],
            enums: &[],
        },
        _ => return Err(Errno::ENOENT),
    })
}

/// Properties attached to each mode object, with their current values.
fn object_props(st: &State, obj_type: u32) -> KResult<(Vec<u32>, Vec<u64>)> {
    Ok(match obj_type {
        OBJ_CRTC => (
            alloc::vec![PROP_ACTIVE, PROP_MODE_ID],
            alloc::vec![st.crtc_active as u64, st.crtc_mode as u64],
        ),
        OBJ_CONNECTOR => (
            alloc::vec![PROP_CRTC_ID, PROP_DPMS],
            alloc::vec![st.connector_crtc as u64, 0],
        ),
        OBJ_PLANE => (
            alloc::vec![
                PROP_TYPE,
                PROP_FB_ID,
                PROP_CRTC_ID,
                PROP_SRC_X,
                PROP_SRC_Y,
                PROP_SRC_W,
                PROP_SRC_H,
                PROP_CRTC_X,
                PROP_CRTC_Y,
                PROP_CRTC_W,
                PROP_CRTC_H,
            ],
            alloc::vec![
                1, // primary plane
                st.plane_fb as u64,
                st.plane_crtc as u64,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        ),
        _ => return Err(Errno::ENOENT),
    })
}

impl DrmFile {
    fn queue_event(&self, ty: u32, user_data: u64) {
        let now = crate::time::monotonic_ns();
        let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed) as u32;
        let mut e = [0u8; 32];
        w32(&mut e, 0, ty);
        w32(&mut e, 4, 32);
        w64(&mut e, 8, user_data);
        w32(&mut e, 16, (now / 1_000_000_000) as u32);
        w32(&mut e, 20, (now % 1_000_000_000 / 1000) as u32);
        w32(&mut e, 24, seq);
        w32(&mut e, 28, CRTC);
        self.events.lock().push_back(e);
        GENERATION.fetch_add(1, Ordering::Relaxed);
        self.wait.wake_all();
        crate::fs::poll_notify();
    }

    fn fb(&self, id: u32) -> KResult<Arc<Fb>> {
        self.st.lock().fbs.get(&id).cloned().ok_or(Errno::ENOENT)
    }

    fn add_fb(
        &self,
        handle: u32,
        width: u32,
        height: u32,
        pitch: u32,
        offset: u32,
        format: u32,
    ) -> KResult<u32> {
        let mut st = self.st.lock();
        let buffer = st.buffers.get(&handle).cloned().ok_or(Errno::ENOENT)?;
        let need = offset as u64 + pitch as u64 * height as u64;
        if width == 0
            || height == 0
            || pitch < width * 4
            || need > buffer.frames.len() as u64 * PAGE_SIZE
        {
            return Err(Errno::EINVAL);
        }
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        st.fbs.insert(
            id,
            Arc::new(Fb {
                buffer,
                width,
                height,
                pitch,
                offset,
                format,
            }),
        );
        Ok(id)
    }

    /// Applies one `DRM_MODE_ATOMIC` transaction: read the property arrays,
    /// validate the whole state, then install it at once (or only validate
    /// it for TEST_ONLY). The geometry is fixed to one full-screen plane,
    /// so those properties are checked but do not change the blit.
    fn atomic(&self, b: &[u8], mm: &AddressSpace) -> KResult<()> {
        let flags = r32(b, 0);
        if flags & !(ATOMIC_TEST_ONLY | ATOMIC_NONBLOCK | ATOMIC_ALLOW_MODESET | PAGE_FLIP_EVENT)
            != 0
        {
            return Err(Errno::EINVAL);
        }
        let nobj = r32(b, 4) as usize;
        if nobj > 64 {
            return Err(Errno::EINVAL);
        }
        let (objs_ptr, counts_ptr) = (r64(b, 8), r64(b, 16));
        let (props_ptr, vals_ptr) = (r64(b, 24), r64(b, 32));
        let user_data = r64(b, 48);

        let mut objs = Vec::with_capacity(nobj);
        let mut counts = Vec::with_capacity(nobj);
        for i in 0..nobj {
            let mut x = [0u8; 4];
            mm.copy_from(objs_ptr + i as u64 * 4, &mut x)?;
            objs.push(u32::from_le_bytes(x));
            mm.copy_from(counts_ptr + i as u64 * 4, &mut x)?;
            counts.push(u32::from_le_bytes(x));
        }
        let total: usize = counts.iter().map(|&c| c as usize).sum();
        if total > 256 {
            return Err(Errno::EINVAL);
        }
        let mut props = Vec::with_capacity(total);
        let mut values = Vec::with_capacity(total);
        for i in 0..total {
            let mut p = [0u8; 4];
            mm.copy_from(props_ptr + i as u64 * 4, &mut p)?;
            props.push(u32::from_le_bytes(p));
            let mut v = [0u8; 8];
            mm.copy_from(vals_ptr + i as u64 * 8, &mut v)?;
            values.push(u64::from_le_bytes(v));
        }

        let mut st = self.st.lock();
        let (mut active, mut mode, mut conn_crtc, mut plane_fb, mut plane_crtc) = (
            st.crtc_active,
            st.crtc_mode,
            st.connector_crtc,
            st.plane_fb,
            st.plane_crtc,
        );
        let mut i = 0;
        for (j, &obj) in objs.iter().enumerate() {
            for _ in 0..counts[j] {
                let (prop, val) = (props[i], values[i]);
                i += 1;
                match (obj, prop) {
                    (CRTC, PROP_ACTIVE) => {
                        if val > 1 {
                            return Err(Errno::EINVAL);
                        }
                        active = val != 0;
                    }
                    (CRTC, PROP_MODE_ID) => {
                        let id = u32::try_from(val).map_err(|_| Errno::EINVAL)?;
                        if id != 0 && !st.blobs.contains_key(&id) {
                            return Err(Errno::ENOENT);
                        }
                        mode = id;
                    }
                    (CONNECTOR, PROP_CRTC_ID) | (PLANE, PROP_CRTC_ID) => {
                        if val != 0 && val != CRTC as u64 {
                            return Err(Errno::EINVAL);
                        }
                        if obj == CONNECTOR {
                            conn_crtc = val as u32;
                        } else {
                            plane_crtc = val as u32;
                        }
                    }
                    (PLANE, PROP_FB_ID) => {
                        let id = u32::try_from(val).map_err(|_| Errno::EINVAL)?;
                        if id != 0 && !st.fbs.contains_key(&id) {
                            return Err(Errno::ENOENT);
                        }
                        plane_fb = id;
                    }
                    (
                        PLANE,
                        PROP_SRC_X | PROP_SRC_Y | PROP_SRC_W | PROP_SRC_H | PROP_CRTC_X
                        | PROP_CRTC_Y | PROP_CRTC_W | PROP_CRTC_H,
                    ) => {
                        if val > (16384u64) << 16 {
                            return Err(Errno::EINVAL);
                        }
                    }
                    _ => return Err(Errno::EINVAL),
                }
            }
        }
        if flags & ATOMIC_TEST_ONLY != 0 {
            return Ok(());
        }
        // Legacy and atomic endpoints share the scanout: the atomic state
        // now describes what SETCRTC/PAGE_FLIP report too.
        st.crtc_active = active;
        st.crtc_mode = mode;
        st.connector_crtc = conn_crtc;
        st.plane_fb = plane_fb;
        st.plane_crtc = plane_crtc;
        drop(st);
        if active && plane_fb != 0 {
            let fb = self.fb(plane_fb)?;
            set_scanout(self.id, Some(fb));
        } else if !active {
            set_scanout(self.id, None);
        }
        if flags & PAGE_FLIP_EVENT != 0 {
            self.queue_event(2, user_data);
        }
        Ok(())
    }

    fn handle(&self, nr: u32, b: &mut [u8], mm: &AddressSpace) -> KResult<()> {
        let s = SCREEN.get().ok_or(Errno::ENODEV)?;
        match nr {
            0x00 => {
                // VERSION
                w32(b, 0, 1);
                w32(b, 4, 0);
                w32(b, 8, 0);
                for (i, text) in [
                    &b"simpledrm"[..],
                    b"20200625",
                    b"DRM over the firmware framebuffer",
                ]
                .iter()
                .enumerate()
                {
                    let o = 16 + i * 16;
                    let cap = r64(b, o) as usize;
                    let ptr = r64(b, o + 8);
                    if ptr != 0 && cap > 0 {
                        mm.copy_to(ptr, &text[..text.len().min(cap)])?;
                    }
                    w64(b, o, text.len() as u64);
                }
            }
            0x01 | 0x02 => {
                // GET_UNIQUE / GET_MAGIC: empty.
                if nr == 0x02 {
                    w32(b, 0, 1);
                } else {
                    w64(b, 0, 0);
                }
            }
            0x09 => {
                // GEM_CLOSE
                self.st
                    .lock()
                    .buffers
                    .remove(&r32(b, 0))
                    .ok_or(Errno::EINVAL)?;
            }
            0x0c => {
                let v = match r64(b, 0) {
                    0x1 => 1,        // DUMB_BUFFER
                    0x3 => 24,       // DUMB_PREFERRED_DEPTH
                    0x6 => 1,        // TIMESTAMP_MONOTONIC
                    0x8 | 0x9 => 64, // CURSOR_WIDTH/HEIGHT
                    0x12 => 1,       // CRTC_IN_VBLANK_EVENT
                    0x2 | 0x4 | 0x5 | 0x7 | 0x10 | 0x11 | 0x13 | 0x14 | 0x15 => 0,
                    _ => return Err(Errno::EINVAL),
                };
                w64(b, 8, v);
            }
            0x0d => match r64(b, 0) {
                1 | 4 => {}
                2 => self.st.lock().universal = r64(b, 8) != 0,
                3 => {
                    // DRM_CLIENT_CAP_ATOMIC
                    if r64(b, 8) > 1 {
                        return Err(Errno::EINVAL);
                    }
                }
                _ => return Err(Errno::EINVAL),
            },
            0x11 | 0x1e | 0x1f => {} // AUTH_MAGIC, SET_MASTER, DROP_MASTER
            0x3a => {
                // WAIT_VBLANK: answer with the current count and time.
                let ty = r32(b, 0);
                let now = crate::time::monotonic_ns();
                if ty & 0x0400_0000 != 0 {
                    self.queue_event(1, r64(b, 8));
                }
                w32(b, 4, SEQUENCE.load(Ordering::Relaxed) as u32);
                w64(b, 8, now / 1_000_000_000);
                w64(b, 16, now % 1_000_000_000 / 1000);
            }
            0x3b => {
                // CRTC_GET_SEQUENCE
                w32(b, 4, 1);
                w64(b, 8, SEQUENCE.load(Ordering::Relaxed));
                w64(b, 16, crate::time::monotonic_ns());
            }
            0xa0 => {
                // GETRESOURCES
                let fbs: Vec<u32> = self.st.lock().fbs.keys().copied().collect();
                let n = put_ids(mm, r64(b, 0), r32(b, 32), &fbs)?;
                w32(b, 32, n);
                let n = put_ids(mm, r64(b, 8), r32(b, 36), &[CRTC])?;
                w32(b, 36, n);
                let n = put_ids(mm, r64(b, 16), r32(b, 40), &[CONNECTOR])?;
                w32(b, 40, n);
                let n = put_ids(mm, r64(b, 24), r32(b, 44), &[ENCODER])?;
                w32(b, 44, n);
                for (i, v) in [1, s.width, 1, s.height].iter().enumerate() {
                    w32(b, 48 + i * 4, *v);
                }
            }
            0xa1 => {
                // GETCRTC
                if r32(b, 12) != CRTC {
                    return Err(Errno::ENOENT);
                }
                let sc = SCANOUT.lock();
                let fb_id = match &*sc {
                    Some((f, fb)) if *f == self.id => self
                        .st
                        .lock()
                        .fbs
                        .iter()
                        .find(|(_, x)| Arc::ptr_eq(x, fb))
                        .map_or(0, |(id, _)| *id),
                    _ => 0,
                };
                w32(b, 16, fb_id);
                w32(b, 20, 0);
                w32(b, 24, 0);
                w32(b, 28, 0);
                w32(b, 32, sc.is_some() as u32);
                b[36..104].copy_from_slice(&mode_info(s));
            }
            0xa2 => {
                // SETCRTC
                if r32(b, 12) != CRTC {
                    return Err(Errno::ENOENT);
                }
                let fb_id = r32(b, 16);
                if fb_id == 0 || r32(b, 32) == 0 {
                    set_scanout(self.id, None);
                } else {
                    let fb = self.fb(fb_id)?;
                    set_scanout(self.id, Some(fb));
                }
            }
            0xa3 | 0xbb => return Err(Errno::ENXIO), // no cursor plane
            0xa4 | 0xa5 => {}                        // gamma: size 0
            0xa6 => {
                if r32(b, 0) != ENCODER {
                    return Err(Errno::ENOENT);
                }
                w32(b, 4, 0); // DRM_MODE_ENCODER_NONE
                w32(b, 8, CRTC);
                w32(b, 12, 1);
                w32(b, 16, 0);
            }
            0xa7 => {
                // GETCONNECTOR
                if r32(b, 48) != CONNECTOR {
                    return Err(Errno::ENOENT);
                }
                let n = put_ids(mm, r64(b, 0), r32(b, 40), &[ENCODER])?;
                w32(b, 40, n);
                if r64(b, 8) != 0 && r32(b, 32) >= 1 {
                    mm.copy_to(r64(b, 8), &mode_info(s))?;
                }
                w32(b, 32, 1);
                let n = put_ids(mm, r64(b, 16), r32(b, 36), &[PROP_DPMS])?;
                put_u64s(mm, r64(b, 24), r32(b, 36), &[0])?;
                w32(b, 36, n);
                w32(b, 44, ENCODER);
                w32(b, 52, 15); // DRM_MODE_CONNECTOR_VIRTUAL
                w32(b, 56, 1);
                w32(b, 60, 1); // connected
                w32(b, 64, s.width * 254 / 960);
                w32(b, 68, s.height * 254 / 960);
                w32(b, 72, 1); // subpixel unknown
            }
            0xaa => {
                // GETPROPERTY
                let meta = prop_meta(r32(b, 16))?;
                w32(b, 20, meta.flags);
                b[24..56].fill(0);
                b[24..24 + meta.name.len()].copy_from_slice(meta.name.as_bytes());
                let n = put_u64s(mm, r64(b, 0), r32(b, 56), meta.values)?;
                w32(b, 56, n);
                if !meta.enums.is_empty()
                    && r64(b, 8) != 0
                    && r32(b, 60) as usize >= meta.enums.len()
                {
                    let mut blob = Vec::new();
                    for (v, name) in meta.enums {
                        blob.extend_from_slice(&v.to_le_bytes());
                        let mut nm = [0u8; 32];
                        nm[..name.len()].copy_from_slice(name.as_bytes());
                        blob.extend_from_slice(&nm);
                    }
                    mm.copy_to(r64(b, 8), &blob)?;
                }
                w32(b, 60, meta.enums.len() as u32);
            }
            0xab => {} // legacy SETPROPERTY: ignore
            0xba => {
                // OBJ_SETPROPERTY: legacy single-property setter, kept in
                // sync with the atomic state.
                let value = r64(b, 0);
                let prop = r32(b, 8);
                let obj = r32(b, 12);
                let mut st = self.st.lock();
                match (obj, prop) {
                    (CRTC, PROP_ACTIVE) => {
                        if value > 1 {
                            return Err(Errno::EINVAL);
                        }
                        st.crtc_active = value != 0;
                    }
                    (CRTC, PROP_MODE_ID) => {
                        let id = u32::try_from(value).map_err(|_| Errno::EINVAL)?;
                        if id != 0 && !st.blobs.contains_key(&id) {
                            return Err(Errno::ENOENT);
                        }
                        st.crtc_mode = id;
                    }
                    (CONNECTOR, PROP_CRTC_ID) | (PLANE, PROP_CRTC_ID) => {
                        if value != 0 && value != CRTC as u64 {
                            return Err(Errno::EINVAL);
                        }
                        if obj == CONNECTOR {
                            st.connector_crtc = value as u32;
                        } else {
                            st.plane_crtc = value as u32;
                        }
                    }
                    (PLANE, PROP_FB_ID) => {
                        let id = u32::try_from(value).map_err(|_| Errno::EINVAL)?;
                        if id != 0 && !st.fbs.contains_key(&id) {
                            return Err(Errno::ENOENT);
                        }
                        st.plane_fb = id;
                    }
                    _ if prop == PROP_DPMS && value <= 3 => {}
                    _ => return Err(Errno::EINVAL),
                }
            }
            0xad => {
                // GETFB
                let fb = self.fb(r32(b, 0))?;
                w32(b, 4, fb.width);
                w32(b, 8, fb.height);
                w32(b, 12, fb.pitch);
                w32(b, 16, 32);
                w32(b, 20, 24);
                w32(b, 24, 0);
            }
            0xae => {
                // ADDFB
                if r32(b, 16) != 32 {
                    return Err(Errno::EINVAL);
                }
                let id = self.add_fb(r32(b, 24), r32(b, 4), r32(b, 8), r32(b, 12), 0, XR24)?;
                w32(b, 0, id);
            }
            0xaf | 0xd0 => {
                // RMFB, CLOSEFB
                let id = r32(b, 0);
                let fb = self.st.lock().fbs.remove(&id).ok_or(Errno::ENOENT)?;
                let showing = SCANOUT
                    .lock()
                    .as_ref()
                    .is_some_and(|(f, x)| *f == self.id && Arc::ptr_eq(x, &fb));
                if showing && nr == 0xaf {
                    set_scanout(self.id, None);
                }
            }
            0xb0 => {
                // PAGE_FLIP
                if r32(b, 0) != CRTC {
                    return Err(Errno::ENOENT);
                }
                let fb = self.fb(r32(b, 4))?;
                set_scanout(self.id, Some(fb));
                if r32(b, 8) & 1 != 0 {
                    self.queue_event(2, r64(b, 16));
                }
            }
            0xb1 => {
                // DIRTYFB
                let fb = self.fb(r32(b, 0))?;
                if let Some((_, x)) = &*SCANOUT.lock()
                    && Arc::ptr_eq(x, &fb)
                {
                    show(&fb);
                }
            }
            0xb2 => {
                // CREATE_DUMB
                let (h, w, bpp) = (r32(b, 0), r32(b, 4), r32(b, 8));
                if w == 0 || h == 0 || w > 16384 || h > 16384 || bpp == 0 || bpp > 32 {
                    return Err(Errno::EINVAL);
                }
                let pitch = (w * bpp.div_ceil(8)).next_multiple_of(64);
                let size = (pitch as u64 * h as u64).next_multiple_of(PAGE_SIZE);
                let mut frames = Vec::with_capacity((size / PAGE_SIZE) as usize);
                for _ in 0..size / PAGE_SIZE {
                    match frame::alloc_zeroed() {
                        Some(f) => frames.push(f),
                        None => {
                            frames.into_iter().for_each(frame::free);
                            return Err(Errno::ENOMEM);
                        }
                    }
                }
                let mut st = self.st.lock();
                st.next_handle += 1;
                let handle = st.next_handle;
                st.buffers.insert(
                    handle,
                    Arc::new(Buffer {
                        width: w,
                        height: h,
                        pitch,
                        frames,
                    }),
                );
                w32(b, 16, handle);
                w32(b, 20, pitch);
                w64(b, 24, size);
            }
            0xb3 => {
                // MAP_DUMB: the mmap offset names the buffer.
                let h = r32(b, 0);
                if !self.st.lock().buffers.contains_key(&h) {
                    return Err(Errno::ENOENT);
                }
                w64(b, 8, (h as u64) << 32);
            }
            0xb4 => {
                self.st
                    .lock()
                    .buffers
                    .remove(&r32(b, 0))
                    .ok_or(Errno::ENOENT)?;
            }
            0xb5 => {
                // GETPLANERESOURCES
                let planes: &[u32] = if self.st.lock().universal {
                    &[PLANE]
                } else {
                    &[]
                };
                let n = put_ids(mm, r64(b, 0), r32(b, 8), planes)?;
                w32(b, 8, n);
            }
            0xb6 => {
                // GETPLANE
                if r32(b, 0) != PLANE {
                    return Err(Errno::ENOENT);
                }
                let showing = SCANOUT.lock().as_ref().is_some_and(|(f, _)| *f == self.id);
                w32(b, 4, if showing { CRTC } else { 0 });
                w32(b, 8, 0);
                w32(b, 12, 1);
                w32(b, 16, 0);
                let n = put_ids(mm, r64(b, 24), r32(b, 20), &[XR24, AR24])?;
                w32(b, 20, n);
            }
            0xb7 => {
                // SETPLANE on the primary plane: show that framebuffer.
                if r32(b, 0) != PLANE {
                    return Err(Errno::EINVAL);
                }
                match r32(b, 8) {
                    0 => set_scanout(self.id, None),
                    id => {
                        let fb = self.fb(id)?;
                        set_scanout(self.id, Some(fb));
                    }
                }
            }
            0xb8 => {
                // ADDFB2
                let format = r32(b, 12);
                if !matches!(format, XR24 | AR24) || r32(b, 16) & 2 != 0 && r64(b, 72) != 0 {
                    return Err(Errno::EINVAL);
                }
                let id = self.add_fb(
                    r32(b, 20),
                    r32(b, 4),
                    r32(b, 8),
                    r32(b, 36),
                    r32(b, 52),
                    format,
                )?;
                w32(b, 0, id);
            }
            0xb9 => {
                // OBJ_GETPROPERTIES
                let (ids, vals) = object_props(&self.st.lock(), r32(b, 24))?;
                let n = put_ids(mm, r64(b, 0), r32(b, 16), &ids)?;
                put_u64s(mm, r64(b, 8), r32(b, 16), &vals)?;
                w32(b, 16, n);
            }
            0xac => {
                // GETPROPBLOB
                let st = self.st.lock();
                let blob = st.blobs.get(&r32(b, 0)).ok_or(Errno::ENOENT)?;
                let cap = r32(b, 4) as usize;
                w32(b, 4, blob.len() as u32);
                if r64(b, 8) != 0 && cap >= blob.len() {
                    mm.copy_to(r64(b, 8), blob)?;
                }
            }
            0xbc => self.atomic(b, mm)?,
            0xbd => {
                // CREATEPROPBLOB
                let len = r32(b, 8) as usize;
                if len > 65536 {
                    return Err(Errno::EINVAL);
                }
                let mut data = vec![0u8; len];
                mm.copy_from(r64(b, 0), &mut data)?;
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                self.st.lock().blobs.insert(id, data);
                w32(b, 12, id);
            }
            0xbe => {
                // DESTROYPROPBLOB
                let id = r32(b, 0);
                self.st.lock().blobs.remove(&id).ok_or(Errno::ENOENT)?;
            }
            0xce => {
                // GETFB2
                let fb = self.fb(r32(b, 0))?;
                w32(b, 4, fb.width);
                w32(b, 8, fb.height);
                w32(b, 12, fb.format);
                w32(b, 36, fb.pitch);
            }
            _ => return Err(Errno::EINVAL),
        }
        Ok(())
    }

    fn buffer_frames(&self, off: u64, pages: u64) -> KResult<Vec<u64>> {
        let st = self.st.lock();
        let buf = st.buffers.get(&((off >> 32) as u32)).ok_or(Errno::EINVAL)?;
        let first = ((off & 0xffff_ffff) / PAGE_SIZE) as usize;
        let end = first + pages as usize;
        if end > buf.frames.len() {
            return Err(Errno::EINVAL);
        }
        let _ = (buf.width, buf.height, buf.pitch);
        Ok(buf.frames[first..end].to_vec())
    }
}

impl Inode for DrmFile {
    fn file_type(&self) -> FileType {
        FileType::CharDevice
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn perm(&self) -> u32 {
        0o666
    }
    fn rdev(&self) -> u64 {
        crate::fs::dev::makedev(226, 0)
    }
    fn seekable(&self) -> bool {
        false
    }
    fn read_stream(&self, buf: &mut [u8], nonblock: bool) -> KResult<usize> {
        loop {
            {
                let mut q = self.events.lock();
                let mut n = 0;
                while n + 32 <= buf.len() {
                    let Some(e) = q.pop_front() else { break };
                    buf[n..n + 32].copy_from_slice(&e);
                    n += 32;
                }
                if n > 0 {
                    return Ok(n);
                }
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            self.wait
                .wait_interruptible(|| !self.events.lock().is_empty())?;
        }
    }
    fn poll(&self) -> u16 {
        poll::POLLOUT
            | if self.events.lock().is_empty() {
                0
            } else {
                poll::POLLIN
            }
    }
    fn poll_generation(&self) -> u64 {
        GENERATION.load(Ordering::Relaxed)
    }
    fn ioctl(&self, req: u32, arg: u64, mm: &AddressSpace) -> KResult<u64> {
        if (req >> 8) & 0xff != b'd' as u32 {
            return Err(Errno::ENOTTY);
        }
        let size = ((req >> 16) & 0x3fff) as usize;
        let mut b = vec![0u8; size.max(128)];
        if size > 0 {
            mm.copy_from(arg, &mut b[..size])?;
        }
        self.handle(req & 0xff, &mut b, mm)?;
        if size > 0 && req >> 30 & 2 != 0 {
            mm.copy_to(arg, &b[..size])?;
        }
        Ok(0)
    }
    fn mmap_frames(&self, off: u64, pages: u64) -> Option<KResult<Vec<u64>>> {
        Some(self.buffer_frames(off, pages))
    }
}
