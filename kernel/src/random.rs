//! Random bytes for `getrandom`, `/dev/urandom` and `AT_RANDOM`.
//!
//! RDRAND when the CPU has it; otherwise a xorshift generator stirred with
//! the TSC on every call. Good enough for hash seeds and stack canaries,
//! not for keys: a proper entropy pool (interrupt timing, RDSEED, a
//! ChaCha20 output stage, as Linux's) is future work.

use crate::sync::SpinLock;

static STATE: SpinLock<u64> = SpinLock::new(0x5e60_5e60_9e37_79b9);

fn next() -> u64 {
    if let Some(v) = crate::hal::x86::rdrand() {
        return v;
    }
    let mut s = STATE.lock();
    let mut x = *s ^ crate::hal::x86::rdtsc().rotate_left(29);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    x.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

pub fn fill(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(8) {
        chunk.copy_from_slice(&next().to_le_bytes()[..chunk.len()]);
    }
}
