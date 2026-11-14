//! Directory entries (`ext4_dir_entry` / `ext4_dir_entry_2`).
//!
//! Every directory block is a chain of entries; a linear scan reads all of
//! them. Hashed (htree) directories keep their index in entries a scan
//! skips: the root block's ".." spans the index, and interior index
//! blocks are one empty entry (inode 0) covering the whole block. The
//! `metadata_csum` tail is an entry with inode 0 as well.

use super::{crc, le16, le32, put16, put32};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

/// Where a name is and what it names.
#[derive(Clone, Copy)]
pub struct DirEntry {
    pub ino: u32,
    /// File block holding the entry (`u32::MAX` for inline directories).
    pub lblk: u32,
    /// Byte offset of the entry in that block.
    pub off: u32,
}

pub type DirMap = BTreeMap<Vec<u8>, DirEntry>;

/// Size of the checksum tail entry.
pub const TAIL_LEN: usize = 12;

pub fn rec_len_from_disk(raw: u16, bs: usize) -> usize {
    let raw = raw as usize;
    if bs >= 65536 {
        if raw == 0xffff || raw == 0 {
            65536
        } else {
            (raw & 0xfffc) | ((raw & 3) << 16)
        }
    } else {
        raw
    }
}

pub fn rec_len_to_disk(len: usize, bs: usize) -> u16 {
    if len < 65536 {
        len as u16
    } else if len == bs {
        if bs == 65536 { 0xffff } else { 0 }
    } else {
        ((len & 65532) | ((len >> 16) & 3)) as u16
    }
}

/// Bytes an entry with a name of `n` bytes needs.
pub fn needed(n: usize) -> usize {
    (8 + n + 3) & !3
}

struct Raw {
    ino: u32,
    rec_len: usize,
    name_len: usize,
}

fn entry_at(b: &[u8], off: usize, filetype: bool, bs: usize) -> Option<Raw> {
    if off + 8 > b.len() {
        return None;
    }
    let ino = le32(b, off);
    let rec_len = rec_len_from_disk(le16(b, off + 4), bs);
    let name_len = if filetype {
        b[off + 6] as usize
    } else {
        le16(b, off + 6) as usize
    };
    if rec_len < 8
        || !rec_len.is_multiple_of(4)
        || off + rec_len > b.len()
        || 8 + name_len > rec_len
    {
        return None; // corrupt
    }
    Some(Raw {
        ino,
        rec_len,
        name_len,
    })
}

/// Adds the entries of one block (or inline area) `b` to `out`.
/// `filetype`: entries carry an 8-bit name length and a type byte
/// (INCOMPAT_FILETYPE) instead of a 16-bit name length.
pub fn parse_block(b: &[u8], filetype: bool, bs: usize, lblk: u32, out: &mut DirMap) {
    let mut off = 0usize;
    while let Some(e) = entry_at(b, off, filetype, bs) {
        if e.ino != 0 && e.name_len != 0 {
            out.entry(b[off + 8..off + 8 + e.name_len].to_vec())
                .or_insert(DirEntry {
                    ino: e.ino,
                    lblk,
                    off: off as u32,
                });
        }
        off += e.rec_len;
    }
}

/// Whether the block ends in a checksum tail.
pub fn has_tail(b: &[u8]) -> bool {
    let t = b.len() - TAIL_LEN;
    le32(b, t) == 0 && le16(b, t + 4) == TAIL_LEN as u16 && b[t + 6] == 0 && b[t + 7] == 0xde
}

/// Writes the checksum tail.
pub fn set_tail(b: &mut [u8], seed: u32) {
    let t = b.len() - TAIL_LEN;
    put32(b, t, 0);
    put16(b, t + 4, TAIL_LEN as u16);
    b[t + 6] = 0;
    b[t + 7] = 0xde;
    let c = crc::crc32c(seed, &b[..t]);
    put32(b, t + 8, c);
}

fn put_entry(
    b: &mut [u8],
    off: usize,
    ino: u32,
    rec_len: usize,
    name: &[u8],
    ft: u8,
    filetype: bool,
) {
    let bs = b.len();
    put32(b, off, ino);
    put16(b, off + 4, rec_len_to_disk(rec_len, bs));
    if filetype {
        b[off + 6] = name.len() as u8;
        b[off + 7] = ft;
    } else {
        put16(b, off + 6, name.len() as u16);
    }
    b[off + 8..off + 8 + name.len()].copy_from_slice(name);
}

/// Puts a new entry into free space of block `b` (whose entries end at
/// `end`): the offset it went to, or None if there is no room.
pub fn try_insert(
    b: &mut [u8],
    end: usize,
    name: &[u8],
    ino: u32,
    ft: u8,
    filetype: bool,
) -> Option<usize> {
    let bs = b.len();
    let need = needed(name.len());
    let mut off = 0usize;
    while off < end {
        let e = entry_at(&b[..end], off, filetype, bs)?;
        let used = if e.ino == 0 { 0 } else { needed(e.name_len) };
        if e.rec_len >= used + need {
            if e.ino == 0 {
                put_entry(b, off, ino, e.rec_len, name, ft, filetype);
                return Some(off);
            }
            put16(b, off + 4, rec_len_to_disk(used, bs));
            let new = off + used;
            put_entry(b, new, ino, e.rec_len - used, name, ft, filetype);
            return Some(new);
        }
        off += e.rec_len;
    }
    None
}

/// Removes the entry at `off` from block `b` (whose entries end at `end`):
/// the previous entry takes its space, or, first in the block, its inode
/// becomes 0. False if no entry starts there.
pub fn remove_at(b: &mut [u8], end: usize, off: usize, filetype: bool) -> bool {
    let bs = b.len();
    let mut cur = 0usize;
    let mut prev: Option<(usize, usize)> = None;
    while cur < end {
        let Some(e) = entry_at(&b[..end], cur, filetype, bs) else {
            return false;
        };
        if cur == off {
            match prev {
                Some((p, plen)) => put16(b, p + 4, rec_len_to_disk(plen + e.rec_len, bs)),
                None => put32(b, cur, 0),
            }
            return true;
        }
        prev = Some((cur, e.rec_len));
        cur += e.rec_len;
    }
    false
}

/// Sets the inode (and type) of the entry at `off`.
pub fn set_entry_ino(b: &mut [u8], off: usize, ino: u32, ft: u8, filetype: bool) {
    put32(b, off, ino);
    if filetype {
        b[off + 7] = ft;
    }
}

/// Packs entries into blocks of `bs` bytes (leaving room for a checksum
/// tail if `tail`): the blocks (without tails) and each entry's (block,
/// offset).
pub fn pack(
    entries: &[(Vec<u8>, u32, u8)],
    bs: usize,
    tail: bool,
    filetype: bool,
) -> (Vec<Vec<u8>>, Vec<(u32, u32)>) {
    let end = if tail { bs - TAIL_LEN } else { bs };
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    let mut locs = Vec::new();
    let mut cur = vec![0u8; bs];
    let mut off = 0usize;
    let mut last: Option<usize> = None;
    for (name, ino, ft) in entries {
        let need = needed(name.len());
        if off + need > end {
            if let Some(l) = last {
                put16(&mut cur, l + 4, rec_len_to_disk(end - l, bs));
            }
            blocks.push(core::mem::replace(&mut cur, vec![0u8; bs]));
            off = 0;
        }
        put_entry(&mut cur, off, *ino, need, name, *ft, filetype);
        locs.push((blocks.len() as u32, off as u32));
        last = Some(off);
        off += need;
    }
    match last {
        Some(l) => put16(&mut cur, l + 4, rec_len_to_disk(end - l, bs)),
        None => put16(&mut cur, 4, rec_len_to_disk(end, bs)),
    }
    blocks.push(cur);
    (blocks, locs)
}
