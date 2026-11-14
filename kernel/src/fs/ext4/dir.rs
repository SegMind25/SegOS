//! Directory entries (`ext4_dir_entry` / `ext4_dir_entry_2`).
//!
//! Every directory block is a chain of entries; a linear scan reads all of
//! them. Hashed (htree) directories keep their index in entries a scan
//! skips: the root block's ".." spans the index, and interior index
//! blocks are one empty entry (inode 0) covering the whole block. The
//! `metadata_csum` tail is an entry with inode 0 as well.

use super::le16;
use super::le32;
use alloc::vec::Vec;

pub struct DirEntry {
    pub name: Vec<u8>,
    pub ino: u32,
}

/// Appends the entries of one block (or inline area) `b` to `out`.
/// `filetype`: entries carry an 8-bit name length and a type byte
/// (INCOMPAT_FILETYPE) instead of a 16-bit name length. `big_blocks`:
/// the block size is 64 KiB, so rec_len uses its wide encoding.
pub fn parse_block(b: &[u8], filetype: bool, big_blocks: bool, out: &mut Vec<DirEntry>) {
    let mut off = 0usize;
    while off + 8 <= b.len() {
        let ino = le32(b, off);
        let raw = le16(b, off + 4) as usize;
        let rec_len = if big_blocks {
            if raw == 0xffff || raw == 0 {
                65536
            } else {
                (raw & 0xfffc) | ((raw & 3) << 16)
            }
        } else {
            raw
        };
        let name_len = if filetype {
            b[off + 6] as usize
        } else {
            le16(b, off + 6) as usize
        };
        if rec_len < 8 || rec_len % 4 != 0 || off + rec_len > b.len() || 8 + name_len > rec_len
        {
            break; // corrupt: keep what was read
        }
        if ino != 0 && name_len != 0 {
            out.push(DirEntry {
                name: b[off + 8..off + 8 + name_len].to_vec(),
                ino,
            });
        }
        off += rec_len;
    }
}
