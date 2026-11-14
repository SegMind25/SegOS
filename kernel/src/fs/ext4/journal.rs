//! jbd2 journal replay.
//!
//! A file system that went down with transactions in its journal has
//! `needs_recovery` set. Replay (as jbd2's `jbd2_journal_recover`): scan
//! the log from `s_start` for transactions that reached their commit
//! block, collect their revoke records, then write each logged block to
//! its home location unless a revoke of the same or a later transaction
//! covers it. Then the journal is marked empty and the flag cleared.
//! Checksums (v2/v3) are not verified. Fast-commit journals are refused.

use super::extent;
use super::{Ext4Fs, INCOMPAT_RECOVER, SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE, crc, le32, put32};
use crate::abi::{Errno, KResult};
use crate::block::{read_bytes, write_bytes};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

const JBD2_MAGIC: u32 = 0xc03b_3998;
const BT_DESCRIPTOR: u32 = 1;
const BT_COMMIT: u32 = 2;
const BT_SB_V1: u32 = 3;
const BT_SB_V2: u32 = 4;
const BT_REVOKE: u32 = 5;

const F_REVOKE: u32 = 0x1;
const F_64BIT: u32 = 0x2;
const F_ASYNC_COMMIT: u32 = 0x4;
const F_CSUM_V2: u32 = 0x8;
const F_CSUM_V3: u32 = 0x10;
const KNOWN_INCOMPAT: u32 = F_REVOKE | F_64BIT | F_ASYNC_COMMIT | F_CSUM_V2 | F_CSUM_V3;

const TAG_ESCAPE: u32 = 1;
const TAG_SAME_UUID: u32 = 2;
const TAG_LAST: u32 = 8;

fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn be16(b: &[u8], off: usize) -> u32 {
    u16::from_be_bytes([b[off], b[off + 1]]) as u32
}

/// One logged block: its home, where its copy is in the log, and whether
/// its first word was escaped.
struct Tag {
    home: u64,
    log: u64,
    escaped: bool,
}

struct Transaction {
    seq: u32,
    tags: Vec<Tag>,
}

/// The journal inode's block map: journal block → device block.
struct Log<'a> {
    fs: &'a Ext4Fs,
    extents: Option<Vec<extent::Extent>>,
    raw: super::inode::RawInode,
}

impl Log<'_> {
    fn map(&self, jblk: u64) -> KResult<u64> {
        let p = match &self.extents {
            Some(e) => extent::lookup(e, jblk).0.unwrap_or(0),
            None => self.raw.map_indirect(self.fs, jblk)?.0,
        };
        if p == 0 { Err(Errno::EIO) } else { Ok(p) }
    }

    fn read(&self, jblk: u64, buf: &mut [u8]) -> KResult<()> {
        let p = self.map(jblk)?;
        self.fs.read_direct(p, 0, buf)
    }
}

pub fn replay(fs: &Ext4Fs) -> KResult<()> {
    let jino = fs.sb.journal_inum;
    if jino == 0 {
        return Err(Errno::EINVAL); // external journal
    }
    let raw = fs.read_raw_inode(jino)?;
    let extents = if raw.has_extents() {
        Some(extent::load(fs, &raw.iblock)?.extents)
    } else {
        None
    };
    let log = Log { fs, extents, raw };
    let bs = fs.block_size() as usize;
    let mut jsb = vec![0u8; bs];
    log.read(0, &mut jsb)?;
    let btype = be32(&jsb, 4);
    if be32(&jsb, 0) != JBD2_MAGIC || !(btype == BT_SB_V1 || btype == BT_SB_V2) {
        return Err(Errno::EINVAL);
    }
    if be32(&jsb, 0xc) as usize != bs {
        return Err(Errno::EINVAL);
    }
    let maxlen = be32(&jsb, 0x10) as u64;
    let first = be32(&jsb, 0x14) as u64;
    let mut seq = be32(&jsb, 0x18);
    let start = be32(&jsb, 0x1c) as u64;
    let incompat = if btype == BT_SB_V2 {
        be32(&jsb, 0x28)
    } else {
        0
    };
    if incompat & !KNOWN_INCOMPAT != 0 {
        return Err(Errno::EINVAL); // fast commits, or unknown
    }
    if first == 0 || first >= maxlen {
        return Err(Errno::EINVAL);
    }
    let csum = incompat & (F_CSUM_V2 | F_CSUM_V3) != 0;
    let tag_bytes = if incompat & F_CSUM_V3 != 0 {
        16
    } else {
        let sz = 12 + if incompat & F_CSUM_V2 != 0 { 2 } else { 0 };
        if incompat & F_64BIT != 0 { sz } else { sz - 4 }
    };
    let next = |p: u64| if p + 1 >= maxlen { first } else { p + 1 };

    let mut committed: Vec<Transaction> = Vec::new();
    let mut revoked: BTreeMap<u64, u32> = BTreeMap::new();
    if start != 0 {
        // Pass 1: find the committed transactions and their revokes.
        let mut pos = start;
        let mut cur = Transaction {
            seq,
            tags: Vec::new(),
        };
        let mut cur_revokes: Vec<u64> = Vec::new();
        let mut b = vec![0u8; bs];
        let mut steps = 0u64;
        while steps < maxlen {
            steps += 1;
            if log.read(pos, &mut b).is_err() {
                break;
            }
            if be32(&b, 0) != JBD2_MAGIC || be32(&b, 8) != seq {
                break;
            }
            match be32(&b, 4) {
                BT_DESCRIPTOR => {
                    let end = bs - if csum { 4 } else { 0 };
                    let mut off = 12;
                    let mut lp = next(pos);
                    while off + tag_bytes <= end {
                        let lo = be32(&b, off) as u64;
                        let (flags, hi) = if tag_bytes == 16 {
                            (be32(&b, off + 4), be32(&b, off + 8) as u64)
                        } else {
                            let hi = if tag_bytes >= 12 {
                                be32(&b, off + 8) as u64
                            } else {
                                0
                            };
                            (be16(&b, off + 6), hi)
                        };
                        let hi = if incompat & F_64BIT != 0 { hi } else { 0 };
                        off += tag_bytes;
                        if flags & TAG_SAME_UUID == 0 {
                            off += 16;
                        }
                        cur.tags.push(Tag {
                            home: lo | (hi << 32),
                            log: lp,
                            escaped: flags & TAG_ESCAPE != 0,
                        });
                        lp = next(lp);
                        if flags & TAG_LAST != 0 {
                            break;
                        }
                    }
                    pos = lp;
                    continue;
                }
                BT_COMMIT => {
                    for r in cur_revokes.drain(..) {
                        let e = revoked.entry(r).or_insert(seq);
                        *e = (*e).max(seq);
                    }
                    let done = core::mem::replace(
                        &mut cur,
                        Transaction {
                            seq: seq.wrapping_add(1),
                            tags: Vec::new(),
                        },
                    );
                    committed.push(done);
                    seq = seq.wrapping_add(1);
                }
                BT_REVOKE => {
                    let count = (be32(&b, 12) as usize).min(bs);
                    let rec = if incompat & F_64BIT != 0 { 8 } else { 4 };
                    let mut off = 16;
                    while off + rec <= count {
                        let blk = if rec == 8 {
                            ((be32(&b, off) as u64) << 32) | be32(&b, off + 4) as u64
                        } else {
                            be32(&b, off) as u64
                        };
                        cur_revokes.push(blk);
                        off += rec;
                    }
                }
                _ => break,
            }
            pos = next(pos);
        }
        // Pass 2: replay.
        let mut data = vec![0u8; bs];
        let mut n = 0;
        for t in &committed {
            for tag in &t.tags {
                if revoked.get(&tag.home).is_some_and(|&r| r >= t.seq) {
                    continue;
                }
                if tag.home >= fs.sb.blocks_count {
                    return Err(Errno::EIO);
                }
                log.read(tag.log, &mut data)?;
                if tag.escaped {
                    data[..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
                }
                write_bytes(fs.dev.as_ref(), tag.home * bs as u64, &data)?;
                n += 1;
            }
        }
        crate::info!(
            "ext4: journal: {} transactions, {} blocks replayed",
            committed.len(),
            n
        );
    }
    fs.drop_cache();
    // The journal is empty now; it goes on one past the last transaction
    // seen (as jbd2 and e2fsck do).
    if start != 0 {
        seq = seq.wrapping_add(1);
    }
    jsb[0x18..0x1c].copy_from_slice(&seq.to_be_bytes());
    jsb[0x1c..0x20].copy_from_slice(&0u32.to_be_bytes());
    if csum && btype == BT_SB_V2 {
        jsb[0xfc..0x100].fill(0);
        let c = crc::crc32c(!0, &jsb[..1024]);
        jsb[0xfc..0x100].copy_from_slice(&c.to_be_bytes());
    }
    let p = log.map(0)?;
    write_bytes(fs.dev.as_ref(), p * bs as u64, &jsb)?;
    // And the file system no longer needs recovery (the superblock may
    // have been among the replayed blocks: read it again).
    let mut sb = vec![0u8; SUPERBLOCK_SIZE];
    read_bytes(fs.dev.as_ref(), SUPERBLOCK_OFFSET, &mut sb)?;
    let incompat = le32(&sb, 0x60) & !INCOMPAT_RECOVER;
    put32(&mut sb, 0x60, incompat);
    if fs.metadata_csum() {
        let c = crc::crc32c(!0, &sb[..0x3fc]);
        put32(&mut sb, 0x3fc, c);
    }
    write_bytes(fs.dev.as_ref(), SUPERBLOCK_OFFSET, &sb)?;
    fs.drop_cache();
    Ok(())
}
