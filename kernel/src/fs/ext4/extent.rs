//! Extent trees, held in memory as a sorted list of extents.
//!
//! A file's tree is read once into a list; changes are made to the list,
//! and [`store`] writes the tree back: in the inode if four extents or
//! fewer, else in fully packed leaf and index blocks (the tree's old
//! blocks are reused, more allocated or the surplus freed; blocks whose
//! content did not change are not rewritten).

use super::{Ext4Fs, FsState, crc, le16, le32, put16, put32};
use crate::abi::{Errno, KResult};
use alloc::vec;
use alloc::vec::Vec;

const EXTENT_MAGIC: u16 = 0xf30a;
/// Extent tree depth limit (Linux: 5).
const MAX_DEPTH: u16 = 5;
/// Longest initialised extent; uninitialised ones are one shorter.
const MAX_INIT_LEN: u32 = 32768;
const MAX_UNINIT_LEN: u32 = 32767;
/// Extents in the inode's i_block.
const ROOT_ENTRIES: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Extent {
    pub lblk: u32,
    pub len: u32,
    pub pblk: u64,
    /// Allocated but not written: reads as zeros.
    pub uninit: bool,
}

impl Extent {
    pub fn end(&self) -> u64 {
        self.lblk as u64 + self.len as u64
    }
}

/// A file's extents and the blocks its tree occupies (leaves first, then
/// each index level, left to right).
pub struct Tree {
    pub extents: Vec<Extent>,
    pub blocks: Vec<u64>,
}

/// Reads the whole tree rooted in `iblock`.
pub fn load(fs: &Ext4Fs, iblock: &[u8]) -> KResult<Tree> {
    let mut levels: Vec<Vec<u64>> = Vec::new();
    let mut extents = Vec::new();
    walk(fs, iblock, None, &mut levels, &mut extents, 0)?;
    let mut blocks = Vec::new();
    for l in levels.iter() {
        blocks.extend_from_slice(l);
    }
    // Sorted and non-overlapping, or the tree is corrupt.
    for w in extents.windows(2) {
        if w[0].end() > w[1].lblk as u64 {
            return Err(Errno::EIO);
        }
    }
    Ok(Tree { extents, blocks })
}

fn walk(
    fs: &Ext4Fs,
    node: &[u8],
    parent_depth: Option<u16>,
    levels: &mut Vec<Vec<u64>>,
    out: &mut Vec<Extent>,
    nesting: usize,
) -> KResult<()> {
    if node.len() < 12 || le16(node, 0) != EXTENT_MAGIC || nesting > MAX_DEPTH as usize {
        return Err(Errno::EIO);
    }
    let entries = le16(node, 2) as usize;
    let depth = le16(node, 6);
    if depth > MAX_DEPTH
        || 12 + entries * 12 > node.len()
        || parent_depth.is_some_and(|d| depth + 1 != d)
    {
        return Err(Errno::EIO);
    }
    for i in 0..entries {
        let e = 12 + i * 12;
        if depth == 0 {
            let raw_len = le16(node, e + 4) as u32;
            let (len, uninit) = if raw_len > MAX_INIT_LEN {
                (raw_len - MAX_INIT_LEN, true)
            } else {
                (raw_len, false)
            };
            if len == 0 {
                continue;
            }
            out.push(Extent {
                lblk: le32(node, e),
                len,
                pblk: ((le16(node, e + 6) as u64) << 32) | le32(node, e + 8) as u64,
                uninit,
            });
        } else {
            let child = ((le16(node, e + 8) as u64) << 32) | le32(node, e + 4) as u64;
            let level = depth as usize - 1; // 0 = leaves
            if levels.len() <= level {
                levels.resize(level + 1, Vec::new());
            }
            levels[level].push(child);
            let b = fs.block(child)?;
            walk(fs, &b, Some(depth), levels, out, nesting + 1)?;
        }
    }
    Ok(())
}

/// The extent containing file block `lblk`, or the hole there:
/// (device block if mapped and initialised, length of the run).
pub fn lookup(extents: &[Extent], lblk: u64) -> (Option<u64>, u64) {
    let i = extents.partition_point(|e| e.lblk as u64 <= lblk);
    if i > 0 {
        let e = &extents[i - 1];
        if lblk < e.end() {
            let off = lblk - e.lblk as u64;
            return ((!e.uninit).then_some(e.pblk + off), e.end() - lblk);
        }
    }
    let next = extents.get(i).map_or(1u64 << 32, |e| e.lblk as u64);
    (None, next.max(lblk + 1) - lblk)
}

/// Like [`lookup`], but says whether the block is allocated (initialised
/// or not): (device block, initialised, run).
pub fn lookup_alloc(extents: &[Extent], lblk: u64) -> Option<(u64, bool, u64)> {
    let i = extents.partition_point(|e| e.lblk as u64 <= lblk);
    let e = extents.get(i.checked_sub(1)?)?;
    if lblk < e.end() {
        let off = lblk - e.lblk as u64;
        return Some((e.pblk + off, !e.uninit, e.end() - lblk));
    }
    None
}

/// Takes `[from, to)` out of the list; the pieces removed (with their
/// device blocks) are returned.
pub fn punch(extents: &mut Vec<Extent>, from: u64, to: u64) -> Vec<Extent> {
    let mut removed = Vec::new();
    let mut out = Vec::with_capacity(extents.len() + 1);
    for &e in extents.iter() {
        let (s, t) = (e.lblk as u64, e.end());
        if t <= from || s >= to {
            out.push(e);
            continue;
        }
        if s < from {
            out.push(Extent {
                len: (from - s) as u32,
                ..e
            });
        }
        let cs = s.max(from);
        let ct = t.min(to);
        removed.push(Extent {
            lblk: cs as u32,
            len: (ct - cs) as u32,
            pblk: e.pblk + (cs - s),
            uninit: e.uninit,
        });
        if t > to {
            out.push(Extent {
                lblk: to as u32,
                len: (t - to) as u32,
                pblk: e.pblk + (to - s),
                uninit: e.uninit,
            });
        }
    }
    *extents = out;
    removed
}

/// Maps `[lblk, lblk + len)` to `pblk..` (initialised), replacing what was
/// there, then merges neighbours.
pub fn insert(extents: &mut Vec<Extent>, lblk: u64, len: u64, pblk: u64) {
    punch(extents, lblk, lblk + len);
    let i = extents.partition_point(|e| (e.lblk as u64) < lblk);
    extents.insert(
        i,
        Extent {
            lblk: lblk as u32,
            len: len as u32,
            pblk,
            uninit: false,
        },
    );
    normalize(extents);
}

/// Merges contiguous neighbours and splits extents longer than the format
/// allows.
fn normalize(extents: &mut Vec<Extent>) {
    let mut out: Vec<Extent> = Vec::with_capacity(extents.len());
    for &e in extents.iter() {
        let mut e = e;
        let max = if e.uninit {
            MAX_UNINIT_LEN
        } else {
            MAX_INIT_LEN
        };
        if let Some(last) = out.last_mut()
            && last.end() == e.lblk as u64
            && last.pblk + last.len as u64 == e.pblk
            && last.uninit == e.uninit
            && last.len < max
        {
            let take = (max - last.len).min(e.len);
            last.len += take;
            e.lblk += take;
            e.pblk += take as u64;
            e.len -= take;
        }
        while e.len > 0 {
            let n = e.len.min(max);
            out.push(Extent { len: n, ..e });
            e.lblk += n;
            e.pblk += n as u64;
            e.len -= n;
        }
    }
    *extents = out;
}

fn put_header(b: &mut [u8], entries: usize, max: usize, depth: u16) {
    put16(b, 0, EXTENT_MAGIC);
    put16(b, 2, entries as u16);
    put16(b, 4, max as u16);
    put16(b, 6, depth);
    put32(b, 8, 0);
}

fn put_leaf_entry(b: &mut [u8], i: usize, e: &Extent) {
    let o = 12 + i * 12;
    put32(b, o, e.lblk);
    put16(
        b,
        o + 4,
        e.len as u16 + if e.uninit { MAX_INIT_LEN as u16 } else { 0 },
    );
    put16(b, o + 6, (e.pblk >> 32) as u16);
    put32(b, o + 8, e.pblk as u32);
}

fn put_index_entry(b: &mut [u8], i: usize, lblk: u32, child: u64) {
    let o = 12 + i * 12;
    put32(b, o, lblk);
    put32(b, o + 4, child as u32);
    put16(b, o + 8, (child >> 32) as u16);
    put16(b, o + 10, 0);
}

/// One node of the tree being written.
enum Node {
    Leaf(Vec<Extent>),
    Index(Vec<(u32, usize)>), // (first block, index of the child node)
}

/// Writes `tree.extents` as the tree: the root into `iblock`, other nodes
/// into blocks. Returns the change in the number of tree blocks.
pub fn store(
    fs: &Ext4Fs,
    st: &mut FsState,
    tree: &mut Tree,
    iblock: &mut [u8],
    csum_seed: u32,
    goal: u64,
) -> KResult<i64> {
    let bs = fs.block_size() as usize;
    let cap = (bs - 12) / 12;
    let old = tree.blocks.len() as i64;
    // Build the levels bottom-up: nodes[level] (0 = leaves).
    let ext = &tree.extents;
    let mut nodes: Vec<Node> = Vec::new();
    let mut level_ranges: Vec<(usize, usize)> = Vec::new(); // node index ranges
    if ext.len() > ROOT_ENTRIES {
        let start = nodes.len();
        for chunk in ext.chunks(cap) {
            nodes.push(Node::Leaf(chunk.to_vec()));
        }
        level_ranges.push((start, nodes.len()));
        loop {
            let (s, e) = *level_ranges.last().unwrap();
            if e - s <= ROOT_ENTRIES {
                break;
            }
            let start = nodes.len();
            let children: Vec<(u32, usize)> = (s..e).map(|i| (first_lblk(&nodes, i), i)).collect();
            for chunk in children.chunks(cap) {
                nodes.push(Node::Index(chunk.to_vec()));
            }
            level_ranges.push((start, nodes.len()));
        }
    }
    if level_ranges.len() as u16 > MAX_DEPTH {
        return Err(Errno::EFBIG);
    }
    // Blocks for the nodes: the old ones first.
    let need = nodes.len();
    let mut blocks: Vec<u64> = tree.blocks.iter().copied().take(need).collect();
    let mut next_goal = blocks.last().map_or(goal, |b| b + 1);
    while blocks.len() < need {
        let got = fs.alloc_blocks(st, next_goal, (need - blocks.len()) as u64);
        let (b, n) = match got {
            Ok(r) => r,
            Err(e) => {
                // Nothing written yet: give back what this call took.
                let new = blocks.split_off(tree.blocks.len().min(need));
                let _ = fs.free_block_list(st, new);
                return Err(e);
            }
        };
        for i in 0..n {
            blocks.push(b + i);
        }
        next_goal = b + n;
    }
    if tree.blocks.len() > need {
        let surplus = tree.blocks.split_off(need);
        fs.free_block_list(st, surplus)?;
    }
    // Write the nodes.
    for (i, node) in nodes.iter().enumerate() {
        let mut b = vec![0u8; bs];
        match node {
            Node::Leaf(es) => {
                put_header(&mut b, es.len(), cap, 0);
                for (j, e) in es.iter().enumerate() {
                    put_leaf_entry(&mut b, j, e);
                }
            }
            Node::Index(cs) => {
                let depth = level_of(&level_ranges, i) as u16;
                put_header(&mut b, cs.len(), cap, depth);
                for (j, &(l, c)) in cs.iter().enumerate() {
                    put_index_entry(&mut b, j, l, blocks[c]);
                }
            }
        }
        if fs.metadata_csum() {
            let t = 12 + cap * 12;
            let c = crc::crc32c(csum_seed, &b[..t]);
            put32(&mut b, t, c);
        }
        let same = fs.block(blocks[i]).map(|old| *old == b).unwrap_or(false);
        if !same {
            fs.write_at(blocks[i], 0, &b)?;
        }
    }
    // The root.
    iblock.fill(0);
    match level_ranges.last() {
        None => {
            put_header(iblock, ext.len(), ROOT_ENTRIES, 0);
            for (j, e) in ext.iter().enumerate() {
                put_leaf_entry(iblock, j, e);
            }
        }
        Some(&(s, e)) => {
            put_header(iblock, e - s, ROOT_ENTRIES, level_ranges.len() as u16);
            for (j, i) in (s..e).enumerate() {
                put_index_entry(iblock, j, first_lblk(&nodes, i), blocks[i]);
            }
        }
    }
    tree.blocks = blocks;
    Ok(tree.blocks.len() as i64 - old)
}

fn first_lblk(nodes: &[Node], i: usize) -> u32 {
    match &nodes[i] {
        Node::Leaf(es) => es[0].lblk,
        Node::Index(cs) => cs[0].0,
    }
}

/// The tree level (0 = leaves) of node `i`.
fn level_of(ranges: &[(usize, usize)], i: usize) -> usize {
    ranges
        .iter()
        .position(|&(s, e)| i >= s && i < e)
        .unwrap_or(0)
}

/// An empty tree root (a new file, or after truncation to zero).
pub fn empty_root(iblock: &mut [u8]) {
    iblock.fill(0);
    put_header(iblock, 0, ROOT_ENTRIES, 0);
}
