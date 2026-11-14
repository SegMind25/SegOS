//! The Linux x86-64 ABI: error numbers, flags and structure layouts, with
//! the values Linux uses (from its UAPI headers' documented values, not its
//! code). Programs compiled for Linux see exactly these.

/// A Linux error number. System calls return `-errno`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Errno(pub i32);

pub type KResult<T> = Result<T, Errno>;

macro_rules! errnos {
    ($($name:ident = $v:expr),* $(,)?) => {
        impl Errno { $(pub const $name: Errno = Errno($v);)* }
    };
}

errnos! {
    EPERM = 1, ENOENT = 2, ESRCH = 3, EINTR = 4, EIO = 5, ENXIO = 6,
    E2BIG = 7, ENOEXEC = 8, EBADF = 9, ECHILD = 10, EAGAIN = 11, ENOMEM = 12,
    EACCES = 13, EFAULT = 14, EBUSY = 16, EEXIST = 17, EXDEV = 18,
    ENODEV = 19, ENOTDIR = 20, EISDIR = 21, EINVAL = 22, ENFILE = 23,
    EMFILE = 24, ENOTTY = 25, EFBIG = 27, ENOSPC = 28, ESPIPE = 29,
    EROFS = 30, EMLINK = 31, EPIPE = 32, ERANGE = 34, ENAMETOOLONG = 36,
    ENOSYS = 38, ENOTEMPTY = 39, ELOOP = 40, EOPNOTSUPP = 95,
}

/// Open flags (`fcntl.h`).
pub mod open {
    pub const O_ACCMODE: u32 = 0o3;
    pub const O_RDONLY: u32 = 0o0;
    pub const O_WRONLY: u32 = 0o1;
    pub const O_RDWR: u32 = 0o2;
    pub const O_CREAT: u32 = 0o100;
    pub const O_EXCL: u32 = 0o200;
    pub const O_NOCTTY: u32 = 0o400;
    pub const O_TRUNC: u32 = 0o1000;
    pub const O_APPEND: u32 = 0o2000;
    pub const O_NONBLOCK: u32 = 0o4000;
    pub const O_DIRECTORY: u32 = 0o200000;
    pub const O_NOFOLLOW: u32 = 0o400000;
    pub const O_CLOEXEC: u32 = 0o2000000;
    pub const O_PATH: u32 = 0o10000000;
}

/// `openat` and friends: relative to the working directory.
pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
pub const AT_REMOVEDIR: u32 = 0x200;
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// File types in `st_mode`.
pub mod mode {
    pub const S_IFMT: u32 = 0o170000;
    pub const S_IFDIR: u32 = 0o040000;
    pub const S_IFCHR: u32 = 0o020000;
    pub const S_IFREG: u32 = 0o100000;
    pub const S_IFLNK: u32 = 0o120000;
}

/// Memory protection and mapping flags (`sys/mman.h`).
pub mod mman {
    pub const PROT_READ: u32 = 1;
    pub const PROT_WRITE: u32 = 2;
    pub const PROT_EXEC: u32 = 4;
    pub const MAP_SHARED: u32 = 0x01;
    pub const MAP_PRIVATE: u32 = 0x02;
    pub const MAP_FIXED: u32 = 0x10;
    pub const MAP_ANONYMOUS: u32 = 0x20;
    pub const MAP_FIXED_NOREPLACE: u32 = 0x100000;
}

/// `struct stat` on x86-64.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub _pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub _unused: [i64; 3],
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Iovec {
    pub base: u64,
    pub len: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Winsize {
    pub rows: u16,
    pub cols: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

/// `struct utsname`: six 65-byte strings.
#[repr(C)]
pub struct Utsname {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

/// Plain data that may be copied to and from user memory byte for byte.
///
/// # Safety
/// Every bit pattern must be a valid value, and the type must have no
/// padding that could leak kernel memory (or the padding is zeroed).
pub unsafe trait Pod: Copy {}
unsafe impl Pod for u8 {}
unsafe impl Pod for u16 {}
unsafe impl Pod for u32 {}
unsafe impl Pod for u64 {}
unsafe impl Pod for i32 {}
unsafe impl Pod for i64 {}
unsafe impl Pod for Stat {}
unsafe impl Pod for Timespec {}
unsafe impl Pod for Iovec {}
unsafe impl Pod for Winsize {}

pub fn as_bytes<T: Pod>(v: &T) -> &[u8] {
    unsafe { core::slice::from_raw_parts(v as *const T as *const u8, size_of::<T>()) }
}

/// `ioctl` requests on terminals.
pub mod ioctl {
    pub const TCGETS: u32 = 0x5401;
    pub const TCSETS: u32 = 0x5402;
    pub const TCSETSW: u32 = 0x5403;
    pub const TCSETSF: u32 = 0x5404;
    pub const TIOCGPGRP: u32 = 0x540f;
    pub const TIOCSPGRP: u32 = 0x5410;
    pub const TIOCGWINSZ: u32 = 0x5413;
    pub const TIOCSWINSZ: u32 = 0x5414;
}
