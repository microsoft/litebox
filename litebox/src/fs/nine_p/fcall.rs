// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! 9P2000.L protocol message definitions and encoding/decoding
//!
//! This module implements the 9P2000.L protocol used for network filesystem access.
//! See <https://9p.io/sys/man/5/intro> and <https://github.com/chaos/diod/blob/master/protocol.md>

use core::fmt::Display;

use super::transport::{self, Write};
use alloc::{borrow::Cow, vec::Vec};
use bitflags::bitflags;

/// File identifier type
pub(super) type Fid = u32;

/// Special tag which `Tversion`/`Rversion` must use as `tag`
pub(super) const NOTAG: u16 = !0;

/// Special value which `Tattach` with no auth must use as `afid`
///
/// If the client does not wish to authenticate the connection, or knows that authentication is
/// not required, the afid field in the attach message should be set to `NOFID`
pub(super) const NOFID: u32 = !0;

/// Special uid which `Tauth`/`Tattach` use as `n_uname` to indicate no uid is specified
pub(super) const NONUNAME: u32 = !0;

/// Room for `Twrite`/`Rread` header
///
/// size\[4\] Tread/Twrite\[2\] tag\[2\] fid\[4\] offset\[8\] count\[4\]
pub(super) const IOHDRSZ: u32 = 24;

/// Room for readdir header
pub(super) const READDIRHDRSZ: u32 = 24;

/// Maximum elements in a single walk.
pub(super) const MAXWELEM: usize = 13;

bitflags! {
    /// Flags passed to Tlopen.
    ///
    /// Same as Linux's open flags.
    /// https://elixir.bootlin.com/linux/v6.12/source/include/net/9p/9p.h#L263
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct LOpenFlags: u32 {
        const O_RDONLY    = 0;
        const O_WRONLY    = 1;
        const O_RDWR    = 2;

        const O_CREAT = 0o100;
        const O_EXCL = 0o200;
        const O_NOCTTY = 0o400;
        const O_TRUNC = 0o1000;
        const O_APPEND = 0o2000;
        const O_NONBLOCK = 0o4000;
        const O_DSYNC = 0o10000;
        const FASYNC = 0o20000;
        const O_DIRECT = 0o40000;
        const O_LARGEFILE = 0o100000;
        const O_DIRECTORY = 0o200000;
        const O_NOFOLLOW = 0o400000;
        const O_NOATIME = 0o1000000;
        const O_CLOEXEC = 0o2000000;
        const O_SYNC = 0o4000000;
    }
}

bitflags! {
    /// File lock type, Flock.typ
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct LockType: u8 {
        const RDLOCK    = 0;
        const WRLOCK    = 1;
        const UNLOCK    = 2;
    }
}

bitflags! {
    /// File lock flags, Flock.flags
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct LockFlag: u32 {
        /// Blocking request
        const BLOCK     = 1;
        /// Reserved for future use
        const RECLAIM   = 2;
    }
}

bitflags! {
    /// File lock status
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct LockStatus: u8 {
        const SUCCESS   = 0;
        const BLOCKED   = 1;
        const ERROR     = 2;
        const GRACE     = 3;
    }
}

bitflags! {
    /// Bits in Qid.typ
    ///
    /// QidType can be constructed from std::fs::FileType via From trait
    ///
    /// # Protocol
    /// 9P2000/9P2000.L
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(super) struct QidType: u8 {
        /// Type bit for directories
        const DIR       = 0x80;
        /// Type bit for append only files
        const APPEND    = 0x40;
        /// Type bit for exclusive use files
        const EXCL      = 0x20;
        /// Type bit for mounted channel
        const MOUNT     = 0x10;
        /// Type bit for authentication file
        const AUTH      = 0x08;
        /// Type bit for not-backed-up file
        const TMP       = 0x04;
        /// Type bits for symbolic links (9P2000.u)
        const SYMLINK   = 0x02;
        /// Type bits for hard-link (9P2000.u)
        const LINK      = 0x01;
        /// Plain file
        const FILE      = 0x00;
    }
}

bitflags! {
    /// Bits in `mask` and `valid` of `Tgetattr` and `Rgetattr`.
    ///
    /// # Protocol
    /// 9P2000.L
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct GetattrMask: u64 {
        const MODE          = 0x00000001;
        const NLINK         = 0x00000002;
        const UID           = 0x00000004;
        const GID           = 0x00000008;
        const RDEV          = 0x00000010;
        const ATIME         = 0x00000020;
        const MTIME         = 0x00000040;
        const CTIME         = 0x00000080;
        const INO           = 0x00000100;
        const SIZE          = 0x00000200;
        const BLOCKS        = 0x00000400;

        const BTIME         = 0x00000800;
        const GEN           = 0x00001000;
        const DATA_VERSION  = 0x00002000;

        /// Mask for fields up to BLOCKS
        const BASIC         = 0x000007ff;
        /// Mask for All fields above
        const ALL           = 0x00003fff;
    }
}

bitflags! {
    /// Bits in `mask` of `Tsetattr`.
    ///
    /// If a time bit is set without the corresponding SET bit, the current
    /// system time on the server is used instead of the value sent in the request.
    ///
    /// # Protocol
    /// 9P2000.L
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct SetattrMask: u32 {
        const MODE      = 0x00000001;
        const UID       = 0x00000002;
        const GID       = 0x00000004;
        const SIZE      = 0x00000008;
        const ATIME     = 0x00000010;
        const MTIME     = 0x00000020;
        const CTIME     = 0x00000040;
        const ATIME_SET = 0x00000080;
        const MTIME_SET = 0x00000100;
    }
}

/// String type used in 9P protocol messages
pub(super) type FcallStr<'a> = Cow<'a, [u8]>;

/// Directory entry data container
#[derive(Clone, Debug)]
pub(super) struct DirEntryData<'a> {
    pub(super) data: Vec<DirEntry<'a>>,
}

impl<'a> DirEntryData<'a> {
    /// Create directory entry data from a vector
    fn with(v: Vec<DirEntry<'a>>) -> DirEntryData<'a> {
        DirEntryData { data: v }
    }

    /// Calculate the total size of all entries
    fn size(&self) -> u64 {
        self.data.iter().fold(0, |a, e| a + e.size())
    }
}

/// 9P message types
#[derive(Copy, Clone, Debug)]
enum FcallType {
    // 9P2000.L
    Rlerror = 7,
    Tstatfs = 8,
    Rstatfs = 9,
    Tlopen = 12,
    Rlopen = 13,
    Tlcreate = 14,
    Rlcreate = 15,
    Tsymlink = 16,
    Rsymlink = 17,
    Tmknod = 18,
    Rmknod = 19,
    Trename = 20,
    Rrename = 21,
    Treadlink = 22,
    Rreadlink = 23,
    Tgetattr = 24,
    Rgetattr = 25,
    Tsetattr = 26,
    Rsetattr = 27,
    Txattrwalk = 30,
    Rxattrwalk = 31,
    Txattrcreate = 32,
    Rxattrcreate = 33,
    Treaddir = 40,
    Rreaddir = 41,
    Tfsync = 50,
    Rfsync = 51,
    Tlock = 52,
    Rlock = 53,
    Tgetlock = 54,
    Rgetlock = 55,
    Tlink = 70,
    Rlink = 71,
    Tmkdir = 72,
    Rmkdir = 73,
    Trenameat = 74,
    Rrenameat = 75,
    Tunlinkat = 76,
    Runlinkat = 77,

    // 9P2000
    Tversion = 100,
    Rversion = 101,
    Tauth = 102,
    Rauth = 103,
    Tattach = 104,
    Rattach = 105,
    Tflush = 108,
    Rflush = 109,
    Twalk = 110,
    Rwalk = 111,
    Tread = 116,
    Rread = 117,
    Twrite = 118,
    Rwrite = 119,
    Tclunk = 120,
    Rclunk = 121,
    Tremove = 122,
    Rremove = 123,
}

impl FcallType {
    /// Convert a u8 to FcallType
    fn from_u8(v: u8) -> Option<FcallType> {
        match v {
            // 9P2000.L
            7 => Some(FcallType::Rlerror),
            8 => Some(FcallType::Tstatfs),
            9 => Some(FcallType::Rstatfs),
            12 => Some(FcallType::Tlopen),
            13 => Some(FcallType::Rlopen),
            14 => Some(FcallType::Tlcreate),
            15 => Some(FcallType::Rlcreate),
            16 => Some(FcallType::Tsymlink),
            17 => Some(FcallType::Rsymlink),
            18 => Some(FcallType::Tmknod),
            19 => Some(FcallType::Rmknod),
            20 => Some(FcallType::Trename),
            21 => Some(FcallType::Rrename),
            22 => Some(FcallType::Treadlink),
            23 => Some(FcallType::Rreadlink),
            24 => Some(FcallType::Tgetattr),
            25 => Some(FcallType::Rgetattr),
            26 => Some(FcallType::Tsetattr),
            27 => Some(FcallType::Rsetattr),
            30 => Some(FcallType::Txattrwalk),
            31 => Some(FcallType::Rxattrwalk),
            32 => Some(FcallType::Txattrcreate),
            33 => Some(FcallType::Rxattrcreate),
            40 => Some(FcallType::Treaddir),
            41 => Some(FcallType::Rreaddir),
            50 => Some(FcallType::Tfsync),
            51 => Some(FcallType::Rfsync),
            52 => Some(FcallType::Tlock),
            53 => Some(FcallType::Rlock),
            54 => Some(FcallType::Tgetlock),
            55 => Some(FcallType::Rgetlock),
            70 => Some(FcallType::Tlink),
            71 => Some(FcallType::Rlink),
            72 => Some(FcallType::Tmkdir),
            73 => Some(FcallType::Rmkdir),
            74 => Some(FcallType::Trenameat),
            75 => Some(FcallType::Rrenameat),
            76 => Some(FcallType::Tunlinkat),
            77 => Some(FcallType::Runlinkat),

            // 9P2000
            100 => Some(FcallType::Tversion),
            101 => Some(FcallType::Rversion),
            102 => Some(FcallType::Tauth),
            103 => Some(FcallType::Rauth),
            104 => Some(FcallType::Tattach),
            105 => Some(FcallType::Rattach),
            108 => Some(FcallType::Tflush),
            109 => Some(FcallType::Rflush),
            110 => Some(FcallType::Twalk),
            111 => Some(FcallType::Rwalk),
            116 => Some(FcallType::Tread),
            117 => Some(FcallType::Rread),
            118 => Some(FcallType::Twrite),
            119 => Some(FcallType::Rwrite),
            120 => Some(FcallType::Tclunk),
            121 => Some(FcallType::Rclunk),
            122 => Some(FcallType::Tremove),
            123 => Some(FcallType::Rremove),
            _ => None,
        }
    }
}

/// Unique identifier for a file
#[derive(Clone, Debug, Copy)]
pub(super) struct Qid {
    pub(super) typ: QidType,
    pub(super) version: u32,
    pub(super) path: u64,
}

/// File system statistics
#[derive(Clone, Debug, Copy)]
struct Statfs {
    typ: u32,
    bsize: u32,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    fsid: u64,
    namelen: u32,
}

/// Time structure
#[derive(Clone, Debug, Copy, Default)]
pub(super) struct Time {
    sec: u64,
    nsec: u64,
}

/// File attributes
#[derive(Clone, Debug, Copy)]
pub(super) struct Stat {
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) nlink: u64,
    pub(super) rdev: u64,
    pub(super) size: u64,
    pub(super) blksize: u64,
    pub(super) blocks: u64,
    pub(super) atime: Time,
    pub(super) mtime: Time,
    pub(super) ctime: Time,
    pub(super) btime: Time,
    pub(super) generation: u64,
    pub(super) data_version: u64,
}

/// Set file attributes
#[derive(Clone, Debug, Copy, Default)]
pub(super) struct SetAttr {
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) size: u64,
    pub(super) atime: Time,
    pub(super) mtime: Time,
}

/// Directory entry
#[derive(Clone, Debug)]
pub(super) struct DirEntry<'a> {
    pub(super) qid: Qid,
    pub(super) offset: u64,
    pub(super) typ: u8,
    pub(super) name: FcallStr<'a>,
}

impl DirEntry<'_> {
    /// Create a static (owned) copy of this directory entry
    pub(super) fn clone_static(&self) -> DirEntry<'static> {
        DirEntry {
            qid: self.qid,
            offset: self.offset,
            typ: self.typ,
            name: FcallStr::Owned(self.name.clone().into_owned()),
        }
    }

    /// Calculate the size of this entry when encoded
    fn size(&self) -> u64 {
        (13 + 8 + 1 + 2 + self.name.len()) as u64
    }
}

/// File lock request
#[derive(Clone, Debug)]
pub(super) struct Flock<'a> {
    typ: LockType,
    flags: LockFlag,
    start: u64,
    length: u64,
    proc_id: u32,
    client_id: FcallStr<'a>,
}

/// Get lock request
#[derive(Clone, Debug)]
struct Getlock<'a> {
    typ: LockType,
    start: u64,
    length: u64,
    proc_id: u32,
    client_id: FcallStr<'a>,
}

// ============================================================================
// Response/Request structures
// ============================================================================

/// Error response
#[derive(Clone, Debug)]
pub(super) struct Rlerror {
    pub(super) ecode: u32,
}

impl Display for Rlerror {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Remote error: {}", self.ecode)
    }
}

/// Attach request
#[derive(Clone, Debug)]
pub(super) struct Tattach<'a> {
    pub(super) fid: u32,
    pub(super) afid: u32,
    pub(super) uname: FcallStr<'a>,
    pub(super) aname: FcallStr<'a>,
    pub(super) n_uname: u32,
}

/// Attach response
#[derive(Clone, Debug)]
pub(super) struct Rattach {
    pub(super) qid: Qid,
}

/// Statfs request
#[derive(Clone, Debug)]
pub(super) struct Tstatfs {
    fid: u32,
}

/// Statfs response
#[derive(Clone, Debug)]
pub(super) struct Rstatfs {
    statfs: Statfs,
}

/// Open request
#[derive(Clone, Debug)]
pub(super) struct Tlopen {
    pub(super) fid: u32,
    pub(super) flags: LOpenFlags,
}

/// Open response
#[derive(Clone, Debug)]
pub(super) struct Rlopen {
    pub(super) qid: Qid,
    pub(super) iounit: u32,
}

/// Create request
#[derive(Clone, Debug)]
pub(super) struct Tlcreate<'a> {
    pub(super) fid: u32,
    pub(super) name: FcallStr<'a>,
    pub(super) flags: LOpenFlags,
    pub(super) mode: u32,
    pub(super) gid: u32,
}

/// Create response
#[derive(Clone, Debug)]
pub(super) struct Rlcreate {
    pub(super) qid: Qid,
    pub(super) iounit: u32,
}

/// Symlink request
#[derive(Clone, Debug)]
pub(super) struct Tsymlink<'a> {
    fid: u32,
    name: FcallStr<'a>,
    symtgt: FcallStr<'a>,
    gid: u32,
}

/// Symlink response
#[derive(Clone, Debug)]
pub(super) struct Rsymlink {
    qid: Qid,
}

/// Mknod request
#[derive(Clone, Debug)]
pub(super) struct Tmknod<'a> {
    dfid: u32,
    name: FcallStr<'a>,
    mode: u32,
    major: u32,
    minor: u32,
    gid: u32,
}

/// Mknod response
#[derive(Clone, Debug)]
pub(super) struct Rmknod {
    qid: Qid,
}

/// Rename request
#[derive(Clone, Debug)]
pub(super) struct Trename<'a> {
    pub(super) fid: u32,
    pub(super) dfid: u32,
    pub(super) name: FcallStr<'a>,
}

/// Rename response
#[derive(Clone, Debug)]
pub(super) struct Rrename {}

/// Readlink request
#[derive(Clone, Debug)]
pub(super) struct Treadlink {
    fid: u32,
}

/// Readlink response
#[derive(Clone, Debug)]
pub(super) struct Rreadlink<'a> {
    target: FcallStr<'a>,
}

/// Getattr request
#[derive(Clone, Debug)]
pub(super) struct Tgetattr {
    pub(super) fid: u32,
    pub(super) req_mask: GetattrMask,
}

/// Getattr response
#[derive(Clone, Debug)]
pub(super) struct Rgetattr {
    pub(super) valid: GetattrMask,
    pub(super) qid: Qid,
    pub(super) stat: Stat,
}

/// Setattr request
#[derive(Clone, Debug)]
pub(super) struct Tsetattr {
    pub(super) fid: u32,
    pub(super) valid: SetattrMask,
    pub(super) stat: SetAttr,
}

/// Setattr response
#[derive(Clone, Debug)]
pub(super) struct Rsetattr {}

/// Xattr walk request
#[derive(Clone, Debug)]
pub(super) struct Txattrwalk<'a> {
    fid: u32,
    new_fid: u32,
    name: FcallStr<'a>,
}

/// Xattr walk response
#[derive(Clone, Debug)]
pub(super) struct Rxattrwalk {
    size: u64,
}

/// Xattr create request
#[derive(Clone, Debug)]
pub(super) struct Txattrcreate<'a> {
    fid: u32,
    name: FcallStr<'a>,
    attr_size: u64,
    flags: u32,
}

/// Xattr create response
#[derive(Clone, Debug)]
pub(super) struct Rxattrcreate {}

/// Readdir request
#[derive(Clone, Debug)]
pub(super) struct Treaddir {
    pub(super) fid: u32,
    pub(super) offset: u64,
    pub(super) count: u32,
}

/// Readdir response
#[derive(Clone, Debug)]
pub(super) struct Rreaddir<'a> {
    pub(super) data: DirEntryData<'a>,
}

/// Fsync request
#[derive(Clone, Debug)]
pub(super) struct Tfsync {
    pub(super) fid: u32,
    pub(super) datasync: u32,
}

/// Fsync response
#[derive(Clone, Debug)]
pub(super) struct Rfsync {}

/// Lock request
#[derive(Clone, Debug)]
pub(super) struct Tlock<'a> {
    fid: u32,
    flock: Flock<'a>,
}

/// Lock response
#[derive(Clone, Debug)]
pub(super) struct Rlock {
    status: LockStatus,
}

/// Getlock request
#[derive(Clone, Debug)]
pub(super) struct Tgetlock<'a> {
    fid: u32,
    flock: Getlock<'a>,
}

/// Getlock response
#[derive(Clone, Debug)]
pub(super) struct Rgetlock<'a> {
    flock: Getlock<'a>,
}

/// Link request
#[derive(Clone, Debug)]
pub(super) struct Tlink<'a> {
    dfid: u32,
    fid: u32,
    name: FcallStr<'a>,
}

/// Link response
#[derive(Clone, Debug)]
pub(super) struct Rlink {}

/// Mkdir request
#[derive(Clone, Debug)]
pub(super) struct Tmkdir<'a> {
    pub(super) dfid: u32,
    pub(super) name: FcallStr<'a>,
    pub(super) mode: u32,
    pub(super) gid: u32,
}

/// Mkdir response
#[derive(Clone, Debug)]
pub(super) struct Rmkdir {
    pub(super) qid: Qid,
}

/// Renameat request
#[derive(Clone, Debug)]
pub(super) struct Trenameat<'a> {
    olddfid: u32,
    oldname: FcallStr<'a>,
    newdfid: u32,
    newname: FcallStr<'a>,
}

/// Renameat response
#[derive(Clone, Debug)]
pub(super) struct Rrenameat {}

/// Unlinkat request
#[derive(Clone, Debug)]
pub(super) struct Tunlinkat<'a> {
    pub(super) dfid: u32,
    pub(super) name: FcallStr<'a>,
    pub(super) flags: u32,
}

/// Unlinkat response
#[derive(Clone, Debug)]
pub(super) struct Runlinkat {}

/// Auth request
#[derive(Clone, Debug)]
pub(super) struct Tauth<'a> {
    afid: u32,
    uname: FcallStr<'a>,
    aname: FcallStr<'a>,
    n_uname: u32,
}

/// Auth response
#[derive(Clone, Debug)]
pub(super) struct Rauth {
    aqid: Qid,
}

/// Version request
#[derive(Clone, Debug)]
pub(super) struct Tversion<'a> {
    pub(super) msize: u32,
    pub(super) version: FcallStr<'a>,
}

/// Version response
#[derive(Clone, Debug)]
pub(super) struct Rversion<'a> {
    pub(super) msize: u32,
    pub(super) version: FcallStr<'a>,
}

/// Flush request
#[derive(Clone, Debug)]
pub(super) struct Tflush {
    oldtag: u16,
}

/// Flush response
#[derive(Clone, Debug)]
pub(super) struct Rflush {}

/// Walk request
#[derive(Clone, Debug)]
pub(super) struct Twalk<'a> {
    pub(super) fid: u32,
    pub(super) new_fid: u32,
    pub(super) wnames: Vec<FcallStr<'a>>,
}

/// Walk response
#[derive(Clone, Debug)]
pub(super) struct Rwalk {
    pub(super) wqids: Vec<Qid>,
}

/// Read request
#[derive(Clone, Debug)]
pub(super) struct Tread {
    pub(super) fid: u32,
    pub(super) offset: u64,
    pub(super) count: u32,
}

/// Read response
#[derive(Clone, Debug)]
pub(super) struct Rread<'a> {
    pub(super) data: Cow<'a, [u8]>,
}

/// Write request
#[derive(Clone, Debug)]
pub(super) struct Twrite<'a> {
    pub(super) fid: u32,
    pub(super) offset: u64,
    pub(super) data: Cow<'a, [u8]>,
}

/// Write response
#[derive(Clone, Debug)]
pub(super) struct Rwrite {
    pub(super) count: u32,
}

/// Clunk request
#[derive(Clone, Debug)]
pub(super) struct Tclunk {
    pub(super) fid: u32,
}

/// Clunk response
#[derive(Clone, Debug)]
pub(super) struct Rclunk {}

/// Remove request
#[derive(Clone, Debug)]
pub(super) struct Tremove {
    pub(super) fid: u32,
}

/// Remove response
#[derive(Clone, Debug)]
pub(super) struct Rremove {}

// ============================================================================
// Fcall enum and conversions
// ============================================================================

/// 9P protocol message
#[derive(Clone, Debug)]
pub(super) enum Fcall<'a> {
    Rlerror(Rlerror),
    Tattach(Tattach<'a>),
    Rattach(Rattach),
    Tstatfs(Tstatfs),
    Rstatfs(Rstatfs),
    Tlopen(Tlopen),
    Rlopen(Rlopen),
    Tlcreate(Tlcreate<'a>),
    Rlcreate(Rlcreate),
    Tsymlink(Tsymlink<'a>),
    Rsymlink(Rsymlink),
    Tmknod(Tmknod<'a>),
    Rmknod(Rmknod),
    Trename(Trename<'a>),
    Rrename(Rrename),
    Treadlink(Treadlink),
    Rreadlink(Rreadlink<'a>),
    Tgetattr(Tgetattr),
    Rgetattr(Rgetattr),
    Tsetattr(Tsetattr),
    Rsetattr(Rsetattr),
    Txattrwalk(Txattrwalk<'a>),
    Rxattrwalk(Rxattrwalk),
    Txattrcreate(Txattrcreate<'a>),
    Rxattrcreate(Rxattrcreate),
    Treaddir(Treaddir),
    Rreaddir(Rreaddir<'a>),
    Tfsync(Tfsync),
    Rfsync(Rfsync),
    Tlock(Tlock<'a>),
    Rlock(Rlock),
    Tgetlock(Tgetlock<'a>),
    Rgetlock(Rgetlock<'a>),
    Tlink(Tlink<'a>),
    Rlink(Rlink),
    Tmkdir(Tmkdir<'a>),
    Rmkdir(Rmkdir),
    Trenameat(Trenameat<'a>),
    Rrenameat(Rrenameat),
    Tunlinkat(Tunlinkat<'a>),
    Runlinkat(Runlinkat),
    Tauth(Tauth<'a>),
    Rauth(Rauth),
    Tversion(Tversion<'a>),
    Rversion(Rversion<'a>),
    Tflush(Tflush),
    Rflush(Rflush),
    Twalk(Twalk<'a>),
    Rwalk(Rwalk),
    Tread(Tread),
    Rread(Rread<'a>),
    Twrite(Twrite<'a>),
    Rwrite(Rwrite),
    Tclunk(Tclunk),
    Rclunk(Rclunk),
    Tremove(Tremove),
    Rremove(Rremove),
}

// Implement From for all message types
macro_rules! impl_from_for_fcall {
    ($($variant:ident($ty:ty)),* $(,)?) => {
        $(
            impl<'a> From<$ty> for Fcall<'a> {
                fn from(v: $ty) -> Fcall<'a> {
                    Fcall::$variant(v)
                }
            }
        )*
    };
}

impl_from_for_fcall! {
    Rlerror(Rlerror),
    Rattach(Rattach),
    Tstatfs(Tstatfs),
    Rstatfs(Rstatfs),
    Tlopen(Tlopen),
    Rlopen(Rlopen),
    Rlcreate(Rlcreate),
    Rsymlink(Rsymlink),
    Rmknod(Rmknod),
    Rrename(Rrename),
    Treadlink(Treadlink),
    Tgetattr(Tgetattr),
    Rgetattr(Rgetattr),
    Tsetattr(Tsetattr),
    Rsetattr(Rsetattr),
    Rxattrwalk(Rxattrwalk),
    Rxattrcreate(Rxattrcreate),
    Treaddir(Treaddir),
    Tfsync(Tfsync),
    Rfsync(Rfsync),
    Rlock(Rlock),
    Rlink(Rlink),
    Rmkdir(Rmkdir),
    Rrenameat(Rrenameat),
    Runlinkat(Runlinkat),
    Rauth(Rauth),
    Tflush(Tflush),
    Rflush(Rflush),
    Rwalk(Rwalk),
    Tread(Tread),
    Rwrite(Rwrite),
    Tclunk(Tclunk),
    Rclunk(Rclunk),
    Tremove(Tremove),
    Rremove(Rremove),
}

impl<'a> From<Tattach<'a>> for Fcall<'a> {
    fn from(v: Tattach<'a>) -> Fcall<'a> {
        Fcall::Tattach(v)
    }
}

impl<'a> From<Tlcreate<'a>> for Fcall<'a> {
    fn from(v: Tlcreate<'a>) -> Fcall<'a> {
        Fcall::Tlcreate(v)
    }
}

impl<'a> From<Tsymlink<'a>> for Fcall<'a> {
    fn from(v: Tsymlink<'a>) -> Fcall<'a> {
        Fcall::Tsymlink(v)
    }
}

impl<'a> From<Tmknod<'a>> for Fcall<'a> {
    fn from(v: Tmknod<'a>) -> Fcall<'a> {
        Fcall::Tmknod(v)
    }
}

impl<'a> From<Trename<'a>> for Fcall<'a> {
    fn from(v: Trename<'a>) -> Fcall<'a> {
        Fcall::Trename(v)
    }
}

impl<'a> From<Rreadlink<'a>> for Fcall<'a> {
    fn from(v: Rreadlink<'a>) -> Fcall<'a> {
        Fcall::Rreadlink(v)
    }
}

impl<'a> From<Txattrwalk<'a>> for Fcall<'a> {
    fn from(v: Txattrwalk<'a>) -> Fcall<'a> {
        Fcall::Txattrwalk(v)
    }
}

impl<'a> From<Txattrcreate<'a>> for Fcall<'a> {
    fn from(v: Txattrcreate<'a>) -> Fcall<'a> {
        Fcall::Txattrcreate(v)
    }
}

impl<'a> From<Rreaddir<'a>> for Fcall<'a> {
    fn from(v: Rreaddir<'a>) -> Fcall<'a> {
        Fcall::Rreaddir(v)
    }
}

impl<'a> From<Tlock<'a>> for Fcall<'a> {
    fn from(v: Tlock<'a>) -> Fcall<'a> {
        Fcall::Tlock(v)
    }
}

impl<'a> From<Tgetlock<'a>> for Fcall<'a> {
    fn from(v: Tgetlock<'a>) -> Fcall<'a> {
        Fcall::Tgetlock(v)
    }
}

impl<'a> From<Rgetlock<'a>> for Fcall<'a> {
    fn from(v: Rgetlock<'a>) -> Fcall<'a> {
        Fcall::Rgetlock(v)
    }
}

impl<'a> From<Tlink<'a>> for Fcall<'a> {
    fn from(v: Tlink<'a>) -> Fcall<'a> {
        Fcall::Tlink(v)
    }
}

impl<'a> From<Tmkdir<'a>> for Fcall<'a> {
    fn from(v: Tmkdir<'a>) -> Fcall<'a> {
        Fcall::Tmkdir(v)
    }
}

impl<'a> From<Trenameat<'a>> for Fcall<'a> {
    fn from(v: Trenameat<'a>) -> Fcall<'a> {
        Fcall::Trenameat(v)
    }
}

impl<'a> From<Tunlinkat<'a>> for Fcall<'a> {
    fn from(v: Tunlinkat<'a>) -> Fcall<'a> {
        Fcall::Tunlinkat(v)
    }
}

impl<'a> From<Tauth<'a>> for Fcall<'a> {
    fn from(v: Tauth<'a>) -> Fcall<'a> {
        Fcall::Tauth(v)
    }
}

impl<'a> From<Tversion<'a>> for Fcall<'a> {
    fn from(v: Tversion<'a>) -> Fcall<'a> {
        Fcall::Tversion(v)
    }
}

impl<'a> From<Rversion<'a>> for Fcall<'a> {
    fn from(v: Rversion<'a>) -> Fcall<'a> {
        Fcall::Rversion(v)
    }
}

impl<'a> From<Twalk<'a>> for Fcall<'a> {
    fn from(v: Twalk<'a>) -> Fcall<'a> {
        Fcall::Twalk(v)
    }
}

impl<'a> From<Rread<'a>> for Fcall<'a> {
    fn from(v: Rread<'a>) -> Fcall<'a> {
        Fcall::Rread(v)
    }
}

impl<'a> From<Twrite<'a>> for Fcall<'a> {
    fn from(v: Twrite<'a>) -> Fcall<'a> {
        Fcall::Twrite(v)
    }
}

/// Tagged 9P message
#[derive(Clone, Debug)]
pub(super) struct TaggedFcall<'a> {
    pub(super) tag: u16,
    pub(super) fcall: Fcall<'a>,
}

impl<'a> TaggedFcall<'a> {
    /// Encode the message to a buffer
    pub(super) fn encode_to_buf(self, buf: &mut Vec<u8>) -> Result<(), transport::WriteError> {
        let TaggedFcall { tag, fcall } = self;

        buf.clear();
        buf.resize(4, 0); // Reserve space for size

        // Encode the message directly to the buffer (appending after the size field)
        encode_fcall(buf, tag, fcall)?;

        // Write the size at the beginning
        let size = u32::try_from(buf.len()).expect("buffer length exceeds u32");
        buf[0..4].copy_from_slice(&size.to_le_bytes());

        Ok(())
    }

    /// Decode a message from a buffer
    pub(super) fn decode(buf: &'a [u8]) -> Result<TaggedFcall<'a>, super::Error> {
        if buf.len() < 7 {
            return Err(super::Error::InvalidResponse);
        }

        let mut decoder = FcallDecoder { buf: &buf[4..] };
        decoder.decode()
    }
}

// ============================================================================
// Encoding functions
// ============================================================================

fn encode_u8<W: Write>(w: &mut W, v: u8) -> Result<(), transport::WriteError> {
    w.write_all(&[v])
}

fn encode_u16<W: Write>(w: &mut W, v: u16) -> Result<(), transport::WriteError> {
    w.write_all(&v.to_le_bytes())
}

fn encode_u32<W: Write>(w: &mut W, v: u32) -> Result<(), transport::WriteError> {
    w.write_all(&v.to_le_bytes())
}

fn encode_u64<W: Write>(w: &mut W, v: u64) -> Result<(), transport::WriteError> {
    w.write_all(&v.to_le_bytes())
}

fn encode_str<W: Write>(w: &mut W, v: &FcallStr<'_>) -> Result<(), transport::WriteError> {
    encode_u16(w, u16::try_from(v.len()).expect("str length exceeds u16"))?;
    w.write_all(v)
}

fn encode_data_buf<W: Write>(w: &mut W, v: &[u8]) -> Result<(), transport::WriteError> {
    encode_u32(
        w,
        u32::try_from(v.len()).expect("data buffer length exceeds u32"),
    )?;
    w.write_all(v)
}

fn encode_vec_str<W: Write>(w: &mut W, v: &[FcallStr<'_>]) -> Result<(), transport::WriteError> {
    encode_u16(w, u16::try_from(v.len()).expect("vec length exceeds u16"))?;
    for s in v {
        encode_str(w, s)?;
    }
    Ok(())
}

fn encode_vec_qid<W: Write>(w: &mut W, v: Vec<Qid>) -> Result<(), transport::WriteError> {
    encode_u16(w, u16::try_from(v.len()).expect("vec length exceeds u16"))?;
    for q in v {
        encode_qid(w, q)?;
    }
    Ok(())
}

fn encode_qidtype<W: Write>(w: &mut W, v: QidType) -> Result<(), transport::WriteError> {
    encode_u8(w, v.bits())
}

fn encode_locktype<W: Write>(w: &mut W, v: LockType) -> Result<(), transport::WriteError> {
    encode_u8(w, v.bits())
}

fn encode_lockstatus<W: Write>(w: &mut W, v: LockStatus) -> Result<(), transport::WriteError> {
    encode_u8(w, v.bits())
}

fn encode_lockflag<W: Write>(w: &mut W, v: LockFlag) -> Result<(), transport::WriteError> {
    encode_u32(w, v.bits())
}

fn encode_getattrmask<W: Write>(w: &mut W, v: GetattrMask) -> Result<(), transport::WriteError> {
    encode_u64(w, v.bits())
}

fn encode_setattrmask<W: Write>(w: &mut W, v: SetattrMask) -> Result<(), transport::WriteError> {
    encode_u32(w, v.bits())
}

fn encode_qid<W: Write>(w: &mut W, v: Qid) -> Result<(), transport::WriteError> {
    encode_qidtype(w, v.typ)?;
    encode_u32(w, v.version)?;
    encode_u64(w, v.path)?;
    Ok(())
}

fn encode_statfs<W: Write>(w: &mut W, v: Statfs) -> Result<(), transport::WriteError> {
    encode_u32(w, v.typ)?;
    encode_u32(w, v.bsize)?;
    encode_u64(w, v.blocks)?;
    encode_u64(w, v.bfree)?;
    encode_u64(w, v.bavail)?;
    encode_u64(w, v.files)?;
    encode_u64(w, v.ffree)?;
    encode_u64(w, v.fsid)?;
    encode_u32(w, v.namelen)?;
    Ok(())
}

fn encode_time<W: Write>(w: &mut W, v: Time) -> Result<(), transport::WriteError> {
    encode_u64(w, v.sec)?;
    encode_u64(w, v.nsec)?;
    Ok(())
}

fn encode_stat<W: Write>(w: &mut W, v: Stat) -> Result<(), transport::WriteError> {
    encode_u32(w, v.mode)?;
    encode_u32(w, v.uid)?;
    encode_u32(w, v.gid)?;
    encode_u64(w, v.nlink)?;
    encode_u64(w, v.rdev)?;
    encode_u64(w, v.size)?;
    encode_u64(w, v.blksize)?;
    encode_u64(w, v.blocks)?;
    encode_time(w, v.atime)?;
    encode_time(w, v.mtime)?;
    encode_time(w, v.ctime)?;
    encode_time(w, v.btime)?;
    encode_u64(w, v.generation)?;
    encode_u64(w, v.data_version)?;
    Ok(())
}

fn encode_setattr<W: Write>(w: &mut W, v: SetAttr) -> Result<(), transport::WriteError> {
    encode_u32(w, v.mode)?;
    encode_u32(w, v.uid)?;
    encode_u32(w, v.gid)?;
    encode_u64(w, v.size)?;
    encode_time(w, v.atime)?;
    encode_time(w, v.mtime)?;
    Ok(())
}

fn encode_direntrydata<W: Write>(
    w: &mut W,
    v: DirEntryData<'_>,
) -> Result<(), transport::WriteError> {
    encode_u32(
        w,
        u32::try_from(v.size()).expect("direntrydata size exceeds u32"),
    )?;
    for e in v.data {
        encode_direntry(w, e)?;
    }
    Ok(())
}

fn encode_direntry<W: Write>(w: &mut W, v: DirEntry<'_>) -> Result<(), transport::WriteError> {
    encode_qid(w, v.qid)?;
    encode_u64(w, v.offset)?;
    encode_u8(w, v.typ)?;
    encode_str(w, &v.name)?;
    Ok(())
}

fn encode_flock<W: Write>(w: &mut W, v: Flock<'_>) -> Result<(), transport::WriteError> {
    encode_locktype(w, v.typ)?;
    encode_lockflag(w, v.flags)?;
    encode_u64(w, v.start)?;
    encode_u64(w, v.length)?;
    encode_u32(w, v.proc_id)?;
    encode_str(w, &v.client_id)?;
    Ok(())
}

fn encode_getlock<W: Write>(w: &mut W, v: Getlock<'_>) -> Result<(), transport::WriteError> {
    encode_locktype(w, v.typ)?;
    encode_u64(w, v.start)?;
    encode_u64(w, v.length)?;
    encode_u32(w, v.proc_id)?;
    encode_str(w, &v.client_id)?;
    Ok(())
}

fn encode_fcall<W: Write>(
    w: &mut W,
    tag: u16,
    fcall: Fcall<'_>,
) -> Result<(), transport::WriteError> {
    match fcall {
        Fcall::Rlerror(v) => {
            encode_u8(w, FcallType::Rlerror as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.ecode)?;
        }
        Fcall::Tattach(v) => {
            encode_u8(w, FcallType::Tattach as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_u32(w, v.afid)?;
            encode_str(w, &v.uname)?;
            encode_str(w, &v.aname)?;
            encode_u32(w, v.n_uname)?;
        }
        Fcall::Rattach(v) => {
            encode_u8(w, FcallType::Rattach as u8)?;
            encode_u16(w, tag)?;
            encode_qid(w, v.qid)?;
        }
        Fcall::Tstatfs(v) => {
            encode_u8(w, FcallType::Tstatfs as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
        }
        Fcall::Rstatfs(v) => {
            encode_u8(w, FcallType::Rstatfs as u8)?;
            encode_u16(w, tag)?;
            encode_statfs(w, v.statfs)?;
        }
        Fcall::Tlopen(v) => {
            encode_u8(w, FcallType::Tlopen as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_u32(w, v.flags.bits())?;
        }
        Fcall::Rlopen(v) => {
            encode_u8(w, FcallType::Rlopen as u8)?;
            encode_u16(w, tag)?;
            encode_qid(w, v.qid)?;
            encode_u32(w, v.iounit)?;
        }
        Fcall::Tlcreate(v) => {
            encode_u8(w, FcallType::Tlcreate as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_str(w, &v.name)?;
            encode_u32(w, v.flags.bits())?;
            encode_u32(w, v.mode)?;
            encode_u32(w, v.gid)?;
        }
        Fcall::Rlcreate(v) => {
            encode_u8(w, FcallType::Rlcreate as u8)?;
            encode_u16(w, tag)?;
            encode_qid(w, v.qid)?;
            encode_u32(w, v.iounit)?;
        }
        Fcall::Tsymlink(v) => {
            encode_u8(w, FcallType::Tsymlink as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_str(w, &v.name)?;
            encode_str(w, &v.symtgt)?;
            encode_u32(w, v.gid)?;
        }
        Fcall::Rsymlink(v) => {
            encode_u8(w, FcallType::Rsymlink as u8)?;
            encode_u16(w, tag)?;
            encode_qid(w, v.qid)?;
        }
        Fcall::Tmknod(v) => {
            encode_u8(w, FcallType::Tmknod as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.dfid)?;
            encode_str(w, &v.name)?;
            encode_u32(w, v.mode)?;
            encode_u32(w, v.major)?;
            encode_u32(w, v.minor)?;
            encode_u32(w, v.gid)?;
        }
        Fcall::Rmknod(v) => {
            encode_u8(w, FcallType::Rmknod as u8)?;
            encode_u16(w, tag)?;
            encode_qid(w, v.qid)?;
        }
        Fcall::Trename(v) => {
            encode_u8(w, FcallType::Trename as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_u32(w, v.dfid)?;
            encode_str(w, &v.name)?;
        }
        Fcall::Rrename(_) => {
            encode_u8(w, FcallType::Rrename as u8)?;
            encode_u16(w, tag)?;
        }
        Fcall::Treadlink(v) => {
            encode_u8(w, FcallType::Treadlink as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
        }
        Fcall::Rreadlink(v) => {
            encode_u8(w, FcallType::Rreadlink as u8)?;
            encode_u16(w, tag)?;
            encode_str(w, &v.target)?;
        }
        Fcall::Tgetattr(v) => {
            encode_u8(w, FcallType::Tgetattr as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_getattrmask(w, v.req_mask)?;
        }
        Fcall::Rgetattr(v) => {
            encode_u8(w, FcallType::Rgetattr as u8)?;
            encode_u16(w, tag)?;
            encode_getattrmask(w, v.valid)?;
            encode_qid(w, v.qid)?;
            encode_stat(w, v.stat)?;
        }
        Fcall::Tsetattr(v) => {
            encode_u8(w, FcallType::Tsetattr as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_setattrmask(w, v.valid)?;
            encode_setattr(w, v.stat)?;
        }
        Fcall::Rsetattr(_) => {
            encode_u8(w, FcallType::Rsetattr as u8)?;
            encode_u16(w, tag)?;
        }
        Fcall::Txattrwalk(v) => {
            encode_u8(w, FcallType::Txattrwalk as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_u32(w, v.new_fid)?;
            encode_str(w, &v.name)?;
        }
        Fcall::Rxattrwalk(v) => {
            encode_u8(w, FcallType::Rxattrwalk as u8)?;
            encode_u16(w, tag)?;
            encode_u64(w, v.size)?;
        }
        Fcall::Txattrcreate(v) => {
            encode_u8(w, FcallType::Txattrcreate as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_str(w, &v.name)?;
            encode_u64(w, v.attr_size)?;
            encode_u32(w, v.flags)?;
        }
        Fcall::Rxattrcreate(_) => {
            encode_u8(w, FcallType::Rxattrcreate as u8)?;
            encode_u16(w, tag)?;
        }
        Fcall::Treaddir(v) => {
            encode_u8(w, FcallType::Treaddir as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_u64(w, v.offset)?;
            encode_u32(w, v.count)?;
        }
        Fcall::Rreaddir(v) => {
            encode_u8(w, FcallType::Rreaddir as u8)?;
            encode_u16(w, tag)?;
            encode_direntrydata(w, v.data)?;
        }
        Fcall::Tfsync(v) => {
            encode_u8(w, FcallType::Tfsync as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_u32(w, v.datasync)?;
        }
        Fcall::Rfsync(_) => {
            encode_u8(w, FcallType::Rfsync as u8)?;
            encode_u16(w, tag)?;
        }
        Fcall::Tlock(v) => {
            encode_u8(w, FcallType::Tlock as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_flock(w, v.flock)?;
        }
        Fcall::Rlock(v) => {
            encode_u8(w, FcallType::Rlock as u8)?;
            encode_u16(w, tag)?;
            encode_lockstatus(w, v.status)?;
        }
        Fcall::Tgetlock(v) => {
            encode_u8(w, FcallType::Tgetlock as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_getlock(w, v.flock)?;
        }
        Fcall::Rgetlock(v) => {
            encode_u8(w, FcallType::Rgetlock as u8)?;
            encode_u16(w, tag)?;
            encode_getlock(w, v.flock)?;
        }
        Fcall::Tlink(v) => {
            encode_u8(w, FcallType::Tlink as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.dfid)?;
            encode_u32(w, v.fid)?;
            encode_str(w, &v.name)?;
        }
        Fcall::Rlink(_) => {
            encode_u8(w, FcallType::Rlink as u8)?;
            encode_u16(w, tag)?;
        }
        Fcall::Tmkdir(v) => {
            encode_u8(w, FcallType::Tmkdir as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.dfid)?;
            encode_str(w, &v.name)?;
            encode_u32(w, v.mode)?;
            encode_u32(w, v.gid)?;
        }
        Fcall::Rmkdir(v) => {
            encode_u8(w, FcallType::Rmkdir as u8)?;
            encode_u16(w, tag)?;
            encode_qid(w, v.qid)?;
        }
        Fcall::Trenameat(v) => {
            encode_u8(w, FcallType::Trenameat as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.olddfid)?;
            encode_str(w, &v.oldname)?;
            encode_u32(w, v.newdfid)?;
            encode_str(w, &v.newname)?;
        }
        Fcall::Rrenameat(_) => {
            encode_u8(w, FcallType::Rrenameat as u8)?;
            encode_u16(w, tag)?;
        }
        Fcall::Tunlinkat(v) => {
            encode_u8(w, FcallType::Tunlinkat as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.dfid)?;
            encode_str(w, &v.name)?;
            encode_u32(w, v.flags)?;
        }
        Fcall::Runlinkat(_) => {
            encode_u8(w, FcallType::Runlinkat as u8)?;
            encode_u16(w, tag)?;
        }
        Fcall::Tauth(v) => {
            encode_u8(w, FcallType::Tauth as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.afid)?;
            encode_str(w, &v.uname)?;
            encode_str(w, &v.aname)?;
            encode_u32(w, v.n_uname)?;
        }
        Fcall::Rauth(v) => {
            encode_u8(w, FcallType::Rauth as u8)?;
            encode_u16(w, tag)?;
            encode_qid(w, v.aqid)?;
        }
        Fcall::Tversion(v) => {
            encode_u8(w, FcallType::Tversion as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.msize)?;
            encode_str(w, &v.version)?;
        }
        Fcall::Rversion(v) => {
            encode_u8(w, FcallType::Rversion as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.msize)?;
            encode_str(w, &v.version)?;
        }
        Fcall::Tflush(v) => {
            encode_u8(w, FcallType::Tflush as u8)?;
            encode_u16(w, tag)?;
            encode_u16(w, v.oldtag)?;
        }
        Fcall::Rflush(_) => {
            encode_u8(w, FcallType::Rflush as u8)?;
            encode_u16(w, tag)?;
        }
        Fcall::Twalk(v) => {
            encode_u8(w, FcallType::Twalk as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_u32(w, v.new_fid)?;
            encode_vec_str(w, &v.wnames)?;
        }
        Fcall::Rwalk(v) => {
            encode_u8(w, FcallType::Rwalk as u8)?;
            encode_u16(w, tag)?;
            encode_vec_qid(w, v.wqids)?;
        }
        Fcall::Tread(v) => {
            encode_u8(w, FcallType::Tread as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_u64(w, v.offset)?;
            encode_u32(w, v.count)?;
        }
        Fcall::Rread(v) => {
            encode_u8(w, FcallType::Rread as u8)?;
            encode_u16(w, tag)?;
            encode_data_buf(w, &v.data)?;
        }
        Fcall::Twrite(v) => {
            encode_u8(w, FcallType::Twrite as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
            encode_u64(w, v.offset)?;
            encode_data_buf(w, &v.data)?;
        }
        Fcall::Rwrite(v) => {
            encode_u8(w, FcallType::Rwrite as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.count)?;
        }
        Fcall::Tclunk(v) => {
            encode_u8(w, FcallType::Tclunk as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
        }
        Fcall::Rclunk(_) => {
            encode_u8(w, FcallType::Rclunk as u8)?;
            encode_u16(w, tag)?;
        }
        Fcall::Tremove(v) => {
            encode_u8(w, FcallType::Tremove as u8)?;
            encode_u16(w, tag)?;
            encode_u32(w, v.fid)?;
        }
        Fcall::Rremove(_) => {
            encode_u8(w, FcallType::Rremove as u8)?;
            encode_u16(w, tag)?;
        }
    }
    Ok(())
}

// ============================================================================
// Decoding
// ============================================================================

struct FcallDecoder<'b> {
    buf: &'b [u8],
}

impl<'b> FcallDecoder<'b> {
    fn decode_u8(&mut self) -> Result<u8, super::Error> {
        if let Some(v) = self.buf.first() {
            self.buf = &self.buf[1..];
            Ok(*v)
        } else {
            Err(super::Error::InvalidResponse)
        }
    }

    fn decode_u16(&mut self) -> Result<u16, super::Error> {
        if self.buf.len() >= 2 {
            let v = u16::from_le_bytes(self.buf[0..2].try_into().unwrap());
            self.buf = &self.buf[2..];
            Ok(v)
        } else {
            Err(super::Error::InvalidResponse)
        }
    }

    fn decode_u32(&mut self) -> Result<u32, super::Error> {
        if self.buf.len() >= 4 {
            let v = u32::from_le_bytes(self.buf[0..4].try_into().unwrap());
            self.buf = &self.buf[4..];
            Ok(v)
        } else {
            Err(super::Error::InvalidResponse)
        }
    }

    fn decode_u64(&mut self) -> Result<u64, super::Error> {
        if self.buf.len() >= 8 {
            let v = u64::from_le_bytes(self.buf[0..8].try_into().unwrap());
            self.buf = &self.buf[8..];
            Ok(v)
        } else {
            Err(super::Error::InvalidResponse)
        }
    }

    fn decode_str(&mut self) -> Result<FcallStr<'b>, super::Error> {
        let n = self.decode_u16()? as usize;
        if self.buf.len() >= n {
            let v = FcallStr::Borrowed(&self.buf[..n]);
            self.buf = &self.buf[n..];
            Ok(v)
        } else {
            Err(super::Error::InvalidResponse)
        }
    }

    fn decode_data_buf(&mut self) -> Result<Cow<'b, [u8]>, super::Error> {
        let n = self.decode_u32()? as usize;
        if self.buf.len() >= n {
            let v = &self.buf[..n];
            self.buf = &self.buf[n..];
            Ok(Cow::from(v))
        } else {
            Err(super::Error::InvalidResponse)
        }
    }

    fn decode_vec_qid(&mut self) -> Result<Vec<Qid>, super::Error> {
        let len = self.decode_u16()?;
        let mut v = Vec::new();
        for _ in 0..len {
            v.push(self.decode_qid()?);
        }
        Ok(v)
    }

    fn decode_direntrydata(&mut self) -> Result<DirEntryData<'b>, super::Error> {
        let end_len = self.buf.len() - self.decode_u32()? as usize;
        let mut v = Vec::new();
        while self.buf.len() > end_len {
            v.push(self.decode_direntry()?);
        }
        Ok(DirEntryData::with(v))
    }

    fn decode_qidtype(&mut self) -> Result<QidType, super::Error> {
        Ok(QidType::from_bits_truncate(self.decode_u8()?))
    }

    fn decode_locktype(&mut self) -> Result<LockType, super::Error> {
        Ok(LockType::from_bits_truncate(self.decode_u8()?))
    }

    fn decode_lockstatus(&mut self) -> Result<LockStatus, super::Error> {
        Ok(LockStatus::from_bits_truncate(self.decode_u8()?))
    }

    fn decode_lockflag(&mut self) -> Result<LockFlag, super::Error> {
        Ok(LockFlag::from_bits_truncate(self.decode_u32()?))
    }

    fn decode_getattrmask(&mut self) -> Result<GetattrMask, super::Error> {
        Ok(GetattrMask::from_bits_truncate(self.decode_u64()?))
    }

    fn decode_setattrmask(&mut self) -> Result<SetattrMask, super::Error> {
        Ok(SetattrMask::from_bits_truncate(self.decode_u32()?))
    }

    fn decode_qid(&mut self) -> Result<Qid, super::Error> {
        Ok(Qid {
            typ: self.decode_qidtype()?,
            version: self.decode_u32()?,
            path: self.decode_u64()?,
        })
    }

    fn decode_statfs(&mut self) -> Result<Statfs, super::Error> {
        Ok(Statfs {
            typ: self.decode_u32()?,
            bsize: self.decode_u32()?,
            blocks: self.decode_u64()?,
            bfree: self.decode_u64()?,
            bavail: self.decode_u64()?,
            files: self.decode_u64()?,
            ffree: self.decode_u64()?,
            fsid: self.decode_u64()?,
            namelen: self.decode_u32()?,
        })
    }

    fn decode_time(&mut self) -> Result<Time, super::Error> {
        Ok(Time {
            sec: self.decode_u64()?,
            nsec: self.decode_u64()?,
        })
    }

    fn decode_stat(&mut self) -> Result<Stat, super::Error> {
        Ok(Stat {
            mode: self.decode_u32()?,
            uid: self.decode_u32()?,
            gid: self.decode_u32()?,
            nlink: self.decode_u64()?,
            rdev: self.decode_u64()?,
            size: self.decode_u64()?,
            blksize: self.decode_u64()?,
            blocks: self.decode_u64()?,
            atime: self.decode_time()?,
            mtime: self.decode_time()?,
            ctime: self.decode_time()?,
            btime: self.decode_time()?,
            generation: self.decode_u64()?,
            data_version: self.decode_u64()?,
        })
    }

    fn decode_setattr(&mut self) -> Result<SetAttr, super::Error> {
        Ok(SetAttr {
            mode: self.decode_u32()?,
            uid: self.decode_u32()?,
            gid: self.decode_u32()?,
            size: self.decode_u64()?,
            atime: self.decode_time()?,
            mtime: self.decode_time()?,
        })
    }

    fn decode_direntry(&mut self) -> Result<DirEntry<'b>, super::Error> {
        Ok(DirEntry {
            qid: self.decode_qid()?,
            offset: self.decode_u64()?,
            typ: self.decode_u8()?,
            name: self.decode_str()?,
        })
    }

    fn decode_flock(&mut self) -> Result<Flock<'b>, super::Error> {
        Ok(Flock {
            typ: self.decode_locktype()?,
            flags: self.decode_lockflag()?,
            start: self.decode_u64()?,
            length: self.decode_u64()?,
            proc_id: self.decode_u32()?,
            client_id: self.decode_str()?,
        })
    }

    fn decode_getlock(&mut self) -> Result<Getlock<'b>, super::Error> {
        Ok(Getlock {
            typ: self.decode_locktype()?,
            start: self.decode_u64()?,
            length: self.decode_u64()?,
            proc_id: self.decode_u32()?,
            client_id: self.decode_str()?,
        })
    }

    fn decode(&mut self) -> Result<TaggedFcall<'b>, super::Error> {
        let msg_type = FcallType::from_u8(self.decode_u8()?);
        let tag = self.decode_u16()?;
        let fcall = match msg_type {
            Some(FcallType::Rlerror) => Fcall::Rlerror(Rlerror {
                ecode: self.decode_u32()?,
            }),
            Some(FcallType::Tattach) => Fcall::Tattach(Tattach {
                fid: self.decode_u32()?,
                afid: self.decode_u32()?,
                uname: self.decode_str()?,
                aname: self.decode_str()?,
                n_uname: self.decode_u32()?,
            }),
            Some(FcallType::Rattach) => Fcall::Rattach(Rattach {
                qid: self.decode_qid()?,
            }),
            Some(FcallType::Tstatfs) => Fcall::Tstatfs(Tstatfs {
                fid: self.decode_u32()?,
            }),
            Some(FcallType::Rstatfs) => Fcall::Rstatfs(Rstatfs {
                statfs: self.decode_statfs()?,
            }),
            Some(FcallType::Tlopen) => Fcall::Tlopen(Tlopen {
                fid: self.decode_u32()?,
                flags: LOpenFlags::from_bits_truncate(self.decode_u32()?),
            }),
            Some(FcallType::Rlopen) => Fcall::Rlopen(Rlopen {
                qid: self.decode_qid()?,
                iounit: self.decode_u32()?,
            }),
            Some(FcallType::Tlcreate) => Fcall::Tlcreate(Tlcreate {
                fid: self.decode_u32()?,
                name: self.decode_str()?,
                flags: LOpenFlags::from_bits_truncate(self.decode_u32()?),
                mode: self.decode_u32()?,
                gid: self.decode_u32()?,
            }),
            Some(FcallType::Rlcreate) => Fcall::Rlcreate(Rlcreate {
                qid: self.decode_qid()?,
                iounit: self.decode_u32()?,
            }),
            Some(FcallType::Tsymlink) => Fcall::Tsymlink(Tsymlink {
                fid: self.decode_u32()?,
                name: self.decode_str()?,
                symtgt: self.decode_str()?,
                gid: self.decode_u32()?,
            }),
            Some(FcallType::Rsymlink) => Fcall::Rsymlink(Rsymlink {
                qid: self.decode_qid()?,
            }),
            Some(FcallType::Tmknod) => Fcall::Tmknod(Tmknod {
                dfid: self.decode_u32()?,
                name: self.decode_str()?,
                mode: self.decode_u32()?,
                major: self.decode_u32()?,
                minor: self.decode_u32()?,
                gid: self.decode_u32()?,
            }),
            Some(FcallType::Rmknod) => Fcall::Rmknod(Rmknod {
                qid: self.decode_qid()?,
            }),
            Some(FcallType::Trename) => Fcall::Trename(Trename {
                fid: self.decode_u32()?,
                dfid: self.decode_u32()?,
                name: self.decode_str()?,
            }),
            Some(FcallType::Rrename) => Fcall::Rrename(Rrename {}),
            Some(FcallType::Treadlink) => Fcall::Treadlink(Treadlink {
                fid: self.decode_u32()?,
            }),
            Some(FcallType::Rreadlink) => Fcall::Rreadlink(Rreadlink {
                target: self.decode_str()?,
            }),
            Some(FcallType::Tgetattr) => Fcall::Tgetattr(Tgetattr {
                fid: self.decode_u32()?,
                req_mask: self.decode_getattrmask()?,
            }),
            Some(FcallType::Rgetattr) => Fcall::Rgetattr(Rgetattr {
                valid: self.decode_getattrmask()?,
                qid: self.decode_qid()?,
                stat: self.decode_stat()?,
            }),
            Some(FcallType::Tsetattr) => Fcall::Tsetattr(Tsetattr {
                fid: self.decode_u32()?,
                valid: self.decode_setattrmask()?,
                stat: self.decode_setattr()?,
            }),
            Some(FcallType::Rsetattr) => Fcall::Rsetattr(Rsetattr {}),
            Some(FcallType::Txattrwalk) => Fcall::Txattrwalk(Txattrwalk {
                fid: self.decode_u32()?,
                new_fid: self.decode_u32()?,
                name: self.decode_str()?,
            }),
            Some(FcallType::Rxattrwalk) => Fcall::Rxattrwalk(Rxattrwalk {
                size: self.decode_u64()?,
            }),
            Some(FcallType::Txattrcreate) => Fcall::Txattrcreate(Txattrcreate {
                fid: self.decode_u32()?,
                name: self.decode_str()?,
                attr_size: self.decode_u64()?,
                flags: self.decode_u32()?,
            }),
            Some(FcallType::Rxattrcreate) => Fcall::Rxattrcreate(Rxattrcreate {}),
            Some(FcallType::Treaddir) => Fcall::Treaddir(Treaddir {
                fid: self.decode_u32()?,
                offset: self.decode_u64()?,
                count: self.decode_u32()?,
            }),
            Some(FcallType::Rreaddir) => Fcall::Rreaddir(Rreaddir {
                data: self.decode_direntrydata()?,
            }),
            Some(FcallType::Tfsync) => Fcall::Tfsync(Tfsync {
                fid: self.decode_u32()?,
                datasync: self.decode_u32()?,
            }),
            Some(FcallType::Rfsync) => Fcall::Rfsync(Rfsync {}),
            Some(FcallType::Tlock) => Fcall::Tlock(Tlock {
                fid: self.decode_u32()?,
                flock: self.decode_flock()?,
            }),
            Some(FcallType::Rlock) => Fcall::Rlock(Rlock {
                status: self.decode_lockstatus()?,
            }),
            Some(FcallType::Tgetlock) => Fcall::Tgetlock(Tgetlock {
                fid: self.decode_u32()?,
                flock: self.decode_getlock()?,
            }),
            Some(FcallType::Rgetlock) => Fcall::Rgetlock(Rgetlock {
                flock: self.decode_getlock()?,
            }),
            Some(FcallType::Tlink) => Fcall::Tlink(Tlink {
                dfid: self.decode_u32()?,
                fid: self.decode_u32()?,
                name: self.decode_str()?,
            }),
            Some(FcallType::Rlink) => Fcall::Rlink(Rlink {}),
            Some(FcallType::Tmkdir) => Fcall::Tmkdir(Tmkdir {
                dfid: self.decode_u32()?,
                name: self.decode_str()?,
                mode: self.decode_u32()?,
                gid: self.decode_u32()?,
            }),
            Some(FcallType::Rmkdir) => Fcall::Rmkdir(Rmkdir {
                qid: self.decode_qid()?,
            }),
            Some(FcallType::Trenameat) => Fcall::Trenameat(Trenameat {
                olddfid: self.decode_u32()?,
                oldname: self.decode_str()?,
                newdfid: self.decode_u32()?,
                newname: self.decode_str()?,
            }),
            Some(FcallType::Rrenameat) => Fcall::Rrenameat(Rrenameat {}),
            Some(FcallType::Tunlinkat) => Fcall::Tunlinkat(Tunlinkat {
                dfid: self.decode_u32()?,
                name: self.decode_str()?,
                flags: self.decode_u32()?,
            }),
            Some(FcallType::Runlinkat) => Fcall::Runlinkat(Runlinkat {}),
            Some(FcallType::Tauth) => Fcall::Tauth(Tauth {
                afid: self.decode_u32()?,
                uname: self.decode_str()?,
                aname: self.decode_str()?,
                n_uname: self.decode_u32()?,
            }),
            Some(FcallType::Rauth) => Fcall::Rauth(Rauth {
                aqid: self.decode_qid()?,
            }),
            Some(FcallType::Tversion) => Fcall::Tversion(Tversion {
                msize: self.decode_u32()?,
                version: self.decode_str()?,
            }),
            Some(FcallType::Rversion) => Fcall::Rversion(Rversion {
                msize: self.decode_u32()?,
                version: self.decode_str()?,
            }),
            Some(FcallType::Tflush) => Fcall::Tflush(Tflush {
                oldtag: self.decode_u16()?,
            }),
            Some(FcallType::Rflush) => Fcall::Rflush(Rflush {}),
            Some(FcallType::Twalk) => Fcall::Twalk(Twalk {
                fid: self.decode_u32()?,
                new_fid: self.decode_u32()?,
                wnames: {
                    let len = self.decode_u16()?;
                    let mut wnames = Vec::new();
                    for _ in 0..len {
                        wnames.push(self.decode_str()?);
                    }
                    wnames
                },
            }),
            Some(FcallType::Rwalk) => Fcall::Rwalk(Rwalk {
                wqids: self.decode_vec_qid()?,
            }),
            Some(FcallType::Tread) => Fcall::Tread(Tread {
                fid: self.decode_u32()?,
                offset: self.decode_u64()?,
                count: self.decode_u32()?,
            }),
            Some(FcallType::Rread) => Fcall::Rread(Rread {
                data: self.decode_data_buf()?,
            }),
            Some(FcallType::Twrite) => Fcall::Twrite(Twrite {
                fid: self.decode_u32()?,
                offset: self.decode_u64()?,
                data: self.decode_data_buf()?,
            }),
            Some(FcallType::Rwrite) => Fcall::Rwrite(Rwrite {
                count: self.decode_u32()?,
            }),
            Some(FcallType::Tclunk) => Fcall::Tclunk(Tclunk {
                fid: self.decode_u32()?,
            }),
            Some(FcallType::Rclunk) => Fcall::Rclunk(Rclunk {}),
            Some(FcallType::Tremove) => Fcall::Tremove(Tremove {
                fid: self.decode_u32()?,
            }),
            Some(FcallType::Rremove) => Fcall::Rremove(Rremove {}),
            None => return Err(super::Error::InvalidResponse),
        };
        Ok(TaggedFcall { tag, fcall })
    }
}
