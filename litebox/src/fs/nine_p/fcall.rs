// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! 9P2000.L protocol message definitions and encoding/decoding
//!
//! This module implements the 9P2000.L protocol used for network filesystem access.
//! See <https://9p.io/sys/man/5/intro> and <https://github.com/chaos/diod/blob/master/protocol.md>

use super::transport;
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

/// Generates a struct definition along with `encode_to` and `decode_from` methods
/// for automatic 9P wire-format serialization.
macro_rules! Serializer {
    // ── Struct definition ─────────────
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident $(<$lt:lifetime>)? {
            $(
                $(#[$fmeta:meta])*
                $fvis:vis $field:ident : $fty:tt $(<$flt:lifetime>)?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name $(<$lt>)? {
            $(
                $(#[$fmeta])*
                $fvis $field : $fty $(<$flt>)?,
            )*
        }

        impl $(<$lt>)? $name $(<$lt>)? {
            #[allow(unused_variables)]
            fn encode_to<W: transport::Write>(&self, w: &mut W) -> Result<(), transport::WriteError> {
                $(Serializer!(@encode w, self.$field, $fty $(<$flt>)?);)*
                Ok(())
            }

            #[allow(unused_variables)]
            fn decode_from(d: &mut Serializer!(@decoder_ty $($lt)?)) -> Result<Self, super::Error> {
                Ok(Self {
                    $($field: Serializer!(@decode d, $fty $(<$flt>)?),)*
                })
            }
        }
    };

    // ── Helper: FcallDecoder type with optional lifetime ─────────────────────
    (@decoder_ty $lt:lifetime) => { FcallDecoder<$lt> };
    (@decoder_ty) => { FcallDecoder<'_> };

    // ── Encode dispatch ──────────────────────────────────────────────────────
    // Types with unique wire-format helpers:
    (@encode $w:ident, $val:expr, FcallStr $(<$lt:lifetime>)?) => {
        encode_str($w, &$val)?;
    };
    (@encode $w:ident, $val:expr, VecFcallStr $(<$lt:lifetime>)?) => {
        encode_vec_str($w, &$val)?;
    };
    (@encode $w:ident, $val:expr, VecQid) => {
        encode_vec_qid($w, &$val)?;
    };
    (@encode $w:ident, $val:expr, DataBuf $(<$lt:lifetime>)?) => {
        encode_data_buf($w, &$val)?;
    };
    // Primitives — encoded as little-endian:
    (@encode $w:ident, $val:expr, u8) => { encode_le($w, $val)?; };
    (@encode $w:ident, $val:expr, u16) => { encode_le($w, $val)?; };
    (@encode $w:ident, $val:expr, u32) => { encode_le($w, $val)?; };
    (@encode $w:ident, $val:expr, u64) => { encode_le($w, $val)?; };
    // Everything else (Serializer! structs, bitflags, DirEntryData) — has encode_to:
    (@encode $w:ident, $val:expr, $ty:tt $(<$lt:lifetime>)?) => {
        $val.encode_to($w)?;
    };

    // ── Decode dispatch ──────────────────────────────────────────────────────
    // Types with unique wire-format helpers:
    (@decode $d:ident, FcallStr $(<$lt:lifetime>)?) => {
        $d.decode_str()?
    };
    (@decode $d:ident, VecFcallStr $(<$lt:lifetime>)?) => {
        $d.decode_vec_str()?
    };
    (@decode $d:ident, VecQid) => {
        $d.decode_vec_qid()?
    };
    (@decode $d:ident, DataBuf $(<$lt:lifetime>)?) => {
        $d.decode_data_buf()?
    };
    // Primitives — decoded from little-endian:
    (@decode $d:ident, u8) => { $d.decode_le::<u8>()? };
    (@decode $d:ident, u16) => { $d.decode_le::<u16>()? };
    (@decode $d:ident, u32) => { $d.decode_le::<u32>()? };
    (@decode $d:ident, u64) => { $d.decode_le::<u64>()? };
    // Everything else (Serializer! structs, bitflags, DirEntryData) — has decode_from:
    (@decode $d:ident, $ty:tt $(<$lt:lifetime>)?) => {
        $ty::decode_from($d)?
    };
}

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

/// Type aliases for complex generic types used as `Serializer!` fields.
type VecFcallStr<'a> = Vec<FcallStr<'a>>;
type VecQid = Vec<Qid>;
type DataBuf<'a> = Cow<'a, [u8]>;

/// Generates `encode_to` and `decode_from` methods for bitflags types so they
/// participate in the `Serializer!` fallback dispatch.
macro_rules! impl_bitflags_serializer {
    ($($name:ident),* $(,)?) => {
        $(
            impl $name {
                fn encode_to<W: transport::Write>(&self, w: &mut W) -> Result<(), transport::WriteError> {
                    encode_le(w, self.bits())
                }

                fn decode_from(d: &mut FcallDecoder<'_>) -> Result<Self, super::Error> {
                    Ok(Self::from_bits_truncate(d.decode_le()?))
                }
            }
        )*
    };
}

impl_bitflags_serializer! {
    LOpenFlags,
    GetattrMask,
    SetattrMask,
    LockStatus,
    LockFlag,
    LockType,
    QidType,
}

/// Directory entry data container
#[derive(Clone, Debug)]
pub(super) struct DirEntryData<'a> {
    pub(super) data: Vec<DirEntry<'a>>,
}

impl<'a> DirEntryData<'a> {
    /// Calculate the total size of all entries
    fn size(&self) -> u64 {
        self.data.iter().fold(0, |a, e| a + e.size())
    }

    fn encode_to<W: transport::Write>(&self, w: &mut W) -> Result<(), transport::WriteError> {
        encode_le(
            w,
            u32::try_from(self.size()).map_err(|_| transport::WriteError)?,
        )?;
        for e in &self.data {
            e.encode_to(w)?;
        }
        Ok(())
    }

    fn decode_from(d: &mut FcallDecoder<'a>) -> Result<Self, super::Error> {
        let end_len = d.buf.len() - d.decode_le::<u32>()? as usize;
        let mut v = Vec::new();
        while d.buf.len() > end_len {
            v.push(DirEntry::decode_from(d)?);
        }
        Ok(DirEntryData { data: v })
    }
}

/// Define a `#[repr($int_ty)]` enum and auto-generate a typed conversion method.
///
/// # Example
/// ```ignore
/// repr_enum! {
///     #[derive(Copy, Clone, Debug)]
///     enum Color: u8, from_u8 {
///         Red   = 1,
///         Green = 2,
///         Blue  = 3,
///     }
/// }
/// assert_eq!(Color::from_u8(2), Some(Color::Green));
/// ```
macro_rules! repr_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident : $int_ty:ty, $from_fn:ident {
            $(
                $(#[$vmeta:meta])*
                $variant:ident = $value:expr
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[repr($int_ty)]
        $vis enum $name {
            $(
                $(#[$vmeta])*
                $variant = $value,
            )*
        }

        impl $name {
            /// Convert a raw integer to the enum, returning `None` for unknown values.
            fn $from_fn(v: $int_ty) -> Option<Self> {
                match v {
                    $( $value => Some(Self::$variant), )*
                    _ => None,
                }
            }
        }
    };
}

repr_enum! {
    /// 9P message types
    #[derive(Copy, Clone, Debug)]
    enum FcallType: u8, from_u8 {
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
}

Serializer! {
    /// Unique identifier for a file
    #[derive(Clone, Debug, Copy)]
    pub(super) struct Qid {
        pub(super) typ: QidType,
        pub(super) version: u32,
        pub(super) path: u64,
    }
}

Serializer! {
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
}

Serializer! {
    /// Time structure
    #[derive(Clone, Debug, Copy, Default)]
    pub(super) struct Time {
        sec: u64,
        nsec: u64,
    }
}

Serializer! {
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
}

Serializer! {
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
}

Serializer! {
    /// Directory entry
    #[derive(Clone, Debug)]
    pub(super) struct DirEntry<'a> {
        pub(super) qid: Qid,
        pub(super) offset: u64,
        pub(super) typ: u8,
        pub(super) name: FcallStr<'a>,
    }
}

impl DirEntry<'_> {
    /// Create an owned copy of this directory entry.
    pub(super) fn into_owned(self) -> DirEntry<'static> {
        DirEntry {
            qid: self.qid,
            offset: self.offset,
            typ: self.typ,
            name: Cow::Owned(self.name.into_owned()),
        }
    }

    /// Calculate the size of this entry when encoded
    fn size(&self) -> u64 {
        (13 + 8 + 1 + 2 + self.name.len()) as u64
    }
}

Serializer! {
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
}

Serializer! {
    /// Get lock request
    #[derive(Clone, Debug)]
    struct Getlock<'a> {
        typ: LockType,
        start: u64,
        length: u64,
        proc_id: u32,
        client_id: FcallStr<'a>,
    }
}

// ============================================================================
// Response/Request structures
// ============================================================================

Serializer! {
    /// Error response
    #[derive(Clone, Debug)]
    pub(super) struct Rlerror {
        pub(super) ecode: u32,
    }
}

impl core::fmt::Display for Rlerror {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Remote error: {}", self.ecode)
    }
}

Serializer! {
    /// Attach request
    #[derive(Clone, Debug)]
    pub(super) struct Tattach<'a> {
        pub(super) fid: u32,
        pub(super) afid: u32,
        pub(super) uname: FcallStr<'a>,
        pub(super) aname: FcallStr<'a>,
        pub(super) n_uname: u32,
    }
}

Serializer! {
    /// Attach response
    #[derive(Clone, Debug)]
    pub(super) struct Rattach {
        pub(super) qid: Qid,
    }
}

Serializer! {
    /// Statfs request
    #[derive(Clone, Debug)]
    pub(super) struct Tstatfs {
        fid: u32,
    }
}

Serializer! {
    /// Statfs response
    #[derive(Clone, Debug)]
    pub(super) struct Rstatfs {
        statfs: Statfs,
    }
}

Serializer! {
    /// Open request
    #[derive(Clone, Debug)]
    pub(super) struct Tlopen {
        pub(super) fid: u32,
        pub(super) flags: LOpenFlags,
    }
}

Serializer! {
    /// Open response
    #[derive(Clone, Debug)]
    pub(super) struct Rlopen {
        pub(super) qid: Qid,
        pub(super) iounit: u32,
    }
}

Serializer! {
    /// Create request
    #[derive(Clone, Debug)]
    pub(super) struct Tlcreate<'a> {
        pub(super) fid: u32,
        pub(super) name: FcallStr<'a>,
        pub(super) flags: LOpenFlags,
        pub(super) mode: u32,
        pub(super) gid: u32,
    }
}

Serializer! {
    /// Create response
    #[derive(Clone, Debug)]
    pub(super) struct Rlcreate {
        pub(super) qid: Qid,
        pub(super) iounit: u32,
    }
}

Serializer! {
    /// Symlink request
    #[derive(Clone, Debug)]
    pub(super) struct Tsymlink<'a> {
        fid: u32,
        name: FcallStr<'a>,
        symtgt: FcallStr<'a>,
        gid: u32,
    }
}

Serializer! {
    /// Symlink response
    #[derive(Clone, Debug)]
    pub(super) struct Rsymlink {
        qid: Qid,
    }
}

Serializer! {
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
}

Serializer! {
    /// Mknod response
    #[derive(Clone, Debug)]
    pub(super) struct Rmknod {
        qid: Qid,
    }
}

Serializer! {
    /// Rename request
    #[derive(Clone, Debug)]
    pub(super) struct Trename<'a> {
        pub(super) fid: u32,
        pub(super) dfid: u32,
        pub(super) name: FcallStr<'a>,
    }
}

Serializer! {
    /// Rename response
    #[derive(Clone, Debug)]
    pub(super) struct Rrename {}
}

Serializer! {
    /// Readlink request
    #[derive(Clone, Debug)]
    pub(super) struct Treadlink {
        fid: u32,
    }
}

Serializer! {
    /// Readlink response
    #[derive(Clone, Debug)]
    pub(super) struct Rreadlink<'a> {
        target: FcallStr<'a>,
    }
}

Serializer! {
    /// Getattr request
    #[derive(Clone, Debug)]
    pub(super) struct Tgetattr {
        pub(super) fid: u32,
        pub(super) req_mask: GetattrMask,
    }
}

Serializer! {
    /// Getattr response
    #[derive(Clone, Debug)]
    pub(super) struct Rgetattr {
        pub(super) valid: GetattrMask,
        pub(super) qid: Qid,
        pub(super) stat: Stat,
    }
}

Serializer! {
    /// Setattr request
    #[derive(Clone, Debug)]
    pub(super) struct Tsetattr {
        pub(super) fid: u32,
        pub(super) valid: SetattrMask,
        pub(super) stat: SetAttr,
    }
}

Serializer! {
    /// Setattr response
    #[derive(Clone, Debug)]
    pub(super) struct Rsetattr {}
}

Serializer! {
    /// Xattr walk request
    #[derive(Clone, Debug)]
    pub(super) struct Txattrwalk<'a> {
        fid: u32,
        new_fid: u32,
        name: FcallStr<'a>,
    }
}

Serializer! {
    /// Xattr walk response
    #[derive(Clone, Debug)]
    pub(super) struct Rxattrwalk {
        size: u64,
    }
}

Serializer! {
    /// Xattr create request
    #[derive(Clone, Debug)]
    pub(super) struct Txattrcreate<'a> {
        fid: u32,
        name: FcallStr<'a>,
        attr_size: u64,
        flags: u32,
    }
}

Serializer! {
    /// Xattr create response
    #[derive(Clone, Debug)]
    pub(super) struct Rxattrcreate {}
}

Serializer! {
    /// Readdir request
    #[derive(Clone, Debug)]
    pub(super) struct Treaddir {
        pub(super) fid: u32,
        pub(super) offset: u64,
        pub(super) count: u32,
    }
}

Serializer! {
    /// Readdir response
    #[derive(Clone, Debug)]
    pub(super) struct Rreaddir<'a> {
        pub(super) data: DirEntryData<'a>,
    }
}

Serializer! {
    /// Fsync request
    #[derive(Clone, Debug)]
    pub(super) struct Tfsync {
        pub(super) fid: u32,
        pub(super) datasync: u32,
    }
}

Serializer! {
    /// Fsync response
    #[derive(Clone, Debug)]
    pub(super) struct Rfsync {}
}

Serializer! {
    /// Lock request
    #[derive(Clone, Debug)]
    pub(super) struct Tlock<'a> {
        fid: u32,
        flock: Flock<'a>,
    }
}

Serializer! {
    /// Lock response
    #[derive(Clone, Debug)]
    pub(super) struct Rlock {
        status: LockStatus,
    }
}

Serializer! {
    /// Getlock request
    #[derive(Clone, Debug)]
    pub(super) struct Tgetlock<'a> {
        fid: u32,
        flock: Getlock<'a>,
    }
}

Serializer! {
    /// Getlock response
    #[derive(Clone, Debug)]
    pub(super) struct Rgetlock<'a> {
        flock: Getlock<'a>,
    }
}

Serializer! {
    /// Link request
    #[derive(Clone, Debug)]
    pub(super) struct Tlink<'a> {
        dfid: u32,
        fid: u32,
        name: FcallStr<'a>,
    }
}

Serializer! {
    /// Link response
    #[derive(Clone, Debug)]
    pub(super) struct Rlink {}
}

Serializer! {
    /// Mkdir request
    #[derive(Clone, Debug)]
    pub(super) struct Tmkdir<'a> {
        pub(super) dfid: u32,
        pub(super) name: FcallStr<'a>,
        pub(super) mode: u32,
        pub(super) gid: u32,
    }
}

Serializer! {
    /// Mkdir response
    #[derive(Clone, Debug)]
    pub(super) struct Rmkdir {
        pub(super) qid: Qid,
    }
}

Serializer! {
    /// Renameat request
    #[derive(Clone, Debug)]
    pub(super) struct Trenameat<'a> {
        olddfid: u32,
        oldname: FcallStr<'a>,
        newdfid: u32,
        newname: FcallStr<'a>,
    }
}

Serializer! {
    /// Renameat response
    #[derive(Clone, Debug)]
    pub(super) struct Rrenameat {}
}

Serializer! {
    /// Unlinkat request
    #[derive(Clone, Debug)]
    pub(super) struct Tunlinkat<'a> {
        pub(super) dfid: u32,
        pub(super) name: FcallStr<'a>,
        pub(super) flags: u32,
    }
}

Serializer! {
    /// Unlinkat response
    #[derive(Clone, Debug)]
    pub(super) struct Runlinkat {}
}

Serializer! {
    /// Auth request
    #[derive(Clone, Debug)]
    pub(super) struct Tauth<'a> {
        afid: u32,
        uname: FcallStr<'a>,
        aname: FcallStr<'a>,
        n_uname: u32,
    }
}

Serializer! {
    /// Auth response
    #[derive(Clone, Debug)]
    pub(super) struct Rauth {
        aqid: Qid,
    }
}

Serializer! {
    /// Version request
    #[derive(Clone, Debug)]
    pub(super) struct Tversion<'a> {
        pub(super) msize: u32,
        pub(super) version: FcallStr<'a>,
    }
}

Serializer! {
    /// Version response
    #[derive(Clone, Debug)]
    pub(super) struct Rversion<'a> {
        pub(super) msize: u32,
        pub(super) version: FcallStr<'a>,
    }
}

Serializer! {
    /// Flush request
    #[derive(Clone, Debug)]
    pub(super) struct Tflush {
        oldtag: u16,
    }
}

Serializer! {
    /// Flush response
    #[derive(Clone, Debug)]
    pub(super) struct Rflush {}
}

Serializer! {
    /// Walk request
    #[derive(Clone, Debug)]
    pub(super) struct Twalk<'a> {
        pub(super) fid: u32,
        pub(super) new_fid: u32,
        pub(super) wnames: VecFcallStr<'a>,
    }
}

Serializer! {
    /// Walk response
    #[derive(Clone, Debug)]
    pub(super) struct Rwalk {
        pub(super) wqids: VecQid,
    }
}

Serializer! {
    /// Read request
    #[derive(Clone, Debug)]
    pub(super) struct Tread {
        pub(super) fid: u32,
        pub(super) offset: u64,
        pub(super) count: u32,
    }
}

Serializer! {
    /// Read response
    #[derive(Clone, Debug)]
    pub(super) struct Rread<'a> {
        pub(super) data: DataBuf<'a>,
    }
}

Serializer! {
    /// Write request
    #[derive(Clone, Debug)]
    pub(super) struct Twrite<'a> {
        pub(super) fid: u32,
        pub(super) offset: u64,
        pub(super) data: DataBuf<'a>,
    }
}

Serializer! {
    /// Write response
    #[derive(Clone, Debug)]
    pub(super) struct Rwrite {
        pub(super) count: u32,
    }
}

Serializer! {
    /// Clunk request
    #[derive(Clone, Debug)]
    pub(super) struct Tclunk {
        pub(super) fid: u32,
    }
}

Serializer! {
    /// Clunk response
    #[derive(Clone, Debug)]
    pub(super) struct Rclunk {}
}

Serializer! {
    /// Remove request
    #[derive(Clone, Debug)]
    pub(super) struct Tremove {
        pub(super) fid: u32,
    }
}

Serializer! {
    /// Remove response
    #[derive(Clone, Debug)]
    pub(super) struct Rremove {}
}

// ============================================================================
// Fcall enum, conversions, and dispatch
// ============================================================================

/// Central dispatch macro: defines the `Fcall` enum, `From` impls, `encode_fcall`,
/// and `FcallDecoder::decode_message` from a single canonical list of message types.
///
/// This ensures all dispatch sites stay in sync automatically.
macro_rules! fcall_types {
    ($($name:ident $(<$lt:lifetime>)?),* $(,)?) => {
        /// 9P protocol message
        #[derive(Clone, Debug)]
        pub(super) enum Fcall<'a> {
            $($name($name $(<$lt>)?),)*
        }

        $(
            impl<'a> From<$name $(<$lt>)?> for Fcall<'a> {
                fn from(v: $name $(<$lt>)?) -> Fcall<'a> {
                    Fcall::$name(v)
                }
            }
        )*

        fn encode_fcall<W: transport::Write>(
            w: &mut W,
            tag: u16,
            fcall: Fcall<'_>,
        ) -> Result<(), transport::WriteError> {
            match fcall {
                $(Fcall::$name(v) => {
                    encode_le(w, FcallType::$name as u8)?;
                    encode_le(w, tag)?;
                    v.encode_to(w)?;
                })*
            }
            Ok(())
        }

        impl<'b> FcallDecoder<'b> {
            fn decode_message(&mut self) -> Result<TaggedFcall<'b>, super::Error> {
                let msg_type = FcallType::from_u8(self.decode_le::<u8>()?);
                let tag = self.decode_le::<u16>()?;
                let fcall = match msg_type {
                    $(Some(FcallType::$name) => Fcall::$name($name::decode_from(self)?),)*
                    None => return Err(super::Error::InvalidResponse),
                };
                Ok(TaggedFcall { tag, fcall })
            }
        }
    };
}

fcall_types! {
    Rlerror,
    Tattach<'a>,
    Rattach,
    Tstatfs,
    Rstatfs,
    Tlopen,
    Rlopen,
    Tlcreate<'a>,
    Rlcreate,
    Tsymlink<'a>,
    Rsymlink,
    Tmknod<'a>,
    Rmknod,
    Trename<'a>,
    Rrename,
    Treadlink,
    Rreadlink<'a>,
    Tgetattr,
    Rgetattr,
    Tsetattr,
    Rsetattr,
    Txattrwalk<'a>,
    Rxattrwalk,
    Txattrcreate<'a>,
    Rxattrcreate,
    Treaddir,
    Rreaddir<'a>,
    Tfsync,
    Rfsync,
    Tlock<'a>,
    Rlock,
    Tgetlock<'a>,
    Rgetlock<'a>,
    Tlink<'a>,
    Rlink,
    Tmkdir<'a>,
    Rmkdir,
    Trenameat<'a>,
    Rrenameat,
    Tunlinkat<'a>,
    Runlinkat,
    Tauth<'a>,
    Rauth,
    Tversion<'a>,
    Rversion<'a>,
    Tflush,
    Rflush,
    Twalk<'a>,
    Rwalk,
    Tread,
    Rread<'a>,
    Twrite<'a>,
    Rwrite,
    Tclunk,
    Rclunk,
    Tremove,
    Rremove,
}

/// Tagged 9P message
///
/// Every 9P message carries a `tag` chosen by the client to match requests
/// with their responses. The special value [`NOTAG`] is reserved for
/// `Tversion`/`Rversion` messages.
#[derive(Clone, Debug)]
pub(super) struct TaggedFcall<'a> {
    /// Unique identifier chosen by the client to correlate a request with its response.
    pub(super) tag: u16,
    /// The 9P message payload.
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
        let size = u32::try_from(buf.len()).map_err(|_| transport::WriteError)?;
        buf[0..4].copy_from_slice(&size.to_le_bytes());

        Ok(())
    }

    /// Decode a message from a buffer
    pub(super) fn decode(buf: &'a [u8]) -> Result<TaggedFcall<'a>, super::Error> {
        if buf.len() < 7 {
            return Err(super::Error::InvalidResponse);
        }

        let mut decoder = FcallDecoder { buf: &buf[4..] };
        decoder.decode_message()
    }
}

// ============================================================================
// Little-endian wire encoding
// ============================================================================

/// Trait for encoding/decoding types in little-endian wire format.
///
/// The 9P protocol uses little-endian byte order for all integer fields.
trait LeWire: Sized + Copy {
    const SIZE: usize;
    fn write_le<W: transport::Write>(self, w: &mut W) -> Result<(), transport::WriteError>;
    fn read_le(buf: &[u8]) -> Option<Self>;
}

macro_rules! impl_le_wire {
    ($($ty:ty),* $(,)?) => {
        $(
            impl LeWire for $ty {
                const SIZE: usize = core::mem::size_of::<$ty>();

                fn write_le<W: transport::Write>(self, w: &mut W) -> Result<(), transport::WriteError> {
                    w.write_all(&self.to_le_bytes())
                }

                fn read_le(buf: &[u8]) -> Option<Self> {
                    Some(<$ty>::from_le_bytes(buf.try_into().ok()?))
                }
            }
        )*
    };
}

impl_le_wire!(u8, u16, u32, u64);

// ============================================================================
// Encoding functions
// ============================================================================

/// Encode a primitive integer in little-endian format to the writer.
fn encode_le<W: transport::Write>(w: &mut W, v: impl LeWire) -> Result<(), transport::WriteError> {
    v.write_le(w)
}

fn encode_str<W: transport::Write>(
    w: &mut W,
    v: &FcallStr<'_>,
) -> Result<(), transport::WriteError> {
    encode_le(
        w,
        u16::try_from(v.len()).map_err(|_| transport::WriteError)?,
    )?;
    w.write_all(v)
}

fn encode_data_buf<W: transport::Write>(w: &mut W, v: &[u8]) -> Result<(), transport::WriteError> {
    encode_le(
        w,
        u32::try_from(v.len()).map_err(|_| transport::WriteError)?,
    )?;
    w.write_all(v)
}

fn encode_vec_str<W: transport::Write>(
    w: &mut W,
    v: &[FcallStr<'_>],
) -> Result<(), transport::WriteError> {
    encode_le(
        w,
        u16::try_from(v.len()).map_err(|_| transport::WriteError)?,
    )?;
    for s in v {
        encode_str(w, s)?;
    }
    Ok(())
}

fn encode_vec_qid<W: transport::Write>(w: &mut W, v: &[Qid]) -> Result<(), transport::WriteError> {
    encode_le(
        w,
        u16::try_from(v.len()).map_err(|_| transport::WriteError)?,
    )?;
    for q in v {
        q.encode_to(w)?;
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
    fn decode_str(&mut self) -> Result<FcallStr<'b>, super::Error> {
        let n = self.decode_le::<u16>()? as usize;
        if self.buf.len() >= n {
            let v = FcallStr::Borrowed(&self.buf[..n]);
            self.buf = &self.buf[n..];
            Ok(v)
        } else {
            Err(super::Error::InvalidResponse)
        }
    }

    fn decode_data_buf(&mut self) -> Result<Cow<'b, [u8]>, super::Error> {
        let n = self.decode_le::<u32>()? as usize;
        if self.buf.len() >= n {
            let v = &self.buf[..n];
            self.buf = &self.buf[n..];
            Ok(Cow::from(v))
        } else {
            Err(super::Error::InvalidResponse)
        }
    }

    fn decode_vec_qid(&mut self) -> Result<Vec<Qid>, super::Error> {
        let len = self.decode_le::<u16>()?;
        let mut v = Vec::new();
        for _ in 0..len {
            v.push(Qid::decode_from(self)?);
        }
        Ok(v)
    }

    fn decode_vec_str(&mut self) -> Result<Vec<FcallStr<'b>>, super::Error> {
        let len = self.decode_le::<u16>()?;
        let mut v = Vec::new();
        for _ in 0..len {
            v.push(self.decode_str()?);
        }
        Ok(v)
    }

    /// Decode a primitive integer from the buffer in little-endian format.
    fn decode_le<T: LeWire>(&mut self) -> Result<T, super::Error> {
        if self.buf.len() >= T::SIZE {
            let v = T::read_le(&self.buf[..T::SIZE]).ok_or(super::Error::InvalidResponse)?;
            self.buf = &self.buf[T::SIZE..];
            Ok(v)
        } else {
            Err(super::Error::InvalidResponse)
        }
    }
}
