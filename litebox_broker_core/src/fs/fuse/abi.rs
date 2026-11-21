// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The FUSE wire format (`linux/fuse.h`), as far as the client uses it.
//!
//! Little-endian, the byte order of the guests this client runs in: FUSE fixes none, and a
//! virtio-fs device learns the driver's from its `FUSE_INIT`. The server is not trusted: a short
//! reply is [`Error::InvalidResponse`]. Layouts are those of 7.12 on ([`MIN_MINOR_VERSION`]);
//! older servers' are shorter.

use alloc::vec::Vec;

use super::{Error, out_of_memory};

/// The protocol major version the client speaks.
pub(super) const KERNEL_VERSION: u32 = 7;
/// The protocol minor version the client asks for.
pub(super) const KERNEL_MINOR_VERSION: u32 = 31;
/// The oldest minor version whose layouts this module encodes.
pub(super) const MIN_MINOR_VERSION: u32 = 12;
/// The minor version that introduced `FUSE_BATCH_FORGET`.
pub(super) const BATCH_FORGET_MINOR_VERSION: u32 = 16;
/// The minor version that introduced `fuse_init_out::max_pages`.
pub(super) const MAX_PAGES_MINOR_VERSION: u32 = 28;

/// The node id of the file system's root, valid from `FUSE_INIT` on, without a lookup.
pub(super) const ROOT_ID: u64 = 1;

/// `FUSE_ATOMIC_O_TRUNC`
pub(super) const INIT_ATOMIC_O_TRUNC: u32 = 1 << 3;
/// `FUSE_BIG_WRITES`
pub(super) const INIT_BIG_WRITES: u32 = 1 << 5;
/// `FUSE_MAX_PAGES`
pub(super) const INIT_MAX_PAGES: u32 = 1 << 22;

/// `FUSE_GETATTR_FH`
pub(super) const GETATTR_FH: u32 = 1;

/// `FATTR_*`
pub(super) mod fattr {
    pub(in super::super) const MODE: u32 = 1 << 0;
    pub(in super::super) const UID: u32 = 1 << 1;
    pub(in super::super) const GID: u32 = 1 << 2;
    pub(in super::super) const SIZE: u32 = 1 << 3;
    pub(in super::super) const ATIME: u32 = 1 << 4;
    pub(in super::super) const MTIME: u32 = 1 << 5;
    pub(in super::super) const FH: u32 = 1 << 6;
    pub(in super::super) const ATIME_NOW: u32 = 1 << 7;
    pub(in super::super) const MTIME_NOW: u32 = 1 << 8;
}

pub(super) const S_IFMT: u32 = 0o170_000;
pub(super) const S_IFDIR: u32 = 0o040_000;
pub(super) const S_IFREG: u32 = 0o100_000;
pub(super) const S_IFLNK: u32 = 0o120_000;
pub(super) const S_IFCHR: u32 = 0o020_000;
const S_IFIFO: u32 = 0o010_000;
const S_IFBLK: u32 = 0o060_000;
const S_IFSOCK: u32 = 0o140_000;

pub(super) const DT_DIR: u32 = 4;
pub(super) const DT_REG: u32 = 8;
pub(super) const DT_LNK: u32 = 10;

/// As on Linux, more than `NAME_MAX`: some hosts' file systems (e.g., vfat, exFAT, CIFS) allow 255
/// UTF-16 units, which take more in UTF-8.
pub(super) const FUSE_NAME_MAX: usize = 1024;
/// `PATH_MAX`, less its NUL.
pub(super) const TARGET_MAX: usize = 4095;

/// `FUSE_*`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(super) enum Opcode {
    Lookup = 1,
    Forget = 2,
    Getattr = 3,
    Setattr = 4,
    Readlink = 5,
    Symlink = 6,
    Mkdir = 9,
    Unlink = 10,
    Rmdir = 11,
    Rename = 12,
    Open = 14,
    Read = 15,
    Write = 16,
    Release = 18,
    Init = 26,
    Opendir = 27,
    Readdir = 28,
    Releasedir = 29,
    Access = 34,
    Create = 35,
    BatchForget = 42,
}

/// `fuse_in_header`.
pub(super) const IN_HEADER_SIZE: usize = 40;
/// `fuse_out_header`.
pub(super) const OUT_HEADER_SIZE: usize = 16;
/// `fuse_attr`.
const ATTR_SIZE: usize = 88;
/// `fuse_attr_out`.
pub(super) const ATTR_OUT_SIZE: usize = 104;
/// `fuse_entry_out`.
pub(super) const ENTRY_OUT_SIZE: usize = 128;
/// `fuse_open_out`.
pub(super) const OPEN_OUT_SIZE: usize = 16;
/// `fuse_write_out`.
pub(super) const WRITE_OUT_SIZE: usize = 8;
/// `fuse_init_out`, as of protocol 7.31.
pub(super) const INIT_OUT_SIZE: usize = 64;
/// `fuse_batch_forget_in`, before its `fuse_forget_one`s.
pub(super) const BATCH_FORGET_IN_SIZE: usize = 8;
/// `fuse_forget_one`.
pub(super) const FORGET_ONE_SIZE: usize = 16;
/// `fuse_dirent` without its name.
const DIRENT_SIZE: usize = 24;

/// A `fuse_in_header`, then the request's arguments.
pub(super) struct Request<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> Request<'a> {
    pub(super) fn new(buf: &'a mut Vec<u8>, opcode: Opcode, unique: u64, nodeid: u64) -> Self {
        buf.clear();
        let mut request = Self { buf };
        request
            .u32(0) // len
            .u32(opcode as u32)
            .u64(unique)
            .u64(nodeid)
            // uid and gid 0: servers such as `virtiofsd` act as themselves, as the userland
            // broker does on host files.
            .u32(0)
            .u32(0)
            .u32(0) // pid
            .u16(0) // total_extlen
            .u16(0); // padding
        debug_assert_eq!(request.buf.len(), IN_HEADER_SIZE);
        request
    }

    pub(super) fn u16(&mut self, value: u16) -> &mut Self {
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub(super) fn u32(&mut self, value: u32) -> &mut Self {
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub(super) fn u64(&mut self, value: u64) -> &mut Self {
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// NUL-terminated.
    pub(super) fn string(&mut self, string: &str) -> &mut Self {
        self.buf.extend_from_slice(string.as_bytes());
        self.buf.push(0);
        self
    }

    /// Fills in the length, with `payload` bytes after the arguments.
    pub(super) fn finish(self, payload: usize) -> Result<&'a [u8], Error> {
        let len = self
            .buf
            .len()
            .checked_add(payload)
            .and_then(|len| u32::try_from(len).ok())
            .ok_or(Error::InvalidPathname)?;
        self.buf[..4].copy_from_slice(&len.to_le_bytes());
        Ok(self.buf)
    }
}

/// Reads a reply's fields in order.
pub(super) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub(super) fn bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let (bytes, rest) = self
            .buf
            .split_at_checked(len)
            .ok_or(Error::InvalidResponse)?;
        self.buf = rest;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (bytes, rest) = self
            .buf
            .split_first_chunk::<N>()
            .ok_or(Error::InvalidResponse)?;
        self.buf = rest;
        Ok(*bytes)
    }

    pub(super) fn u16(&mut self) -> Result<u16, Error> {
        self.array().map(u16::from_le_bytes)
    }

    pub(super) fn u32(&mut self) -> Result<u32, Error> {
        self.array().map(u32::from_le_bytes)
    }

    pub(super) fn i32(&mut self) -> Result<i32, Error> {
        self.array().map(i32::from_le_bytes)
    }

    pub(super) fn u64(&mut self) -> Result<u64, Error> {
        self.array().map(u64::from_le_bytes)
    }

    pub(super) fn skip(&mut self, len: usize) -> Result<(), Error> {
        self.bytes(len).map(|_| ())
    }

    pub(super) fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.buf)
    }
}

/// `fuse_out_header`.
pub(super) struct OutHeader {
    pub(super) len: u32,
    /// Zero, or a negated errno.
    pub(super) error: i32,
    pub(super) unique: u64,
}

impl OutHeader {
    pub(super) fn decode(bytes: &[u8; OUT_HEADER_SIZE]) -> Self {
        let mut r = Reader::new(bytes);
        // In bounds: the header is exactly these fields.
        Self {
            len: r.u32().unwrap_or_default(),
            error: r.i32().unwrap_or_default(),
            unique: r.u64().unwrap_or_default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Time {
    /// A `time_t`, sent as unsigned.
    pub(super) seconds: i64,
    /// Less than a billion.
    pub(super) nanoseconds: u32,
}

/// `fuse_attr`, the fields the client uses.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Attr {
    pub(super) ino: u64,
    pub(super) size: u64,
    pub(super) atime: Time,
    pub(super) mtime: Time,
    pub(super) ctime: Time,
    pub(super) mode: u32,
    pub(super) nlink: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) blksize: u32,
}

impl Attr {
    /// Fails, as Linux's client does, on a size beyond `i64::MAX` (an `off_t`), so that positions
    /// computed from it cannot overflow, and on a mode of no file type.
    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        let ino = r.u64()?;
        let size = r.u64()?;
        if size > i64::MAX.cast_unsigned() {
            return Err(Error::InvalidResponse);
        }
        let _blocks = r.u64()?;
        let [atime, mtime, ctime] = [r.u64()?, r.u64()?, r.u64()?];
        let [atimensec, mtimensec, ctimensec] = [r.u32()?, r.u32()?, r.u32()?];
        let time = |seconds: u64, nanoseconds: u32| {
            if nanoseconds >= 1_000_000_000 {
                return Err(Error::InvalidResponse);
            }
            Ok(Time {
                seconds: seconds.cast_signed(),
                nanoseconds,
            })
        };
        let mode = r.u32()?;
        if !matches!(
            mode & S_IFMT,
            S_IFSOCK | S_IFLNK | S_IFREG | S_IFBLK | S_IFDIR | S_IFCHR | S_IFIFO
        ) {
            return Err(Error::InvalidResponse);
        }
        let nlink = r.u32()?;
        let uid = r.u32()?;
        let gid = r.u32()?;
        let _rdev = r.u32()?;
        let blksize = r.u32()?;
        let _flags = r.u32()?;
        Ok(Self {
            ino,
            size,
            atime: time(atime, atimensec)?,
            mtime: time(mtime, mtimensec)?,
            ctime: time(ctime, ctimensec)?,
            mode,
            nlink,
            uid,
            gid,
            blksize,
        })
    }

    pub(super) fn file_type(&self) -> u32 {
        self.mode & S_IFMT
    }

    pub(super) fn is_dir(&self) -> bool {
        self.file_type() == S_IFDIR
    }
}

/// `fuse_entry_out`, the fields the client uses.
pub(super) struct EntryOut {
    /// Its lookup is counted; zero for a negative entry (no such name).
    pub(super) nodeid: u64,
    /// The default for a negative entry.
    pub(super) attr: Attr,
}

impl EntryOut {
    /// A negative entry's attributes are not interpreted, as on Linux, but must be whole.
    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        let nodeid = r.u64()?;
        // generation, entry_valid, attr_valid, entry_valid_nsec, attr_valid_nsec
        r.skip(3 * 8 + 2 * 4)?;
        if nodeid == 0 {
            r.skip(ATTR_SIZE)?;
            return Ok(Self {
                nodeid,
                attr: Attr::default(),
            });
        }
        let attr = Attr::decode(r)?;
        Ok(Self { nodeid, attr })
    }
}

/// `fuse_attr_out`'s attributes.
pub(super) fn decode_attr_out(r: &mut Reader<'_>) -> Result<Attr, Error> {
    // attr_valid, attr_valid_nsec, dummy
    r.skip(8 + 2 * 4)?;
    Attr::decode(r)
}

/// `FOPEN_*`: how the server opened a file (`fuse_open_out::open_flags`).
pub(super) mod fopen {
    /// Not seekable (`nonseekable_open`), but read and written at a position they advance.
    pub(in super::super) const NONSEEKABLE: u32 = 1 << 2;
    /// No position (`stream_open`): every request is at offset 0, which the server ignores.
    /// Overrides [`NONSEEKABLE`].
    pub(in super::super) const STREAM: u32 = 1 << 4;
}

/// `fuse_open_out`, the fields the client uses.
#[derive(Clone, Copy, Debug)]
pub(super) struct OpenOut {
    pub(super) fh: u64,
    /// `FOPEN_*` bits.
    pub(super) open_flags: u32,
}

pub(super) fn decode_open_out(r: &mut Reader<'_>) -> Result<OpenOut, Error> {
    let fh = r.u64()?;
    let open_flags = r.u32()?;
    // padding
    r.skip(4)?;
    Ok(OpenOut { fh, open_flags })
}

/// `fuse_init_out`, the fields the client uses.
pub(super) struct InitOut {
    pub(super) major: u32,
    pub(super) minor: u32,
    pub(super) flags: u32,
    pub(super) max_write: u32,
    /// `None` if the server did not send it.
    pub(super) max_pages: Option<u16>,
}

impl InitOut {
    /// Older servers send only the first 24 bytes (`FUSE_COMPAT_22_INIT_OUT_SIZE`); `max_pages`
    /// is there from [`MAX_PAGES_MINOR_VERSION`], if the reply is long enough.
    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        let major = r.u32()?;
        let minor = r.u32()?;
        let _max_readahead = r.u32()?;
        let flags = r.u32()?;
        let _max_background = r.u16()?;
        let _congestion_threshold = r.u16()?;
        let max_write = r.u32()?;
        let max_pages = if minor >= MAX_PAGES_MINOR_VERSION {
            // After `time_gran`.
            r.u32().and_then(|_| r.u16()).ok()
        } else {
            None
        };
        Ok(Self {
            major,
            minor,
            flags,
            max_write,
            max_pages,
        })
    }
}

/// `fuse_dirent`, with its name.
pub(super) struct Dirent<'a> {
    pub(super) ino: u64,
    /// The cookie to continue after this entry.
    pub(super) off: u64,
    pub(super) typ: u32,
    pub(super) name: &'a [u8],
}

impl<'a> Dirent<'a> {
    /// The entries in a `FUSE_READDIR` reply, each padded to 8 bytes, the last one included.
    pub(super) fn decode_all(mut data: &'a [u8]) -> Result<Vec<Self>, Error> {
        let mut entries = Vec::new();
        while !data.is_empty() {
            let mut r = Reader::new(data);
            let ino = r.u64()?;
            let off = r.u64()?;
            let namelen = usize::try_from(r.u32()?).map_err(|_| Error::InvalidResponse)?;
            let typ = r.u32()?;
            if namelen > FUSE_NAME_MAX {
                return Err(Error::InvalidResponse);
            }
            let name = r.bytes(namelen)?;
            if name.is_empty() || name.contains(&0) || name.contains(&b'/') {
                return Err(Error::InvalidResponse);
            }
            entries.try_reserve(1).map_err(out_of_memory)?;
            entries.push(Self {
                ino,
                off,
                typ,
                name,
            });
            let record = (DIRENT_SIZE + namelen).next_multiple_of(8);
            data = data.get(record..).ok_or(Error::InvalidResponse)?;
        }
        Ok(entries)
    }
}
