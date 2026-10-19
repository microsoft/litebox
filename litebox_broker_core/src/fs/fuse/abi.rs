// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The FUSE wire format (`linux/fuse.h`), as far as the client uses it.
//!
//! This client encodes every message little-endian, the byte order of the guests it runs in
//! (x86-64, AArch64). FUSE itself does not fix the byte order: a virtio-fs device learns the
//! driver's from its `FUSE_INIT`, and answers in kind. Requests
//! are built with [`Request`]; replies are parsed with [`Reader`], which treats anything short or
//! malformed as [`Error::InvalidResponse`], as the server is not trusted.
//!
//! Layouts are those of protocol 7.12 and later, the oldest the client accepts
//! ([`MIN_MINOR_VERSION`]): older servers use shorter `fuse_entry_out`, `fuse_attr_out`,
//! `fuse_create_in`, and `fuse_mkdir_in`.

use alloc::vec::Vec;

use super::Error;

/// The protocol major version the client speaks.
pub(super) const KERNEL_VERSION: u32 = 7;
/// The protocol minor version the client asks for.
pub(super) const KERNEL_MINOR_VERSION: u32 = 31;
/// The oldest minor version whose layouts this module encodes.
pub(super) const MIN_MINOR_VERSION: u32 = 12;
/// The minor version that introduced `FUSE_BATCH_FORGET`.
pub(super) const BATCH_FORGET_MINOR_VERSION: u32 = 16;

/// The node id of the filesystem's root, valid from `FUSE_INIT` on, without a lookup.
pub(super) const ROOT_ID: u64 = 1;

/// `FUSE_ATOMIC_O_TRUNC`: the server handles `O_TRUNC` in `FUSE_OPEN`.
pub(super) const INIT_ATOMIC_O_TRUNC: u32 = 1 << 3;

/// `FUSE_GETATTR_FH`: `fuse_getattr_in::fh` is valid.
pub(super) const GETATTR_FH: u32 = 1;

/// `FATTR_*`: which `fuse_setattr_in` fields are valid.
pub(super) mod fattr {
    pub(in super::super) const MODE: u32 = 1 << 0;
    pub(in super::super) const UID: u32 = 1 << 1;
    pub(in super::super) const GID: u32 = 1 << 2;
    pub(in super::super) const SIZE: u32 = 1 << 3;
    pub(in super::super) const FH: u32 = 1 << 6;
}

/// `S_IFMT` and the file types the client distinguishes.
pub(super) const S_IFMT: u32 = 0o170_000;
pub(super) const S_IFDIR: u32 = 0o040_000;
pub(super) const S_IFREG: u32 = 0o100_000;

/// `DT_DIR`: a directory entry's type.
pub(super) const DT_DIR: u32 = 4;

/// `FUSE_*` opcodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(super) enum Opcode {
    Lookup = 1,
    Forget = 2,
    Getattr = 3,
    Setattr = 4,
    Mkdir = 9,
    Unlink = 10,
    Rmdir = 11,
    Open = 14,
    Read = 15,
    Write = 16,
    Release = 18,
    Init = 26,
    Opendir = 27,
    Readdir = 28,
    Releasedir = 29,
    Create = 35,
    BatchForget = 42,
}

/// `fuse_in_header`.
pub(super) const IN_HEADER_SIZE: usize = 40;
/// `fuse_out_header`.
pub(super) const OUT_HEADER_SIZE: usize = 16;
/// `fuse_write_in`, between the header and the data of a `FUSE_WRITE`.
pub(super) const WRITE_IN_SIZE: usize = 40;
/// `fuse_batch_forget_in`, before its `fuse_forget_one`s.
pub(super) const BATCH_FORGET_IN_SIZE: usize = 8;
/// `fuse_forget_one`.
pub(super) const FORGET_ONE_SIZE: usize = 16;
/// `fuse_dirent` without its name.
const DIRENT_SIZE: usize = 24;

/// The credentials a request is made with (`fuse_in_header`'s `uid` and `gid`); servers such as
/// `virtiofsd` create files as them.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Credentials {
    pub(super) uid: u32,
    pub(super) gid: u32,
}

/// A request under construction: a `fuse_in_header`, then its arguments.
pub(super) struct Request<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> Request<'a> {
    /// Starts a request in `buf` (cleared), its length to be filled in by [`Self::finish`].
    pub(super) fn new(
        buf: &'a mut Vec<u8>,
        opcode: Opcode,
        unique: u64,
        nodeid: u64,
        credentials: Credentials,
    ) -> Self {
        buf.clear();
        let mut request = Self { buf };
        request
            .u32(0) // len
            .u32(opcode as u32)
            .u64(unique)
            .u64(nodeid)
            .u32(credentials.uid)
            .u32(credentials.gid)
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

    pub(super) fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self
    }

    /// A name argument: its bytes, then a NUL.
    pub(super) fn name(&mut self, name: &str) -> &mut Self {
        self.bytes(name.as_bytes()).bytes(&[0])
    }

    /// Fills in the header's length; returns the whole request.
    pub(super) fn finish(self) -> Result<&'a [u8], Error> {
        let len = u32::try_from(self.buf.len()).map_err(|_| Error::InvalidPathname)?;
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
        if len > self.buf.len() {
            return Err(Error::InvalidResponse);
        }
        let (bytes, rest) = self.buf.split_at(len);
        self.buf = rest;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.bytes(N)?.try_into().unwrap())
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

    /// Whatever is left.
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
    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            len: r.u32()?,
            error: r.i32()?,
            unique: r.u64()?,
        })
    }
}

/// `fuse_attr`, the fields the client uses.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Attr {
    pub(super) ino: u64,
    pub(super) size: u64,
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) rdev: u32,
    pub(super) blksize: u32,
}

impl Attr {
    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        let ino = r.u64()?;
        let size = r.u64()?;
        // blocks, atime, mtime, ctime, atimensec, mtimensec, ctimensec
        r.skip(4 * 8 + 3 * 4)?;
        let mode = r.u32()?;
        let _nlink = r.u32()?;
        let uid = r.u32()?;
        let gid = r.u32()?;
        let rdev = r.u32()?;
        let blksize = r.u32()?;
        let _flags = r.u32()?;
        Ok(Self {
            ino,
            size,
            mode,
            uid,
            gid,
            rdev,
            blksize,
        })
    }

    pub(super) fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
}

/// `fuse_entry_out`, the fields the client uses.
pub(super) struct EntryOut {
    /// The node, its lookup count incremented; zero for a negative entry (no such name).
    pub(super) nodeid: u64,
    pub(super) attr: Attr,
}

impl EntryOut {
    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        let nodeid = r.u64()?;
        // generation, entry_valid, attr_valid, entry_valid_nsec, attr_valid_nsec
        r.skip(3 * 8 + 2 * 4)?;
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

/// `fuse_open_out`'s file handle.
pub(super) fn decode_open_out(r: &mut Reader<'_>) -> Result<u64, Error> {
    let fh = r.u64()?;
    // open_flags, padding
    r.skip(2 * 4)?;
    Ok(fh)
}

/// `fuse_init_out`, the fields the client uses.
pub(super) struct InitOut {
    pub(super) major: u32,
    pub(super) minor: u32,
    pub(super) flags: u32,
    pub(super) max_write: u32,
}

impl InitOut {
    /// Servers answering an older minor version send only the first 24 bytes
    /// (`FUSE_COMPAT_22_INIT_OUT_SIZE`), which is all the client uses.
    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        let major = r.u32()?;
        let minor = r.u32()?;
        let _max_readahead = r.u32()?;
        let flags = r.u32()?;
        let _max_background = r.u16()?;
        let _congestion_threshold = r.u16()?;
        let max_write = r.u32()?;
        Ok(Self {
            major,
            minor,
            flags,
            max_write,
        })
    }
}

/// `fuse_dirent`, with its name.
pub(super) struct Dirent {
    pub(super) ino: u64,
    /// The cookie to continue reading the directory after this entry.
    pub(super) off: u64,
    pub(super) typ: u32,
    pub(super) name: Vec<u8>,
}

impl Dirent {
    /// The entries in a `FUSE_READDIR` reply, each padded to 8 bytes (the last one may not be).
    pub(super) fn decode_all(mut data: &[u8]) -> Result<Vec<Self>, Error> {
        let mut entries = Vec::new();
        while !data.is_empty() {
            let mut r = Reader::new(data);
            let ino = r.u64()?;
            let off = r.u64()?;
            let namelen = usize::try_from(r.u32()?).map_err(|_| Error::InvalidResponse)?;
            let typ = r.u32()?;
            let name = r.bytes(namelen)?;
            if name.is_empty() || name.contains(&0) || name.contains(&b'/') {
                return Err(Error::InvalidResponse);
            }
            entries.push(Self {
                ino,
                off,
                typ,
                name: name.to_vec(),
            });
            let record = (DIRENT_SIZE + namelen).next_multiple_of(8);
            data = data.get(record..).unwrap_or_default();
        }
        Ok(entries)
    }
}
