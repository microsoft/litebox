// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A FUSE client over a message [`Transport`]: one request in flight at a time, serialized by a
//! lock. Forgets are held back and sent in batches ([`FORGET_BATCH`]).

use alloc::vec::Vec;

use hashbrown::HashSet;
use litebox_platform::buffer::{RawBytes, ReadBuffer, WriteBuffer};
use litebox_platform::sync::{Mutex, RawSyncPrimitivesProvider};

use super::abi::{self, Attr, Dirent, EntryOut, InitOut, Opcode, OpenOut, Reader, Request};
use super::transport::{self, Transport};
use super::{Error, out_of_memory};
use crate::BrokerError;

const PAGE_SIZE: usize = 4096;

/// How many nodes' forgets are sent together: a node held costs the server little (virtiofsd keeps
/// an `O_PATH` descriptor open), but each message costs a trip to the device.
pub(super) const FORGET_BATCH: usize = 64;
const _: () = assert!(
    abi::IN_HEADER_SIZE + abi::BATCH_FORGET_IN_SIZE + FORGET_BATCH * abi::FORGET_ONE_SIZE
        <= transport::SMALL_MESSAGE_SIZE
);
// The longest request, a `FUSE_SYMLINK` with the longest name and target (each NUL-terminated),
// fits every transport.
const _: () = assert!(
    abi::IN_HEADER_SIZE + (abi::FUSE_NAME_MAX + 1) + (abi::TARGET_MAX + 1)
        <= transport::MIN_REQUEST_SIZE
);

/// Linux's, without `FUSE_MAX_PAGES`.
const DEFAULT_MAX_PAGES: usize = 32;

/// More than Linux's page: [`Client::readdir_all`] reads whole directories, a round trip per
/// batch, and 64 KiB holds a thousand or so typical entries.
const READDIR_ROOM: usize = 64 * 1024;

/// Caps on a listing from the untrusted server, as for 9P.
const MAX_READDIR_ENTRIES: usize = 1_000_000;
const MAX_READDIR_NAME_BYTES: usize = 64 << 20;

/// Fields not in `valid` are ignored.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SetAttr {
    /// `FATTR_*` bits.
    pub(super) valid: u32,
    pub(super) fh: u64,
    pub(super) size: u64,
    pub(super) atime: abi::Time,
    pub(super) mtime: abi::Time,
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

pub(super) struct DirEntry {
    pub(super) ino: u64,
    /// `DT_*`.
    pub(super) typ: u32,
    pub(super) name: Vec<u8>,
}

#[derive(Clone, Copy)]
struct Payload<'a> {
    source: &'a dyn WriteBuffer,
    offset: usize,
    len: usize,
}

struct Body<'a> {
    raw: RawBytes<'a>,
    scratch: &'a mut Vec<u8>,
}

impl<'a> Body<'a> {
    /// A snapshot, which the server cannot change as it is parsed.
    fn bytes(self) -> Result<&'a [u8], Error> {
        let Self { raw, scratch } = self;
        scratch.clear();
        scratch.try_reserve(raw.len()).map_err(out_of_memory)?;
        scratch.resize(raw.len(), 0);
        raw.copy_to_slice(scratch);
        Ok(scratch.as_slice())
    }
}

struct State<T> {
    transport: T,
    request: Vec<u8>,
    /// Where reply bodies are copied out to be parsed.
    scratch: Vec<u8>,
    /// Never zero, which servers use for notifications.
    next_unique: u64,
    failed: bool,
    /// `(nodeid, nlookup)`, one per node.
    forgets: Vec<(u64, u64)>,
    batch_forget: bool,
}

impl<T: Transport> State<T> {
    fn call<R>(
        &mut self,
        opcode: Opcode,
        nodeid: u64,
        args: impl FnOnce(&mut Request<'_>),
        payload: Option<Payload<'_>>,
        room: usize,
        parse: impl FnOnce(Body<'_>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        if self.failed {
            return Err(Error::Io);
        }
        let unique = self.next_unique;
        self.next_unique += 1;
        let Self {
            transport,
            request,
            scratch,
            failed,
            ..
        } = self;
        let payload_len = payload.map_or(0, |payload| payload.len);
        let mut builder = Request::new(request, opcode, unique, nodeid);
        args(&mut builder);
        let request = builder.finish(payload_len)?;
        if request.len() > transport.max_request_size() {
            // Only names make requests this long.
            return Err(Error::InvalidPathname);
        }
        if let Some(Payload {
            source,
            offset,
            len,
        }) = payload
        {
            let Some(buffer) = transport.payload() else {
                *failed = true;
                return Err(Error::Io);
            };
            source.copy_to_raw_at(offset, buffer.subrange(0..len))?;
        }
        let reply = transport.round_trip(request, payload_len, room).map_err(
            |transport::TransportError| {
                *failed = true;
                Error::Io
            },
        )?;
        let header = abi::OutHeader::decode(&reply.header);
        let body_len = usize::try_from(header.len)
            .ok()
            .and_then(|len| len.checked_sub(abi::OUT_HEADER_SIZE))
            .filter(|&len| {
                header.unique == unique
                    && len <= room
                    && len <= reply.body.len()
                    && abi::OUT_HEADER_SIZE + len <= reply.len
            })
            .ok_or(Error::InvalidResponse)?;
        match header.error {
            0 => parse(Body {
                raw: reply.body.subrange(0..body_len),
                scratch,
            }),
            // Without a body. As Linux's client, which reserves -512 on (e.g., `ERESTARTSYS`).
            error @ -511..=-1 if body_len == 0 => Err(Error::Remote(error.unsigned_abs())),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Holding forgets back is safe: the server keeps the node longer, and cannot reuse its id.
    fn forget(&mut self, nodeid: u64, nlookup: u64) {
        match self.forgets.iter_mut().find(|(id, _)| *id == nodeid) {
            Some((_, pending)) => *pending = pending.saturating_add(nlookup),
            None => self.forgets.push((nodeid, nlookup)),
        }
        if self.forgets.len() >= FORGET_BATCH {
            self.flush_forgets();
        }
    }

    /// Failures are ignored: there is no reply, and a failed transport is not used again.
    fn flush_forgets(&mut self) {
        if self.forgets.is_empty() {
            return;
        }
        let forgets = core::mem::take(&mut self.forgets);
        if self.batch_forget {
            let count = u32::try_from(forgets.len()).expect("a batch is small");
            let _ = self.send(Opcode::BatchForget, 0, |r| {
                r.u32(count).u32(0); // count, dummy
                for &(nodeid, nlookup) in &forgets {
                    r.u64(nodeid).u64(nlookup);
                }
            });
        } else {
            for &(nodeid, nlookup) in &forgets {
                let _ = self.send(Opcode::Forget, nodeid, |r| {
                    r.u64(nlookup);
                });
            }
        }
        // Keep the allocation for the next batch.
        self.forgets = forgets;
        self.forgets.clear();
    }

    fn send(
        &mut self,
        opcode: Opcode,
        nodeid: u64,
        args: impl FnOnce(&mut Request<'_>),
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Io);
        }
        let unique = self.next_unique;
        self.next_unique += 1;
        let mut builder = Request::new(&mut self.request, opcode, unique, nodeid);
        args(&mut builder);
        let request = builder.finish(0)?;
        self.transport.send(request).map_err(|_| {
            self.failed = true;
            Error::Io
        })
    }
}

pub(super) struct Client<Platform: RawSyncPrimitivesProvider, T: Transport> {
    state: Mutex<Platform, State<T>>,
    max_read: usize,
    max_write: usize,
    atomic_o_trunc: bool,
}

/// The most a `FUSE_READ` and a `FUSE_WRITE` carry: whole pages, as on Linux, so that transfers in
/// order stay aligned.
pub(super) fn io_sizes(init: &InitOut, max_payload: usize) -> (usize, usize) {
    // A server's limit of no pages is taken as one, as on Linux.
    let max_pages = match init.max_pages {
        Some(max_pages) if init.flags & abi::INIT_MAX_PAGES != 0 => usize::from(max_pages.max(1)),
        _ => DEFAULT_MAX_PAGES,
    };
    let max_data = max_payload.min(max_pages * PAGE_SIZE);
    // As on Linux, a page without `FUSE_BIG_WRITES`, and at least a page with it.
    let max_write = if init.flags & abi::INIT_BIG_WRITES == 0 {
        PAGE_SIZE
    } else {
        usize::try_from(init.max_write)
            .unwrap_or(usize::MAX)
            .min(max_data)
    };
    (page_floor(max_data), page_floor(max_write))
}

impl<Platform: RawSyncPrimitivesProvider, T: Transport> Client<Platform, T> {
    /// Negotiates the protocol with `FUSE_INIT`.
    pub(super) fn new(transport: T) -> Result<Self, Error> {
        let max_payload = transport.max_payload_size();
        if transport.max_request_size() < transport::MIN_REQUEST_SIZE
            || max_payload < transport::MIN_PAYLOAD_SIZE
        {
            return Err(Error::Io);
        }
        let mut state = State {
            transport,
            request: Vec::with_capacity(transport::MIN_REQUEST_SIZE),
            scratch: Vec::with_capacity(PAGE_SIZE),
            next_unique: 1,
            failed: false,
            forgets: Vec::with_capacity(FORGET_BATCH),
            batch_forget: false,
        };
        let init = state.call(
            Opcode::Init,
            0,
            |r| {
                r.u32(abi::KERNEL_VERSION)
                    .u32(abi::KERNEL_MINOR_VERSION)
                    .u32(0) // max_readahead
                    .u32(abi::INIT_ATOMIC_O_TRUNC | abi::INIT_BIG_WRITES | abi::INIT_MAX_PAGES);
            },
            None,
            abi::INIT_OUT_SIZE,
            |body| InitOut::decode(&mut Reader::new(body.bytes()?)),
        )?;
        // An older server answers with its own major version, expecting another `FUSE_INIT` at
        // it, which this client does not speak.
        if init.major != abi::KERNEL_VERSION || init.minor < abi::MIN_MINOR_VERSION {
            return Err(Error::InvalidResponse);
        }
        state.batch_forget = init.minor >= abi::BATCH_FORGET_MINOR_VERSION;
        let (max_read, max_write) = io_sizes(&init, max_payload);
        Ok(Self {
            state: Mutex::new(state),
            max_read,
            max_write,
            atomic_o_trunc: init.flags & abi::INIT_ATOMIC_O_TRUNC != 0,
        })
    }

    fn call<R>(
        &self,
        opcode: Opcode,
        nodeid: u64,
        args: impl FnOnce(&mut Request<'_>),
        room: usize,
        parse: impl FnOnce(&mut Reader<'_>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        self.state
            .lock()
            .call(opcode, nodeid, args, None, room, |body| {
                parse(&mut Reader::new(body.bytes()?))
            })
    }

    pub(super) fn max_read(&self) -> usize {
        self.max_read
    }

    pub(super) fn max_write(&self) -> usize {
        self.max_write
    }

    /// Whether the server truncates on `O_TRUNC` in [`Self::open`]; else the caller must.
    pub(super) fn atomic_o_trunc(&self) -> bool {
        self.atomic_o_trunc
    }

    /// The root is no directory's entry, as on Linux: one naming it is invalid, and not forgotten.
    pub(super) fn lookup(&self, parent: u64, name: &str) -> Result<EntryOut, Error> {
        check_name(name)?;
        let entry = self.call(
            Opcode::Lookup,
            parent,
            |r| {
                r.string(name);
            },
            abi::ENTRY_OUT_SIZE,
            EntryOut::decode,
        )?;
        if entry.nodeid == 0 {
            // A negative entry.
            return Err(Error::Remote(super::ENOENT));
        }
        if entry.nodeid == abi::ROOT_ID {
            return Err(Error::InvalidResponse);
        }
        Ok(entry)
    }

    /// Whether the server's user may access `nodeid` as `mask` (`R_OK`, `W_OK`, `X_OK`); as on
    /// Linux, a server without `FUSE_ACCESS` allows everything.
    pub(super) fn access(&self, nodeid: u64, mask: u32) -> Result<(), Error> {
        let result = self.call(
            Opcode::Access,
            nodeid,
            |r| {
                r.u32(mask).u32(0); // padding
            },
            0,
            |_| Ok(()),
        );
        match result {
            Err(Error::Remote(super::ENOSYS)) => Ok(()),
            result => result,
        }
    }

    /// Eventually: forgets are sent in batches.
    pub(super) fn forget(&self, nodeid: u64, nlookup: u64) {
        self.state.lock().forget(nodeid, nlookup);
    }

    pub(super) fn getattr(&self, nodeid: u64, fh: Option<u64>) -> Result<Attr, Error> {
        self.call(
            Opcode::Getattr,
            nodeid,
            |r| {
                r.u32(if fh.is_some() { abi::GETATTR_FH } else { 0 })
                    .u32(0) // dummy
                    .u64(fh.unwrap_or(0));
            },
            abi::ATTR_OUT_SIZE,
            abi::decode_attr_out,
        )
    }

    pub(super) fn setattr(&self, nodeid: u64, attr: SetAttr) -> Result<Attr, Error> {
        self.call(
            Opcode::Setattr,
            nodeid,
            |r| {
                r.u32(attr.valid)
                    .u32(0) // padding
                    .u64(attr.fh)
                    .u64(attr.size)
                    .u64(0) // lock_owner
                    .u64(attr.atime.seconds.cast_unsigned())
                    .u64(attr.mtime.seconds.cast_unsigned())
                    .u64(0) // ctime
                    .u32(attr.atime.nanoseconds)
                    .u32(attr.mtime.nanoseconds)
                    .u32(0) // ctimensec
                    .u32(attr.mode)
                    .u32(0) // unused4
                    .u32(attr.uid)
                    .u32(attr.gid)
                    .u32(0); // unused5
            },
            abi::ATTR_OUT_SIZE,
            abi::decode_attr_out,
        )
    }

    pub(super) fn readlink(&self, nodeid: u64) -> Result<Vec<u8>, Error> {
        let target = self.call(
            Opcode::Readlink,
            nodeid,
            |_| {},
            abi::TARGET_MAX,
            |r| Ok(r.rest().to_vec()),
        )?;
        if target.is_empty() || target.contains(&0) {
            return Err(Error::InvalidResponse);
        }
        Ok(target)
    }

    pub(super) fn open(&self, nodeid: u64, flags: u32, dir: bool) -> Result<OpenOut, Error> {
        self.call(
            if dir { Opcode::Opendir } else { Opcode::Open },
            nodeid,
            |r| {
                r.u32(flags).u32(0); // open_flags
            },
            abi::OPEN_OUT_SIZE,
            abi::decode_open_out,
        )
    }

    /// Failures are ignored: the handle is gone either way.
    pub(super) fn release(&self, nodeid: u64, fh: u64, flags: u32, dir: bool) {
        let _ = self.call(
            if dir {
                Opcode::Releasedir
            } else {
                Opcode::Release
            },
            nodeid,
            |r| {
                r.u64(fh)
                    .u32(flags)
                    .u32(0) // release_flags
                    .u64(0); // lock_owner
            },
            0,
            |_| Ok(()),
        );
    }

    /// Into `buf` from `at`; fewer than `count` bytes is the end of the file.
    pub(super) fn read(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        buf: &mut dyn ReadBuffer,
        at: usize,
        count: usize,
    ) -> Result<usize, Error> {
        assert!(count <= self.max_read && count <= buf.len() - at);
        self.state.lock().call(
            Opcode::Read,
            nodeid,
            |r| read_in(r, fh, offset, count),
            None,
            count,
            |body| {
                buf.copy_from_raw_at(at, body.raw)?;
                Ok(body.raw.len())
            },
        )
    }

    pub(super) fn write(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        buf: &dyn WriteBuffer,
        at: usize,
        count: usize,
    ) -> Result<usize, Error> {
        assert!(count <= self.max_write && count <= buf.len() - at);
        let size = u32::try_from(count).map_err(|_| Error::Io)?;
        self.state.lock().call(
            Opcode::Write,
            nodeid,
            |r| {
                r.u64(fh)
                    .u64(offset)
                    .u32(size)
                    .u32(0) // write_flags
                    .u64(0) // lock_owner
                    .u32(0) // flags
                    .u32(0); // padding
            },
            Some(Payload {
                source: buf,
                offset: at,
                len: count,
            }),
            abi::WRITE_OUT_SIZE,
            |body| {
                // A whole `fuse_write_out`: the size written, then padding.
                let mut r = Reader::new(body.bytes()?);
                let written = r.u32()?;
                r.skip(4)?;
                usize::try_from(written)
                    .ok()
                    .filter(|&written| written <= count)
                    .ok_or(Error::InvalidResponse)
            },
        )
    }

    /// The server is not trusted to end the directory: a batch must not end at an offset already
    /// read from (cookies are opaque, so need not increase), and the listing is capped
    /// ([`MAX_READDIR_ENTRIES`], [`MAX_READDIR_NAME_BYTES`]).
    pub(super) fn readdir_all(&self, nodeid: u64, fh: u64) -> Result<Vec<DirEntry>, Error> {
        let room = READDIR_ROOM.min(self.max_read);
        let mut entries = Vec::new();
        let mut name_bytes = 0;
        let mut offset = 0;
        let mut read_from = HashSet::new();
        loop {
            read_from
                .try_reserve(1)
                .map_err(|_| Error::from(BrokerError::OutOfMemory))?;
            read_from.insert(offset);
            let next = self.state.lock().call(
                Opcode::Readdir,
                nodeid,
                |r| read_in(r, fh, offset, room),
                None,
                room,
                |body| {
                    let batch = Dirent::decode_all(body.bytes()?)?;
                    let Some(last) = batch.last() else {
                        return Ok(None);
                    };
                    let next = last.off;
                    name_bytes += batch.iter().map(|entry| entry.name.len()).sum::<usize>();
                    if read_from.contains(&next)
                        || entries.len() + batch.len() > MAX_READDIR_ENTRIES
                        || name_bytes > MAX_READDIR_NAME_BYTES
                    {
                        return Err(Error::InvalidResponse);
                    }
                    entries.try_reserve(batch.len()).map_err(out_of_memory)?;
                    for entry in batch {
                        let mut name = Vec::new();
                        name.try_reserve_exact(entry.name.len())
                            .map_err(out_of_memory)?;
                        name.extend_from_slice(entry.name);
                        entries.push(DirEntry {
                            ino: entry.ino,
                            typ: entry.typ,
                            name,
                        });
                    }
                    Ok(Some(next))
                },
            );
            match next {
                Ok(Some(next)) => offset = next,
                Ok(None) => break,
                Err(error) => return Err(error),
            }
        }
        Ok(entries)
    }

    /// The entry's lookup is counted.
    pub(super) fn create(
        &self,
        parent: u64,
        name: &str,
        flags: u32,
        mode: u32,
    ) -> Result<(EntryOut, OpenOut), Error> {
        check_name(name)?;
        let (entry, open) = self.call(
            Opcode::Create,
            parent,
            |r| {
                r.u32(flags)
                    .u32(mode)
                    .u32(0) // umask: `mode` is final
                    .u32(0) // open_flags
                    .string(name);
            },
            abi::ENTRY_OUT_SIZE + abi::OPEN_OUT_SIZE,
            |r| Ok((EntryOut::decode(r)?, abi::decode_open_out(r)?)),
        )?;
        Ok((
            self.new_entry(entry, abi::S_IFREG, Some((open.fh, flags)))?,
            open,
        ))
    }

    /// The entry's lookup is counted.
    pub(super) fn mkdir(&self, parent: u64, name: &str, mode: u32) -> Result<EntryOut, Error> {
        check_name(name)?;
        let entry = self.call(
            Opcode::Mkdir,
            parent,
            |r| {
                r.u32(mode)
                    .u32(0) // umask: `mode` is final
                    .string(name);
            },
            abi::ENTRY_OUT_SIZE,
            EntryOut::decode,
        )?;
        self.new_entry(entry, abi::S_IFDIR, None)
    }

    /// The entry's lookup is counted.
    pub(super) fn symlink(&self, parent: u64, name: &str, target: &str) -> Result<EntryOut, Error> {
        check_name(name)?;
        if target.is_empty() || target.len() > abi::TARGET_MAX || target.contains('\0') {
            return Err(Error::InvalidPathname);
        }
        let entry = self.call(
            Opcode::Symlink,
            parent,
            |r| {
                r.string(name).string(target);
            },
            abi::ENTRY_OUT_SIZE,
            EntryOut::decode,
        )?;
        self.new_entry(entry, abi::S_IFLNK, None)
    }

    /// As on Linux, a new node is not the root, and of the type created (`S_IFMT` bits). Unlike
    /// Linux, a node of another type, which a host race can make as servers such as `virtiofsd`
    /// look the name up after creating it, is forgotten, and its open (`fh`, `flags`) released.
    fn new_entry(
        &self,
        entry: EntryOut,
        file_type: u32,
        open: Option<(u64, u32)>,
    ) -> Result<EntryOut, Error> {
        if matches!(entry.nodeid, 0 | abi::ROOT_ID) {
            return Err(Error::InvalidResponse);
        }
        if entry.attr.file_type() != file_type {
            if let Some((fh, flags)) = open {
                self.release(entry.nodeid, fh, flags, false);
            }
            self.forget(entry.nodeid, 1);
            return Err(Error::InvalidResponse);
        }
        Ok(entry)
    }

    pub(super) fn remove(&self, parent: u64, name: &str, dir: bool) -> Result<(), Error> {
        check_name(name)?;
        self.call(
            if dir { Opcode::Rmdir } else { Opcode::Unlink },
            parent,
            |r| {
                r.string(name);
            },
            0,
            |_| Ok(()),
        )
    }

    pub(super) fn rename(
        &self,
        old_parent: u64,
        old_name: &str,
        new_parent: u64,
        new_name: &str,
    ) -> Result<(), Error> {
        check_name(old_name)?;
        check_name(new_name)?;
        self.call(
            Opcode::Rename,
            old_parent,
            |r| {
                r.u64(new_parent).string(old_name).string(new_name);
            },
            0,
            |_| Ok(()),
        )
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: Transport> Drop for Client<Platform, T> {
    /// The client goes away once every node does, so no forget is lost.
    fn drop(&mut self) {
        self.state.lock().flush_forgets();
    }
}

/// `len` rounded down to whole pages, but at least one.
fn page_floor(len: usize) -> usize {
    (len / PAGE_SIZE).max(1) * PAGE_SIZE
}

/// `fuse_read_in`, for `FUSE_READ` and `FUSE_READDIR`.
fn read_in(r: &mut Request<'_>, fh: u64, offset: u64, count: usize) {
    r.u64(fh)
        .u64(offset)
        .u32(u32::try_from(count).unwrap_or(u32::MAX))
        .u32(0) // read_flags
        .u64(0) // lock_owner
        .u32(0) // flags
        .u32(0); // padding
}

/// The resolver handles `.` and `..` itself: the server need not confine them to the export.
fn check_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\0']) {
        return Err(Error::InvalidPathname);
    }
    if name.len() > abi::FUSE_NAME_MAX {
        return Err(Error::Remote(super::ENAMETOOLONG));
    }
    Ok(())
}
