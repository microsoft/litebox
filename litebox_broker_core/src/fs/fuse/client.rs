// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! FUSE client implementation
//!
//! A synchronous client for the FUSE protocol over a message [`Transport`]: one request in flight
//! at a time, serialized by a lock.

use alloc::vec;
use alloc::vec::Vec;

use litebox_platform::sync::{Mutex, RawSyncPrimitivesProvider};

use super::Error;
use super::abi::{
    self, Attr, Credentials, Dirent, EntryOut, InitOut, Opcode, OutHeader, Reader, Request,
};
use super::transport::Transport;

const PAGE_SIZE: usize = 4096;

/// The smallest message the transport must carry: a write's headers, and a page of data.
const MIN_MESSAGE_SIZE: usize = abi::IN_HEADER_SIZE + abi::WRITE_IN_SIZE + PAGE_SIZE;

/// How many nodes' forgets are held back to be sent together: each costs the server a little
/// (e.g., virtiofsd keeps the file open), but each message costs a round trip to the device.
pub(super) const FORGET_BATCH: usize = 64;
const _: () = assert!(
    abi::IN_HEADER_SIZE + abi::BATCH_FORGET_IN_SIZE + FORGET_BATCH * abi::FORGET_ONE_SIZE
        <= super::transport::MAX_SEND_SIZE
);

/// What a `FUSE_SETATTR` changes; fields not in `valid` are ignored.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SetAttr {
    /// `FATTR_*` bits.
    pub(super) valid: u32,
    pub(super) fh: u64,
    pub(super) size: u64,
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

/// Connection state, behind the client's lock.
struct State<T> {
    transport: T,
    /// The request being built.
    request: Vec<u8>,
    /// The reply, [`Transport::max_message_size`] bytes.
    response: Vec<u8>,
    /// The next request's `unique`; never zero, which servers use for notifications.
    next_unique: u64,
    /// The transport failed; every request fails from then on.
    failed: bool,
    /// Forgets not yet sent, by node: `(nodeid, nlookup)`.
    forgets: Vec<(u64, u64)>,
    /// Whether the server understands `FUSE_BATCH_FORGET`.
    batch_forget: bool,
}

impl<T: Transport> State<T> {
    /// Sends a request (its arguments added by `args`), and parses its reply's body, at most
    /// `max_body` bytes, with `parse`.
    fn call<R>(
        &mut self,
        opcode: Opcode,
        nodeid: u64,
        credentials: Credentials,
        max_body: usize,
        args: impl FnOnce(&mut Request<'_>),
        parse: impl FnOnce(&mut Reader<'_>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        if self.failed {
            return Err(Error::Io);
        }
        let unique = self.next_unique;
        self.next_unique += 1;
        let Self {
            transport,
            request,
            response,
            failed,
            ..
        } = self;
        let mut builder = Request::new(request, opcode, unique, nodeid, credentials);
        args(&mut builder);
        let request = builder.finish()?;
        if request.len() > response.len() {
            // Only names can make a request this long.
            return Err(Error::InvalidPathname);
        }
        // The server is offered no more room than the largest valid reply: some (e.g., virtiofsd
        // 1.10) fill all of it on a `FUSE_READ`, whatever its size, trusting the client (as
        // Linux's) to size it.
        let max_reply = max_body
            .saturating_add(abi::OUT_HEADER_SIZE)
            .min(response.len());
        let response = &mut response[..max_reply];
        let len = transport.round_trip(request, response).map_err(|_| {
            *failed = true;
            Error::Io
        })?;
        let reply = &response[..len.min(response.len())];
        let header = OutHeader::decode(&mut Reader::new(reply))?;
        let body = usize::try_from(header.len)
            .ok()
            .filter(|&len| len >= abi::OUT_HEADER_SIZE)
            .and_then(|len| reply.get(abi::OUT_HEADER_SIZE..len))
            .ok_or(Error::InvalidResponse)?;
        if header.unique != unique {
            return Err(Error::InvalidResponse);
        }
        match header.error {
            0 => parse(&mut Reader::new(body)),
            // A negated errno.
            error @ -4095..=-1 => Err(Error::Remote(error.unsigned_abs())),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Holds back a forget of `nlookup` of `nodeid`'s lookups, sending what is held back once
    /// there is a batch.
    ///
    /// Holding forgets back is always safe: the server keeps the node a little longer, and cannot
    /// reuse its id meanwhile.
    fn forget(&mut self, nodeid: u64, nlookup: u64) {
        match self.forgets.iter_mut().find(|(id, _)| *id == nodeid) {
            Some((_, pending)) => *pending = pending.saturating_add(nlookup),
            None => self.forgets.push((nodeid, nlookup)),
        }
        if self.forgets.len() >= FORGET_BATCH {
            self.flush_forgets();
        }
    }

    /// Sends the forgets held back. Failures are ignored: there is no reply, and a failed
    /// transport is not used again anyway.
    fn flush_forgets(&mut self) {
        let forgets = core::mem::take(&mut self.forgets);
        if forgets.is_empty() {
            return;
        }
        if self.batch_forget {
            let _ = self.send(Opcode::BatchForget, 0, |r| {
                r.u32(u32::try_from(forgets.len()).unwrap()).u32(0); // count, dummy
                for &(nodeid, nlookup) in &forgets {
                    r.u64(nodeid).u64(nlookup);
                }
            });
        } else {
            for (nodeid, nlookup) in forgets {
                let _ = self.send(Opcode::Forget, nodeid, |r| {
                    r.u64(nlookup);
                });
            }
        }
    }

    /// Sends a request that has no reply.
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
        let mut builder = Request::new(
            &mut self.request,
            opcode,
            unique,
            nodeid,
            Credentials::default(),
        );
        args(&mut builder);
        let request = builder.finish()?;
        self.transport.send(request).map_err(|_| {
            self.failed = true;
            Error::Io
        })
    }
}

/// FUSE client
pub(super) struct Client<Platform: RawSyncPrimitivesProvider, T: Transport> {
    state: Mutex<Platform, State<T>>,
    /// The most data a `FUSE_READ` (or `FUSE_READDIR`) asks for.
    max_read: usize,
    /// The most data a `FUSE_WRITE` carries.
    max_write: usize,
    /// Whether the server handles `O_TRUNC` in `FUSE_OPEN`.
    atomic_o_trunc: bool,
}

impl<Platform: RawSyncPrimitivesProvider, T: Transport> Client<Platform, T> {
    /// Cap on the number of entries `readdir_all` will accumulate from an untrusted server before
    /// bailing with `InvalidResponse`.
    const MAX_READDIR_ENTRIES: usize = 1_000_000;

    /// Create a new FUSE client, negotiating the protocol with `FUSE_INIT`.
    pub(super) fn new(transport: T) -> Result<Self, Error> {
        let max_message = transport.max_message_size();
        if max_message < MIN_MESSAGE_SIZE {
            return Err(Error::Io);
        }
        let mut state = State {
            transport,
            request: Vec::with_capacity(max_message),
            response: vec![0; max_message],
            next_unique: 1,
            failed: false,
            forgets: Vec::new(),
            batch_forget: false,
        };
        let init = state.call(
            Opcode::Init,
            0,
            Credentials::default(),
            usize::MAX,
            |r| {
                r.u32(abi::KERNEL_VERSION)
                    .u32(abi::KERNEL_MINOR_VERSION)
                    .u32(0) // max_readahead
                    .u32(abi::INIT_ATOMIC_O_TRUNC);
            },
            InitOut::decode,
        )?;
        // A server with an older major version answers with its own, expecting another
        // `FUSE_INIT` at that version, which this client does not speak; one with a newer major
        // version answers with the client's. Any other major is not a version this client can
        // use either.
        if init.major != abi::KERNEL_VERSION || init.minor < abi::MIN_MINOR_VERSION {
            return Err(Error::InvalidResponse);
        }
        state.batch_forget = init.minor >= abi::BATCH_FORGET_MINOR_VERSION;
        // As Linux does, a server's `max_write` below a page is taken as a page. Transfers are
        // whole pages, so that a file read or written in order stays aligned.
        let max_write = usize::try_from(init.max_write)
            .unwrap_or(usize::MAX)
            .min(max_message - abi::IN_HEADER_SIZE - abi::WRITE_IN_SIZE);
        Ok(Self {
            state: Mutex::new(state),
            max_read: page_floor(max_message - abi::OUT_HEADER_SIZE),
            max_write: page_floor(max_write),
            atomic_o_trunc: init.flags & abi::INIT_ATOMIC_O_TRUNC != 0,
        })
    }

    /// Sends a request whose reply has no more than its fixed-size arguments.
    fn call<R>(
        &self,
        opcode: Opcode,
        nodeid: u64,
        credentials: Credentials,
        args: impl FnOnce(&mut Request<'_>),
        parse: impl FnOnce(&mut Reader<'_>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        self.call_with_data(opcode, nodeid, credentials, usize::MAX, args, parse)
    }

    /// Sends a request whose reply's body is data, at most `max_body` bytes.
    fn call_with_data<R>(
        &self,
        opcode: Opcode,
        nodeid: u64,
        credentials: Credentials,
        max_body: usize,
        args: impl FnOnce(&mut Request<'_>),
        parse: impl FnOnce(&mut Reader<'_>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        self.state
            .lock()
            .call(opcode, nodeid, credentials, max_body, args, parse)
    }

    /// The most data a single [`Self::read`] reads.
    pub(super) fn max_read(&self) -> usize {
        self.max_read
    }

    /// The most data a single [`Self::write`] writes.
    pub(super) fn max_write(&self) -> usize {
        self.max_write
    }

    /// Whether the server truncates on `O_TRUNC` in [`Self::open`]; else the caller must.
    pub(super) fn atomic_o_trunc(&self) -> bool {
        self.atomic_o_trunc
    }

    /// Look up `name` in `parent`, incrementing the node's lookup count.
    pub(super) fn lookup(&self, parent: u64, name: &str) -> Result<EntryOut, Error> {
        check_name(name)?;
        let entry = self.call(
            Opcode::Lookup,
            parent,
            Credentials::default(),
            |r| {
                r.name(name);
            },
            EntryOut::decode,
        )?;
        if entry.nodeid == 0 {
            // A negative entry: the name does not exist.
            return Err(Error::Remote(super::ENOENT));
        }
        Ok(entry)
    }

    /// Drop `nlookup` of `nodeid`'s lookups, eventually: forgets are sent in batches.
    pub(super) fn forget(&self, nodeid: u64, nlookup: u64) {
        self.state.lock().forget(nodeid, nlookup);
    }

    /// Get attributes, of the open file `fh` if given.
    pub(super) fn getattr(&self, nodeid: u64, fh: Option<u64>) -> Result<Attr, Error> {
        self.call(
            Opcode::Getattr,
            nodeid,
            Credentials::default(),
            |r| {
                r.u32(if fh.is_some() { abi::GETATTR_FH } else { 0 })
                    .u32(0) // dummy
                    .u64(fh.unwrap_or(0));
            },
            abi::decode_attr_out,
        )
    }

    /// Set attributes.
    pub(super) fn setattr(&self, nodeid: u64, attr: SetAttr) -> Result<Attr, Error> {
        self.call(
            Opcode::Setattr,
            nodeid,
            Credentials::default(),
            |r| {
                r.u32(attr.valid)
                    .u32(0) // padding
                    .u64(attr.fh)
                    .u64(attr.size)
                    .u64(0) // lock_owner
                    .u64(0) // atime
                    .u64(0) // mtime
                    .u64(0) // ctime
                    .u32(0) // atimensec
                    .u32(0) // mtimensec
                    .u32(0) // ctimensec
                    .u32(attr.mode)
                    .u32(0) // unused4
                    .u32(attr.uid)
                    .u32(attr.gid)
                    .u32(0); // unused5
            },
            abi::decode_attr_out,
        )
    }

    /// Open a file (or, with `dir`, a directory) with Linux `open(2)` `flags`; returns its handle.
    pub(super) fn open(&self, nodeid: u64, flags: u32, dir: bool) -> Result<u64, Error> {
        self.call(
            if dir { Opcode::Opendir } else { Opcode::Open },
            nodeid,
            Credentials::default(),
            |r| {
                r.u32(flags).u32(0); // open_flags
            },
            abi::decode_open_out,
        )
    }

    /// Release an open file (or, with `dir`, directory). Failures are ignored: the handle is gone
    /// either way.
    pub(super) fn release(&self, nodeid: u64, fh: u64, flags: u32, dir: bool) {
        let _ = self.call(
            if dir {
                Opcode::Releasedir
            } else {
                Opcode::Release
            },
            nodeid,
            Credentials::default(),
            |r| {
                r.u64(fh)
                    .u32(flags)
                    .u32(0) // release_flags
                    .u64(0); // lock_owner
            },
            |_| Ok(()),
        );
    }

    /// Read from an open file, at most a message's worth.
    pub(super) fn read(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        let count = buf.len().min(self.max_read);
        self.call_with_data(
            Opcode::Read,
            nodeid,
            Credentials::default(),
            count,
            |r| read_in(r, fh, offset, count),
            |r| {
                let data = r.rest();
                if data.len() > count {
                    return Err(Error::InvalidResponse);
                }
                buf[..data.len()].copy_from_slice(data);
                Ok(data.len())
            },
        )
    }

    /// Write to an open file, at most a message's worth.
    pub(super) fn write(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<usize, Error> {
        let data = &data[..data.len().min(self.max_write)];
        self.call(
            Opcode::Write,
            nodeid,
            Credentials::default(),
            |r| {
                r.u64(fh)
                    .u64(offset)
                    .u32(u32::try_from(data.len()).unwrap())
                    .u32(0) // write_flags
                    .u64(0) // lock_owner
                    .u32(0) // flags
                    .u32(0) // padding
                    .bytes(data);
            },
            |r| {
                let written = usize::try_from(r.u32()?).map_err(|_| Error::InvalidResponse)?;
                if written > data.len() {
                    return Err(Error::InvalidResponse);
                }
                Ok(written)
            },
        )
    }

    /// Read directory entries starting at the given offset.
    ///
    /// The `offset` is an opaque cookie from the server (taken from [`Dirent::off`]); pass `0` to
    /// start from the beginning. An empty result is the end of the directory.
    fn readdir(&self, nodeid: u64, fh: u64, offset: u64) -> Result<Vec<Dirent>, Error> {
        self.call_with_data(
            Opcode::Readdir,
            nodeid,
            Credentials::default(),
            self.max_read,
            |r| read_in(r, fh, offset, self.max_read),
            |r| Dirent::decode_all(r.rest()),
        )
    }

    /// Read all entries of an open directory.
    pub(super) fn readdir_all(&self, nodeid: u64, fh: u64) -> Result<Vec<Dirent>, Error> {
        let mut all_entries = Vec::new();
        let mut offset = 0;
        loop {
            let entries = self.readdir(nodeid, fh, offset)?;
            let Some(last) = entries.last() else {
                break;
            };
            offset = last.off;
            if all_entries
                .len()
                .checked_add(entries.len())
                .is_none_or(|len| len > Self::MAX_READDIR_ENTRIES)
            {
                return Err(Error::InvalidResponse);
            }
            all_entries.extend(entries);
        }
        Ok(all_entries)
    }

    /// Create and open the file `name` in `parent`, as `credentials`; returns its entry (its
    /// lookup count incremented) and handle.
    pub(super) fn create(
        &self,
        parent: u64,
        name: &str,
        flags: u32,
        mode: u32,
        credentials: Credentials,
    ) -> Result<(EntryOut, u64), Error> {
        check_name(name)?;
        self.call(
            Opcode::Create,
            parent,
            credentials,
            |r| {
                r.u32(flags)
                    .u32(mode)
                    .u32(0) // umask: `mode` is final
                    .u32(0) // open_flags
                    .name(name);
            },
            |r| {
                let entry = EntryOut::decode(r)?;
                let fh = abi::decode_open_out(r)?;
                if entry.nodeid == 0 {
                    return Err(Error::InvalidResponse);
                }
                Ok((entry, fh))
            },
        )
    }

    /// Create the directory `name` in `parent`, as `credentials`; returns its entry (its lookup
    /// count incremented).
    pub(super) fn mkdir(
        &self,
        parent: u64,
        name: &str,
        mode: u32,
        credentials: Credentials,
    ) -> Result<EntryOut, Error> {
        check_name(name)?;
        let entry = self.call(
            Opcode::Mkdir,
            parent,
            credentials,
            |r| {
                r.u32(mode)
                    .u32(0) // umask: `mode` is final
                    .name(name);
            },
            EntryOut::decode,
        )?;
        if entry.nodeid == 0 {
            return Err(Error::InvalidResponse);
        }
        Ok(entry)
    }

    /// Remove the file (or, with `dir`, the directory) `name` from `parent`.
    pub(super) fn remove(&self, parent: u64, name: &str, dir: bool) -> Result<(), Error> {
        check_name(name)?;
        self.call(
            if dir { Opcode::Rmdir } else { Opcode::Unlink },
            parent,
            Credentials::default(),
            |r| {
                r.name(name);
            },
            |_| Ok(()),
        )
    }
}

impl<Platform: RawSyncPrimitivesProvider, T: Transport> Drop for Client<Platform, T> {
    /// Sends the forgets still held back: the client goes away once every node does.
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

/// A single path component the server can be asked about: FUSE names are NUL-terminated, and the
/// resolver handles `.` and `..` itself.
fn check_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\0']) {
        return Err(Error::InvalidPathname);
    }
    Ok(())
}
