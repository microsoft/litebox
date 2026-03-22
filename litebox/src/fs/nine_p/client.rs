// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Pipelined 9P client implementation
//!
//! This module provides a high-level client for the 9P2000.L protocol.
//! Multiple guest threads can issue requests concurrently — each request
//! acquires a tag from the [`PendingTable`](super::pending_table::PendingTable),
//! sends its message under the write lock, then spin-waits for the dedicated
//! worker thread to deliver the matching response.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::{Mutex, RawSyncPrimitivesProvider};
use crate::utils::id_pool::IdPool;

use super::Error;
use super::fcall::{self, Fcall, FcallStr, GetattrMask, TaggedFcall};
use super::pending_table::PendingTable;
use super::transport::{self, Read, Write};

/// Fid generator with thread-safe access
struct FidGenerator<Platform: RawSyncPrimitivesProvider> {
    inner: Mutex<Platform, IdPool>,
}

impl<Platform: RawSyncPrimitivesProvider> Default for FidGenerator<Platform> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Platform: RawSyncPrimitivesProvider> FidGenerator<Platform> {
    /// Create a new fid generator
    fn new() -> Self {
        FidGenerator {
            inner: Mutex::new(IdPool::new()),
        }
    }

    /// Allocate a new fid
    fn next(&self) -> Result<u32, Error> {
        self.inner.lock().allocate().ok_or(Error::Io)
    }

    /// Release a fid for reuse
    fn free(&self, id: u32) {
        self.inner.lock().recycle(id);
    }
}

/// 9P client state for writing to the connection
struct ClientWriteState<W> {
    /// The underlying transport (write half)
    transport: W,
    /// Write buffer
    wbuf: Vec<u8>,
}

/// State shared between guest threads (via [`Client`]) and the worker thread
/// (via [`super::WorkerHandle`]).
///
/// Separated from `Client` so that the worker does **not** hold an `Arc` to
/// the transport writer.  When the [`super::FileSystem`] is dropped, the
/// `Client` (and its writer) is dropped immediately, closing the transport.
/// The worker then observes EOF on the reader and exits.
pub(super) struct ClientInner {
    /// Pending request table — coordinates guest threads and the worker
    pending_table: PendingTable,
    /// Set once the transport has observed an unrecoverable I/O failure.
    poisoned: AtomicBool,
}

impl ClientInner {
    /// Called by the 9P worker thread in a loop. Reads one response from
    /// the reader and dispatches it to the pending table by tag.
    ///
    /// Returns `false` when the connection is dead (EOF or error),
    /// signalling the worker to exit.
    pub(super) fn poll_responses<R: Read>(&self, reader: &mut R, reader_buf: &mut Vec<u8>) -> bool {
        if transport::read_to_buf(reader, reader_buf).is_err() {
            self.poisoned.store(true, Ordering::Release);
            return false;
        }

        if reader_buf.len() < 7 {
            self.poisoned.store(true, Ordering::Release);
            return false;
        }
        let tag = u16::from_le_bytes([reader_buf[5], reader_buf[6]]);

        if tag == 0 {
            // Fire-and-forget clunk response — discard
            return true;
        }

        if !self.pending_table.complete(tag, reader_buf) {
            // Response for unknown/freed tag — protocol desync
            self.poisoned.store(true, Ordering::Release);
            return false;
        }
        true
    }
}

/// Pipelined 9P client.
///
/// Guest threads send requests through the write half (protected by a mutex)
/// and spin-wait on the [`PendingTable`] for responses. A dedicated worker
/// thread reads responses from the transport read half and dispatches them
/// by tag via [`ClientInner::poll_responses`].
pub(super) struct Client<Platform: RawSyncPrimitivesProvider, W: Write> {
    /// Maximum message size negotiated with server
    msize: u32,
    /// Write state protected by a mutex (write half of transport)
    write_state: Mutex<Platform, ClientWriteState<W>>,
    /// Shared state visible to the worker thread
    inner: Arc<ClientInner>,
    /// Fid generator
    fids: FidGenerator<Platform>,
}

impl<Platform: RawSyncPrimitivesProvider, W: Write> Client<Platform, W> {
    /// Create a new 9P client, performing version negotiation and attach
    /// synchronously using both halves of the transport.
    ///
    /// After construction the client only retains the write half; the read
    /// half is returned to the caller for use by the response worker thread.
    ///
    /// # Arguments
    /// * `writer` - Write half of the transport
    /// * `reader` - Read half of the transport (returned after handshake)
    /// * `max_msize` - Maximum message size to request
    /// * `uname` - Username for attach
    /// * `aname` - Attach path (e.g. "/")
    pub(super) fn new_with_handshake<R: Read>(
        mut writer: W,
        mut reader: R,
        max_msize: u32,
        uname: &str,
        aname: &str,
    ) -> Result<(Self, R, fcall::Qid, fcall::Fid), Error> {
        const MIN_MSIZE: u32 = 4096 + fcall::READDIRHDRSZ;
        let bufsize = max_msize.max(MIN_MSIZE);

        let mut wbuf = Vec::with_capacity(bufsize as usize);
        let mut rbuf = Vec::with_capacity(bufsize as usize);

        // --- Version handshake (synchronous) ---
        transport::write_message(
            &mut writer,
            &mut wbuf,
            TaggedFcall {
                tag: fcall::NOTAG,
                fcall: Fcall::Tversion(fcall::Tversion {
                    msize: bufsize,
                    version: fcall::FcallStr::Borrowed(b"9P2000.L"),
                }),
            },
        )
        .map_err(|e| match e {
            transport::WriteError::Interrupted => Error::Interrupted,
            transport::WriteError::Io => Error::Io,
        })?;

        let response = transport::read_message(&mut reader, &mut rbuf)?;

        let msize = match response {
            TaggedFcall {
                tag: fcall::NOTAG,
                fcall: Fcall::Rversion(fcall::Rversion { msize, version }),
            } => {
                if &*version != b"9P2000.L" {
                    return Err(Error::InvalidResponse);
                }
                msize.min(bufsize)
            }
            TaggedFcall {
                fcall: Fcall::Rlerror(e),
                ..
            } => return Err(Error::from(e)),
            _ => return Err(Error::InvalidResponse),
        };

        // --- Attach (synchronous) ---
        let fids: FidGenerator<Platform> = FidGenerator::new();
        let fid = fids.next()?;
        transport::write_message(
            &mut writer,
            &mut wbuf,
            TaggedFcall {
                tag: 1,
                fcall: Fcall::Tattach(fcall::Tattach {
                    afid: fcall::NOFID,
                    fid,
                    n_uname: fcall::NONUNAME,
                    uname: fcall::FcallStr::Borrowed(uname.as_bytes()),
                    aname: fcall::FcallStr::Borrowed(aname.as_bytes()),
                }),
            },
        )
        .map_err(|e| match e {
            transport::WriteError::Interrupted => Error::Interrupted,
            transport::WriteError::Io => Error::Io,
        })?;

        let attach_resp = transport::read_message(&mut reader, &mut rbuf)?;
        let (qid, root_fid) = match attach_resp {
            TaggedFcall {
                tag: 1,
                fcall: Fcall::Rattach(fcall::Rattach { qid }),
            } => (qid, fid),
            TaggedFcall {
                fcall: Fcall::Rlerror(e),
                ..
            } => {
                fids.free(fid);
                return Err(Error::from(e));
            }
            _ => {
                fids.free(fid);
                return Err(Error::InvalidResponse);
            }
        };

        wbuf.truncate(msize as usize);

        let client = Client {
            msize,
            write_state: Mutex::new(ClientWriteState {
                transport: writer,
                wbuf,
            }),
            inner: Arc::new(ClientInner {
                pending_table: PendingTable::new(),
                poisoned: AtomicBool::new(false),
            }),
            fids,
        };

        Ok((client, reader, qid, root_fid))
    }

    /// Returns the negotiated maximum message size.
    pub(super) fn msize(&self) -> u32 {
        self.msize
    }

    /// Send a request and wait for the response via the pending table.
    ///
    /// 1. Allocate a tag from the bitmap (spin with backoff if full)
    /// 2. Lock write half, encode + send the request, unlock
    /// 3. Spin-wait for the worker to deliver the response
    /// 4. Decode and process the response
    fn fcall<F, R>(&self, fcall: Fcall<'_>, f: F) -> Result<R, Error>
    where
        F: FnOnce(Fcall<'_>) -> Result<R, Error>,
    {
        if self.inner.poisoned.load(Ordering::Acquire) {
            return Err(Error::Io);
        }

        // 1. Allocate tag (spin with backoff if all in use)
        let tag = loop {
            if let Some(t) = self.inner.pending_table.alloc_tag() {
                break t;
            }
            if self.inner.poisoned.load(Ordering::Acquire) {
                return Err(Error::Io);
            }
            core::hint::spin_loop();
        };

        // 2. Lock write half, encode + send, unlock
        {
            let mut write_state = self.write_state.lock();
            if self.inner.poisoned.load(Ordering::Acquire) {
                self.inner.pending_table.free_tag(tag);
                return Err(Error::Io);
            }
            let ClientWriteState { transport, wbuf } = &mut *write_state;
            if let Err(e) = transport::write_message(
                transport,
                wbuf,
                TaggedFcall {
                    tag: tag.get(),
                    fcall,
                },
            ) {
                self.inner.pending_table.free_tag(tag);
                self.inner.poisoned.store(true, Ordering::Release);
                return Err(match e {
                    transport::WriteError::Interrupted => Error::Interrupted,
                    transport::WriteError::Io => Error::Io,
                });
            }
        } // write lock released here

        // 3. Spin-wait for response from the worker thread
        let completion = match self
            .inner
            .pending_table
            .wait_for_completion(tag, &self.inner.poisoned)
        {
            Ok(c) => c,
            Err(tag) => {
                self.inner.pending_table.free_tag(tag);
                return Err(Error::Io);
            }
        };

        // 4. Decode response and process
        let response =
            fcall::TaggedFcall::decode(&completion).map_err(|_| Error::InvalidResponse)?;
        f(response.fcall)
        // completion dropped here → frees tag automatically
    }

    /// Returns an `Arc` to the shared inner state so the worker can
    /// dispatch responses without preventing the writer from being dropped.
    pub(super) fn shared_inner(&self) -> Arc<ClientInner> {
        Arc::clone(&self.inner)
    }

    /// Walks the path from the given fid.
    ///
    /// The given wnames should not exceed the maximum number of elements (fcall::MAXWELEM),
    /// which is checked at the beginning of the function. This is an internal function that
    /// is used by [`walk_chunked`](Client::walk_chunked), which handles the case where the number of elements exceeds the limit.
    fn walk_once(
        &self,
        fid: fcall::Fid,
        wnames: &[FcallStr],
    ) -> Result<(Vec<fcall::Qid>, fcall::Fid), Error> {
        if wnames.len() > fcall::MAXWELEM {
            return Err(Error::InvalidPathname);
        }
        let new_fid = self.fids.next()?;
        let ret = self.fcall(
            Fcall::Twalk(fcall::Twalk {
                fid,
                new_fid,
                wnames: wnames.to_vec(),
            }),
            |response| match response {
                Fcall::Rwalk(fcall::Rwalk { wqids }) => Ok((wqids, new_fid)),
                Fcall::Rlerror(err) => Err(Error::from(err)),
                _ => Err(Error::InvalidResponse),
            },
        );
        if ret.is_err() {
            self.fids.free(new_fid);
        }
        ret
    }

    /// Walks the path from the given fid, handling paths longer than fcall::MAXWELEM by walking in chunks.
    ///
    /// Returns the qids for each path component and a new fid for the final location on success.
    fn walk_chunked(
        &self,
        fid: fcall::Fid,
        wnames: &[FcallStr],
    ) -> Result<(Vec<fcall::Qid>, fcall::Fid), Error> {
        if wnames.is_empty() {
            return self.walk_once(fid, wnames);
        }
        let mut wqids = Vec::with_capacity(fcall::MAXWELEM);
        let mut f = fid;
        for wnames in wnames.chunks(fcall::MAXWELEM) {
            let (mut new_wqids, new_f) = self.walk_once(f, wnames)?;
            let new_len = new_wqids.len();
            wqids.append(&mut new_wqids);
            // Clunk the old fid if it's not the original fid
            if f != fid {
                self.clunk_async(f);
            }
            f = new_f;
            // It means that the walk failed at the nwqid-th element
            if new_len < wnames.len() {
                self.clunk_async(f);
                return Err(Error::Remote(super::ENOENT));
            }
        }
        Ok((wqids, f))
    }

    /// Walk to a path from a given fid
    ///
    /// Returns the qids for each path component and a new fid for the final location
    pub(super) fn walk<S: AsRef<[u8]>>(
        &self,
        fid: fcall::Fid,
        wnames: &[S],
    ) -> Result<(Vec<fcall::Qid>, fcall::Fid), Error> {
        let wnames: Vec<fcall::FcallStr<'_>> = wnames
            .iter()
            .map(|s| fcall::FcallStr::Borrowed(s.as_ref()))
            .collect();
        self.walk_chunked(fid, &wnames)
    }

    /// Open a file
    pub(super) fn open(
        &self,
        fid: fcall::Fid,
        flags: fcall::LOpenFlags,
    ) -> Result<fcall::Qid, Error> {
        self.fcall(
            Fcall::Tlopen(fcall::Tlopen { fid, flags }),
            |response| match response {
                Fcall::Rlopen(fcall::Rlopen { qid, .. }) => Ok(qid),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Create a file with the given name and flags.
    ///
    /// The input dfid initially represents the parent directory of the new file.
    /// After the call it represents the new file.
    pub(super) fn create(
        &self,
        dfid: fcall::Fid,
        name: &str,
        flags: fcall::LOpenFlags,
        mode: u32,
        gid: u32,
    ) -> Result<(fcall::Qid, fcall::Fid), Error> {
        self.fcall(
            Fcall::Tlcreate(fcall::Tlcreate {
                fid: dfid,
                name: fcall::FcallStr::Borrowed(name.as_bytes()),
                flags,
                mode,
                gid,
            }),
            |response| match response {
                Fcall::Rlcreate(fcall::Rlcreate { qid, iounit: _ }) => Ok((qid, dfid)),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Read from a file
    pub(super) fn read(
        &self,
        fid: fcall::Fid,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        let count = buf.len().min((self.msize - fcall::IOHDRSZ) as usize);
        self.fcall(
            Fcall::Tread(fcall::Tread {
                fid,
                offset,
                count: u32::try_from(count).map_err(|_| Error::InvalidResponse)?,
            }),
            |response| match response {
                Fcall::Rread(fcall::Rread { data }) => {
                    buf[..data.len()].copy_from_slice(&data);
                    Ok(data.len())
                }
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Write to a file
    pub(super) fn write(&self, fid: fcall::Fid, offset: u64, data: &[u8]) -> Result<usize, Error> {
        let count = data.len().min((self.msize - fcall::IOHDRSZ) as usize);
        self.fcall(
            Fcall::Twrite(fcall::Twrite {
                fid,
                offset,
                data: alloc::borrow::Cow::Borrowed(&data[..count]),
            }),
            |response| match response {
                Fcall::Rwrite(fcall::Rwrite { count }) => Ok(count as usize),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Get file attributes
    pub(super) fn getattr(
        &self,
        fid: fcall::Fid,
        req_mask: GetattrMask,
    ) -> Result<fcall::Rgetattr, Error> {
        self.fcall(
            Fcall::Tgetattr(fcall::Tgetattr { fid, req_mask }),
            |response| match response {
                Fcall::Rgetattr(r) => Ok(r),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Set file attributes
    pub(super) fn setattr(
        &self,
        fid: fcall::Fid,
        valid: fcall::SetattrMask,
        stat: fcall::SetAttr,
    ) -> Result<(), Error> {
        self.fcall(
            Fcall::Tsetattr(fcall::Tsetattr { fid, valid, stat }),
            |response| match response {
                Fcall::Rsetattr(_) => Ok(()),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Read directory entries starting at the given offset.
    ///
    /// The `offset` is an opaque cookie from the server (taken from
    /// [`DirEntry::offset`](fcall::DirEntry::offset)); pass `0` to start from the beginning.
    /// Use [`readdir_all`](Client::readdir_all) to read all entries.
    pub(super) fn readdir(
        &self,
        fid: fcall::Fid,
        offset: u64,
    ) -> Result<Vec<fcall::DirEntry<'static>>, Error> {
        let count = self.msize - fcall::READDIRHDRSZ;
        self.fcall(
            Fcall::Treaddir(fcall::Treaddir { fid, offset, count }),
            |response| match response {
                Fcall::Rreaddir(fcall::Rreaddir { data }) => Ok(data
                    .data
                    .into_iter()
                    .map(fcall::DirEntry::into_owned)
                    .collect()),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Read all directory entries
    pub(super) fn readdir_all(
        &self,
        fid: fcall::Fid,
    ) -> Result<Vec<fcall::DirEntry<'static>>, Error> {
        let mut all_entries = Vec::new();
        let mut offset = 0u64;
        loop {
            let entries = self.readdir(fid, offset)?;
            if entries.is_empty() {
                break;
            }
            offset = entries.last().unwrap().offset;
            all_entries.extend(entries);
        }
        Ok(all_entries)
    }

    /// Create a directory
    pub(super) fn mkdir(
        &self,
        dfid: fcall::Fid,
        name: &str,
        mode: u32,
        gid: u32,
    ) -> Result<fcall::Qid, Error> {
        self.fcall(
            Fcall::Tmkdir(fcall::Tmkdir {
                dfid,
                name: fcall::FcallStr::Borrowed(name.as_bytes()),
                mode,
                gid,
            }),
            |response| match response {
                Fcall::Rmkdir(fcall::Rmkdir { qid }) => Ok(qid),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Remove the file represented by fid and clunk the fid, even if the remove fails
    pub(super) fn remove(&self, fid: fcall::Fid) -> Result<(), Error> {
        self.fcall(
            Fcall::Tremove(fcall::Tremove { fid }),
            |response| match response {
                Fcall::Rremove(_) => Ok(()),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Remove (unlink) a file or directory
    pub(super) fn unlinkat(&self, dfid: fcall::Fid, name: &str, flags: u32) -> Result<(), Error> {
        self.fcall(
            Fcall::Tunlinkat(fcall::Tunlinkat {
                dfid,
                name: fcall::FcallStr::Borrowed(name.as_bytes()),
                flags,
            }),
            |response| match response {
                Fcall::Runlinkat(_) => Ok(()),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Rename a file
    pub(super) fn rename(
        &self,
        fid: fcall::Fid,
        dfid: fcall::Fid,
        name: &str,
    ) -> Result<(), Error> {
        self.fcall(
            Fcall::Trename(fcall::Trename {
                fid,
                dfid,
                name: fcall::FcallStr::Borrowed(name.as_bytes()),
            }),
            |response| match response {
                Fcall::Rrename(_) => Ok(()),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Fsync a file
    #[expect(dead_code)]
    pub(super) fn fsync(&self, fid: fcall::Fid, datasync: bool) -> Result<(), Error> {
        self.fcall(
            Fcall::Tfsync(fcall::Tfsync {
                fid,
                datasync: u32::from(datasync),
            }),
            |response| match response {
                Fcall::Rfsync(_) => Ok(()),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Clunk (close) a fid
    #[allow(dead_code)]
    pub(super) fn clunk(&self, fid: fcall::Fid) -> Result<(), Error> {
        let result = self.fcall(
            Fcall::Tclunk(fcall::Tclunk { fid }),
            |response| match response {
                Fcall::Rclunk(_) => Ok(()),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        );
        self.fids.free(fid);
        result
    }

    /// Send a Tclunk without waiting for the Rclunk response.
    ///
    /// Uses tag 0 so the worker thread discards the response without
    /// looking it up in the pending table. The fid is intentionally NOT
    /// recycled to the pool because the server may still reference it
    /// until it processes the Tclunk; with u32 fids and short-lived
    /// sandboxes this is safe.
    pub(super) fn clunk_async(&self, fid: fcall::Fid) {
        if self.inner.poisoned.load(Ordering::Acquire) {
            return;
        }
        let mut write_state = self.write_state.lock();
        if self.inner.poisoned.load(Ordering::Acquire) {
            return;
        }
        let ClientWriteState { transport, wbuf } = &mut *write_state;
        if matches!(
            transport::write_message(
                transport,
                wbuf,
                TaggedFcall {
                    tag: 0, // fire-and-forget: worker discards tag-0 responses
                    fcall: Fcall::Tclunk(fcall::Tclunk { fid }),
                },
            ),
            Err(transport::WriteError::Io)
        ) {
            self.inner.poisoned.store(true, Ordering::Release);
        }
    }

    /// Clone a fid (walk with empty path)
    pub(super) fn clone_fid(&self, fid: fcall::Fid) -> Result<fcall::Fid, Error> {
        let empty: [&str; 0] = [];
        let (_, new_fid) = self.walk(fid, &empty)?;
        Ok(new_fid)
    }

    /// Release a fid back to the pool without clunking
    ///
    /// Use this when the fid has already been invalidated (e.g., after remove)
    pub(super) fn free_fid(&self, fid: fcall::Fid) {
        self.fids.free(fid);
    }

    /// Read the target of a symlink identified by `fid`.
    pub(super) fn readlink(&self, fid: fcall::Fid) -> Result<alloc::vec::Vec<u8>, Error> {
        self.fcall(
            Fcall::Treadlink(fcall::Treadlink { fid }),
            |response| match response {
                Fcall::Rreadlink(r) => Ok(r.target.into_owned()),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::io::{Cursor, Read as _};
    use std::sync::{Arc, Mutex as StdMutex};

    use crate::platform::mock::MockPlatform;

    use super::*;

    /// Read half: feeds pre-encoded responses from a `Cursor`.
    struct MockReader {
        reads: Cursor<Vec<u8>>,
    }

    impl Read for MockReader {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, transport::ReadError> {
            self.reads.read(buf).map_err(|_| transport::ReadError::Io)
        }
    }

    fn encode_message(msg: TaggedFcall<'_>) -> Vec<u8> {
        let mut buf = Vec::new();
        transport::write_message(&mut buf, &mut Vec::new(), msg).expect("encode message");
        buf
    }

    /// Build a handshake response pair (Rversion + Rattach) for mock readers.
    fn handshake_responses(msize: u32) -> Vec<u8> {
        let mut resp = Vec::new();
        resp.extend(encode_message(TaggedFcall {
            tag: fcall::NOTAG,
            fcall: Fcall::Rversion(fcall::Rversion {
                msize,
                version: fcall::FcallStr::Borrowed(b"9P2000.L"),
            }),
        }));
        resp.extend(encode_message(TaggedFcall {
            tag: 1,
            fcall: Fcall::Rattach(fcall::Rattach {
                qid: fcall::Qid {
                    typ: fcall::QidType::empty(),
                    version: 0,
                    path: 1,
                },
            }),
        }));
        resp
    }

    /// Channel-based reader: blocks in `recv()` until data is fed via a sender.
    struct ChannelReader {
        rx: std::sync::mpsc::Receiver<Vec<u8>>,
        buf: Cursor<Vec<u8>>,
    }

    impl Read for ChannelReader {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, transport::ReadError> {
            #[allow(clippy::cast_possible_truncation)]
            // Cursor position fits in usize for in-memory buffers
            if self.buf.position() as usize >= self.buf.get_ref().len() {
                match self.rx.recv() {
                    Ok(data) => self.buf = Cursor::new(data),
                    Err(_) => return Err(transport::ReadError::Io),
                }
            }
            self.buf.read(buf).map_err(|_| transport::ReadError::Io)
        }
    }

    /// Writer that records each write and notifies via a channel.
    struct NotifyWriter {
        writes: Arc<StdMutex<Vec<Vec<u8>>>>,
        notify_tx: StdMutex<std::sync::mpsc::Sender<()>>,
    }

    impl Write for NotifyWriter {
        fn write(&mut self, buf: &[u8]) -> Result<usize, transport::WriteError> {
            self.writes.lock().unwrap().push(buf.to_vec());
            let _ = self.notify_tx.lock().unwrap().send(());
            Ok(buf.len())
        }
    }

    #[test]
    fn request_tag_wraps_before_notag() {
        // In the pipelined client, tags are allocated from a 1..=64 bitmap,
        // so they never reach NOTAG (u16::MAX). Verify two sequential fcalls
        // get bitmap-allocated tags.
        let write_log = Arc::new(StdMutex::new(Vec::new()));

        // Channel-based reader: blocks until data is fed via the sender.
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();

        let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

        let handshake_reader = MockReader {
            reads: Cursor::new(handshake_responses(8192)),
        };
        let writer = NotifyWriter {
            writes: write_log.clone(),
            notify_tx: StdMutex::new(notify_tx),
        };
        let (client, _, _, _) = Client::<MockPlatform, _>::new_with_handshake(
            writer,
            handshake_reader,
            8192,
            "root",
            "/",
        )
        .expect("client should initialize");

        // Drain the handshake write notifications
        while notify_rx.try_recv().is_ok() {}

        let client = Arc::new(client);
        let inner = client.shared_inner();
        let channel_reader = ChannelReader {
            rx,
            buf: Cursor::new(Vec::new()),
        };
        let worker = std::thread::spawn(move || {
            let mut reader = channel_reader;
            let mut buf = Vec::with_capacity(8192);
            while inner.poll_responses(&mut reader, &mut buf) {}
        });

        // Helper thread that feeds responses after each request is written.
        let responder = std::thread::spawn(move || {
            // Wait for first request write
            notify_rx.recv().unwrap();
            tx.send(encode_message(TaggedFcall {
                tag: 1,
                fcall: Fcall::Rclunk(fcall::Rclunk {}),
            }))
            .unwrap();
            // Wait for second request write
            notify_rx.recv().unwrap();
            tx.send(encode_message(TaggedFcall {
                tag: 1,
                fcall: Fcall::Rclunk(fcall::Rclunk {}),
            }))
            .unwrap();
            // Drop tx to signal EOF
        });

        client
            .fcall(
                Fcall::Tclunk(fcall::Tclunk { fid: 10 }),
                |response| match response {
                    Fcall::Rclunk(_) => Ok(()),
                    _ => Err(Error::InvalidResponse),
                },
            )
            .expect("first request should succeed");
        client
            .fcall(
                Fcall::Tclunk(fcall::Tclunk { fid: 11 }),
                |response| match response {
                    Fcall::Rclunk(_) => Ok(()),
                    _ => Err(Error::InvalidResponse),
                },
            )
            .expect("second request should succeed");

        responder.join().unwrap();
        worker.join().unwrap();

        let write_log = write_log.lock().unwrap();
        assert_eq!(
            write_log.len(),
            4,
            "version + attach + 2 requests should be written"
        );

        let first = TaggedFcall::decode(&write_log[2]).expect("decode first request");
        let second = TaggedFcall::decode(&write_log[3]).expect("decode second request");
        assert!(
            first.tag >= 1 && first.tag <= 64,
            "first tag {} should be bitmap-allocated (1..=64)",
            first.tag
        );
        assert!(
            second.tag >= 1 && second.tag <= 64,
            "second tag {} should be bitmap-allocated (1..=64)",
            second.tag
        );
    }

    /// Write half that fails after a partial write, simulating a broken connection.
    struct PartialWriteThenFailWriter {
        write_calls: Arc<StdMutex<usize>>,
        allow_handshake_writes: Arc<StdMutex<usize>>,
        fail_after_partial: StdMutex<bool>,
    }

    impl PartialWriteThenFailWriter {
        fn new(write_calls: Arc<StdMutex<usize>>, handshake_writes: usize) -> Self {
            Self {
                write_calls,
                allow_handshake_writes: Arc::new(StdMutex::new(handshake_writes)),
                fail_after_partial: StdMutex::new(false),
            }
        }
    }

    impl Write for PartialWriteThenFailWriter {
        fn write(&mut self, buf: &[u8]) -> Result<usize, transport::WriteError> {
            *self.write_calls.lock().unwrap() += 1;
            let mut allowed = self.allow_handshake_writes.lock().unwrap();
            if *allowed > 0 {
                *allowed -= 1;
                return Ok(buf.len());
            }
            drop(allowed);
            let mut failed = self.fail_after_partial.lock().unwrap();
            if !*failed {
                *failed = true;
                return Ok(buf.len().min(3));
            }
            Err(transport::WriteError::Io)
        }
    }

    #[test]
    fn clunk_async_poisoned_write_failure_blocks_future_requests() {
        let write_calls = Arc::new(StdMutex::new(0));

        let mut responses = handshake_responses(8192);
        // No extra responses needed — clunk_async uses tag 0 (fire-and-forget)
        // and the subsequent fcall will fail before waiting for a response.
        // Add a tag-0 Rclunk so the reader doesn't immediately EOF:
        responses.extend(encode_message(TaggedFcall {
            tag: 0,
            fcall: Fcall::Rclunk(fcall::Rclunk {}),
        }));

        let reader = MockReader {
            reads: Cursor::new(responses),
        };
        // Allow 2 writes for the version+attach handshake
        let writer = PartialWriteThenFailWriter::new(write_calls.clone(), 2);

        let (client, _reader, _, _) =
            Client::<MockPlatform, _>::new_with_handshake(writer, reader, 8192, "root", "/")
                .expect("client should initialize");

        // Reset write call counter after handshake
        *write_calls.lock().unwrap() = 0;

        client.clunk_async(7);
        assert_eq!(
            *write_calls.lock().unwrap(),
            2,
            "async clunk should attempt a partial write and then fail"
        );

        let result = client.fcall(
            Fcall::Tclunk(fcall::Tclunk { fid: 8 }),
            |response| match response {
                Fcall::Rclunk(_) => Ok(()),
                _ => Err(Error::InvalidResponse),
            },
        );
        assert!(matches!(result, Err(Error::Io)));
        assert_eq!(
            *write_calls.lock().unwrap(),
            2,
            "poisoned client must not send further requests"
        );
    }
}
