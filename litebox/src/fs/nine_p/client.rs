// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! 9P client implementation
//!
//! This module provides a high-level client for the 9P2000.L protocol.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, Ordering};

use crate::sync::{Mutex, RawSyncPrimitivesProvider};
use crate::utils::id_pool::IdPool;

use super::Error;
use super::fcall::{self, Fcall, FcallStr, GetattrMask, TaggedFcall};
use super::transport::{self, Read, Write};

/// Pool of 9P fid VALUES, shared between the [`Client`] and every live
/// [`Fid`] handle. Recycling a value back to the pool happens only when the
/// last `Fid` clone for that value is dropped, so an in-flight read or write
/// keeps the pool slot reserved even after the descriptor that owned it has
/// been closed. This is what prevents the fid-reuse data-corruption race in
/// concurrent close-during-read.
struct FidPool<Platform: RawSyncPrimitivesProvider> {
    inner: Mutex<Platform, IdPool>,
}

impl<Platform: RawSyncPrimitivesProvider> FidPool<Platform> {
    fn new() -> Self {
        Self {
            inner: Mutex::new(IdPool::new()),
        }
    }

    /// Allocate a raw fid VALUE. The caller is fully responsible for the
    /// lifecycle: call [`recycle`](Self::recycle) if the value never reached
    /// the server (e.g., a Twalk that errored), or [`Client::clunk_raw`] +
    /// recycle if it did. Used for short-lived intermediates inside
    /// [`Client::walk_chunked`] that never escape to user code.
    fn allocate_raw(&self) -> Result<fcall::Fid, Error> {
        self.inner.lock().allocate().ok_or(Error::Io)
    }

    /// Wrap a raw fid value into a refcounted handle, transferring ownership
    /// of the pool slot. The slot is recycled when the LAST [`Fid`] clone is
    /// dropped.
    fn adopt(self: &Arc<Self>, id: fcall::Fid) -> Fid<Platform> {
        Fid {
            inner: Arc::new(FidInner {
                id,
                pool: Arc::clone(self),
            }),
        }
    }

    /// Allocate directly into a refcounted handle. Equivalent to
    /// `adopt(allocate_raw()?)` and used for fids that the caller will hand
    /// out to user code.
    fn allocate(self: &Arc<Self>) -> Result<Fid<Platform>, Error> {
        let id = self.allocate_raw()?;
        Ok(self.adopt(id))
    }

    fn recycle(&self, id: fcall::Fid) {
        self.inner.lock().recycle(id);
    }
}

/// Refcounted handle to a 9P fid value.
///
/// Cheap to clone (one `Arc` bump). The pool slot for the underlying value
/// is reclaimed when the last clone is dropped. The 9P server-side fid is
/// destroyed by [`Client::clunk`], which is independent: a stale Tread
/// issued after a clunk gets `EBADF` from the server, but the *value* will
/// not be reassigned to a different file while any handle still exists, so
/// data corruption is not possible.
pub(super) struct Fid<Platform: RawSyncPrimitivesProvider> {
    inner: Arc<FidInner<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider> Clone for Fid<Platform> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider> Fid<Platform> {
    /// The wire-level u32 fid for encoding into 9P messages.
    pub(super) fn id(&self) -> fcall::Fid {
        self.inner.id
    }
}

impl<Platform: RawSyncPrimitivesProvider> core::fmt::Debug for Fid<Platform> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Fid({})", self.inner.id)
    }
}

struct FidInner<Platform: RawSyncPrimitivesProvider> {
    id: fcall::Fid,
    pool: Arc<FidPool<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider> Drop for FidInner<Platform> {
    fn drop(&mut self) {
        self.pool.recycle(self.id);
    }
}

/// 9P client state for writing to the connection
struct ClientWriteState<T> {
    /// The underlying transport
    transport: T,
    /// Write buffer
    wbuf: Vec<u8>,
}

/// 9P client
///
/// This client provides synchronous 9P protocol operations. It uses a transport
/// that implements both Read and Write traits.
pub(super) struct Client<Platform: RawSyncPrimitivesProvider, T: Read + Write> {
    /// Maximum message size negotiated with server
    msize: u32,
    /// Write state protected by a mutex
    write_state: Mutex<Platform, ClientWriteState<T>>,
    /// Read buffer for responses
    rbuf: Mutex<Platform, Vec<u8>>,
    /// Pool of fid values, shared with every live [`Fid`] handle.
    fids: Arc<FidPool<Platform>>,
    /// Next tag for synchronous operations
    next_tag: AtomicU16,
}

impl<Platform: RawSyncPrimitivesProvider, T: Read + Write> Client<Platform, T> {
    const MAX_READDIR_ENTRIES: usize = 1_000_000;

    /// Create a new 9P client and perform version negotiation
    ///
    /// # Arguments
    /// * `transport` - The underlying transport for read/write operations
    /// * `max_msize` - Maximum message size to request
    pub(super) fn new(mut transport: T, max_msize: u32) -> Result<Self, Error> {
        const MIN_MSIZE: u32 = 4096 + fcall::READDIRHDRSZ;
        let bufsize = max_msize.max(MIN_MSIZE);

        let mut wbuf = Vec::with_capacity(bufsize as usize);
        let mut rbuf = Vec::with_capacity(bufsize as usize);

        // Perform version handshake
        transport::write_message(
            &mut transport,
            &mut wbuf,
            TaggedFcall {
                tag: fcall::NOTAG,
                fcall: Fcall::Tversion(fcall::Tversion {
                    msize: bufsize,
                    version: fcall::FcallStr::Borrowed(b"9P2000.L"),
                }),
            },
        )
        .map_err(|_| Error::Io)?;

        let response = transport::read_message(&mut transport, &mut rbuf, bufsize as usize)?;

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
        if msize < fcall::IOHDRSZ.max(fcall::READDIRHDRSZ) {
            return Err(Error::InvalidResponse);
        }

        wbuf.truncate(msize as usize);
        rbuf.truncate(msize as usize);

        Ok(Client {
            msize,
            write_state: Mutex::new(ClientWriteState { transport, wbuf }),
            rbuf: Mutex::new(rbuf),
            fids: Arc::new(FidPool::new()),
            next_tag: AtomicU16::new(1),
        })
    }

    /// Send a request and wait for the response
    fn fcall<F, R>(&self, fcall: Fcall<'_>, f: F) -> Result<R, Error>
    where
        F: FnOnce(Fcall<'_>) -> Result<R, Error>,
    {
        let tag = self.next_tag();

        let mut write_state = self.write_state.lock();
        let ClientWriteState { transport, wbuf } = &mut *write_state;
        transport::write_message(transport, wbuf, TaggedFcall { tag, fcall })
            .map_err(|_| Error::Io)?;

        let mut rbuf = self.rbuf.lock();
        let response = transport::read_message(transport, &mut rbuf, self.msize as usize)?;
        if response.tag != tag {
            return Err(Error::InvalidResponse);
        }
        f(response.fcall)
    }

    fn next_tag(&self) -> u16 {
        loop {
            let current = self.next_tag.load(Ordering::Relaxed);
            debug_assert!(current != fcall::NOTAG);
            let next = if current == fcall::NOTAG - 1 {
                1
            } else {
                current + 1
            };
            if self
                .next_tag
                .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return current;
            }
        }
    }

    /// Attach to a remote filesystem
    pub(super) fn attach(
        &self,
        uname: &str,
        aname: &str,
    ) -> Result<(fcall::Qid, Fid<Platform>), Error> {
        let fid = self.fids.allocate()?;
        let id = fid.id();
        let res = self.fcall(
            Fcall::Tattach(fcall::Tattach {
                afid: fcall::NOFID,
                fid: id,
                n_uname: fcall::NONUNAME,
                uname: fcall::FcallStr::Borrowed(uname.as_bytes()),
                aname: fcall::FcallStr::Borrowed(aname.as_bytes()),
            }),
            |response| match response {
                Fcall::Rattach(fcall::Rattach { qid }) => Ok(qid),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        );
        // On error, `fid` drops here and its FidInner::drop returns the value
        // to the pool. On success, the caller owns the Fid and is responsible
        // for clunking when done.
        res.map(|qid| (qid, fid))
    }

    /// Internal: walks one chunk on raw u32 fids.
    ///
    /// Allocates a fresh fid value via [`FidPool::allocate_raw`], sends Twalk,
    /// and returns the new value on success. On error the fid is recycled
    /// directly (a failed Twalk does not establish newfid server-side, so no
    /// Tclunk is needed). Used as the building block for both [`Client::walk_once`]
    /// (which promotes the result into a [`Fid`]) and [`Client::walk_chunked`] (which
    /// keeps intermediates as raw u32 to avoid one `Arc` allocation per chunk
    /// on deep paths).
    fn walk_once_raw(
        &self,
        fid: fcall::Fid,
        wnames: &[FcallStr],
    ) -> Result<(Vec<fcall::Qid>, fcall::Fid), Error> {
        if wnames.len() > fcall::MAXWELEM {
            return Err(Error::InvalidPathname);
        }
        let new_fid = self.fids.allocate_raw()?;
        let ret = self.fcall(
            Fcall::Twalk(fcall::Twalk {
                fid,
                new_fid,
                wnames: wnames.to_vec(),
            }),
            |response| match response {
                Fcall::Rwalk(fcall::Rwalk { wqids }) => Ok(wqids),
                Fcall::Rlerror(err) => Err(Error::from(err)),
                _ => Err(Error::InvalidResponse),
            },
        );
        match ret {
            Ok(wqids) => Ok((wqids, new_fid)),
            Err(err) => {
                self.fids.recycle(new_fid);
                Err(err)
            }
        }
    }

    /// Internal: clunk a raw u32 fid value. Sends Tclunk and recycles the
    /// pool slot. Errors from the server are swallowed (the resource is
    /// being torn down anyway).
    fn clunk_raw(&self, fid: fcall::Fid) {
        let _ = self.fcall(
            Fcall::Tclunk(fcall::Tclunk { fid }),
            |response| match response {
                Fcall::Rclunk(_) => Ok(()),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        );
        self.fids.recycle(fid);
    }

    /// Walks the path from the given fid.
    ///
    /// The given wnames should not exceed the maximum number of elements (fcall::MAXWELEM),
    /// which is checked at the beginning of the function. This is an internal function that
    /// is used by [`walk_chunked`](Client::walk_chunked), which handles the case where the number of elements exceeds the limit.
    fn walk_once(
        &self,
        fid: &Fid<Platform>,
        wnames: &[FcallStr],
    ) -> Result<(Vec<fcall::Qid>, Fid<Platform>), Error> {
        let (wqids, raw) = self.walk_once_raw(fid.id(), wnames)?;
        Ok((wqids, self.fids.adopt(raw)))
    }

    /// Walks the path from the given fid, handling paths longer than fcall::MAXWELEM by walking in chunks.
    ///
    /// Returns the qids for each path component and a new fid for the final location on success.
    /// Intermediate fids between chunks are kept as raw u32 to avoid an `Arc` allocation per
    /// chunk; only the final result is promoted into a [`Fid`] handle.
    fn walk_chunked(
        &self,
        fid: &Fid<Platform>,
        wnames: &[FcallStr],
    ) -> Result<(Vec<fcall::Qid>, Fid<Platform>), Error> {
        if wnames.is_empty() {
            return self.walk_once(fid, wnames);
        }
        let mut wqids = Vec::with_capacity(fcall::MAXWELEM);
        // `None` means we're still walking from the caller's input fid;
        // `Some` is a raw intermediate that must be clunked before moving on.
        let mut prev: Option<fcall::Fid> = None;
        for chunk in wnames.chunks(fcall::MAXWELEM) {
            let from = prev.unwrap_or_else(|| fid.id());
            let (mut new_wqids, new_f) = match self.walk_once_raw(from, chunk) {
                Ok(v) => v,
                Err(err) => {
                    if let Some(p) = prev {
                        self.clunk_raw(p);
                    }
                    return Err(err);
                }
            };
            let new_len = new_wqids.len();
            wqids.append(&mut new_wqids);
            if let Some(p) = prev.take() {
                self.clunk_raw(p);
            }
            if new_len < chunk.len() {
                // Partial Rwalk: see `test_nine_p_partial_walk_newfid_lifecycle`
                // — diod establishes new_fid even on a partial walk, so we
                // must clunk it (server-side cleanup). `clunk_raw` swallows
                // any Rlerror, so this is also safe against servers that
                // follow a stricter spec read.
                self.clunk_raw(new_f);
                return Err(Error::Remote(super::ENOENT));
            }
            prev = Some(new_f);
        }
        // `prev` is `Some` because `wnames` was non-empty. Promote the final
        // raw fid into a refcounted handle for the caller.
        Ok((wqids, self.fids.adopt(prev.unwrap())))
    }

    /// Walk to a path from a given fid
    ///
    /// Returns the qids for each path component and a new fid for the final location
    pub(super) fn walk<S: AsRef<[u8]>>(
        &self,
        fid: &Fid<Platform>,
        wnames: &[S],
    ) -> Result<(Vec<fcall::Qid>, Fid<Platform>), Error> {
        let wnames: Vec<fcall::FcallStr<'_>> = wnames
            .iter()
            .map(|s| fcall::FcallStr::Borrowed(s.as_ref()))
            .collect();
        self.walk_chunked(fid, &wnames)
    }

    /// Open a file
    pub(super) fn open(
        &self,
        fid: &Fid<Platform>,
        flags: fcall::LOpenFlags,
    ) -> Result<fcall::Qid, Error> {
        self.fcall(
            Fcall::Tlopen(fcall::Tlopen {
                fid: fid.id(),
                flags,
            }),
            |response| match response {
                Fcall::Rlopen(fcall::Rlopen { qid, .. }) => Ok(qid),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Create a file with the given name and flags.
    ///
    /// The input `dfid` initially represents the parent directory of the new
    /// file; on success the same fid value represents the new file server-side
    /// and is returned. On error, `dfid` is still bound to the parent dir
    /// per 9P2000.L semantics, so we clunk it here so the caller doesn't have
    /// to manage cleanup of a consumed handle.
    pub(super) fn create(
        &self,
        dfid: Fid<Platform>,
        name: &str,
        flags: fcall::LOpenFlags,
        mode: u32,
        gid: u32,
    ) -> Result<(fcall::Qid, Fid<Platform>), Error> {
        let res = self.fcall(
            Fcall::Tlcreate(fcall::Tlcreate {
                fid: dfid.id(),
                name: fcall::FcallStr::Borrowed(name.as_bytes()),
                flags,
                mode,
                gid,
            }),
            |response| match response {
                Fcall::Rlcreate(fcall::Rlcreate { qid, iounit: _ }) => Ok(qid),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        );
        match res {
            Ok(qid) => Ok((qid, dfid)),
            Err(err) => {
                self.clunk(dfid);
                Err(err)
            }
        }
    }

    /// Read from a file
    pub(super) fn read(
        &self,
        fid: &Fid<Platform>,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        let max_count = self
            .msize
            .checked_sub(fcall::IOHDRSZ)
            .ok_or(Error::InvalidResponse)? as usize;
        let count = buf.len().min(max_count);
        self.fcall(
            Fcall::Tread(fcall::Tread {
                fid: fid.id(),
                offset,
                count: u32::try_from(count).map_err(|_| Error::InvalidResponse)?,
            }),
            |response| match response {
                Fcall::Rread(fcall::Rread { data }) => {
                    if data.len() > count {
                        return Err(Error::InvalidResponse);
                    }
                    buf[..data.len()].copy_from_slice(&data);
                    Ok(data.len())
                }
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Write to a file
    pub(super) fn write(
        &self,
        fid: &Fid<Platform>,
        offset: u64,
        data: &[u8],
    ) -> Result<usize, Error> {
        let max_count = self
            .msize
            .checked_sub(fcall::IOHDRSZ)
            .ok_or(Error::InvalidResponse)? as usize;
        let count = data.len().min(max_count);
        self.fcall(
            Fcall::Twrite(fcall::Twrite {
                fid: fid.id(),
                offset,
                data: alloc::borrow::Cow::Borrowed(&data[..count]),
            }),
            |response| match response {
                Fcall::Rwrite(fcall::Rwrite { count: written }) => {
                    let written = written as usize;
                    if written > count {
                        return Err(Error::InvalidResponse);
                    }
                    Ok(written)
                }
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Get file attributes
    pub(super) fn getattr(
        &self,
        fid: &Fid<Platform>,
        req_mask: GetattrMask,
    ) -> Result<fcall::Rgetattr, Error> {
        self.fcall(
            Fcall::Tgetattr(fcall::Tgetattr {
                fid: fid.id(),
                req_mask,
            }),
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
        fid: &Fid<Platform>,
        valid: fcall::SetattrMask,
        stat: fcall::SetAttr,
    ) -> Result<(), Error> {
        self.fcall(
            Fcall::Tsetattr(fcall::Tsetattr {
                fid: fid.id(),
                valid,
                stat,
            }),
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
        fid: &Fid<Platform>,
        offset: u64,
    ) -> Result<Vec<fcall::DirEntry<'static>>, Error> {
        let count = self
            .msize
            .checked_sub(fcall::READDIRHDRSZ)
            .ok_or(Error::InvalidResponse)?;
        self.fcall(
            Fcall::Treaddir(fcall::Treaddir {
                fid: fid.id(),
                offset,
                count,
            }),
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
        fid: &Fid<Platform>,
    ) -> Result<Vec<fcall::DirEntry<'static>>, Error> {
        let mut all_entries = Vec::new();
        let mut offset = 0u64;
        loop {
            let entries = self.readdir(fid, offset)?;
            if entries.is_empty() {
                break;
            }
            let next_offset = entries.last().unwrap().offset;
            if next_offset <= offset {
                return Err(Error::InvalidResponse);
            }
            if all_entries
                .len()
                .checked_add(entries.len())
                .is_none_or(|len| len > Self::MAX_READDIR_ENTRIES)
            {
                return Err(Error::InvalidResponse);
            }
            offset = next_offset;
            all_entries.extend(entries);
        }
        Ok(all_entries)
    }

    /// Create a directory
    pub(super) fn mkdir(
        &self,
        dfid: &Fid<Platform>,
        name: &str,
        mode: u32,
        gid: u32,
    ) -> Result<fcall::Qid, Error> {
        self.fcall(
            Fcall::Tmkdir(fcall::Tmkdir {
                dfid: dfid.id(),
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

    /// Remove the file represented by `fid`. The server destroys the fid
    /// regardless of whether the remove succeeds or fails, so this consumes
    /// the [`Fid`] handle.
    pub(super) fn remove(&self, fid: Fid<Platform>) -> Result<(), Error> {
        self.fcall(
            Fcall::Tremove(fcall::Tremove { fid: fid.id() }),
            |response| match response {
                Fcall::Rremove(_) => Ok(()),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
        // `fid` drops here regardless of result; the local pool slot is
        // returned. Server-side, Tremove destroys the fid even on Rlerror.
    }

    /// Remove (unlink) a file or directory
    pub(super) fn unlinkat(
        &self,
        dfid: &Fid<Platform>,
        name: &str,
        flags: u32,
    ) -> Result<(), Error> {
        self.fcall(
            Fcall::Tunlinkat(fcall::Tunlinkat {
                dfid: dfid.id(),
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
    #[expect(dead_code)]
    pub(super) fn rename(
        &self,
        fid: &Fid<Platform>,
        dfid: &Fid<Platform>,
        name: &str,
    ) -> Result<(), Error> {
        self.fcall(
            Fcall::Trename(fcall::Trename {
                fid: fid.id(),
                dfid: dfid.id(),
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
    pub(super) fn fsync(&self, fid: &Fid<Platform>, datasync: bool) -> Result<(), Error> {
        self.fcall(
            Fcall::Tfsync(fcall::Tfsync {
                fid: fid.id(),
                datasync: u32::from(datasync),
            }),
            |response| match response {
                Fcall::Rfsync(_) => Ok(()),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        )
    }

    /// Clunk (close) a fid.
    ///
    /// Consumes the [`Fid`] handle. Sends Tclunk so the server-side fid is
    /// destroyed; the local pool slot for the underlying value is reclaimed
    /// only when the LAST `Fid` clone is dropped, so concurrent in-flight
    /// operations on a clone keep the value reserved (preventing a different
    /// file from being assigned the same fid value while a stale Tread is in
    /// flight). Errors from the server are intentionally swallowed — the
    /// resource is being torn down and there's nothing useful for callers
    /// to do with the failure.
    pub(super) fn clunk(&self, fid: Fid<Platform>) {
        let _ = self.fcall(
            Fcall::Tclunk(fcall::Tclunk { fid: fid.id() }),
            |response| match response {
                Fcall::Rclunk(_) => Ok(()),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        );
        // `fid` drops here. If this was the last clone, FidInner::drop runs
        // and recycles the pool slot.
    }

    /// Clone a fid (walk with empty path)
    pub(super) fn clone_fid(&self, fid: &Fid<Platform>) -> Result<Fid<Platform>, Error> {
        let empty: [&str; 0] = [];
        let (_, new_fid) = self.walk(fid, &empty)?;
        Ok(new_fid)
    }
}
