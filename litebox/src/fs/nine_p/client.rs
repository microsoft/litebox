// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! 9P client implementation
//!
//! This module provides a high-level client for the 9P2000.L protocol.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, Ordering};

use crate::sync::{Mutex, RawSyncPrimitivesProvider};

use super::Error;
use super::fcall::{self, Fcall, FcallStr, GetattrMask, TaggedFcall};
use super::transport::{self, Read, Write};

/// ID generator for fids
struct IdGenerator {
    next: u32,
    free_ids: Vec<u32>,
}

impl IdGenerator {
    const fn new() -> Self {
        IdGenerator {
            next: 0,
            free_ids: Vec::new(),
        }
    }

    fn next(&mut self) -> u32 {
        if let Some(id) = self.free_ids.pop() {
            id
        } else {
            let id = self.next;
            self.next = self.next.checked_add(1).expect("out of fids");
            id
        }
    }

    fn free(&mut self, id: u32) {
        self.free_ids.push(id);
    }
}

/// Fid generator with thread-safe access
struct FidGenerator<Platform: RawSyncPrimitivesProvider> {
    inner: Mutex<Platform, IdGenerator>,
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
            inner: Mutex::new(IdGenerator::new()),
        }
    }

    /// Allocate a new fid
    fn next(&self) -> u32 {
        self.inner.lock().next()
    }

    /// Release a fid for reuse
    fn free(&self, id: u32) {
        self.inner.lock().free(id);
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
    /// Fid generator
    fids: FidGenerator<Platform>,
    /// Next tag for synchronous operations
    next_tag: AtomicU16,
}

impl<Platform: RawSyncPrimitivesProvider, T: Read + Write> Client<Platform, T> {
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

        let response = transport::read_message(&mut transport, &mut rbuf)?;

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

        wbuf.truncate(msize as usize);
        rbuf.truncate(msize as usize);

        Ok(Client {
            msize,
            write_state: Mutex::new(ClientWriteState { transport, wbuf }),
            rbuf: Mutex::new(rbuf),
            fids: FidGenerator::new(),
            next_tag: AtomicU16::new(1),
        })
    }

    /// Send a request and wait for the response
    fn fcall<F, R>(&self, fcall: Fcall<'_>, f: F) -> Result<R, Error>
    where
        F: FnOnce(Fcall<'_>) -> Result<R, Error>,
    {
        let tag = self.next_tag.fetch_add(1, Ordering::Relaxed);
        if tag == fcall::NOTAG {
            todo!("tag wraparound");
        }

        let mut write_state = self.write_state.lock();
        let ClientWriteState { transport, wbuf } = &mut *write_state;
        transport::write_message(transport, wbuf, TaggedFcall { tag, fcall })
            .map_err(|_| Error::Io)?;

        let mut rbuf = self.rbuf.lock();

        // Loop until we get a response with matching tag (in case of stale responses)
        // TODO: support concurrent requests by allowing out-of-order responses and matching tags accordingly
        loop {
            let response = transport::read_message(transport, &mut rbuf)?;
            if response.tag == tag {
                return f(response.fcall);
            }
        }
    }

    /// Attach to a remote filesystem
    pub(super) fn attach(
        &self,
        uname: &str,
        aname: &str,
    ) -> Result<(fcall::Qid, fcall::Fid), Error> {
        let fid = self.fids.next();
        let res = self.fcall(
            Fcall::Tattach(fcall::Tattach {
                afid: fcall::NOFID,
                fid,
                n_uname: fcall::NONUNAME,
                uname: fcall::FcallStr::Borrowed(uname.as_bytes()),
                aname: fcall::FcallStr::Borrowed(aname.as_bytes()),
            }),
            |response| match response {
                Fcall::Rattach(fcall::Rattach { qid }) => Ok((qid, fid)),
                Fcall::Rlerror(e) => Err(Error::from(e)),
                _ => Err(Error::InvalidResponse),
            },
        );
        if res.is_err() {
            self.fids.free(fid);
        }
        res
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
        let new_fid = self.fids.next();
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
                let _ = self.clunk(f);
            }
            f = new_f;
            // It means that the walk failed at the nwqid-th element
            if new_len < wnames.len() {
                if wqids
                    .last()
                    .is_some_and(|e| e.typ == fcall::QidType::SYMLINK)
                {
                    todo!("symlink");
                }
                let _ = self.clunk(f);
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
                count: u32::try_from(count).expect("count exceeds u32"),
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

    /// Read directory entries
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
    #[expect(dead_code)]
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
}
