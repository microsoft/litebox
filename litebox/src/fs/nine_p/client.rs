// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! 9P client implementation
//!
//! This module provides a high-level client for the 9P2000.L protocol.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::sync::{Mutex, RawSyncPrimitivesProvider};

use super::Error;
use super::fcall::{self, Fcall, FcallStr, GetattrMask, TaggedFcall};
use super::transport::{self, Read, Write};

/// Client identifier for lock operations
pub(crate) const CLIENT_ID: &str = "litebox-9p";

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
pub(crate) struct FidGenerator<Platform: RawSyncPrimitivesProvider> {
    inner: Mutex<Platform, IdGenerator>,
}

impl<Platform: RawSyncPrimitivesProvider> Default for FidGenerator<Platform> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Platform: RawSyncPrimitivesProvider> FidGenerator<Platform> {
    /// Create a new fid generator
    pub(crate) fn new() -> Self {
        FidGenerator {
            inner: Mutex::new(IdGenerator::new()),
        }
    }

    /// Allocate a new fid
    pub(crate) fn next(&self) -> u32 {
        self.inner.lock().next()
    }

    /// Release a fid for reuse
    pub(crate) fn free(&self, id: u32) {
        self.inner.lock().free(id);
    }
}

/// 9P client state for writing to the connection
pub(crate) struct ClientWriteState<T> {
    /// The underlying transport
    transport: T,
    /// Write buffer
    wbuf: Vec<u8>,
}

/// 9P client
///
/// This client provides synchronous 9P protocol operations. It uses a transport
/// that implements both Read and Write traits.
pub(crate) struct Client<Platform: RawSyncPrimitivesProvider, T: Read + Write> {
    /// Maximum message size negotiated with server
    msize: u32,
    /// Write state protected by a mutex
    write_state: Mutex<Platform, ClientWriteState<T>>,
    /// Read buffer for responses
    rbuf: Mutex<Platform, Vec<u8>>,
    /// Fid generator
    fids: FidGenerator<Platform>,
    /// Next tag for synchronous operations
    next_tag: AtomicU32,
}

impl<Platform: RawSyncPrimitivesProvider, T: Read + Write> Client<Platform, T> {
    /// Create a new 9P client and perform version negotiation
    ///
    /// # Arguments
    /// * `transport` - The underlying transport for read/write operations
    /// * `max_msize` - Maximum message size to request
    pub(crate) fn new(mut transport: T, max_msize: u32) -> Result<Self, Error> {
        const MIN_MSIZE: u32 = 4096 + fcall::READDIRHDRSZ;
        let bufsize = max_msize.max(MIN_MSIZE) as usize;

        let mut wbuf = Vec::with_capacity(bufsize);
        let mut rbuf = Vec::with_capacity(bufsize);

        // Perform version handshake
        transport::write_message(
            &mut transport,
            &mut wbuf,
            &TaggedFcall {
                tag: fcall::NOTAG,
                fcall: Fcall::Tversion(fcall::Tversion {
                    msize: bufsize as u32,
                    version: "9P2000.L".into(),
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
                if version.as_bytes() != b"9P2000.L" {
                    return Err(Error::InvalidResponse);
                }
                msize.min(bufsize as u32)
            }
            TaggedFcall {
                fcall: Fcall::Rlerror(e),
                ..
            } => return Err(Error::Remote(e)),
            _ => return Err(Error::InvalidResponse),
        };

        wbuf.truncate(msize as usize);
        rbuf.truncate(msize as usize);

        Ok(Client {
            msize,
            write_state: Mutex::new(ClientWriteState { transport, wbuf }),
            rbuf: Mutex::new(rbuf),
            fids: FidGenerator::new(),
            next_tag: AtomicU32::new(1),
        })
    }

    /// Get the negotiated message size
    pub(crate) fn msize(&self) -> u32 {
        self.msize
    }

    /// Send a request and wait for the response
    fn fcall(&self, fcall: Fcall<'_>) -> Result<Fcall<'static>, Error> {
        let tag = self.next_tag.fetch_add(1, Ordering::Relaxed) as u16;

        let mut write_state = self.write_state.lock();
        let ClientWriteState { transport, wbuf } = &mut *write_state;
        transport::write_message(transport, wbuf, &TaggedFcall { tag, fcall })
            .map_err(|_| Error::Io)?;

        let mut rbuf = self.rbuf.lock();

        // Loop until we get a response with matching tag (in case of stale responses)
        loop {
            let response = transport::read_message(transport, &mut rbuf)?;
            if response.tag == tag {
                return Ok(response.fcall.clone_static());
            }
        }
    }

    /// Attach to a remote filesystem
    pub(crate) fn attach(
        &self,
        uname: &str,
        aname: &str,
    ) -> Result<(fcall::Qid, fcall::Fid), Error> {
        let fid = self.fids.next();
        match self.fcall(Fcall::Tattach(fcall::Tattach {
            afid: fcall::NOFID,
            fid,
            n_uname: fcall::NONUNAME,
            uname: uname.into(),
            aname: aname.into(),
        }))? {
            Fcall::Rattach(fcall::Rattach { qid }) => Ok((qid, fid)),
            Fcall::Rlerror(e) => {
                self.fids.free(fid);
                Err(Error::Remote(e))
            }
            _ => {
                self.fids.free(fid);
                Err(Error::InvalidResponse)
            }
        }
    }

    /// Walks the path from the given fid.
    ///
    /// The given wnames should not exceed the maximum number of elements (fcall::MAXWELEM),
    /// which is checked at the beginning of the function. This is an internal function that
    /// is used by [`_walk`](Client::_walk), which handles the case where the number of elements exceeds the limit.
    fn _walk1(
        &self,
        fid: fcall::Fid,
        wnames: &[FcallStr],
    ) -> Result<(Vec<fcall::Qid>, fcall::Fid), Error> {
        if wnames.len() > fcall::MAXWELEM {
            return Err(Error::NameTooLong);
        }
        let new_fid = self.fids.next();
        let ret = match self.fcall(Fcall::Twalk(fcall::Twalk {
            fid,
            new_fid,
            wnames: wnames.to_vec(),
        }))? {
            Fcall::Rwalk(fcall::Rwalk { wqids }) => Ok((wqids, new_fid)),
            Fcall::Rlerror(err) => Err(Error::Remote(err)),
            _ => Err(Error::InvalidResponse),
        };
        if ret.is_err() {
            self.fids.free(new_fid);
        }
        ret
    }

    /// Walks the path from the given fid, handling paths longer than fcall::MAXWELEM by walking in chunks.
    ///
    /// Returns the qids for each path component and a new fid for the final location on success.
    fn _walk(
        &self,
        fid: fcall::Fid,
        wnames: &[FcallStr],
    ) -> Result<(Vec<fcall::Qid>, fcall::Fid), Error> {
        if wnames.is_empty() {
            return self._walk1(fid, wnames);
        }
        let mut wqids = Vec::with_capacity(fcall::MAXWELEM);
        let mut f = fid;
        for wnames in wnames.chunks(fcall::MAXWELEM) {
            let (mut new_wqids, new_f) = self._walk1(f, wnames)?;
            let new_len = new_wqids.len();
            wqids.append(&mut new_wqids);
            // Clunk the old fid if it's not the original fid
            if f != fid {
                let _ = self.clunk(f);
            }
            f = new_f;
            // It means that the walk failed at the nwqid-th element
            if new_len < wnames.len() {
                if let Some(e) = wqids.last() {
                    if e.typ == fcall::QidType::SYMLINK {
                        todo!("symlink");
                    }
                }
                let _ = self.clunk(f);
                return Err(Error::NotFound);
            }
        }
        Ok((wqids, f))
    }

    /// Walk to a path from a given fid
    ///
    /// Returns the qids for each path component and a new fid for the final location
    pub(super) fn walk<'a, S: Into<FcallStr<'a>> + AsRef<[u8]>>(
        &self,
        fid: fcall::Fid,
        wnames: &[S],
    ) -> Result<(Vec<fcall::Qid>, fcall::Fid), Error> {
        let wnames: Vec<FcallStr> = wnames.iter().map(|s| s.into()).collect();
        self._walk(fid, &wnames)
    }

    /// Open a file
    pub(super) fn open(
        &self,
        fid: fcall::Fid,
        flags: fcall::LOpenFlags,
    ) -> Result<fcall::Qid, Error> {
        match self.fcall(Fcall::Tlopen(fcall::Tlopen { fid, flags }))? {
            Fcall::Rlopen(fcall::Rlopen { qid, .. }) => Ok(qid),
            Fcall::Rlerror(e) => Err(Error::Remote(e)),
            _ => Err(Error::InvalidResponse),
        }
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
        match self.fcall(Fcall::Tlcreate(fcall::Tlcreate {
            fid: dfid,
            name: name.into(),
            flags,
            mode,
            gid,
        }))? {
            Fcall::Rlcreate(fcall::Rlcreate { qid, iounit: _ }) => Ok((qid, dfid)),
            Fcall::Rlerror(e) => Err(Error::Remote(e)),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Read from a file
    pub(crate) fn read(
        &self,
        fid: fcall::Fid,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        let count = buf.len().min((self.msize - fcall::IOHDRSZ) as usize);
        match self.fcall(Fcall::Tread(fcall::Tread {
            fid,
            offset,
            count: count as u32,
        }))? {
            Fcall::Rread(fcall::Rread { data }) => {
                buf[..data.len()].copy_from_slice(&data);
                Ok(data.len())
            }
            Fcall::Rlerror(e) => Err(Error::Remote(e)),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Write to a file
    pub(crate) fn write(&self, fid: fcall::Fid, offset: u64, data: &[u8]) -> Result<usize, Error> {
        let count = data.len().min((self.msize - fcall::IOHDRSZ) as usize);
        match self.fcall(Fcall::Twrite(fcall::Twrite {
            fid,
            offset,
            data: alloc::borrow::Cow::Borrowed(&data[..count]),
        }))? {
            Fcall::Rwrite(fcall::Rwrite { count }) => Ok(count as usize),
            Fcall::Rlerror(e) => Err(Error::Remote(e)),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Get file attributes
    pub(crate) fn getattr(
        &self,
        fid: fcall::Fid,
        req_mask: GetattrMask,
    ) -> Result<fcall::Rgetattr, Error> {
        match self.fcall(Fcall::Tgetattr(fcall::Tgetattr { fid, req_mask }))? {
            Fcall::Rgetattr(r) => Ok(r),
            Fcall::Rlerror(e) => Err(Error::Remote(e)),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Set file attributes
    pub(crate) fn setattr(
        &self,
        fid: fcall::Fid,
        valid: fcall::SetattrMask,
        stat: fcall::SetAttr,
    ) -> Result<(), Error> {
        match self.fcall(Fcall::Tsetattr(fcall::Tsetattr { fid, valid, stat }))? {
            Fcall::Rsetattr(_) => Ok(()),
            Fcall::Rlerror(e) => Err(Error::Remote(e)),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Read directory entries
    pub(crate) fn readdir(
        &self,
        fid: fcall::Fid,
        offset: u64,
    ) -> Result<Vec<fcall::DirEntry<'static>>, Error> {
        let count = self.msize - fcall::READDIRHDRSZ;
        match self.fcall(Fcall::Treaddir(fcall::Treaddir { fid, offset, count }))? {
            Fcall::Rreaddir(fcall::Rreaddir { data }) => {
                // Clone the directory entries to owned versions
                Ok(data.data)
            }
            Fcall::Rlerror(e) => Err(Error::Remote(e)),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Read all directory entries
    pub(crate) fn readdir_all(
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
    pub(crate) fn mkdir(
        &self,
        dfid: fcall::Fid,
        name: &str,
        mode: u32,
        gid: u32,
    ) -> Result<fcall::Qid, Error> {
        match self.fcall(Fcall::Tmkdir(fcall::Tmkdir {
            dfid,
            name: name.into(),
            mode,
            gid,
        }))? {
            Fcall::Rmkdir(fcall::Rmkdir { qid }) => Ok(qid),
            Fcall::Rlerror(e) => Err(Error::Remote(e)),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Remove the file represented by fid and clunk the fid, even if the remove fails
    pub(crate) fn remove(&self, fid: fcall::Fid) -> Result<(), Error> {
        match self.fcall(Fcall::Tremove(fcall::Tremove { fid }))? {
            Fcall::Rremove(_) => Ok(()),
            Fcall::Rlerror(e) => Err(Error::from(e)),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Remove (unlink) a file or directory
    pub(crate) fn unlinkat(&self, dfid: fcall::Fid, name: &str, flags: u32) -> Result<(), Error> {
        match self.fcall(Fcall::Tunlinkat(fcall::Tunlinkat {
            dfid,
            name: name.into(),
            flags,
        }))? {
            Fcall::Runlinkat(_) => Ok(()),
            Fcall::Rlerror(e) => Err(Error::from(e)),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Rename a file
    pub(crate) fn rename(
        &self,
        fid: fcall::Fid,
        dfid: fcall::Fid,
        name: &str,
    ) -> Result<(), Error> {
        match self.fcall(Fcall::Trename(fcall::Trename {
            fid,
            dfid,
            name: name.into(),
        }))? {
            Fcall::Rrename(_) => Ok(()),
            Fcall::Rlerror(e) => Err(Error::Remote(e)),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Fsync a file
    pub(crate) fn fsync(&self, fid: fcall::Fid, datasync: bool) -> Result<(), Error> {
        match self.fcall(Fcall::Tfsync(fcall::Tfsync {
            fid,
            datasync: u32::from(datasync),
        }))? {
            Fcall::Rfsync(_) => Ok(()),
            Fcall::Rlerror(e) => Err(Error::Remote(e)),
            _ => Err(Error::InvalidResponse),
        }
    }

    /// Clunk (close) a fid
    pub(crate) fn clunk(&self, fid: fcall::Fid) -> Result<(), Error> {
        let result = match self.fcall(Fcall::Tclunk(fcall::Tclunk { fid }))? {
            Fcall::Rclunk(_) => Ok(()),
            Fcall::Rlerror(e) => Err(Error::Remote(e)),
            _ => Err(Error::InvalidResponse),
        };
        self.fids.free(fid);
        result
    }

    /// Clone a fid (walk with empty path)
    pub(crate) fn clone_fid(&self, fid: fcall::Fid) -> Result<fcall::Fid, Error> {
        let empty: [&str; 0] = [];
        let (_, new_fid) = self.walk(fid, &empty)?;
        Ok(new_fid)
    }

    /// Release a fid back to the pool without clunking
    ///
    /// Use this when the fid has already been invalidated (e.g., after remove)
    pub(crate) fn free_fid(&self, fid: fcall::Fid) {
        self.fids.free(fid);
    }
}
