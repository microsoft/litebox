// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host directories over 9P2000.L or FUSE ([`Share`]), like
//! `litebox_broker_userland`'s `--mount HOST:GUEST`, but read-only for now.
//! The runner's [`Transport`]s carry whole messages (e.g., a virtio-9p or
//! virtio-fs device), where the 9P client expects a byte stream.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use litebox_broker_core::fs::backend::{
    Backend, CreationMetadata, DirHandle, FileHandle, HandleRef, Permissioned, SeekBehavior,
    WalkOutcome, WalkingDirHandle,
};
use litebox_broker_core::fs::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, ReadDirError,
    ReadError as FsReadError, RmdirError, TruncateError, UnlinkError, WalkError,
    WriteError as FsWriteError,
};
use litebox_broker_core::fs::fuse::{self, Fuse};
use litebox_broker_core::fs::inode_allocator::InodeAllocator;
use litebox_broker_core::fs::nine_p::transport::{Read, ReadError, Write, WriteError};
use litebox_broker_core::fs::nine_p::{self, NineP};
use litebox_broker_core::fs::{DirEntry, FileStatus, Mode, OFlags};
use litebox_broker_core::readiness::ReadinessSource;
use litebox_platform_vm_kernel::VmKernel;

/// Carries a share's messages to its server, one request at a time: whole
/// messages, unlike the byte stream of `nine_p::transport`, which the share
/// adapts it to.
pub trait Transport: Send {
    /// The largest message either way, at least 8 KiB; the client's `msize`.
    fn max_message_size(&self) -> usize;

    /// Sends `request`, one whole message, and waits for its response: its
    /// length, its bytes copied into `response` (truncated; unchecked).
    ///
    /// Offer the server no more room for its response than `response`, as
    /// FUSE servers may fill it all. The FUSE client trims `response` to the
    /// largest valid reply only for replies that carry data (`FUSE_READ`,
    /// `FUSE_READDIR`); for the others, and for 9P, it is the whole message
    /// buffer, so its length is room, not a bound on the response.
    ///
    /// # Errors
    ///
    /// The transport failed, e.g., the server did not answer in time; it is
    /// not used again.
    fn round_trip(&mut self, request: &[u8], response: &mut [u8]) -> Result<usize, TransportError>;

    /// Sends `request`, one whole message that has no response (FUSE's
    /// `FUSE_FORGET`; 9P has none), at most 4 KiB.
    ///
    /// # Errors
    ///
    /// The transport failed, as for [`Self::round_trip`], or cannot send
    /// such messages, as 9P transports need not.
    fn send(&mut self, request: &[u8]) -> Result<(), TransportError> {
        let _ = request;
        Err(TransportError)
    }
}

/// A [`Transport`] failed; the share's operations fail with I/O errors from
/// then on.
#[derive(Clone, Copy, Debug)]
pub struct TransportError;

/// The protocol a [`Share`]'s server speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// 9P2000.L, e.g., over virtio-9p.
    NineP,
    /// FUSE, e.g., over virtio-fs.
    Fuse,
}

/// A host directory mounted, read-only, at `path`.
pub struct Share {
    /// Must be absolute and normalized, and unlike any other mount's path
    /// (e.g., `/dev`, or `/` with a root tar), or building the broker's files
    /// panics. Should also be neither `/` nor in `/dev`, which the broker
    /// does not check: such a share would be the root, or sit among the
    /// devices.
    pub path: String,
    pub protocol: Protocol,
    pub transport: Box<dyn Transport>,
}

/// The 9P client writes a whole request, then reads its response; a request
/// goes out once complete (its size field says so).
pub(crate) struct Stream {
    transport: Box<dyn Transport>,
    request: Vec<u8>,
    response: Vec<u8>,
    response_len: usize,
    read: usize,
}

impl Stream {
    fn new(transport: Box<dyn Transport>) -> Self {
        let response = alloc::vec![0; transport.max_message_size()];
        Self {
            transport,
            request: Vec::new(),
            response,
            response_len: 0,
            read: 0,
        }
    }

    fn max_message_size(&self) -> usize {
        self.transport.max_message_size()
    }

    /// From the request's size field, once written.
    fn request_len(&self) -> Option<usize> {
        let size = self.request.first_chunk::<4>()?;
        usize::try_from(u32::from_le_bytes(*size)).ok()
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError> {
        if self.request.is_empty() {
            // A new request: whatever is left of the last response is stale.
            self.response_len = 0;
            self.read = 0;
        }
        self.request.extend_from_slice(buf);
        let Some(len) = self.request_len() else {
            return Ok(buf.len());
        };
        if len < 4 || len > self.transport.max_message_size() || self.request.len() > len {
            self.request.clear();
            return Err(WriteError);
        }
        if self.request.len() == len {
            let result = self.transport.round_trip(&self.request, &mut self.response);
            self.request.clear();
            self.response_len = result
                .map_err(|TransportError| WriteError)?
                .min(self.response.len());
        }
        Ok(buf.len())
    }
}

/// Zero at the end of the response, which [`Read::read_exact`] fails.
impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        let rest = &self.response[self.read..self.response_len];
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.read += n;
        Ok(n)
    }
}

/// A [`Transport`] as the FUSE client's, which carries whole messages too.
pub(crate) struct FuseTransport(Box<dyn Transport>);

impl fuse::transport::Transport for FuseTransport {
    fn max_message_size(&self) -> usize {
        self.0.max_message_size()
    }

    fn round_trip(
        &mut self,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, fuse::transport::TransportError> {
        self.0
            .round_trip(request, response)
            .map_err(|TransportError| fuse::transport::TransportError)
    }

    fn send(&mut self, request: &[u8]) -> Result<(), fuse::transport::TransportError> {
        self.0
            .send(request)
            .map_err(|TransportError| fuse::transport::TransportError)
    }
}

/// A [`Share`]'s directory, as `litebox_broker_userland`'s `LocalFs` is a
/// host directory, but read-only, as `TarRo` is: what would change it fails
/// before it reaches the protocol's backend `B`, which, e.g., does not
/// support opening a directory for writing. The rest goes to `B`, with its
/// own handles.
pub(crate) struct ShareFs<B>(B);

/// Linux's defaults for the user and tree a 9P mount attaches as; servers
/// such as QEMU's ignore them.
const USER: &str = "nobody";
const TREE: &str = "";

impl ShareFs<NineP<VmKernel, Stream>> {
    /// Attaches to the 9P server at the other end of `transport`.
    ///
    /// # Errors
    ///
    /// Version negotiation or the attach failed.
    pub(crate) fn nine_p(
        transport: Box<dyn Transport>,
        allocator: InodeAllocator,
    ) -> Result<Self, nine_p::Error> {
        let stream = Stream::new(transport);
        let msize = u32::try_from(stream.max_message_size()).unwrap_or(u32::MAX);
        NineP::new(stream, msize, USER, TREE, allocator).map(Self)
    }
}

impl ShareFs<Fuse<VmKernel, FuseTransport>> {
    /// Connects to the FUSE server at the other end of `transport`.
    ///
    /// # Errors
    ///
    /// Protocol negotiation (`FUSE_INIT`) failed.
    pub(crate) fn fuse(
        transport: Box<dyn Transport>,
        allocator: InodeAllocator,
    ) -> Result<Self, fuse::Error> {
        Fuse::new(FuseTransport(transport), allocator).map(Self)
    }
}

const WRITE_FLAGS: OFlags = OFlags::CREAT
    .union(OFlags::TRUNC)
    .union(OFlags::WRONLY)
    .union(OFlags::RDWR);

impl<B: Backend> Backend for ShareFs<B> {
    fn root(&self) -> WalkingDirHandle<'_> {
        self.0.root()
    }

    fn walk_directories<'a>(
        &'a self,
        from: WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<WalkOutcome<WalkingDirHandle<'a>>, WalkError> {
        self.0.walk_directories(from, components)
    }

    fn owned_dir_at(
        &self,
        dir: WalkingDirHandle<'_>,
        flags: OFlags,
    ) -> Result<DirHandle, OpenError> {
        if flags.intersects(WRITE_FLAGS) {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        self.0.owned_dir_at(dir, flags)
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<WalkingDirHandle<'a>> {
        self.0.walking_dir_at(dir)
    }

    /// An exclusive creation of an existing file must succeed, read-only, for
    /// the resolver to report `EEXIST` rather than `EROFS`, as `TarRo` does.
    fn open_file_at(
        &self,
        dir: WalkingDirHandle<'_>,
        name: &str,
        flags: OFlags,
    ) -> Result<Permissioned<FileHandle>, OpenError> {
        let exclusive = flags.contains(OFlags::CREAT | OFlags::EXCL);
        if !exclusive && flags.intersects(WRITE_FLAGS) {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        self.0
            .open_file_at(dir, name, flags - WRITE_FLAGS - OFlags::EXCL)
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        self.0.list_dir_at(handle)
    }

    fn lookup_at(&self, dir: &DirHandle, name: &str) -> Result<Option<DirEntry>, ReadDirError> {
        self.0.lookup_at(dir, name)
    }

    fn read(&self, h: &FileHandle, buf: &mut [u8], offset: usize) -> Result<usize, FsReadError> {
        self.0.read(h, buf, offset)
    }

    fn get_static_backing_data(&self, h: &FileHandle) -> Option<&'static [u8]> {
        self.0.get_static_backing_data(h)
    }

    fn write(&self, _h: &FileHandle, _buf: &[u8], _offset: usize) -> Result<usize, FsWriteError> {
        Err(FsWriteError::NotForWriting)
    }

    fn truncate(&self, _h: &FileHandle, _length: usize) -> Result<(), TruncateError> {
        Err(TruncateError::NotForWriting)
    }

    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior {
        self.0.seek_behavior(h)
    }

    fn status(&self, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        self.0.status(h)
    }

    fn is_terminal(&self, h: &FileHandle) -> bool {
        self.0.is_terminal(h)
    }

    fn readiness_source(&self, h: &FileHandle) -> Option<Arc<dyn ReadinessSource>> {
        self.0.readiness_source(h)
    }

    fn create_file_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        Err(OpenError::ReadOnlyFileSystem)
    }

    fn mkdir_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn unlink_at(&self, _dir: DirHandle, _name: &str) -> Result<(), UnlinkError> {
        Err(UnlinkError::ReadOnlyFileSystem)
    }

    fn rmdir_at(&self, _dir: DirHandle, _name: &str) -> Result<(), RmdirError> {
        Err(RmdirError::ReadOnlyFileSystem)
    }

    fn chmod(&self, _h: HandleRef<'_>, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chown(
        &self,
        _h: HandleRef<'_>,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        Err(ChownError::ReadOnlyFileSystem)
    }
}
