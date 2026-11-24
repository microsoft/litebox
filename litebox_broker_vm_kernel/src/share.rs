// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host directories ([`Share`]) over 9P2000.L or FUSE ([`Server`]),
//! read-only for now, like `litebox_broker_userland`'s `--mount-ro
//! HOST:GUEST`: only [`ReadOnly`] enforces that, as the backends would write.
//! The runner's [`NinePTransport`]s carry whole messages, where the 9P client
//! expects a byte stream. Symlink targets are passed through unchanged: an
//! absolute one resolves from the guest's root, not from the share's.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use litebox_broker_core::fs::backend::{
    Backend, Caller, CreationMetadata, DirHandle, DirPathResult, FileHandle, FileTerminal,
    HandleRef, PermissionInfo, Resolution, ResolvedDir, ResolvedFile, ResolvedTarget, SeekBehavior,
};
use litebox_broker_core::fs::errors::{
    ChmodError, ChownError, FileStatusError, MapSharedError, MkdirError, OpenError, ReadDirError,
    ReadError as FsReadError, RenameError, ResolutionError, RmdirError, SetTimesError,
    SymlinkError, TruncateError, UnlinkError, WalkError, WriteError as FsWriteError,
};
use litebox_broker_core::fs::fuse::transport::Transport as FuseTransport;
use litebox_broker_core::fs::fuse::{self, Fuse};
use litebox_broker_core::fs::inode_allocator::InodeAllocator;
use litebox_broker_core::fs::nine_p::transport::{Read, ReadError, Write, WriteError};
use litebox_broker_core::fs::nine_p::{self, NineP};
use litebox_broker_core::fs::read_only::ReadOnly;
use litebox_broker_core::fs::shared_storage::SharedFile;
use litebox_broker_core::fs::{DirEntry, FileStatus, Mode, OFlags, SetFileTimes};
use litebox_broker_core::readiness::ReadinessSource;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use litebox_platform_vm_kernel::VmKernel;

/// Carries 9P messages to a server, one request at a time: whole messages,
/// unlike the byte stream of `nine_p::transport`, which the share adapts it
/// to.
pub trait NinePTransport: Send {
    /// The largest message either way, at least 8 KiB; the client's `msize`.
    fn max_message_size(&self) -> usize;

    /// Sends `request`, one whole message, and waits for its response: its
    /// length, its bytes copied into `response` (truncated; unchecked as 9P).
    ///
    /// # Errors
    ///
    /// The transport failed, e.g., the server did not answer in time; it is
    /// not used again.
    fn round_trip(
        &mut self,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, NinePTransportError>;
}

/// A [`NinePTransport`] failed; the share's operations fail with I/O errors
/// from then on.
#[derive(Clone, Copy, Debug)]
pub struct NinePTransportError;

/// A [`Share`]'s server, by the protocol it speaks.
pub enum Server {
    /// 9P2000.L, e.g., QEMU's virtio-9p.
    NineP(Box<dyn NinePTransport>),
    /// FUSE, e.g., virtiofsd behind a virtio-fs device.
    Fuse(Box<dyn FuseTransport>),
}

/// A host directory mounted, read-only, at `path`.
pub struct Share {
    /// Must be absolute and normalized, and unlike any other mount's path
    /// (e.g., `/dev`, or `/` with a root tar), or building the broker's files
    /// panics. Should also be neither `/` nor in `/dev`, which the broker
    /// does not check: such a share would be the root, or sit among the
    /// devices.
    pub path: String,
    pub server: Server,
}

/// The 9P client writes a whole request, then reads its response; a request
/// goes out once complete (its size field says so).
pub(crate) struct Stream {
    transport: Box<dyn NinePTransport>,
    request: Vec<u8>,
    response: Vec<u8>,
    response_len: usize,
    read: usize,
}

impl Stream {
    fn new(transport: Box<dyn NinePTransport>) -> Self {
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
                .map_err(|NinePTransportError| WriteError)?
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

/// A [`Share`]'s directory, as `litebox_broker_userland`'s `--mount-ro` is a
/// host directory: the protocol's backend `B` in a [`ReadOnly`] view, which
/// refuses what would change it. A 9P share's files report no times.
pub(crate) struct ShareFs<B: Backend> {
    inner: ReadOnly<B>,
    timed: bool,
}

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
        transport: Box<dyn NinePTransport>,
        allocator: InodeAllocator,
    ) -> Result<Self, nine_p::Error> {
        let stream = Stream::new(transport);
        let msize = u32::try_from(stream.max_message_size()).unwrap_or(u32::MAX);
        let fs = NineP::new(stream, msize, USER, TREE, allocator)?;
        Ok(Self {
            inner: ReadOnly::new(fs),
            timed: false,
        })
    }
}

impl ShareFs<Fuse<VmKernel, Box<dyn FuseTransport>>> {
    /// Connects to the FUSE server at the other end of `transport`
    /// (`FUSE_INIT`).
    pub(crate) fn fuse(
        transport: Box<dyn FuseTransport>,
        allocator: InodeAllocator,
    ) -> Result<Self, fuse::Error> {
        Ok(Self {
            inner: ReadOnly::new(Fuse::new(transport, allocator)?),
            timed: true,
        })
    }
}

impl<B: Backend> ShareFs<B> {
    /// `status`, without times unless the share reports them.
    fn timed(&self, mut status: FileStatus) -> FileStatus {
        if !self.timed {
            status.times = None;
        }
        status
    }
}

impl<B: Backend> Backend for ShareFs<B> {
    fn root(&self, caller: Caller<'_>) -> Result<ResolvedDir<'_>, WalkError> {
        self.inner.root(caller)
    }

    fn resolve<'a>(
        &'a self,
        caller: Caller<'_>,
        from: ResolvedDir<'a>,
        components: &[&str],
        authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        self.inner
            .resolve(caller, from, components, authorize_dir_lookup)
    }

    fn read_link_at(
        &self,
        caller: Caller<'_>,
        dir: &ResolvedDir<'_>,
        name: &str,
    ) -> Result<String, WalkError> {
        self.inner.read_link_at(caller, dir, name)
    }

    fn open_dir(&self, dir: ResolvedDir<'_>, flags: OFlags) -> Result<DirHandle, OpenError> {
        self.inner.open_dir(dir, flags)
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Result<ResolvedDir<'a>, WalkError> {
        self.inner.walking_dir_at(dir)
    }

    fn walking_dir_with_path<'a>(
        &'a self,
        dir: &DirHandle,
    ) -> Result<(ResolvedDir<'a>, DirPathResult), WalkError> {
        self.inner.walking_dir_with_path(dir)
    }

    fn dir_path(
        &self,
        caller: Caller<'_>,
        dir: &DirHandle,
    ) -> Result<Option<Vec<String>>, WalkError> {
        self.inner.dir_path(caller, dir)
    }

    fn parent_dir(
        &self,
        caller: Caller<'_>,
        dir: &DirHandle,
    ) -> Result<Option<DirHandle>, WalkError> {
        self.inner.parent_dir(caller, dir)
    }

    fn check_search_permission(&self, dir: &ResolvedDir<'_>) -> Result<(), WalkError> {
        self.inner.check_search_permission(dir)
    }

    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
        self.inner.open_file(file, flags)
    }

    fn list_dir_at(
        &self,
        caller: Caller<'_>,
        handle: DirHandle,
    ) -> Result<Vec<DirEntry>, ReadDirError> {
        self.inner.list_dir_at(caller, handle)
    }

    fn lookup_at(&self, dir: &DirHandle, name: &str) -> Result<Option<DirEntry>, ReadDirError> {
        self.inner.lookup_at(dir, name)
    }

    fn read(
        &self,
        h: &FileHandle,
        buf: &mut dyn ReadBuffer,
        offset: usize,
    ) -> Result<usize, FsReadError> {
        self.inner.read(h, buf, offset)
    }

    fn get_static_backing_data(&self, h: &FileHandle) -> Option<&'static [u8]> {
        self.inner.get_static_backing_data(h)
    }

    fn map_shared(&self, h: &FileHandle) -> Result<Arc<SharedFile>, MapSharedError> {
        self.inner.map_shared(h)
    }

    fn write(
        &self,
        h: &FileHandle,
        buf: &dyn WriteBuffer,
        offset: usize,
    ) -> Result<usize, FsWriteError> {
        self.inner.write(h, buf, offset)
    }

    fn truncate(&self, h: &FileHandle, length: usize) -> Result<(), TruncateError> {
        self.inner.truncate(h, length)
    }

    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior {
        self.inner.seek_behavior(h)
    }

    fn status(&self, caller: Caller<'_>, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        self.inner
            .status(caller, h)
            .map(|status| self.timed(status))
    }

    fn resolved_status(
        &self,
        caller: Caller<'_>,
        target: &ResolvedTarget<'_>,
    ) -> Result<FileStatus, FileStatusError> {
        self.inner
            .resolved_status(caller, target)
            .map(|status| self.timed(status))
    }

    fn terminal(&self, h: &FileHandle) -> Option<FileTerminal> {
        self.inner.terminal(h)
    }

    fn readiness_source(&self, h: &FileHandle) -> Option<Arc<dyn ReadinessSource>> {
        self.inner.readiness_source(h)
    }

    fn create_file_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        self.inner.create_file_at(dir, name, metadata)
    }

    fn symlink_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        target: &str,
        metadata: CreationMetadata,
    ) -> Result<(), SymlinkError> {
        self.inner.symlink_at(dir, name, target, metadata)
    }

    fn mkdir_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        self.inner.mkdir_at(dir, name, metadata)
    }

    fn unlink_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), UnlinkError> {
        self.inner.unlink_at(dir, name)
    }

    fn rmdir_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), RmdirError> {
        self.inner.rmdir_at(dir, name)
    }

    fn rename_at(
        &self,
        old_dir: DirHandle,
        old_name: &str,
        new_dir: DirHandle,
        new_name: &str,
    ) -> Result<(), RenameError> {
        self.inner.rename_at(old_dir, old_name, new_dir, new_name)
    }

    fn set_times(
        &self,
        target: ResolvedTarget<'_>,
        times: &SetFileTimes,
    ) -> Result<(), SetTimesError> {
        self.inner.set_times(target, times)
    }

    fn chmod(&self, target: ResolvedTarget<'_>, mode: Mode) -> Result<(), ChmodError> {
        self.inner.chmod(target, mode)
    }

    fn chown(
        &self,
        target: ResolvedTarget<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        self.inner.chown(target, user, group)
    }
}
