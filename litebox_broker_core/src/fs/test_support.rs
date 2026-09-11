// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared support for the broker-core filesystem tests.
//!
//! The [`Fs`] facade pairs a [`Resolver`] with the device I/O a broker session would supply, so
//! the tests can exercise resolver and backend semantics without a session, transport, or guest
//! descriptor table. Every method delegates directly to the resolver; no behavior is added here.

use alloc::vec::Vec;

use litebox_broker_protocol::fs::{
    FileAccessMode, FileDirectoryEntry, FileMode as Mode, FileOpenFlags,
    FileSeekWhence as SeekWhence, FileStatus, FileUser as UserInfo,
};
use litebox_broker_protocol::stdio::StdioOutputStream;

use super::backend::{Backend, DeviceIo, NoDeviceIo};
#[cfg(target_os = "linux")]
use super::errors::TruncateError;
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, ReadDirError, ReadError,
    RmdirError, SeekError, UnlinkError, WriteError,
};
use super::resolver::{Resolver, ResolverEntry};
use crate::test_platform::TestPlatform;

/// The unprivileged user these tests act as unless they need root.
pub(in crate::fs) const USER: UserInfo = UserInfo {
    user: 1000,
    group: 1000,
};

/// The privileged user, used for test setup that has to bypass permission checks.
pub(in crate::fs) const ROOT: UserInfo = UserInfo::ROOT;

/// A test-only facade over [`Resolver`].
///
/// It supplies the device I/O that a broker session normally provides, and it keeps the ported
/// test bodies readable by not repeating that argument at every call site. Every method delegates
/// directly to the resolver, so no behavior is added here.
pub(in crate::fs) struct Fs<BackendType: Backend + 'static> {
    resolver: Resolver<TestPlatform, BackendType>,
}

/// One open filesystem entry, the resolver's equivalent of an open file description.
pub(in crate::fs) type Entry<BackendType> = ResolverEntry<BackendType>;

impl<BackendType: Backend + 'static> Fs<BackendType> {
    pub(in crate::fs) fn new(backend: BackendType) -> Self {
        Self {
            resolver: Resolver::new(backend),
        }
    }

    pub(in crate::fs) fn open(
        &self,
        user: UserInfo,
        path: &str,
        access: FileAccessMode,
        flags: FileOpenFlags,
        mode: Mode,
    ) -> Result<Entry<BackendType>, OpenError> {
        self.resolver.open(user, path, access, flags, mode)
    }

    pub(in crate::fs) fn read(
        &self,
        entry: &mut Entry<BackendType>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        self.read_with(&NoDeviceIo, entry, buf, offset)
    }

    pub(in crate::fs) fn write(
        &self,
        entry: &mut Entry<BackendType>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        self.write_with(&NoDeviceIo, entry, buf, offset)
    }

    /// Like [`Self::read`], but against the device I/O a broker session would supply.
    pub(in crate::fs) fn read_with(
        &self,
        device_io: &dyn DeviceIo,
        entry: &mut Entry<BackendType>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        self.resolver.read(device_io, entry, buf, offset)
    }

    /// Like [`Self::write`], but against the device I/O a broker session would supply.
    pub(in crate::fs) fn write_with(
        &self,
        device_io: &dyn DeviceIo,
        entry: &mut Entry<BackendType>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        self.resolver.write(device_io, entry, buf, offset)
    }

    pub(in crate::fs) fn seek(
        &self,
        entry: &mut Entry<BackendType>,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        self.resolver.seek(entry, offset, whence)
    }

    #[cfg(target_os = "linux")]
    pub(in crate::fs) fn truncate(
        &self,
        entry: &mut Entry<BackendType>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        self.resolver.truncate(entry, length, reset_offset)
    }

    pub(in crate::fs) fn chmod(
        &self,
        user: UserInfo,
        path: &str,
        mode: Mode,
    ) -> Result<(), ChmodError> {
        self.resolver.chmod(user, path, mode)
    }

    pub(in crate::fs) fn chown(
        &self,
        user: UserInfo,
        path: &str,
        owner: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        self.resolver.chown(user, path, owner, group)
    }

    pub(in crate::fs) fn unlink(&self, user: UserInfo, path: &str) -> Result<(), UnlinkError> {
        self.resolver.unlink(user, path)
    }

    pub(in crate::fs) fn mkdir(
        &self,
        user: UserInfo,
        path: &str,
        mode: Mode,
    ) -> Result<(), MkdirError> {
        self.resolver.mkdir(user, path, mode)
    }

    pub(in crate::fs) fn rmdir(&self, user: UserInfo, path: &str) -> Result<(), RmdirError> {
        self.resolver.rmdir(user, path)
    }

    pub(in crate::fs) fn read_dir(
        &self,
        entry: &Entry<BackendType>,
    ) -> Result<Vec<FileDirectoryEntry>, ReadDirError> {
        self.resolver.read_dir(entry)
    }

    pub(in crate::fs) fn file_status(
        &self,
        user: UserInfo,
        path: &str,
    ) -> Result<FileStatus, FileStatusError> {
        self.resolver.file_status(user, path)
    }

    pub(in crate::fs) fn handle_status(
        &self,
        entry: &Entry<BackendType>,
    ) -> Result<FileStatus, FileStatusError> {
        self.resolver.handle_status(entry)
    }
}

/// Device I/O for a broker session whose standard-I/O provider cannot service transfers.
///
/// This mirrors [`crate::stdio`], which completes empty transfers without consulting the provider
/// and reports an I/O error for anything that would need it.
pub(in crate::fs) struct UnservicedStdio;

impl DeviceIo for UnservicedStdio {
    fn read_stdin(&self, output: &mut [u8]) -> Result<usize, ReadError> {
        if output.is_empty() {
            return Ok(0);
        }
        Err(ReadError::Io)
    }

    fn write_stdio(&self, _stream: StdioOutputStream, input: &[u8]) -> Result<usize, WriteError> {
        if input.is_empty() {
            return Ok(0);
        }
        Err(WriteError::Io)
    }

    fn fill_random(&self, _output: &mut [u8]) -> Result<(), ReadError> {
        Err(ReadError::Io)
    }
}
