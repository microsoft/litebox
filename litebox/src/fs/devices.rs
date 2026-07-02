// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Device provider for LiteBox including standard input/output devices,
//! /dev/null, and /dev/urandom.

// TODO(#15): convert legacy wildcard enum dispatch in this file to explicit arms.
#![allow(clippy::wildcard_enum_match_arm)]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::sync::Weak;

use crate::{
    LiteBox,
    event::{Events, IOPollable, observer::Observer},
    fd::{Descriptors, MetadataError},
    fs::{
        FileStatus, FileType, Mode, NodeInfo, OFlags, SeekWhence, UserInfo,
        errors::{
            ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
            ReadDirError, ReadError, RenameError, RmdirError, SeekError, TruncateError,
            UnlinkError, WriteError,
        },
    },
    path::Arg,
    platform::{StdioOutStream, StdioReadError, StdioWriteError, TimeProvider},
};

/// Block size for stdio devices
const STDIO_BLOCK_SIZE: usize = 1024;
/// Block size for null device
const NULL_BLOCK_SIZE: usize = 0x1000;
/// Block size for /dev/urandom
const URANDOM_BLOCK_SIZE: usize = 0x1000;

/// Constant node information for stdin.
const STDIN_NODE_INFO: NodeInfo = NodeInfo {
    dev: 64,
    ino: 9,
    rdev: core::num::NonZeroUsize::new(0x500),
};
/// Constant node information for stdout.
const STDOUT_NODE_INFO: NodeInfo = NodeInfo {
    dev: 64,
    ino: 10,
    rdev: core::num::NonZeroUsize::new(0x500),
};
/// Constant node information for stderr.
const STDERR_NODE_INFO: NodeInfo = NodeInfo {
    dev: 64,
    ino: 11,
    rdev: core::num::NonZeroUsize::new(0x500),
};
/// Node info for /dev/tty (controlling terminal)
const TTY_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 12,
    rdev: core::num::NonZeroUsize::new(0x500),
};
/// Node info for /dev/null
const NULL_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 4,
    rdev: core::num::NonZeroUsize::new(0x103),
};
/// Node info for /dev/urandom
const URANDOM_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 8,
    rdev: core::num::NonZeroUsize::new(0x109),
};
/// Node info for /dev/ptmx
const PTMX_NODE_INFO: NodeInfo = NodeInfo {
    dev: 5,
    ino: 2,
    rdev: core::num::NonZeroUsize::new(0x502),
};

/// Per-entry status flags for device-backed file descriptors.
#[derive(Clone, Copy)]
pub struct DeviceStatusFlags(pub OFlags);

impl DeviceStatusFlags {
    /// Returns the stored status flags.
    #[must_use]
    pub fn get_status(&self) -> OFlags {
        self.0 & OFlags::STATUS_FLAGS_MASK
    }

    /// Sets or clears a status flag.
    pub fn set_status(&mut self, flag: OFlags, on: bool) {
        if on {
            self.0 |= flag;
        } else {
            self.0 &= !flag;
        }
    }
}

/// Wrapper for polling host stdin.
///
/// Implements `IOPollable` by querying the host kernel to check if stdin has
/// data available. This enables epoll/poll/select on the guest's stdin fd.
pub struct StdinPollable(pub Arc<dyn Fn() -> bool + Send + Sync>);

impl IOPollable for StdinPollable {
    fn register_observer(&self, _observer: Weak<dyn Observer<Events>>, _mask: Events) {
        // Stdin observers are not cached — check_io_events polls the host each
        // time. The epoll wait loop calls scan_once repeatedly with short
        // timeouts, so this effectively acts as level-triggered polling.
    }

    fn check_io_events(&self) -> Events {
        let mut events = Events::OUT;
        if (self.0)() {
            events |= Events::IN;
        }
        events
    }

    fn needs_host_poll(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy)]
enum Device {
    Stdin,
    Stdout,
    Stderr,
    /// Controlling terminal (/dev/tty) — reads from stdin, writes to stdout.
    Tty,
    Null,
    URandom,
}

/// A backing implementation for [`FileSystem`](super::FileSystem).
///
/// This provider provides `/dev/stdin`, `/dev/stdout`, `/dev/stderr`,
/// `/dev/null`, and `/dev/urandom`.
pub struct FileSystem<
    Platform: crate::sync::RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + TimeProvider
        + 'static,
> {
    #[cfg(test)]
    test_box: LiteBox<Platform>,
    platform: &'static Platform,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
}

#[cfg(test)]
impl<
    Platform: crate::platform::StdioProvider
        + crate::sync::RawSyncPrimitivesProvider
        + TimeProvider
        + crate::platform::DebugLogProvider
        + crate::platform::CrngProvider,
> FileSystem<Platform>
{
    super::impl_test_descriptor_compat!();
}

impl<
    Platform: crate::platform::StdioProvider + crate::sync::RawSyncPrimitivesProvider + TimeProvider,
> FileSystem<Platform>
{
    /// Construct a new `FileSystem` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialiation step,
    /// and the created `FileSystem` handle is expected to be shared across all usage over the
    /// system.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            #[cfg(test)]
            test_box: litebox.clone(),
            platform: litebox.x.platform,
            current_working_dir: "/".into(),
        }
    }
}

impl<
    Platform: crate::sync::RawSyncPrimitivesProvider + crate::platform::StdioProvider + TimeProvider,
> super::private::Sealed for FileSystem<Platform>
{
}

impl<
    Platform: crate::sync::RawSyncPrimitivesProvider + crate::platform::StdioProvider + TimeProvider,
> FileSystem<Platform>
{
    // Gives the absolute path for `path`, resolving any `.` or `..`s, and making sure to account
    // for any relative paths from current working directory.
    //
    // Note: does NOT account for symlinks.
    fn absolute_path(&self, path: impl Arg) -> Result<String, PathError> {
        assert!(self.current_working_dir.ends_with('/'));
        let path = path.as_rust_str()?;
        if path.starts_with('/') {
            // Absolute path
            Ok(path.normalized()?)
        } else {
            // Relative path
            Ok((self.current_working_dir.clone() + path.as_rust_str()?).normalized()?)
        }
    }

    fn device_file_status(device: Device) -> FileStatus {
        match device {
            Device::Stdin => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::WGRP,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: STDIN_NODE_INFO,
                blksize: STDIO_BLOCK_SIZE,
            },
            Device::Stdout => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::WGRP,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: STDOUT_NODE_INFO,
                blksize: STDIO_BLOCK_SIZE,
            },
            Device::Stderr => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::WGRP,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: STDERR_NODE_INFO,
                blksize: STDIO_BLOCK_SIZE,
            },
            Device::Tty => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: TTY_NODE_INFO,
                blksize: STDIO_BLOCK_SIZE,
            },
            Device::Null => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: NULL_NODE_INFO,
                blksize: NULL_BLOCK_SIZE,
            },
            Device::URandom => FileStatus {
                file_type: FileType::CharacterDevice,
                mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
                size: 0,
                owner: UserInfo::ROOT,
                node_info: URANDOM_NODE_INFO,
                blksize: URANDOM_BLOCK_SIZE,
            },
        }
    }
}

impl<
    Platform: crate::sync::RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + crate::platform::CrngProvider
        + crate::platform::DebugLogProvider
        + TimeProvider,
> super::FileSystem for FileSystem<Platform>
{
    type DescriptorPlatform = Platform;

    fn open(
        &self,
        path: impl Arg,
        flags: OFlags,
        mode: Mode,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<FileFd<Platform>, OpenError> {
        let requested_status = flags & OFlags::STATUS_FLAGS_MASK;
        let open_directory = flags.contains(OFlags::DIRECTORY);
        let flags = flags - OFlags::DIRECTORY;
        let _nonblocking = flags.contains(OFlags::NONBLOCK);
        let flags = flags - OFlags::NONBLOCK;
        // ignore NOCTTY, NOFOLLOW, and APPEND
        let flags = flags - OFlags::NOCTTY - OFlags::NOFOLLOW - OFlags::APPEND;
        let truncate = flags.contains(OFlags::TRUNC);
        let flags = flags - OFlags::TRUNC;
        let excl = flags.contains(OFlags::EXCL);
        // Existing device nodes ignore create-only metadata and large-file mode bits.
        let flags = flags - OFlags::CREAT - OFlags::EXCL - OFlags::LARGEFILE;
        let _ = mode;
        let path = self.absolute_path(path)?;
        let device = match path.as_str() {
            "/dev/stdin" => {
                if excl {
                    return Err(OpenError::AlreadyExists);
                }
                if flags == OFlags::RDONLY || flags == OFlags::RDWR {
                    Device::Stdin
                } else {
                    return Err(OpenError::AccessNotAllowed);
                }
            }
            "/dev/stdout" => {
                if excl {
                    return Err(OpenError::AlreadyExists);
                }
                if flags == OFlags::WRONLY || flags == OFlags::RDWR {
                    Device::Stdout
                } else {
                    return Err(OpenError::AccessNotAllowed);
                }
            }
            "/dev/stderr" => {
                if excl {
                    return Err(OpenError::AlreadyExists);
                }
                if flags == OFlags::WRONLY || flags == OFlags::RDWR {
                    Device::Stderr
                } else {
                    return Err(OpenError::AccessNotAllowed);
                }
            }
            "/dev/null" => {
                if excl {
                    return Err(OpenError::AlreadyExists);
                }
                Device::Null
            }
            "/dev/urandom" => {
                if excl {
                    return Err(OpenError::AlreadyExists);
                }
                Device::URandom
            }
            "/dev/tty" => {
                if excl {
                    return Err(OpenError::AlreadyExists);
                }
                Device::Tty
            }
            "/dev/ptmx" => return Err(OpenError::PathError(PathError::NoSuchFileOrDirectory)),
            p if p.starts_with("/dev/pts/") => {
                if excl {
                    return Err(OpenError::AlreadyExists);
                }
                let num_str = &p["/dev/pts/".len()..];
                let _idx: u32 = num_str
                    .parse()
                    .map_err(|_| OpenError::PathError(PathError::NoSuchFileOrDirectory))?;
                if self
                    .platform
                    .host_stdin_tty_device_info()
                    .is_some_and(|info| p == info.path)
                {
                    Device::Tty
                } else {
                    return Err(OpenError::PathError(PathError::NoSuchFileOrDirectory));
                }
            }
            _ => return Err(OpenError::PathError(PathError::NoSuchFileOrDirectory)),
        };
        if open_directory {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }
        let fd = descriptors.insert(DescriptorEntry::<Platform> {
            entry: device,
            _marker: core::marker::PhantomData,
        });
        if truncate {
            // Note: matching Linux behavior, this does not actually perform any truncation, and
            // instead, it is silently ignored if you attempt to truncate upon opening stdio.
            assert!(matches!(
                <Self as super::FileSystem>::truncate(self, &fd, 0, true, descriptors),
                Err(TruncateError::IsTerminalDevice)
            ));
        }
        <Self as super::FileSystem>::set_open_status_flags(
            self,
            &fd,
            requested_status,
            descriptors,
        )
        .map_err(|_| OpenError::Io)?;
        Ok(fd)
    }

    fn close(
        &self,
        fd: &FileFd<Platform>,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), CloseError> {
        descriptors.remove(fd);
        Ok(())
    }

    fn read(
        &self,
        fd: &FileFd<Platform>,
        buf: &mut [u8],
        _offset: Option<usize>,
        descriptors: &Descriptors<Platform>,
    ) -> Result<usize, ReadError> {
        let nonblocking = {
            let nonblocking = descriptors
                .with_metadata(fd, |DeviceStatusFlags(flags)| {
                    flags.contains(OFlags::NONBLOCK)
                })
                .unwrap_or(false);
            match &descriptors.get_entry(fd).ok_or(ReadError::ClosedFd)?.entry {
                Device::Stdin | Device::Tty => nonblocking,
                Device::Stdout | Device::Stderr => {
                    return Err(ReadError::NotForReading);
                }
                Device::Null => {
                    // /dev/null read returns EOF
                    return Ok(0);
                }
                Device::URandom => {
                    self.platform.fill_bytes_crng(buf);
                    return Ok(buf.len());
                }
            }
        };
        // Stdin is a stream device — offsets are meaningless. Ignore any
        // explicit offset (the layered FS may supply one for concurrency safety).
        if buf.is_empty() {
            return Ok(0);
        }
        let read_result = if nonblocking {
            self.platform.read_from_stdin_nonblocking(buf)
        } else {
            self.platform.read_from_stdin(buf)
        };
        match read_result {
            Ok(n) => Ok(n),
            Err(StdioReadError::Closed) => Ok(0), // EOF — terminal disconnected
            Err(StdioReadError::WouldBlock) => Err(ReadError::WouldBlock),
        }
    }

    fn write(
        &self,
        fd: &FileFd<Platform>,
        buf: &[u8],
        _offset: Option<usize>,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<usize, WriteError> {
        let stream = match &descriptors.get_entry(fd).ok_or(WriteError::ClosedFd)?.entry {
            Device::Stdin => return Err(WriteError::NotForWriting),
            Device::Stdout | Device::Tty => StdioOutStream::Stdout,
            Device::Stderr => StdioOutStream::Stderr,
            Device::Null | Device::URandom => {
                // /dev/null discards data: report as if written fully
                //
                // Writing to /dev/random or /dev/urandom will update the entropy
                // pool with the data written, but this will not result in a higher
                // entropy count. This means that it will impact the contents read
                // from both files, but it will not make reads from /dev/random
                // faster. For simplicity, we just discard the data written to
                // /dev/urandom here.
                return Ok(buf.len());
            }
        };
        // Stdout/stderr are stream devices — offsets are meaningless.
        if buf.is_empty() {
            return Ok(0);
        }
        match self.platform.write_to(stream, buf) {
            Ok(n) => Ok(n),
            Err(StdioWriteError::Closed) => Ok(buf.len()),
        }
    }

    fn seek(
        &self,
        fd: &FileFd<Platform>,
        _offset: isize,
        _whence: SeekWhence,
        descriptors: &Descriptors<Platform>,
    ) -> Result<usize, SeekError> {
        match &descriptors.get_entry(fd).ok_or(SeekError::ClosedFd)?.entry {
            Device::Stdin | Device::Stdout | Device::Stderr | Device::Tty => {
                Err(SeekError::NonSeekable)
            }
            Device::Null | Device::URandom => {
                // Linux allows lseek on /dev/null and returns position 0 (or sets to length 0).
                Ok(0)
            }
        }
    }

    fn truncate(
        &self,
        _fd: &FileFd<Platform>,
        _length: usize,
        _reset_offset: bool,
        _descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), TruncateError> {
        Err(TruncateError::IsTerminalDevice)
    }

    fn chmod(
        &self,
        path: impl Arg,
        _mode: Mode,
        _descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), ChmodError> {
        // Only accept chmod on PTY paths (/dev/ptmx, /dev/pts/N). This
        // is what dropbear's grantpt() needs when allocating a PTY
        // slave for an incoming SSH session — without it, the sandbox
        // crashed at the unimplemented! below for every PTY-requesting
        // session. We don't honour the mode bits in the sandbox
        // (there's no real permission boundary to enforce on a
        // sandbox-internal PTY), but accepting the syscall is what the
        // native kernel does for root on these paths.
        //
        // Other device chmod targets (/dev/null, /dev/urandom, …)
        // return NotTheOwner (EPERM); on native Linux non-root chmod
        // on those devices also fails. Nothing in the workloads we
        // have so far calls chmod on them, and refusing is safer than
        // silently accepting until we know the semantics each caller
        // expects.
        let path_str = path.as_rust_str().map_err(|_| ChmodError::NotTheOwner)?;
        if path_str == "/dev/ptmx" || path_str.starts_with("/dev/pts/") {
            return Ok(());
        }
        Err(ChmodError::NotTheOwner)
    }

    fn chown(
        &self,
        path: impl Arg,
        _user: Option<u16>,
        _group: Option<u16>,
        _descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), ChownError> {
        let path_str = path.as_rust_str().map_err(|_| ChownError::NotTheOwner)?;
        if path_str == "/dev/ptmx" || path_str.starts_with("/dev/pts/") {
            return Ok(());
        }
        Err(ChownError::NotTheOwner)
    }

    #[expect(unused_variables, reason = "unimplemented")]
    fn unlink(
        &self,
        path: impl Arg,
        _descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), UnlinkError> {
        unimplemented!()
    }

    fn rename(
        &self,
        _old: impl Arg,
        _new: impl Arg,
        _descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), RenameError> {
        unimplemented!()
    }

    fn mkdir(
        &self,
        _path: impl Arg,
        _mode: Mode,
        _descriptors: &Descriptors<Platform>,
    ) -> Result<(), MkdirError> {
        Err(MkdirError::Io)
    }

    fn rmdir(
        &self,
        _path: impl Arg,
        _descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), RmdirError> {
        unimplemented!()
    }

    fn read_dir(
        &self,
        _fd: &FileFd<Platform>,
        _descriptors: &mut Descriptors<Platform>,
    ) -> Result<alloc::vec::Vec<crate::fs::DirEntry>, ReadDirError> {
        Err(ReadDirError::NotADirectory)
    }

    #[allow(clippy::cast_possible_truncation)] // 64-bit only target
    fn file_status(
        &self,
        path: impl Arg,
        _descriptors: &Descriptors<Platform>,
    ) -> Result<FileStatus, FileStatusError> {
        let path = self.absolute_path(path)?;
        let device = match path.as_str() {
            "/dev/stdin" => Device::Stdin,
            "/dev/stdout" => Device::Stdout,
            "/dev/stderr" => Device::Stderr,
            "/dev/tty" => Device::Tty,
            "/dev/null" => Device::Null,
            "/dev/urandom" => Device::URandom,
            "/dev/ptmx" => {
                return Ok(FileStatus {
                    file_type: FileType::CharacterDevice,
                    mode: Mode::RUSR
                        | Mode::WUSR
                        | Mode::RGRP
                        | Mode::WGRP
                        | Mode::ROTH
                        | Mode::WOTH,
                    size: 0,
                    owner: UserInfo::ROOT,
                    node_info: PTMX_NODE_INFO,
                    blksize: STDIO_BLOCK_SIZE,
                });
            }
            p if p.starts_with("/dev/pts/") => {
                let idx: u32 = p["/dev/pts/".len()..]
                    .parse()
                    .map_err(|_| FileStatusError::PathError(PathError::NoSuchFileOrDirectory))?;
                if let Some(info) = self.platform.host_stdin_tty_device_info()
                    && p == info.path
                {
                    return Ok(FileStatus {
                        file_type: FileType::CharacterDevice,
                        mode: Mode::RUSR | Mode::WUSR | Mode::WGRP,
                        size: 0,
                        owner: UserInfo::ROOT,
                        node_info: NodeInfo {
                            dev: info.dev as usize,
                            ino: info.ino as usize,
                            rdev: core::num::NonZeroUsize::new(info.rdev as usize),
                        },
                        blksize: STDIO_BLOCK_SIZE,
                    });
                }
                return Ok(FileStatus {
                    file_type: FileType::CharacterDevice,
                    mode: Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP,
                    size: 0,
                    owner: UserInfo::ROOT,
                    node_info: NodeInfo {
                        dev: 5,
                        ino: (idx + 3) as usize,
                        rdev: core::num::NonZeroUsize::new(0x8800 + idx as usize),
                    },
                    blksize: STDIO_BLOCK_SIZE,
                });
            }
            "/dev" | "/dev/" | "/dev/pts" | "/dev/pts/" => {
                return Ok(FileStatus {
                    file_type: FileType::Directory,
                    mode: Mode::RUSR
                        | Mode::XUSR
                        | Mode::RGRP
                        | Mode::XGRP
                        | Mode::ROTH
                        | Mode::XOTH,
                    size: 0,
                    owner: UserInfo::ROOT,
                    node_info: NodeInfo {
                        dev: 5,
                        ino: 1,
                        rdev: None,
                    },
                    blksize: 4096,
                });
            }
            _ => return Err(FileStatusError::PathError(PathError::NoSuchFileOrDirectory)),
        };
        Ok(Self::device_file_status(device))
    }

    fn fd_file_status(
        &self,
        fd: &FileFd<Platform>,
        descriptors: &Descriptors<Platform>,
    ) -> Result<FileStatus, FileStatusError> {
        let device = descriptors
            .get_entry(fd)
            .ok_or(FileStatusError::ClosedFd)?
            .entry;
        Ok(Self::device_file_status(device))
    }

    fn get_io_pollable(
        &self,
        fd: &FileFd<Platform>,
        descriptors: &Descriptors<Platform>,
    ) -> Option<alloc::boxed::Box<dyn crate::event::IOPollable>> {
        let entry = descriptors.get_entry(fd)?;
        match entry.entry {
            Device::Stdin | Device::Tty => {
                let platform = self.platform;
                Some(alloc::boxed::Box::new(StdinPollable(Arc::new(move || {
                    platform.poll_stdin_readable()
                }))))
            }
            _ => None,
        }
    }

    fn set_open_status_flags(
        &self,
        fd: &FileFd<Platform>,
        flags: OFlags,
        descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), MetadataError> {
        let status = flags & OFlags::STATUS_FLAGS_MASK;
        match descriptors.with_metadata_mut(fd, |DeviceStatusFlags(existing)| {
            *existing = status;
        }) {
            Ok(()) => Ok(()),
            Err(MetadataError::NoSuchMetadata) => {
                let old = descriptors.set_entry_metadata(fd, DeviceStatusFlags(status));
                debug_assert!(old.is_none());
                Ok(())
            }
            Err(MetadataError::ClosedFd) => Err(MetadataError::ClosedFd),
        }
    }

    fn open_at(
        &self,
        _dirfd: &FileFd<Platform>,
        _rel_path: impl crate::path::Arg,
        _flags: super::OFlags,
        _mode: super::Mode,
        _descriptors: &mut Descriptors<Platform>,
    ) -> Result<FileFd<Platform>, super::errors::OpenError> {
        // Device fds are not directories — fd-relative open is not meaningful.
        Err(super::errors::OpenError::NotADirectory)
    }

    fn stat_at(
        &self,
        _dirfd: &FileFd<Platform>,
        _rel_path: impl crate::path::Arg,
        _follow_symlinks: bool,
        _descriptors: &Descriptors<Platform>,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        Err(super::errors::FileStatusError::NotADirectory)
    }

    fn unlink_at(
        &self,
        _dirfd: &FileFd<Platform>,
        _rel_path: impl crate::path::Arg,
        _descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), super::errors::UnlinkError> {
        Err(super::errors::UnlinkError::NotADirectory)
    }

    fn readlink_at(
        &self,
        _dirfd: &FileFd<Platform>,
        _rel_path: impl crate::path::Arg,
        _descriptors: &Descriptors<Platform>,
    ) -> Result<alloc::string::String, super::errors::ReadLinkError> {
        Err(super::errors::ReadLinkError::NotADirectory)
    }

    fn rename_at(
        &self,
        _old_dirfd: &FileFd<Platform>,
        _old_rel: impl crate::path::Arg,
        _new_dirfd: &FileFd<Platform>,
        _new_rel: impl crate::path::Arg,
        _descriptors: &mut Descriptors<Platform>,
    ) -> Result<(), super::errors::RenameError> {
        Err(super::errors::RenameError::NotADirectory)
    }

    fn fd_path(
        &self,
        _fd: &FileFd<Platform>,
        _descriptors: &Descriptors<Platform>,
    ) -> Option<alloc::string::String> {
        // Devices don't track paths.
        None
    }

    fn mkdir_at(
        &self,
        _dirfd: &FileFd<Platform>,
        _rel_path: impl Arg,
        _mode: Mode,
        _descriptors: &Descriptors<Platform>,
    ) -> Result<(), MkdirError> {
        Err(MkdirError::Io)
    }
}

// Manual implementation of FD subsystem integration for devices.
#[doc(hidden)]
pub struct DescriptorEntry<
    Platform: crate::sync::RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + crate::platform::TimeProvider,
> {
    entry: Device,
    _marker: core::marker::PhantomData<fn() -> Platform>,
}
impl<
    Platform: crate::sync::RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + crate::platform::TimeProvider,
> crate::fd::FdEnabledSubsystem for FileSystem<Platform>
{
    const KIND: crate::fd::SubsystemKind = crate::fd::SubsystemKind::Fs;

    type Entry = DescriptorEntry<Platform>;
}
impl<
    Platform: crate::sync::RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + crate::platform::TimeProvider,
> crate::fd::FdEnabledSubsystemEntry for DescriptorEntry<Platform>
{
    fn on_dup(&self) {}

    fn on_close(&self) {}
}
impl<
    Platform: crate::sync::RawSyncPrimitivesProvider
        + crate::platform::StdioProvider
        + crate::platform::TimeProvider,
> From<Device> for DescriptorEntry<Platform>
{
    fn from(entry: Device) -> Self {
        Self {
            entry,
            _marker: core::marker::PhantomData,
        }
    }
}
pub type FileFd<Platform> = crate::fd::TypedFd<FileSystem<Platform>>;
