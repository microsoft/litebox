// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Error handling. See [`Errno`].

#![expect(
    clippy::match_same_arms,
    reason = "in this one module, we want to make sure we do the necessary repeat, just to keep consistency; \
              thus we don't want clippy to complain about this here"
)]
// Funnily, we can't use `expect` here, and must use `allow`: this may be a Rust bug with how it
// handles the `expect` lint for these imports. Anyways, we don't expect this one to go away, so
// perfectly fine to `allow` in this module.
#![allow(
    clippy::wildcard_imports,
    reason = "in this one module, we want to pull in all the constants, rather than manually list them"
)]

use thiserror::Error;

mod generated;

/// Linux error numbers
///
/// This is a transparent wrapper around Linux error numbers (i.e., `i32`s) intended
/// to provide some type safety by expecting explicit conversions to/from `i32`s.
#[derive(PartialEq, Eq, Clone, Copy, Error)]
pub struct Errno {
    // `u16`, not `u8`, to hold the kernel-internal restart codes, whose Linux values (512 and 514)
    // exceed 255.
    value: core::num::NonZeroU16,
}

impl From<Errno> for i32 {
    fn from(e: Errno) -> Self {
        e.value.get().into()
    }
}

impl core::fmt::Display for Errno {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl core::fmt::Debug for Errno {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Errno({} = {})", self.value.get(), self.as_str())
    }
}

impl Errno {
    // Kernel-internal codes for a syscall interrupted by a signal, with Linux's values. They exceed
    // the largest real errno, `Errno::MAX`, so conversions from integers never produce them. They
    // never reach the guest: signal delivery either restarts the syscall or replaces them with
    // `EINTR`.

    /// Restart the syscall unless a handler without `SA_RESTART` runs. Interrupted waits convert
    /// to this, as in Linux.
    pub const ERESTARTSYS: Self = Self::from_const(512);
    /// Restart the syscall, even after a handler runs.
    pub const ERESTARTNOINTR: Self = Self::from_const(513);
    /// Restart the syscall only if no handler runs.
    pub const ERESTARTNOHAND: Self = Self::from_const(514);

    /// Provide the negative integer representation of the error
    ///
    /// ```
    /// # use litebox_common_linux::errno::Errno;
    /// assert_eq!(-1, Errno::EPERM.as_neg());
    /// // Direct conversion to i32 will give the positive variant
    /// assert_eq!(1, Errno::EPERM.into());
    /// ```
    pub fn as_neg(self) -> i32 {
        -i32::from(self)
    }

    /// Returns `EINTR` in place of a restart code, for an interrupted syscall that must not
    /// restart.
    #[must_use]
    pub fn without_restart(self) -> Self {
        if self == Self::ERESTARTSYS || self == Self::ERESTARTNOINTR || self == Self::ERESTARTNOHAND
        {
            Self::EINTR
        } else {
            self
        }
    }

    /// (Private-only) Helper function that makes the associated constants on [`Errno`] significantly more
    /// readable. Not intended to be used outside this crate, or even this module.
    const fn from_const(v: u16) -> Self {
        Self {
            value: core::num::NonZeroU16::new(v).unwrap(),
        }
    }
}

/// Errors when converting to an [`Errno`]
#[derive(Error, Debug)]
pub enum ErrnoConversionError {
    #[error("Expected positive error number")]
    ExpectedPositive,
    #[error("Error number cannot be zero")]
    ExpectedNonZero,
    #[error("Error number is unexpectedly large")]
    ExpectedSmallEnough,
}

impl TryFrom<i32> for Errno {
    type Error = ErrnoConversionError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        let value: u32 = value
            .try_into()
            .or(Err(ErrnoConversionError::ExpectedPositive))?;
        Self::try_from(value)
    }
}
impl TryFrom<u32> for Errno {
    type Error = ErrnoConversionError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let value: u8 = value
            .try_into()
            .or(Err(ErrnoConversionError::ExpectedSmallEnough))?;
        Self::try_from(value)
    }
}
impl TryFrom<u8> for Errno {
    type Error = ErrnoConversionError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = core::num::NonZeroU16::new(value.into())
            .ok_or(ErrnoConversionError::ExpectedNonZero)?;
        if value.get() <= Self::MAX.value.get() {
            Ok(Self { value })
        } else {
            Err(ErrnoConversionError::ExpectedSmallEnough)
        }
    }
}

impl From<litebox::process::ProcessError> for Errno {
    fn from(value: litebox::process::ProcessError) -> Self {
        match value {
            litebox::process::ProcessError::PolicyDenied => Errno::EPERM,
            litebox::process::ProcessError::Unavailable => Errno::ENOSYS,
            litebox::process::ProcessError::Busy
            | litebox::process::ProcessError::ResourceExhausted => Errno::EAGAIN,
            litebox::process::ProcessError::OutOfMemory => Errno::ENOMEM,
            litebox::process::ProcessError::ServiceFailed
            | litebox::process::ProcessError::InvalidChild => Errno::EIO,
            litebox::process::ProcessError::NoSuchProcess => Errno::ESRCH,
        }
    }
}

impl From<litebox::fs::errors::PathError> for Errno {
    fn from(value: litebox::fs::errors::PathError) -> Self {
        match value {
            litebox::fs::errors::PathError::NoSuchFileOrDirectory => Errno::ENOENT,
            litebox::fs::errors::PathError::NoSearchPerms => Errno::EACCES,
            litebox::fs::errors::PathError::InvalidPathname => Errno::EINVAL,
            litebox::fs::errors::PathError::MissingComponent => Errno::ENOENT,
            litebox::fs::errors::PathError::ComponentNotADirectory => Errno::ENOTDIR,
        }
    }
}

impl From<litebox::fs::errors::OpenError> for Errno {
    fn from(value: litebox::fs::errors::OpenError) -> Self {
        match value {
            litebox::fs::errors::OpenError::AccessNotAllowed => Errno::EACCES,
            litebox::fs::errors::OpenError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::OpenError::PathError(path_error) => path_error.into(),
            litebox::fs::errors::OpenError::ReadOnlyFileSystem => Errno::EROFS,
            litebox::fs::errors::OpenError::AlreadyExists => Errno::EEXIST,
            litebox::fs::errors::OpenError::Io => Errno::EIO,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::UnlinkError> for Errno {
    fn from(value: litebox::fs::errors::UnlinkError) -> Self {
        match value {
            litebox::fs::errors::UnlinkError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::UnlinkError::IsADirectory => Errno::EISDIR,
            litebox::fs::errors::UnlinkError::ReadOnlyFileSystem => Errno::EROFS,
            litebox::fs::errors::UnlinkError::Io => Errno::EIO,
            litebox::fs::errors::UnlinkError::PathError(path_error) => path_error.into(),
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::RmdirError> for Errno {
    fn from(value: litebox::fs::errors::RmdirError) -> Self {
        match value {
            litebox::fs::errors::RmdirError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::RmdirError::Busy => Errno::EBUSY,
            litebox::fs::errors::RmdirError::NotEmpty => Errno::ENOTEMPTY,
            litebox::fs::errors::RmdirError::NotADirectory => Errno::ENOTDIR,
            litebox::fs::errors::RmdirError::ReadOnlyFileSystem => Errno::EROFS,
            litebox::fs::errors::RmdirError::Io => Errno::EIO,
            litebox::fs::errors::RmdirError::PathError(path_error) => path_error.into(),
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::ReadError> for Errno {
    fn from(value: litebox::fs::errors::ReadError) -> Self {
        match value {
            litebox::fs::errors::ReadError::ClosedFd => Errno::EBADF,
            litebox::fs::errors::ReadError::NotAFile => Errno::EISDIR,
            litebox::fs::errors::ReadError::NotForReading => Errno::EBADF,
            litebox::fs::errors::ReadError::WouldBlock => Errno::EAGAIN,
            litebox::fs::errors::ReadError::WaitError(e) => match e {
                litebox::event::wait::WaitError::Interrupted => Errno::ERESTARTSYS,
                litebox::event::wait::WaitError::TimedOut => Errno::ETIMEDOUT,
            },
            litebox::fs::errors::ReadError::Io => Errno::EIO,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::WriteError> for Errno {
    fn from(value: litebox::fs::errors::WriteError) -> Self {
        match value {
            litebox::fs::errors::WriteError::NotAFile => Errno::EISDIR,
            litebox::fs::errors::WriteError::NotForWriting => Errno::EBADF,
            litebox::fs::errors::WriteError::WouldBlock => Errno::EAGAIN,
            litebox::fs::errors::WriteError::WaitError(e) => match e {
                litebox::event::wait::WaitError::Interrupted => Errno::ERESTARTSYS,
                litebox::event::wait::WaitError::TimedOut => Errno::ETIMEDOUT,
            },
            litebox::fs::errors::WriteError::Io => Errno::EIO,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::SeekError> for Errno {
    fn from(value: litebox::fs::errors::SeekError) -> Self {
        match value {
            litebox::fs::errors::SeekError::NotAFile | litebox::fs::errors::SeekError::ClosedFd => {
                Errno::EBADF
            }
            litebox::fs::errors::SeekError::InvalidOffset => Errno::EINVAL,
            litebox::fs::errors::SeekError::NonSeekable => Errno::ESPIPE,
            litebox::fs::errors::SeekError::NotOpenForSeeking => Errno::EBADF,
            litebox::fs::errors::SeekError::Io => Errno::EIO,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::MkdirError> for Errno {
    fn from(value: litebox::fs::errors::MkdirError) -> Self {
        match value {
            litebox::fs::errors::MkdirError::PathError(path_error) => path_error.into(),
            litebox::fs::errors::MkdirError::AlreadyExists => Errno::EEXIST,
            litebox::fs::errors::MkdirError::ReadOnlyFileSystem => Errno::EROFS,
            litebox::fs::errors::MkdirError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::MkdirError::Io => Errno::EIO,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::platform::page_mgmt::AllocationError> for Errno {
    fn from(value: litebox::platform::page_mgmt::AllocationError) -> Self {
        match value {
            litebox::platform::page_mgmt::AllocationError::Unaligned => Errno::EINVAL,
            litebox::platform::page_mgmt::AllocationError::BelowMinAddress => Errno::EPERM,
            litebox::platform::page_mgmt::AllocationError::PermissionDenied => Errno::EACCES,
            litebox::platform::page_mgmt::AllocationError::OutOfMemory
            | litebox::platform::page_mgmt::AllocationError::AboveMaxAddress
            | litebox::platform::page_mgmt::AllocationError::AddressPartiallyInUse
            | litebox::platform::page_mgmt::AllocationError::AddressInUseByPlatform => {
                Errno::ENOMEM
            }
            litebox::platform::page_mgmt::AllocationError::AddressInUse => Errno::EEXIST,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::platform::page_mgmt::DeallocationError> for Errno {
    fn from(value: litebox::platform::page_mgmt::DeallocationError) -> Self {
        match value {
            litebox::platform::page_mgmt::DeallocationError::Unaligned => Errno::EINVAL,
            litebox::platform::page_mgmt::DeallocationError::AlreadyUnallocated => Errno::ENOMEM,
            _ => unimplemented!(),
        }
    }
}

impl From<crate::vmem::VmemUnmapError> for Errno {
    fn from(value: crate::vmem::VmemUnmapError) -> Self {
        match value {
            crate::vmem::VmemUnmapError::UnAligned => Errno::EINVAL,
            crate::vmem::VmemUnmapError::InvalidRange(_) => Errno::EINVAL,
            crate::vmem::VmemUnmapError::UnmapError(e) => e.into(),
        }
    }
}

impl From<crate::vmem::VmemResetError> for Errno {
    fn from(value: crate::vmem::VmemResetError) -> Self {
        match value {
            crate::vmem::VmemResetError::UnAligned => Errno::EINVAL,
            crate::vmem::VmemResetError::AlreadyUnallocated => Errno::ENOMEM,
            crate::vmem::VmemResetError::FileBacked => Errno::EINVAL,
        }
    }
}

impl From<crate::vmem::MappingError> for Errno {
    fn from(value: crate::vmem::MappingError) -> Self {
        match value {
            crate::vmem::MappingError::UnAligned => Errno::EINVAL,
            crate::vmem::MappingError::OutOfMemory => Errno::ENOMEM,
            crate::vmem::MappingError::MemoryAccess => Errno::EFAULT,
            crate::vmem::MappingError::BadFD(_) => Errno::EBADF,
            crate::vmem::MappingError::NotAFile => Errno::EISDIR,
            crate::vmem::MappingError::NotForReading => Errno::EACCES,
            crate::vmem::MappingError::InvalidPermissions => Errno::EINVAL,
            crate::vmem::MappingError::MapError(e) => e.into(),
            crate::vmem::MappingError::ProtectError(e) => e.into(),
        }
    }
}

impl From<litebox::platform::page_mgmt::RemapError> for Errno {
    fn from(value: litebox::platform::page_mgmt::RemapError) -> Self {
        match value {
            litebox::platform::page_mgmt::RemapError::UnsupportedByPlatform => Errno::ENOSYS,
            litebox::platform::page_mgmt::RemapError::Unaligned
            | litebox::platform::page_mgmt::RemapError::Overlapping => Errno::EINVAL,
            litebox::platform::page_mgmt::RemapError::InvalidRange
            | litebox::platform::page_mgmt::RemapError::AlreadyAllocated
            | litebox::platform::page_mgmt::RemapError::AlreadyUnallocated => Errno::EFAULT,
            litebox::platform::page_mgmt::RemapError::OutOfMemory
            | litebox::platform::page_mgmt::RemapError::PermissionDenied => Errno::ENOMEM,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::platform::page_mgmt::PermissionUpdateError> for Errno {
    fn from(value: litebox::platform::page_mgmt::PermissionUpdateError) -> Self {
        match value {
            litebox::platform::page_mgmt::PermissionUpdateError::Unaligned => Errno::EINVAL,
            litebox::platform::page_mgmt::PermissionUpdateError::Unallocated
            | litebox::platform::page_mgmt::PermissionUpdateError::OutOfMemory => Errno::ENOMEM,
            litebox::platform::page_mgmt::PermissionUpdateError::PermissionDenied => Errno::EACCES,
            litebox::platform::page_mgmt::PermissionUpdateError::PlatformFailure => Errno::EINVAL,
            _ => unimplemented!(),
        }
    }
}

impl From<crate::vmem::VmemProtectError> for Errno {
    fn from(value: crate::vmem::VmemProtectError) -> Self {
        match value {
            crate::vmem::VmemProtectError::UnAligned(_) => Errno::EINVAL,
            crate::vmem::VmemProtectError::InvalidRange(_) => Errno::ENOMEM,
            crate::vmem::VmemProtectError::NoAccess { .. } => Errno::EACCES,
            crate::vmem::VmemProtectError::UnsupportedProtection => Errno::EINVAL,
            crate::vmem::VmemProtectError::ProtectError(e) => e.into(),
        }
    }
}

impl From<litebox::fs::errors::FileStatusError> for Errno {
    fn from(value: litebox::fs::errors::FileStatusError) -> Self {
        match value {
            litebox::fs::errors::FileStatusError::ClosedFd => Errno::EBADF,
            litebox::fs::errors::FileStatusError::PathError(path_error) => path_error.into(),
            litebox::fs::errors::FileStatusError::Io => Errno::EIO,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::IsTerminalError> for Errno {
    fn from(value: litebox::fs::errors::IsTerminalError) -> Self {
        match value {
            litebox::fs::errors::IsTerminalError::ClosedFd => Errno::EBADF,
            litebox::fs::errors::IsTerminalError::Io => Errno::EIO,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::StatusFlagsError> for Errno {
    fn from(value: litebox::fs::errors::StatusFlagsError) -> Self {
        match value {
            litebox::fs::errors::StatusFlagsError::ClosedFd
            | litebox::fs::errors::StatusFlagsError::PathOnly => Errno::EBADF,
            litebox::fs::errors::StatusFlagsError::Io => Errno::EIO,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::inet_socket::errors::SocketError> for Errno {
    fn from(value: litebox::inet_socket::errors::SocketError) -> Self {
        match value {
            litebox::inet_socket::errors::SocketError::UnsupportedType => Errno::ESOCKTNOSUPPORT,
            litebox::inet_socket::errors::SocketError::BrokerUnavailable => Errno::EAFNOSUPPORT,
            litebox::inet_socket::errors::SocketError::ResourceExhausted => Errno::ENOBUFS,
            litebox::inet_socket::errors::SocketError::PermissionDenied => Errno::EACCES,
            litebox::inet_socket::errors::SocketError::BackendFailure => Errno::EIO,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::inet_socket::errors::AcceptError> for Errno {
    fn from(value: litebox::inet_socket::errors::AcceptError) -> Self {
        match value {
            litebox::inet_socket::errors::AcceptError::NotListening => Errno::EINVAL,
            litebox::inet_socket::errors::AcceptError::NoConnectionsReady
            | litebox::inet_socket::errors::AcceptError::NonBlocking => Errno::EAGAIN,
            litebox::inet_socket::errors::AcceptError::UnsupportedOperation => Errno::EOPNOTSUPP,
            litebox::inet_socket::errors::AcceptError::OperationFailed(error) => error.into(),
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::inet_socket::errors::BindError> for Errno {
    fn from(value: litebox::inet_socket::errors::BindError) -> Self {
        match value {
            litebox::inet_socket::errors::BindError::UnsupportedAddress(_) => Errno::EAFNOSUPPORT,
            litebox::inet_socket::errors::BindError::PortAlreadyInUse(_) => Errno::EADDRINUSE,
            litebox::inet_socket::errors::BindError::UnsupportedOperation => Errno::EOPNOTSUPP,
            litebox::inet_socket::errors::BindError::OperationFailed(error) => error.into(),
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::inet_socket::errors::ConnectError> for Errno {
    fn from(value: litebox::inet_socket::errors::ConnectError) -> Self {
        match value {
            litebox::inet_socket::errors::ConnectError::UnsupportedAddress(_) => {
                Errno::EAFNOSUPPORT
            }
            litebox::inet_socket::errors::ConnectError::InProgress => Errno::EINPROGRESS,
            litebox::inet_socket::errors::ConnectError::AlreadyInProgress => Errno::EALREADY,
            litebox::inet_socket::errors::ConnectError::AlreadyConnected => Errno::EISCONN,
            litebox::inet_socket::errors::ConnectError::InvalidState => Errno::ECONNREFUSED,
            litebox::inet_socket::errors::ConnectError::TimedOut => Errno::ETIMEDOUT,
            litebox::inet_socket::errors::ConnectError::OperationFailed(error) => error.into(),
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::inet_socket::errors::SocketAsyncError> for Errno {
    fn from(value: litebox::inet_socket::errors::SocketAsyncError) -> Self {
        match value {
            litebox::inet_socket::errors::SocketAsyncError::ConnectionRefused => {
                Errno::ECONNREFUSED
            }
            litebox::inet_socket::errors::SocketAsyncError::ConnectionReset => Errno::ECONNRESET,
            litebox::inet_socket::errors::SocketAsyncError::TimedOut => Errno::ETIMEDOUT,
            litebox::inet_socket::errors::SocketAsyncError::ConnectionAborted => {
                Errno::ECONNABORTED
            }
            litebox::inet_socket::errors::SocketAsyncError::NetworkUnreachable => {
                Errno::ENETUNREACH
            }
            litebox::inet_socket::errors::SocketAsyncError::HostUnreachable => Errno::EHOSTUNREACH,
            litebox::inet_socket::errors::SocketAsyncError::AddressInUse => Errno::EADDRINUSE,
            litebox::inet_socket::errors::SocketAsyncError::AddressNotAvailable => {
                Errno::EADDRNOTAVAIL
            }
            litebox::inet_socket::errors::SocketAsyncError::NotConnected => Errno::ENOTCONN,
            litebox::inet_socket::errors::SocketAsyncError::InvalidArgument => Errno::EINVAL,
            litebox::inet_socket::errors::SocketAsyncError::PolicyDenied => Errno::EACCES,
            litebox::inet_socket::errors::SocketAsyncError::ResourceExhausted => Errno::ENOBUFS,
            litebox::inet_socket::errors::SocketAsyncError::UnsupportedOperation => {
                Errno::EOPNOTSUPP
            }
            litebox::inet_socket::errors::SocketAsyncError::BackendFailure => Errno::EIO,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::inet_socket::errors::ShutdownError> for Errno {
    fn from(value: litebox::inet_socket::errors::ShutdownError) -> Self {
        match value {
            litebox::inet_socket::errors::ShutdownError::Listening => Errno::ENOTCONN,
            litebox::inet_socket::errors::ShutdownError::UnsupportedOperation => Errno::EOPNOTSUPP,
            litebox::inet_socket::errors::ShutdownError::OperationFailed(error) => error.into(),
            _ => unimplemented!(),
        }
    }
}

impl TryFrom<Errno> for litebox::inet_socket::errors::SocketAsyncError {
    type Error = Errno;

    fn try_from(value: Errno) -> Result<Self, Self::Error> {
        match value {
            Errno::ECONNREFUSED => {
                Ok(litebox::inet_socket::errors::SocketAsyncError::ConnectionRefused)
            }
            Errno::ECONNRESET => {
                Ok(litebox::inet_socket::errors::SocketAsyncError::ConnectionReset)
            }
            Errno::ETIMEDOUT => Ok(litebox::inet_socket::errors::SocketAsyncError::TimedOut),
            Errno::ECONNABORTED => {
                Ok(litebox::inet_socket::errors::SocketAsyncError::ConnectionAborted)
            }
            Errno::ENETUNREACH => {
                Ok(litebox::inet_socket::errors::SocketAsyncError::NetworkUnreachable)
            }
            Errno::EHOSTUNREACH => {
                Ok(litebox::inet_socket::errors::SocketAsyncError::HostUnreachable)
            }
            Errno::EADDRINUSE => Ok(litebox::inet_socket::errors::SocketAsyncError::AddressInUse),
            Errno::EADDRNOTAVAIL => {
                Ok(litebox::inet_socket::errors::SocketAsyncError::AddressNotAvailable)
            }
            Errno::ENOTCONN => Ok(litebox::inet_socket::errors::SocketAsyncError::NotConnected),
            Errno::EINVAL => Ok(litebox::inet_socket::errors::SocketAsyncError::InvalidArgument),
            Errno::EACCES => Ok(litebox::inet_socket::errors::SocketAsyncError::PolicyDenied),
            Errno::ENOBUFS => Ok(litebox::inet_socket::errors::SocketAsyncError::ResourceExhausted),
            Errno::EOPNOTSUPP => {
                Ok(litebox::inet_socket::errors::SocketAsyncError::UnsupportedOperation)
            }
            Errno::EIO => Ok(litebox::inet_socket::errors::SocketAsyncError::BackendFailure),
            _ => Err(value),
        }
    }
}

impl From<litebox::inet_socket::errors::RemoteAddrError> for Errno {
    fn from(value: litebox::inet_socket::errors::RemoteAddrError) -> Self {
        match value {
            litebox::inet_socket::errors::RemoteAddrError::NotConnected => Errno::ENOTCONN,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::inet_socket::errors::ListenError> for Errno {
    fn from(value: litebox::inet_socket::errors::ListenError) -> Self {
        match value {
            litebox::inet_socket::errors::ListenError::InvalidAddress => Errno::EINVAL,
            litebox::inet_socket::errors::ListenError::InvalidState => Errno::EINVAL,
            litebox::inet_socket::errors::ListenError::UnsupportedOperation => Errno::EOPNOTSUPP,
            litebox::inet_socket::errors::ListenError::OperationFailed(error) => error.into(),

            _ => unimplemented!(),
        }
    }
}

impl From<litebox::inet_socket::errors::SocketWriteError> for Errno {
    fn from(value: litebox::inet_socket::errors::SocketWriteError) -> Self {
        match value {
            litebox::inet_socket::errors::SocketWriteError::WriteShutdown
            | litebox::inet_socket::errors::SocketWriteError::NotConnected
            | litebox::inet_socket::errors::SocketWriteError::ConnectionClosed => Errno::EPIPE,
            litebox::inet_socket::errors::SocketWriteError::Unaddressable => Errno::EINVAL,
            litebox::inet_socket::errors::SocketWriteError::BufferFull
            | litebox::inet_socket::errors::SocketWriteError::NonBlocking => Errno::EAGAIN,
            litebox::inet_socket::errors::SocketWriteError::MessageTooLong => Errno::EMSGSIZE,
            litebox::inet_socket::errors::SocketWriteError::DestinationAddressRequired => {
                Errno::EDESTADDRREQ
            }
            litebox::inet_socket::errors::SocketWriteError::Socket(error) => error.into(),
        }
    }
}

impl<E> From<litebox::event::polling::TryOpError<E>> for Errno
where
    E: Into<Errno>,
{
    fn from(value: litebox::event::polling::TryOpError<E>) -> Self {
        match value {
            litebox::event::polling::TryOpError::TryAgain => Errno::EAGAIN,
            litebox::event::polling::TryOpError::WaitError(e) => match e {
                litebox::event::wait::WaitError::Interrupted => Errno::ERESTARTSYS,
                litebox::event::wait::WaitError::TimedOut => Errno::ETIMEDOUT,
            },
            litebox::event::polling::TryOpError::Other(e) => e.into(),
        }
    }
}

impl From<litebox::event::counter::EventCounterError> for Errno {
    fn from(value: litebox::event::counter::EventCounterError) -> Self {
        match value {
            litebox::event::counter::EventCounterError::InvalidInput => Errno::EINVAL,
            litebox::event::counter::EventCounterError::WouldBlock => Errno::EAGAIN,
            // A resource limit or allocation failure is not retryable; EAGAIN
            // would tell a caller to spin on `eventfd2`/read/write against a
            // permanent condition. ENOMEM is the documented eventfd2 exhaustion
            // errno and honestly covers the folded out-of-memory case.
            litebox::event::counter::EventCounterError::ResourceExhausted => Errno::ENOMEM,
            litebox::event::counter::EventCounterError::PermissionDenied => Errno::EACCES,
            litebox::event::counter::EventCounterError::Io
            | litebox::event::counter::EventCounterError::Unavailable => Errno::EIO,
            _ => Errno::EIO,
        }
    }
}

impl From<litebox::event::timer::TimerError> for Errno {
    fn from(value: litebox::event::timer::TimerError) -> Self {
        match value {
            litebox::event::timer::TimerError::WouldBlock => Errno::EAGAIN,
            litebox::event::timer::TimerError::ResourceExhausted => Errno::ENOMEM,
            litebox::event::timer::TimerError::PermissionDenied => Errno::EACCES,
            litebox::event::timer::TimerError::Io
            | litebox::event::timer::TimerError::Unavailable => Errno::EIO,
            _ => Errno::EIO,
        }
    }
}

impl From<litebox::event::readiness_queue::ReadinessQueueError> for Errno {
    fn from(value: litebox::event::readiness_queue::ReadinessQueueError) -> Self {
        use litebox::event::readiness_queue::ReadinessQueueError;
        match value {
            ReadinessQueueError::AlreadyRegistered => Errno::EEXIST,
            ReadinessQueueError::NotRegistered => Errno::ENOENT,
            ReadinessQueueError::UnsupportedTarget | ReadinessQueueError::PermissionDenied => {
                Errno::EPERM
            }
            ReadinessQueueError::WouldBlock => Errno::EAGAIN,
            ReadinessQueueError::ResourceExhausted => Errno::ENOSPC,
            ReadinessQueueError::OutOfMemory => Errno::ENOMEM,
            ReadinessQueueError::Io | ReadinessQueueError::Unavailable => Errno::EIO,
            _ => Errno::EIO,
        }
    }
}

impl From<litebox::fs::errors::ReadDirError> for Errno {
    fn from(value: litebox::fs::errors::ReadDirError) -> Self {
        match value {
            litebox::fs::errors::ReadDirError::NotADirectory => Errno::ENOTDIR,
            litebox::fs::errors::ReadDirError::NotOpenForReading => Errno::EBADF,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::sync::futex::FutexError> for Errno {
    fn from(value: litebox::sync::futex::FutexError) -> Self {
        match value {
            litebox::sync::futex::FutexError::NotAligned => Errno::EINVAL,
            litebox::sync::futex::FutexError::ImmediatelyWokenBecauseValueMismatch => Errno::EAGAIN,
            litebox::sync::futex::FutexError::WaitError(e) => match e {
                litebox::event::wait::WaitError::Interrupted => Errno::ERESTARTSYS,
                litebox::event::wait::WaitError::TimedOut => Errno::ETIMEDOUT,
            },
            litebox::sync::futex::FutexError::Fault => Errno::EFAULT,
        }
    }
}

impl From<litebox::pipes::errors::ReadError> for Errno {
    fn from(value: litebox::pipes::errors::ReadError) -> Self {
        match value {
            litebox::pipes::errors::ReadError::NotForReading => Errno::EBADF,
            litebox::pipes::errors::ReadError::WouldBlock => Errno::EWOULDBLOCK,
            litebox::pipes::errors::ReadError::WaitError(e) => match e {
                litebox::event::wait::WaitError::Interrupted => Errno::ERESTARTSYS,
                litebox::event::wait::WaitError::TimedOut => Errno::ETIMEDOUT,
            },
            litebox::pipes::errors::ReadError::Io => Errno::EIO,
            _ => todo!(),
        }
    }
}

impl From<litebox::pipes::errors::WriteError> for Errno {
    fn from(value: litebox::pipes::errors::WriteError) -> Self {
        match value {
            litebox::pipes::errors::WriteError::ReadEndClosed => Errno::EPIPE,
            litebox::pipes::errors::WriteError::NotForWriting => Errno::EBADF,
            litebox::pipes::errors::WriteError::WouldBlock => Errno::EWOULDBLOCK,
            litebox::pipes::errors::WriteError::WaitError(e) => match e {
                litebox::event::wait::WaitError::Interrupted => Errno::ERESTARTSYS,
                litebox::event::wait::WaitError::TimedOut => Errno::ETIMEDOUT,
            },
            litebox::pipes::errors::WriteError::Io => Errno::EIO,
            _ => todo!(),
        }
    }
}

impl From<litebox::pipes::errors::CreateError> for Errno {
    fn from(value: litebox::pipes::errors::CreateError) -> Self {
        match value {
            litebox::pipes::errors::CreateError::ResourceExhausted => Errno::ENFILE,
            litebox::pipes::errors::CreateError::OutOfMemory => Errno::ENOMEM,
            litebox::pipes::errors::CreateError::PermissionDenied => Errno::EACCES,
            litebox::pipes::errors::CreateError::Io => Errno::EIO,
            _ => todo!(),
        }
    }
}

impl From<litebox::unix_socket::errors::UnixSocketError> for Errno {
    fn from(value: litebox::unix_socket::errors::UnixSocketError) -> Self {
        use litebox::unix_socket::errors::UnixSocketError;
        use litebox_broker_protocol::fs::FileError;
        use litebox_broker_protocol::unix_socket::UnixSocketError as SocketError;
        match value {
            UnixSocketError::Socket(error) => match error {
                SocketError::AddressInUse => Errno::EADDRINUSE,
                SocketError::ConnectionRefused => Errno::ECONNREFUSED,
                SocketError::WrongType => Errno::EPROTOTYPE,
                SocketError::InvalidArgument => Errno::EINVAL,
                SocketError::AlreadyConnected => Errno::EISCONN,
                SocketError::NotConnected => Errno::ENOTCONN,
                SocketError::Unsupported => Errno::EOPNOTSUPP,
                SocketError::MessageTooLarge => Errno::EMSGSIZE,
                SocketError::BrokenPipe => Errno::EPIPE,
                SocketError::NotPermitted => Errno::EPERM,
                SocketError::ConnectionReset => Errno::ECONNRESET,
                SocketError::File(error) => match error {
                    FileError::NoSuchFileOrDirectory | FileError::MissingComponent => Errno::ENOENT,
                    FileError::AccessNotAllowed
                    | FileError::NoWritePermissions
                    | FileError::NoSearchPermissions => Errno::EACCES,
                    FileError::ReadOnlyFs => Errno::EROFS,
                    FileError::AlreadyExists => Errno::EADDRINUSE,
                    FileError::InvalidPathname => Errno::EINVAL,
                    FileError::ComponentNotDirectory | FileError::NotDirectory => Errno::ENOTDIR,
                    _ => Errno::EIO,
                },
                _ => Errno::EIO,
            },
            UnixSocketError::WouldBlock => Errno::EAGAIN,
            UnixSocketError::Interrupted => Errno::EINTR,
            UnixSocketError::WaitError(error) => match error {
                litebox::event::wait::WaitError::Interrupted => Errno::ERESTARTSYS,
                litebox::event::wait::WaitError::TimedOut => Errno::ETIMEDOUT,
            },
            UnixSocketError::ResourceExhausted => Errno::ENOBUFS,
            UnixSocketError::OutOfMemory => Errno::ENOMEM,
            UnixSocketError::PermissionDenied => Errno::EACCES,
            UnixSocketError::Unsupported => Errno::EINVAL,
            _ => Errno::EIO,
        }
    }
}

impl From<litebox::fs::errors::TruncateError> for Errno {
    fn from(value: litebox::fs::errors::TruncateError) -> Self {
        match value {
            litebox::fs::errors::TruncateError::IsDirectory => Errno::EISDIR,
            litebox::fs::errors::TruncateError::NotForWriting => Errno::EACCES,
            litebox::fs::errors::TruncateError::NotOpenForWriting => Errno::EBADF,
            litebox::fs::errors::TruncateError::IsTerminalDevice => Errno::EINVAL,
            litebox::fs::errors::TruncateError::ClosedFd => Errno::EBADF,
            litebox::fs::errors::TruncateError::Io => Errno::EIO,
        }
    }
}

impl From<litebox::platform::ArchSpecificError> for Errno {
    fn from(value: litebox::platform::ArchSpecificError) -> Self {
        match value {
            litebox::platform::ArchSpecificError::RegisterUnsupported => {
                // Reaching here means that a shim is attempting to easily run on a platform that
                // fully disallows it. There is no reasonable handling here, so we panic.
                // XXX: should this be ENOSYS or EINVAL?
                unimplemented!()
            }
            litebox::platform::ArchSpecificError::RegisterReserved => Errno::EINVAL,
            litebox::platform::ArchSpecificError::RegisterUnpermittedValue => Errno::EPERM,
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Errno;
    use litebox::process::ProcessError;

    #[test]
    fn process_errors_map_to_linux_errno() {
        let cases = [
            (ProcessError::PolicyDenied, Errno::EPERM),
            (ProcessError::Unavailable, Errno::ENOSYS),
            (ProcessError::Busy, Errno::EAGAIN),
            (ProcessError::ResourceExhausted, Errno::EAGAIN),
            (ProcessError::OutOfMemory, Errno::ENOMEM),
            (ProcessError::ServiceFailed, Errno::EIO),
            (ProcessError::InvalidChild, Errno::EIO),
            (ProcessError::NoSuchProcess, Errno::ESRCH),
        ];

        for (error, expected) in cases {
            assert_eq!(Errno::from(error), expected);
        }
    }
}
