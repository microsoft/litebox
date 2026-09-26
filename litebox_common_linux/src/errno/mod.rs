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
    value: core::num::NonZeroU8,
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

    /// (Private-only) Helper function that makes the associated constants on [`Errno`] significantly more
    /// readable. Not intended to be used outside this crate, or even this module.
    const fn from_const(v: u8) -> Self {
        Self {
            value: core::num::NonZeroU8::new(v).unwrap(),
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
        let value =
            core::num::NonZeroU8::new(value).ok_or(ErrnoConversionError::ExpectedNonZero)?;
        if value.get() <= Self::MAX.value.get() {
            Ok(Self { value })
        } else {
            Err(ErrnoConversionError::ExpectedSmallEnough)
        }
    }
}

impl From<litebox::fs::errors::PathError> for Errno {
    fn from(value: litebox::fs::errors::PathError) -> Self {
        match value {
            litebox::fs::errors::PathError::NoSuchFileOrDirectory => Errno::ENOENT,
            litebox::fs::errors::PathError::NoSearchPerms { .. } => Errno::EACCES,
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
            litebox::fs::errors::OpenError::OperationNotPermitted => Errno::EPERM,
            litebox::fs::errors::OpenError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::OpenError::PathError(path_error) => path_error.into(),
            litebox::fs::errors::OpenError::ReadOnlyFileSystem => Errno::EROFS,
            litebox::fs::errors::OpenError::AlreadyExists => Errno::EEXIST,
            litebox::fs::errors::OpenError::TooManySymbolicLinks => Errno::ELOOP,
            litebox::fs::errors::OpenError::TruncateError(error) => error.into(),
            litebox::fs::errors::OpenError::Io => Errno::EIO,
            litebox::fs::errors::OpenError::UnsupportedFlags => Errno::EINVAL,
            _ => Errno::EIO,
        }
    }
}

impl From<litebox::fs::errors::UnlinkError> for Errno {
    fn from(value: litebox::fs::errors::UnlinkError) -> Self {
        match value {
            litebox::fs::errors::UnlinkError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::UnlinkError::OperationNotPermitted => Errno::EPERM,
            litebox::fs::errors::UnlinkError::IsADirectory => Errno::EISDIR,
            litebox::fs::errors::UnlinkError::ReadOnlyFileSystem => Errno::EROFS,
            litebox::fs::errors::UnlinkError::Io => Errno::EIO,
            litebox::fs::errors::UnlinkError::PathError(path_error) => path_error.into(),
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::RenameError> for Errno {
    fn from(value: litebox::fs::errors::RenameError) -> Self {
        match value {
            litebox::fs::errors::RenameError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::RenameError::OperationNotPermitted => Errno::EPERM,
            litebox::fs::errors::RenameError::NotEmpty => Errno::ENOTEMPTY,
            litebox::fs::errors::RenameError::IsADirectory => Errno::EISDIR,
            litebox::fs::errors::RenameError::NotADirectory => Errno::ENOTDIR,
            litebox::fs::errors::RenameError::AlreadyExists => Errno::EEXIST,
            litebox::fs::errors::RenameError::CrossDevice => Errno::EXDEV,
            litebox::fs::errors::RenameError::InvalidArgument => Errno::EINVAL,
            litebox::fs::errors::RenameError::ReadOnlyFileSystem => Errno::EROFS,
            litebox::fs::errors::RenameError::Io => Errno::EIO,
            litebox::fs::errors::RenameError::PathError(path_error) => path_error.into(),
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::RmdirError> for Errno {
    fn from(value: litebox::fs::errors::RmdirError) -> Self {
        match value {
            litebox::fs::errors::RmdirError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::RmdirError::OperationNotPermitted => Errno::EPERM,
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

impl From<litebox::fs::errors::CloseError> for Errno {
    fn from(value: litebox::fs::errors::CloseError) -> Self {
        #[expect(clippy::match_single_binding)]
        match value {
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::net::errors::CloseError> for Errno {
    fn from(value: litebox::net::errors::CloseError) -> Self {
        match value {
            litebox::net::errors::CloseError::InvalidFd => Errno::EBADF,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::ReadError> for Errno {
    fn from(value: litebox::fs::errors::ReadError) -> Self {
        match value {
            litebox::fs::errors::ReadError::NotAFile => Errno::EISDIR,
            litebox::fs::errors::ReadError::NotForReading => Errno::EBADF,
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
            litebox::fs::errors::WriteError::ReadOnlyFileSystem => Errno::EROFS,
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

impl From<litebox::fs::errors::SymlinkError> for Errno {
    fn from(value: litebox::fs::errors::SymlinkError) -> Self {
        match value {
            litebox::fs::errors::SymlinkError::PathError(path_error) => path_error.into(),
            litebox::fs::errors::SymlinkError::AlreadyExists => Errno::EEXIST,
            litebox::fs::errors::SymlinkError::ReadOnlyFileSystem => Errno::EROFS,
            litebox::fs::errors::SymlinkError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::SymlinkError::Io => Errno::EIO,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::ReadlinkError> for Errno {
    fn from(value: litebox::fs::errors::ReadlinkError) -> Self {
        match value {
            litebox::fs::errors::ReadlinkError::PathError(path_error) => path_error.into(),
            // readlink(2) on a non-symlink is EINVAL.
            litebox::fs::errors::ReadlinkError::NotASymlink => Errno::EINVAL,
            litebox::fs::errors::ReadlinkError::Io => Errno::EIO,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::ChmodError> for Errno {
    fn from(value: litebox::fs::errors::ChmodError) -> Self {
        match value {
            litebox::fs::errors::ChmodError::NotTheOwner => Errno::EPERM,
            litebox::fs::errors::ChmodError::ReadOnlyFileSystem => Errno::EROFS,
            litebox::fs::errors::ChmodError::Io => Errno::EIO,
            litebox::fs::errors::ChmodError::PathError(path_error) => path_error.into(),
            litebox::fs::errors::ChmodError::ClosedFd => Errno::EBADF,
            litebox::fs::errors::ChmodError::PathOnlyFd => Errno::EBADF,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::ChownError> for Errno {
    fn from(value: litebox::fs::errors::ChownError) -> Self {
        match value {
            litebox::fs::errors::ChownError::NotTheOwner => Errno::EPERM,
            litebox::fs::errors::ChownError::ReadOnlyFileSystem => Errno::EROFS,
            litebox::fs::errors::ChownError::Io => Errno::EIO,
            litebox::fs::errors::ChownError::PathError(path_error) => path_error.into(),
            litebox::fs::errors::ChownError::ClosedFd => Errno::EBADF,
            litebox::fs::errors::ChownError::PathOnlyFd => Errno::EBADF,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::UtimeError> for Errno {
    fn from(value: litebox::fs::errors::UtimeError) -> Self {
        match value {
            litebox::fs::errors::UtimeError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::UtimeError::ReadOnlyFileSystem => Errno::EROFS,
            litebox::fs::errors::UtimeError::Io => Errno::EIO,
            litebox::fs::errors::UtimeError::PathError(path_error) => path_error.into(),
            litebox::fs::errors::UtimeError::ClosedFd => Errno::EBADF,
            litebox::fs::errors::UtimeError::PathOnlyFd => Errno::EBADF,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::platform::page_mgmt::AllocationError> for Errno {
    fn from(value: litebox::platform::page_mgmt::AllocationError) -> Self {
        match value {
            litebox::platform::page_mgmt::AllocationError::Unaligned
            | litebox::platform::page_mgmt::AllocationError::AboveMaxAddress => Errno::EINVAL,
            litebox::platform::page_mgmt::AllocationError::BelowMinAddress => Errno::EPERM,
            litebox::platform::page_mgmt::AllocationError::OutOfMemory
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

impl From<litebox::mm::vmem::VmemUnmapError> for Errno {
    fn from(value: litebox::mm::vmem::VmemUnmapError) -> Self {
        match value {
            litebox::mm::vmem::VmemUnmapError::UnAligned => Errno::EINVAL,
            litebox::mm::vmem::VmemUnmapError::UnmapError(e) => e.into(),
        }
    }
}

impl From<litebox::mm::vmem::VmemResetError> for Errno {
    fn from(value: litebox::mm::vmem::VmemResetError) -> Self {
        match value {
            litebox::mm::vmem::VmemResetError::UnAligned => Errno::EINVAL,
            litebox::mm::vmem::VmemResetError::AlreadyUnallocated => Errno::ENOMEM,
            litebox::mm::vmem::VmemResetError::FileBacked => Errno::EINVAL,
        }
    }
}

impl From<litebox::mm::vmem::MappingError> for Errno {
    fn from(value: litebox::mm::vmem::MappingError) -> Self {
        match value {
            litebox::mm::vmem::MappingError::UnAligned => Errno::EINVAL,
            litebox::mm::vmem::MappingError::OutOfMemory => Errno::ENOMEM,
            litebox::mm::vmem::MappingError::BadFD(_) => Errno::EBADF,
            litebox::mm::vmem::MappingError::NotAFile => Errno::EISDIR,
            litebox::mm::vmem::MappingError::NotForReading => Errno::EACCES,
            litebox::mm::vmem::MappingError::Io(errno) => {
                Errno::try_from(errno).unwrap_or(Errno::EIO)
            }
            litebox::mm::vmem::MappingError::MapError(e) => e.into(),
            // Real Linux returns `ENOMEM` for the analogous "another thread raced this mmap"
            // case (e.g. `MAP_FIXED` colliding with a concurrent unmap of the same range).
            litebox::mm::vmem::MappingError::ConcurrentlyRemoved
            | litebox::mm::vmem::MappingError::InitializationIdentityExhausted => Errno::ENOMEM,
            litebox::mm::vmem::MappingError::FinalizeProtection(error) => error.into(),
            litebox::mm::vmem::MappingError::Cleanup { primary, .. } => (*primary).into(),
            _ => Errno::EIO,
        }
    }
}

impl From<litebox::platform::page_mgmt::RemapError> for Errno {
    fn from(value: litebox::platform::page_mgmt::RemapError) -> Self {
        match value {
            litebox::platform::page_mgmt::RemapError::Unaligned
            | litebox::platform::page_mgmt::RemapError::Overlapping => Errno::EINVAL,
            litebox::platform::page_mgmt::RemapError::AlreadyAllocated
            | litebox::platform::page_mgmt::RemapError::AlreadyUnallocated => Errno::EFAULT,
            litebox::platform::page_mgmt::RemapError::OutOfMemory => Errno::ENOMEM,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::platform::page_mgmt::PermissionUpdateError> for Errno {
    fn from(value: litebox::platform::page_mgmt::PermissionUpdateError) -> Self {
        match value {
            litebox::platform::page_mgmt::PermissionUpdateError::Unaligned => Errno::EINVAL,
            litebox::platform::page_mgmt::PermissionUpdateError::Unallocated => Errno::ENOMEM,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::mm::vmem::VmemProtectError> for Errno {
    fn from(value: litebox::mm::vmem::VmemProtectError) -> Self {
        match value {
            litebox::mm::vmem::VmemProtectError::UnAligned(_) => Errno::EINVAL,
            litebox::mm::vmem::VmemProtectError::InvalidRange(_) => Errno::ENOMEM,
            litebox::mm::vmem::VmemProtectError::NoAccess { .. } => Errno::EACCES,
            litebox::mm::vmem::VmemProtectError::ProtectError(e) => e.into(),
            litebox::mm::vmem::VmemProtectError::DeferredAllocate(_) => Errno::ENOMEM,
        }
    }
}

impl From<litebox::path::ConversionError> for Errno {
    fn from(value: litebox::path::ConversionError) -> Self {
        match value {
            litebox::path::ConversionError::FailedToConvertTo(_) => Errno::EINVAL,
        }
    }
}

impl From<litebox::fs::errors::FileStatusError> for Errno {
    fn from(value: litebox::fs::errors::FileStatusError) -> Self {
        match value {
            litebox::fs::errors::FileStatusError::ClosedFd => Errno::EBADF,
            litebox::fs::errors::FileStatusError::Io => Errno::EIO,
            litebox::fs::errors::FileStatusError::PathError(path_error) => path_error.into(),
            _ => Errno::EIO,
        }
    }
}

impl From<litebox::net::errors::SocketError> for Errno {
    fn from(value: litebox::net::errors::SocketError) -> Self {
        match value {
            litebox::net::errors::SocketError::UnsupportedProtocol(_) => Errno::EPROTONOSUPPORT,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::net::errors::AcceptError> for Errno {
    fn from(value: litebox::net::errors::AcceptError) -> Self {
        match value {
            litebox::net::errors::AcceptError::InvalidFd => Errno::EBADF,
            litebox::net::errors::AcceptError::NotListening => Errno::ENOTCONN,
            litebox::net::errors::AcceptError::NoConnectionsReady => Errno::EAGAIN,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::net::errors::BindError> for Errno {
    fn from(value: litebox::net::errors::BindError) -> Self {
        match value {
            litebox::net::errors::BindError::InvalidFd => Errno::EBADF,
            litebox::net::errors::BindError::UnsupportedAddress(_) => Errno::EAFNOSUPPORT,
            litebox::net::errors::BindError::PortAlreadyInUse(_) => Errno::EADDRINUSE,
            litebox::net::errors::BindError::AlreadyBound => Errno::EINVAL,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::net::errors::ConnectError> for Errno {
    fn from(value: litebox::net::errors::ConnectError) -> Self {
        match value {
            litebox::net::errors::ConnectError::InvalidFd => Errno::EBADF,
            litebox::net::errors::ConnectError::UnsupportedAddress(_) => Errno::EAFNOSUPPORT,
            litebox::net::errors::ConnectError::PortAllocationFailure(_) => Errno::EADDRINUSE,
            litebox::net::errors::ConnectError::Unaddressable => Errno::ECONNREFUSED,
            litebox::net::errors::ConnectError::InProgress => Errno::EINPROGRESS,
            litebox::net::errors::ConnectError::InvalidState => Errno::ECONNREFUSED,
            litebox::net::errors::ConnectError::TimedOut => Errno::ETIMEDOUT,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::net::errors::SocketAsyncError> for Errno {
    fn from(value: litebox::net::errors::SocketAsyncError) -> Self {
        match value {
            litebox::net::errors::SocketAsyncError::ConnectionRefused => Errno::ECONNREFUSED,
            litebox::net::errors::SocketAsyncError::ConnectionReset => Errno::ECONNRESET,
            litebox::net::errors::SocketAsyncError::TimedOut => Errno::ETIMEDOUT,
            _ => unimplemented!(),
        }
    }
}

impl TryFrom<Errno> for litebox::net::errors::SocketAsyncError {
    type Error = Errno;

    fn try_from(value: Errno) -> Result<Self, Self::Error> {
        match value {
            Errno::ECONNREFUSED => Ok(litebox::net::errors::SocketAsyncError::ConnectionRefused),
            Errno::ECONNRESET => Ok(litebox::net::errors::SocketAsyncError::ConnectionReset),
            Errno::ETIMEDOUT => Ok(litebox::net::errors::SocketAsyncError::TimedOut),
            _ => Err(value),
        }
    }
}

impl From<litebox::net::errors::LocalAddrError> for Errno {
    fn from(value: litebox::net::errors::LocalAddrError) -> Self {
        match value {
            litebox::net::errors::LocalAddrError::InvalidFd => Errno::EBADF,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::net::errors::RemoteAddrError> for Errno {
    fn from(value: litebox::net::errors::RemoteAddrError) -> Self {
        match value {
            litebox::net::errors::RemoteAddrError::InvalidFd => Errno::EBADF,
            litebox::net::errors::RemoteAddrError::NotConnected => Errno::ENOTCONN,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::net::errors::ListenError> for Errno {
    fn from(value: litebox::net::errors::ListenError) -> Self {
        match value {
            litebox::net::errors::ListenError::InvalidFd => Errno::EBADF,
            litebox::net::errors::ListenError::InvalidAddress => Errno::EINVAL,
            litebox::net::errors::ListenError::InvalidState => Errno::EINVAL,
            litebox::net::errors::ListenError::NoAvailableFreeEphemeralPorts => Errno::ENOSPC,

            _ => unimplemented!(),
        }
    }
}

impl From<litebox::net::local_ports::LocalPortAllocationError> for Errno {
    fn from(value: litebox::net::local_ports::LocalPortAllocationError) -> Self {
        match value {
            litebox::net::local_ports::LocalPortAllocationError::AlreadyInUse(_) => {
                Errno::EADDRINUSE
            }
            litebox::net::local_ports::LocalPortAllocationError::NoAvailableFreePorts => {
                Errno::EAGAIN
            }
        }
    }
}

impl From<litebox::net::errors::SendError> for Errno {
    fn from(value: litebox::net::errors::SendError) -> Self {
        match value {
            litebox::net::errors::SendError::InvalidFd => Errno::EBADF,
            litebox::net::errors::SendError::SocketInInvalidState => Errno::EPIPE,
            litebox::net::errors::SendError::Unaddressable => Errno::EINVAL,
            litebox::net::errors::SendError::BufferFull => Errno::EAGAIN,
            litebox::net::errors::SendError::PortAllocationFailure(e) => e.into(),
            litebox::net::errors::SendError::UnnecessaryDestinationAddress => Errno::EISCONN,
            litebox::net::errors::SendError::DestinationAddressRequired => Errno::EDESTADDRREQ,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::net::socket_channel::ChannelWriteError> for Errno {
    fn from(value: litebox::net::socket_channel::ChannelWriteError) -> Self {
        match value {
            litebox::net::socket_channel::ChannelWriteError::WriteShutdown
            | litebox::net::socket_channel::ChannelWriteError::NotConnected
            | litebox::net::socket_channel::ChannelWriteError::ConnectionClosed => Errno::EPIPE,
            litebox::net::socket_channel::ChannelWriteError::Unaddressable => Errno::EINVAL,
            litebox::net::socket_channel::ChannelWriteError::BufferFull => Errno::EAGAIN,
            litebox::net::socket_channel::ChannelWriteError::DestinationAddressRequired => {
                Errno::EDESTADDRREQ
            }
        }
    }
}

impl From<litebox::net::errors::ReceiveError> for Errno {
    fn from(value: litebox::net::errors::ReceiveError) -> Self {
        match value {
            litebox::net::errors::ReceiveError::InvalidFd => Errno::EBADF,
            litebox::net::errors::ReceiveError::SocketInInvalidState => Errno::EAGAIN,
            litebox::net::errors::ReceiveError::OperationFinished => Errno::ESHUTDOWN,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::net::errors::SetTcpOptionError> for Errno {
    fn from(value: litebox::net::errors::SetTcpOptionError) -> Self {
        match value {
            litebox::net::errors::SetTcpOptionError::InvalidFd => Errno::EBADF,
            litebox::net::errors::SetTcpOptionError::NotTcpSocket => Errno::ENOPROTOOPT,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::net::errors::GetTcpOptionError> for Errno {
    fn from(value: litebox::net::errors::GetTcpOptionError) -> Self {
        match value {
            litebox::net::errors::GetTcpOptionError::InvalidFd => Errno::EBADF,
            litebox::net::errors::GetTcpOptionError::NotTcpSocket => Errno::ENOPROTOOPT,
            _ => unimplemented!(),
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
                litebox::event::wait::WaitError::Interrupted => Errno::EINTR,
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
            litebox::event::counter::EventCounterError::WouldBlock
            | litebox::event::counter::EventCounterError::ResourceExhausted => Errno::EAGAIN,
            litebox::event::counter::EventCounterError::PermissionDenied => Errno::EACCES,
            litebox::event::counter::EventCounterError::Io
            | litebox::event::counter::EventCounterError::Unavailable => Errno::EIO,
            _ => Errno::EIO,
        }
    }
}

impl From<litebox::fs::errors::ReadDirError> for Errno {
    fn from(value: litebox::fs::errors::ReadDirError) -> Self {
        match value {
            litebox::fs::errors::ReadDirError::ClosedFd
            | litebox::fs::errors::ReadDirError::PathOnlyFd => Errno::EBADF,
            litebox::fs::errors::ReadDirError::NotADirectory => Errno::ENOTDIR,
            litebox::fs::errors::ReadDirError::Io => Errno::EIO,
            _ => Errno::EIO,
        }
    }
}

impl From<litebox::sync::futex::FutexError> for Errno {
    fn from(value: litebox::sync::futex::FutexError) -> Self {
        match value {
            litebox::sync::futex::FutexError::NotAligned
            | litebox::sync::futex::FutexError::SameKey => Errno::EINVAL,
            litebox::sync::futex::FutexError::ImmediatelyWokenBecauseValueMismatch => Errno::EAGAIN,
            litebox::sync::futex::FutexError::WaitError(e) => match e {
                litebox::event::wait::WaitError::Interrupted => Errno::EINTR,
                litebox::event::wait::WaitError::TimedOut => Errno::ETIMEDOUT,
            },
            litebox::sync::futex::FutexError::Fault => Errno::EFAULT,
        }
    }
}

impl From<litebox::pipes::errors::ReadError> for Errno {
    fn from(value: litebox::pipes::errors::ReadError) -> Self {
        match value {
            litebox::pipes::errors::ReadError::ClosedFd
            | litebox::pipes::errors::ReadError::NotForReading => Errno::EBADF,
            litebox::pipes::errors::ReadError::WouldBlock => Errno::EWOULDBLOCK,
            litebox::pipes::errors::ReadError::WaitError(e) => match e {
                litebox::event::wait::WaitError::Interrupted => Errno::EINTR,
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
            litebox::pipes::errors::WriteError::ClosedFd => Errno::EBADF,
            litebox::pipes::errors::WriteError::ReadEndClosed => Errno::EPIPE,
            litebox::pipes::errors::WriteError::NotForWriting => Errno::EBADF,
            litebox::pipes::errors::WriteError::WouldBlock => Errno::EWOULDBLOCK,
            litebox::pipes::errors::WriteError::WaitError(e) => match e {
                litebox::event::wait::WaitError::Interrupted => Errno::EINTR,
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

impl From<litebox::pipes::errors::CloseError> for Errno {
    fn from(_value: litebox::pipes::errors::CloseError) -> Self {
        todo!()
    }
}

impl From<litebox::pipes::errors::ClosedError> for Errno {
    fn from(value: litebox::pipes::errors::ClosedError) -> Self {
        match value {
            litebox::pipes::errors::ClosedError::ClosedFd => Errno::EBADF,
        }
    }
}

impl From<litebox::fs::errors::TruncateError> for Errno {
    fn from(value: litebox::fs::errors::TruncateError) -> Self {
        match value {
            litebox::fs::errors::TruncateError::IsDirectory => Errno::EISDIR,
            litebox::fs::errors::TruncateError::NotForWriting => Errno::EINVAL,
            litebox::fs::errors::TruncateError::PathOnlyFd => Errno::EBADF,
            litebox::fs::errors::TruncateError::IsTerminalDevice => Errno::EINVAL,
            litebox::fs::errors::TruncateError::ClosedFd => Errno::EBADF,
            litebox::fs::errors::TruncateError::ReadOnlyFileSystem => Errno::EROFS,
            litebox::fs::errors::TruncateError::Io => Errno::EIO,
        }
    }
}

#[cfg(target_arch = "x86_64")]
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
