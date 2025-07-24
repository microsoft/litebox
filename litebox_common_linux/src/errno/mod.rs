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
            litebox::fs::errors::OpenError::NoWritePerms => Errno::EACCES,
            litebox::fs::errors::OpenError::PathError(path_error) => path_error.into(),
            litebox::fs::errors::OpenError::ReadOnlyFileSystem => Errno::EROFS,
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

impl From<litebox::fs::errors::ReadError> for Errno {
    fn from(value: litebox::fs::errors::ReadError) -> Self {
        match value {
            litebox::fs::errors::ReadError::NotAFile => Errno::EISDIR,
            litebox::fs::errors::ReadError::NotForReading => Errno::EACCES,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::fs::errors::WriteError> for Errno {
    fn from(value: litebox::fs::errors::WriteError) -> Self {
        match value {
            litebox::fs::errors::WriteError::NotAFile => Errno::EISDIR,
            litebox::fs::errors::WriteError::NotForWriting => Errno::EACCES,
            _ => unimplemented!(),
        }
    }
}

impl From<litebox::platform::page_mgmt::AllocationError> for Errno {
    fn from(value: litebox::platform::page_mgmt::AllocationError) -> Self {
        match value {
            litebox::platform::page_mgmt::AllocationError::Unaligned => Errno::EINVAL,
            litebox::platform::page_mgmt::AllocationError::AlreadyAllocated => Errno::EINVAL,
            litebox::platform::page_mgmt::AllocationError::OutOfMemory => Errno::ENOMEM,
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

impl From<litebox::mm::linux::VmemUnmapError> for Errno {
    fn from(value: litebox::mm::linux::VmemUnmapError) -> Self {
        match value {
            litebox::mm::linux::VmemUnmapError::UnAligned => Errno::EINVAL,
            litebox::mm::linux::VmemUnmapError::UnmapError(e) => e.into(),
        }
    }
}

impl From<litebox::mm::linux::MappingError> for Errno {
    fn from(value: litebox::mm::linux::MappingError) -> Self {
        match value {
            litebox::mm::linux::MappingError::UnAligned => Errno::EINVAL,
            litebox::mm::linux::MappingError::OutOfMemory => Errno::ENOMEM,
            litebox::mm::linux::MappingError::BadFD(_) => Errno::EBADF,
            litebox::mm::linux::MappingError::NotAFile => Errno::EISDIR,
            litebox::mm::linux::MappingError::NotForReading => Errno::EACCES,
            litebox::mm::linux::MappingError::MapError(e) => e.into(),
            _ => unimplemented!(),
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

impl From<litebox::mm::linux::VmemProtectError> for Errno {
    fn from(value: litebox::mm::linux::VmemProtectError) -> Self {
        match value {
            litebox::mm::linux::VmemProtectError::UnAligned(_) => Errno::EINVAL,
            litebox::mm::linux::VmemProtectError::InvalidRange(_) => Errno::ENOMEM,
            litebox::mm::linux::VmemProtectError::NoAccess { .. } => Errno::EACCES,
            litebox::mm::linux::VmemProtectError::ProtectError(e) => e.into(),
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
            litebox::fs::errors::FileStatusError::PathError(path_error) => path_error.into(),
            _ => unimplemented!(),
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

impl From<litebox::net::errors::SendError> for Errno {
    fn from(value: litebox::net::errors::SendError) -> Self {
        match value {
            litebox::net::errors::SendError::InvalidFd => Errno::EBADF,
            litebox::net::errors::SendError::SocketInInvalidState => Errno::ENOTCONN,
            _ => unimplemented!(),
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

impl From<litebox::event::polling::TryOpError<Errno>> for Errno {
    fn from(value: litebox::event::polling::TryOpError<Errno>) -> Self {
        match value {
            litebox::event::polling::TryOpError::TryAgain => Errno::EAGAIN,
            litebox::event::polling::TryOpError::TimedOut => Errno::ETIMEDOUT,
            litebox::event::polling::TryOpError::Other(e) => e,
        }
    }
}
