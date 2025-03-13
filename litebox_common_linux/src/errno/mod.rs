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

mod constants;

/// Linux error numbers
///
/// This is a transparent wrapper around Linux error numbers (i.e., `i32`s) intended
/// to provide some type safety by expecting explicit conversions to/from `i32`s.
///
/// The associated constants for this are generated using:
/// ```sh
/// /usr/bin/errno -l | awk \
///     -e 'function f(n,c,s){print "/// "s "\npub const " n ": Self = Self::from_const(" c ");"}' \
///     -e 'BEGIN{max=0}' \
///     -e '{n=$1; c=$2; $1=""; $2=""; f(n,c,substr($0,3)); max=max>c?max:c;}' \
///     -e 'END{f("MAX",max,"The maximum supported Errno")}'
/// ```
#[derive(PartialEq, Eq, Clone, Copy, Debug, Error)]
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
        // TODO: Update this with a nicer display message based on actual error number constants
        write!(f, "Errno({})", self.value.get())
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

    /// (Private-only) Helper function that makes the associated [`constants`] significantly more
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
