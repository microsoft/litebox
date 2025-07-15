use thiserror::Error;

mod generated;

/// FreeBSD error numbers
///
/// This is a transparent wrapper around FreeBSD error numbers (i.e., `i32`s) intended
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
    /// # use crate::errno::Errno;
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
