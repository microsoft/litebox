//! Miscellaneous "kitchen sink" for use in various LiteBox crates.
//!
//! Note: while we do not anticipate significant API changes in these utilities, these utilities do
//! not (necessarily) come with the API stability guarantees of the rest of LiteBox's modules. They
//! exist mostly to share utility code that used in the various LiteBox crates, and as such, might
//! be changed if necessary.
// NOTE: There is a separate `utilities` module in this crate meant for crate-internal utilities.

pub mod rng;

/// An extension trait that adds `truncate` to truncate integers to a specific size of the same
/// signedness.
pub trait TruncateExt<To> {
    /// Truncate `self` to `To`, taking only lower-order bits.
    fn truncate(self) -> To;
}

macro_rules! impl_truncate {
    ($from:ty, $to:ty) => {
        impl TruncateExt<$to> for $from {
            #[inline(always)]
            fn truncate(self) -> $to {
                <$to>::from_le_bytes(
                    self.to_le_bytes()[..const { core::mem::size_of::<$to>() }]
                        .try_into()
                        .expect("guaranteed to be optimized out"),
                )
            }
        }
    };
}

impl_truncate! { usize, u32 }
impl_truncate! { usize, u16 }
impl_truncate! { usize, u8 }
impl_truncate! { u128, u64 }
impl_truncate! { u128, u32 }
impl_truncate! { u128, u16 }
impl_truncate! { u128, u8 }
impl_truncate! { u64, u32 }
impl_truncate! { u64, u16 }
impl_truncate! { u64, u8 }
impl_truncate! { u32, u16 }
impl_truncate! { u32, u8 }
impl_truncate! { u16, u8 }

impl_truncate! { isize, i32 }
impl_truncate! { isize, i16 }
impl_truncate! { isize, i8 }
impl_truncate! { i128, i64 }
impl_truncate! { i128, i32 }
impl_truncate! { i128, i16 }
impl_truncate! { i128, i8 }
impl_truncate! { i64, i32 }
impl_truncate! { i64, i16 }
impl_truncate! { i64, i8 }
impl_truncate! { i32, i16 }
impl_truncate! { i32, i8 }
impl_truncate! { i16, i8 }

impl_truncate! { u32, u32 }
impl_truncate! { i32, i32 }

/// An extension trait that adds `reinterpret_as_signed` to unsigned integers.
pub trait ReinterpretSignedExt {
    type Signed;
    /// Reinterpret `self` to `Self::To`
    fn reinterpret_as_signed(self) -> Self::Signed;
}

/// An extension trait that adds `reinterpret_as_unsigned` to signed integers.
pub trait ReinterpretUnsignedExt {
    type Unsigned;
    /// Reinterpret `self` to `Self::To`
    fn reinterpret_as_unsigned(self) -> Self::Unsigned;
}

macro_rules! impl_reinterpret {
    ($unsigned:ty, $signed:ty) => {
        impl ReinterpretSignedExt for $unsigned {
            type Signed = $signed;
            #[inline(always)]
            fn reinterpret_as_signed(self) -> $signed {
                <$signed>::from_ne_bytes(self.to_ne_bytes())
            }
        }
        impl ReinterpretUnsignedExt for $signed {
            type Unsigned = $unsigned;
            #[inline(always)]
            fn reinterpret_as_unsigned(self) -> $unsigned {
                <$unsigned>::from_ne_bytes(self.to_ne_bytes())
            }
        }
    };
}

impl_reinterpret! { usize, isize }
impl_reinterpret! { u128, i128 }
impl_reinterpret! { u64, i64 }
impl_reinterpret! { u32, i32 }
impl_reinterpret! { u16, i16 }
impl_reinterpret! { u8, i8 }
