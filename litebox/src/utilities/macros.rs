// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/// Define a `#[repr($int_ty)]` enum and auto-generate a typed conversion method.
///
/// # Example
/// ```ignore
/// repr_enum! {
///     #[derive(Copy, Clone, Debug)]
///     enum Color: u8, from_u8 {
///         Red   = 1,
///         Green = 2,
///         Blue  = 3,
///     }
/// }
/// assert_eq!(Color::from_u8(2), Some(Color::Green));
/// ```
macro_rules! repr_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident : $int_ty:ty, $from_fn:ident {
            $(
                $(#[$vmeta:meta])*
                $variant:ident = $value:expr
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[repr($int_ty)]
        $vis enum $name {
            $(
                $(#[$vmeta])*
                $variant = $value,
            )*
        }

        impl $name {
            /// Convert a raw integer to the enum, returning `None` for unknown values.
            $vis fn $from_fn(v: $int_ty) -> Option<Self> {
                match v {
                    $( $value => Some(Self::$variant), )*
                    _ => None,
                }
            }
        }
    };
}
pub(crate) use repr_enum;
