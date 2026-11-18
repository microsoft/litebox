// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Macros that define protocol DTOs together with their wire codecs.

macro_rules! wire_struct {
    (
        $(#[$attribute:meta])* $visibility:vis struct $name:ident {
            $($(#[$field_attribute:meta])* $field_visibility:vis $field:ident: $ty:ty),* $(,)?
        }
        $(validate |$value:ident| $check:expr)?
    ) => {
        $(#[$attribute])*
        $visibility struct $name {
            $($(#[$field_attribute])* $field_visibility $field: $ty),*
        }

        impl $crate::wire::Wire for $name {
            const MAX_SIZE: usize = 0 $(+ <$ty as $crate::wire::Wire>::MAX_SIZE)*;

            fn encode(&self, encoder: &mut $crate::wire::Encoder) {
                let Self { $($field),* } = self;
                $(<$ty as $crate::wire::Wire>::encode($field, encoder);)*
            }

            fn decode(decoder: &mut $crate::wire::Decoder<'_>) -> Result<Self, $crate::wire::WireError> {
                let value = Self { $($field: <$ty as $crate::wire::Wire>::decode(decoder)?),* };
                $(if !{ let $value = &value; $check } {
                    return Err($crate::wire::WireError::InvalidTag);
                })?
                Ok(value)
            }
        }
    };
}

macro_rules! wire_enum {
    (@impl $name:ident {
        $($variant:ident $(($item:ident: $ty:ty))? $({$($field:ident: $field_ty:ty),*})?),* $(,)?
    }) => {
        impl $crate::wire::Wire for $name {
            const MAX_SIZE: usize = 1 + $crate::wire::max_size(&[
                $(0 $(+ <$ty as $crate::wire::Wire>::MAX_SIZE)? $($(+ <$field_ty as $crate::wire::Wire>::MAX_SIZE)*)?),*
            ]);

            fn encode(&self, encoder: &mut $crate::wire::Encoder) {
                #[allow(clippy::enum_variant_names)]
                #[repr(u8)]
                enum Tag { $($variant),* }
                match self {
                    $(Self::$variant $(($item))? $({$($field),*})? => {
                        <u8 as $crate::wire::Wire>::encode(&(Tag::$variant as u8), encoder);
                        $(<$ty as $crate::wire::Wire>::encode($item, encoder);)?
                        $($(<$field_ty as $crate::wire::Wire>::encode($field, encoder);)*)?
                    }),*
                }
            }

            fn decode(decoder: &mut $crate::wire::Decoder<'_>) -> Result<Self, $crate::wire::WireError> {
                #[allow(clippy::enum_variant_names)]
                #[repr(u8)]
                enum Tag { $($variant),* }
                const TAGS: &[Tag] = &[$(Tag::$variant),*];
                let tag = TAGS.get(usize::from(<u8 as $crate::wire::Wire>::decode(decoder)?))
                    .ok_or($crate::wire::WireError::InvalidTag)?;
                Ok(match tag {
                    $(Tag::$variant => Self::$variant
                        $((<$ty as $crate::wire::Wire>::decode(decoder)?))?
                        $({$($field: <$field_ty as $crate::wire::Wire>::decode(decoder)?),*})?
                    ),*
                })
            }
        }
    };
    (
        $(#[$attribute:meta])* $visibility:vis enum $name:ident {
            $(
                $(#[$variant_attribute:meta])* $variant:ident $(($ty:ty))?
                $({$($(#[$field_attribute:meta])* $field:ident: $field_ty:ty),* $(,)?})?
            ),* $(,)?
        }
    ) => {
        $(#[$attribute])*
        $visibility enum $name {
            $(
                $(#[$variant_attribute])* $variant $(($ty))?
                $({$($(#[$field_attribute])* $field: $field_ty),*})?
            ),*
        }

        wire_enum!(@impl $name {
            $($variant $((value: $ty))? $({$($field: $field_ty),*})?),*
        });
    };
}

macro_rules! wire_newtype {
    ($name:ident: $ty:ty) => {
        impl $crate::wire::Wire for $name {
            const MAX_SIZE: usize = <$ty as $crate::wire::Wire>::MAX_SIZE;

            fn encode(&self, encoder: &mut $crate::wire::Encoder) {
                <$ty as $crate::wire::Wire>::encode(&self.0, encoder);
            }

            fn decode(
                decoder: &mut $crate::wire::Decoder<'_>,
            ) -> Result<Self, $crate::wire::WireError> {
                Ok(Self(<$ty as $crate::wire::Wire>::decode(decoder)?))
            }
        }
    };
}

macro_rules! wire_flags {
    ($name:ident: $ty:ty) => {
        impl $crate::wire::Wire for $name {
            const MAX_SIZE: usize = <$ty as $crate::wire::Wire>::MAX_SIZE;

            fn encode(&self, encoder: &mut $crate::wire::Encoder) {
                <$ty as $crate::wire::Wire>::encode(&self.bits(), encoder);
            }

            fn decode(
                decoder: &mut $crate::wire::Decoder<'_>,
            ) -> Result<Self, $crate::wire::WireError> {
                Self::from_bits(<$ty as $crate::wire::Wire>::decode(decoder)?)
                    .ok_or($crate::wire::WireError::InvalidTag)
            }
        }
    };
}
