// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::num::NonZeroU64;
use core::time::Duration;

use crate::readiness::ReadinessFlags;
use crate::shared_buffer::{
    MAX_SHARED_BUFFER_SEQUENCE_SLOTS, SharedBufferSequence, SharedBufferSlotIndex,
};
use crate::{
    ObjectHandle, ProcessGroupId, ProcessId, ProtocolVersion, RequestId, SessionId,
    SharedObjectToken, ThreadId,
};

use super::{Wire, WireError};

#[derive(Default)]
pub(crate) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }
}

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn finish(&self) -> Result<(), WireError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }

    /// Bytes not yet decoded.
    pub(super) fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(WireError::OffsetOverflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(WireError::TruncatedFrame)?;
        let mut value = [0; N];
        value.copy_from_slice(bytes);
        self.offset = end;
        Ok(value)
    }
}

macro_rules! wire_integer {
    ($($ty:ty),* $(,)?) => {$(
        impl Wire for $ty {
            const MAX_SIZE: usize = core::mem::size_of::<Self>();

            fn encode(&self, encoder: &mut Encoder) {
                encoder.bytes(&self.to_le_bytes());
            }

            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
                Ok(Self::from_le_bytes(decoder.bytes()?))
            }
        }
    )*};
}

wire_integer!(u8, u16, u32, u64, u128, i64);

impl<const N: usize> Wire for [u8; N] {
    const MAX_SIZE: usize = N;

    fn encode(&self, encoder: &mut Encoder) {
        encoder.bytes(self);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        decoder.bytes()
    }
}

impl Wire for bool {
    const MAX_SIZE: usize = 1;

    fn encode(&self, encoder: &mut Encoder) {
        u8::from(*self).encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        match u8::decode(decoder)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::InvalidTag),
        }
    }
}

impl<T: Wire> Wire for Option<T> {
    const MAX_SIZE: usize = 1 + T::MAX_SIZE;

    fn encode(&self, encoder: &mut Encoder) {
        self.is_some().encode(encoder);
        if let Some(value) = self {
            value.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        if bool::decode(decoder)? {
            T::decode(decoder).map(Some)
        } else {
            Ok(None)
        }
    }
}

wire_newtype!(ProtocolVersion: u16);
wire_newtype!(ObjectHandle: u64);
wire_newtype!(RequestId: u64);
wire_newtype!(SharedObjectToken: u64);
wire_newtype!(ProcessId: u32);
wire_newtype!(ThreadId: u32);
wire_newtype!(ProcessGroupId: u32);
wire_newtype!(SessionId: u32);
wire_newtype!(SharedBufferSlotIndex: u32);
wire_newtype!(ReadinessFlags: u32);

impl Wire for NonZeroU64 {
    const MAX_SIZE: usize = u64::MAX_SIZE;

    fn encode(&self, encoder: &mut Encoder) {
        self.get().encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        Self::new(u64::decode(decoder)?).ok_or(WireError::InvalidTag)
    }
}

impl Wire for SharedBufferSequence {
    const MAX_SIZE: usize = 1 + MAX_SHARED_BUFFER_SEQUENCE_SLOTS * u32::MAX_SIZE + u32::MAX_SIZE;

    fn encode(&self, encoder: &mut Encoder) {
        // The constructor bounds the count to MAX_SHARED_BUFFER_SEQUENCE_SLOTS (16).
        #[expect(clippy::cast_possible_truncation)]
        let count = self.slot_indices().len() as u8;
        count.encode(encoder);
        for slot in self.slot_indices() {
            slot.encode(encoder);
        }
        self.length().encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        let count = usize::from(u8::decode(decoder)?);
        let mut slots = [SharedBufferSlotIndex::default(); MAX_SHARED_BUFFER_SEQUENCE_SLOTS];
        let slots = slots.get_mut(..count).ok_or(WireError::InvalidTag)?;
        for slot in &mut *slots {
            *slot = SharedBufferSlotIndex::decode(decoder)?;
        }
        Self::new(slots, u32::decode(decoder)?).map_err(|_| WireError::InvalidTag)
    }
}

impl Wire for Duration {
    const MAX_SIZE: usize = u64::MAX_SIZE + u32::MAX_SIZE;

    fn encode(&self, encoder: &mut Encoder) {
        self.as_secs().encode(encoder);
        self.subsec_nanos().encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        let seconds = u64::decode(decoder)?;
        let nanoseconds = u32::decode(decoder)?;
        if nanoseconds >= 1_000_000_000 {
            return Err(WireError::InvalidTag);
        }
        Ok(Self::new(seconds, nanoseconds))
    }
}

impl Wire for SocketAddrV4 {
    const MAX_SIZE: usize = 4 + u16::MAX_SIZE;

    fn encode(&self, encoder: &mut Encoder) {
        self.ip().octets().encode(encoder);
        self.port().encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        let ip = Ipv4Addr::from(<[u8; 4]>::decode(decoder)?);
        Ok(Self::new(ip, u16::decode(decoder)?))
    }
}
