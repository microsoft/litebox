// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Positional, little-endian broker control-channel codec, without padding.
//!
//! Family DTO modules declare types and their wire layouts together. This module
//! keeps framing and the per-family codecs for special values and bitflags.
//! Enum tags are zero-based declaration ordinals; options use a strict boolean
//! followed by the value only when present. Handshake and active frames start
//! with distinct phase bytes. Notifications have their own channel and no phase.

use alloc::vec::Vec;
use thiserror::Error;

use crate::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
    BrokerResponse,
};

pub(crate) use primitive::{Decoder, Encoder};

mod fs;
mod primitive;
mod process;
mod readiness_queue;
mod shared_futex;
mod socket;
mod terminal;
mod vsock_socket;

// Leading phase byte lets handshake/active enums reuse tag spaces and rejects wrong-phase frames before decoding the body.
const HANDSHAKE_PHASE: u8 = 0;
const ACTIVE_PHASE: u8 = 1;

/// Maximum byte length of any encoded active request or response.
pub const MAX_ENCODED_ACTIVE_MESSAGE_SIZE: usize =
    1 + max_size(&[BrokerRequest::MAX_SIZE, BrokerResponse::MAX_SIZE]);

/// Maximum byte length of any encoded broker notification.
pub const MAX_ENCODED_NOTIFICATION_SIZE: usize = BrokerNotification::MAX_SIZE;

/// Error produced while encoding or decoding a broker wire message.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    #[error("truncated broker wire frame")]
    TruncatedFrame,
    #[error("trailing broker wire bytes")]
    TrailingBytes,
    #[error("invalid broker wire tag")]
    InvalidTag,
    #[error("broker wire message is not valid in this protocol phase")]
    WrongMessagePhase,
    #[error("broker wire offset overflow")]
    OffsetOverflow,
}

pub(crate) trait Wire: Sized {
    const MAX_SIZE: usize;

    fn encode(&self, encoder: &mut Encoder);
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError>;
}

pub(crate) const fn max_size(sizes: &[usize]) -> usize {
    let mut maximum = 0;
    let mut remaining = sizes;
    while let Some((&size, rest)) = remaining.split_first() {
        maximum = if size > maximum { size } else { maximum };
        remaining = rest;
    }
    maximum
}

fn encode_frame<T: Wire>(phase: u8, value: &T) -> Vec<u8> {
    let mut encoder = Encoder::default();
    phase.encode(&mut encoder);
    value.encode(&mut encoder);
    encoder.finish()
}

fn decode_frame<T: Wire>(frame: &[u8], expected_phase: u8) -> Result<T, WireError> {
    let mut decoder = Decoder::new(frame);
    match u8::decode(&mut decoder)? {
        phase if phase == expected_phase => {}
        HANDSHAKE_PHASE | ACTIVE_PHASE => return Err(WireError::WrongMessagePhase),
        _ => return Err(WireError::InvalidTag),
    }
    let value = T::decode(&mut decoder)?;
    decoder.finish()?;
    Ok(value)
}

/// Encodes a broker handshake request body, including its non-empty phase tag.
pub fn encode_handshake_request(request: &BrokerHandshakeRequest) -> Vec<u8> {
    encode_frame(HANDSHAKE_PHASE, request)
}

/// Decodes a broker handshake request body.
pub fn decode_handshake_request(frame: &[u8]) -> Result<BrokerHandshakeRequest, WireError> {
    decode_frame(frame, HANDSHAKE_PHASE)
}

/// Encodes a broker request body, including its non-empty phase tag.
pub fn encode_request(request: &BrokerRequest) -> Vec<u8> {
    encode_frame(ACTIVE_PHASE, request)
}

/// Decodes a broker request body.
pub fn decode_request(frame: &[u8]) -> Result<BrokerRequest, WireError> {
    decode_frame(frame, ACTIVE_PHASE)
}

/// Encodes a broker handshake response body, including its non-empty phase tag.
pub fn encode_handshake_response(response: &BrokerHandshakeResponse) -> Vec<u8> {
    encode_frame(HANDSHAKE_PHASE, response)
}

/// Decodes a broker handshake response body.
pub fn decode_handshake_response(frame: &[u8]) -> Result<BrokerHandshakeResponse, WireError> {
    decode_frame(frame, HANDSHAKE_PHASE)
}

/// Encodes a broker response body, including its non-empty phase tag.
pub fn encode_response(response: &BrokerResponse) -> Vec<u8> {
    encode_frame(ACTIVE_PHASE, response)
}

/// Decodes a broker response body.
pub fn decode_response(frame: &[u8]) -> Result<BrokerResponse, WireError> {
    decode_frame(frame, ACTIVE_PHASE)
}

/// Encodes a broker notification body, including its non-empty enum tag.
pub fn encode_notification(notification: &BrokerNotification) -> Vec<u8> {
    let mut encoder = Encoder::default();
    notification.encode(&mut encoder);
    encoder.finish()
}

/// Decodes a broker notification body.
pub fn decode_notification(frame: &[u8]) -> Result<BrokerNotification, WireError> {
    let mut decoder = Decoder::new(frame);
    let notification = BrokerNotification::decode(&mut decoder)?;
    decoder.finish()?;
    Ok(notification)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[test]
fn fs_mount_wire_shape_is_pinned() {
    use crate::RequestId;
    use crate::fs::{FileUser, MountFileRequest};
    use crate::message::{BrokerOperation, BrokerResult, FileRequest, FileResponse};
    use crate::shared_buffer::{SharedBufferSequence, SharedBufferSlotIndex};

    let request = BrokerRequest {
        request_id: RequestId(13),
        operation: BrokerOperation::File(FileRequest::Mount(MountFileRequest {
            path: SharedBufferSequence::new(&[SharedBufferSlotIndex(2)], 3).unwrap(),
            user: FileUser { user: 5, group: 7 },
        })),
    };
    let encoded = encode_request(&request);
    assert_eq!(
        encoded,
        [
            1, 13, 0, 0, 0, 0, 0, 0, 0, 9, 23, 1, 2, 0, 0, 0, 3, 0, 0, 0, 5, 0, 7, 0
        ]
    );
    assert_eq!(decode_request(&encoded).unwrap(), request);
    for length in 0..encoded.len() {
        assert_eq!(
            decode_request(&encoded[..length]),
            Err(WireError::TruncatedFrame)
        );
    }

    let response = BrokerResponse {
        request_id: RequestId(13),
        result: BrokerResult::File(FileResponse::Mount),
    };
    let encoded = encode_response(&response);
    assert_eq!(encoded, [1, 13, 0, 0, 0, 0, 0, 0, 0, 9, 24]);
    assert_eq!(decode_response(&encoded).unwrap(), response);
}
