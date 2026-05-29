// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Reusable byte codec for broker request/response control-channel messages.

#![no_std]

extern crate alloc;

use core::fmt;

use alloc::vec::Vec;
use litebox_broker_protocol::{
    BrokerRequest, BrokerResponse, ErrorCode, ObjectGeneration, ObjectHandle, ObjectId,
    ObjectReferenceGeneration, ObjectReferenceId, ProtocolVersion, ReadinessState, WaitOutcome,
};
use litebox_broker_transport::{ReceivedRequest, ReceivedResponse};

const REQUEST_TAG_NEGOTIATE: u8 = 0;
const REQUEST_TAG_CREATE_EVENT: u8 = 1;
const REQUEST_TAG_WAIT_EVENT: u8 = 2;
const REQUEST_TAG_SIGNAL_EVENT: u8 = 3;

const RESPONSE_TAG_NEGOTIATED: u8 = 0;
const RESPONSE_TAG_HANDLE: u8 = 1;
const RESPONSE_TAG_READINESS: u8 = 2;
const RESPONSE_TAG_WAIT: u8 = 3;
const RESPONSE_TAG_ERROR: u8 = 4;
const RESPONSE_TAG_VERSION_MISMATCH: u8 = 5;

const WAIT_OUTCOME_TAG_READY: u8 = 1;
const WAIT_OUTCOME_TAG_WOULD_BLOCK: u8 = 2;

/// Error produced while encoding or decoding a broker wire message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    /// The encoder was asked to emit a request tag this codec does not own.
    EncodeUnknownRequestTag,
    /// The encoder was asked to emit a response tag this codec does not own.
    EncodeUnknownResponseTag,
    /// The encoder was asked to emit a wait-outcome tag this codec does not own.
    EncodeUnknownWaitOutcome,
    /// The frame ended before a complete field could be decoded.
    TruncatedFrame,
    /// The frame contained bytes after the decoded message.
    TrailingBytes,
    /// A boolean field was not encoded as 0 or 1.
    InvalidBoolean,
    /// The wait-outcome tag is unknown.
    UnknownWaitOutcome,
    /// A decoder offset overflowed.
    OffsetOverflow,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedFrame => f.write_str("truncated broker wire frame"),
            Self::EncodeUnknownRequestTag => {
                f.write_str("cannot encode unknown broker request tag")
            }
            Self::EncodeUnknownResponseTag => {
                f.write_str("cannot encode unknown broker response tag")
            }
            Self::EncodeUnknownWaitOutcome => {
                f.write_str("cannot encode unknown broker wait outcome tag")
            }
            Self::TrailingBytes => f.write_str("trailing broker wire bytes"),
            Self::InvalidBoolean => f.write_str("invalid broker wire boolean"),
            Self::UnknownWaitOutcome => f.write_str("unknown broker wait outcome"),
            Self::OffsetOverflow => f.write_str("broker wire offset overflow"),
        }
    }
}

impl core::error::Error for WireError {}

/// Encodes a broker request body.
///
/// Successful encodings are always non-empty because the first byte is the
/// message tag.
pub fn encode_request(request: BrokerRequest) -> Result<Vec<u8>, WireError> {
    let mut encoder = Encoder::default();
    match request {
        BrokerRequest::Negotiate { protocol_version } => {
            encoder.u8(REQUEST_TAG_NEGOTIATE);
            encoder.u16(protocol_version.major);
            encoder.u16(protocol_version.minor);
        }
        BrokerRequest::CreateEvent => {
            encoder.u8(REQUEST_TAG_CREATE_EVENT);
        }
        BrokerRequest::WaitEvent { handle } => {
            encoder.u8(REQUEST_TAG_WAIT_EVENT);
            encoder.handle(handle);
        }
        BrokerRequest::SignalEvent { handle } => {
            encoder.u8(REQUEST_TAG_SIGNAL_EVENT);
            encoder.handle(handle);
        }
        _ => return Err(WireError::EncodeUnknownRequestTag),
    }
    Ok(encoder.finish())
}

/// Decodes a broker request body.
pub fn decode_request(frame: &[u8]) -> Result<ReceivedRequest, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    let request = match tag {
        REQUEST_TAG_NEGOTIATE => BrokerRequest::Negotiate {
            protocol_version: ProtocolVersion::new(decoder.u16()?, decoder.u16()?),
        },
        REQUEST_TAG_CREATE_EVENT => BrokerRequest::CreateEvent,
        REQUEST_TAG_WAIT_EVENT => BrokerRequest::WaitEvent {
            handle: decoder.handle()?,
        },
        REQUEST_TAG_SIGNAL_EVENT => BrokerRequest::SignalEvent {
            handle: decoder.handle()?,
        },
        _ => return Ok(ReceivedRequest::Unknown),
    };
    decoder.finish()?;
    Ok(ReceivedRequest::Request(request))
}

/// Encodes a broker response body.
///
/// Successful encodings are always non-empty because the first byte is the
/// message tag.
pub fn encode_response(response: BrokerResponse) -> Result<Vec<u8>, WireError> {
    let mut encoder = Encoder::default();
    match response {
        BrokerResponse::Negotiated {
            broker_protocol_version,
        } => {
            encoder.u8(RESPONSE_TAG_NEGOTIATED);
            encoder.u16(broker_protocol_version.major);
            encoder.u16(broker_protocol_version.minor);
        }
        BrokerResponse::VersionMismatch {
            broker_protocol_version,
        } => {
            encoder.u8(RESPONSE_TAG_VERSION_MISMATCH);
            encoder.u16(broker_protocol_version.major);
            encoder.u16(broker_protocol_version.minor);
        }
        BrokerResponse::Handle(handle) => {
            encoder.u8(RESPONSE_TAG_HANDLE);
            encoder.handle(handle);
        }
        BrokerResponse::Readiness(readiness) => {
            encoder.u8(RESPONSE_TAG_READINESS);
            encoder.readiness(readiness);
        }
        BrokerResponse::Wait(outcome) => {
            encoder.u8(RESPONSE_TAG_WAIT);
            match outcome {
                WaitOutcome::Ready(readiness) => {
                    encoder.u8(WAIT_OUTCOME_TAG_READY);
                    encoder.readiness(readiness);
                }
                WaitOutcome::WouldBlock(readiness) => {
                    encoder.u8(WAIT_OUTCOME_TAG_WOULD_BLOCK);
                    encoder.readiness(readiness);
                }
                _ => return Err(WireError::EncodeUnknownWaitOutcome),
            }
        }
        BrokerResponse::Error(error) => {
            encoder.u8(RESPONSE_TAG_ERROR);
            encoder.u16(error.as_raw());
        }
        _ => return Err(WireError::EncodeUnknownResponseTag),
    }
    Ok(encoder.finish())
}

/// Decodes a broker response body.
pub fn decode_response(frame: &[u8]) -> Result<ReceivedResponse, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    let response = match tag {
        RESPONSE_TAG_NEGOTIATED => BrokerResponse::Negotiated {
            broker_protocol_version: ProtocolVersion::new(decoder.u16()?, decoder.u16()?),
        },
        RESPONSE_TAG_VERSION_MISMATCH => BrokerResponse::VersionMismatch {
            broker_protocol_version: ProtocolVersion::new(decoder.u16()?, decoder.u16()?),
        },
        RESPONSE_TAG_HANDLE => BrokerResponse::Handle(decoder.handle()?),
        RESPONSE_TAG_READINESS => BrokerResponse::Readiness(decoder.readiness()?),
        RESPONSE_TAG_WAIT => {
            let outcome = match decoder.u8()? {
                WAIT_OUTCOME_TAG_READY => WaitOutcome::Ready(decoder.readiness()?),
                WAIT_OUTCOME_TAG_WOULD_BLOCK => WaitOutcome::WouldBlock(decoder.readiness()?),
                _ => return Err(WireError::UnknownWaitOutcome),
            };
            BrokerResponse::Wait(outcome)
        }
        RESPONSE_TAG_ERROR => {
            let error = ErrorCode::from_raw(decoder.u16()?);
            BrokerResponse::Error(error)
        }
        _ => return Ok(ReceivedResponse::Unknown),
    };
    decoder.finish()?;
    Ok(ReceivedResponse::Response(response))
}

#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn handle(&mut self, handle: ObjectHandle) {
        self.u64(handle.object_id.get());
        self.u64(handle.object_generation.get());
        self.u64(handle.reference_id.get());
        self.u64(handle.reference_generation.get());
    }

    fn readiness(&mut self, readiness: ReadinessState) {
        self.bool(readiness.ready);
        self.u64(readiness.generation);
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn finish(&self) -> Result<(), WireError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }

    fn bool(&mut self) -> Result<bool, WireError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::InvalidBoolean),
        }
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        let bytes = self.take(1)?;
        Ok(bytes[0])
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn handle(&mut self) -> Result<ObjectHandle, WireError> {
        let object_id = ObjectId::new(self.u64()?);
        let object_generation = ObjectGeneration::new(self.u64()?);
        let reference_id = ObjectReferenceId::new(self.u64()?);
        let reference_generation = ObjectReferenceGeneration::new(self.u64()?);

        Ok(ObjectHandle::new(
            object_id,
            object_generation,
            reference_id,
            reference_generation,
        ))
    }

    fn readiness(&mut self) -> Result<ReadinessState, WireError> {
        Ok(ReadinessState::new(self.bool()?, self.u64()?))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(WireError::OffsetOverflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(WireError::TruncatedFrame)?;
        self.offset = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_codec_round_trips_all_variants() {
        let handle = sample_handle();
        let requests = [
            BrokerRequest::Negotiate {
                protocol_version: ProtocolVersion::new(1, 0),
            },
            BrokerRequest::CreateEvent,
            BrokerRequest::WaitEvent { handle },
            BrokerRequest::SignalEvent { handle },
        ];

        for request in requests {
            assert_eq!(
                decode_request(&encode_request(request).unwrap()).unwrap(),
                ReceivedRequest::Request(request)
            );
        }
    }

    #[test]
    fn response_codec_round_trips_all_variants() {
        let handle = sample_handle();
        let responses = [
            BrokerResponse::Negotiated {
                broker_protocol_version: ProtocolVersion::new(1, 0),
            },
            BrokerResponse::VersionMismatch {
                broker_protocol_version: ProtocolVersion::new(1, 0),
            },
            BrokerResponse::Handle(handle),
            BrokerResponse::Readiness(ReadinessState::new(false, 7)),
            BrokerResponse::Wait(WaitOutcome::Ready(ReadinessState::new(true, 8))),
            BrokerResponse::Wait(WaitOutcome::WouldBlock(ReadinessState::new(false, 9))),
            BrokerResponse::Error(ErrorCode::PolicyDenied),
            BrokerResponse::Error(ErrorCode::Internal),
        ];

        for response in responses {
            assert_eq!(
                decode_response(&encode_response(response).unwrap()).unwrap(),
                ReceivedResponse::Response(response)
            );
        }
    }

    #[test]
    fn decode_rejects_malformed_request_frames() {
        assert_eq!(
            decode_request(&[0xff, 1, 2, 3]),
            Ok(ReceivedRequest::Unknown)
        );
        assert_eq!(decode_request(&[0, 1]), Err(WireError::TruncatedFrame));
        let mut frame = encode_request(BrokerRequest::CreateEvent).unwrap();
        frame.push(0xff);
        assert_eq!(decode_request(&frame), Err(WireError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_malformed_response_frames() {
        assert_eq!(
            decode_response(&[0xff, 1, 2, 3]),
            Ok(ReceivedResponse::Unknown)
        );
        assert_eq!(
            decode_response(&[3, 0xff]),
            Err(WireError::UnknownWaitOutcome)
        );
        assert_eq!(
            decode_response(&[4, 0xff, 0xff]),
            Ok(ReceivedResponse::Response(BrokerResponse::Error(
                ErrorCode::Unknown(0xffff)
            )))
        );

        let mut invalid_bool = [2, 2, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            decode_response(&invalid_bool),
            Err(WireError::InvalidBoolean)
        );

        invalid_bool[1] = 1;
        invalid_bool[9] = 1;
        let mut frame = invalid_bool.to_vec();
        frame.push(0xff);
        assert_eq!(decode_response(&frame), Err(WireError::TrailingBytes));
    }

    #[test]
    fn readiness_response_wire_shape_is_pinned() {
        assert_eq!(
            encode_response(BrokerResponse::Readiness(ReadinessState::new(
                true,
                0x0102_0304_0506_0708
            )))
            .unwrap(),
            [2, 1, 8, 7, 6, 5, 4, 3, 2, 1]
        );
    }

    const fn sample_handle() -> ObjectHandle {
        ObjectHandle::new(
            ObjectId::new(11),
            ObjectGeneration::new(12),
            ObjectReferenceId::new(13),
            ObjectReferenceGeneration::new(14),
        )
    }
}
