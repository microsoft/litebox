// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Reusable byte codec for broker request/response control-channel messages.
//!
//! The wire codec mirrors the protocol DTO hierarchy:
//! - this module owns public encode/decode entry points and top-level broker
//!   envelope tags;
//! - object-family modules such as `event` own their operation and nested value
//!   tags;
//! - `primitive` owns shared scalar/value encoders.
//!
//! New object families should add a top-level broker message tag and a private
//! family codec module instead of adding flat helpers here. Existing payloads
//! are positional; changing fields is an ABI change, so prefer a new operation
//! tag or explicit negotiated-version gate for payload evolution.

use alloc::vec::Vec;
use thiserror::Error;

use crate::error::ErrorCode;
use crate::message::{
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerOperation,
    BrokerRequest, BrokerResponse, BrokerResult, ReadinessNotification,
};
use crate::readiness::ReadinessFlags;

use primitive::{Decoder, Encoder};

mod event;
mod pipe;
mod primitive;

const REQUEST_TAG_NEGOTIATE: u8 = 0;
const REQUEST_TAG_EVENT: u8 = 1;
const REQUEST_TAG_CLOSE_OBJECT: u8 = 2;
const REQUEST_TAG_PIPE: u8 = 3;
const REQUEST_TAG_CHECK_READINESS: u8 = 4;

const RESPONSE_TAG_NEGOTIATED: u8 = 0;
const RESPONSE_TAG_EVENT: u8 = 1;
const RESPONSE_TAG_HANDSHAKE_ERROR: u8 = 2;
const RESPONSE_TAG_VERSION_MISMATCH: u8 = 3;
const RESPONSE_TAG_OBJECT_CLOSED: u8 = 4;
const RESPONSE_TAG_PIPE: u8 = 5;
const RESPONSE_TAG_READINESS: u8 = 6;
const RESPONSE_TAG_ERROR: u8 = 7;

const NOTIFICATION_TAG_READINESS: u8 = 0;

/// Maximum byte length of any encoded active request or response.
pub const MAX_ENCODED_ACTIVE_MESSAGE_SIZE: usize = 26;

/// Maximum byte length of any encoded broker notification.
pub const MAX_ENCODED_NOTIFICATION_SIZE: usize = 13;

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

/// Encodes a broker handshake request body.
///
/// Successful encodings are always non-empty because the first byte is the
/// message tag.
pub fn encode_handshake_request(request: BrokerHandshakeRequest) -> Vec<u8> {
    let mut encoder = Encoder::default();
    encoder.u8(REQUEST_TAG_NEGOTIATE);
    encoder.protocol_version(request.protocol_version);
    encoder.finish()
}

/// Decodes a broker handshake request body.
pub fn decode_handshake_request(frame: &[u8]) -> Result<BrokerHandshakeRequest, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    let request = match tag {
        REQUEST_TAG_NEGOTIATE => BrokerHandshakeRequest {
            protocol_version: decoder.protocol_version()?,
        },
        REQUEST_TAG_EVENT
        | REQUEST_TAG_CLOSE_OBJECT
        | REQUEST_TAG_PIPE
        | REQUEST_TAG_CHECK_READINESS => {
            return Err(WireError::WrongMessagePhase);
        }
        _ => return Err(WireError::InvalidTag),
    };
    decoder.finish()?;
    Ok(request)
}

/// Encodes a broker request body.
///
/// Successful encodings are always non-empty because the first byte is the
/// message tag.
pub fn encode_request(request: BrokerRequest) -> Vec<u8> {
    let mut encoder = Encoder::default();
    let BrokerRequest {
        request_id,
        operation,
    } = request;
    match operation {
        BrokerOperation::CloseObject(handle) => {
            encoder.u8(REQUEST_TAG_CLOSE_OBJECT);
            encoder.request_id(request_id);
            encoder.handle(handle);
        }
        BrokerOperation::CheckReadiness(handle) => {
            encoder.u8(REQUEST_TAG_CHECK_READINESS);
            encoder.request_id(request_id);
            encoder.handle(handle);
        }
        BrokerOperation::Event(request) => {
            encoder.u8(REQUEST_TAG_EVENT);
            encoder.request_id(request_id);
            event::encode_event_request(&mut encoder, request);
        }
        BrokerOperation::Pipe(request) => {
            encoder.u8(REQUEST_TAG_PIPE);
            encoder.request_id(request_id);
            pipe::encode_pipe_request(&mut encoder, request);
        }
    }
    encoder.finish()
}

/// Decodes a broker request body.
pub fn decode_request(frame: &[u8]) -> Result<BrokerRequest, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    match tag {
        REQUEST_TAG_NEGOTIATE => return Err(WireError::WrongMessagePhase),
        REQUEST_TAG_CLOSE_OBJECT
        | REQUEST_TAG_CHECK_READINESS
        | REQUEST_TAG_EVENT
        | REQUEST_TAG_PIPE => {}
        _ => return Err(WireError::InvalidTag),
    }
    let request_id = decoder.request_id()?;
    let operation = match tag {
        REQUEST_TAG_CLOSE_OBJECT => BrokerOperation::CloseObject(decoder.handle()?),
        REQUEST_TAG_CHECK_READINESS => BrokerOperation::CheckReadiness(decoder.handle()?),
        REQUEST_TAG_EVENT => BrokerOperation::Event(event::decode_event_request(&mut decoder)?),
        REQUEST_TAG_PIPE => BrokerOperation::Pipe(pipe::decode_pipe_request(&mut decoder)?),
        _ => unreachable!("active request tag was validated"),
    };
    decoder.finish()?;
    Ok(BrokerRequest {
        request_id,
        operation,
    })
}

/// Encodes a broker handshake response body.
///
/// Successful encodings are always non-empty because the first byte is the
/// message tag.
pub fn encode_handshake_response(response: BrokerHandshakeResponse) -> Vec<u8> {
    let mut encoder = Encoder::default();
    match response {
        BrokerHandshakeResponse::Negotiated {
            broker_protocol_version,
        } => {
            encoder.u8(RESPONSE_TAG_NEGOTIATED);
            encoder.protocol_version(broker_protocol_version);
        }
        BrokerHandshakeResponse::VersionMismatch {
            broker_protocol_version,
        } => {
            encoder.u8(RESPONSE_TAG_VERSION_MISMATCH);
            encoder.protocol_version(broker_protocol_version);
        }
        BrokerHandshakeResponse::Error(error) => {
            encoder.u8(RESPONSE_TAG_HANDSHAKE_ERROR);
            encoder.u16(error.as_raw());
        }
    }
    encoder.finish()
}

/// Decodes a broker handshake response body.
pub fn decode_handshake_response(frame: &[u8]) -> Result<BrokerHandshakeResponse, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    let response = match tag {
        RESPONSE_TAG_NEGOTIATED => BrokerHandshakeResponse::Negotiated {
            broker_protocol_version: decoder.protocol_version()?,
        },
        RESPONSE_TAG_EVENT
        | RESPONSE_TAG_OBJECT_CLOSED
        | RESPONSE_TAG_PIPE
        | RESPONSE_TAG_READINESS
        | RESPONSE_TAG_ERROR => {
            return Err(WireError::WrongMessagePhase);
        }
        RESPONSE_TAG_VERSION_MISMATCH => BrokerHandshakeResponse::VersionMismatch {
            broker_protocol_version: decoder.protocol_version()?,
        },
        RESPONSE_TAG_HANDSHAKE_ERROR => {
            let error = ErrorCode::from_raw(decoder.u16()?).ok_or(WireError::InvalidTag)?;
            BrokerHandshakeResponse::Error(error)
        }
        _ => return Err(WireError::InvalidTag),
    };
    decoder.finish()?;
    Ok(response)
}

/// Encodes a broker response body.
///
/// Successful encodings are always non-empty because the first byte is the
/// message tag.
pub fn encode_response(response: BrokerResponse) -> Vec<u8> {
    let mut encoder = Encoder::default();
    let BrokerResponse { request_id, result } = response;
    match result {
        BrokerResult::ObjectClosed => {
            encoder.u8(RESPONSE_TAG_OBJECT_CLOSED);
            encoder.request_id(request_id);
        }
        BrokerResult::Readiness(readiness) => {
            encoder.u8(RESPONSE_TAG_READINESS);
            encoder.request_id(request_id);
            encoder.u32(readiness.0);
        }
        BrokerResult::Event(response) => {
            encoder.u8(RESPONSE_TAG_EVENT);
            encoder.request_id(request_id);
            event::encode_event_response(&mut encoder, response);
        }
        BrokerResult::Pipe(response) => {
            encoder.u8(RESPONSE_TAG_PIPE);
            encoder.request_id(request_id);
            pipe::encode_pipe_response(&mut encoder, response);
        }
        BrokerResult::Error(error) => {
            encoder.u8(RESPONSE_TAG_ERROR);
            encoder.request_id(request_id);
            encoder.u16(error.as_raw());
        }
    }
    encoder.finish()
}

/// Decodes a broker response body.
pub fn decode_response(frame: &[u8]) -> Result<BrokerResponse, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    match tag {
        RESPONSE_TAG_NEGOTIATED | RESPONSE_TAG_HANDSHAKE_ERROR | RESPONSE_TAG_VERSION_MISMATCH => {
            return Err(WireError::WrongMessagePhase);
        }
        RESPONSE_TAG_EVENT
        | RESPONSE_TAG_OBJECT_CLOSED
        | RESPONSE_TAG_PIPE
        | RESPONSE_TAG_READINESS
        | RESPONSE_TAG_ERROR => {}
        _ => return Err(WireError::InvalidTag),
    }
    let request_id = decoder.request_id()?;
    let result = match tag {
        RESPONSE_TAG_EVENT => BrokerResult::Event(event::decode_event_response(&mut decoder)?),
        RESPONSE_TAG_PIPE => BrokerResult::Pipe(pipe::decode_pipe_response(&mut decoder)?),
        RESPONSE_TAG_ERROR => {
            let error = ErrorCode::from_raw(decoder.u16()?).ok_or(WireError::InvalidTag)?;
            BrokerResult::Error(error)
        }
        RESPONSE_TAG_OBJECT_CLOSED => BrokerResult::ObjectClosed,
        RESPONSE_TAG_READINESS => BrokerResult::Readiness(ReadinessFlags(decoder.u32()?)),
        _ => unreachable!("active response tag was validated"),
    };
    decoder.finish()?;
    Ok(BrokerResponse { request_id, result })
}

/// Encodes a broker notification body.
///
/// Successful encodings are always non-empty because the first byte is the
/// message tag.
pub fn encode_notification(notification: BrokerNotification) -> Vec<u8> {
    let mut encoder = Encoder::default();
    match notification {
        BrokerNotification::Readiness(notification) => {
            encoder.u8(NOTIFICATION_TAG_READINESS);
            encoder.handle(notification.handle);
            encoder.u32(notification.readiness.0);
        }
    }
    encoder.finish()
}

/// Decodes a broker notification body.
pub fn decode_notification(frame: &[u8]) -> Result<BrokerNotification, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    let notification = match tag {
        NOTIFICATION_TAG_READINESS => BrokerNotification::Readiness(ReadinessNotification {
            handle: decoder.handle()?,
            readiness: ReadinessFlags(decoder.u32()?),
        }),
        _ => return Err(WireError::InvalidTag),
    };
    decoder.finish()?;
    Ok(notification)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{
        AddEventRequest, AddEventResponse, ConsumeEventRequest, CreateEventRequest,
        CreateEventResponse, EventConsumeMode, EventConsumption,
    };
    use crate::message::{EventRequest, EventResponse, PipeRequest, PipeResponse};
    use crate::pipe::{
        CreatePipeRequest, CreatePipeResponse, ReadPipeRequest, ReadPipeResponse, WritePipeRequest,
        WritePipeResponse,
    };
    use crate::shared_memory::{SharedBufferDescriptor, SharedBufferSlotIndex};
    use crate::{ObjectHandle, ProtocolVersion, RequestId};

    const TEST_REQUEST_ID: RequestId = RequestId(0x0102_0304_0506_0708);

    #[test]
    fn handshake_request_codec_round_trips_all_variants() {
        let requests = [BrokerHandshakeRequest {
            protocol_version: ProtocolVersion(1),
        }];

        for request in requests {
            assert_eq!(
                decode_handshake_request(&encode_handshake_request(request.clone())).unwrap(),
                request
            );
        }
    }

    #[test]
    fn request_codec_round_trips_all_variants() {
        let handle = ObjectHandle(13);
        let operations = [
            BrokerOperation::CloseObject(handle),
            BrokerOperation::CheckReadiness(handle),
            BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 0,
            })),
            BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 7,
            })),
            BrokerOperation::Event(EventRequest::Add(AddEventRequest { handle, value: 3 })),
            BrokerOperation::Event(EventRequest::Consume(ConsumeEventRequest {
                handle,
                mode: EventConsumeMode::All,
            })),
            BrokerOperation::Event(EventRequest::Consume(ConsumeEventRequest {
                handle,
                mode: EventConsumeMode::One,
            })),
            BrokerOperation::Pipe(PipeRequest::Create(CreatePipeRequest {
                capacity: 4096,
                atomic_write_size: 512,
            })),
            BrokerOperation::Pipe(PipeRequest::Read(ReadPipeRequest {
                handle,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(2),
                    length: 32,
                },
            })),
            BrokerOperation::Pipe(PipeRequest::Write(WritePipeRequest {
                handle,
                buffer: SharedBufferDescriptor {
                    slot_index: SharedBufferSlotIndex(15),
                    length: 3,
                },
            })),
        ];
        let mut maximum_encoded_size = 0;

        for operation in operations {
            let request = BrokerRequest {
                request_id: TEST_REQUEST_ID,
                operation,
            };
            let encoded = encode_request(request.clone());
            maximum_encoded_size = maximum_encoded_size.max(encoded.len());
            assert!(encoded.len() <= MAX_ENCODED_ACTIVE_MESSAGE_SIZE);
            assert_eq!(decode_request(&encoded).unwrap(), request);
        }
        assert_eq!(maximum_encoded_size, MAX_ENCODED_ACTIVE_MESSAGE_SIZE);
    }

    #[test]
    fn request_codec_round_trips_identifier_bounds() {
        for request_id in [RequestId(0), RequestId(u64::MAX)] {
            let request = BrokerRequest {
                request_id,
                operation: BrokerOperation::CloseObject(ObjectHandle(13)),
            };
            assert_eq!(
                decode_request(&encode_request(request.clone())).unwrap(),
                request
            );
        }
    }

    #[test]
    fn handshake_response_codec_round_trips_all_variants() {
        let responses = [
            BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: ProtocolVersion(1),
            },
            BrokerHandshakeResponse::VersionMismatch {
                broker_protocol_version: ProtocolVersion(1),
            },
            BrokerHandshakeResponse::Error(ErrorCode::PolicyDenied),
            BrokerHandshakeResponse::Error(ErrorCode::Internal),
        ];

        for response in responses {
            assert_eq!(
                decode_handshake_response(&encode_handshake_response(response.clone())).unwrap(),
                response
            );
        }
    }

    #[test]
    fn response_codec_round_trips_all_variants() {
        let handle = ObjectHandle(13);
        let results = [
            BrokerResult::ObjectClosed,
            BrokerResult::Readiness(ReadinessFlags::READ),
            BrokerResult::Readiness(ReadinessFlags::WRITE),
            BrokerResult::Event(EventResponse::Create(CreateEventResponse { handle })),
            BrokerResult::Event(EventResponse::Add(AddEventResponse {
                readiness: ReadinessFlags::READ | ReadinessFlags::WRITE,
            })),
            BrokerResult::Event(EventResponse::Consume(EventConsumption {
                value: 3,
                readiness: ReadinessFlags::WRITE,
            })),
            BrokerResult::Pipe(PipeResponse::Create(CreatePipeResponse {
                read_handle: handle,
                write_handle: ObjectHandle(14),
            })),
            BrokerResult::Pipe(PipeResponse::Read(ReadPipeResponse { read: 3 })),
            BrokerResult::Pipe(PipeResponse::Write(WritePipeResponse { written: 3 })),
            BrokerResult::Error(ErrorCode::PolicyDenied),
            BrokerResult::Error(ErrorCode::WouldBlock),
            BrokerResult::Error(ErrorCode::PeerClosed),
            BrokerResult::Error(ErrorCode::OutOfMemory),
            BrokerResult::Error(ErrorCode::Internal),
        ];
        let mut maximum_encoded_size = 0;

        for result in results {
            let response = BrokerResponse {
                request_id: TEST_REQUEST_ID,
                result,
            };
            let encoded = encode_response(response.clone());
            maximum_encoded_size = maximum_encoded_size.max(encoded.len());
            assert!(encoded.len() <= MAX_ENCODED_ACTIVE_MESSAGE_SIZE);
            assert_eq!(decode_response(&encoded).unwrap(), response);
        }
        assert_eq!(maximum_encoded_size, MAX_ENCODED_ACTIVE_MESSAGE_SIZE);
    }

    #[test]
    fn response_codec_round_trips_identifier_bounds() {
        for request_id in [RequestId(0), RequestId(u64::MAX)] {
            let response = BrokerResponse {
                request_id,
                result: BrokerResult::ObjectClosed,
            };
            assert_eq!(
                decode_response(&encode_response(response.clone())).unwrap(),
                response
            );
        }
    }

    #[test]
    fn notification_codec_round_trips_all_variants() {
        let handle = ObjectHandle(13);
        let notifications = [BrokerNotification::Readiness(ReadinessNotification {
            handle,
            readiness: ReadinessFlags::READ | ReadinessFlags::HANGUP,
        })];
        let mut maximum_encoded_size = 0;

        for notification in notifications {
            let encoded = encode_notification(notification.clone());
            maximum_encoded_size = maximum_encoded_size.max(encoded.len());
            assert!(encoded.len() <= MAX_ENCODED_NOTIFICATION_SIZE);
            assert_eq!(decode_notification(&encoded).unwrap(), notification);
        }
        assert_eq!(maximum_encoded_size, MAX_ENCODED_NOTIFICATION_SIZE);
    }

    #[test]
    fn decode_rejects_malformed_handshake_request_frames() {
        assert_eq!(
            decode_handshake_request(&[0xff, 1, 2, 3]),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            decode_handshake_request(&[0, 1]),
            Err(WireError::TruncatedFrame)
        );
        assert_eq!(
            decode_handshake_request(&encode_request(BrokerRequest {
                request_id: TEST_REQUEST_ID,
                operation: BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                    initial_count: 0,
                })),
            })),
            Err(WireError::WrongMessagePhase)
        );
        assert_eq!(
            decode_handshake_request(&encode_request(BrokerRequest {
                request_id: TEST_REQUEST_ID,
                operation: BrokerOperation::CloseObject(ObjectHandle(13)),
            })),
            Err(WireError::WrongMessagePhase)
        );
        let mut frame = encode_handshake_request(BrokerHandshakeRequest {
            protocol_version: ProtocolVersion(1),
        });
        frame.push(0xff);
        assert_eq!(
            decode_handshake_request(&frame),
            Err(WireError::TrailingBytes)
        );
    }

    #[test]
    fn decode_rejects_malformed_request_frames() {
        assert_eq!(decode_request(&[0xff, 1, 2, 3]), Err(WireError::InvalidTag));
        assert_eq!(
            decode_request(&encode_handshake_request(BrokerHandshakeRequest {
                protocol_version: ProtocolVersion(1),
            })),
            Err(WireError::WrongMessagePhase)
        );
        assert_eq!(
            decode_request(&[REQUEST_TAG_EVENT, 0, 0, 0, 0, 0, 0, 0]),
            Err(WireError::TruncatedFrame)
        );
        let mut unknown_consume_mode = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Event(EventRequest::Consume(ConsumeEventRequest {
                handle: ObjectHandle(13),
                mode: EventConsumeMode::All,
            })),
        });
        *unknown_consume_mode.last_mut().unwrap() = 0xff;
        assert_eq!(
            decode_request(&unknown_consume_mode),
            Err(WireError::InvalidTag)
        );
        let mut frame = encode_request(BrokerRequest {
            request_id: TEST_REQUEST_ID,
            operation: BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 0,
            })),
        });
        frame.push(0xff);
        assert_eq!(decode_request(&frame), Err(WireError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_malformed_handshake_response_frames() {
        assert_eq!(
            decode_handshake_response(&[0xff, 1, 2, 3]),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            decode_handshake_response(&[0, 1]),
            Err(WireError::TruncatedFrame)
        );
        assert_eq!(
            decode_handshake_response(&[2, 0xff, 0xff]),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            decode_handshake_response(&encode_response(BrokerResponse {
                request_id: TEST_REQUEST_ID,
                result: BrokerResult::Event(EventResponse::Create(CreateEventResponse {
                    handle: ObjectHandle(13),
                })),
            })),
            Err(WireError::WrongMessagePhase)
        );
        assert_eq!(
            decode_handshake_response(&encode_response(BrokerResponse {
                request_id: TEST_REQUEST_ID,
                result: BrokerResult::ObjectClosed,
            })),
            Err(WireError::WrongMessagePhase)
        );
        assert_eq!(
            decode_handshake_response(&encode_response(BrokerResponse {
                request_id: TEST_REQUEST_ID,
                result: BrokerResult::Error(ErrorCode::WouldBlock),
            })),
            Err(WireError::WrongMessagePhase)
        );

        let mut frame = encode_handshake_response(BrokerHandshakeResponse::Negotiated {
            broker_protocol_version: ProtocolVersion(1),
        });
        frame.push(0xff);
        assert_eq!(
            decode_handshake_response(&frame),
            Err(WireError::TrailingBytes)
        );
    }

    #[test]
    fn decode_rejects_malformed_response_frames() {
        assert_eq!(
            decode_response(&[0xff, 1, 2, 3]),
            Err(WireError::InvalidTag)
        );
        for response in [
            BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: ProtocolVersion(1),
            },
            BrokerHandshakeResponse::VersionMismatch {
                broker_protocol_version: ProtocolVersion(1),
            },
            BrokerHandshakeResponse::Error(ErrorCode::PolicyDenied),
        ] {
            assert_eq!(
                decode_response(&encode_handshake_response(response)),
                Err(WireError::WrongMessagePhase)
            );
        }
        assert_eq!(
            decode_response(&[RESPONSE_TAG_READINESS, 0xff]),
            Err(WireError::TruncatedFrame)
        );
        let mut invalid_error = Vec::from([RESPONSE_TAG_ERROR]);
        invalid_error.extend_from_slice(&TEST_REQUEST_ID.0.to_le_bytes());
        invalid_error.extend_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(decode_response(&invalid_error), Err(WireError::InvalidTag));

        let truncated = [RESPONSE_TAG_EVENT, 2, 2, 0];
        assert_eq!(decode_response(&truncated), Err(WireError::TruncatedFrame));

        let mut frame = encode_response(BrokerResponse {
            request_id: TEST_REQUEST_ID,
            result: BrokerResult::Event(EventResponse::Add(AddEventResponse {
                readiness: ReadinessFlags::READ | ReadinessFlags::WRITE,
            })),
        });
        frame.push(0xff);
        assert_eq!(decode_response(&frame), Err(WireError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_malformed_notification_frames() {
        assert_eq!(
            decode_notification(&[0xff, 1, 2, 3]),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            decode_notification(&[NOTIFICATION_TAG_READINESS]),
            Err(WireError::TruncatedFrame)
        );

        let mut truncated =
            encode_notification(BrokerNotification::Readiness(ReadinessNotification {
                handle: ObjectHandle(13),
                readiness: ReadinessFlags::READ,
            }));
        truncated.pop();
        assert_eq!(
            decode_notification(&truncated),
            Err(WireError::TruncatedFrame)
        );

        let mut trailing =
            encode_notification(BrokerNotification::Readiness(ReadinessNotification {
                handle: ObjectHandle(13),
                readiness: ReadinessFlags::READ,
            }));
        trailing.push(0xff);
        assert_eq!(
            decode_notification(&trailing),
            Err(WireError::TrailingBytes)
        );
    }

    #[test]
    fn event_create_request_wire_shape_is_pinned() {
        assert_eq!(
            encode_request(BrokerRequest {
                request_id: RequestId(13),
                operation: BrokerOperation::Event(EventRequest::Create(CreateEventRequest {
                    initial_count: 7,
                })),
            }),
            [1, 13, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn event_add_response_wire_shape_is_pinned() {
        assert_eq!(
            encode_response(BrokerResponse {
                request_id: RequestId(13),
                result: BrokerResult::Event(EventResponse::Add(AddEventResponse {
                    readiness: ReadinessFlags::READ,
                })),
            }),
            [1, 13, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0]
        );
    }

    #[test]
    fn readiness_notification_wire_shape_is_pinned() {
        assert_eq!(
            encode_notification(BrokerNotification::Readiness(ReadinessNotification {
                handle: ObjectHandle(13),
                readiness: ReadinessFlags::READ | ReadinessFlags::HANGUP,
            })),
            [0, 13, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0]
        );
    }
}
