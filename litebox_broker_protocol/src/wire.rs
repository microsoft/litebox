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
    BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
    BrokerResponse, ReadinessNotification,
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
const RESPONSE_TAG_ERROR: u8 = 2;
const RESPONSE_TAG_VERSION_MISMATCH: u8 = 3;
const RESPONSE_TAG_OBJECT_CLOSED: u8 = 4;
const RESPONSE_TAG_PIPE: u8 = 5;
const RESPONSE_TAG_READINESS: u8 = 6;

const NOTIFICATION_TAG_READINESS: u8 = 0;

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
    match request {
        BrokerRequest::CloseObject(handle) => {
            encoder.u8(REQUEST_TAG_CLOSE_OBJECT);
            encoder.handle(handle);
        }
        BrokerRequest::CheckReadiness(handle) => {
            encoder.u8(REQUEST_TAG_CHECK_READINESS);
            encoder.handle(handle);
        }
        BrokerRequest::Event(request) => {
            encoder.u8(REQUEST_TAG_EVENT);
            event::encode_event_request(&mut encoder, request);
        }
        BrokerRequest::Pipe(request) => {
            encoder.u8(REQUEST_TAG_PIPE);
            pipe::encode_pipe_request(&mut encoder, request);
        }
    }
    encoder.finish()
}

/// Decodes a broker request body.
pub fn decode_request(frame: &[u8]) -> Result<BrokerRequest, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    let request = match tag {
        REQUEST_TAG_NEGOTIATE => return Err(WireError::WrongMessagePhase),
        REQUEST_TAG_CLOSE_OBJECT => BrokerRequest::CloseObject(decoder.handle()?),
        REQUEST_TAG_CHECK_READINESS => BrokerRequest::CheckReadiness(decoder.handle()?),
        REQUEST_TAG_EVENT => BrokerRequest::Event(event::decode_event_request(&mut decoder)?),
        REQUEST_TAG_PIPE => BrokerRequest::Pipe(pipe::decode_pipe_request(&mut decoder)?),
        _ => return Err(WireError::InvalidTag),
    };
    decoder.finish()?;
    Ok(request)
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
            encoder.u8(RESPONSE_TAG_ERROR);
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
        | RESPONSE_TAG_READINESS => {
            return Err(WireError::WrongMessagePhase);
        }
        RESPONSE_TAG_VERSION_MISMATCH => BrokerHandshakeResponse::VersionMismatch {
            broker_protocol_version: decoder.protocol_version()?,
        },
        RESPONSE_TAG_ERROR => {
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
    match response {
        BrokerResponse::ObjectClosed => {
            encoder.u8(RESPONSE_TAG_OBJECT_CLOSED);
        }
        BrokerResponse::Readiness(readiness) => {
            encoder.u8(RESPONSE_TAG_READINESS);
            encoder.u32(readiness.0);
        }
        BrokerResponse::Event(response) => {
            encoder.u8(RESPONSE_TAG_EVENT);
            event::encode_event_response(&mut encoder, response);
        }
        BrokerResponse::Pipe(response) => {
            encoder.u8(RESPONSE_TAG_PIPE);
            pipe::encode_pipe_response(&mut encoder, response);
        }
        BrokerResponse::Error(error) => {
            encoder.u8(RESPONSE_TAG_ERROR);
            encoder.u16(error.as_raw());
        }
    }
    encoder.finish()
}

/// Decodes a broker response body.
pub fn decode_response(frame: &[u8]) -> Result<BrokerResponse, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    let response = match tag {
        RESPONSE_TAG_NEGOTIATED | RESPONSE_TAG_VERSION_MISMATCH => {
            return Err(WireError::WrongMessagePhase);
        }
        RESPONSE_TAG_EVENT => BrokerResponse::Event(event::decode_event_response(&mut decoder)?),
        RESPONSE_TAG_PIPE => BrokerResponse::Pipe(pipe::decode_pipe_response(&mut decoder)?),
        RESPONSE_TAG_ERROR => {
            let error = ErrorCode::from_raw(decoder.u16()?).ok_or(WireError::InvalidTag)?;
            BrokerResponse::Error(error)
        }
        RESPONSE_TAG_OBJECT_CLOSED => BrokerResponse::ObjectClosed,
        RESPONSE_TAG_READINESS => BrokerResponse::Readiness(ReadinessFlags(decoder.u32()?)),
        _ => return Err(WireError::InvalidTag),
    };
    decoder.finish()?;
    Ok(response)
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
    use crate::{ObjectHandle, ProtocolVersion};

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
        let requests = [
            BrokerRequest::CloseObject(handle),
            BrokerRequest::CheckReadiness(handle),
            BrokerRequest::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 0,
            })),
            BrokerRequest::Event(EventRequest::Create(CreateEventRequest {
                initial_count: 7,
            })),
            BrokerRequest::Event(EventRequest::Add(AddEventRequest { handle, value: 3 })),
            BrokerRequest::Event(EventRequest::Consume(ConsumeEventRequest {
                handle,
                mode: EventConsumeMode::All,
            })),
            BrokerRequest::Event(EventRequest::Consume(ConsumeEventRequest {
                handle,
                mode: EventConsumeMode::One,
            })),
            BrokerRequest::Pipe(PipeRequest::Create(CreatePipeRequest {
                capacity: 4096,
                atomic_write_size: 512,
            })),
            BrokerRequest::Pipe(PipeRequest::Read(ReadPipeRequest { handle, length: 32 })),
            BrokerRequest::Pipe(PipeRequest::Write(WritePipeRequest {
                handle,
                data: Vec::from([1, 2, 3]),
            })),
        ];

        for request in requests {
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
        let responses = [
            BrokerResponse::ObjectClosed,
            BrokerResponse::Readiness(ReadinessFlags::READ),
            BrokerResponse::Readiness(ReadinessFlags::WRITE),
            BrokerResponse::Event(EventResponse::Create(CreateEventResponse { handle })),
            BrokerResponse::Event(EventResponse::Add(AddEventResponse {
                readiness: ReadinessFlags::READ | ReadinessFlags::WRITE,
            })),
            BrokerResponse::Event(EventResponse::Consume(EventConsumption {
                value: 3,
                readiness: ReadinessFlags::WRITE,
            })),
            BrokerResponse::Pipe(PipeResponse::Create(CreatePipeResponse {
                read_handle: handle,
                write_handle: ObjectHandle(14),
            })),
            BrokerResponse::Pipe(PipeResponse::Read(ReadPipeResponse {
                data: Vec::from([1, 2, 3]),
            })),
            BrokerResponse::Pipe(PipeResponse::Write(WritePipeResponse { written: 3 })),
            BrokerResponse::Error(ErrorCode::PolicyDenied),
            BrokerResponse::Error(ErrorCode::WouldBlock),
            BrokerResponse::Error(ErrorCode::PeerClosed),
            BrokerResponse::Error(ErrorCode::OutOfMemory),
            BrokerResponse::Error(ErrorCode::Internal),
        ];

        for response in responses {
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

        for notification in notifications {
            assert_eq!(
                decode_notification(&encode_notification(notification.clone())).unwrap(),
                notification
            );
        }
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
            decode_handshake_request(&encode_request(BrokerRequest::Event(EventRequest::Create(
                CreateEventRequest { initial_count: 0 },
            )))),
            Err(WireError::WrongMessagePhase)
        );
        assert_eq!(
            decode_handshake_request(&encode_request(BrokerRequest::CloseObject(ObjectHandle(
                13
            )))),
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
        let mut unknown_consume_mode = encode_request(BrokerRequest::Event(EventRequest::Consume(
            ConsumeEventRequest {
                handle: ObjectHandle(13),
                mode: EventConsumeMode::All,
            },
        )));
        *unknown_consume_mode.last_mut().unwrap() = 0xff;
        assert_eq!(
            decode_request(&unknown_consume_mode),
            Err(WireError::InvalidTag)
        );
        let mut frame = encode_request(BrokerRequest::Event(EventRequest::Create(
            CreateEventRequest { initial_count: 0 },
        )));
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
            decode_handshake_response(&encode_response(BrokerResponse::Event(
                EventResponse::Create(CreateEventResponse {
                    handle: ObjectHandle(13),
                }),
            ))),
            Err(WireError::WrongMessagePhase)
        );
        assert_eq!(
            decode_handshake_response(&encode_response(BrokerResponse::ObjectClosed)),
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
        assert_eq!(
            decode_response(&encode_handshake_response(
                BrokerHandshakeResponse::Negotiated {
                    broker_protocol_version: ProtocolVersion(1),
                },
            )),
            Err(WireError::WrongMessagePhase)
        );
        assert_eq!(
            decode_response(&[RESPONSE_TAG_READINESS, 0xff]),
            Err(WireError::TruncatedFrame)
        );
        assert_eq!(
            decode_response(&[2, 0xff, 0xff]),
            Err(WireError::InvalidTag)
        );

        let truncated = [1, 2, 2, 0];
        assert_eq!(decode_response(&truncated), Err(WireError::TruncatedFrame));

        let mut frame = encode_response(BrokerResponse::Event(EventResponse::Add(
            AddEventResponse {
                readiness: ReadinessFlags::READ | ReadinessFlags::WRITE,
            },
        )));
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
    fn event_add_response_wire_shape_is_pinned() {
        assert_eq!(
            encode_response(BrokerResponse::Event(EventResponse::Add(
                AddEventResponse {
                    readiness: ReadinessFlags::READ,
                }
            ))),
            [1, 1, 1, 0, 0, 0]
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
