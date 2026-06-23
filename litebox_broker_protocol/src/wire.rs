// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Reusable byte codec for broker request/response control-channel messages.
//!
//! The wire codec mirrors the protocol DTO hierarchy:
//! - this module owns public encode/decode entry points and top-level broker
//!   envelope tags;
//! - `core_message` owns `CoreRequest`/`CoreResponse` family tags;
//! - object-family modules such as `event` own their operation and nested value
//!   tags;
//! - `primitive` owns shared scalar/value encoders.
//!
//! New object families should add a core family tag and a private family codec
//! module instead of adding flat helpers here. Existing payloads are positional;
//! changing fields is an ABI change, so prefer a new operation tag or explicit
//! negotiated-version gate for payload evolution.

use alloc::vec::Vec;
use thiserror::Error;

use crate::{BrokerRequest, BrokerResponse, ErrorCode};

use primitive::{Decoder, Encoder};

mod core_message;
mod event;
mod primitive;

const REQUEST_TAG_NEGOTIATE: u8 = 0;
const REQUEST_TAG_CORE: u8 = 1;

const RESPONSE_TAG_NEGOTIATED: u8 = 0;
const RESPONSE_TAG_CORE: u8 = 1;
const RESPONSE_TAG_ERROR: u8 = 2;
const RESPONSE_TAG_VERSION_MISMATCH: u8 = 3;

/// Error produced while encoding or decoding a broker wire message.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    #[error("truncated broker wire frame")]
    TruncatedFrame,
    #[error("trailing broker wire bytes")]
    TrailingBytes,
    #[error("invalid broker wire boolean")]
    InvalidBoolean,
    #[error("invalid broker wire tag")]
    InvalidTag,
    #[error("broker wire offset overflow")]
    OffsetOverflow,
}

/// Encodes a broker request body.
///
/// Successful encodings are always non-empty because the first byte is the
/// message tag.
pub fn encode_request(request: BrokerRequest) -> Vec<u8> {
    let mut encoder = Encoder::default();
    match request {
        BrokerRequest::Negotiate { protocol_version } => {
            encoder.u8(REQUEST_TAG_NEGOTIATE);
            encoder.protocol_version(protocol_version);
        }
        BrokerRequest::Core(request) => {
            encoder.u8(REQUEST_TAG_CORE);
            core_message::encode_core_request(&mut encoder, request);
        }
    }
    encoder.finish()
}

/// Decodes a broker request body.
pub fn decode_request(frame: &[u8]) -> Result<BrokerRequest, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    let request = match tag {
        REQUEST_TAG_NEGOTIATE => BrokerRequest::Negotiate {
            protocol_version: decoder.protocol_version()?,
        },
        REQUEST_TAG_CORE => BrokerRequest::Core(core_message::decode_core_request(&mut decoder)?),
        _ => return Err(WireError::InvalidTag),
    };
    decoder.finish()?;
    Ok(request)
}

/// Encodes a broker response body.
///
/// Successful encodings are always non-empty because the first byte is the
/// message tag.
pub fn encode_response(response: BrokerResponse) -> Vec<u8> {
    let mut encoder = Encoder::default();
    match response {
        BrokerResponse::Negotiated {
            broker_protocol_version,
        } => {
            encoder.u8(RESPONSE_TAG_NEGOTIATED);
            encoder.protocol_version(broker_protocol_version);
        }
        BrokerResponse::VersionMismatch {
            broker_protocol_version,
        } => {
            encoder.u8(RESPONSE_TAG_VERSION_MISMATCH);
            encoder.protocol_version(broker_protocol_version);
        }
        BrokerResponse::Core(response) => {
            encoder.u8(RESPONSE_TAG_CORE);
            core_message::encode_core_response(&mut encoder, response);
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
        RESPONSE_TAG_NEGOTIATED => BrokerResponse::Negotiated {
            broker_protocol_version: decoder.protocol_version()?,
        },
        RESPONSE_TAG_VERSION_MISMATCH => BrokerResponse::VersionMismatch {
            broker_protocol_version: decoder.protocol_version()?,
        },
        RESPONSE_TAG_CORE => {
            BrokerResponse::Core(core_message::decode_core_response(&mut decoder)?)
        }
        RESPONSE_TAG_ERROR => {
            let error = ErrorCode::from_raw(decoder.u16()?);
            BrokerResponse::Error(error)
        }
        _ => return Err(WireError::InvalidTag),
    };
    decoder.finish()?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AddEventRequest, AddEventResponse, ConsumeEventRequest, ConsumeEventResponse, CoreRequest,
        CoreResponse, CreateEventRequest, CreateEventResponse, EventConsumeMode, EventRequest,
        EventResponse, ObjectHandle, ProtocolVersion, ReadinessState, WaitEventRequest,
        WaitEventResponse, WaitOutcome,
    };

    #[test]
    fn request_codec_round_trips_all_variants() {
        let handle = sample_handle();
        let requests = [
            BrokerRequest::Negotiate {
                protocol_version: ProtocolVersion::new(1),
            },
            event_request(EventRequest::Create(CreateEventRequest::new(0))),
            event_request(EventRequest::Create(CreateEventRequest::new(7))),
            event_request(EventRequest::Wait(WaitEventRequest::new(handle))),
            event_request(EventRequest::Add(AddEventRequest::new(handle, 3))),
            event_request(EventRequest::Consume(ConsumeEventRequest::new(
                handle,
                EventConsumeMode::All,
            ))),
            event_request(EventRequest::Consume(ConsumeEventRequest::new(
                handle,
                EventConsumeMode::One,
            ))),
        ];

        for request in requests {
            assert_eq!(
                decode_request(&encode_request(request.clone())).unwrap(),
                request
            );
        }
    }

    #[test]
    fn response_codec_round_trips_all_variants() {
        let handle = sample_handle();
        let responses = [
            BrokerResponse::Negotiated {
                broker_protocol_version: ProtocolVersion::new(1),
            },
            BrokerResponse::VersionMismatch {
                broker_protocol_version: ProtocolVersion::new(1),
            },
            event_response(EventResponse::Create(CreateEventResponse::new(handle))),
            event_response(EventResponse::Wait(WaitEventResponse::new(
                WaitOutcome::Ready(ReadinessState::new(true, false)),
            ))),
            event_response(EventResponse::Wait(WaitEventResponse::new(
                WaitOutcome::WouldBlock(ReadinessState::new(false, true)),
            ))),
            event_response(EventResponse::Add(AddEventResponse::new(
                ReadinessState::new(true, true),
            ))),
            event_response(EventResponse::Consume(ConsumeEventResponse::new(
                3,
                ReadinessState::new(false, true),
            ))),
            BrokerResponse::Error(ErrorCode::PolicyDenied),
            BrokerResponse::Error(ErrorCode::WouldBlock),
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
    fn decode_rejects_malformed_request_frames() {
        assert_eq!(decode_request(&[0xff, 1, 2, 3]), Err(WireError::InvalidTag));
        let mut unknown_consume_mode = encode_request(event_request(EventRequest::Consume(
            ConsumeEventRequest::new(sample_handle(), EventConsumeMode::All),
        )));
        *unknown_consume_mode.last_mut().unwrap() = 0xff;
        assert_eq!(
            decode_request(&unknown_consume_mode),
            Err(WireError::InvalidTag)
        );
        assert_eq!(decode_request(&[0, 1]), Err(WireError::TruncatedFrame));
        let mut frame = encode_request(event_request(EventRequest::Create(
            CreateEventRequest::new(0),
        )));
        frame.push(0xff);
        assert_eq!(decode_request(&frame), Err(WireError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_malformed_response_frames() {
        assert_eq!(
            decode_response(&[0xff, 1, 2, 3]),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            decode_response(&[1, 0, 1, 0xff]),
            Err(WireError::InvalidTag)
        );
        assert_eq!(
            decode_response(&[2, 0xff, 0xff]),
            Ok(BrokerResponse::Error(ErrorCode::Unknown(0xffff)))
        );

        let mut invalid_bool = [1, 0, 2, 2, 0];
        assert_eq!(
            decode_response(&invalid_bool),
            Err(WireError::InvalidBoolean)
        );

        invalid_bool[3] = 1;
        invalid_bool[4] = 1;
        let mut frame = invalid_bool.to_vec();
        frame.push(0xff);
        assert_eq!(decode_response(&frame), Err(WireError::TrailingBytes));
    }

    #[test]
    fn event_add_response_wire_shape_is_pinned() {
        assert_eq!(
            encode_response(event_response(EventResponse::Add(AddEventResponse::new(
                ReadinessState::new(true, false)
            )))),
            [1, 0, 2, 1, 0]
        );
    }

    const fn sample_handle() -> ObjectHandle {
        ObjectHandle(13)
    }

    const fn event_request(request: EventRequest) -> BrokerRequest {
        BrokerRequest::Core(CoreRequest::Event(request))
    }

    const fn event_response(response: EventResponse) -> BrokerResponse {
        BrokerResponse::Core(CoreResponse::Event(response))
    }
}
