// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Reusable byte codec for broker request/response control-channel messages.

#![no_std]

extern crate alloc;

use core::fmt;

use alloc::vec::Vec;
use litebox_broker_protocol::{
    AddEventRequest, AddEventResponse, BrokerRequest, BrokerResponse, ConsumeEventRequest,
    ConsumeEventResponse, CoreRequest, CoreResponse, CreateEventRequest, CreateEventResponse,
    ErrorCode, EventConsumeMode, EventRequest, EventResponse, ObjectHandle,
    ObjectReferenceGeneration, ObjectReferenceId, ProtocolVersion, ReadinessState,
    ReceivedBrokerRequest, ReceivedBrokerResponse, WaitEventRequest, WaitEventResponse,
    WaitOutcome,
};

const REQUEST_TAG_NEGOTIATE: u8 = 0;
const REQUEST_TAG_CORE: u8 = 1;
const CORE_REQUEST_TAG_EVENT: u8 = 0;
const EVENT_REQUEST_TAG_CREATE: u8 = 0;
const EVENT_REQUEST_TAG_WAIT: u8 = 1;
const EVENT_REQUEST_TAG_ADD: u8 = 2;
const EVENT_REQUEST_TAG_CONSUME: u8 = 3;

const RESPONSE_TAG_NEGOTIATED: u8 = 0;
const RESPONSE_TAG_CORE: u8 = 1;
const RESPONSE_TAG_ERROR: u8 = 2;
const RESPONSE_TAG_VERSION_MISMATCH: u8 = 3;
const CORE_RESPONSE_TAG_EVENT: u8 = 0;
const EVENT_RESPONSE_TAG_CREATED: u8 = 0;
const EVENT_RESPONSE_TAG_WAITED: u8 = 1;
const EVENT_RESPONSE_TAG_ADDED: u8 = 2;
const EVENT_RESPONSE_TAG_CONSUMED: u8 = 3;

const WAIT_OUTCOME_TAG_READY: u8 = 1;
const WAIT_OUTCOME_TAG_WOULD_BLOCK: u8 = 2;
const EVENT_CONSUME_MODE_TAG_ALL: u8 = 1;
const EVENT_CONSUME_MODE_TAG_ONE: u8 = 2;

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
    /// The encoder was asked to emit an event consume mode this codec does not own.
    EncodeUnknownEventConsumeMode,
    /// The frame ended before a complete field could be decoded.
    TruncatedFrame,
    /// The frame contained bytes after the decoded message.
    TrailingBytes,
    /// A boolean field was not encoded as 0 or 1.
    InvalidBoolean,
    /// The wait-outcome tag is unknown.
    UnknownWaitOutcome,
    /// The event consume mode tag is unknown.
    UnknownEventConsumeMode,
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
            Self::EncodeUnknownEventConsumeMode => {
                f.write_str("cannot encode unknown broker event consume mode")
            }
            Self::TrailingBytes => f.write_str("trailing broker wire bytes"),
            Self::InvalidBoolean => f.write_str("invalid broker wire boolean"),
            Self::UnknownWaitOutcome => f.write_str("unknown broker wait outcome"),
            Self::UnknownEventConsumeMode => f.write_str("unknown broker event consume mode"),
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
        BrokerRequest::Core(request) => encode_core_request(&mut encoder, request)?,
        _ => return Err(WireError::EncodeUnknownRequestTag),
    }
    Ok(encoder.finish())
}

fn encode_core_request(encoder: &mut Encoder, request: CoreRequest) -> Result<(), WireError> {
    encoder.u8(REQUEST_TAG_CORE);
    match request {
        CoreRequest::Event(request) => {
            encoder.u8(CORE_REQUEST_TAG_EVENT);
            encode_event_request(encoder, request)
        }
        _ => Err(WireError::EncodeUnknownRequestTag),
    }
}

fn encode_event_request(encoder: &mut Encoder, request: EventRequest) -> Result<(), WireError> {
    match request {
        EventRequest::Create(request) => {
            encoder.u8(EVENT_REQUEST_TAG_CREATE);
            encoder.u64(request.initial_count);
            Ok(())
        }
        EventRequest::Wait(request) => {
            encoder.u8(EVENT_REQUEST_TAG_WAIT);
            encoder.handle(request.handle);
            Ok(())
        }
        EventRequest::Add(request) => {
            encoder.u8(EVENT_REQUEST_TAG_ADD);
            encoder.handle(request.handle);
            encoder.u64(request.value);
            Ok(())
        }
        EventRequest::Consume(request) => {
            encoder.u8(EVENT_REQUEST_TAG_CONSUME);
            encoder.handle(request.handle);
            encode_event_consume_mode(encoder, request.mode)
        }
        _ => Err(WireError::EncodeUnknownRequestTag),
    }
}

/// Decodes a broker request body.
pub fn decode_request(frame: &[u8]) -> Result<ReceivedBrokerRequest, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    let request = match tag {
        REQUEST_TAG_NEGOTIATE => BrokerRequest::Negotiate {
            protocol_version: ProtocolVersion::new(decoder.u16()?, decoder.u16()?),
        },
        REQUEST_TAG_CORE => match decode_core_request(&mut decoder)? {
            Some(request) => BrokerRequest::Core(request),
            None => return Ok(ReceivedBrokerRequest::Unknown),
        },
        _ => return Ok(ReceivedBrokerRequest::Unknown),
    };
    decoder.finish()?;
    Ok(ReceivedBrokerRequest::Request(request))
}

fn decode_core_request(decoder: &mut Decoder<'_>) -> Result<Option<CoreRequest>, WireError> {
    let request = match decoder.u8()? {
        CORE_REQUEST_TAG_EVENT => match decode_event_request(decoder)? {
            Some(request) => CoreRequest::Event(request),
            None => return Ok(None),
        },
        _ => return Ok(None),
    };

    Ok(Some(request))
}

fn decode_event_request(decoder: &mut Decoder<'_>) -> Result<Option<EventRequest>, WireError> {
    let request = match decoder.u8()? {
        EVENT_REQUEST_TAG_CREATE => EventRequest::Create(CreateEventRequest::new(decoder.u64()?)),
        EVENT_REQUEST_TAG_WAIT => EventRequest::Wait(WaitEventRequest::new(decoder.handle()?)),
        EVENT_REQUEST_TAG_ADD => {
            EventRequest::Add(AddEventRequest::new(decoder.handle()?, decoder.u64()?))
        }
        EVENT_REQUEST_TAG_CONSUME => EventRequest::Consume(ConsumeEventRequest::new(
            decoder.handle()?,
            decode_event_consume_mode(decoder)?,
        )),
        _ => return Ok(None),
    };

    Ok(Some(request))
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
        BrokerResponse::Core(response) => encode_core_response(&mut encoder, response)?,
        BrokerResponse::Error(error) => {
            encoder.u8(RESPONSE_TAG_ERROR);
            encoder.u16(error.as_raw());
        }
        _ => return Err(WireError::EncodeUnknownResponseTag),
    }
    Ok(encoder.finish())
}

fn encode_core_response(encoder: &mut Encoder, response: CoreResponse) -> Result<(), WireError> {
    encoder.u8(RESPONSE_TAG_CORE);
    match response {
        CoreResponse::Event(response) => {
            encoder.u8(CORE_RESPONSE_TAG_EVENT);
            encode_event_response(encoder, response)
        }
        _ => Err(WireError::EncodeUnknownResponseTag),
    }
}

fn encode_event_response(encoder: &mut Encoder, response: EventResponse) -> Result<(), WireError> {
    match response {
        EventResponse::Create(response) => {
            encoder.u8(EVENT_RESPONSE_TAG_CREATED);
            encoder.handle(response.handle);
            Ok(())
        }
        EventResponse::Wait(response) => {
            encoder.u8(EVENT_RESPONSE_TAG_WAITED);
            encode_wait_outcome(encoder, response.outcome)
        }
        EventResponse::Add(response) => {
            encoder.u8(EVENT_RESPONSE_TAG_ADDED);
            encoder.readiness(response.readiness);
            Ok(())
        }
        EventResponse::Consume(response) => {
            encoder.u8(EVENT_RESPONSE_TAG_CONSUMED);
            encoder.u64(response.value);
            encoder.readiness(response.readiness);
            Ok(())
        }
        _ => Err(WireError::EncodeUnknownResponseTag),
    }
}

fn encode_wait_outcome(encoder: &mut Encoder, outcome: WaitOutcome) -> Result<(), WireError> {
    match outcome {
        WaitOutcome::Ready(readiness) => {
            encoder.u8(WAIT_OUTCOME_TAG_READY);
            encoder.readiness(readiness);
            Ok(())
        }
        WaitOutcome::WouldBlock(readiness) => {
            encoder.u8(WAIT_OUTCOME_TAG_WOULD_BLOCK);
            encoder.readiness(readiness);
            Ok(())
        }
        _ => Err(WireError::EncodeUnknownWaitOutcome),
    }
}

/// Decodes a broker response body.
pub fn decode_response(frame: &[u8]) -> Result<ReceivedBrokerResponse, WireError> {
    let mut decoder = Decoder::new(frame);
    let tag = decoder.u8()?;
    let response = match tag {
        RESPONSE_TAG_NEGOTIATED => BrokerResponse::Negotiated {
            broker_protocol_version: ProtocolVersion::new(decoder.u16()?, decoder.u16()?),
        },
        RESPONSE_TAG_VERSION_MISMATCH => BrokerResponse::VersionMismatch {
            broker_protocol_version: ProtocolVersion::new(decoder.u16()?, decoder.u16()?),
        },
        RESPONSE_TAG_CORE => match decode_core_response(&mut decoder)? {
            Some(response) => BrokerResponse::Core(response),
            None => return Ok(ReceivedBrokerResponse::Unknown),
        },
        RESPONSE_TAG_ERROR => {
            let error = ErrorCode::from_raw(decoder.u16()?);
            BrokerResponse::Error(error)
        }
        _ => return Ok(ReceivedBrokerResponse::Unknown),
    };
    decoder.finish()?;
    Ok(ReceivedBrokerResponse::Response(response))
}

fn decode_core_response(decoder: &mut Decoder<'_>) -> Result<Option<CoreResponse>, WireError> {
    let response = match decoder.u8()? {
        CORE_RESPONSE_TAG_EVENT => match decode_event_response(decoder)? {
            Some(response) => CoreResponse::Event(response),
            None => return Ok(None),
        },
        _ => return Ok(None),
    };

    Ok(Some(response))
}

fn decode_event_response(decoder: &mut Decoder<'_>) -> Result<Option<EventResponse>, WireError> {
    let response = match decoder.u8()? {
        EVENT_RESPONSE_TAG_CREATED => {
            EventResponse::Create(CreateEventResponse::new(decoder.handle()?))
        }
        EVENT_RESPONSE_TAG_WAITED => {
            EventResponse::Wait(WaitEventResponse::new(decode_wait_outcome(decoder)?))
        }
        EVENT_RESPONSE_TAG_ADDED => EventResponse::Add(AddEventResponse::new(decoder.readiness()?)),
        EVENT_RESPONSE_TAG_CONSUMED => EventResponse::Consume(ConsumeEventResponse::new(
            decoder.u64()?,
            decoder.readiness()?,
        )),
        _ => return Ok(None),
    };

    Ok(Some(response))
}

fn decode_wait_outcome(decoder: &mut Decoder<'_>) -> Result<WaitOutcome, WireError> {
    match decoder.u8()? {
        WAIT_OUTCOME_TAG_READY => Ok(WaitOutcome::Ready(decoder.readiness()?)),
        WAIT_OUTCOME_TAG_WOULD_BLOCK => Ok(WaitOutcome::WouldBlock(decoder.readiness()?)),
        _ => Err(WireError::UnknownWaitOutcome),
    }
}

fn encode_event_consume_mode(
    encoder: &mut Encoder,
    mode: EventConsumeMode,
) -> Result<(), WireError> {
    match mode {
        EventConsumeMode::All => {
            encoder.u8(EVENT_CONSUME_MODE_TAG_ALL);
            Ok(())
        }
        EventConsumeMode::One => {
            encoder.u8(EVENT_CONSUME_MODE_TAG_ONE);
            Ok(())
        }
        _ => Err(WireError::EncodeUnknownEventConsumeMode),
    }
}

fn decode_event_consume_mode(decoder: &mut Decoder<'_>) -> Result<EventConsumeMode, WireError> {
    match decoder.u8()? {
        EVENT_CONSUME_MODE_TAG_ALL => Ok(EventConsumeMode::All),
        EVENT_CONSUME_MODE_TAG_ONE => Ok(EventConsumeMode::One),
        _ => Err(WireError::UnknownEventConsumeMode),
    }
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
        self.u64(handle.reference_id.get());
        self.u64(handle.reference_generation.get());
    }

    fn readiness(&mut self, readiness: ReadinessState) {
        self.bool(readiness.read_ready);
        self.bool(readiness.write_ready);
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
        let reference_id = ObjectReferenceId::new(self.u64()?);
        let reference_generation = ObjectReferenceGeneration::new(self.u64()?);

        Ok(ObjectHandle::new(reference_id, reference_generation))
    }

    fn readiness(&mut self) -> Result<ReadinessState, WireError> {
        Ok(ReadinessState::new(self.bool()?, self.bool()?, self.u64()?))
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
                decode_request(&encode_request(request).unwrap()).unwrap(),
                ReceivedBrokerRequest::Request(request)
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
            event_response(EventResponse::Create(CreateEventResponse::new(handle))),
            event_response(EventResponse::Wait(WaitEventResponse::new(
                WaitOutcome::Ready(ReadinessState::new(true, false, 8)),
            ))),
            event_response(EventResponse::Wait(WaitEventResponse::new(
                WaitOutcome::WouldBlock(ReadinessState::new(false, true, 9)),
            ))),
            event_response(EventResponse::Add(AddEventResponse::new(
                ReadinessState::new(true, true, 10),
            ))),
            event_response(EventResponse::Consume(ConsumeEventResponse::new(
                3,
                ReadinessState::new(false, true, 11),
            ))),
            BrokerResponse::Error(ErrorCode::PolicyDenied),
            BrokerResponse::Error(ErrorCode::WouldBlock),
            BrokerResponse::Error(ErrorCode::Internal),
        ];

        for response in responses {
            assert_eq!(
                decode_response(&encode_response(response).unwrap()).unwrap(),
                ReceivedBrokerResponse::Response(response)
            );
        }
    }

    #[test]
    fn decode_rejects_malformed_request_frames() {
        assert_eq!(
            decode_request(&[0xff, 1, 2, 3]),
            Ok(ReceivedBrokerRequest::Unknown)
        );
        assert_eq!(decode_request(&[0, 1]), Err(WireError::TruncatedFrame));
        let mut frame = encode_request(event_request(EventRequest::Create(
            CreateEventRequest::new(0),
        )))
        .unwrap();
        frame.push(0xff);
        assert_eq!(decode_request(&frame), Err(WireError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_malformed_response_frames() {
        assert_eq!(
            decode_response(&[0xff, 1, 2, 3]),
            Ok(ReceivedBrokerResponse::Unknown)
        );
        assert_eq!(
            decode_response(&[1, 0, 1, 0xff]),
            Err(WireError::UnknownWaitOutcome)
        );
        assert_eq!(
            decode_response(&[2, 0xff, 0xff]),
            Ok(ReceivedBrokerResponse::Response(BrokerResponse::Error(
                ErrorCode::Unknown(0xffff)
            )))
        );

        let mut invalid_bool = [1, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            decode_response(&invalid_bool),
            Err(WireError::InvalidBoolean)
        );

        invalid_bool[3] = 1;
        invalid_bool[4] = 1;
        invalid_bool[12] = 1;
        let mut frame = invalid_bool.to_vec();
        frame.push(0xff);
        assert_eq!(decode_response(&frame), Err(WireError::TrailingBytes));
    }

    #[test]
    fn readiness_response_wire_shape_is_pinned() {
        assert_eq!(
            encode_response(event_response(EventResponse::Add(AddEventResponse::new(
                ReadinessState::new(true, false, 0x0102_0304_0506_0708)
            ))))
            .unwrap(),
            [1, 0, 2, 1, 0, 8, 7, 6, 5, 4, 3, 2, 1]
        );
    }

    const fn sample_handle() -> ObjectHandle {
        ObjectHandle::new(
            ObjectReferenceId::new(13),
            ObjectReferenceGeneration::new(14),
        )
    }

    const fn event_request(request: EventRequest) -> BrokerRequest {
        BrokerRequest::Core(CoreRequest::Event(request))
    }

    const fn event_response(response: EventResponse) -> BrokerResponse {
        BrokerResponse::Core(CoreResponse::Event(response))
    }
}
