// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{
    AddEventRequest, AddEventResponse, ConsumeEventRequest, ConsumeEventResponse,
    CreateEventRequest, CreateEventResponse, EventConsumeMode, EventRequest, EventResponse,
    ReadinessState, WaitEventRequest, WaitEventResponse, WaitOutcome,
};

use super::WireError;
use super::primitive::{Decoder, Encoder};

// Event operation tags live with the event family. Future event operations
// should add tags here; unrelated object families should get their own module.
const EVENT_REQUEST_TAG_CREATE: u8 = 0;
const EVENT_REQUEST_TAG_WAIT: u8 = 1;
const EVENT_REQUEST_TAG_ADD: u8 = 2;
const EVENT_REQUEST_TAG_CONSUME: u8 = 3;

const EVENT_RESPONSE_TAG_CREATED: u8 = 0;
const EVENT_RESPONSE_TAG_WAITED: u8 = 1;
const EVENT_RESPONSE_TAG_ADDED: u8 = 2;
const EVENT_RESPONSE_TAG_CONSUMED: u8 = 3;

const WAIT_OUTCOME_TAG_READY: u8 = 1;
const WAIT_OUTCOME_TAG_WOULD_BLOCK: u8 = 2;
const EVENT_CONSUME_MODE_TAG_ALL: u8 = 1;
const EVENT_CONSUME_MODE_TAG_ONE: u8 = 2;

pub(super) fn encode_event_request(encoder: &mut Encoder, request: EventRequest) {
    match request {
        EventRequest::Create(request) => {
            encoder.u8(EVENT_REQUEST_TAG_CREATE);
            encoder.u64(request.initial_count);
        }
        EventRequest::Wait(request) => {
            encoder.u8(EVENT_REQUEST_TAG_WAIT);
            encoder.handle(request.handle);
        }
        EventRequest::Add(request) => {
            encoder.u8(EVENT_REQUEST_TAG_ADD);
            encoder.handle(request.handle);
            encoder.u64(request.value);
        }
        EventRequest::Consume(request) => {
            encoder.u8(EVENT_REQUEST_TAG_CONSUME);
            encoder.handle(request.handle);
            encode_consume_mode(encoder, request.mode);
        }
    }
}

pub(super) fn decode_event_request(
    decoder: &mut Decoder<'_>,
) -> Result<Option<EventRequest>, WireError> {
    let request = match decoder.u8()? {
        EVENT_REQUEST_TAG_CREATE => EventRequest::Create(CreateEventRequest::new(decoder.u64()?)),
        EVENT_REQUEST_TAG_WAIT => EventRequest::Wait(WaitEventRequest::new(decoder.handle()?)),
        EVENT_REQUEST_TAG_ADD => {
            EventRequest::Add(AddEventRequest::new(decoder.handle()?, decoder.u64()?))
        }
        EVENT_REQUEST_TAG_CONSUME => EventRequest::Consume(ConsumeEventRequest::new(
            decoder.handle()?,
            match decode_consume_mode(decoder)? {
                Some(mode) => mode,
                None => return Ok(None),
            },
        )),
        _ => return Ok(None),
    };

    Ok(Some(request))
}

pub(super) fn encode_event_response(encoder: &mut Encoder, response: EventResponse) {
    match response {
        EventResponse::Create(response) => {
            encoder.u8(EVENT_RESPONSE_TAG_CREATED);
            encoder.handle(response.handle);
        }
        EventResponse::Wait(response) => {
            encoder.u8(EVENT_RESPONSE_TAG_WAITED);
            encode_wait_outcome(encoder, response.outcome);
        }
        EventResponse::Add(response) => {
            encoder.u8(EVENT_RESPONSE_TAG_ADDED);
            encode_readiness(encoder, response.readiness);
        }
        EventResponse::Consume(response) => {
            encoder.u8(EVENT_RESPONSE_TAG_CONSUMED);
            encoder.u64(response.value);
            encode_readiness(encoder, response.readiness);
        }
    }
}

pub(super) fn decode_event_response(
    decoder: &mut Decoder<'_>,
) -> Result<Option<EventResponse>, WireError> {
    let response = match decoder.u8()? {
        EVENT_RESPONSE_TAG_CREATED => {
            EventResponse::Create(CreateEventResponse::new(decoder.handle()?))
        }
        EVENT_RESPONSE_TAG_WAITED => EventResponse::Wait(WaitEventResponse::new(
            match decode_wait_outcome(decoder)? {
                Some(outcome) => outcome,
                None => return Ok(None),
            },
        )),
        EVENT_RESPONSE_TAG_ADDED => {
            EventResponse::Add(AddEventResponse::new(decode_readiness(decoder)?))
        }
        EVENT_RESPONSE_TAG_CONSUMED => EventResponse::Consume(ConsumeEventResponse::new(
            decoder.u64()?,
            decode_readiness(decoder)?,
        )),
        _ => return Ok(None),
    };

    Ok(Some(response))
}

fn encode_wait_outcome(encoder: &mut Encoder, outcome: WaitOutcome) {
    match outcome {
        WaitOutcome::Ready(readiness) => {
            encoder.u8(WAIT_OUTCOME_TAG_READY);
            encode_readiness(encoder, readiness);
        }
        WaitOutcome::WouldBlock(readiness) => {
            encoder.u8(WAIT_OUTCOME_TAG_WOULD_BLOCK);
            encode_readiness(encoder, readiness);
        }
    }
}

fn decode_wait_outcome(decoder: &mut Decoder<'_>) -> Result<Option<WaitOutcome>, WireError> {
    match decoder.u8()? {
        WAIT_OUTCOME_TAG_READY => Ok(Some(WaitOutcome::Ready(decode_readiness(decoder)?))),
        WAIT_OUTCOME_TAG_WOULD_BLOCK => {
            Ok(Some(WaitOutcome::WouldBlock(decode_readiness(decoder)?)))
        }
        _ => Ok(None),
    }
}

fn encode_readiness(encoder: &mut Encoder, readiness: ReadinessState) {
    encoder.bool(readiness.read_ready);
    encoder.bool(readiness.write_ready);
}

fn decode_readiness(decoder: &mut Decoder<'_>) -> Result<ReadinessState, WireError> {
    Ok(ReadinessState::new(decoder.bool()?, decoder.bool()?))
}

fn encode_consume_mode(encoder: &mut Encoder, mode: EventConsumeMode) {
    match mode {
        EventConsumeMode::All => {
            encoder.u8(EVENT_CONSUME_MODE_TAG_ALL);
        }
        EventConsumeMode::One => {
            encoder.u8(EVENT_CONSUME_MODE_TAG_ONE);
        }
    }
}

fn decode_consume_mode(decoder: &mut Decoder<'_>) -> Result<Option<EventConsumeMode>, WireError> {
    match decoder.u8()? {
        EVENT_CONSUME_MODE_TAG_ALL => Ok(Some(EventConsumeMode::All)),
        EVENT_CONSUME_MODE_TAG_ONE => Ok(Some(EventConsumeMode::One)),
        _ => Ok(None),
    }
}
