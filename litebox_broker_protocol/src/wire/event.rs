// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::event::{
    AddEventRequest, AddEventResponse, ConsumeEventRequest, CreateEventRequest,
    CreateEventResponse, EventConsumeMode, EventConsumption,
};
use crate::message::{EventRequest, EventResponse};
use crate::readiness::ReadinessFlags;

use super::WireError;
use super::primitive::{Decoder, Encoder};

// Event operation tags live with the event family. Future event operations
// should add tags here; unrelated object families should get their own module.
const EVENT_REQUEST_TAG_CREATE: u8 = 0;
const EVENT_REQUEST_TAG_ADD: u8 = 1;
const EVENT_REQUEST_TAG_CONSUME: u8 = 2;

const EVENT_RESPONSE_TAG_CREATE: u8 = 0;
const EVENT_RESPONSE_TAG_ADD: u8 = 1;
const EVENT_RESPONSE_TAG_CONSUME: u8 = 2;

const EVENT_CONSUME_MODE_TAG_ALL: u8 = 1;
const EVENT_CONSUME_MODE_TAG_ONE: u8 = 2;

pub(super) fn encode_event_request(encoder: &mut Encoder, request: EventRequest) {
    match request {
        EventRequest::Create(request) => {
            encoder.u8(EVENT_REQUEST_TAG_CREATE);
            encoder.u64(request.initial_count);
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

pub(super) fn decode_event_request(decoder: &mut Decoder<'_>) -> Result<EventRequest, WireError> {
    let request = match decoder.u8()? {
        EVENT_REQUEST_TAG_CREATE => EventRequest::Create(CreateEventRequest {
            initial_count: decoder.u64()?,
        }),
        EVENT_REQUEST_TAG_ADD => EventRequest::Add(AddEventRequest {
            handle: decoder.handle()?,
            value: decoder.u64()?,
        }),
        EVENT_REQUEST_TAG_CONSUME => EventRequest::Consume(ConsumeEventRequest {
            handle: decoder.handle()?,
            mode: decode_consume_mode(decoder)?,
        }),
        _ => return Err(WireError::InvalidTag),
    };

    Ok(request)
}

pub(super) fn encode_event_response(encoder: &mut Encoder, response: EventResponse) {
    match response {
        EventResponse::Create(response) => {
            encoder.u8(EVENT_RESPONSE_TAG_CREATE);
            encoder.handle(response.handle);
        }
        EventResponse::Add(response) => {
            encoder.u8(EVENT_RESPONSE_TAG_ADD);
            encoder.u32(response.readiness.0);
        }
        EventResponse::Consume(response) => {
            encoder.u8(EVENT_RESPONSE_TAG_CONSUME);
            encoder.u64(response.value);
            encoder.u32(response.readiness.0);
        }
    }
}

pub(super) fn decode_event_response(decoder: &mut Decoder<'_>) -> Result<EventResponse, WireError> {
    let response = match decoder.u8()? {
        EVENT_RESPONSE_TAG_CREATE => EventResponse::Create(CreateEventResponse {
            handle: decoder.handle()?,
        }),
        EVENT_RESPONSE_TAG_ADD => EventResponse::Add(AddEventResponse {
            readiness: ReadinessFlags(decoder.u32()?),
        }),
        EVENT_RESPONSE_TAG_CONSUME => EventResponse::Consume(EventConsumption {
            value: decoder.u64()?,
            readiness: ReadinessFlags(decoder.u32()?),
        }),
        _ => return Err(WireError::InvalidTag),
    };

    Ok(response)
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

fn decode_consume_mode(decoder: &mut Decoder<'_>) -> Result<EventConsumeMode, WireError> {
    match decoder.u8()? {
        EVENT_CONSUME_MODE_TAG_ALL => Ok(EventConsumeMode::All),
        EVENT_CONSUME_MODE_TAG_ONE => Ok(EventConsumeMode::One),
        _ => Err(WireError::InvalidTag),
    }
}
