// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{TimerRequest, TimerResponse};
use crate::timer::{
    CreateTimerResponse, GetTimerRequest, GetTimerResponse, ReadTimerRequest, ReadTimerResponse,
    SetTimerRequest, SetTimerResponse, TimerSpec,
};

use super::WireError;
use super::primitive::{Decoder, Encoder};

const TIMER_REQUEST_TAG_CREATE: u8 = 0;
const TIMER_REQUEST_TAG_SET: u8 = 1;
const TIMER_REQUEST_TAG_GET: u8 = 2;
const TIMER_REQUEST_TAG_READ: u8 = 3;

const TIMER_RESPONSE_TAG_CREATE: u8 = 0;
const TIMER_RESPONSE_TAG_SET: u8 = 1;
const TIMER_RESPONSE_TAG_GET: u8 = 2;
const TIMER_RESPONSE_TAG_READ: u8 = 3;

pub(super) fn encode_timer_request(encoder: &mut Encoder, request: TimerRequest) {
    match request {
        TimerRequest::Create => encoder.u8(TIMER_REQUEST_TAG_CREATE),
        TimerRequest::Set(request) => {
            encoder.u8(TIMER_REQUEST_TAG_SET);
            encoder.handle(request.handle);
            encode_timer_spec(encoder, request.spec);
        }
        TimerRequest::Get(request) => {
            encoder.u8(TIMER_REQUEST_TAG_GET);
            encoder.handle(request.handle);
        }
        TimerRequest::Read(request) => {
            encoder.u8(TIMER_REQUEST_TAG_READ);
            encoder.handle(request.handle);
        }
    }
}

pub(super) fn decode_timer_request(decoder: &mut Decoder<'_>) -> Result<TimerRequest, WireError> {
    let request = match decoder.u8()? {
        TIMER_REQUEST_TAG_CREATE => TimerRequest::Create,
        TIMER_REQUEST_TAG_SET => TimerRequest::Set(SetTimerRequest {
            handle: decoder.handle()?,
            spec: decode_timer_spec(decoder)?,
        }),
        TIMER_REQUEST_TAG_GET => TimerRequest::Get(GetTimerRequest {
            handle: decoder.handle()?,
        }),
        TIMER_REQUEST_TAG_READ => TimerRequest::Read(ReadTimerRequest {
            handle: decoder.handle()?,
        }),
        _ => return Err(WireError::InvalidTag),
    };

    Ok(request)
}

pub(super) fn encode_timer_response(encoder: &mut Encoder, response: TimerResponse) {
    match response {
        TimerResponse::Create(response) => {
            encoder.u8(TIMER_RESPONSE_TAG_CREATE);
            encoder.handle(response.handle);
        }
        TimerResponse::Set(response) => {
            encoder.u8(TIMER_RESPONSE_TAG_SET);
            encode_timer_spec(encoder, response.previous);
        }
        TimerResponse::Get(response) => {
            encoder.u8(TIMER_RESPONSE_TAG_GET);
            encode_timer_spec(encoder, response.current);
        }
        TimerResponse::Read(response) => {
            encoder.u8(TIMER_RESPONSE_TAG_READ);
            encoder.u64(response.expirations);
        }
    }
}

pub(super) fn decode_timer_response(decoder: &mut Decoder<'_>) -> Result<TimerResponse, WireError> {
    let response = match decoder.u8()? {
        TIMER_RESPONSE_TAG_CREATE => TimerResponse::Create(CreateTimerResponse {
            handle: decoder.handle()?,
        }),
        TIMER_RESPONSE_TAG_SET => TimerResponse::Set(SetTimerResponse {
            previous: decode_timer_spec(decoder)?,
        }),
        TIMER_RESPONSE_TAG_GET => TimerResponse::Get(GetTimerResponse {
            current: decode_timer_spec(decoder)?,
        }),
        TIMER_RESPONSE_TAG_READ => TimerResponse::Read(ReadTimerResponse {
            expirations: decoder.u64()?,
        }),
        _ => return Err(WireError::InvalidTag),
    };

    Ok(response)
}

fn encode_timer_spec(encoder: &mut Encoder, spec: TimerSpec) {
    encoder.u64(spec.value_ns);
    encoder.u64(spec.interval_ns);
}

fn decode_timer_spec(decoder: &mut Decoder<'_>) -> Result<TimerSpec, WireError> {
    Ok(TimerSpec {
        value_ns: decoder.u64()?,
        interval_ns: decoder.u64()?,
    })
}
