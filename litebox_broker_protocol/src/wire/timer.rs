// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{TimerRequest, TimerResponse};
use crate::readiness::ReadinessFlags;
use crate::timer::{
    CreateTimerRequest, CreateTimerResponse, GetTimerRequest, GetTimerResponse, ReadTimerRequest,
    ReadTimerResponse, SetTimerRequest, SetTimerResponse, TimerSpec,
};

use super::WireError;
use super::primitive::{Decoder, Encoder};

// Timer operation tags live with the timerfd family. Future timerfd
// operations should add tags here; unrelated object families get their own
// module.
const TIMERFD_REQUEST_TAG_CREATE: u8 = 0;
const TIMERFD_REQUEST_TAG_SET: u8 = 1;
const TIMERFD_REQUEST_TAG_GET: u8 = 2;
const TIMERFD_REQUEST_TAG_READ: u8 = 3;

const TIMERFD_RESPONSE_TAG_CREATE: u8 = 0;
const TIMERFD_RESPONSE_TAG_SET: u8 = 1;
const TIMERFD_RESPONSE_TAG_GET: u8 = 2;
const TIMERFD_RESPONSE_TAG_READ: u8 = 3;

fn encode_spec(encoder: &mut Encoder, spec: TimerSpec) {
    encoder.u64(spec.value_seconds);
    encoder.u64(spec.value_nanoseconds);
    encoder.u64(spec.interval_seconds);
    encoder.u64(spec.interval_nanoseconds);
}

fn decode_spec(decoder: &mut Decoder<'_>) -> Result<TimerSpec, WireError> {
    Ok(TimerSpec {
        value_seconds: decoder.u64()?,
        value_nanoseconds: decoder.u64()?,
        interval_seconds: decoder.u64()?,
        interval_nanoseconds: decoder.u64()?,
    })
}

pub(super) fn encode_timer_request(encoder: &mut Encoder, request: TimerRequest) {
    match request {
        TimerRequest::Create(request) => {
            encoder.u8(TIMERFD_REQUEST_TAG_CREATE);
            encoder.u32(request.clock_id.cast_unsigned());
        }
        TimerRequest::Set(request) => {
            encoder.u8(TIMERFD_REQUEST_TAG_SET);
            encoder.handle(request.handle);
            encoder.u32(request.flags);
            encode_spec(encoder, request.specification);
        }
        TimerRequest::Get(request) => {
            encoder.u8(TIMERFD_REQUEST_TAG_GET);
            encoder.handle(request.handle);
        }
        TimerRequest::Read(request) => {
            encoder.u8(TIMERFD_REQUEST_TAG_READ);
            encoder.handle(request.handle);
        }
    }
}

pub(super) fn decode_timer_request(decoder: &mut Decoder<'_>) -> Result<TimerRequest, WireError> {
    let request = match decoder.u8()? {
        TIMERFD_REQUEST_TAG_CREATE => TimerRequest::Create(CreateTimerRequest {
            clock_id: decoder.u32()?.cast_signed(),
        }),
        TIMERFD_REQUEST_TAG_SET => {
            let handle = decoder.handle()?;
            let flags = decoder.u32()?;
            TimerRequest::Set(SetTimerRequest {
                handle,
                flags,
                specification: decode_spec(decoder)?,
            })
        }
        TIMERFD_REQUEST_TAG_GET => TimerRequest::Get(GetTimerRequest {
            handle: decoder.handle()?,
        }),
        TIMERFD_REQUEST_TAG_READ => TimerRequest::Read(ReadTimerRequest {
            handle: decoder.handle()?,
        }),
        _ => return Err(WireError::InvalidTag),
    };

    Ok(request)
}

pub(super) fn encode_timer_response(encoder: &mut Encoder, response: TimerResponse) {
    match response {
        TimerResponse::Create(response) => {
            encoder.u8(TIMERFD_RESPONSE_TAG_CREATE);
            encoder.handle(response.handle);
        }
        TimerResponse::Set(response) => {
            encoder.u8(TIMERFD_RESPONSE_TAG_SET);
            encoder.u32(response.readiness.0);
            encode_spec(encoder, response.previous);
        }
        TimerResponse::Get(response) => {
            encoder.u8(TIMERFD_RESPONSE_TAG_GET);
            encode_spec(encoder, response.current);
        }
        TimerResponse::Read(response) => {
            encoder.u8(TIMERFD_RESPONSE_TAG_READ);
            encoder.u64(response.expirations);
            encoder.u8(u8::from(response.cancelled));
            encoder.u32(response.readiness.0);
        }
    }
}

pub(super) fn decode_timer_response(decoder: &mut Decoder<'_>) -> Result<TimerResponse, WireError> {
    let response = match decoder.u8()? {
        TIMERFD_RESPONSE_TAG_CREATE => TimerResponse::Create(CreateTimerResponse {
            handle: decoder.handle()?,
        }),
        TIMERFD_RESPONSE_TAG_SET => {
            let readiness = ReadinessFlags(decoder.u32()?);
            TimerResponse::Set(SetTimerResponse {
                readiness,
                previous: decode_spec(decoder)?,
            })
        }
        TIMERFD_RESPONSE_TAG_GET => TimerResponse::Get(GetTimerResponse {
            current: decode_spec(decoder)?,
        }),
        TIMERFD_RESPONSE_TAG_READ => TimerResponse::Read(ReadTimerResponse {
            expirations: decoder.u64()?,
            cancelled: decoder.u8()? != 0,
            readiness: ReadinessFlags(decoder.u32()?),
        }),
        _ => return Err(WireError::InvalidTag),
    };

    Ok(response)
}
