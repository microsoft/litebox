// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{SignalRequest, SignalResponse};
use crate::signal::{OpenSignalsResponse, PendingSignal, SendSignalRequest, TakeSignalRequest};

use super::WireError;
use super::primitive::{Decoder, Encoder};

const SIGNAL_REQUEST_TAG_OPEN: u8 = 0;
const SIGNAL_REQUEST_TAG_SEND: u8 = 1;
const SIGNAL_REQUEST_TAG_TAKE: u8 = 2;

const SIGNAL_RESPONSE_TAG_OPEN: u8 = 0;
const SIGNAL_RESPONSE_TAG_SENT: u8 = 1;
const SIGNAL_RESPONSE_TAG_TAKE: u8 = 2;

pub(super) fn encode_signal_request(encoder: &mut Encoder, request: SignalRequest) {
    match request {
        SignalRequest::Open => encoder.u8(SIGNAL_REQUEST_TAG_OPEN),
        SignalRequest::Send(request) => {
            encoder.u8(SIGNAL_REQUEST_TAG_SEND);
            encoder.process_id(request.process_id);
            encoder.u32(request.signal);
        }
        SignalRequest::Take(request) => {
            encoder.u8(SIGNAL_REQUEST_TAG_TAKE);
            encoder.handle(request.handle);
        }
    }
}

pub(super) fn decode_signal_request(decoder: &mut Decoder<'_>) -> Result<SignalRequest, WireError> {
    Ok(match decoder.u8()? {
        SIGNAL_REQUEST_TAG_OPEN => SignalRequest::Open,
        SIGNAL_REQUEST_TAG_SEND => SignalRequest::Send(SendSignalRequest {
            process_id: decoder.process_id()?,
            signal: decoder.u32()?,
        }),
        SIGNAL_REQUEST_TAG_TAKE => SignalRequest::Take(TakeSignalRequest {
            handle: decoder.handle()?,
        }),
        _ => return Err(WireError::InvalidTag),
    })
}

pub(super) fn encode_signal_response(encoder: &mut Encoder, response: SignalResponse) {
    match response {
        SignalResponse::Open(response) => {
            encoder.u8(SIGNAL_RESPONSE_TAG_OPEN);
            encoder.handle(response.handle);
        }
        SignalResponse::Sent => encoder.u8(SIGNAL_RESPONSE_TAG_SENT),
        SignalResponse::Take(response) => {
            encoder.u8(SIGNAL_RESPONSE_TAG_TAKE);
            encoder.u32(response.signal);
            encoder.process_id(response.sender);
        }
    }
}

pub(super) fn decode_signal_response(
    decoder: &mut Decoder<'_>,
) -> Result<SignalResponse, WireError> {
    Ok(match decoder.u8()? {
        SIGNAL_RESPONSE_TAG_OPEN => SignalResponse::Open(OpenSignalsResponse {
            handle: decoder.handle()?,
        }),
        SIGNAL_RESPONSE_TAG_SENT => SignalResponse::Sent,
        SIGNAL_RESPONSE_TAG_TAKE => SignalResponse::Take(PendingSignal {
            signal: decoder.u32()?,
            sender: decoder.process_id()?,
        }),
        _ => return Err(WireError::InvalidTag),
    })
}
