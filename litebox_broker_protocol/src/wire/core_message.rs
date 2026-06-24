// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::{CoreRequest, CoreResponse};

use super::WireError;
use super::primitive::{Decoder, Encoder};

// Core tags select object-family codecs. Add new object families here, then
// keep their operation-specific tags inside a dedicated family module.
const CORE_REQUEST_TAG_EVENT: u8 = 0;
const CORE_RESPONSE_TAG_EVENT: u8 = 0;

pub(super) fn encode_core_request(encoder: &mut Encoder, request: CoreRequest) {
    match request {
        CoreRequest::Event(request) => {
            encoder.u8(CORE_REQUEST_TAG_EVENT);
            super::event::encode_event_request(encoder, request);
        }
    }
}

pub(super) fn decode_core_request(decoder: &mut Decoder<'_>) -> Result<CoreRequest, WireError> {
    let request = match decoder.u8()? {
        CORE_REQUEST_TAG_EVENT => CoreRequest::Event(super::event::decode_event_request(decoder)?),
        _ => return Err(WireError::InvalidTag),
    };

    Ok(request)
}

pub(super) fn encode_core_response(encoder: &mut Encoder, response: CoreResponse) {
    match response {
        CoreResponse::Event(response) => {
            encoder.u8(CORE_RESPONSE_TAG_EVENT);
            super::event::encode_event_response(encoder, response);
        }
    }
}

pub(super) fn decode_core_response(decoder: &mut Decoder<'_>) -> Result<CoreResponse, WireError> {
    let response = match decoder.u8()? {
        CORE_RESPONSE_TAG_EVENT => {
            CoreResponse::Event(super::event::decode_event_response(decoder)?)
        }
        _ => return Err(WireError::InvalidTag),
    };

    Ok(response)
}
