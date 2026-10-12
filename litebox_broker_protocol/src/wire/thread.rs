// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{ThreadRequest, ThreadResponse};

use super::WireError;
use super::primitive::{Decoder, Encoder};

const THREAD_REQUEST_TAG_CREATE: u8 = 0;
const THREAD_REQUEST_TAG_EXIT: u8 = 1;

const THREAD_RESPONSE_TAG_CREATE: u8 = 0;
const THREAD_RESPONSE_TAG_EXIT: u8 = 1;

pub(super) fn encode_thread_request(encoder: &mut Encoder, request: ThreadRequest) {
    match request {
        ThreadRequest::Create => encoder.u8(THREAD_REQUEST_TAG_CREATE),
        ThreadRequest::Exit(thread_id) => {
            encoder.u8(THREAD_REQUEST_TAG_EXIT);
            encoder.thread_id(thread_id);
        }
    }
}

pub(super) fn decode_thread_request(decoder: &mut Decoder<'_>) -> Result<ThreadRequest, WireError> {
    Ok(match decoder.u8()? {
        THREAD_REQUEST_TAG_CREATE => ThreadRequest::Create,
        THREAD_REQUEST_TAG_EXIT => ThreadRequest::Exit(decoder.thread_id()?),
        _ => return Err(WireError::InvalidTag),
    })
}

pub(super) fn encode_thread_response(encoder: &mut Encoder, response: ThreadResponse) {
    match response {
        ThreadResponse::Create(thread_id) => {
            encoder.u8(THREAD_RESPONSE_TAG_CREATE);
            encoder.thread_id(thread_id);
        }
        ThreadResponse::Exit => encoder.u8(THREAD_RESPONSE_TAG_EXIT),
    }
}

pub(super) fn decode_thread_response(
    decoder: &mut Decoder<'_>,
) -> Result<ThreadResponse, WireError> {
    Ok(match decoder.u8()? {
        THREAD_RESPONSE_TAG_CREATE => ThreadResponse::Create(decoder.thread_id()?),
        THREAD_RESPONSE_TAG_EXIT => ThreadResponse::Exit,
        _ => return Err(WireError::InvalidTag),
    })
}
