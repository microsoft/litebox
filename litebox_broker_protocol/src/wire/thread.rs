// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{ThreadRequest, ThreadResponse};
use crate::process::CreateThreadRequest;

use super::WireError;
use super::primitive::{Decoder, Encoder};
use super::socket::{decode_bool, encode_bool};

const THREAD_REQUEST_TAG_CREATE: u8 = 0;
const THREAD_REQUEST_TAG_EXIT: u8 = 1;
const THREAD_REQUEST_TAG_MOVE_TO_INITIAL: u8 = 2;

const THREAD_RESPONSE_TAG_CREATE: u8 = 0;
const THREAD_RESPONSE_TAG_EXIT: u8 = 1;
const THREAD_RESPONSE_TAG_MOVE_TO_INITIAL: u8 = 2;

pub(super) fn encode_thread_request(encoder: &mut Encoder, request: ThreadRequest) {
    match request {
        ThreadRequest::Create(CreateThreadRequest { creator, share_fs }) => {
            encoder.u8(THREAD_REQUEST_TAG_CREATE);
            match creator {
                Some(thread_id) => {
                    encoder.u8(1);
                    encoder.thread_id(thread_id);
                }
                None => encoder.u8(0),
            }
            encode_bool(encoder, share_fs);
        }
        ThreadRequest::Exit(thread_id) => {
            encoder.u8(THREAD_REQUEST_TAG_EXIT);
            encoder.thread_id(thread_id);
        }
        ThreadRequest::MoveToInitial(thread_id) => {
            encoder.u8(THREAD_REQUEST_TAG_MOVE_TO_INITIAL);
            encoder.thread_id(thread_id);
        }
    }
}

pub(super) fn decode_thread_request(decoder: &mut Decoder<'_>) -> Result<ThreadRequest, WireError> {
    Ok(match decoder.u8()? {
        THREAD_REQUEST_TAG_CREATE => ThreadRequest::Create(CreateThreadRequest {
            creator: match decoder.u8()? {
                0 => None,
                1 => Some(decoder.thread_id()?),
                _ => return Err(WireError::InvalidTag),
            },
            share_fs: decode_bool(decoder)?,
        }),
        THREAD_REQUEST_TAG_EXIT => ThreadRequest::Exit(decoder.thread_id()?),
        THREAD_REQUEST_TAG_MOVE_TO_INITIAL => ThreadRequest::MoveToInitial(decoder.thread_id()?),
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
        ThreadResponse::MoveToInitial => encoder.u8(THREAD_RESPONSE_TAG_MOVE_TO_INITIAL),
    }
}

pub(super) fn decode_thread_response(
    decoder: &mut Decoder<'_>,
) -> Result<ThreadResponse, WireError> {
    Ok(match decoder.u8()? {
        THREAD_RESPONSE_TAG_CREATE => ThreadResponse::Create(decoder.thread_id()?),
        THREAD_RESPONSE_TAG_EXIT => ThreadResponse::Exit,
        THREAD_RESPONSE_TAG_MOVE_TO_INITIAL => ThreadResponse::MoveToInitial,
        _ => return Err(WireError::InvalidTag),
    })
}
