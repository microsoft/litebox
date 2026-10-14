// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{ReadinessQueueRequest, ReadinessQueueResponse};
use crate::readiness::ReadinessFlags;
use crate::readiness_queue::{
    AddReadinessQueueEntryRequest, CreateReadinessQueueResponse, ModifyReadinessQueueEntryRequest,
    ReadinessQueueEntryFlags, ReadinessQueueError, ReadinessQueueInterest,
    RemoveReadinessQueueEntryRequest, TakeReadyRequest, TakeReadyResponse,
};

use super::WireError;
use super::primitive::{Decoder, Encoder};

const READINESS_QUEUE_REQUEST_TAG_CREATE: u8 = 0;
const READINESS_QUEUE_REQUEST_TAG_ADD: u8 = 1;
const READINESS_QUEUE_REQUEST_TAG_MODIFY: u8 = 2;
const READINESS_QUEUE_REQUEST_TAG_REMOVE: u8 = 3;
const READINESS_QUEUE_REQUEST_TAG_TAKE_READY: u8 = 4;

const READINESS_QUEUE_RESPONSE_TAG_CREATE: u8 = 0;
const READINESS_QUEUE_RESPONSE_TAG_ADD: u8 = 1;
const READINESS_QUEUE_RESPONSE_TAG_MODIFY: u8 = 2;
const READINESS_QUEUE_RESPONSE_TAG_REMOVE: u8 = 3;
const READINESS_QUEUE_RESPONSE_TAG_TAKE_READY: u8 = 4;
const READINESS_QUEUE_RESPONSE_TAG_FAILED: u8 = 5;

const READINESS_QUEUE_ERROR_TAG_ALREADY_REGISTERED: u8 = 0;
const READINESS_QUEUE_ERROR_TAG_NOT_REGISTERED: u8 = 1;

pub(super) fn encode_readiness_queue_request(
    encoder: &mut Encoder,
    request: ReadinessQueueRequest,
) {
    match request {
        ReadinessQueueRequest::Create => encoder.u8(READINESS_QUEUE_REQUEST_TAG_CREATE),
        ReadinessQueueRequest::Add(request) => {
            encoder.u8(READINESS_QUEUE_REQUEST_TAG_ADD);
            encoder.handle(request.queue);
            encoder.handle(request.target);
            encoder.u64(request.key);
            encode_interest(encoder, request.interest);
        }
        ReadinessQueueRequest::Modify(request) => {
            encoder.u8(READINESS_QUEUE_REQUEST_TAG_MODIFY);
            encoder.handle(request.queue);
            encoder.handle(request.target);
            encoder.u64(request.key);
            encode_interest(encoder, request.interest);
        }
        ReadinessQueueRequest::Remove(request) => {
            encoder.u8(READINESS_QUEUE_REQUEST_TAG_REMOVE);
            encoder.handle(request.queue);
            encoder.handle(request.target);
            encoder.u64(request.key);
        }
        ReadinessQueueRequest::TakeReady(request) => {
            encoder.u8(READINESS_QUEUE_REQUEST_TAG_TAKE_READY);
            encoder.handle(request.queue);
            encoder.shared_buffer_sequence(request.buffer);
        }
    }
}

pub(super) fn decode_readiness_queue_request(
    decoder: &mut Decoder<'_>,
) -> Result<ReadinessQueueRequest, WireError> {
    let request = match decoder.u8()? {
        READINESS_QUEUE_REQUEST_TAG_CREATE => ReadinessQueueRequest::Create,
        READINESS_QUEUE_REQUEST_TAG_ADD => {
            ReadinessQueueRequest::Add(AddReadinessQueueEntryRequest {
                queue: decoder.handle()?,
                target: decoder.handle()?,
                key: decoder.u64()?,
                interest: decode_interest(decoder)?,
            })
        }
        READINESS_QUEUE_REQUEST_TAG_MODIFY => {
            ReadinessQueueRequest::Modify(ModifyReadinessQueueEntryRequest {
                queue: decoder.handle()?,
                target: decoder.handle()?,
                key: decoder.u64()?,
                interest: decode_interest(decoder)?,
            })
        }
        READINESS_QUEUE_REQUEST_TAG_REMOVE => {
            ReadinessQueueRequest::Remove(RemoveReadinessQueueEntryRequest {
                queue: decoder.handle()?,
                target: decoder.handle()?,
                key: decoder.u64()?,
            })
        }
        READINESS_QUEUE_REQUEST_TAG_TAKE_READY => {
            ReadinessQueueRequest::TakeReady(TakeReadyRequest {
                queue: decoder.handle()?,
                buffer: decoder.shared_buffer_sequence()?,
            })
        }
        _ => return Err(WireError::InvalidTag),
    };
    Ok(request)
}

pub(super) fn encode_readiness_queue_response(
    encoder: &mut Encoder,
    response: ReadinessQueueResponse,
) {
    match response {
        ReadinessQueueResponse::Create(response) => {
            encoder.u8(READINESS_QUEUE_RESPONSE_TAG_CREATE);
            encoder.handle(response.handle);
        }
        ReadinessQueueResponse::Add => encoder.u8(READINESS_QUEUE_RESPONSE_TAG_ADD),
        ReadinessQueueResponse::Modify => encoder.u8(READINESS_QUEUE_RESPONSE_TAG_MODIFY),
        ReadinessQueueResponse::Remove => encoder.u8(READINESS_QUEUE_RESPONSE_TAG_REMOVE),
        ReadinessQueueResponse::TakeReady(response) => {
            encoder.u8(READINESS_QUEUE_RESPONSE_TAG_TAKE_READY);
            encoder.u32(response.count);
        }
        ReadinessQueueResponse::Failed(error) => {
            encoder.u8(READINESS_QUEUE_RESPONSE_TAG_FAILED);
            encoder.u8(match error {
                ReadinessQueueError::AlreadyRegistered => {
                    READINESS_QUEUE_ERROR_TAG_ALREADY_REGISTERED
                }
                ReadinessQueueError::NotRegistered => READINESS_QUEUE_ERROR_TAG_NOT_REGISTERED,
            });
        }
    }
}

pub(super) fn decode_readiness_queue_response(
    decoder: &mut Decoder<'_>,
) -> Result<ReadinessQueueResponse, WireError> {
    let response = match decoder.u8()? {
        READINESS_QUEUE_RESPONSE_TAG_CREATE => {
            ReadinessQueueResponse::Create(CreateReadinessQueueResponse {
                handle: decoder.handle()?,
            })
        }
        READINESS_QUEUE_RESPONSE_TAG_ADD => ReadinessQueueResponse::Add,
        READINESS_QUEUE_RESPONSE_TAG_MODIFY => ReadinessQueueResponse::Modify,
        READINESS_QUEUE_RESPONSE_TAG_REMOVE => ReadinessQueueResponse::Remove,
        READINESS_QUEUE_RESPONSE_TAG_TAKE_READY => {
            ReadinessQueueResponse::TakeReady(TakeReadyResponse {
                count: decoder.u32()?,
            })
        }
        READINESS_QUEUE_RESPONSE_TAG_FAILED => {
            ReadinessQueueResponse::Failed(match decoder.u8()? {
                READINESS_QUEUE_ERROR_TAG_ALREADY_REGISTERED => {
                    ReadinessQueueError::AlreadyRegistered
                }
                READINESS_QUEUE_ERROR_TAG_NOT_REGISTERED => ReadinessQueueError::NotRegistered,
                _ => return Err(WireError::InvalidTag),
            })
        }
        _ => return Err(WireError::InvalidTag),
    };
    Ok(response)
}

fn encode_interest(encoder: &mut Encoder, interest: ReadinessQueueInterest) {
    encoder.u32(interest.readiness.0);
    encoder.u8(interest.flags.bits());
    encoder.u64(interest.token);
}

fn decode_interest(decoder: &mut Decoder<'_>) -> Result<ReadinessQueueInterest, WireError> {
    Ok(ReadinessQueueInterest {
        readiness: ReadinessFlags(decoder.u32()?),
        flags: ReadinessQueueEntryFlags::from_bits(decoder.u8()?).ok_or(WireError::InvalidTag)?,
        token: decoder.u64()?,
    })
}
