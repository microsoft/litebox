// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{SharedFutexRequest, SharedFutexResponse};
use crate::shared_futex::{
    CreateFutexWaiterResponse, CreateSharedMemoryResponse, FutexArmRequest, FutexDisarmRequest,
    FutexDisarmResponse, FutexWakeRequest, FutexWakeResponse, SharedFutexKey, SharedMemoryId,
};

use super::WireError;
use super::primitive::{Decoder, Encoder};

const SHARED_FUTEX_REQUEST_TAG_CREATE_MEMORY: u8 = 0;
const SHARED_FUTEX_REQUEST_TAG_CREATE_WAITER: u8 = 1;
const SHARED_FUTEX_REQUEST_TAG_ARM: u8 = 2;
const SHARED_FUTEX_REQUEST_TAG_WAKE: u8 = 3;
const SHARED_FUTEX_REQUEST_TAG_DISARM: u8 = 4;

const SHARED_FUTEX_RESPONSE_TAG_CREATE_MEMORY: u8 = 0;
const SHARED_FUTEX_RESPONSE_TAG_CREATE_WAITER: u8 = 1;
const SHARED_FUTEX_RESPONSE_TAG_ARM: u8 = 2;
const SHARED_FUTEX_RESPONSE_TAG_WAKE: u8 = 3;
const SHARED_FUTEX_RESPONSE_TAG_DISARM: u8 = 4;

fn encode_key(encoder: &mut Encoder, key: SharedFutexKey) {
    encoder.u128(key.memory.0);
    encoder.u64(key.offset);
}

fn decode_key(decoder: &mut Decoder<'_>) -> Result<SharedFutexKey, WireError> {
    Ok(SharedFutexKey {
        memory: SharedMemoryId(decoder.u128()?),
        offset: decoder.u64()?,
    })
}

pub(super) fn encode_shared_futex_request(encoder: &mut Encoder, request: SharedFutexRequest) {
    match request {
        SharedFutexRequest::CreateMemory => {
            encoder.u8(SHARED_FUTEX_REQUEST_TAG_CREATE_MEMORY);
        }
        SharedFutexRequest::CreateWaiter => {
            encoder.u8(SHARED_FUTEX_REQUEST_TAG_CREATE_WAITER);
        }
        SharedFutexRequest::Arm(request) => {
            encoder.u8(SHARED_FUTEX_REQUEST_TAG_ARM);
            encode_key(encoder, request.key);
            encoder.u32(request.bitset);
            encoder.handle(request.waiter);
        }
        SharedFutexRequest::Wake(request) => {
            encoder.u8(SHARED_FUTEX_REQUEST_TAG_WAKE);
            encode_key(encoder, request.key);
            encoder.u32(request.count);
            encoder.u32(request.bitset);
        }
        SharedFutexRequest::Disarm(request) => {
            encoder.u8(SHARED_FUTEX_REQUEST_TAG_DISARM);
            encoder.handle(request.waiter);
        }
    }
}

pub(super) fn decode_shared_futex_request(
    decoder: &mut Decoder<'_>,
) -> Result<SharedFutexRequest, WireError> {
    Ok(match decoder.u8()? {
        SHARED_FUTEX_REQUEST_TAG_CREATE_MEMORY => SharedFutexRequest::CreateMemory,
        SHARED_FUTEX_REQUEST_TAG_CREATE_WAITER => SharedFutexRequest::CreateWaiter,
        SHARED_FUTEX_REQUEST_TAG_ARM => SharedFutexRequest::Arm(FutexArmRequest {
            key: decode_key(decoder)?,
            bitset: decoder.u32()?,
            waiter: decoder.handle()?,
        }),
        SHARED_FUTEX_REQUEST_TAG_WAKE => SharedFutexRequest::Wake(FutexWakeRequest {
            key: decode_key(decoder)?,
            count: decoder.u32()?,
            bitset: decoder.u32()?,
        }),
        SHARED_FUTEX_REQUEST_TAG_DISARM => SharedFutexRequest::Disarm(FutexDisarmRequest {
            waiter: decoder.handle()?,
        }),
        _ => return Err(WireError::InvalidTag),
    })
}

pub(super) fn encode_shared_futex_response(encoder: &mut Encoder, response: SharedFutexResponse) {
    match response {
        SharedFutexResponse::CreateMemory(response) => {
            encoder.u8(SHARED_FUTEX_RESPONSE_TAG_CREATE_MEMORY);
            encoder.u128(response.memory.0);
        }
        SharedFutexResponse::CreateWaiter(response) => {
            encoder.u8(SHARED_FUTEX_RESPONSE_TAG_CREATE_WAITER);
            encoder.handle(response.handle);
        }
        SharedFutexResponse::Arm => {
            encoder.u8(SHARED_FUTEX_RESPONSE_TAG_ARM);
        }
        SharedFutexResponse::Wake(response) => {
            encoder.u8(SHARED_FUTEX_RESPONSE_TAG_WAKE);
            encoder.u32(response.woken);
        }
        SharedFutexResponse::Disarm(response) => {
            encoder.u8(SHARED_FUTEX_RESPONSE_TAG_DISARM);
            super::socket::encode_bool(encoder, response.woken);
        }
    }
}

pub(super) fn decode_shared_futex_response(
    decoder: &mut Decoder<'_>,
) -> Result<SharedFutexResponse, WireError> {
    Ok(match decoder.u8()? {
        SHARED_FUTEX_RESPONSE_TAG_CREATE_MEMORY => {
            SharedFutexResponse::CreateMemory(CreateSharedMemoryResponse {
                memory: SharedMemoryId(decoder.u128()?),
            })
        }
        SHARED_FUTEX_RESPONSE_TAG_CREATE_WAITER => {
            SharedFutexResponse::CreateWaiter(CreateFutexWaiterResponse {
                handle: decoder.handle()?,
            })
        }
        SHARED_FUTEX_RESPONSE_TAG_ARM => SharedFutexResponse::Arm,
        SHARED_FUTEX_RESPONSE_TAG_WAKE => SharedFutexResponse::Wake(FutexWakeResponse {
            woken: decoder.u32()?,
        }),
        SHARED_FUTEX_RESPONSE_TAG_DISARM => SharedFutexResponse::Disarm(FutexDisarmResponse {
            woken: super::socket::decode_bool(decoder)?,
        }),
        _ => return Err(WireError::InvalidTag),
    })
}
