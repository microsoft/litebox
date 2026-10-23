// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{SharedMemoryRequest, SharedMemoryResponse};
use crate::shared_memory::{
    CreateFutexWaiterResponse, CreateSharedMemoryRequest, CreateSharedMemoryResponse,
    FutexArmRequest, FutexDisarmRequest, FutexDisarmResponse, FutexWakeRequest, FutexWakeResponse,
};

use super::WireError;
use super::primitive::{Decoder, Encoder};

const SHARED_MEMORY_REQUEST_TAG_CREATE: u8 = 0;
const SHARED_MEMORY_REQUEST_TAG_CREATE_FUTEX_WAITER: u8 = 1;
const SHARED_MEMORY_REQUEST_TAG_FUTEX_ARM: u8 = 2;
const SHARED_MEMORY_REQUEST_TAG_FUTEX_WAKE: u8 = 3;
const SHARED_MEMORY_REQUEST_TAG_FUTEX_DISARM: u8 = 4;

const SHARED_MEMORY_RESPONSE_TAG_CREATE: u8 = 0;
const SHARED_MEMORY_RESPONSE_TAG_CREATE_FUTEX_WAITER: u8 = 1;
const SHARED_MEMORY_RESPONSE_TAG_FUTEX_ARM: u8 = 2;
const SHARED_MEMORY_RESPONSE_TAG_FUTEX_WAKE: u8 = 3;
const SHARED_MEMORY_RESPONSE_TAG_FUTEX_DISARM: u8 = 4;

pub(super) fn encode_shared_memory_request(encoder: &mut Encoder, request: SharedMemoryRequest) {
    match request {
        SharedMemoryRequest::Create(request) => {
            encoder.u8(SHARED_MEMORY_REQUEST_TAG_CREATE);
            encoder.u64(request.length);
        }
        SharedMemoryRequest::CreateFutexWaiter => {
            encoder.u8(SHARED_MEMORY_REQUEST_TAG_CREATE_FUTEX_WAITER);
        }
        SharedMemoryRequest::FutexArm(request) => {
            encoder.u8(SHARED_MEMORY_REQUEST_TAG_FUTEX_ARM);
            encoder.handle(request.memory);
            encoder.u64(request.offset);
            encoder.u32(request.bitset);
            encoder.handle(request.waiter);
        }
        SharedMemoryRequest::FutexWake(request) => {
            encoder.u8(SHARED_MEMORY_REQUEST_TAG_FUTEX_WAKE);
            encoder.handle(request.memory);
            encoder.u64(request.offset);
            encoder.u32(request.count);
            encoder.u32(request.bitset);
        }
        SharedMemoryRequest::FutexDisarm(request) => {
            encoder.u8(SHARED_MEMORY_REQUEST_TAG_FUTEX_DISARM);
            encoder.handle(request.waiter);
        }
    }
}

pub(super) fn decode_shared_memory_request(
    decoder: &mut Decoder<'_>,
) -> Result<SharedMemoryRequest, WireError> {
    Ok(match decoder.u8()? {
        SHARED_MEMORY_REQUEST_TAG_CREATE => {
            SharedMemoryRequest::Create(CreateSharedMemoryRequest {
                length: decoder.u64()?,
            })
        }
        SHARED_MEMORY_REQUEST_TAG_CREATE_FUTEX_WAITER => SharedMemoryRequest::CreateFutexWaiter,
        SHARED_MEMORY_REQUEST_TAG_FUTEX_ARM => SharedMemoryRequest::FutexArm(FutexArmRequest {
            memory: decoder.handle()?,
            offset: decoder.u64()?,
            bitset: decoder.u32()?,
            waiter: decoder.handle()?,
        }),
        SHARED_MEMORY_REQUEST_TAG_FUTEX_WAKE => SharedMemoryRequest::FutexWake(FutexWakeRequest {
            memory: decoder.handle()?,
            offset: decoder.u64()?,
            count: decoder.u32()?,
            bitset: decoder.u32()?,
        }),
        SHARED_MEMORY_REQUEST_TAG_FUTEX_DISARM => {
            SharedMemoryRequest::FutexDisarm(FutexDisarmRequest {
                waiter: decoder.handle()?,
            })
        }
        _ => return Err(WireError::InvalidTag),
    })
}

pub(super) fn encode_shared_memory_response(encoder: &mut Encoder, response: SharedMemoryResponse) {
    match response {
        SharedMemoryResponse::Create(response) => {
            encoder.u8(SHARED_MEMORY_RESPONSE_TAG_CREATE);
            encoder.handle(response.handle);
        }
        SharedMemoryResponse::CreateFutexWaiter(response) => {
            encoder.u8(SHARED_MEMORY_RESPONSE_TAG_CREATE_FUTEX_WAITER);
            encoder.handle(response.handle);
        }
        SharedMemoryResponse::FutexArm => {
            encoder.u8(SHARED_MEMORY_RESPONSE_TAG_FUTEX_ARM);
        }
        SharedMemoryResponse::FutexWake(response) => {
            encoder.u8(SHARED_MEMORY_RESPONSE_TAG_FUTEX_WAKE);
            encoder.u32(response.woken);
        }
        SharedMemoryResponse::FutexDisarm(response) => {
            encoder.u8(SHARED_MEMORY_RESPONSE_TAG_FUTEX_DISARM);
            super::socket::encode_bool(encoder, response.woken);
        }
    }
}

pub(super) fn decode_shared_memory_response(
    decoder: &mut Decoder<'_>,
) -> Result<SharedMemoryResponse, WireError> {
    Ok(match decoder.u8()? {
        SHARED_MEMORY_RESPONSE_TAG_CREATE => {
            SharedMemoryResponse::Create(CreateSharedMemoryResponse {
                handle: decoder.handle()?,
            })
        }
        SHARED_MEMORY_RESPONSE_TAG_CREATE_FUTEX_WAITER => {
            SharedMemoryResponse::CreateFutexWaiter(CreateFutexWaiterResponse {
                handle: decoder.handle()?,
            })
        }
        SHARED_MEMORY_RESPONSE_TAG_FUTEX_ARM => SharedMemoryResponse::FutexArm,
        SHARED_MEMORY_RESPONSE_TAG_FUTEX_WAKE => {
            SharedMemoryResponse::FutexWake(FutexWakeResponse {
                woken: decoder.u32()?,
            })
        }
        SHARED_MEMORY_RESPONSE_TAG_FUTEX_DISARM => {
            SharedMemoryResponse::FutexDisarm(FutexDisarmResponse {
                woken: super::socket::decode_bool(decoder)?,
            })
        }
        _ => return Err(WireError::InvalidTag),
    })
}
