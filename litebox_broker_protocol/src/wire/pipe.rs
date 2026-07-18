// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{PipeRequest, PipeResponse};
use crate::pipe::{
    CreatePipeRequest, CreatePipeResponse, ReadPipeRequest, ReadPipeResponse, WritePipeRequest,
    WritePipeResponse,
};

use super::WireError;
use super::primitive::{Decoder, Encoder};

const PIPE_REQUEST_TAG_CREATE: u8 = 0;
const PIPE_REQUEST_TAG_READ: u8 = 1;
const PIPE_REQUEST_TAG_WRITE: u8 = 2;

const PIPE_RESPONSE_TAG_CREATED: u8 = 0;
const PIPE_RESPONSE_TAG_READ: u8 = 1;
const PIPE_RESPONSE_TAG_WRITTEN: u8 = 2;

pub(super) fn encode_pipe_request(encoder: &mut Encoder, request: PipeRequest) {
    match request {
        PipeRequest::Create(request) => {
            encoder.u8(PIPE_REQUEST_TAG_CREATE);
            encoder.u64(request.capacity);
            encoder.u64(request.atomic_write_size);
        }
        PipeRequest::Read(request) => {
            encoder.u8(PIPE_REQUEST_TAG_READ);
            encoder.handle(request.handle);
            encoder.u32(request.length);
        }
        PipeRequest::Write(request) => {
            encoder.u8(PIPE_REQUEST_TAG_WRITE);
            encoder.handle(request.handle);
            encoder.bytes(&request.data);
        }
    }
}

pub(super) fn decode_pipe_request(decoder: &mut Decoder<'_>) -> Result<PipeRequest, WireError> {
    match decoder.u8()? {
        PIPE_REQUEST_TAG_CREATE => Ok(PipeRequest::Create(CreatePipeRequest {
            capacity: decoder.u64()?,
            atomic_write_size: decoder.u64()?,
        })),
        PIPE_REQUEST_TAG_READ => Ok(PipeRequest::Read(ReadPipeRequest {
            handle: decoder.handle()?,
            length: decoder.u32()?,
        })),
        PIPE_REQUEST_TAG_WRITE => Ok(PipeRequest::Write(WritePipeRequest {
            handle: decoder.handle()?,
            data: decoder.bytes()?,
        })),
        _ => Err(WireError::InvalidTag),
    }
}

pub(super) fn encode_pipe_response(encoder: &mut Encoder, response: PipeResponse) {
    match response {
        PipeResponse::Create(response) => {
            encoder.u8(PIPE_RESPONSE_TAG_CREATED);
            encoder.handle(response.read_handle);
            encoder.handle(response.write_handle);
        }
        PipeResponse::Read(response) => {
            encoder.u8(PIPE_RESPONSE_TAG_READ);
            encoder.bytes(&response.data);
        }
        PipeResponse::Write(response) => {
            encoder.u8(PIPE_RESPONSE_TAG_WRITTEN);
            encoder.u32(response.written);
        }
    }
}

pub(super) fn decode_pipe_response(decoder: &mut Decoder<'_>) -> Result<PipeResponse, WireError> {
    match decoder.u8()? {
        PIPE_RESPONSE_TAG_CREATED => Ok(PipeResponse::Create(CreatePipeResponse {
            read_handle: decoder.handle()?,
            write_handle: decoder.handle()?,
        })),
        PIPE_RESPONSE_TAG_READ => Ok(PipeResponse::Read(ReadPipeResponse {
            data: decoder.bytes()?,
        })),
        PIPE_RESPONSE_TAG_WRITTEN => Ok(PipeResponse::Write(WritePipeResponse {
            written: decoder.u32()?,
        })),
        _ => Err(WireError::InvalidTag),
    }
}
