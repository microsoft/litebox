// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::WireError;
use super::primitive::{Decoder, Encoder};
use crate::message::{PipeRequest, PipeResponse};
use crate::pipe::{
    CreatePipeRequest, CreatePipeResponse, ReadPipeRequest, ReadPipeResponse, ReopenPipeRequest,
    ReopenPipeResponse, WritePipeRequest, WritePipeResponse,
};

const PIPE_REQUEST_TAG_CREATE: u8 = 0;
const PIPE_REQUEST_TAG_READ: u8 = 1;
const PIPE_REQUEST_TAG_WRITE: u8 = 2;
const PIPE_REQUEST_TAG_REOPEN: u8 = 3;

const PIPE_RESPONSE_TAG_CREATE: u8 = 0;
const PIPE_RESPONSE_TAG_READ: u8 = 1;
const PIPE_RESPONSE_TAG_WRITE: u8 = 2;
const PIPE_RESPONSE_TAG_REOPEN: u8 = 3;

pub(super) fn encode_pipe_request(encoder: &mut Encoder, request: PipeRequest) {
    match request {
        PipeRequest::Create(request) => {
            encoder.u8(PIPE_REQUEST_TAG_CREATE);
            encoder.u64(request.capacity);
            encoder.u64(request.atomic_write_size);
            encoder.u16(request.flags.bits());
        }
        PipeRequest::Read(request) => {
            encoder.u8(PIPE_REQUEST_TAG_READ);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.buffer);
        }
        PipeRequest::Reopen(request) => {
            encoder.u8(PIPE_REQUEST_TAG_REOPEN);
            encoder.handle(request.handle);
            super::fs::encode_access_mode(encoder, request.access);
            encoder.u16(request.flags.bits());
        }
        PipeRequest::Write(request) => {
            encoder.u8(PIPE_REQUEST_TAG_WRITE);
            encoder.handle(request.handle);
            encoder.shared_buffer_sequence(request.buffer);
        }
    }
}

pub(super) fn decode_pipe_request(decoder: &mut Decoder<'_>) -> Result<PipeRequest, WireError> {
    match decoder.u8()? {
        PIPE_REQUEST_TAG_CREATE => Ok(PipeRequest::Create(CreatePipeRequest {
            capacity: decoder.u64()?,
            atomic_write_size: decoder.u64()?,
            flags: super::fs::decode_open_flags(decoder)?,
        })),
        PIPE_REQUEST_TAG_READ => Ok(PipeRequest::Read(ReadPipeRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_sequence()?,
        })),
        PIPE_REQUEST_TAG_WRITE => Ok(PipeRequest::Write(WritePipeRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_sequence()?,
        })),
        PIPE_REQUEST_TAG_REOPEN => Ok(PipeRequest::Reopen(ReopenPipeRequest {
            handle: decoder.handle()?,
            access: super::fs::decode_access_mode(decoder)?,
            flags: super::fs::decode_open_flags(decoder)?,
        })),
        _ => Err(WireError::InvalidTag),
    }
}

pub(super) fn encode_pipe_response(encoder: &mut Encoder, response: PipeResponse) {
    match response {
        PipeResponse::Create(response) => {
            encoder.u8(PIPE_RESPONSE_TAG_CREATE);
            encoder.handle(response.read_handle);
            encoder.handle(response.write_handle);
        }
        PipeResponse::Read(response) => {
            encoder.u8(PIPE_RESPONSE_TAG_READ);
            encoder.u32(response.read);
        }
        PipeResponse::Reopen(response) => {
            encoder.u8(PIPE_RESPONSE_TAG_REOPEN);
            encoder.handle(response.handle);
        }
        PipeResponse::Write(response) => {
            encoder.u8(PIPE_RESPONSE_TAG_WRITE);
            encoder.u32(response.written);
        }
    }
}

pub(super) fn decode_pipe_response(decoder: &mut Decoder<'_>) -> Result<PipeResponse, WireError> {
    match decoder.u8()? {
        PIPE_RESPONSE_TAG_CREATE => Ok(PipeResponse::Create(CreatePipeResponse {
            read_handle: decoder.handle()?,
            write_handle: decoder.handle()?,
        })),
        PIPE_RESPONSE_TAG_READ => Ok(PipeResponse::Read(ReadPipeResponse {
            read: decoder.u32()?,
        })),
        PIPE_RESPONSE_TAG_WRITE => Ok(PipeResponse::Write(WritePipeResponse {
            written: decoder.u32()?,
        })),
        PIPE_RESPONSE_TAG_REOPEN => Ok(PipeResponse::Reopen(ReopenPipeResponse {
            handle: decoder.handle()?,
        })),
        _ => Err(WireError::InvalidTag),
    }
}
