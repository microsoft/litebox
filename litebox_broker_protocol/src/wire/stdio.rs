// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{StdioRequest, StdioResponse};
use crate::stdio::{
    ReadStdioRequest, ReadStdioResponse, StdioOutputStream, WriteStdioRequest, WriteStdioResponse,
};

use super::{
    WireError,
    primitive::{Decoder, Encoder},
};

const REQUEST_TAG_READ: u8 = 0;
const REQUEST_TAG_WRITE: u8 = 1;
const RESPONSE_TAG_READ: u8 = 0;
const RESPONSE_TAG_WRITE: u8 = 1;

const OUTPUT_STREAM_TAG_STDOUT: u8 = 0;
const OUTPUT_STREAM_TAG_STDERR: u8 = 1;

pub(super) fn encode_stdio_request(encoder: &mut Encoder, request: StdioRequest) {
    match request {
        StdioRequest::Read(request) => {
            encoder.u8(REQUEST_TAG_READ);
            encoder.shared_buffer_descriptor(request.buffer);
        }
        StdioRequest::Write(request) => {
            encoder.u8(REQUEST_TAG_WRITE);
            encode_output_stream(encoder, request.stream);
            encoder.shared_buffer_descriptor(request.buffer);
        }
    }
}

pub(super) fn decode_stdio_request(decoder: &mut Decoder<'_>) -> Result<StdioRequest, WireError> {
    match decoder.u8()? {
        REQUEST_TAG_READ => Ok(StdioRequest::Read(ReadStdioRequest {
            buffer: decoder.shared_buffer_descriptor()?,
        })),
        REQUEST_TAG_WRITE => Ok(StdioRequest::Write(WriteStdioRequest {
            stream: decode_output_stream(decoder)?,
            buffer: decoder.shared_buffer_descriptor()?,
        })),
        _ => Err(WireError::InvalidTag),
    }
}

pub(super) fn encode_stdio_response(encoder: &mut Encoder, response: StdioResponse) {
    match response {
        StdioResponse::Read(response) => {
            encoder.u8(RESPONSE_TAG_READ);
            encoder.u32(response.read);
        }
        StdioResponse::Write(response) => {
            encoder.u8(RESPONSE_TAG_WRITE);
            encoder.u32(response.written);
        }
    }
}

pub(super) fn decode_stdio_response(decoder: &mut Decoder<'_>) -> Result<StdioResponse, WireError> {
    match decoder.u8()? {
        RESPONSE_TAG_READ => Ok(StdioResponse::Read(ReadStdioResponse {
            read: decoder.u32()?,
        })),
        RESPONSE_TAG_WRITE => Ok(StdioResponse::Write(WriteStdioResponse {
            written: decoder.u32()?,
        })),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_output_stream(encoder: &mut Encoder, stream: StdioOutputStream) {
    encoder.u8(match stream {
        StdioOutputStream::Stdout => OUTPUT_STREAM_TAG_STDOUT,
        StdioOutputStream::Stderr => OUTPUT_STREAM_TAG_STDERR,
    });
}

fn decode_output_stream(decoder: &mut Decoder<'_>) -> Result<StdioOutputStream, WireError> {
    match decoder.u8()? {
        OUTPUT_STREAM_TAG_STDOUT => Ok(StdioOutputStream::Stdout),
        OUTPUT_STREAM_TAG_STDERR => Ok(StdioOutputStream::Stderr),
        _ => Err(WireError::InvalidTag),
    }
}
