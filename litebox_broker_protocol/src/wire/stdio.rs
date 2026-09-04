// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{StdioRequest, StdioResponse};
use crate::stdio::{
    IsTerminalStdioRequest, IsTerminalStdioResponse, ReadStdioRequest, ReadStdioResponse,
    StdioOutputStream, StdioStream, WriteStdioRequest, WriteStdioResponse,
};

use super::{
    WireError,
    primitive::{Decoder, Encoder},
};

const REQUEST_TAG_READ: u8 = 0;
const REQUEST_TAG_WRITE: u8 = 1;
const REQUEST_TAG_IS_TERMINAL: u8 = 2;
const RESPONSE_TAG_READ: u8 = 0;
const RESPONSE_TAG_WRITE: u8 = 1;
const RESPONSE_TAG_IS_TERMINAL: u8 = 2;

const OUTPUT_STREAM_TAG_STDOUT: u8 = 0;
const OUTPUT_STREAM_TAG_STDERR: u8 = 1;

const STREAM_TAG_STDIN: u8 = 0;
const STREAM_TAG_STDOUT: u8 = 1;
const STREAM_TAG_STDERR: u8 = 2;

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
        StdioRequest::IsTerminal(request) => {
            encoder.u8(REQUEST_TAG_IS_TERMINAL);
            encode_stream(encoder, request.stream);
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
        REQUEST_TAG_IS_TERMINAL => Ok(StdioRequest::IsTerminal(IsTerminalStdioRequest {
            stream: decode_stream(decoder)?,
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
        StdioResponse::IsTerminal(response) => {
            encoder.u8(RESPONSE_TAG_IS_TERMINAL);
            encoder.u8(u8::from(response.is_terminal));
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
        RESPONSE_TAG_IS_TERMINAL => Ok(StdioResponse::IsTerminal(IsTerminalStdioResponse {
            is_terminal: match decoder.u8()? {
                0 => false,
                1 => true,
                _ => return Err(WireError::InvalidTag),
            },
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

fn encode_stream(encoder: &mut Encoder, stream: StdioStream) {
    encoder.u8(match stream {
        StdioStream::Stdin => STREAM_TAG_STDIN,
        StdioStream::Stdout => STREAM_TAG_STDOUT,
        StdioStream::Stderr => STREAM_TAG_STDERR,
    });
}

fn decode_stream(decoder: &mut Decoder<'_>) -> Result<StdioStream, WireError> {
    match decoder.u8()? {
        STREAM_TAG_STDIN => Ok(StdioStream::Stdin),
        STREAM_TAG_STDOUT => Ok(StdioStream::Stdout),
        STREAM_TAG_STDERR => Ok(StdioStream::Stderr),
        _ => Err(WireError::InvalidTag),
    }
}
