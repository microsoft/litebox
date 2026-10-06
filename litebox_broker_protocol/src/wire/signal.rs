// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{SignalRequest, SignalResponse};
use crate::signal::{
    OpenSignalsResponse, PendingSignal, SendSignalRequest, SignalEvent, SignalTarget,
    TakeSignalRequest,
};

use super::primitive::{Decoder, Encoder};
use super::{WireError, decode_child_exit, encode_child_exit};

const SIGNAL_REQUEST_TAG_OPEN: u8 = 0;
const SIGNAL_REQUEST_TAG_SEND: u8 = 1;
const SIGNAL_REQUEST_TAG_TAKE: u8 = 2;

const SIGNAL_TARGET_TAG_PROCESS: u8 = 0;
const SIGNAL_TARGET_TAG_PROCESS_GROUP: u8 = 1;
const SIGNAL_TARGET_TAG_ALL: u8 = 2;

const SIGNAL_RESPONSE_TAG_OPEN: u8 = 0;
const SIGNAL_RESPONSE_TAG_SENT: u8 = 1;
const SIGNAL_RESPONSE_TAG_TAKE: u8 = 2;

const SIGNAL_EVENT_TAG_SIGNAL: u8 = 0;
const SIGNAL_EVENT_TAG_CHILD_EXITED: u8 = 1;
const SIGNAL_EVENT_TAG_CHILD_REMOVED: u8 = 2;

pub(super) fn encode_signal_request(encoder: &mut Encoder, request: SignalRequest) {
    match request {
        SignalRequest::Open => encoder.u8(SIGNAL_REQUEST_TAG_OPEN),
        SignalRequest::Send(request) => {
            encoder.u8(SIGNAL_REQUEST_TAG_SEND);
            encode_signal_target(encoder, request.target);
            encoder.u32(request.signal);
        }
        SignalRequest::Take(request) => {
            encoder.u8(SIGNAL_REQUEST_TAG_TAKE);
            encoder.handle(request.handle);
        }
    }
}

pub(super) fn decode_signal_request(decoder: &mut Decoder<'_>) -> Result<SignalRequest, WireError> {
    Ok(match decoder.u8()? {
        SIGNAL_REQUEST_TAG_OPEN => SignalRequest::Open,
        SIGNAL_REQUEST_TAG_SEND => SignalRequest::Send(SendSignalRequest {
            target: decode_signal_target(decoder)?,
            signal: decoder.u32()?,
        }),
        SIGNAL_REQUEST_TAG_TAKE => SignalRequest::Take(TakeSignalRequest {
            handle: decoder.handle()?,
        }),
        _ => return Err(WireError::InvalidTag),
    })
}

fn encode_signal_target(encoder: &mut Encoder, target: SignalTarget) {
    match target {
        SignalTarget::Process(process_id) => {
            encoder.u8(SIGNAL_TARGET_TAG_PROCESS);
            encoder.process_id(process_id);
        }
        SignalTarget::ProcessGroup(process_group) => {
            encoder.u8(SIGNAL_TARGET_TAG_PROCESS_GROUP);
            encoder.process_id(process_group);
        }
        SignalTarget::All => encoder.u8(SIGNAL_TARGET_TAG_ALL),
    }
}

fn decode_signal_target(decoder: &mut Decoder<'_>) -> Result<SignalTarget, WireError> {
    Ok(match decoder.u8()? {
        SIGNAL_TARGET_TAG_PROCESS => SignalTarget::Process(decoder.process_id()?),
        SIGNAL_TARGET_TAG_PROCESS_GROUP => SignalTarget::ProcessGroup(decoder.process_id()?),
        SIGNAL_TARGET_TAG_ALL => SignalTarget::All,
        _ => return Err(WireError::InvalidTag),
    })
}

pub(super) fn encode_signal_response(encoder: &mut Encoder, response: SignalResponse) {
    match response {
        SignalResponse::Open(response) => {
            encoder.u8(SIGNAL_RESPONSE_TAG_OPEN);
            encoder.handle(response.handle);
        }
        SignalResponse::Sent => encoder.u8(SIGNAL_RESPONSE_TAG_SENT),
        SignalResponse::Take(event) => {
            encoder.u8(SIGNAL_RESPONSE_TAG_TAKE);
            match event {
                SignalEvent::Signal(signal) => {
                    encoder.u8(SIGNAL_EVENT_TAG_SIGNAL);
                    encoder.u32(signal.signal);
                    encoder.process_id(signal.sender);
                }
                SignalEvent::ChildExited(child_exit) => {
                    encoder.u8(SIGNAL_EVENT_TAG_CHILD_EXITED);
                    encode_child_exit(encoder, child_exit);
                }
                SignalEvent::ChildRemoved => encoder.u8(SIGNAL_EVENT_TAG_CHILD_REMOVED),
            }
        }
    }
}

pub(super) fn decode_signal_response(
    decoder: &mut Decoder<'_>,
) -> Result<SignalResponse, WireError> {
    Ok(match decoder.u8()? {
        SIGNAL_RESPONSE_TAG_OPEN => SignalResponse::Open(OpenSignalsResponse {
            handle: decoder.handle()?,
        }),
        SIGNAL_RESPONSE_TAG_SENT => SignalResponse::Sent,
        SIGNAL_RESPONSE_TAG_TAKE => SignalResponse::Take(match decoder.u8()? {
            SIGNAL_EVENT_TAG_SIGNAL => SignalEvent::Signal(PendingSignal {
                signal: decoder.u32()?,
                sender: decoder.process_id()?,
            }),
            SIGNAL_EVENT_TAG_CHILD_EXITED => SignalEvent::ChildExited(decode_child_exit(decoder)?),
            SIGNAL_EVENT_TAG_CHILD_REMOVED => SignalEvent::ChildRemoved,
            _ => return Err(WireError::InvalidTag),
        }),
        _ => return Err(WireError::InvalidTag),
    })
}
