// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{ProcessGroupRequest, ProcessGroupResponse};
use crate::process_group::SetProcessGroupRequest;

use super::WireError;
use super::primitive::{Decoder, Encoder};

const PROCESS_GROUP_REQUEST_TAG_SET: u8 = 0;
const PROCESS_GROUP_REQUEST_TAG_CREATE_SESSION: u8 = 1;

const PROCESS_GROUP_RESPONSE_TAG_SET: u8 = 0;
const PROCESS_GROUP_RESPONSE_TAG_CREATE_SESSION: u8 = 1;

pub(super) fn encode_process_group_request(encoder: &mut Encoder, request: ProcessGroupRequest) {
    match request {
        ProcessGroupRequest::Set(request) => {
            encoder.u8(PROCESS_GROUP_REQUEST_TAG_SET);
            encoder.process_id(request.process_id);
            encoder.process_group_id(request.process_group);
        }
        ProcessGroupRequest::CreateSession(process_id) => {
            encoder.u8(PROCESS_GROUP_REQUEST_TAG_CREATE_SESSION);
            encoder.process_id(process_id);
        }
    }
}

pub(super) fn decode_process_group_request(
    decoder: &mut Decoder<'_>,
) -> Result<ProcessGroupRequest, WireError> {
    Ok(match decoder.u8()? {
        PROCESS_GROUP_REQUEST_TAG_SET => ProcessGroupRequest::Set(SetProcessGroupRequest {
            process_id: decoder.process_id()?,
            process_group: decoder.process_group_id()?,
        }),
        PROCESS_GROUP_REQUEST_TAG_CREATE_SESSION => {
            ProcessGroupRequest::CreateSession(decoder.process_id()?)
        }
        _ => return Err(WireError::InvalidTag),
    })
}

pub(super) fn encode_process_group_response(encoder: &mut Encoder, response: ProcessGroupResponse) {
    match response {
        ProcessGroupResponse::Set => encoder.u8(PROCESS_GROUP_RESPONSE_TAG_SET),
        ProcessGroupResponse::CreateSession => {
            encoder.u8(PROCESS_GROUP_RESPONSE_TAG_CREATE_SESSION);
        }
    }
}

pub(super) fn decode_process_group_response(
    decoder: &mut Decoder<'_>,
) -> Result<ProcessGroupResponse, WireError> {
    Ok(match decoder.u8()? {
        PROCESS_GROUP_RESPONSE_TAG_SET => ProcessGroupResponse::Set,
        PROCESS_GROUP_RESPONSE_TAG_CREATE_SESSION => ProcessGroupResponse::CreateSession,
        _ => return Err(WireError::InvalidTag),
    })
}
