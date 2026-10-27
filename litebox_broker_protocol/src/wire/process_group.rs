// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::{ProcessGroupRequest, ProcessGroupResponse};
use crate::process_group::{
    ProcessGroupError, ProcessGroupMembership, SetControllingTerminalRequest,
    SetForegroundGroupRequest, SetProcessGroupRequest,
};

use super::WireError;
use super::primitive::{Decoder, Encoder};

const PROCESS_GROUP_REQUEST_TAG_SET: u8 = 0;
const PROCESS_GROUP_REQUEST_TAG_CREATE_SESSION: u8 = 1;
const PROCESS_GROUP_REQUEST_TAG_GET_FOREGROUND_GROUP: u8 = 2;
const PROCESS_GROUP_REQUEST_TAG_SET_FOREGROUND_GROUP: u8 = 3;
const PROCESS_GROUP_REQUEST_TAG_SET_CONTROLLING_TERMINAL: u8 = 4;

const PROCESS_GROUP_RESPONSE_TAG_SET: u8 = 0;
const PROCESS_GROUP_RESPONSE_TAG_CREATE_SESSION: u8 = 1;
const PROCESS_GROUP_RESPONSE_TAG_GET_FOREGROUND_GROUP: u8 = 2;
const PROCESS_GROUP_RESPONSE_TAG_SET_FOREGROUND_GROUP: u8 = 3;
const PROCESS_GROUP_RESPONSE_TAG_SET_CONTROLLING_TERMINAL: u8 = 4;
const PROCESS_GROUP_RESPONSE_TAG_FAILED: u8 = u8::MAX;

const PROCESS_GROUP_ERROR_TAG_NOT_CONTROLLING_TERMINAL: u8 = 0;
const PROCESS_GROUP_ERROR_TAG_NO_SUCH_PROCESS_GROUP: u8 = 1;
const PROCESS_GROUP_ERROR_TAG_NOT_IN_SESSION: u8 = 2;

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
        ProcessGroupRequest::GetForegroundGroup(terminal) => {
            encoder.u8(PROCESS_GROUP_REQUEST_TAG_GET_FOREGROUND_GROUP);
            encoder.handle(terminal);
        }
        ProcessGroupRequest::SetForegroundGroup(request) => {
            encoder.u8(PROCESS_GROUP_REQUEST_TAG_SET_FOREGROUND_GROUP);
            encoder.handle(request.terminal);
            encoder.process_group_id(request.process_group);
        }
        ProcessGroupRequest::SetControllingTerminal(request) => {
            encoder.u8(PROCESS_GROUP_REQUEST_TAG_SET_CONTROLLING_TERMINAL);
            encoder.process_id(request.process_id);
            encoder.handle(request.terminal);
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
        PROCESS_GROUP_REQUEST_TAG_GET_FOREGROUND_GROUP => {
            ProcessGroupRequest::GetForegroundGroup(decoder.handle()?)
        }
        PROCESS_GROUP_REQUEST_TAG_SET_FOREGROUND_GROUP => {
            ProcessGroupRequest::SetForegroundGroup(SetForegroundGroupRequest {
                terminal: decoder.handle()?,
                process_group: decoder.process_group_id()?,
            })
        }
        PROCESS_GROUP_REQUEST_TAG_SET_CONTROLLING_TERMINAL => {
            ProcessGroupRequest::SetControllingTerminal(SetControllingTerminalRequest {
                process_id: decoder.process_id()?,
                terminal: decoder.handle()?,
            })
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
        ProcessGroupResponse::GetForegroundGroup(foreground) => {
            encoder.u8(PROCESS_GROUP_RESPONSE_TAG_GET_FOREGROUND_GROUP);
            encoder.process_group_id(foreground.process_group);
            encoder.session_id(foreground.session);
        }
        ProcessGroupResponse::SetForegroundGroup => {
            encoder.u8(PROCESS_GROUP_RESPONSE_TAG_SET_FOREGROUND_GROUP);
        }
        ProcessGroupResponse::SetControllingTerminal => {
            encoder.u8(PROCESS_GROUP_RESPONSE_TAG_SET_CONTROLLING_TERMINAL);
        }
        ProcessGroupResponse::Failed(error) => {
            encoder.u8(PROCESS_GROUP_RESPONSE_TAG_FAILED);
            encoder.u8(match error {
                ProcessGroupError::NotControllingTerminal => {
                    PROCESS_GROUP_ERROR_TAG_NOT_CONTROLLING_TERMINAL
                }
                ProcessGroupError::NoSuchProcessGroup => {
                    PROCESS_GROUP_ERROR_TAG_NO_SUCH_PROCESS_GROUP
                }
                ProcessGroupError::NotInSession => PROCESS_GROUP_ERROR_TAG_NOT_IN_SESSION,
            });
        }
    }
}

pub(super) fn decode_process_group_response(
    decoder: &mut Decoder<'_>,
) -> Result<ProcessGroupResponse, WireError> {
    Ok(match decoder.u8()? {
        PROCESS_GROUP_RESPONSE_TAG_SET => ProcessGroupResponse::Set,
        PROCESS_GROUP_RESPONSE_TAG_CREATE_SESSION => ProcessGroupResponse::CreateSession,
        PROCESS_GROUP_RESPONSE_TAG_GET_FOREGROUND_GROUP => {
            ProcessGroupResponse::GetForegroundGroup(ProcessGroupMembership {
                process_group: decoder.process_group_id()?,
                session: decoder.session_id()?,
            })
        }
        PROCESS_GROUP_RESPONSE_TAG_SET_FOREGROUND_GROUP => ProcessGroupResponse::SetForegroundGroup,
        PROCESS_GROUP_RESPONSE_TAG_SET_CONTROLLING_TERMINAL => {
            ProcessGroupResponse::SetControllingTerminal
        }
        PROCESS_GROUP_RESPONSE_TAG_FAILED => ProcessGroupResponse::Failed(match decoder.u8()? {
            PROCESS_GROUP_ERROR_TAG_NOT_CONTROLLING_TERMINAL => {
                ProcessGroupError::NotControllingTerminal
            }
            PROCESS_GROUP_ERROR_TAG_NO_SUCH_PROCESS_GROUP => ProcessGroupError::NoSuchProcessGroup,
            PROCESS_GROUP_ERROR_TAG_NOT_IN_SESSION => ProcessGroupError::NotInSession,
            _ => return Err(WireError::InvalidTag),
        }),
        _ => return Err(WireError::InvalidTag),
    })
}
