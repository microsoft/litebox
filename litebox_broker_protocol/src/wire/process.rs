// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::ProcessId;
use crate::message::{ProcessRequest, ProcessResponse};
use crate::process::{
    ChildExit, ChildSelector, DuplicateObjectsToChildRequest, ExitChildProcessRequest,
    ProcessExitStatus, ProcessIdentity, ProcessInfo, ProcessStartupDescriptor,
    StartChildProcessRequest, StartChildWithExistingRunnerRequest, ThreadInfo,
    WriteChildMemoryRequest,
};
use crate::process_group::ProcessGroupMembership;

use super::WireError;
use super::primitive::{Decoder, Encoder};

const PROCESS_REQUEST_TAG_ALLOCATE_CHILD: u8 = 0;
const PROCESS_REQUEST_TAG_DUPLICATE_OBJECTS_TO_CHILD: u8 = 1;
const PROCESS_REQUEST_TAG_WRITE_CHILD_MEMORY: u8 = 2;
const PROCESS_REQUEST_TAG_START_CHILD: u8 = 3;
const PROCESS_REQUEST_TAG_EXIT_CHILD: u8 = 4;
const PROCESS_REQUEST_TAG_CANCEL_CHILD: u8 = 5;
const PROCESS_REQUEST_TAG_REPORT_EXIT_STATUS: u8 = 6;
const PROCESS_REQUEST_TAG_SET_CHILD_EXIT_RETENTION: u8 = 7;
const PROCESS_REQUEST_TAG_SET_ORPHAN_ADOPTION: u8 = 8;
const PROCESS_REQUEST_TAG_COLLECT_CHILD_EXIT: u8 = 9;
const PROCESS_REQUEST_TAG_GET_INFO: u8 = 10;
const PROCESS_REQUEST_TAG_GET_THREAD_INFO: u8 = 11;
const PROCESS_REQUEST_TAG_START_CHILD_WITH_EXISTING_RUNNER: u8 = 12;

const PROCESS_RESPONSE_TAG_ALLOCATE_CHILD: u8 = 0;
const PROCESS_RESPONSE_TAG_DUPLICATE_OBJECTS_TO_CHILD: u8 = 1;
const PROCESS_RESPONSE_TAG_WRITE_CHILD_MEMORY: u8 = 2;
const PROCESS_RESPONSE_TAG_START_CHILD: u8 = 3;
const PROCESS_RESPONSE_TAG_EXIT_CHILD: u8 = 4;
const PROCESS_RESPONSE_TAG_CANCEL_CHILD: u8 = 5;
const PROCESS_RESPONSE_TAG_REPORT_EXIT_STATUS: u8 = 6;
const PROCESS_RESPONSE_TAG_SET_CHILD_EXIT_RETENTION: u8 = 7;
const PROCESS_RESPONSE_TAG_SET_ORPHAN_ADOPTION: u8 = 8;
const PROCESS_RESPONSE_TAG_COLLECT_CHILD_EXIT: u8 = 9;
const PROCESS_RESPONSE_TAG_GET_INFO: u8 = 10;
const PROCESS_RESPONSE_TAG_GET_THREAD_INFO: u8 = 11;
const PROCESS_RESPONSE_TAG_START_CHILD_WITH_EXISTING_RUNNER: u8 = 12;

const PROCESS_EXIT_STATUS_TAG_EXITED: u8 = 0;
const PROCESS_EXIT_STATUS_TAG_SIGNALED: u8 = 1;
const PROCESS_EXIT_STATUS_TAG_UNKNOWN: u8 = 2;

const CHILD_SELECTOR_TAG_ANY: u8 = 0;
const CHILD_SELECTOR_TAG_PROCESS: u8 = 1;
const CHILD_SELECTOR_TAG_PROCESS_GROUP: u8 = 2;

pub(super) fn encode_process_request(encoder: &mut Encoder, request: ProcessRequest) {
    match request {
        ProcessRequest::AllocateChild => encoder.u8(PROCESS_REQUEST_TAG_ALLOCATE_CHILD),
        ProcessRequest::DuplicateObjectsToChild(DuplicateObjectsToChildRequest {
            child_process_id,
            handles,
        }) => {
            encoder.u8(PROCESS_REQUEST_TAG_DUPLICATE_OBJECTS_TO_CHILD);
            encoder.process_id(child_process_id);
            encoder.shared_buffer_sequence(handles);
        }
        ProcessRequest::WriteChildMemory(WriteChildMemoryRequest {
            child_process_id,
            offset,
            data,
        }) => {
            encoder.u8(PROCESS_REQUEST_TAG_WRITE_CHILD_MEMORY);
            encoder.process_id(child_process_id);
            encoder.u64(offset);
            encoder.shared_buffer_sequence(data);
        }
        ProcessRequest::StartChild(StartChildProcessRequest {
            child_process_id,
            startup,
        }) => {
            encoder.u8(PROCESS_REQUEST_TAG_START_CHILD);
            encoder.process_id(child_process_id);
            encoder.shared_buffer_sequence(startup.buffer);
        }
        ProcessRequest::StartChildWithExistingRunner(StartChildWithExistingRunnerRequest {
            child_process_id,
            launch_descriptor_length,
            data,
        }) => {
            encoder.u8(PROCESS_REQUEST_TAG_START_CHILD_WITH_EXISTING_RUNNER);
            encoder.process_id(child_process_id);
            encoder.u32(launch_descriptor_length);
            encoder.shared_buffer_sequence(data);
        }
        ProcessRequest::ExitChild(ExitChildProcessRequest {
            child_process_id,
            exit_status,
        }) => {
            encoder.u8(PROCESS_REQUEST_TAG_EXIT_CHILD);
            encoder.process_id(child_process_id);
            encode_process_exit_status(encoder, exit_status);
        }
        ProcessRequest::CancelChild(child_process_id) => {
            encoder.u8(PROCESS_REQUEST_TAG_CANCEL_CHILD);
            encoder.process_id(child_process_id);
        }
        ProcessRequest::ReportExitStatus(exit_status) => {
            encoder.u8(PROCESS_REQUEST_TAG_REPORT_EXIT_STATUS);
            encode_process_exit_status(encoder, exit_status);
        }
        ProcessRequest::SetChildExitRetention(enabled) => {
            encoder.u8(PROCESS_REQUEST_TAG_SET_CHILD_EXIT_RETENTION);
            encoder.u8(u8::from(enabled));
        }
        ProcessRequest::SetOrphanAdoption(enabled) => {
            encoder.u8(PROCESS_REQUEST_TAG_SET_ORPHAN_ADOPTION);
            encoder.u8(u8::from(enabled));
        }
        ProcessRequest::CollectChildExit(selector) => {
            encoder.u8(PROCESS_REQUEST_TAG_COLLECT_CHILD_EXIT);
            encode_child_selector(encoder, selector);
        }
        ProcessRequest::GetInfo(process_id) => {
            encoder.u8(PROCESS_REQUEST_TAG_GET_INFO);
            encoder.process_id(process_id);
        }
        ProcessRequest::GetThreadInfo(thread_id) => {
            encoder.u8(PROCESS_REQUEST_TAG_GET_THREAD_INFO);
            encoder.thread_id(thread_id);
        }
    }
}

pub(super) fn decode_process_request(
    decoder: &mut Decoder<'_>,
) -> Result<ProcessRequest, WireError> {
    Ok(match decoder.u8()? {
        PROCESS_REQUEST_TAG_ALLOCATE_CHILD => ProcessRequest::AllocateChild,
        PROCESS_REQUEST_TAG_DUPLICATE_OBJECTS_TO_CHILD => {
            ProcessRequest::DuplicateObjectsToChild(DuplicateObjectsToChildRequest {
                child_process_id: decoder.process_id()?,
                handles: decoder.shared_buffer_sequence()?,
            })
        }
        PROCESS_REQUEST_TAG_WRITE_CHILD_MEMORY => {
            ProcessRequest::WriteChildMemory(WriteChildMemoryRequest {
                child_process_id: decoder.process_id()?,
                offset: decoder.u64()?,
                data: decoder.shared_buffer_sequence()?,
            })
        }
        PROCESS_REQUEST_TAG_START_CHILD => ProcessRequest::StartChild(StartChildProcessRequest {
            child_process_id: decoder.process_id()?,
            startup: ProcessStartupDescriptor {
                buffer: decoder.shared_buffer_sequence()?,
            },
        }),
        PROCESS_REQUEST_TAG_START_CHILD_WITH_EXISTING_RUNNER => {
            ProcessRequest::StartChildWithExistingRunner(StartChildWithExistingRunnerRequest {
                child_process_id: decoder.process_id()?,
                launch_descriptor_length: decoder.u32()?,
                data: decoder.shared_buffer_sequence()?,
            })
        }
        PROCESS_REQUEST_TAG_EXIT_CHILD => ProcessRequest::ExitChild(ExitChildProcessRequest {
            child_process_id: decoder.process_id()?,
            exit_status: decode_process_exit_status(decoder)?,
        }),
        PROCESS_REQUEST_TAG_CANCEL_CHILD => ProcessRequest::CancelChild(decoder.process_id()?),
        PROCESS_REQUEST_TAG_REPORT_EXIT_STATUS => {
            ProcessRequest::ReportExitStatus(decode_process_exit_status(decoder)?)
        }
        PROCESS_REQUEST_TAG_SET_CHILD_EXIT_RETENTION => {
            ProcessRequest::SetChildExitRetention(decode_bool(decoder)?)
        }
        PROCESS_REQUEST_TAG_SET_ORPHAN_ADOPTION => {
            ProcessRequest::SetOrphanAdoption(decode_bool(decoder)?)
        }
        PROCESS_REQUEST_TAG_COLLECT_CHILD_EXIT => {
            ProcessRequest::CollectChildExit(decode_child_selector(decoder)?)
        }
        PROCESS_REQUEST_TAG_GET_INFO => ProcessRequest::GetInfo(decoder.process_id()?),
        PROCESS_REQUEST_TAG_GET_THREAD_INFO => ProcessRequest::GetThreadInfo(decoder.thread_id()?),
        _ => return Err(WireError::InvalidTag),
    })
}

pub(super) fn encode_process_response(encoder: &mut Encoder, response: ProcessResponse) {
    match response {
        ProcessResponse::AllocateChild(ProcessIdentity {
            process_id,
            initial_thread_id,
        }) => {
            encoder.u8(PROCESS_RESPONSE_TAG_ALLOCATE_CHILD);
            encoder.process_id(process_id);
            encoder.thread_id(initial_thread_id);
        }
        ProcessResponse::DuplicateObjectsToChild => {
            encoder.u8(PROCESS_RESPONSE_TAG_DUPLICATE_OBJECTS_TO_CHILD);
        }
        ProcessResponse::WriteChildMemory => encoder.u8(PROCESS_RESPONSE_TAG_WRITE_CHILD_MEMORY),
        ProcessResponse::StartChild => encoder.u8(PROCESS_RESPONSE_TAG_START_CHILD),
        ProcessResponse::StartChildWithExistingRunner => {
            encoder.u8(PROCESS_RESPONSE_TAG_START_CHILD_WITH_EXISTING_RUNNER);
        }
        ProcessResponse::ExitChild => encoder.u8(PROCESS_RESPONSE_TAG_EXIT_CHILD),
        ProcessResponse::CancelChild => encoder.u8(PROCESS_RESPONSE_TAG_CANCEL_CHILD),
        ProcessResponse::ReportExitStatus => encoder.u8(PROCESS_RESPONSE_TAG_REPORT_EXIT_STATUS),
        ProcessResponse::SetChildExitRetention => {
            encoder.u8(PROCESS_RESPONSE_TAG_SET_CHILD_EXIT_RETENTION);
        }
        ProcessResponse::SetOrphanAdoption => {
            encoder.u8(PROCESS_RESPONSE_TAG_SET_ORPHAN_ADOPTION);
        }
        ProcessResponse::CollectChildExit(child_exit) => {
            encoder.u8(PROCESS_RESPONSE_TAG_COLLECT_CHILD_EXIT);
            encode_child_exit(encoder, child_exit);
        }
        ProcessResponse::GetInfo(info) => {
            encoder.u8(PROCESS_RESPONSE_TAG_GET_INFO);
            encode_process_info(encoder, info);
        }
        ProcessResponse::GetThreadInfo(ThreadInfo {
            process_id,
            initial,
        }) => {
            encoder.u8(PROCESS_RESPONSE_TAG_GET_THREAD_INFO);
            encoder.process_id(process_id);
            encoder.u8(u8::from(initial));
        }
    }
}

pub(super) fn decode_process_response(
    decoder: &mut Decoder<'_>,
) -> Result<ProcessResponse, WireError> {
    Ok(match decoder.u8()? {
        PROCESS_RESPONSE_TAG_ALLOCATE_CHILD => ProcessResponse::AllocateChild(ProcessIdentity {
            process_id: decoder.process_id()?,
            initial_thread_id: decoder.thread_id()?,
        }),
        PROCESS_RESPONSE_TAG_DUPLICATE_OBJECTS_TO_CHILD => ProcessResponse::DuplicateObjectsToChild,
        PROCESS_RESPONSE_TAG_WRITE_CHILD_MEMORY => ProcessResponse::WriteChildMemory,
        PROCESS_RESPONSE_TAG_START_CHILD => ProcessResponse::StartChild,
        PROCESS_RESPONSE_TAG_START_CHILD_WITH_EXISTING_RUNNER => {
            ProcessResponse::StartChildWithExistingRunner
        }
        PROCESS_RESPONSE_TAG_EXIT_CHILD => ProcessResponse::ExitChild,
        PROCESS_RESPONSE_TAG_CANCEL_CHILD => ProcessResponse::CancelChild,
        PROCESS_RESPONSE_TAG_REPORT_EXIT_STATUS => ProcessResponse::ReportExitStatus,
        PROCESS_RESPONSE_TAG_SET_CHILD_EXIT_RETENTION => ProcessResponse::SetChildExitRetention,
        PROCESS_RESPONSE_TAG_SET_ORPHAN_ADOPTION => ProcessResponse::SetOrphanAdoption,
        PROCESS_RESPONSE_TAG_COLLECT_CHILD_EXIT => {
            ProcessResponse::CollectChildExit(decode_child_exit(decoder)?)
        }
        PROCESS_RESPONSE_TAG_GET_INFO => ProcessResponse::GetInfo(decode_process_info(decoder)?),
        PROCESS_RESPONSE_TAG_GET_THREAD_INFO => ProcessResponse::GetThreadInfo(ThreadInfo {
            process_id: decoder.process_id()?,
            initial: decode_bool(decoder)?,
        }),
        _ => return Err(WireError::InvalidTag),
    })
}

pub(super) fn encode_child_exit(encoder: &mut Encoder, child_exit: ChildExit) {
    encoder.process_id(child_exit.process_id);
    encode_process_exit_status(encoder, child_exit.exit_status);
}

pub(super) fn decode_child_exit(decoder: &mut Decoder<'_>) -> Result<ChildExit, WireError> {
    Ok(ChildExit {
        process_id: decoder.process_id()?,
        exit_status: decode_process_exit_status(decoder)?,
    })
}

fn encode_process_exit_status(encoder: &mut Encoder, status: ProcessExitStatus) {
    match status {
        ProcessExitStatus::Exited { code } => {
            encoder.u8(PROCESS_EXIT_STATUS_TAG_EXITED);
            encoder.u32(code);
        }
        ProcessExitStatus::Signaled { signal } => {
            encoder.u8(PROCESS_EXIT_STATUS_TAG_SIGNALED);
            encoder.u32(signal);
        }
        ProcessExitStatus::Unknown => encoder.u8(PROCESS_EXIT_STATUS_TAG_UNKNOWN),
    }
}

fn decode_process_exit_status(decoder: &mut Decoder<'_>) -> Result<ProcessExitStatus, WireError> {
    match decoder.u8()? {
        PROCESS_EXIT_STATUS_TAG_EXITED => Ok(ProcessExitStatus::Exited {
            code: decoder.u32()?,
        }),
        PROCESS_EXIT_STATUS_TAG_SIGNALED => Ok(ProcessExitStatus::Signaled {
            signal: decoder.u32()?,
        }),
        PROCESS_EXIT_STATUS_TAG_UNKNOWN => Ok(ProcessExitStatus::Unknown),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_child_selector(encoder: &mut Encoder, selector: ChildSelector) {
    match selector {
        ChildSelector::Any => encoder.u8(CHILD_SELECTOR_TAG_ANY),
        ChildSelector::Process(process_id) => {
            encoder.u8(CHILD_SELECTOR_TAG_PROCESS);
            encoder.process_id(process_id);
        }
        ChildSelector::ProcessGroup(process_group) => {
            encoder.u8(CHILD_SELECTOR_TAG_PROCESS_GROUP);
            encoder.process_group_id(process_group);
        }
    }
}

fn decode_child_selector(decoder: &mut Decoder<'_>) -> Result<ChildSelector, WireError> {
    Ok(match decoder.u8()? {
        CHILD_SELECTOR_TAG_ANY => ChildSelector::Any,
        CHILD_SELECTOR_TAG_PROCESS => ChildSelector::Process(decoder.process_id()?),
        CHILD_SELECTOR_TAG_PROCESS_GROUP => {
            ChildSelector::ProcessGroup(decoder.process_group_id()?)
        }
        _ => return Err(WireError::InvalidTag),
    })
}

fn encode_process_info(encoder: &mut Encoder, info: ProcessInfo) {
    encode_optional_process_id(encoder, info.creator);
    encode_optional_process_id(encoder, info.parent);
    encoder.process_group_id(info.membership.process_group);
    encoder.session_id(info.membership.session);
}

fn decode_process_info(decoder: &mut Decoder<'_>) -> Result<ProcessInfo, WireError> {
    Ok(ProcessInfo {
        creator: decode_optional_process_id(decoder)?,
        parent: decode_optional_process_id(decoder)?,
        membership: ProcessGroupMembership {
            process_group: decoder.process_group_id()?,
            session: decoder.session_id()?,
        },
    })
}

fn encode_optional_process_id(encoder: &mut Encoder, process_id: Option<ProcessId>) {
    match process_id {
        Some(process_id) => {
            encoder.u8(1);
            encoder.process_id(process_id);
        }
        None => encoder.u8(0),
    }
}

fn decode_optional_process_id(decoder: &mut Decoder<'_>) -> Result<Option<ProcessId>, WireError> {
    match decoder.u8()? {
        0 => Ok(None),
        1 => Ok(Some(decoder.process_id()?)),
        _ => Err(WireError::InvalidTag),
    }
}

fn decode_bool(decoder: &mut Decoder<'_>) -> Result<bool, WireError> {
    match decoder.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(WireError::InvalidTag),
    }
}
