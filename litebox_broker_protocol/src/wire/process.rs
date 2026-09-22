// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::message::BrokerResult;
use crate::process::{
    DuplicationOutcome, ProcessBootstrapFormat, ProcessBootstrapVersion, ProcessIdentity,
    ProcessStartupDescriptor, StartChildProcessRequest,
};

use super::primitive::{Decoder, Encoder};
use super::{WireError, decode_inherited_objects, encode_inherited_objects};

const START_CHILD_PROCESS_TAG_BOOTSTRAP: u8 = 0;
const START_CHILD_PROCESS_TAG_DUPLICATE: u8 = 1;

const START_CHILD_PROCESS_RESULT_TAG_STARTED: u8 = 0;
const START_CHILD_PROCESS_RESULT_TAG_DUPLICATION: u8 = 1;

const DUPLICATION_OUTCOME_TAG_REFUSED: u8 = 0;
const DUPLICATION_OUTCOME_TAG_PARENT_UPDATE: u8 = 1;

pub(super) fn encode_start_child_process_request(
    encoder: &mut Encoder,
    request: StartChildProcessRequest,
) {
    match request {
        StartChildProcessRequest::Bootstrap(ProcessStartupDescriptor {
            format,
            version,
            buffer,
            inherited_objects,
        }) => {
            encoder.u8(START_CHILD_PROCESS_TAG_BOOTSTRAP);
            encoder.u32(format.0);
            encoder.u16(version.0);
            encoder.shared_buffer_sequence(buffer);
            encode_inherited_objects(encoder, inherited_objects);
        }
        StartChildProcessRequest::Duplicate { image, dirty } => {
            encoder.u8(START_CHILD_PROCESS_TAG_DUPLICATE);
            encoder.shared_buffer_sequence(image);
            encoder.shared_buffer_sequence(dirty);
        }
    }
}

pub(super) fn decode_start_child_process_request(
    decoder: &mut Decoder<'_>,
) -> Result<StartChildProcessRequest, WireError> {
    match decoder.u8()? {
        START_CHILD_PROCESS_TAG_BOOTSTRAP => Ok(StartChildProcessRequest::Bootstrap(
            ProcessStartupDescriptor {
                format: ProcessBootstrapFormat(decoder.u32()?),
                version: ProcessBootstrapVersion(decoder.u16()?),
                buffer: decoder.shared_buffer_sequence()?,
                inherited_objects: decode_inherited_objects(decoder)?,
            },
        )),
        START_CHILD_PROCESS_TAG_DUPLICATE => Ok(StartChildProcessRequest::Duplicate {
            image: decoder.shared_buffer_sequence()?,
            dirty: decoder.shared_buffer_sequence()?,
        }),
        _ => Err(WireError::InvalidTag),
    }
}

pub(super) fn encode_process_started(encoder: &mut Encoder, identity: ProcessIdentity) {
    encoder.u8(START_CHILD_PROCESS_RESULT_TAG_STARTED);
    encoder.process_id(identity.process_id);
    encoder.thread_id(identity.initial_thread_id);
}

pub(super) fn encode_process_duplication(encoder: &mut Encoder, outcome: DuplicationOutcome) {
    encoder.u8(START_CHILD_PROCESS_RESULT_TAG_DUPLICATION);
    encode_duplication_outcome(encoder, outcome);
}

pub(super) fn decode_start_child_process_result(
    decoder: &mut Decoder<'_>,
) -> Result<BrokerResult, WireError> {
    match decoder.u8()? {
        START_CHILD_PROCESS_RESULT_TAG_STARTED => {
            Ok(BrokerResult::ProcessStarted(ProcessIdentity {
                process_id: decoder.process_id()?,
                initial_thread_id: decoder.thread_id()?,
            }))
        }
        START_CHILD_PROCESS_RESULT_TAG_DUPLICATION => Ok(BrokerResult::ProcessDuplication(
            decode_duplication_outcome(decoder)?,
        )),
        _ => Err(WireError::InvalidTag),
    }
}

pub(super) fn encode_duplication_outcome(encoder: &mut Encoder, outcome: DuplicationOutcome) {
    match outcome {
        DuplicationOutcome::Refused => encoder.u8(DUPLICATION_OUTCOME_TAG_REFUSED),
        DuplicationOutcome::ParentUpdate { patch, child } => {
            encoder.u8(DUPLICATION_OUTCOME_TAG_PARENT_UPDATE);
            encoder.shared_buffer_sequence(patch);
            encoder.process_id(child.process_id);
            encoder.thread_id(child.initial_thread_id);
        }
    }
}

pub(super) fn decode_duplication_outcome(
    decoder: &mut Decoder<'_>,
) -> Result<DuplicationOutcome, WireError> {
    match decoder.u8()? {
        DUPLICATION_OUTCOME_TAG_REFUSED => Ok(DuplicationOutcome::Refused),
        DUPLICATION_OUTCOME_TAG_PARENT_UPDATE => Ok(DuplicationOutcome::ParentUpdate {
            patch: decoder.shared_buffer_sequence()?,
            child: ProcessIdentity {
                process_id: decoder.process_id()?,
                initial_thread_id: decoder.thread_id()?,
            },
        }),
        _ => Err(WireError::InvalidTag),
    }
}
