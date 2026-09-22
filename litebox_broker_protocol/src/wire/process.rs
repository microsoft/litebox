// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::process::{DuplicateProcess, DuplicationOutcome, ProcessIdentity};

use super::WireError;
use super::primitive::{Decoder, Encoder};

const DUPLICATION_OUTCOME_TAG_REFUSED: u8 = 0;
const DUPLICATION_OUTCOME_TAG_PARENT_UPDATE: u8 = 1;

pub(super) const MAX_ENCODED_DUPLICATE_PROCESS_SIZE: usize = 74;
pub(super) const MAX_ENCODED_DUPLICATION_OUTCOME_SIZE: usize = 46;

pub(super) fn encode_duplicate_process(request: DuplicateProcess) -> alloc::vec::Vec<u8> {
    let mut encoder = Encoder::default();
    encoder.shared_buffer_sequence(request.image);
    encoder.shared_buffer_sequence(request.dirty);
    encoder.finish()
}

pub(super) fn decode_duplicate_process(frame: &[u8]) -> Result<DuplicateProcess, WireError> {
    let mut decoder = Decoder::new(frame);
    let request = DuplicateProcess {
        image: decoder.shared_buffer_sequence()?,
        dirty: decoder.shared_buffer_sequence()?,
    };
    decoder.finish()?;
    Ok(request)
}

pub(super) fn encode_duplication_outcome(outcome: DuplicationOutcome) -> alloc::vec::Vec<u8> {
    let mut encoder = Encoder::default();
    match outcome {
        DuplicationOutcome::Refused => encoder.u8(DUPLICATION_OUTCOME_TAG_REFUSED),
        DuplicationOutcome::ParentUpdate { patch, child } => {
            encoder.u8(DUPLICATION_OUTCOME_TAG_PARENT_UPDATE);
            encoder.shared_buffer_sequence(patch);
            encoder.process_id(child.process_id);
            encoder.thread_id(child.initial_thread_id);
        }
    }
    encoder.finish()
}

pub(super) fn decode_duplication_outcome(frame: &[u8]) -> Result<DuplicationOutcome, WireError> {
    let mut decoder = Decoder::new(frame);
    let outcome = match decoder.u8()? {
        DUPLICATION_OUTCOME_TAG_REFUSED => DuplicationOutcome::Refused,
        DUPLICATION_OUTCOME_TAG_PARENT_UPDATE => DuplicationOutcome::ParentUpdate {
            patch: decoder.shared_buffer_sequence()?,
            child: ProcessIdentity {
                process_id: decoder.process_id()?,
                initial_thread_id: decoder.thread_id()?,
            },
        },
        _ => return Err(WireError::InvalidTag),
    };
    decoder.finish()?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use crate::process::{DuplicateProcess, DuplicationOutcome, ProcessIdentity};
    use crate::shared_buffer::{SharedBufferSequence, SharedBufferSlotIndex};
    use crate::{ProcessId, ThreadId};

    use super::{
        MAX_ENCODED_DUPLICATE_PROCESS_SIZE, MAX_ENCODED_DUPLICATION_OUTCOME_SIZE,
        decode_duplicate_process, decode_duplication_outcome, encode_duplicate_process,
        encode_duplication_outcome,
    };

    fn sequence() -> SharedBufferSequence {
        let slots: [_; 8] =
            core::array::from_fn(|index| SharedBufferSlotIndex(u32::try_from(index).unwrap()));
        SharedBufferSequence::new(&slots, 512 * 1024).unwrap()
    }

    #[test]
    fn duplication_payloads_round_trip_within_bounds() {
        let sequence = sequence();
        let request = DuplicateProcess {
            image: sequence,
            dirty: sequence,
        };
        let encoded = encode_duplicate_process(request);
        assert_eq!(encoded.len(), MAX_ENCODED_DUPLICATE_PROCESS_SIZE);
        assert_eq!(decode_duplicate_process(&encoded).unwrap(), request);

        for outcome in [
            DuplicationOutcome::Refused,
            DuplicationOutcome::ParentUpdate {
                patch: sequence,
                child: ProcessIdentity {
                    process_id: ProcessId(u32::MAX),
                    initial_thread_id: ThreadId(u32::MAX),
                },
            },
        ] {
            let encoded = encode_duplication_outcome(outcome);
            assert!(encoded.len() <= MAX_ENCODED_DUPLICATION_OUTCOME_SIZE);
            assert_eq!(decode_duplication_outcome(&encoded).unwrap(), outcome);
        }
        assert_eq!(encode_duplication_outcome(DuplicationOutcome::Refused), [0]);
    }
}
