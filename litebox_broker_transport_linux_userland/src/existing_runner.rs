// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Opaque runner adoption data for a Linux runner cloned by another runner.
//!
//! The parent runner creates a connected socket pair immediately before cloning. The clone keeps
//! both ends; the broker takes its end from the clone's descriptor table with `pidfd_getfd`, so
//! no filesystem rendezvous exists for another process to predict or occupy.

use std::io::{Error, ErrorKind, Result};
use std::os::fd::RawFd;

const ENCODED_SIZE: usize = 8;

/// Host identity and broker endpoint of an already-created Linux runner process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExistingRunnerDescriptor {
    /// Host process ID of the cloned child.
    pub process_id: u32,
    /// Descriptor number, in the clone, of the broker's end of its control socket pair.
    pub broker_fd: RawFd,
}

impl ExistingRunnerDescriptor {
    /// Encodes this descriptor.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate(ErrorKind::InvalidInput)?;
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(ENCODED_SIZE)?;
        encoded.extend_from_slice(&self.process_id.to_le_bytes());
        encoded.extend_from_slice(&self.broker_fd.to_le_bytes());
        Ok(encoded)
    }

    /// Decodes and validates a descriptor received from an untrusted runner.
    pub fn decode(encoded: &[u8]) -> Result<Self> {
        let encoded: &[u8; ENCODED_SIZE] = encoded
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid runner descriptor size"))?;
        let descriptor = Self {
            process_id: u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]),
            broker_fd: RawFd::from_le_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]),
        };
        descriptor.validate(ErrorKind::InvalidData)?;
        Ok(descriptor)
    }

    fn validate(self, kind: ErrorKind) -> Result<()> {
        // Standard streams are never broker endpoints.
        if self.process_id == 0 || i32::try_from(self.process_id).is_err() || self.broker_fd <= 2 {
            return Err(Error::new(kind, "invalid runner descriptor"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_round_trips() {
        let descriptor = ExistingRunnerDescriptor {
            process_id: 42,
            broker_fd: 7,
        };
        let encoded = descriptor.encode().unwrap();
        assert_eq!(encoded.len(), ENCODED_SIZE);
        assert_eq!(&encoded[..4], &descriptor.process_id.to_le_bytes());
        assert_eq!(
            ExistingRunnerDescriptor::decode(&encoded).unwrap(),
            descriptor
        );
    }

    #[test]
    fn descriptor_rejects_invalid_fields_and_lengths() {
        let encoded = ExistingRunnerDescriptor {
            process_id: 42,
            broker_fd: 7,
        }
        .encode()
        .unwrap();
        let mut zero_pid = encoded.clone();
        zero_pid[..4].copy_from_slice(&0u32.to_le_bytes());
        let mut negative_pid = encoded.clone();
        negative_pid[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut standard_stream = encoded.clone();
        standard_stream[4..].copy_from_slice(&2i32.to_le_bytes());
        let mut trailing_byte = encoded.clone();
        trailing_byte.push(0);
        for invalid in [
            &encoded[..ENCODED_SIZE - 1],
            &zero_pid,
            &negative_pid,
            &standard_stream,
            &trailing_byte,
        ] {
            let error = ExistingRunnerDescriptor::decode(invalid)
                .expect_err("an invalid descriptor must be rejected");
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }
        assert!(
            ExistingRunnerDescriptor {
                process_id: 42,
                broker_fd: 0,
            }
            .encode()
            .is_err()
        );
    }
}
