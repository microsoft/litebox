// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Opaque runner adoption data for a Linux runner cloned by another runner.
//!
//! Before cloning, the parent runner asks the broker for its pending child's control connection.
//! The broker creates a connected socket pair, keeps its end, and delivers the other end to the
//! parent out of band, whose clone inherits it, so no filesystem rendezvous exists for another
//! process to predict or occupy, and the broker never takes a descriptor from a runner.

use std::io::{Error, ErrorKind, Result};

const ENCODED_SIZE: usize = 4;

/// Host identity of an already-created Linux runner process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExistingRunnerDescriptor {
    /// Host process ID of the cloned child.
    pub process_id: u32,
}

impl ExistingRunnerDescriptor {
    /// Encodes this descriptor.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate(ErrorKind::InvalidInput)?;
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(ENCODED_SIZE)?;
        encoded.extend_from_slice(&self.process_id.to_le_bytes());
        Ok(encoded)
    }

    /// Decodes and validates a descriptor received from an untrusted runner.
    pub fn decode(encoded: &[u8]) -> Result<Self> {
        let encoded: &[u8; ENCODED_SIZE] = encoded
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid runner descriptor size"))?;
        let descriptor = Self {
            process_id: u32::from_le_bytes(*encoded),
        };
        descriptor.validate(ErrorKind::InvalidData)?;
        Ok(descriptor)
    }

    fn validate(self, kind: ErrorKind) -> Result<()> {
        if self.process_id == 0 || i32::try_from(self.process_id).is_err() {
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
        let descriptor = ExistingRunnerDescriptor { process_id: 42 };
        let encoded = descriptor.encode().unwrap();
        assert_eq!(encoded, descriptor.process_id.to_le_bytes());
        assert_eq!(
            ExistingRunnerDescriptor::decode(&encoded).unwrap(),
            descriptor
        );
    }

    #[test]
    fn descriptor_rejects_invalid_fields_and_lengths() {
        let encoded = ExistingRunnerDescriptor { process_id: 42 }
            .encode()
            .unwrap();
        let zero_pid = 0u32.to_le_bytes();
        let negative_pid = u32::MAX.to_le_bytes();
        let mut trailing_byte = encoded.clone();
        trailing_byte.push(0);
        for invalid in [
            &encoded[..ENCODED_SIZE - 1],
            &zero_pid[..],
            &negative_pid[..],
            &trailing_byte,
        ] {
            let error = ExistingRunnerDescriptor::decode(invalid)
                .expect_err("an invalid descriptor must be rejected");
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }
        assert!(ExistingRunnerDescriptor { process_id: 0 }.encode().is_err());
    }
}
