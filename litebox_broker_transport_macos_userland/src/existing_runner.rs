// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Opaque runner adoption data for a macOS runner natively forked by another runner.
//!
//! macOS cannot hand the broker a descriptor from the clone's table, so the broker listens for
//! the clone instead: it binds [`ExistingRunnerDescriptor::rendezvous_socket_path`] in its own
//! runner directory, which the clone derives from the control socket path it inherited and its
//! own process ID. The path depends only on the broker-chosen directory and the validated process
//! ID, and the broker authenticates whoever connects as the adopted process.

use std::io::{Error, ErrorKind, Result};
use std::path::{Path, PathBuf};

const ENCODED_SIZE: usize = 4;

/// Host identity of an already-created macOS runner process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExistingRunnerDescriptor {
    /// Host process ID of the forked child.
    pub process_id: u32,
}

impl ExistingRunnerDescriptor {
    /// Encodes this descriptor.
    ///
    /// # Errors
    ///
    /// Fails with [`ErrorKind::InvalidInput`] if the process ID is not a positive `pid_t`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate(ErrorKind::InvalidInput)?;
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(ENCODED_SIZE)?;
        encoded.extend_from_slice(&self.process_id.to_le_bytes());
        Ok(encoded)
    }

    /// Decodes and validates a descriptor received from an untrusted runner.
    ///
    /// # Errors
    ///
    /// Fails with [`ErrorKind::InvalidData`] if the length is wrong or the process ID is not a
    /// positive `pid_t`.
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

    /// Returns where the broker listens for this runner, inside `runner_directory`, the
    /// broker-owned directory that holds every runner's control socket.
    ///
    /// The name stays short because `sun_path` holds at most 104 bytes.
    #[must_use]
    pub fn rendezvous_socket_path(&self, runner_directory: &Path) -> PathBuf {
        runner_directory.join(format!("fork-{}.sock", self.process_id))
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
        assert_eq!(encoded, 42u32.to_le_bytes());
        assert_eq!(
            ExistingRunnerDescriptor::decode(&encoded).unwrap(),
            descriptor
        );
        assert_eq!(
            descriptor.rendezvous_socket_path(Path::new("/broker")),
            Path::new("/broker/fork-42.sock")
        );
    }

    #[test]
    fn descriptor_rejects_invalid_process_ids_and_lengths() {
        let encoded = ExistingRunnerDescriptor { process_id: 42 }
            .encode()
            .unwrap();
        let mut trailing_byte = encoded.clone();
        trailing_byte.push(0);
        for invalid in [
            &encoded[..ENCODED_SIZE - 1],
            &0u32.to_le_bytes(),
            &u32::MAX.to_le_bytes(),
            &trailing_byte,
        ] {
            let error = ExistingRunnerDescriptor::decode(invalid)
                .expect_err("an invalid descriptor must be rejected");
            assert_eq!(error.kind(), ErrorKind::InvalidData, "input {invalid:?}");
        }
        for process_id in [0, u32::MAX] {
            let error = ExistingRunnerDescriptor { process_id }
                .encode()
                .expect_err("an invalid descriptor must not be encoded");
            assert_eq!(error.kind(), ErrorKind::InvalidInput);
        }
    }
}
