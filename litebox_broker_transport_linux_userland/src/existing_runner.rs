// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Opaque runner adoption data for a Linux runner created by another runner.

use std::ffi::{OsStr, OsString};
use std::io::{Error, ErrorKind, Result};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const HEADER_SIZE: usize = 8;
const DIRECTORY_PREFIX: &str = "litebox-native-runner-";
const SOCKET_NAME: &str = "broker.sock";
static NEXT_DIRECTORY_NONCE: AtomicU64 = AtomicU64::new(0);

/// Host identity and control endpoint of an already-created Linux runner process.
pub struct ExistingRunnerDescriptor {
    /// Host process ID of the cloned child.
    pub process_id: u32,
    /// Dedicated broker control socket for the child.
    pub control_channel: PathBuf,
}

impl ExistingRunnerDescriptor {
    /// Encodes this descriptor, validating its socket path against the calling runner's PID.
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_control_channel(&self.control_channel, std::process::id())?;
        let path = self.control_channel.as_os_str().as_bytes();
        let path_length = u32::try_from(path.len())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "control channel is too long"))?;
        let length = HEADER_SIZE
            .checked_add(path.len())
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "runner descriptor is too long"))?;
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(length)?;
        encoded.extend_from_slice(&self.process_id.to_le_bytes());
        encoded.extend_from_slice(&path_length.to_le_bytes());
        encoded.extend_from_slice(path);
        Ok(encoded)
    }

    /// Decodes a descriptor and validates its socket path against the known parent runner's PID.
    pub fn decode(encoded: &[u8], parent_process_id: u32) -> Result<Self> {
        let header: &[u8; HEADER_SIZE] = encoded
            .get(..HEADER_SIZE)
            .and_then(|header| header.try_into().ok())
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "runner descriptor is truncated"))?;
        let process_id = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let path_length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if parent_process_id == 0
            || process_id == 0
            || HEADER_SIZE.checked_add(path_length) != Some(encoded.len())
        {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid runner descriptor",
            ));
        }
        let control_channel = PathBuf::from(OsString::from_vec(encoded[HEADER_SIZE..].to_vec()));
        validate_control_channel(&control_channel, parent_process_id)?;
        Ok(Self {
            process_id,
            control_channel,
        })
    }
}

/// Creates a process-unique path for a cloned runner's control socket.
pub fn unique_control_channel() -> PathBuf {
    let process_id = std::process::id();
    let nonce = NEXT_DIRECTORY_NONCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir()
        .join(format!("{DIRECTORY_PREFIX}{process_id}-{nonce}"))
        .join(SOCKET_NAME)
}

/// Removes a control socket and its private directory after launch or supervision ends.
pub fn remove_control_channel(path: &Path) {
    let _ = std::fs::remove_file(path);
    if let Some(directory) = path.parent() {
        let _ = std::fs::remove_dir(directory);
    }
}

fn validate_control_channel(path: &Path, parent_process_id: u32) -> Result<()> {
    let Some(directory) = path.parent() else {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "invalid control channel",
        ));
    };
    let expected_prefix = format!("{DIRECTORY_PREFIX}{parent_process_id}-");
    let valid = path.file_name() == Some(OsStr::new(SOCKET_NAME))
        && directory.parent() == Some(std::env::temp_dir().as_path())
        && directory
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| {
                name.strip_prefix(&expected_prefix).is_some_and(|nonce| {
                    !nonce.is_empty() && nonce.bytes().all(|byte| byte.is_ascii_digit())
                })
            });
    if !valid {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "invalid control channel",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_round_trips() {
        let control_channel = unique_control_channel();
        let descriptor = ExistingRunnerDescriptor {
            process_id: 42,
            control_channel: control_channel.clone(),
        };
        let encoded = descriptor.encode().unwrap();
        assert_eq!(
            encoded.len(),
            HEADER_SIZE + control_channel.as_os_str().as_bytes().len()
        );
        assert_eq!(&encoded[..4], &descriptor.process_id.to_le_bytes());
        let decoded = ExistingRunnerDescriptor::decode(&encoded, std::process::id()).unwrap();
        assert_eq!(decoded.process_id, descriptor.process_id);
        assert_eq!(decoded.control_channel, descriptor.control_channel);
        remove_control_channel(&control_channel);
    }

    #[test]
    fn descriptor_rejects_a_different_parent() {
        let descriptor = ExistingRunnerDescriptor {
            process_id: 42,
            control_channel: unique_control_channel(),
        };
        let encoded = descriptor.encode().unwrap();
        let other_parent = if std::process::id() == 1 { 2 } else { 1 };
        let error = ExistingRunnerDescriptor::decode(&encoded, other_parent)
            .err()
            .expect("a different parent's socket must be rejected");
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn descriptor_rejects_invalid_headers_and_lengths() {
        let descriptor = ExistingRunnerDescriptor {
            process_id: 42,
            control_channel: unique_control_channel(),
        };
        let encoded = descriptor.encode().unwrap();
        let mut zero_pid = encoded.clone();
        zero_pid[..4].copy_from_slice(&0u32.to_le_bytes());
        let mut wrong_length = encoded.clone();
        wrong_length[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut trailing_byte = encoded.clone();
        trailing_byte.push(0);
        for invalid in [
            &encoded[..HEADER_SIZE - 1],
            &zero_pid,
            &wrong_length,
            &trailing_byte,
        ] {
            let error = ExistingRunnerDescriptor::decode(invalid, std::process::id())
                .err()
                .expect("an invalid descriptor must be rejected");
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }
        assert!(ExistingRunnerDescriptor::decode(&encoded, 0).is_err());
    }
}
