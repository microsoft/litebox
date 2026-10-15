// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Opaque launch data for a Linux runner created by another runner.

use std::ffi::{OsStr, OsString};
use std::io::{Error, ErrorKind, Result};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const HEADER_SIZE: usize = 12;
const DIRECTORY_PREFIX: &str = "litebox-native-runner-";
const SOCKET_NAME: &str = "broker.sock";
static NEXT_DIRECTORY_NONCE: AtomicU64 = AtomicU64::new(0);

/// Description of an already-created Linux runner process.
pub struct ExistingRunnerLaunchDescriptor {
    /// Host process ID of the runner that created the child.
    pub parent_process_id: u32,
    /// Host process ID of the cloned child.
    pub process_id: u32,
    /// Dedicated broker control socket for the child.
    pub control_channel: PathBuf,
}

impl ExistingRunnerLaunchDescriptor {
    /// Encodes this descriptor for the opaque broker launch field.
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_control_channel(&self.control_channel, self.parent_process_id)?;
        let path = self.control_channel.as_os_str().as_bytes();
        let path_length = u32::try_from(path.len())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "control channel is too long"))?;
        let length = HEADER_SIZE
            .checked_add(path.len())
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "launch descriptor is too long"))?;
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(length)?;
        encoded.extend_from_slice(&self.parent_process_id.to_le_bytes());
        encoded.extend_from_slice(&self.process_id.to_le_bytes());
        encoded.extend_from_slice(&path_length.to_le_bytes());
        encoded.extend_from_slice(path);
        Ok(encoded)
    }

    /// Decodes and validates an opaque broker launch descriptor.
    pub fn decode(encoded: &[u8]) -> Result<Self> {
        let header: &[u8; HEADER_SIZE] = encoded
            .get(..HEADER_SIZE)
            .and_then(|header| header.try_into().ok())
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "launch descriptor is truncated"))?;
        let parent_process_id = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let process_id = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let path_length =
            u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
        if parent_process_id == 0
            || process_id == 0
            || HEADER_SIZE.checked_add(path_length) != Some(encoded.len())
        {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid launch descriptor",
            ));
        }
        let control_channel = PathBuf::from(OsString::from_vec(encoded[HEADER_SIZE..].to_vec()));
        validate_control_channel(&control_channel, parent_process_id)?;
        Ok(Self {
            parent_process_id,
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
        let descriptor = ExistingRunnerLaunchDescriptor {
            parent_process_id: std::process::id(),
            process_id: 42,
            control_channel: control_channel.clone(),
        };
        let encoded = descriptor.encode().unwrap();
        let decoded = ExistingRunnerLaunchDescriptor::decode(&encoded).unwrap();
        assert_eq!(decoded.parent_process_id, descriptor.parent_process_id);
        assert_eq!(decoded.process_id, descriptor.process_id);
        assert_eq!(decoded.control_channel, descriptor.control_channel);
        remove_control_channel(&control_channel);
    }
}
