// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Opaque runner adoption data for a Windows runner created by another runner.

use std::ffi::OsString;
use std::io::{Error, ErrorKind, Result};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::sync::atomic::{AtomicU64, Ordering};

const HEADER_SIZE: usize = 16;
const PIPE_PREFIX: &str = r"\\.\pipe\litebox-native-runner-";
static NEXT_PIPE_NONCE: AtomicU64 = AtomicU64::new(0);

/// Host identity and control endpoint of an already-created Windows runner process.
pub struct ExistingRunnerDescriptor {
    /// Child process handle value in the parent runner's handle table.
    pub process_handle: u64,
    /// Windows process identifier expected for `process_handle` and the pipe client.
    pub process_id: u32,
    /// Dedicated broker control channel for the child.
    pub control_channel: OsString,
}

impl ExistingRunnerDescriptor {
    /// Encodes this descriptor for the opaque broker launch field.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let path: Vec<_> = self.control_channel.encode_wide().collect();
        let path_bytes = path
            .len()
            .checked_mul(core::mem::size_of::<u16>())
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "control channel is too long"))?;
        let length = HEADER_SIZE
            .checked_add(path_bytes)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "runner descriptor is too long"))?;
        let mut encoded = Vec::new();
        encoded.try_reserve_exact(length)?;
        encoded.extend_from_slice(&self.process_handle.to_le_bytes());
        encoded.extend_from_slice(&self.process_id.to_le_bytes());
        let path_length = u32::try_from(path.len())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "control channel is too long"))?;
        encoded.extend_from_slice(&path_length.to_le_bytes());
        for code_unit in path {
            encoded.extend_from_slice(&code_unit.to_le_bytes());
        }
        Ok(encoded)
    }

    /// Decodes a descriptor and validates its pipe name against the known parent runner's PID.
    pub fn decode(encoded: &[u8], parent_process_id: u32) -> Result<Self> {
        let header: &[u8; HEADER_SIZE] = encoded
            .get(..HEADER_SIZE)
            .and_then(|header| header.try_into().ok())
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "runner descriptor is truncated"))?;
        let process_handle = u64::from_le_bytes([
            header[0], header[1], header[2], header[3], header[4], header[5], header[6], header[7],
        ]);
        let process_id = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        let path_length =
            u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as usize;
        let path_bytes = path_length
            .checked_mul(core::mem::size_of::<u16>())
            .and_then(|length| HEADER_SIZE.checked_add(length))
            .filter(|length| *length == encoded.len())
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid control channel length"))?;
        debug_assert_eq!(path_bytes, encoded.len());
        let (path, remainder) = encoded[HEADER_SIZE..].as_chunks::<2>();
        debug_assert_eq!(remainder, []);
        let path: Vec<_> = path
            .iter()
            .map(|bytes| u16::from_le_bytes(*bytes))
            .collect();
        let control_channel = OsString::from_wide(&path);
        let expected_prefix = format!("{PIPE_PREFIX}{parent_process_id}-");
        let valid_control_channel = control_channel
            .to_str()
            .and_then(|name| name.strip_prefix(&expected_prefix))
            .is_some_and(|nonce| {
                !nonce.is_empty() && nonce.bytes().all(|byte| byte.is_ascii_digit())
            });
        if parent_process_id == 0
            || process_handle == 0
            || process_id == 0
            || !valid_control_channel
        {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid runner descriptor",
            ));
        }
        Ok(Self {
            process_handle,
            process_id,
            control_channel,
        })
    }
}

/// Creates a process-unique control-channel name for a cloned runner.
pub fn unique_control_channel() -> OsString {
    let nonce = NEXT_PIPE_NONCE.fetch_add(1, Ordering::Relaxed);
    format!("{PIPE_PREFIX}{}-{nonce}", std::process::id()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_round_trips() {
        let descriptor = ExistingRunnerDescriptor {
            process_handle: 0x1234,
            process_id: 42,
            control_channel: unique_control_channel(),
        };
        let encoded = descriptor.encode().unwrap();
        let decoded = ExistingRunnerDescriptor::decode(&encoded, std::process::id()).unwrap();
        assert_eq!(decoded.process_handle, descriptor.process_handle);
        assert_eq!(decoded.process_id, descriptor.process_id);
        assert_eq!(decoded.control_channel, descriptor.control_channel);
    }

    #[test]
    fn descriptor_rejects_a_different_parent() {
        let descriptor = ExistingRunnerDescriptor {
            process_handle: 0x1234,
            process_id: 42,
            control_channel: unique_control_channel(),
        };
        let encoded = descriptor.encode().unwrap();
        let other_parent = if std::process::id() == 1 { 2 } else { 1 };
        for parent_process_id in [0, other_parent] {
            let error = ExistingRunnerDescriptor::decode(&encoded, parent_process_id)
                .err()
                .expect("an invalid or different parent must be rejected");
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }
    }

    #[test]
    fn descriptor_rejects_malformed_pipe_names() {
        let parent_process_id = std::process::id();
        let prefix = format!("{PIPE_PREFIX}{parent_process_id}-");
        for control_channel in [
            OsString::from(r"\\.\pipe\unrelated-0"),
            OsString::from(format!("{PIPE_PREFIX}{parent_process_id}0-0")),
            OsString::from(prefix.clone()),
            OsString::from(format!("{prefix}abc")),
            OsString::from(format!("{prefix}-1")),
            OsString::from(format!("{prefix}1\\extra")),
            OsString::from(format!("{prefix}1\0")),
            OsString::from_wide(
                &prefix
                    .encode_utf16()
                    .chain(core::iter::once(0xD800))
                    .collect::<Vec<_>>(),
            ),
        ] {
            let descriptor = ExistingRunnerDescriptor {
                process_handle: 0x1234,
                process_id: 42,
                control_channel,
            };
            let encoded = descriptor.encode().unwrap();
            let error = ExistingRunnerDescriptor::decode(&encoded, parent_process_id)
                .err()
                .expect("a malformed pipe name must be rejected");
            assert_eq!(error.kind(), ErrorKind::InvalidData);
        }
    }
}
