// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Opaque runner adoption data for a Windows runner created by another runner.
//!
//! Control-pipe names carry an unguessable nonce, so other processes cannot predict and
//! pre-create them; the broker also binds them as the first instance and the child verifies the
//! server.

use std::ffi::OsString;
use std::hash::Hasher as _;
use std::io::{Error, ErrorKind, Result};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::sync::atomic::{AtomicU64, Ordering};

const HEADER_SIZE: usize = 16;
const PIPE_PREFIX: &str = r"\\.\pipe\litebox-native-runner-";
/// Bytes of keyed-hash output in each control-pipe name.
const NONCE_SIZE: usize = 16;

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
                nonce.len() == 2 * NONCE_SIZE
                    && nonce
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

/// Generator of unpredictable control-channel names for a runner's native clones.
///
/// Its key comes from the system RNG, which a process created by `RtlCloneUserProcess` cannot
/// use, so the key is drawn once in a normally started runner and inherited by its clones. Each
/// name is a keyed hash of the naming process's ID and a counter, so names stay distinct across
/// a runner and its clones while other processes cannot predict them.
pub struct ControlChannelNames {
    key: [u64; 2],
    next: AtomicU64,
}

impl ControlChannelNames {
    /// Creates a generator with a fresh key from the system RNG.
    pub fn new() -> Result<Self> {
        let mut key = [0u8; 16];
        // SAFETY: `key` is writable for its length, and the system-preferred RNG needs no
        // algorithm handle.
        let status = unsafe {
            windows_sys::Win32::Security::Cryptography::BCryptGenRandom(
                core::ptr::null_mut(),
                key.as_mut_ptr(),
                u32::try_from(key.len()).map_err(|_| Error::other("key is too long"))?,
                windows_sys::Win32::Security::Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            return Err(Error::other(format!(
                "failed to generate a control-channel key: {status:#x}"
            )));
        }
        let (low, high) = key.split_at(8);
        Ok(Self {
            key: [
                u64::from_le_bytes(low.try_into().map_err(|_| Error::other("invalid key"))?),
                u64::from_le_bytes(high.try_into().map_err(|_| Error::other("invalid key"))?),
            ],
            next: AtomicU64::new(0),
        })
    }

    /// Returns the next control-channel name for a clone of the calling process.
    pub fn next_name(&self) -> OsString {
        let process_id = std::process::id();
        let counter = self.next.fetch_add(1, Ordering::Relaxed);
        let half = |domain: u8| {
            // SipHash is a keyed pseudorandom function, which is all an unguessable name needs.
            #[allow(deprecated, reason = "std offers no other keyed SipHash")]
            let mut hasher = std::hash::SipHasher::new_with_keys(self.key[0], self.key[1]);
            hasher.write_u8(domain);
            hasher.write_u32(process_id);
            hasher.write_u64(counter);
            hasher.finish()
        };
        format!("{PIPE_PREFIX}{process_id}-{:016x}{:016x}", half(0), half(1)).into()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_round_trips() {
        let descriptor = ExistingRunnerDescriptor {
            process_handle: 0x1234,
            process_id: 42,
            control_channel: ControlChannelNames::new().unwrap().next_name(),
        };
        let encoded = descriptor.encode().unwrap();
        let decoded = ExistingRunnerDescriptor::decode(&encoded, std::process::id()).unwrap();
        assert_eq!(decoded.process_handle, descriptor.process_handle);
        assert_eq!(decoded.process_id, descriptor.process_id);
        assert_eq!(decoded.control_channel, descriptor.control_channel);
    }

    #[test]
    fn control_channels_are_distinct_and_keyed() {
        let names = ControlChannelNames::new().unwrap();
        let first = names.next_name();
        let second = names.next_name();
        assert_ne!(first, second);
        assert_ne!(first, ControlChannelNames::new().unwrap().next_name());
        let prefix = format!("{PIPE_PREFIX}{}-", std::process::id());
        let nonce = first.to_str().unwrap().strip_prefix(&prefix).unwrap();
        assert_eq!(nonce.len(), 2 * NONCE_SIZE);
    }

    #[test]
    fn descriptor_rejects_a_different_parent() {
        let descriptor = ExistingRunnerDescriptor {
            process_handle: 0x1234,
            process_id: 42,
            control_channel: ControlChannelNames::new().unwrap().next_name(),
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
            OsString::from(format!("{prefix}1")),
            OsString::from(format!("{prefix}{}", "0".repeat(2 * NONCE_SIZE - 1))),
            OsString::from(format!("{prefix}{}", "0".repeat(2 * NONCE_SIZE + 1))),
            OsString::from(format!("{prefix}{}", "A".repeat(2 * NONCE_SIZE))),
            OsString::from(format!("{prefix}{}\\extra", "0".repeat(2 * NONCE_SIZE))),
            OsString::from(format!("{prefix}{}\0", "0".repeat(2 * NONCE_SIZE - 1))),
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
