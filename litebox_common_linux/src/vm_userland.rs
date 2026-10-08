// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! How the LiteBox VM kernel launches a Linux program in a ring-3 runner
//! process (`litebox_runner_linux_on_vm_userland`), and how the runner reports
//! its end. The process serves no requests: it runs the program once and
//! exits.
//!
//! - Images (`StartupInfo::images` of `litebox_common_vm_abi`): the program's
//!   arguments at [`ARGV_IMAGE`] and environment at [`ENVP_IMAGE`], each a
//!   sequence of NUL-terminated strings ([`encode_strings`]). `argv[0]` is the
//!   program's absolute path in the broker's file system.
//! - Identity: unused, all zeros.
//! - Exit code (the `Exit` call): [`exit_code`] of the program's status, or
//!   [`RUNNER_FAILURE`] if the runner itself failed.

use alloc::vec::Vec;
use litebox_broker_protocol::process::ProcessExitStatus;

/// `StartupInfo::images` indices.
pub const ARGV_IMAGE: usize = 0;
pub const ENVP_IMAGE: usize = 1;

/// The runner failed before or instead of running the program. Distinct from
/// every [`exit_code`], which are wait statuses and so fit 16 bits.
pub const RUNNER_FAILURE: u32 = u32::MAX;

/// Each string NUL-terminated, in order; `None` if one contains a NUL.
pub fn encode_strings<'a>(strings: impl IntoIterator<Item = &'a str>) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    for s in strings {
        if s.contains('\0') {
            return None;
        }
        bytes.extend_from_slice(s.as_bytes());
        bytes.push(0);
    }
    Some(bytes)
}

/// The strings of [`encode_strings`], without their NULs; `None` unless
/// `bytes` is empty or ends with a NUL.
pub fn decode_strings(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    let Some((&last, body)) = bytes.split_last() else {
        return Some(Vec::new());
    };
    if last != 0 {
        return None;
    }
    Some(body.split(|&b| b == 0).collect())
}

/// The program's status as a Linux wait status: `code << 8` for an exit, the
/// signal number for a signal death; [`RUNNER_FAILURE`] for an unknown one.
pub fn exit_code(status: ProcessExitStatus) -> u32 {
    match status {
        ProcessExitStatus::Exited { code } => (code & 0xff) << 8,
        ProcessExitStatus::Signaled { signal } => signal & 0x7f,
        _ => RUNNER_FAILURE,
    }
}

/// The inverse of [`exit_code`]; `None` for [`RUNNER_FAILURE`] or any other
/// value it never returns.
pub fn exit_status(code: u32) -> Option<ProcessExitStatus> {
    match (code >> 8, code & 0xff) {
        (exit, 0) if exit <= 0xff => Some(ProcessExitStatus::Exited { code: exit }),
        (0, signal) if signal <= 0x7f => Some(ProcessExitStatus::Signaled { signal }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_round_trip() {
        let bytes = encode_strings(["/hello", "", "a b"]).unwrap();
        assert_eq!(bytes, b"/hello\0\0a b\0");
        assert_eq!(
            decode_strings(&bytes).unwrap(),
            [&b"/hello"[..], b"", b"a b"]
        );
        assert_eq!(encode_strings([]).unwrap(), b"");
        assert_eq!(decode_strings(b"").unwrap(), [] as [&[u8]; 0]);
        assert_eq!(encode_strings(["a\0b"]), None);
        assert_eq!(decode_strings(b"abc"), None);
    }

    #[test]
    fn exit_codes_round_trip() {
        for status in [
            ProcessExitStatus::Exited { code: 0 },
            ProcessExitStatus::Exited { code: 255 },
            ProcessExitStatus::Signaled { signal: 9 },
        ] {
            assert_eq!(exit_status(exit_code(status)), Some(status));
        }
        assert_eq!(exit_code(ProcessExitStatus::Unknown), RUNNER_FAILURE);
        assert_eq!(exit_status(RUNNER_FAILURE), None);
    }
}
