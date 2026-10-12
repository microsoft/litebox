// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Program launches in envelopes ([`Protocol::PROGRAM`]), for runners of
//! standalone command-line programs on any guest OS. A request's payload is a
//! [`Program`]: a [`ProgramHeader`], then the path, the arguments, and the
//! environment, each NUL-terminated. A reply's payload is an [`ExitReply`].
//! Each envelope is only its payload.

use crate::envelope::{Envelope, Layout, PartKind, Protocol};
use alloc::ffi::CString;
use alloc::string::String;
use alloc::vec::Vec;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// What to run. The path is absolute, in the runner's file system (e.g., the
/// broker's); the arguments start with the program's name, by convention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub path: String,
    pub argv: Vec<CString>,
    pub envp: Vec<CString>,
}

/// Counts of the strings after the path.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ProgramHeader {
    argc: u32,
    envc: u32,
}

/// How a program ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// With an exit code (e.g., a Windows process's, or a Unix process's
    /// status).
    Exited { code: u32 },
    /// By a signal, on guest OSes that have them.
    Signaled { signal: u32 },
    /// The runner could not tell.
    Unknown,
}

const EXITED: u32 = 0;
const SIGNALED: u32 = 1;
const UNKNOWN: u32 = 2;

/// An [`ExitStatus`] on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ExitReply {
    kind: u32,
    /// The exit code or the signal.
    value: u32,
}

impl From<ExitStatus> for ExitReply {
    fn from(status: ExitStatus) -> Self {
        let (kind, value) = match status {
            ExitStatus::Exited { code } => (EXITED, code),
            ExitStatus::Signaled { signal } => (SIGNALED, signal),
            ExitStatus::Unknown => (UNKNOWN, 0),
        };
        Self { kind, value }
    }
}

impl ExitReply {
    /// `None` for an unknown kind.
    pub fn status(self) -> Option<ExitStatus> {
        match (self.kind, self.value) {
            (EXITED, code) => Some(ExitStatus::Exited { code }),
            (SIGNALED, signal) => Some(ExitStatus::Signaled { signal }),
            (UNKNOWN, 0) => Some(ExitStatus::Unknown),
            _ => None,
        }
    }
}

/// An envelope with `payload` as its only part.
fn envelope(payload: &[u8]) -> Option<Vec<u8>> {
    let layout = Layout::new(
        Protocol::PROGRAM,
        &[(PartKind::PAYLOAD, payload.len() as u64)],
    )
    .ok()?;
    let mut message = alloc::vec![0u8; usize::try_from(layout.message_len()).ok()?];
    layout.write_table(&mut message).ok()?;
    message[layout.parts()[0].range()].copy_from_slice(payload);
    Some(message)
}

/// The payload of a [`Protocol::PROGRAM`] envelope.
fn payload(message: &[u8]) -> Option<&[u8]> {
    let envelope = Envelope::parse(message).ok()?;
    (envelope.protocol() == Protocol::PROGRAM && envelope.parts().len() == 1)
        .then(|| envelope.payload())
}

/// `None` for a relative path, a path with a NUL, or too many strings.
pub fn encode_request(program: &Program) -> Option<Vec<u8>> {
    if !program.path.starts_with('/') || program.path.contains('\0') {
        return None;
    }
    let header = ProgramHeader {
        argc: u32::try_from(program.argv.len()).ok()?,
        envc: u32::try_from(program.envp.len()).ok()?,
    };
    let mut payload = Vec::from(header.as_bytes());
    payload.extend_from_slice(program.path.as_bytes());
    payload.push(0);
    for string in program.argv.iter().chain(&program.envp) {
        payload.extend_from_slice(string.as_bytes_with_nul());
    }
    envelope(&payload)
}

/// `None` for a malformed request, including trailing bytes.
pub fn decode_request(message: &[u8]) -> Option<Program> {
    let (header, mut rest) = ProgramHeader::read_from_prefix(payload(message)?).ok()?;
    let mut next = || {
        let len = rest.iter().position(|&byte| byte == 0)?;
        let string = CString::new(&rest[..len]).ok()?;
        rest = &rest[len + 1..];
        Some(string)
    };
    let path = next()?.into_string().ok()?;
    if !path.starts_with('/') {
        return None;
    }
    let mut strings = |count: u32| (0..count).map(|_| next()).collect::<Option<Vec<_>>>();
    let argv = strings(header.argc)?;
    let envp = strings(header.envc)?;
    rest.is_empty().then_some(Program { path, argv, envp })
}

/// # Panics
///
/// Never: an exit reply always fits an envelope.
pub fn encode_reply(status: ExitStatus) -> Vec<u8> {
    envelope(ExitReply::from(status).as_bytes()).expect("an exit reply fits an envelope")
}

/// `None` for a malformed reply.
pub fn decode_reply(message: &[u8]) -> Option<ExitStatus> {
    ExitReply::read_from_bytes(payload(message)?).ok()?.status()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_replies_round_trip() {
        let program = Program {
            path: String::from("/hello"),
            argv: alloc::vec![CString::new("hello").unwrap(), CString::new("").unwrap()],
            envp: alloc::vec![CString::new("A=b").unwrap()],
        };
        let request = encode_request(&program).unwrap();
        assert_eq!(decode_request(&request), Some(program.clone()));
        for status in [
            ExitStatus::Exited { code: 3 },
            ExitStatus::Signaled { signal: 9 },
            ExitStatus::Unknown,
        ] {
            assert_eq!(decode_reply(&encode_reply(status)), Some(status));
        }
        assert_eq!(decode_reply(&request), None, "not an exit reply");
        let truncated = envelope(&payload(&request).unwrap()[..20]).unwrap();
        assert_eq!(decode_request(&truncated), None);
        let relative = Program {
            path: String::from("hello"),
            ..program
        };
        assert_eq!(encode_request(&relative), None);
        let bad = envelope(ExitReply { kind: 7, value: 0 }.as_bytes()).unwrap();
        assert_eq!(decode_reply(&bad), None);
    }
}
