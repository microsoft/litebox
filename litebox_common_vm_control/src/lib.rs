// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The control channel of the LiteBox VM kernel (`litebox_runner_vm_kernel`):
//! the host controls the kernel itself, which serves the channel without a
//! guest agent. Guests' standard streams are not on it.
//!
//! The channel must be a reliable byte stream: port [`PORT`] of the VM's
//! virtio console device, as a `virtserialport` (QEMU holds its output until
//! the host takes it; a `virtconsole` drops it), e.g., on a Unix socket:
//!
//! ```text
//! -device virtio-serial-pci,id=vs0,disable-legacy=on
//! -chardev socket,id=control,path=control.sock,server=on,wait=on
//! -device virtserialport,chardev=control,bus=vs0.0,nr=1
//! ```
//!
//! The host sends one [`Request`] at a time, starting with
//! [`Request::Hello`], and waits for its [`Response`]. A message is a frame:
//! its length (le32), then its postcard encoding.
//!
//! The kernel cannot tell whether the host is connected: without one, it
//! waits for requests indefinitely, so if the host goes away, the VMM must
//! end the VM. A frame longer than [`MAX_FRAME_LEN`] means the stream is out
//! of sync, and the kernel panics; other malformed requests get
//! [`Response::Error`].

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The protocol version, which [`Request::Hello`] checks.
pub const VERSION: u32 = 1;

/// The console port of the channel.
pub const PORT: u32 = 1;

/// The longest frame body either end takes.
pub const MAX_FRAME_LEN: usize = 16 << 20;

/// OP-TEE client parameters per call.
pub const OPTEE_PARAMS: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// First: [`Response::Hello`], or an error if the versions differ.
    Hello { version: u32 },
    /// Runs programs at once ([`Service::Programs`]):
    /// [`Response::Ran`] once all ended.
    Run { programs: Vec<Program> },
    /// An OP-TEE client call ([`Service::Optee`]): [`Response::Optee`].
    Optee(OpteeCall),
    /// Live TA instances ([`Service::Optee`]): [`Response::OpteeInstances`].
    OpteeInstances,
    /// Powers the VM off, QEMU reporting `success` (see
    /// `litebox_hal::power::exit`), after [`Response::ShuttingDown`].
    Shutdown { success: bool },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Hello {
        version: u32,
        service: Service,
    },
    Ran {
        /// In the order of the programs.
        runs: Vec<RunResult>,
        /// Shared by the programs, which share their standard streams.
        stdout: Captured,
        stderr: Captured,
    },
    Optee(OpteeCompletion),
    OpteeInstances(u64),
    ShuttingDown,
    /// The request was not served.
    Error(String),
}

impl Request {
    /// Unlike `Debug`, bounded: contents may be up to [`MAX_FRAME_LEN`].
    pub fn name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "Hello",
            Self::Run { .. } => "Run",
            Self::Optee(_) => "Optee",
            Self::OpteeInstances => "OpteeInstances",
            Self::Shutdown { .. } => "Shutdown",
        }
    }
}

/// What the kernel serves; its payload decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Service {
    /// Standalone programs, a runner process each.
    Programs,
    /// OP-TEE TAs, a runner process per TA instance.
    Optee,
}

/// A program to run, in a runner process of its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    /// `argv[0]` is the program's absolute path, in the runner's file system.
    pub argv: Vec<String>,
    /// `KEY=VALUE` strings.
    pub envp: Vec<String>,
    pub stdin: Stdin,
}

/// A program's standard input. Programs run at once share it, so at most one
/// has input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stdin {
    /// These bytes, then its end (none: `/dev/null`).
    Bytes(Vec<u8>),
    /// The console's (port 0's): what the host sends it, when it sends it. It
    /// never ends.
    Console,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunResult {
    /// How the program ended, or why it did not run to its end.
    pub status: Result<ExitStatus, String>,
    /// Guest syscalls the runner did not take directly, so the kernel
    /// reflected them.
    pub reflected_syscalls: u64,
}

/// How a program ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitStatus {
    Exited {
        code: u32,
    },
    Signaled {
        signal: u32,
    },
    /// The runner could not tell.
    Unknown,
}

/// What an output stream wrote, up to a limit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Captured {
    pub bytes: Vec<u8>,
    /// The stream wrote more than `bytes`.
    pub truncated: bool,
}

/// A GlobalPlatform TEE client call, as `litebox_shim_vm_kernel::optee`'s
/// `Invocation`, plus its target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpteeCall {
    /// The `OpenSession` target's UUID, in RFC 4122 byte order.
    pub ta: [u8; 16],
    pub func: EntryFunc,
    pub session: u32,
    pub cmd_id: u32,
    /// `TEE_LOGIN_*`.
    pub login: u32,
    /// RFC 4122 byte order.
    pub client_uuid: [u8; 16],
    pub params: [InParam; OPTEE_PARAMS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryFunc {
    OpenSession,
    InvokeCommand,
    CloseSession,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum InParam {
    #[default]
    None,
    ValueInput {
        a: u64,
        b: u64,
    },
    ValueOutput,
    ValueInout {
        a: u64,
        b: u64,
    },
    MemrefInput(Vec<u8>),
    MemrefOutput {
        capacity: u64,
    },
    /// The TA sees the whole capacity, `data` zero-padded.
    MemrefInout {
        data: Vec<u8>,
        capacity: u64,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutParam {
    #[default]
    None,
    Value {
        a: u64,
        b: u64,
    },
    /// `size` is the TA's, which exceeds the capacity for a short buffer;
    /// `data` is at most the capacity.
    Memref {
        data: Vec<u8>,
        size: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpteeCompletion {
    /// `TEE_Result`, possibly TA-defined.
    pub result: u32,
    pub origin: u32,
    pub session: u32,
    pub params: [OutParam; OPTEE_PARAMS],
}

/// `message` as a frame.
///
/// # Panics
///
/// If the encoding exceeds [`MAX_FRAME_LEN`].
pub fn encode<T: Serialize>(message: &T) -> Vec<u8> {
    let mut frame =
        postcard::to_extend(message, alloc::vec![0; 4]).expect("encoding to a Vec does not fail");
    let len = frame.len() - 4;
    assert!(len <= MAX_FRAME_LEN, "a {len}-byte message");
    frame[..4].copy_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
    frame
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// A frame longer than [`MAX_FRAME_LEN`]: the stream is out of sync, so
    /// the channel is unusable.
    TooLong(usize),
    /// The frame is skipped; the stream stays in sync.
    Malformed(postcard::Error),
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong(len) => write!(f, "a {len}-byte frame exceeds {MAX_FRAME_LEN} bytes"),
            Self::Malformed(error) => write!(f, "malformed message: {error}"),
        }
    }
}

impl core::error::Error for FrameError {}

/// Splits a byte stream into messages.
#[derive(Default)]
pub struct Decoder {
    buffer: Vec<u8>,
}

impl Decoder {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// The next message, once its whole frame arrived.
    ///
    /// # Errors
    ///
    /// See [`FrameError`].
    pub fn next_message<T: DeserializeOwned>(&mut self) -> Result<Option<T>, FrameError> {
        let Some((len, rest)) = self.buffer.split_first_chunk::<4>() else {
            return Ok(None);
        };
        let len = usize::try_from(u32::from_le_bytes(*len)).unwrap_or(usize::MAX);
        if len > MAX_FRAME_LEN {
            return Err(FrameError::TooLong(len));
        }
        let Some(body) = rest.get(..len) else {
            return Ok(None);
        };
        let message = postcard::from_bytes(body).map_err(FrameError::Malformed);
        self.buffer.drain(..4 + len);
        message.map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn requests() -> Vec<Request> {
        vec![
            Request::Hello { version: VERSION },
            Request::Run {
                programs: vec![Program {
                    argv: vec!["/hello".into(), "world".into()],
                    envp: vec!["A=b".into()],
                    stdin: Stdin::Bytes(b"input".to_vec()),
                }],
            },
            Request::Optee(OpteeCall {
                ta: [1; 16],
                func: EntryFunc::InvokeCommand,
                session: 2,
                cmd_id: 3,
                login: 4,
                client_uuid: [5; 16],
                params: [
                    InParam::ValueInout { a: 1, b: 2 },
                    InParam::MemrefInout {
                        data: vec![1, 2, 3],
                        capacity: 8,
                    },
                    InParam::MemrefOutput { capacity: 4 },
                    InParam::None,
                ],
            }),
            Request::Shutdown { success: true },
        ]
    }

    #[test]
    fn messages_round_trip_split_anywhere() {
        let requests = requests();
        let stream: Vec<u8> = requests.iter().flat_map(encode).collect();
        let mut decoder = Decoder::default();
        let mut received = Vec::new();
        // Byte by byte: frames may arrive split anywhere.
        for byte in stream {
            decoder.push(&[byte]);
            while let Some(request) = decoder.next_message::<Request>().unwrap() {
                received.push(request);
            }
        }
        assert_eq!(received, requests);
    }

    #[test]
    fn malformed_frames_are_skipped() {
        let mut decoder = Decoder::default();
        // Variant 200 of `Request` does not exist.
        decoder.push(&[1, 0, 0, 0, 200]);
        decoder.push(&encode(&Request::OpteeInstances));
        assert!(matches!(
            decoder.next_message::<Request>(),
            Err(FrameError::Malformed(_))
        ));
        assert_eq!(decoder.next_message(), Ok(Some(Request::OpteeInstances)));
    }

    #[test]
    fn overlong_frames_are_refused_before_their_body() {
        let mut decoder = Decoder::default();
        decoder.push(&u32::try_from(MAX_FRAME_LEN + 1).unwrap().to_le_bytes());
        assert_eq!(
            decoder.next_message::<Request>(),
            Err(FrameError::TooLong(MAX_FRAME_LEN + 1))
        );
    }
}
