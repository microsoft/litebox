// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The control channel of the LiteBox VM kernel (`litebox_runner_vm_kernel`):
//! the host controls the kernel itself, which serves the channel without a
//! guest agent. Guests' standard streams are the VM console's; the channel
//! carries only a run's output, bounded, in its response.
//!
//! The channel is a virtio-vsock stream connection from the host (CID 2) to
//! port [`PORT`] of the VM's CID, e.g., with QEMU's
//! `-device vhost-vsock-pci,guest-cid=3,disable-legacy=on`, and an
//! `AF_VSOCK` socket connected to CID 3, port [`PORT`], on the host. The
//! kernel serves one connection at a time, and listens again once the host
//! disconnects.
//!
//! A connection must start with [`Request::Hello`]; otherwise the kernel
//! answers [`Response::Error`] (best effort) and closes the connection.
//! After that, the host sends one [`Request`] at a time and waits for its
//! [`Response`].
//!
//! # Trust model
//!
//! The channel has no authentication: as with Kata Containers' agent,
//! whoever connects controls the VM. With vhost-vsock, any host process
//! that can open `AF_VSOCK` sockets can connect to the guest's CID, run
//! programs (which see the VM's shares and network), and shut the VM down;
//! on Linux, that is every local user by default. Use the channel only on
//! hosts whose users are all trusted. Otherwise, restrict vsock on the host:
//! e.g., with a VMM whose vsock is a Unix socket guarded by file permissions
//! ("hybrid vsock": Firecracker, Cloud Hypervisor, `vhost-device-vsock`), or
//! with an LSM policy.
//!
//! # Frames
//!
//! A message is a frame: its length (le32), then its body. Only [`encode`]
//! and [`Decoder`] know how a body is encoded, which may change with
//! [`VERSION`] (e.g., to a verified codec); a body decodes completely, as
//! exactly one message, or is rejected. Bodies are postcard (`no_std`, no
//! allocation beyond the messages, compact for byte buffers), the one
//! dependency beyond `serde`. A frame longer than [`MAX_FRAME_LEN`] means the
//! stream is out of sync, and the kernel closes the connection; other
//! malformed requests, including lists longer than their bounds (see
//! [`MAX_PROGRAMS`] and [`MAX_STRINGS`]), get [`Response::Error`] with
//! [`FrameError::Malformed`]. Decoding a request allocates a bounded
//! multiple of its frame (see [`MAX_STRINGS`]).

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;
use serde::de::{DeserializeOwned, Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

/// The protocol version, which [`Request::Hello`] checks.
pub const VERSION: u32 = 1;

/// The kernel's vsock port of the channel.
pub const PORT: u32 = 1024;

/// The longest frame body either end takes. The kernel's heap allocates at
/// most 16 MiB at once, and decoding takes a few times the body (see
/// [`MAX_STRINGS`]).
pub const MAX_FRAME_LEN: usize = 1 << 20;

/// The most programs a [`Request::Run`] runs at once: each is a runner
/// process. Decoding rejects more (see [`MAX_STRINGS`]).
pub const MAX_PROGRAMS: usize = 16;

/// The most strings in a [`Program`]'s `argv`, and in its `envp`.
///
/// Decoding bounds these lists, and [`Request::Run`]'s programs, as it goes:
/// a longer list makes the request [`FrameError::Malformed`], which the
/// kernel answers as such. So a compact frame cannot make the kernel
/// allocate much more than its length: an empty string is 1 byte in a frame
/// but 24 in a list. The kernel's heap rounds allocations up to powers of
/// two (slabs, then buddies), which can double each one. Decoding a
/// [`MAX_FRAME_LEN`] frame then takes at most:
/// - per list, 4096 × 24 B = 96 KiB, 128 KiB rounded, at once, far below
///   the heap's 16 MiB;
/// - for all lists, [`MAX_PROGRAMS`] × 2 × 128 KiB = 4 MiB;
/// - for the strings' bytes, at most the frame's 1 MiB, plus up to about
///   2 MiB of rounding (e.g., a 33-byte string takes 64).
///
/// So roughly 7 MiB beyond the frame. Byte buffers are bounded by the frame.
pub const MAX_STRINGS: usize = 4096;

/// OP-TEE client parameters per call.
pub const OPTEE_PARAMS: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// First: [`Response::Hello`]; an error, and the connection closed, if
    /// the versions differ. A later one is checked again, the same way.
    Hello { version: u32 },
    /// Runs 1 to [`MAX_PROGRAMS`] programs at once ([`Service::Programs`]):
    /// [`Response::Ran`] once all ended.
    Run {
        #[serde(deserialize_with = "bounded::<_, _, MAX_PROGRAMS>")]
        programs: Vec<Program>,
    },
    /// An OP-TEE client call ([`Service::Optee`]): [`Response::Optee`].
    Optee(OpteeCall),
    /// Live runner processes, like `ps`: [`Response::Processes`].
    Processes,
    /// Powers the VM off, QEMU reporting `success` (see
    /// `litebox_hal::power::exit`), after [`Response::ShuttingDown`]; the
    /// host should close the connection once it has that.
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
    Processes(Vec<ProcessInfo>),
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
            Self::Processes => "Processes",
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

/// A live runner process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Not reused while the VM runs.
    pub id: u64,
    /// What it runs, e.g., [`Self::ta_name`].
    pub name: String,
}

impl ProcessInfo {
    /// The name of an OP-TEE TA instance's process: its TA's UUID, in RFC
    /// 4122 byte order, as `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
    pub fn ta_name(uuid: &[u8; 16]) -> String {
        use core::fmt::Write as _;
        let mut name = String::with_capacity(36);
        for (index, byte) in uuid.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                name.push('-');
            }
            let _ = write!(name, "{byte:02x}");
        }
        name
    }
}

/// A program to run, in a runner process of its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    /// `argv[0]` is the program's absolute path, in the runner's file system.
    /// At most [`MAX_STRINGS`].
    #[serde(deserialize_with = "bounded::<_, _, MAX_STRINGS>")]
    pub argv: Vec<String>,
    /// `KEY=VALUE` strings, at most [`MAX_STRINGS`].
    #[serde(deserialize_with = "bounded::<_, _, MAX_STRINGS>")]
    pub envp: Vec<String>,
    pub stdin: Stdin,
}

/// A program's standard input. Programs run at once share it, so at most one
/// has input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stdin {
    /// These bytes, then its end (none: `/dev/null`).
    Bytes(Vec<u8>),
    /// The console's: what the host sends it, when it sends it. It never
    /// ends.
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

/// Deserializes a list of at most `MAX` elements: a longer one fails as soon
/// as its length is known, and at most `MAX` are allocated for, whatever the
/// length says.
fn bounded<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T, const MAX: usize>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for Bounded<T, MAX> {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "a sequence of at most {MAX} elements")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let hint = seq.size_hint().unwrap_or(0);
            if hint > MAX {
                return Err(A::Error::invalid_length(hint, &self));
            }
            let mut elements = Vec::with_capacity(hint);
            while let Some(element) = seq.next_element()? {
                if elements.len() == MAX {
                    return Err(A::Error::invalid_length(MAX + 1, &self));
                }
                elements.push(element);
            }
            Ok(elements)
        }
    }

    deserializer.deserialize_seq(Bounded::<T, MAX>(PhantomData))
}

/// `message` as a frame.
///
/// # Errors
///
/// [`FrameError::TooLong`], or [`FrameError::Malformed`] if `message` cannot
/// be serialized.
pub fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>, FrameError> {
    let mut frame =
        postcard::to_extend(message, alloc::vec![0; 4]).map_err(|_| FrameError::Malformed)?;
    let len = frame.len() - 4;
    let encoded = u32::try_from(len)
        .ok()
        .filter(|_| len <= MAX_FRAME_LEN)
        .ok_or(FrameError::TooLong(len))?;
    frame[..4].copy_from_slice(&encoded.to_le_bytes());
    Ok(frame)
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// A frame of this many bytes, longer than [`MAX_FRAME_LEN`]. From
    /// [`Decoder`], it means the stream is out of sync, or the peer
    /// misbehaves, so the connection is unusable.
    TooLong(usize),
    /// A message that cannot be serialized, or a body that does not decode
    /// as exactly one message. [`Decoder`] skips such a frame, so the stream
    /// stays in sync.
    Malformed,
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong(len) => write!(f, "a {len}-byte frame exceeds {MAX_FRAME_LEN} bytes"),
            Self::Malformed => f.write_str("malformed message"),
        }
    }
}

impl core::error::Error for FrameError {}

/// Splits a byte stream into messages. Holds at most one frame and what was
/// pushed with its end, so its user bounds it by pushing only while
/// [`Self::next_message`] has nothing.
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
            // Room for the rest of the frame, once.
            let missing = len - rest.len();
            self.buffer.reserve_exact(missing);
            return Ok(None);
        };
        let message = match postcard::take_from_bytes(body) {
            Ok((message, [])) => Ok(Some(message)),
            _ => Err(FrameError::Malformed),
        };
        self.buffer.drain(..4 + len);
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    extern crate std;

    /// Tracks the largest allocation of each thread, as tests run in
    /// threads of their own.
    struct Tracking;

    std::thread_local! {
        static LARGEST: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }

    // Safety: forwards to the system allocator.
    unsafe impl core::alloc::GlobalAlloc for Tracking {
        unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
            let _ = LARGEST.try_with(|largest| largest.set(largest.get().max(layout.size())));
            // Safety: the caller's contract.
            unsafe { std::alloc::System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
            // Safety: the caller's contract.
            unsafe { std::alloc::System.dealloc(ptr, layout) }
        }

        unsafe fn realloc(
            &self,
            ptr: *mut u8,
            layout: core::alloc::Layout,
            new_size: usize,
        ) -> *mut u8 {
            let _ = LARGEST.try_with(|largest| largest.set(largest.get().max(new_size)));
            // Safety: the caller's contract.
            unsafe { std::alloc::System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: Tracking = Tracking;

    /// What `f` returns, and the largest allocation it made.
    fn largest_allocation<R>(f: impl FnOnce() -> R) -> (R, usize) {
        LARGEST.with(|largest| largest.set(0));
        let result = f();
        (result, LARGEST.with(core::cell::Cell::get))
    }

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
            Request::Processes,
            Request::Shutdown { success: true },
        ]
    }

    #[test]
    fn messages_round_trip_split_anywhere() {
        let requests = requests();
        let stream: Vec<u8> = requests
            .iter()
            .flat_map(|request| encode(request).unwrap())
            .collect();
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
        decoder.push(&encode(&Request::Processes).unwrap());
        assert_eq!(
            decoder.next_message::<Request>(),
            Err(FrameError::Malformed)
        );
        assert_eq!(decoder.next_message(), Ok(Some(Request::Processes)));
    }

    #[test]
    fn frames_with_trailing_bytes_are_skipped() {
        let mut frame = encode(&Request::Processes).unwrap();
        frame.push(0);
        frame[0] += 1;
        let mut decoder = Decoder::default();
        decoder.push(&frame);
        decoder.push(&encode(&Request::Processes).unwrap());
        assert_eq!(
            decoder.next_message::<Request>(),
            Err(FrameError::Malformed)
        );
        assert_eq!(decoder.next_message(), Ok(Some(Request::Processes)));
    }

    #[test]
    fn truncated_bodies_are_malformed() {
        let hello = encode(&Request::Hello { version: VERSION }).unwrap();
        // The frame says it ends before its message does.
        let mut frame = Vec::from(u32::try_from(hello.len() - 5).unwrap().to_le_bytes());
        frame.extend_from_slice(&hello[4..hello.len() - 1]);
        let mut decoder = Decoder::default();
        decoder.push(&frame);
        decoder.push(&encode(&Request::Processes).unwrap());
        assert_eq!(
            decoder.next_message::<Request>(),
            Err(FrameError::Malformed)
        );
        assert_eq!(decoder.next_message(), Ok(Some(Request::Processes)));
    }

    #[test]
    fn garbage_and_empty_bodies_are_malformed() {
        let mut decoder = Decoder::default();
        decoder.push(&[0, 0, 0, 0]);
        let garbage: Vec<u8> = (0..=255u8).cycle().skip(77).take(300).collect();
        decoder.push(&u32::try_from(garbage.len()).unwrap().to_le_bytes());
        decoder.push(&garbage);
        assert_eq!(
            decoder.next_message::<Request>(),
            Err(FrameError::Malformed)
        );
        assert_eq!(
            decoder.next_message::<Request>(),
            Err(FrameError::Malformed)
        );
        assert_eq!(decoder.next_message::<Request>(), Ok(None));
    }

    #[test]
    fn incomplete_frames_wait() {
        let frame = encode(&Request::Processes).unwrap();
        let mut decoder = Decoder::default();
        decoder.push(&frame[..frame.len() - 1]);
        assert_eq!(decoder.next_message::<Request>(), Ok(None));
        decoder.push(&frame[frame.len() - 1..]);
        assert_eq!(decoder.next_message(), Ok(Some(Request::Processes)));
    }

    #[test]
    fn frames_up_to_the_limit_are_taken() {
        // Encoded: variant, then the length (3 bytes as a varint), then the
        // bytes.
        let error = Response::Error("x".repeat(MAX_FRAME_LEN - 4));
        let frame = encode(&error).unwrap();
        assert_eq!(frame.len(), 4 + MAX_FRAME_LEN);
        let mut decoder = Decoder::default();
        decoder.push(&frame);
        assert_eq!(decoder.next_message(), Ok(Some(error)));
        let over = Response::Error("x".repeat(MAX_FRAME_LEN - 3));
        assert_eq!(encode(&over), Err(FrameError::TooLong(MAX_FRAME_LEN + 1)));
    }

    #[test]
    fn overlong_messages_are_not_encoded() {
        let request = Request::Run {
            programs: vec![Program {
                argv: Vec::new(),
                envp: Vec::new(),
                stdin: Stdin::Bytes(vec![0; MAX_FRAME_LEN]),
            }],
        };
        assert!(matches!(encode(&request), Err(FrameError::TooLong(_))));
    }

    #[test]
    fn overlong_frames_are_refused_before_their_body() {
        let mut decoder = Decoder::default();
        decoder.push(&u32::try_from(MAX_FRAME_LEN + 1).unwrap().to_le_bytes());
        assert_eq!(
            decoder.next_message::<Request>(),
            Err(FrameError::TooLong(MAX_FRAME_LEN + 1))
        );
        let mut decoder = Decoder::default();
        decoder.push(&u32::MAX.to_le_bytes());
        assert!(matches!(
            decoder.next_message::<Request>(),
            Err(FrameError::TooLong(_))
        ));
    }

    /// A `Run` of one program with `argv` and `envp` of `argc` and `envc`
    /// empty strings, as compact as postcard encodes it.
    fn compact_run(programs: usize, argc: usize, envc: usize) -> Vec<u8> {
        fn varint(mut value: usize, body: &mut Vec<u8>) {
            while value >= 0x80 {
                body.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
                value >>= 7;
            }
            body.push(u8::try_from(value).unwrap());
        }
        // `Request::Run`, then the programs.
        let mut body = vec![1];
        varint(programs, &mut body);
        for _ in 0..programs {
            varint(argc, &mut body);
            body.resize(body.len() + argc, 0);
            varint(envc, &mut body);
            body.resize(body.len() + envc, 0);
            // `Stdin::Bytes`, empty.
            body.extend([0, 0]);
        }
        let mut frame = Vec::from(u32::try_from(body.len()).unwrap().to_le_bytes());
        frame.extend(body);
        frame
    }

    fn decode(frame: &[u8]) -> Result<Option<Request>, FrameError> {
        let mut decoder = Decoder::default();
        decoder.push(frame);
        decoder.next_message()
    }

    #[test]
    fn compact_frames_of_many_strings_are_malformed() {
        // A compact frame of 750,000 empty `argv` strings: 24 MB if decoded unbounded.
        let mut frame = Vec::from(750_008u32.to_le_bytes());
        frame.extend(b"\x01\x01\xb0\xe3\x2d");
        frame.resize(frame.len() + 750_000, 0);
        frame.extend(b"\0\0\0");
        assert_eq!(frame, compact_run(1, 750_000, 0));
        for frame in [frame, compact_run(1, 0, 750_000)] {
            let (decoded, largest) = largest_allocation(|| decode(&frame));
            assert_eq!(decoded, Err(FrameError::Malformed));
            // No more than the frame, which the decoder buffers.
            assert!(largest <= frame.len(), "{largest}");
        }
    }

    #[test]
    fn lists_are_bounded() {
        let at = |programs, argc, envc| {
            let Ok(Some(Request::Run { programs })) = decode(&compact_run(programs, argc, envc))
            else {
                panic!("{programs} programs, {argc} args, {envc} envs");
            };
            (
                programs.len(),
                programs[0].argv.len(),
                programs[0].envp.len(),
            )
        };
        assert_eq!(at(1, MAX_STRINGS, 0), (1, MAX_STRINGS, 0));
        assert_eq!(at(1, 0, MAX_STRINGS), (1, 0, MAX_STRINGS));
        assert_eq!(at(MAX_PROGRAMS, 1, 1), (MAX_PROGRAMS, 1, 1));
        // The largest decodes in a frame.
        assert_eq!(
            at(MAX_PROGRAMS, MAX_STRINGS, MAX_STRINGS),
            (MAX_PROGRAMS, MAX_STRINGS, MAX_STRINGS)
        );
        for (programs, argc, envc) in [
            (1, MAX_STRINGS + 1, 0),
            (1, 0, MAX_STRINGS + 1),
            (MAX_PROGRAMS + 1, 0, 0),
        ] {
            assert_eq!(
                decode(&compact_run(programs, argc, envc)),
                Err(FrameError::Malformed),
                "{programs} programs, {argc} args, {envc} envs"
            );
        }
    }

    #[test]
    fn ta_names_are_uuids() {
        let uuid = [
            0x8a, 0xaa, 0xf2, 0x00, 0x24, 0x50, 0x11, 0xe4, 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5,
            0xc5, 0x1b,
        ];
        assert_eq!(
            ProcessInfo::ta_name(&uuid),
            "8aaaf200-2450-11e4-abe2-0002a5d5c51b"
        );
    }
}
