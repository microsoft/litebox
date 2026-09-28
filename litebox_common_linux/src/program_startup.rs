// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Bounded Linux program startup payload used by constrained `vfork` transfer.

use alloc::ffi::CString;
use alloc::string::String;
use alloc::vec::Vec;

use litebox::pipes::HalfPipeType;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::process::MAX_PROCESS_BOOTSTRAP_SIZE;
use litebox_broker_protocol::stdio::StdioStream;

use crate::OFlags;
use crate::signal::SigSet;

const HEADER_SIZE: usize = size_of::<[u32; 9]>() + size_of::<[u64; 2]>();
/// Size of an inherited descriptor's number, handle, and kind tag, which precede its kind's fields.
const INHERITED_FD_HEADER_SIZE: usize = size_of::<u32>() + size_of::<u64>() + size_of::<u8>();
const FILE_TAG: u8 = 0;
const STDIO_TAG: u8 = 1;
const PIPE_TAG: u8 = 2;

/// Linux program state needed to load a child in a fresh runner.
///
/// Platform-managed architectural context is intentionally outside this payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxProgramStartup {
    /// Parent process ID visible to the child.
    pub parent_process_id: i32,
    /// Real user ID.
    pub uid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Signals blocked across `execve`.
    pub blocked_signals: SigSet,
    /// Signals whose ignored disposition survives `execve`.
    pub ignored_signals: SigSet,
    /// Absolute executable path.
    pub path: String,
    /// Program arguments.
    pub argv: Vec<CString>,
    /// Program environment.
    pub envp: Vec<CString>,
    /// Descriptors the program inherits, in strictly ascending descriptor order.
    pub inherited_fds: Vec<InheritedFd>,
}

/// A descriptor inherited across `execve`, as Linux keeps every descriptor not marked
/// close-on-exec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InheritedFd {
    /// Descriptor number.
    pub fd: u32,
    /// The child's broker handle to the descriptor's object.
    ///
    /// Descriptors with the same handle share one open file description, whose kind and metadata
    /// are taken from the first of them.
    pub handle: ObjectHandle,
    /// What the descriptor refers to.
    pub kind: InheritedFdKind,
}

/// The kind of object an [`InheritedFd`] refers to, with the metadata the runner tracks for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InheritedFdKind {
    /// A file, whose access mode and status flags the broker keeps.
    File,
    /// A file that refers to a standard stream.
    Stdio {
        /// The standard stream.
        stream: StdioStream,
        /// Status flags the runner tracks for the stream, if any.
        status_flags: Option<OFlags>,
    },
    /// An end of a pipe.
    Pipe {
        /// Which end.
        endpoint: HalfPipeType,
        /// The end's access mode, which must match `endpoint`, and status flags.
        status_flags: OFlags,
    },
}

/// Invalid or unsupported Linux program startup data.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum LinuxProgramStartupError {
    /// The startup exceeds the bounded payload size.
    #[error("Linux program startup is too large")]
    TooLarge,
    /// The startup payload is malformed.
    #[error("malformed Linux program startup")]
    Malformed,
    /// The executable path is not an absolute UTF-8 path.
    #[error("invalid Linux program path")]
    InvalidPath,
    /// The parent process ID is not representable by Linux process semantics.
    #[error("invalid Linux program parent process ID")]
    InvalidParentProcess,
    /// An argument or environment string contains an interior NUL.
    #[error("invalid Linux program string")]
    InvalidString,
    /// An inherited descriptor's metadata does not match its kind.
    #[error("invalid Linux program inherited descriptor")]
    InvalidInheritedFd,
}

impl LinuxProgramStartup {
    /// Encodes this startup into the bounded broker payload.
    pub fn encode(&self) -> Result<Vec<u8>, LinuxProgramStartupError> {
        validate(self)?;
        let encoded_len = encoded_len(self)?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(encoded_len)
            .map_err(|_| LinuxProgramStartupError::TooLarge)?;
        push_u32(&mut output, self.parent_process_id.cast_unsigned());
        push_u32(&mut output, self.uid);
        push_u32(&mut output, self.euid);
        push_u32(&mut output, self.gid);
        push_u32(&mut output, self.egid);
        push_u64(&mut output, self.blocked_signals.as_u64());
        push_u64(&mut output, self.ignored_signals.as_u64());
        push_u32(
            &mut output,
            u32::try_from(self.path.len()).map_err(|_| LinuxProgramStartupError::TooLarge)?,
        );
        push_u32(
            &mut output,
            u32::try_from(self.argv.len()).map_err(|_| LinuxProgramStartupError::TooLarge)?,
        );
        push_u32(
            &mut output,
            u32::try_from(self.envp.len()).map_err(|_| LinuxProgramStartupError::TooLarge)?,
        );
        push_u32(
            &mut output,
            u32::try_from(self.inherited_fds.len())
                .map_err(|_| LinuxProgramStartupError::TooLarge)?,
        );
        output.extend_from_slice(self.path.as_bytes());
        for value in self.argv.iter().chain(&self.envp) {
            let value = value.as_bytes();
            push_u32(
                &mut output,
                u32::try_from(value.len()).map_err(|_| LinuxProgramStartupError::TooLarge)?,
            );
            output.extend_from_slice(value);
        }
        for inherited in &self.inherited_fds {
            inherited.encode(&mut output);
        }
        debug_assert_eq!(output.len(), encoded_len);
        Ok(output)
    }

    /// Decodes and validates a bounded broker payload.
    pub fn decode(payload: &[u8]) -> Result<Self, LinuxProgramStartupError> {
        if payload.len() < HEADER_SIZE || payload.len() > MAX_PROCESS_BOOTSTRAP_SIZE as usize {
            return Err(LinuxProgramStartupError::Malformed);
        }
        let mut input = payload;
        let parent_process_id = read_u32(&mut input)?.cast_signed();
        let real_user_id = read_u32(&mut input)?;
        let effective_user_id = read_u32(&mut input)?;
        let real_group_id = read_u32(&mut input)?;
        let effective_group_id = read_u32(&mut input)?;
        let blocked_signals = SigSet::from_u64(read_u64(&mut input)?);
        let ignored_signals = SigSet::from_u64(read_u64(&mut input)?);
        let path_length = usize::try_from(read_u32(&mut input)?)
            .map_err(|_| LinuxProgramStartupError::Malformed)?;
        let argv_count = usize::try_from(read_u32(&mut input)?)
            .map_err(|_| LinuxProgramStartupError::Malformed)?;
        let envp_count = usize::try_from(read_u32(&mut input)?)
            .map_err(|_| LinuxProgramStartupError::Malformed)?;
        let inherited_fd_count = usize::try_from(read_u32(&mut input)?)
            .map_err(|_| LinuxProgramStartupError::Malformed)?;
        let path_bytes = take_bytes(&mut input, path_length)?;
        let path = core::str::from_utf8(path_bytes)
            .map_err(|_| LinuxProgramStartupError::InvalidPath)?
            .into();
        let value_count = argv_count
            .checked_add(envp_count)
            .ok_or(LinuxProgramStartupError::Malformed)?;
        if value_count > input.len() / size_of::<u32>() {
            return Err(LinuxProgramStartupError::Malformed);
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(value_count)
            .map_err(|_| LinuxProgramStartupError::TooLarge)?;
        for _ in 0..value_count {
            let length = usize::try_from(read_u32(&mut input)?)
                .map_err(|_| LinuxProgramStartupError::Malformed)?;
            values.push(
                CString::new(take_bytes(&mut input, length)?)
                    .map_err(|_| LinuxProgramStartupError::InvalidString)?,
            );
        }
        if inherited_fd_count > input.len() / INHERITED_FD_HEADER_SIZE {
            return Err(LinuxProgramStartupError::Malformed);
        }
        let mut inherited_fds = Vec::new();
        inherited_fds
            .try_reserve_exact(inherited_fd_count)
            .map_err(|_| LinuxProgramStartupError::TooLarge)?;
        for _ in 0..inherited_fd_count {
            inherited_fds.push(InheritedFd::decode(&mut input)?);
        }
        if !input.is_empty() {
            return Err(LinuxProgramStartupError::Malformed);
        }
        let envp = values.split_off(argv_count);
        let startup = Self {
            parent_process_id,
            uid: real_user_id,
            euid: effective_user_id,
            gid: real_group_id,
            egid: effective_group_id,
            blocked_signals,
            ignored_signals,
            path,
            argv: values,
            envp,
            inherited_fds,
        };
        validate(&startup)?;
        Ok(startup)
    }
}

impl InheritedFd {
    fn encoded_len(&self) -> usize {
        INHERITED_FD_HEADER_SIZE
            + match self.kind {
                InheritedFdKind::File => 0,
                InheritedFdKind::Stdio { status_flags, .. } => {
                    size_of::<[u8; 2]>() + status_flags.map_or(0, |_| size_of::<u32>())
                }
                InheritedFdKind::Pipe { .. } => size_of::<u8>() + size_of::<u32>(),
            }
    }

    fn encode(&self, output: &mut Vec<u8>) {
        push_u32(output, self.fd);
        push_u64(output, self.handle.0);
        match self.kind {
            InheritedFdKind::File => output.push(FILE_TAG),
            InheritedFdKind::Stdio {
                stream,
                status_flags,
            } => {
                output.push(STDIO_TAG);
                output.push(match stream {
                    StdioStream::Stdin => 0,
                    StdioStream::Stdout => 1,
                    StdioStream::Stderr => 2,
                });
                output.push(u8::from(status_flags.is_some()));
                if let Some(flags) = status_flags {
                    push_u32(output, flags.bits());
                }
            }
            InheritedFdKind::Pipe {
                endpoint,
                status_flags,
            } => {
                output.push(PIPE_TAG);
                output.push(match endpoint {
                    HalfPipeType::ReceiverHalf => 0,
                    HalfPipeType::SenderHalf => 1,
                });
                push_u32(output, status_flags.bits());
            }
        }
    }

    fn decode(input: &mut &[u8]) -> Result<Self, LinuxProgramStartupError> {
        let fd = read_u32(input)?;
        let handle = ObjectHandle(read_u64(input)?);
        let kind = match read_u8(input)? {
            FILE_TAG => InheritedFdKind::File,
            STDIO_TAG => InheritedFdKind::Stdio {
                stream: match read_u8(input)? {
                    0 => StdioStream::Stdin,
                    1 => StdioStream::Stdout,
                    2 => StdioStream::Stderr,
                    _ => return Err(LinuxProgramStartupError::Malformed),
                },
                status_flags: match read_u8(input)? {
                    0 => None,
                    1 => Some(OFlags::from_bits_retain(read_u32(input)?)),
                    _ => return Err(LinuxProgramStartupError::Malformed),
                },
            },
            PIPE_TAG => InheritedFdKind::Pipe {
                endpoint: match read_u8(input)? {
                    0 => HalfPipeType::ReceiverHalf,
                    1 => HalfPipeType::SenderHalf,
                    _ => return Err(LinuxProgramStartupError::Malformed),
                },
                status_flags: OFlags::from_bits_retain(read_u32(input)?),
            },
            _ => return Err(LinuxProgramStartupError::Malformed),
        };
        Ok(Self { fd, handle, kind })
    }
}

fn validate(startup: &LinuxProgramStartup) -> Result<(), LinuxProgramStartupError> {
    const ACCESS_MODE: OFlags = OFlags::WRONLY.union(OFlags::RDWR);

    if startup.parent_process_id <= 0 {
        return Err(LinuxProgramStartupError::InvalidParentProcess);
    }
    if !startup.path.starts_with('/') || startup.path.as_bytes().contains(&0) {
        return Err(LinuxProgramStartupError::InvalidPath);
    }
    for inherited in &startup.inherited_fds {
        if let InheritedFdKind::Pipe {
            endpoint,
            status_flags,
        } = inherited.kind
        {
            let access_mode = match endpoint {
                HalfPipeType::ReceiverHalf => OFlags::RDONLY,
                HalfPipeType::SenderHalf => OFlags::WRONLY,
            };
            if status_flags & ACCESS_MODE != access_mode {
                return Err(LinuxProgramStartupError::InvalidInheritedFd);
            }
        }
    }
    Ok(())
}

fn encoded_len(startup: &LinuxProgramStartup) -> Result<usize, LinuxProgramStartupError> {
    let mut length = HEADER_SIZE
        .checked_add(startup.path.len())
        .ok_or(LinuxProgramStartupError::TooLarge)?;
    if length > MAX_PROCESS_BOOTSTRAP_SIZE as usize {
        return Err(LinuxProgramStartupError::TooLarge);
    }
    for value in startup.argv.iter().chain(&startup.envp) {
        length = length
            .checked_add(size_of::<u32>())
            .and_then(|length| length.checked_add(value.as_bytes().len()))
            .ok_or(LinuxProgramStartupError::TooLarge)?;
        if length > MAX_PROCESS_BOOTSTRAP_SIZE as usize {
            return Err(LinuxProgramStartupError::TooLarge);
        }
    }
    for inherited in &startup.inherited_fds {
        length = length
            .checked_add(inherited.encoded_len())
            .ok_or(LinuxProgramStartupError::TooLarge)?;
        if length > MAX_PROCESS_BOOTSTRAP_SIZE as usize {
            return Err(LinuxProgramStartupError::TooLarge);
        }
    }
    Ok(length)
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn read_u8(input: &mut &[u8]) -> Result<u8, LinuxProgramStartupError> {
    Ok(take_bytes(input, size_of::<u8>())?[0])
}

fn read_u32(input: &mut &[u8]) -> Result<u32, LinuxProgramStartupError> {
    let bytes = take_bytes(input, size_of::<u32>())?;
    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| LinuxProgramStartupError::Malformed)?,
    ))
}

fn read_u64(input: &mut &[u8]) -> Result<u64, LinuxProgramStartupError> {
    let bytes = take_bytes(input, size_of::<u64>())?;
    Ok(u64::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| LinuxProgramStartupError::Malformed)?,
    ))
}

fn take_bytes<'a>(
    input: &mut &'a [u8],
    length: usize,
) -> Result<&'a [u8], LinuxProgramStartupError> {
    if length > input.len() {
        return Err(LinuxProgramStartupError::Malformed);
    }
    let (value, remaining) = input.split_at(length);
    *input = remaining;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::Signal;
    use alloc::vec;

    #[test]
    fn program_startup_round_trips() {
        let startup = LinuxProgramStartup {
            parent_process_id: 17,
            uid: 1000,
            euid: 1001,
            gid: 1002,
            egid: 1003,
            blocked_signals: SigSet::empty().with(Signal::SIGUSR1),
            ignored_signals: SigSet::empty().with(Signal::SIGPIPE),
            path: "/bin/child".into(),
            argv: vec![
                CString::new("child").unwrap(),
                CString::new("argument").unwrap(),
            ],
            envp: vec![CString::new("KEY=value").unwrap()],
            inherited_fds: vec![
                InheritedFd {
                    fd: 1,
                    handle: ObjectHandle(7),
                    kind: InheritedFdKind::Stdio {
                        stream: StdioStream::Stdout,
                        status_flags: Some(OFlags::APPEND | OFlags::RDWR),
                    },
                },
                InheritedFd {
                    fd: 2,
                    handle: ObjectHandle(10),
                    kind: InheritedFdKind::Stdio {
                        stream: StdioStream::Stderr,
                        status_flags: None,
                    },
                },
                InheritedFd {
                    fd: 4,
                    handle: ObjectHandle(u64::MAX),
                    kind: InheritedFdKind::File,
                },
                InheritedFd {
                    fd: 5,
                    handle: ObjectHandle(8),
                    kind: InheritedFdKind::Pipe {
                        endpoint: HalfPipeType::ReceiverHalf,
                        status_flags: OFlags::RDONLY | OFlags::NONBLOCK,
                    },
                },
                InheritedFd {
                    fd: 6,
                    handle: ObjectHandle(9),
                    kind: InheritedFdKind::Pipe {
                        endpoint: HalfPipeType::SenderHalf,
                        status_flags: OFlags::WRONLY,
                    },
                },
            ],
        };

        assert_eq!(
            LinuxProgramStartup::decode(&startup.encode().unwrap()),
            Ok(startup)
        );
    }

    #[test]
    fn program_startup_vector_count_is_payload_bounded() {
        let startup = LinuxProgramStartup {
            parent_process_id: 1,
            uid: 0,
            euid: 0,
            gid: 0,
            egid: 0,
            blocked_signals: SigSet::empty(),
            ignored_signals: SigSet::empty(),
            path: "/child".into(),
            argv: vec![CString::new("").unwrap(); 1025],
            envp: Vec::new(),
            inherited_fds: Vec::new(),
        };

        assert_eq!(
            LinuxProgramStartup::decode(&startup.encode().unwrap()),
            Ok(startup)
        );
    }

    #[test]
    fn program_startup_rejects_trailing_and_invalid_strings() {
        let startup = LinuxProgramStartup {
            parent_process_id: 1,
            uid: 0,
            euid: 0,
            gid: 0,
            egid: 0,
            blocked_signals: SigSet::empty(),
            ignored_signals: SigSet::empty(),
            path: "/child".into(),
            argv: vec![CString::new("child").unwrap()],
            envp: Vec::new(),
            inherited_fds: Vec::new(),
        };
        let mut encoded = startup.encode().unwrap();
        encoded.push(0);
        assert_eq!(
            LinuxProgramStartup::decode(&encoded),
            Err(LinuxProgramStartupError::Malformed)
        );

        let mut invalid = startup.encode().unwrap();
        let first_argument = HEADER_SIZE + startup.path.len() + size_of::<u32>();
        invalid[first_argument] = 0;
        assert_eq!(
            LinuxProgramStartup::decode(&invalid),
            Err(LinuxProgramStartupError::InvalidString)
        );
    }
}
