// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Bounded Linux process startup payloads, which start a child in a fresh runner after
//! constrained `vfork` transfer or `fork`.

use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Range;

use litebox::pipes::HalfPipeType;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::process::MAX_PROCESS_BOOTSTRAP_SIZE;
use zerocopy::{FromBytes, IntoBytes};

use crate::signal::{NSIG, SigAction, SigAltStack, SigSet};
use crate::vmem::VmFlags;
use crate::{PtRegs, TASK_COMM_LEN};

const HEADER_SIZE: usize = size_of::<u8>() + size_of::<[u32; 11]>() + size_of::<[u64; 2]>();
/// Size of an inherited descriptor's number, handle, and kind tag, which precede its kind's fields.
const INHERITED_FD_HEADER_SIZE: usize = size_of::<u32>() + size_of::<u64>() + size_of::<u8>();
/// Size of a memory region's start, end, and flags.
const FORK_REGION_SIZE: usize = size_of::<[u64; 2]>() + size_of::<u32>();
const FILE_TAG: u8 = 0;
const PIPE_TAG: u8 = 1;
const PROGRAM_STARTUP_TAG: u8 = 0;
const FORK_STARTUP_TAG: u8 = 1;

/// Linux startup of a child process in a fresh runner.
pub enum LinuxProcessStartup {
    /// Load a program, as `execve` does.
    Program(LinuxProgramStartup),
    /// Continue a process duplicated by `fork`.
    Fork(Box<LinuxForkStartup>),
}

impl LinuxProcessStartup {
    /// Decodes and validates a bounded broker payload produced by
    /// [`LinuxProgramStartup::encode`] or [`LinuxForkStartup::encode`].
    pub fn decode(payload: &[u8]) -> Result<Self, LinuxProgramStartupError> {
        match payload.first() {
            Some(&PROGRAM_STARTUP_TAG) => LinuxProgramStartup::decode(payload).map(Self::Program),
            Some(&FORK_STARTUP_TAG) => {
                LinuxForkStartup::decode(payload).map(|startup| Self::Fork(Box::new(startup)))
            }
            _ => Err(LinuxProgramStartupError::Malformed),
        }
    }
}

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
    /// File mode creation mask, with only permission bits set.
    pub umask: u32,
    /// Absolute executable path.
    pub path: String,
    /// Absolute working directory.
    pub cwd: String,
    /// Program arguments.
    pub argv: Vec<CString>,
    /// Program environment.
    pub envp: Vec<CString>,
    /// Descriptors the program inherits, in strictly ascending descriptor order.
    pub inherited_fds: Vec<InheritedFd>,
}

/// A descriptor inherited across `execve`, as Linux keeps every descriptor not marked
/// close-on-exec.
///
/// This is the Linux startup record for a descriptor whose object the parent passed to the child
/// as a [`litebox::process::InheritableFd`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InheritedFd {
    /// Descriptor number.
    pub fd: u32,
    /// The child's broker handle to the descriptor's object, as returned by
    /// [`litebox::process::Process::inherit`].
    ///
    /// Descriptors with the same handle share one open file description, whose kind is taken from
    /// the first of them.
    pub handle: ObjectHandle,
    /// What the descriptor refers to.
    pub kind: InheritedFdKind,
}

/// The kind of object an [`InheritedFd`] refers to.
///
/// The broker keeps the access mode and status flags of every kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InheritedFdKind {
    /// A file, including a standard stream.
    File,
    /// An end of a pipe.
    Pipe {
        /// Which end.
        endpoint: HalfPipeType,
    },
}

/// Linux process state needed to continue a child duplicated by `fork` in a fresh runner.
///
/// The child's memory contents travel separately, in a process image holding the contents of
/// each region that [has contents](ForkMemoryRegion::has_contents) back to back, in region order.
#[derive(Clone)]
pub struct LinuxForkStartup {
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
    /// File mode creation mask, with only permission bits set.
    pub umask: u32,
    /// Absolute working directory.
    pub cwd: String,
    /// Command name.
    pub comm: [u8; TASK_COMM_LEN],
    /// Blocked signals.
    pub blocked_signals: SigSet,
    /// Signal dispositions, indexed by signal number minus one.
    pub signal_actions: [SigAction; NSIG],
    /// Alternate signal stack.
    pub alternate_signal_stack: SigAltStack,
    /// Registers at the `fork` system call, which the child returns from.
    pub registers: PtRegs,
    /// Thread pointer, such as the FS base on x86-64.
    pub thread_pointer: usize,
    /// The parent's system call entry point, which the child's must match because the
    /// duplicated code calls it.
    pub syscall_entry_point: usize,
    /// Address where the child stores its thread ID, or zero.
    pub set_child_tid: usize,
    /// Address the child clears and wakes when it exits, or zero.
    pub clear_child_tid: usize,
    /// Initial program break.
    pub initial_program_break: usize,
    /// Current program break.
    pub program_break: usize,
    /// Memory regions, in strictly ascending address order.
    pub regions: Vec<ForkMemoryRegion>,
    /// Descriptors the child inherits, in strictly ascending descriptor order.
    pub fds: Vec<ForkedFd>,
}

/// A memory region of a process duplicated by `fork`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkMemoryRegion {
    /// Page-aligned addresses.
    pub range: Range<usize>,
    /// Region flags.
    pub flags: VmFlags,
}

impl ForkMemoryRegion {
    /// Returns whether the region's contents are in the process image, which holds those of
    /// every region with any access permission. Any other region starts zero-filled.
    pub fn has_contents(&self) -> bool {
        self.flags.intersects(VmFlags::VM_ACCESS_FLAGS)
    }
}

/// A descriptor a child duplicated by `fork` inherits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkedFd {
    /// The descriptor and the child's broker handle to its object.
    pub inherited: InheritedFd,
    /// Whether the descriptor is closed on `execve`.
    pub close_on_exec: bool,
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
    /// The working directory is not an absolute UTF-8 path.
    #[error("invalid Linux program working directory")]
    InvalidWorkingDirectory,
    /// The file mode creation mask has bits other than permission bits.
    #[error("invalid Linux program umask")]
    InvalidUmask,
    /// The parent process ID is not representable by Linux process semantics.
    #[error("invalid Linux program parent process ID")]
    InvalidParentProcess,
    /// An argument or environment string contains an interior NUL.
    #[error("invalid Linux program string")]
    InvalidString,
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
        output.push(PROGRAM_STARTUP_TAG);
        push_u32(&mut output, self.parent_process_id.cast_unsigned());
        push_u32(&mut output, self.uid);
        push_u32(&mut output, self.euid);
        push_u32(&mut output, self.gid);
        push_u32(&mut output, self.egid);
        push_u64(&mut output, self.blocked_signals.as_u64());
        push_u64(&mut output, self.ignored_signals.as_u64());
        push_u32(&mut output, self.umask);
        push_u32(
            &mut output,
            u32::try_from(self.path.len()).map_err(|_| LinuxProgramStartupError::TooLarge)?,
        );
        push_u32(
            &mut output,
            u32::try_from(self.cwd.len()).map_err(|_| LinuxProgramStartupError::TooLarge)?,
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
        output.extend_from_slice(self.cwd.as_bytes());
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
    fn decode(payload: &[u8]) -> Result<Self, LinuxProgramStartupError> {
        if payload.len() < HEADER_SIZE || payload.len() > MAX_PROCESS_BOOTSTRAP_SIZE as usize {
            return Err(LinuxProgramStartupError::Malformed);
        }
        let mut input = payload;
        if read_u8(&mut input)? != PROGRAM_STARTUP_TAG {
            return Err(LinuxProgramStartupError::Malformed);
        }
        let parent_process_id = read_u32(&mut input)?.cast_signed();
        let real_user_id = read_u32(&mut input)?;
        let effective_user_id = read_u32(&mut input)?;
        let real_group_id = read_u32(&mut input)?;
        let effective_group_id = read_u32(&mut input)?;
        let blocked_signals = SigSet::from_u64(read_u64(&mut input)?);
        let ignored_signals = SigSet::from_u64(read_u64(&mut input)?);
        let umask = read_u32(&mut input)?;
        let path_length = usize::try_from(read_u32(&mut input)?)
            .map_err(|_| LinuxProgramStartupError::Malformed)?;
        let cwd_length = usize::try_from(read_u32(&mut input)?)
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
        let cwd_bytes = take_bytes(&mut input, cwd_length)?;
        let cwd = core::str::from_utf8(cwd_bytes)
            .map_err(|_| LinuxProgramStartupError::InvalidWorkingDirectory)?
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
            umask,
            path,
            cwd,
            argv: values,
            envp,
            inherited_fds,
        };
        validate(&startup)?;
        Ok(startup)
    }
}

impl LinuxForkStartup {
    /// Encodes this startup into the bounded broker payload.
    pub fn encode(&self) -> Result<Vec<u8>, LinuxProgramStartupError> {
        validate_fork(self)?;
        let mut output = Vec::new();
        output.push(FORK_STARTUP_TAG);
        push_u32(&mut output, self.parent_process_id.cast_unsigned());
        push_u32(&mut output, self.uid);
        push_u32(&mut output, self.euid);
        push_u32(&mut output, self.gid);
        push_u32(&mut output, self.egid);
        push_u32(&mut output, self.umask);
        output.extend_from_slice(&self.comm);
        push_u64(&mut output, self.blocked_signals.as_u64());
        output.extend_from_slice(self.signal_actions.as_bytes());
        output.extend_from_slice(self.alternate_signal_stack.as_bytes());
        output.extend_from_slice(self.registers.as_bytes());
        for value in [
            self.thread_pointer,
            self.syscall_entry_point,
            self.set_child_tid,
            self.clear_child_tid,
            self.initial_program_break,
            self.program_break,
        ] {
            push_u64(&mut output, value as u64);
        }
        for count in [self.cwd.len(), self.regions.len(), self.fds.len()] {
            push_u32(
                &mut output,
                u32::try_from(count).map_err(|_| LinuxProgramStartupError::TooLarge)?,
            );
        }
        output.extend_from_slice(self.cwd.as_bytes());
        for region in &self.regions {
            push_u64(&mut output, region.range.start as u64);
            push_u64(&mut output, region.range.end as u64);
            push_u32(&mut output, region.flags.bits());
        }
        for fd in &self.fds {
            fd.inherited.encode(&mut output);
            output.push(u8::from(fd.close_on_exec));
        }
        if output.len() > MAX_PROCESS_BOOTSTRAP_SIZE as usize {
            return Err(LinuxProgramStartupError::TooLarge);
        }
        Ok(output)
    }

    /// Decodes and validates a bounded broker payload.
    #[expect(
        clippy::similar_names,
        reason = "uid/euid and gid/egid are Linux credential names"
    )]
    fn decode(payload: &[u8]) -> Result<Self, LinuxProgramStartupError> {
        if payload.len() > MAX_PROCESS_BOOTSTRAP_SIZE as usize {
            return Err(LinuxProgramStartupError::Malformed);
        }
        let mut input = payload;
        if read_u8(&mut input)? != FORK_STARTUP_TAG {
            return Err(LinuxProgramStartupError::Malformed);
        }
        let parent_process_id = read_u32(&mut input)?.cast_signed();
        let uid = read_u32(&mut input)?;
        let euid = read_u32(&mut input)?;
        let gid = read_u32(&mut input)?;
        let egid = read_u32(&mut input)?;
        let umask = read_u32(&mut input)?;
        let comm = take_bytes(&mut input, TASK_COMM_LEN)?
            .try_into()
            .map_err(|_| LinuxProgramStartupError::Malformed)?;
        let blocked_signals = SigSet::from_u64(read_u64(&mut input)?);
        let signal_actions = read_value(&mut input)?;
        let alternate_signal_stack = read_value(&mut input)?;
        let registers = read_value(&mut input)?;
        let thread_pointer = read_usize(&mut input)?;
        let syscall_entry_point = read_usize(&mut input)?;
        let set_child_tid = read_usize(&mut input)?;
        let clear_child_tid = read_usize(&mut input)?;
        let initial_program_break = read_usize(&mut input)?;
        let program_break = read_usize(&mut input)?;
        let cwd_length = usize::try_from(read_u32(&mut input)?)
            .map_err(|_| LinuxProgramStartupError::Malformed)?;
        let region_count = usize::try_from(read_u32(&mut input)?)
            .map_err(|_| LinuxProgramStartupError::Malformed)?;
        let fd_count = usize::try_from(read_u32(&mut input)?)
            .map_err(|_| LinuxProgramStartupError::Malformed)?;
        let cwd = core::str::from_utf8(take_bytes(&mut input, cwd_length)?)
            .map_err(|_| LinuxProgramStartupError::InvalidWorkingDirectory)?
            .into();
        if region_count > input.len() / FORK_REGION_SIZE {
            return Err(LinuxProgramStartupError::Malformed);
        }
        let mut regions = Vec::with_capacity(region_count);
        for _ in 0..region_count {
            let start = read_usize(&mut input)?;
            let end = read_usize(&mut input)?;
            let flags = VmFlags::from_bits(read_u32(&mut input)?)
                .ok_or(LinuxProgramStartupError::Malformed)?;
            regions.push(ForkMemoryRegion {
                range: start..end,
                flags,
            });
        }
        if fd_count > input.len() / (INHERITED_FD_HEADER_SIZE + size_of::<u8>()) {
            return Err(LinuxProgramStartupError::Malformed);
        }
        let mut fds = Vec::with_capacity(fd_count);
        for _ in 0..fd_count {
            let inherited = InheritedFd::decode(&mut input)?;
            let close_on_exec = match read_u8(&mut input)? {
                0 => false,
                1 => true,
                _ => return Err(LinuxProgramStartupError::Malformed),
            };
            fds.push(ForkedFd {
                inherited,
                close_on_exec,
            });
        }
        if !input.is_empty() {
            return Err(LinuxProgramStartupError::Malformed);
        }
        let startup = Self {
            parent_process_id,
            uid,
            euid,
            gid,
            egid,
            umask,
            cwd,
            comm,
            blocked_signals,
            signal_actions,
            alternate_signal_stack,
            registers,
            thread_pointer,
            syscall_entry_point,
            set_child_tid,
            clear_child_tid,
            initial_program_break,
            program_break,
            regions,
            fds,
        };
        validate_fork(&startup)?;
        Ok(startup)
    }
}

impl InheritedFd {
    fn encoded_len(&self) -> usize {
        INHERITED_FD_HEADER_SIZE
            + match self.kind {
                InheritedFdKind::File => 0,
                InheritedFdKind::Pipe { .. } => size_of::<u8>(),
            }
    }

    fn encode(&self, output: &mut Vec<u8>) {
        push_u32(output, self.fd);
        push_u64(output, self.handle.0);
        match self.kind {
            InheritedFdKind::File => output.push(FILE_TAG),
            InheritedFdKind::Pipe { endpoint } => {
                output.push(PIPE_TAG);
                output.push(match endpoint {
                    HalfPipeType::ReceiverHalf => 0,
                    HalfPipeType::SenderHalf => 1,
                });
            }
        }
    }

    fn decode(input: &mut &[u8]) -> Result<Self, LinuxProgramStartupError> {
        let fd = read_u32(input)?;
        let handle = ObjectHandle(read_u64(input)?);
        let kind = match read_u8(input)? {
            FILE_TAG => InheritedFdKind::File,
            PIPE_TAG => InheritedFdKind::Pipe {
                endpoint: match read_u8(input)? {
                    0 => HalfPipeType::ReceiverHalf,
                    1 => HalfPipeType::SenderHalf,
                    _ => return Err(LinuxProgramStartupError::Malformed),
                },
            },
            _ => return Err(LinuxProgramStartupError::Malformed),
        };
        Ok(Self { fd, handle, kind })
    }
}

fn validate(startup: &LinuxProgramStartup) -> Result<(), LinuxProgramStartupError> {
    if startup.parent_process_id <= 0 {
        return Err(LinuxProgramStartupError::InvalidParentProcess);
    }
    if !startup.path.starts_with('/') || startup.path.as_bytes().contains(&0) {
        return Err(LinuxProgramStartupError::InvalidPath);
    }
    if !startup.cwd.starts_with('/') || startup.cwd.as_bytes().contains(&0) {
        return Err(LinuxProgramStartupError::InvalidWorkingDirectory);
    }
    if startup.umask & !0o777 != 0 {
        return Err(LinuxProgramStartupError::InvalidUmask);
    }
    Ok(())
}

fn validate_fork(startup: &LinuxForkStartup) -> Result<(), LinuxProgramStartupError> {
    if startup.parent_process_id <= 0 {
        return Err(LinuxProgramStartupError::InvalidParentProcess);
    }
    if !startup.cwd.starts_with('/') || startup.cwd.as_bytes().contains(&0) {
        return Err(LinuxProgramStartupError::InvalidWorkingDirectory);
    }
    if startup.umask & !0o777 != 0 {
        return Err(LinuxProgramStartupError::InvalidUmask);
    }
    let mut previous_end = 0;
    for region in &startup.regions {
        if region.range.start < previous_end || region.range.start >= region.range.end {
            return Err(LinuxProgramStartupError::Malformed);
        }
        previous_end = region.range.end;
    }
    if startup
        .fds
        .windows(2)
        .any(|pair| pair[0].inherited.fd >= pair[1].inherited.fd)
    {
        return Err(LinuxProgramStartupError::Malformed);
    }
    Ok(())
}

fn encoded_len(startup: &LinuxProgramStartup) -> Result<usize, LinuxProgramStartupError> {
    let mut length = HEADER_SIZE
        .checked_add(startup.path.len())
        .and_then(|length| length.checked_add(startup.cwd.len()))
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

fn read_usize(input: &mut &[u8]) -> Result<usize, LinuxProgramStartupError> {
    usize::try_from(read_u64(input)?).map_err(|_| LinuxProgramStartupError::Malformed)
}

fn read_value<T: FromBytes>(input: &mut &[u8]) -> Result<T, LinuxProgramStartupError> {
    T::read_from_bytes(take_bytes(input, size_of::<T>())?)
        .map_err(|_| LinuxProgramStartupError::Malformed)
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
            umask: 0o027,
            path: "/bin/child".into(),
            cwd: "/home/user".into(),
            argv: vec![
                CString::new("child").unwrap(),
                CString::new("argument").unwrap(),
            ],
            envp: vec![CString::new("KEY=value").unwrap()],
            inherited_fds: vec![
                InheritedFd {
                    fd: 1,
                    handle: ObjectHandle(7),
                    kind: InheritedFdKind::File,
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
                    },
                },
                InheritedFd {
                    fd: 6,
                    handle: ObjectHandle(9),
                    kind: InheritedFdKind::Pipe {
                        endpoint: HalfPipeType::SenderHalf,
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
            umask: 0o022,
            path: "/child".into(),
            cwd: "/".into(),
            argv: vec![CString::new("").unwrap(); 1025],
            envp: Vec::new(),
            inherited_fds: Vec::new(),
        };

        assert_eq!(
            LinuxProgramStartup::decode(&startup.encode().unwrap()),
            Ok(startup)
        );
    }

    fn fork_startup() -> LinuxForkStartup {
        let mut signal_actions = [SigAction {
            sigaction: crate::signal::SIG_DFL,
            flags: crate::signal::SaFlags::empty(),
            __pad: 0,
            restorer: 0,
            mask: SigSet::empty(),
        }; NSIG];
        signal_actions[0] = SigAction {
            sigaction: 0x1234,
            flags: crate::signal::SaFlags::RESTORER,
            __pad: 0,
            restorer: 0x5678,
            mask: SigSet::empty().with(Signal::SIGUSR2),
        };
        LinuxForkStartup {
            parent_process_id: 17,
            uid: 1000,
            euid: 1001,
            gid: 1002,
            egid: 1003,
            umask: 0o027,
            cwd: "/home/user".into(),
            comm: *b"python3\0\0\0\0\0\0\0\0\0",
            blocked_signals: SigSet::empty().with(Signal::SIGUSR1),
            signal_actions,
            alternate_signal_stack: SigAltStack {
                sp: 0x7000_0000,
                flags: crate::signal::SsFlags::empty(),
                __pad: 0,
                size: 0x4000,
            },
            registers: PtRegs::default(),
            thread_pointer: 0x7fff_0000,
            syscall_entry_point: 0x5555_0000,
            set_child_tid: 0x7fff_1000,
            clear_child_tid: 0,
            initial_program_break: 0x40_0000,
            program_break: 0x40_2000,
            regions: vec![
                ForkMemoryRegion {
                    range: 0x40_0000..0x40_2000,
                    flags: VmFlags::VM_READ | VmFlags::VM_WRITE,
                },
                ForkMemoryRegion {
                    range: 0x7000_0000..0x7000_4000,
                    flags: VmFlags::empty(),
                },
            ],
            fds: vec![
                ForkedFd {
                    inherited: InheritedFd {
                        fd: 0,
                        handle: ObjectHandle(7),
                        kind: InheritedFdKind::File,
                    },
                    close_on_exec: false,
                },
                ForkedFd {
                    inherited: InheritedFd {
                        fd: 3,
                        handle: ObjectHandle(8),
                        kind: InheritedFdKind::Pipe {
                            endpoint: HalfPipeType::SenderHalf,
                        },
                    },
                    close_on_exec: true,
                },
            ],
        }
    }

    #[test]
    fn fork_startup_round_trips() {
        let startup = fork_startup();
        let encoded = startup.encode().unwrap();
        let Ok(LinuxProcessStartup::Fork(decoded)) = LinuxProcessStartup::decode(&encoded) else {
            panic!("fork startup must decode as a fork");
        };
        assert_eq!(decoded.regions, startup.regions);
        assert_eq!(decoded.fds, startup.fds);
        assert_eq!(decoded.comm, startup.comm);
        assert_eq!(decoded.signal_actions[0].restorer, 0x5678);
        assert_eq!(decoded.encode().unwrap(), encoded);
    }

    #[test]
    fn fork_startup_rejects_malformed_payloads() {
        let startup = fork_startup();
        let encoded = startup.encode().unwrap();

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            LinuxProcessStartup::decode(&trailing),
            Err(LinuxProgramStartupError::Malformed)
        ));
        assert!(matches!(
            LinuxProcessStartup::decode(&encoded[..encoded.len() - 1]),
            Err(LinuxProgramStartupError::Malformed)
        ));
        let mut unknown = encoded;
        unknown[0] = 2;
        assert!(matches!(
            LinuxProcessStartup::decode(&unknown),
            Err(LinuxProgramStartupError::Malformed)
        ));

        let mut overlapping = startup.clone();
        overlapping.regions[1].range = 0x40_1000..0x40_3000;
        assert!(matches!(
            overlapping.encode(),
            Err(LinuxProgramStartupError::Malformed)
        ));
        let mut unordered = startup;
        unordered.fds.swap(0, 1);
        assert!(matches!(
            unordered.encode(),
            Err(LinuxProgramStartupError::Malformed)
        ));
    }

    #[test]
    fn process_startup_decodes_program() {
        let startup = LinuxProgramStartup {
            parent_process_id: 1,
            uid: 0,
            euid: 0,
            gid: 0,
            egid: 0,
            blocked_signals: SigSet::empty(),
            ignored_signals: SigSet::empty(),
            umask: 0o022,
            path: "/child".into(),
            cwd: "/".into(),
            argv: vec![CString::new("child").unwrap()],
            envp: Vec::new(),
            inherited_fds: Vec::new(),
        };
        let Ok(LinuxProcessStartup::Program(decoded)) =
            LinuxProcessStartup::decode(&startup.encode().unwrap())
        else {
            panic!("program startup must decode as a program");
        };
        assert_eq!(decoded, startup);
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
            umask: 0o022,
            path: "/child".into(),
            cwd: "/".into(),
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
        let first_argument =
            HEADER_SIZE + startup.path.len() + startup.cwd.len() + size_of::<u32>();
        invalid[first_argument] = 0;
        assert_eq!(
            LinuxProgramStartup::decode(&invalid),
            Err(LinuxProgramStartupError::InvalidString)
        );
    }
}
