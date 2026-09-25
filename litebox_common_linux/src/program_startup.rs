// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Bounded Linux program startup payload used by constrained `vfork` transfer.

use alloc::ffi::CString;
use alloc::string::String;
use alloc::vec::Vec;

use litebox_broker_protocol::process::MAX_PROCESS_BOOTSTRAP_SIZE;

const HEADER_SIZE: usize = size_of::<[u32; 8]>();

/// Linux program state needed to load a child in a fresh runner.
///
/// Broker object inheritance and platform-managed architectural context are intentionally outside
/// this payload.
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
    /// Absolute executable path.
    pub path: String,
    /// Program arguments.
    pub argv: Vec<CString>,
    /// Program environment.
    pub envp: Vec<CString>,
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
        output.extend_from_slice(self.path.as_bytes());
        for value in self.argv.iter().chain(&self.envp) {
            let value = value.as_bytes();
            push_u32(
                &mut output,
                u32::try_from(value.len()).map_err(|_| LinuxProgramStartupError::TooLarge)?,
            );
            output.extend_from_slice(value);
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
        let path_length = usize::try_from(read_u32(&mut input)?)
            .map_err(|_| LinuxProgramStartupError::Malformed)?;
        let argv_count = usize::try_from(read_u32(&mut input)?)
            .map_err(|_| LinuxProgramStartupError::Malformed)?;
        let envp_count = usize::try_from(read_u32(&mut input)?)
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
            path,
            argv: values,
            envp,
        };
        validate(&startup)?;
        Ok(startup)
    }
}

fn validate(startup: &LinuxProgramStartup) -> Result<(), LinuxProgramStartupError> {
    if startup.parent_process_id <= 0 {
        return Err(LinuxProgramStartupError::InvalidParentProcess);
    }
    if !startup.path.starts_with('/') || startup.path.as_bytes().contains(&0) {
        return Err(LinuxProgramStartupError::InvalidPath);
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
    Ok(length)
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn read_u32(input: &mut &[u8]) -> Result<u32, LinuxProgramStartupError> {
    let bytes = take_bytes(input, size_of::<u32>())?;
    Ok(u32::from_le_bytes(
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
    use alloc::vec;

    #[test]
    fn program_startup_round_trips() {
        let startup = LinuxProgramStartup {
            parent_process_id: 17,
            uid: 1000,
            euid: 1001,
            gid: 1002,
            egid: 1003,
            path: "/bin/child".into(),
            argv: vec![
                CString::new("child").unwrap(),
                CString::new("argument").unwrap(),
            ],
            envp: vec![CString::new("KEY=value").unwrap()],
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
            path: "/child".into(),
            argv: vec![CString::new("").unwrap(); 1025],
            envp: Vec::new(),
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
            path: "/child".into(),
            argv: vec![CString::new("child").unwrap()],
            envp: Vec::new(),
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
