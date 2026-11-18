// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows host file I/O directly between a file and a buffer's [`RawBytes`],
//! with no bounce buffer, timestamp updates, and directory identities.
//!
//! Only a buffer whose bytes are one contiguous part transfers directly, with
//! one `ReadFile` or `WriteFile` given the offset in an `OVERLAPPED`: one
//! positioned read or write, as the bounce path makes through std's
//! `seek_read` or `seek_write`.
//!
//! [`RawBytes`]: litebox_platform::buffer::RawBytes

use std::fs::{File, FileTimes, OpenOptions};
use std::io::{Error, Result};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use litebox_broker_core::fs::FileType;
use litebox_broker_core::fs::errors::SetTimesError;
use litebox_broker_protocol::fs::{FileTimeUpdate, FileTimestamp, SetFileTimes};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use windows_sys::Win32::Foundation::{ERROR_HANDLE_EOF, ERROR_IO_PENDING};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FileIdInfo,
    GetFileInformationByHandleEx, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::core::BOOL;

#[allow(clippy::cast_possible_truncation)]
const ID_INFO_LENGTH: u32 = size_of::<FILE_ID_INFO>() as u32;

/// Reads from `file` at `offset` directly into `buf`, from `start` to its end,
/// with one `ReadFile`.
///
/// Returns `None` without reading unless those bytes of `buf` are one
/// contiguous part of raw bytes.
///
/// # Panics
///
/// Panics if `start` exceeds `buf`.
pub(crate) fn read_at(
    file: &File,
    buf: &mut dyn ReadBuffer,
    start: usize,
    offset: u64,
) -> Option<Result<usize>> {
    let mut result = None;
    let length = buf.len() - start;
    buf.read_direct_at(start, length, &mut |parts| {
        let [part] = parts else { return 0 };
        let read = transfer(offset, part.len(), |length, transferred, overlapped| {
            // SAFETY: `part` is raw bytes that are writable for `length` bytes
            // and that the kernel fills without Rust references to them;
            // `transfer` passes valid `transferred` and `overlapped` and never
            // returns while the read may still use them.
            unsafe {
                ReadFile(
                    file.as_raw_handle(),
                    part.as_ptr(),
                    length,
                    transferred,
                    overlapped,
                )
            }
        });
        // Like `seek_read`, a read at or past the end reads nothing.
        let read = match read {
            Err(error) if error.raw_os_error() == Some(ERROR_HANDLE_EOF.cast_signed()) => Ok(0),
            read => read,
        };
        *result.insert(read).as_ref().unwrap_or(&0)
    })?;
    result
}

/// Writes `buf`, from `start` to its end, to `file` at `offset` directly with
/// one `WriteFile`.
///
/// Returns `None` without writing unless those bytes of `buf` are one
/// contiguous part of raw bytes.
///
/// # Panics
///
/// Panics if `start` exceeds `buf`.
pub(crate) fn write_at(
    file: &File,
    buf: &dyn WriteBuffer,
    start: usize,
    offset: u64,
) -> Option<Result<usize>> {
    let mut result = None;
    buf.write_direct_at(start, buf.len() - start, &mut |parts| {
        let [part] = parts else { return 0 };
        let written = transfer(offset, part.len(), |length, transferred, overlapped| {
            // SAFETY: `part` is raw bytes that are readable for `length` bytes
            // and that the kernel reads without Rust references to them;
            // `transfer` passes valid `transferred` and `overlapped` and never
            // returns while the write may still use them.
            unsafe {
                WriteFile(
                    file.as_raw_handle(),
                    part.as_ptr(),
                    length,
                    transferred,
                    overlapped,
                )
            }
        });
        *result.insert(written).as_ref().unwrap_or(&0)
    })?;
    result
}

/// Makes `call`, a `ReadFile` or `WriteFile` passed the length to transfer
/// (`length` clamped at `u32::MAX`, as std does), where to store how many bytes
/// it transferred, and an `OVERLAPPED` holding `offset`, and returns how many
/// bytes it transferred.
fn transfer(
    offset: u64,
    length: usize,
    call: impl FnOnce(u32, *mut u32, *mut OVERLAPPED) -> BOOL,
) -> Result<usize> {
    // Windows treats offsets past `i64::MAX` as special values, such as "use the current file
    // position", so reject them as Linux rejects them.
    if i64::try_from(offset).is_err() {
        return Err(Error::from(std::io::ErrorKind::InvalidInput));
    }
    let mut overlapped = OVERLAPPED::default();
    // Splits the offset into its low and high halves.
    #[allow(clippy::cast_possible_truncation)]
    {
        overlapped.Anonymous.Anonymous.Offset = offset as u32;
        overlapped.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
    }
    let length = u32::try_from(length).unwrap_or(u32::MAX);
    let mut transferred = 0;
    if call(length, &raw mut transferred, &raw mut overlapped) != 0 {
        return Ok(transferred as usize);
    }
    let error = Error::last_os_error();
    // On a file open for asynchronous I/O, the call would go on using
    // `overlapped` and the buffer after returning, so abort, as std does when
    // such a call doesn't complete; `LocalFs` opens files only for synchronous
    // I/O.
    if error.raw_os_error() == Some(ERROR_IO_PENDING.cast_signed()) {
        std::process::abort();
    }
    Err(error)
}

/// Returns the volume serial number and 128-bit file ID of the directory at
/// `path`, without following a final reparse point.
///
/// These name the host directory itself rather than the spelling of `path`, so
/// every spelling that reaches one directory, such as one differing in case or
/// using an 8.3 short name, yields the same pair. A file system that reports no
/// `FILE_ID_INFO` fails the query rather than falling back on a weaker
/// identity.
pub(super) fn directory_id(path: &Path) -> Result<(u64, u128)> {
    // Reading attributes is the only access needed, and sharing everything keeps
    // the probe from blocking concurrent host or guest operations.
    let dir = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    // Check the object opened, as stat does, so a path that no longer names a
    // directory yields no identity.
    if super::host_file_type(&dir.metadata()?)? != FileType::Directory {
        return Err(super::io_errors::unsupported_object());
    }
    let mut info = FILE_ID_INFO::default();
    // SAFETY: `info` outlives the call, which writes at most `ID_INFO_LENGTH`
    // bytes, its size, into it; `dir` keeps the handle open.
    let queried = unsafe {
        GetFileInformationByHandleEx(
            dir.as_raw_handle(),
            FileIdInfo,
            (&raw mut info).cast(),
            ID_INFO_LENGTH,
        )
    };
    if queried == 0 {
        return Err(Error::last_os_error());
    }
    Ok((
        info.VolumeSerialNumber,
        u128::from_le_bytes(info.FileId.Identifier),
    ))
}

fn system_time_from_timestamp(
    time: &FileTimestamp,
) -> core::result::Result<SystemTime, SetTimesError> {
    if time.nanoseconds >= 1_000_000_000 {
        return Err(SetTimesError::Io);
    }
    let converted = if time.seconds >= 0 {
        UNIX_EPOCH.checked_add(Duration::new(time.seconds.unsigned_abs(), time.nanoseconds))
    } else {
        let duration = if time.nanoseconds == 0 {
            Duration::from_secs(time.seconds.unsigned_abs())
        } else {
            Duration::new(
                time.seconds.unsigned_abs() - 1,
                1_000_000_000 - time.nanoseconds,
            )
        };
        UNIX_EPOCH.checked_sub(duration)
    };
    converted.ok_or_else(|| {
        litebox_util_log::warn!(
            seconds = time.seconds, nanoseconds = time.nanoseconds;
            "timestamp unrepresentable on Windows"
        );
        SetTimesError::Io
    })
}

/// Applies `times` to `path` without following a final reparse point.
pub(super) fn set_times(
    path: &Path,
    times: &SetFileTimes,
) -> core::result::Result<(), SetTimesError> {
    let mut updates = FileTimes::new();
    for (access, update) in [(true, &times.access), (false, &times.modify)] {
        let time = match update {
            FileTimeUpdate::Omit => continue,
            // No native NOW on Windows; the host clock is what Windows uses for other updates.
            FileTimeUpdate::Now => SystemTime::now(),
            FileTimeUpdate::Set(time) => system_time_from_timestamp(time)?,
        };
        updates = if access {
            updates.set_accessed(time)
        } else {
            updates.set_modified(time)
        };
    }
    OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .and_then(|file| file.set_times(updates))
        .map_err(super::io_errors::set_times_error)
}
