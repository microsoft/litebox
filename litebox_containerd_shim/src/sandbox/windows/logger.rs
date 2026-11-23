// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Replaces containerd-shim's Windows logger: `File::write` can abort on a pending overlapped write.

use std::io;
use std::os::windows::io::{AsRawHandle as _, OwnedHandle};
use std::ptr::null_mut;
use std::str::FromStr as _;
use std::sync::{Arc, Mutex};

use log::{LevelFilter, Log, Metadata, Record};
use windows_sys::Win32::Foundation::{ERROR_NO_DATA, ERROR_PIPE_CONNECTED, SYSTEMTIME};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, DisconnectNamedPipe};
use windows_sys::Win32::System::SystemInformation::GetSystemTime;

use super::bridge::{event, overlapped, owner_only_pipe};
use super::is;

pub fn init_log(namespace: &str, id: &str, debug: bool) -> io::Result<()> {
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|level| LevelFilter::from_str(&level).ok())
        .unwrap_or(LevelFilter::Info);
    let level = if debug {
        level.max(LevelFilter::Debug)
    } else {
        level
    };
    let log = PipeLog::new(
        &format!(r"\\.\pipe\containerd-shim-{namespace}-{id}-log"),
        level,
    )?;
    log::set_boxed_logger(Box::new(log)).map_err(io::Error::other)?;
    log::set_max_level(level);
    Ok(())
}

struct PipeLog {
    level: LevelFilter,
    pipe: Arc<OwnedHandle>,
    /// Serialize whole lines, including partial writes.
    event: Mutex<OwnedHandle>,
}

impl PipeLog {
    fn new(name: &str, level: LevelFilter) -> io::Result<Self> {
        let pipe = Arc::new(owner_only_pipe(name)?);
        let event = Mutex::new(event()?);
        std::thread::spawn({
            let pipe = Arc::clone(&pipe);
            move || {
                if let Err(error) = serve(&pipe) {
                    eprintln!("the log's pipe failed: {error}");
                }
            }
        });
        Ok(Self { level, pipe, event })
    }

    /// Waits while a connected client does not read, as a full FIFO does on Linux.
    fn write_all(&self, mut line: &[u8]) -> io::Result<()> {
        let event = self.event.lock().expect("lock poisoned");
        while !line.is_empty() {
            let length = u32::try_from(line.len()).unwrap_or(u32::MAX);
            // SAFETY: `line` outlives the write, which `overlapped` waits for.
            let written = overlapped(&self.pipe, &event, |overlapped| unsafe {
                WriteFile(
                    self.pipe.as_raw_handle(),
                    line.as_ptr(),
                    length,
                    null_mut(),
                    overlapped,
                )
            })?;
            if written == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            line = &line[written..];
        }
        Ok(())
    }
}

impl Log for PipeLog {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "time=\"{}\" level={} msg=\"{}\"\n",
            now(),
            record.level().as_str().to_lowercase(),
            record.args()
        );
        // With no client, the line is lost.
        let _ = self.write_all(line.as_bytes());
    }

    fn flush(&self) {}
}

fn serve(pipe: &OwnedHandle) -> io::Result<()> {
    let event = event()?;
    let mut buffer = [0; 512];
    let length = u32::try_from(buffer.len()).expect("the buffer is 512 bytes long");
    loop {
        // SAFETY: the connection is waited for.
        let connected = overlapped(pipe, &event, |overlapped| unsafe {
            ConnectNamedPipe(pipe.as_raw_handle(), overlapped)
        });
        match connected {
            Ok(_) => {}
            Err(error) if is(&error, ERROR_PIPE_CONNECTED) || is(&error, ERROR_NO_DATA) => {}
            Err(error) => return Err(error),
        }
        loop {
            // SAFETY: `buffer` outlives the read, which `overlapped` waits for.
            let read = overlapped(pipe, &event, |overlapped| unsafe {
                ReadFile(
                    pipe.as_raw_handle(),
                    buffer.as_mut_ptr(),
                    length,
                    null_mut(),
                    overlapped,
                )
            });
            if read.is_err() {
                break;
            }
        }
        // SAFETY: `pipe` is open.
        unsafe { DisconnectNamedPipe(pipe.as_raw_handle()) };
    }
}

fn now() -> String {
    let mut time = SYSTEMTIME::default();
    // SAFETY: `time` is writable.
    unsafe { GetSystemTime(&raw mut time) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        time.wYear,
        time.wMonth,
        time.wDay,
        time.wHour,
        time.wMinute,
        time.wSecond,
        time.wMilliseconds
    )
}
