// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Compute systems and their processes, through the Host Compute Service (`computecore.dll`).

use std::ffi::{OsStr, OsString, c_void};
use std::io::{self, Read};
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::mpsc::SyncSender;

use windows_sys::Win32::Foundation::{
    E_OUTOFMEMORY, E_UNEXPECTED, ERROR_BROKEN_PIPE, GENERIC_ALL, HANDLE,
    HCS_E_SYSTEM_ALREADY_STOPPED, HCS_E_SYSTEM_NOT_FOUND, LocalFree,
};
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::HostComputeSystem::{
    HCS_EVENT, HCS_OPERATION, HCS_PROCESS, HCS_PROCESS_INFORMATION, HCS_SYSTEM,
    HcsCloseComputeSystem, HcsCloseOperation, HcsCloseProcess, HcsCreateComputeSystem,
    HcsCreateOperation, HcsCreateProcess, HcsEventOptionNone, HcsEventProcessExited,
    HcsEventServiceDisconnect, HcsEventSystemExited, HcsGetProcessProperties, HcsOpenComputeSystem,
    HcsSetComputeSystemCallback, HcsSetProcessCallback, HcsStartComputeSystem,
    HcsTerminateComputeSystem, HcsWaitForOperationResult, HcsWaitForOperationResultAndProcessInfo,
};
use windows_sys::core::{HRESULT, PWSTR};

use super::super::bridge::{event, overlapped};
use super::super::is;
use super::super::security::{from_wide, wide};
use super::Error;

/// How long an operation may take: hcsshim's default for starting a container.
const OPERATION_TIMEOUT_MS: u32 = 240_000;
const QUOTE: char = '"';
const BACKSLASH: char = '\\';

struct Operation(HCS_OPERATION);

impl Operation {
    fn new() -> Result<Self, Error> {
        // SAFETY: neither context nor callback: the result is waited for.
        let operation = unsafe { HcsCreateOperation(null(), None) };
        if operation.is_null() {
            return Err(Error::new(E_OUTOFMEMORY));
        }
        Ok(Self(operation))
    }

    /// `started` is what the call given this operation returned; the result is the HCS's document.
    fn wait(&self, started: HRESULT) -> Result<String, Error> {
        self.wait_with(started, |operation, document| {
            // SAFETY: the operation is open, and `document` outlives the call.
            unsafe { HcsWaitForOperationResult(operation, OPERATION_TIMEOUT_MS, document) }
        })
    }

    fn wait_with(
        &self,
        started: HRESULT,
        wait: impl FnOnce(HCS_OPERATION, *mut PWSTR) -> HRESULT,
    ) -> Result<String, Error> {
        if started < 0 {
            return Err(Error::new(started));
        }
        let mut document = null_mut();
        let code = wait(self.0, &raw mut document);
        let document = if document.is_null() {
            String::new()
        } else {
            // SAFETY: the HCS returned a NUL-terminated string for the caller to free.
            unsafe {
                let text = from_wide(document);
                LocalFree(document.cast());
                text
            }
        };
        if code < 0 {
            return Err(Error { code, document });
        }
        Ok(document)
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        // SAFETY: the operation is open, and waited for or never started.
        unsafe { HcsCloseOperation(self.0) };
    }
}

/// A compute system, closed when dropped: one with `ShouldTerminateOnLastHandleClosed` then ends.
#[derive(Debug)]
pub struct System(HCS_SYSTEM);

// SAFETY: an HCS handle is not bound to a thread, and the HCS serializes the calls on it.
unsafe impl Send for System {}
// SAFETY: as above.
unsafe impl Sync for System {}

impl System {
    /// `document` is an HCS schema `ComputeSystem`.
    pub fn create(id: &str, document: &str) -> Result<Self, Error> {
        let operation = Operation::new()?;
        let mut system = null_mut();
        // SAFETY: the NUL-terminated strings and `system` outlive the call; no security descriptor
        // gives the default.
        let started = unsafe {
            HcsCreateComputeSystem(
                wide(OsStr::new(id)).as_ptr(),
                wide(OsStr::new(document)).as_ptr(),
                operation.0,
                null(),
                &raw mut system,
            )
        };
        // Owned before the wait, so that its failure closes it.
        let system = (!system.is_null()).then_some(Self(system));
        operation.wait(started)?;
        system.ok_or_else(|| Error::new(E_UNEXPECTED))
    }

    pub fn open(id: &str) -> Result<Option<Self>, Error> {
        let mut system = null_mut();
        // SAFETY: the NUL-terminated `id` and `system` outlive the call, which is synchronous.
        let code = unsafe {
            HcsOpenComputeSystem(wide(OsStr::new(id)).as_ptr(), GENERIC_ALL, &raw mut system)
        };
        match code {
            HCS_E_SYSTEM_NOT_FOUND => Ok(None),
            code if code < 0 => Err(Error::new(code)),
            _ => Ok(Some(Self(system))),
        }
    }

    pub fn start(&self) -> Result<(), Error> {
        let operation = Operation::new()?;
        // SAFETY: the system and the operation are open; no options.
        let started = unsafe { HcsStartComputeSystem(self.0, operation.0, null()) };
        operation.wait(started).map(drop)
    }

    /// Sends to `exited` once the system stops or the HCS goes away.
    pub fn notify_exit(&self, exited: SyncSender<()>) -> Result<(), Error> {
        register(exited, |context| {
            // SAFETY: the system is open, and `context` stays valid for good.
            unsafe {
                HcsSetComputeSystemCallback(self.0, HcsEventOptionNone, context, Some(on_event))
            }
        })
    }

    /// Ends every process of the system, which then stops ([`System::notify_exit`] tells when);
    /// returns false if it had stopped already.
    pub fn terminate(&self) -> Result<bool, Error> {
        let operation = Operation::new()?;
        // SAFETY: the system and the operation are open; no options.
        let started = unsafe { HcsTerminateComputeSystem(self.0, operation.0, null()) };
        match operation.wait(started) {
            Err(error)
                if [HCS_E_SYSTEM_ALREADY_STOPPED, HCS_E_SYSTEM_NOT_FOUND].contains(&error.code) =>
            {
                Ok(false)
            }
            result => result.map(|_| true),
        }
    }

    /// Starts a process from `parameters`, an HCS schema `ProcessParameters` that asks for stdout
    /// and stderr pipes.
    pub fn create_process(&self, parameters: &str) -> io::Result<Spawned> {
        let operation = Operation::new()?;
        let mut process = null_mut();
        // SAFETY: the system and the operation are open, and the NUL-terminated parameters and
        // `process` outlive the call; no security descriptor gives the default.
        let started = unsafe {
            HcsCreateProcess(
                self.0,
                wide(OsStr::new(parameters)).as_ptr(),
                operation.0,
                null(),
                &raw mut process,
            )
        };
        let process = (!process.is_null()).then_some(Process(process));
        let mut information = HCS_PROCESS_INFORMATION::default();
        operation.wait_with(started, |operation, document| {
            // SAFETY: the operation is open, and `information` and `document` outlive the call.
            unsafe {
                HcsWaitForOperationResultAndProcessInfo(
                    operation,
                    OPERATION_TIMEOUT_MS,
                    &raw mut information,
                    document,
                )
            }
        })?;
        // Owned before anything can fail, so that a failure closes them.
        let [stdin, stdout, stderr] = [
            information.StdInput,
            information.StdOutput,
            information.StdError,
        ]
        .map(|handle| {
            // SAFETY: the HCS gives the caller its pipes' handles, open or null.
            unsafe { owned(handle) }
        });
        drop(stdin);
        let process = process.ok_or_else(|| Error::new(E_UNEXPECTED))?;
        let pipe = |handle: Option<OwnedHandle>| {
            Pipe::new(handle.ok_or_else(|| io::Error::other("the HCS gave no output pipe"))?)
        };
        Ok(Spawned {
            process,
            pid: information.ProcessId,
            stdout: pipe(stdout)?,
            stderr: pipe(stderr)?,
        })
    }
}

impl Drop for System {
    fn drop(&mut self) {
        // SAFETY: the system is open.
        unsafe { HcsCloseComputeSystem(self.0) };
    }
}

pub struct Spawned {
    pub process: Process,
    /// A host PID: a process-isolated container's processes are the host's.
    pub pid: u32,
    pub stdout: Pipe,
    pub stderr: Pipe,
}

#[derive(Debug)]
pub struct Process(HCS_PROCESS);

// SAFETY: as `System`'s.
unsafe impl Send for Process {}
// SAFETY: as above.
unsafe impl Sync for Process {}

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Running,
    Exited(Option<u32>),
}

impl Process {
    /// Sends to `exited` once the process exits or the HCS goes away.
    pub fn notify_exit(&self, exited: SyncSender<()>) -> Result<(), Error> {
        register(exited, |context| {
            // SAFETY: the process is open, and `context` stays valid for good.
            unsafe { HcsSetProcessCallback(self.0, HcsEventOptionNone, context, Some(on_event)) }
        })
    }

    pub fn status(&self) -> Result<Status, Error> {
        let operation = Operation::new()?;
        // SAFETY: the process and the operation are open; no query gives the process's status.
        let started = unsafe { HcsGetProcessProperties(self.0, operation.0, null()) };
        let document = operation.wait(started)?;
        Ok(parse_status(&document))
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: the process is open.
        unsafe { HcsCloseProcess(self.0) };
    }
}

/// An HCS schema `ProcessStatus`; an unreadable one is still running, as far as this knows.
fn parse_status(document: &str) -> Status {
    let status: serde_json::Value = serde_json::from_str(document).unwrap_or_default();
    if status["Exited"].as_bool() == Some(true) {
        let code = status["ExitCode"]
            .as_u64()
            .and_then(|code| u32::try_from(code).ok());
        Status::Exited(code)
    } else {
        Status::Running
    }
}

/// Leaks `exited` as the context of the callback `set` registers: the HCS documents no point after
/// which it no longer calls back.
fn register(
    exited: SyncSender<()>,
    set: impl FnOnce(*const c_void) -> HRESULT,
) -> Result<(), Error> {
    let context = Box::into_raw(Box::new(exited));
    let code = set(context.cast_const().cast());
    if code < 0 {
        // SAFETY: the HCS did not take `context`, which `Box::into_raw` made.
        drop(unsafe { Box::from_raw(context) });
        return Err(Error::new(code));
    }
    Ok(())
}

/// Must not unwind, as the HCS calls it.
unsafe extern "system" fn on_event(event: *const HCS_EVENT, context: *const c_void) {
    // SAFETY: the HCS passes an event valid for the call, or null.
    let Some(event) = (unsafe { event.as_ref() }) else {
        return;
    };
    let ends = [
        HcsEventProcessExited,
        HcsEventSystemExited,
        HcsEventServiceDisconnect,
    ];
    if ends.contains(&event.Type) {
        // SAFETY: `context` is `register`'s leaked sender.
        let exited = unsafe { &*context.cast::<SyncSender<()>>() };
        let _ = exited.try_send(());
    }
}

/// # Safety
///
/// `handle` is null, or an open handle that nothing else owns.
unsafe fn owned(handle: HANDLE) -> Option<OwnedHandle> {
    // SAFETY: the caller's.
    (!handle.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// A process's output pipe, which ends at the process's exit.
pub struct Pipe {
    handle: OwnedHandle,
    event: OwnedHandle,
}

impl Pipe {
    fn new(handle: OwnedHandle) -> io::Result<Self> {
        Ok(Self {
            handle,
            event: event()?,
        })
    }
}

impl Read for Pipe {
    /// Whether the HCS made the pipe overlapped or not.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        let handle = self.handle.as_raw_handle();
        let read = overlapped(&self.handle, &self.event, |overlapped| {
            // SAFETY: `buffer` holds `length` bytes, and it and `overlapped` outlive the operation,
            // which `overlapped` waits for.
            unsafe { ReadFile(handle, buffer.as_mut_ptr(), length, null_mut(), overlapped) }
        });
        match read {
            Err(error) if is(&error, ERROR_BROKEN_PIPE) => Ok(0),
            read => read,
        }
    }
}

/// `program` and `arguments` quoted so that the C runtime and `CommandLineToArgvW` parse them
/// back. The program's name is parsed without escapes.
pub fn command_line(program: &Path, arguments: &[OsString]) -> io::Result<String> {
    let name = program
        .to_str()
        .filter(|name| !name.contains(['\0', QUOTE]))
        .ok_or_else(|| invalid("the program", program.as_os_str()))?;
    let mut line = format!("{QUOTE}{name}{QUOTE}");
    for argument in arguments {
        let text = argument
            .to_str()
            .ok_or_else(|| invalid("an argument", argument))?;
        if text.contains('\0') {
            return Err(invalid("an argument", argument));
        }
        line.push(' ');
        push_argument(&mut line, text);
    }
    Ok(line)
}

/// The C runtime's rules: backslashes are literal unless a quote follows; then `2n + 1` of them
/// give `n` and a literal quote, and `2n` give `n` and end the quoting.
fn push_argument(line: &mut String, argument: &str) {
    let quoted = argument.is_empty() || argument.contains([' ', '\t']);
    if quoted {
        line.push(QUOTE);
    }
    let mut backslashes = 0;
    for character in argument.chars() {
        if character == BACKSLASH {
            backslashes += 1;
        } else {
            if character == QUOTE {
                line.extend(std::iter::repeat_n(BACKSLASH, backslashes + 1));
            }
            backslashes = 0;
        }
        line.push(character);
    }
    if quoted {
        line.extend(std::iter::repeat_n(BACKSLASH, backslashes));
        line.push(QUOTE);
    }
}

fn invalid(what: &str, text: &OsStr) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{what} {} cannot be given to a process", text.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_quoted_as_the_c_runtime_parses_them() {
        let cases: [(&[&str], &str); 6] = [
            (&["a b c", "d", "e"], r#""a b c" d e"#),
            (&[r#"ab"c"#, "\\", "d"], r#"ab\"c \ d"#),
            (&[r"a\\\b", "de fg", "h"], r#"a\\\b "de fg" h"#),
            (&[r#"a\"b"#, "c", "d"], r#"a\\\"b c d"#),
            (&[r"a\\b c", "d", "e"], r#""a\\b c" d e"#),
            (&[r"C:\a dir\", ""], r#""C:\a dir\\" """#),
        ];
        let program = Path::new(r"C:\Program Files\a.exe");
        for (arguments, quoted) in cases {
            let arguments: Vec<OsString> = arguments.iter().map(OsString::from).collect();
            assert_eq!(
                command_line(program, &arguments).unwrap(),
                format!(r#""{}" {quoted}"#, program.display()),
                "{arguments:?}"
            );
        }
        assert!(command_line(Path::new("a"), &[OsString::from("b\0")]).is_err());
        assert!(command_line(Path::new(r#"a"b"#), &[]).is_err());
    }
}
