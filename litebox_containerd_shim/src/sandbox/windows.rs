// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows: the broker in a Job Object, which ends it and its runners with the daemon (in place
//! of the guardian); a state root that only its user can use; and the guest service's client
//! through a relay, since ttrpc on Windows connects only to named pipes.
//!
//! The relay connects to the broker's bridge (Winsock `AF_UNIX`), then serves that stream on a
//! named pipe of one instance, which only this user can open, locally, and which the daemon's
//! client opens at once: the relay checks that it did.

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::hash::{BuildHasher as _, Hasher as _, RandomState};
use std::io::{self, Read as _, Write as _};
use std::net::Shutdown;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::{AsRawHandle as _, AsRawSocket as _, FromRawHandle as _, OwnedHandle};
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use containerd_shim::protos::ttrpc;
use litebox_guest_service_protocol::GUEST_SERVICE_PORT;
use litebox_guest_service_protocol::guest_service_ttrpc::GuestServiceClient;
use socket2::{Domain, SockAddr, Socket, Type};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, ERROR_SUCCESS,
    INVALID_HANDLE_VALUE, LocalFree, WIN32_ERROR,
};
use windows_sys::Win32::Networking::WinSock::{
    POLLRDNORM, POLLWRNORM, SOCKET, SOCKET_ERROR, WSAGetLastError, WSAPOLLFD, WSAPoll,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorDacl, GetTokenInformation,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED,
    PIPE_ACCESS_DUPLEX, READ_CONTROL, ReadFile, WRITE_DAC, WriteFile,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateEventW, GetCurrentProcess, OpenProcessToken,
    OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
};

use super::{CONNECT_TIMEOUT, STOP_TIMEOUT, StateDir, broker_arguments, broker_program, log_lines};
use crate::spec::Egress;
use crate::{Result, internal};

/// How long the bridge may take to answer a `CONNECT`.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// The longest answer to a `CONNECT`: `OK <host port>\n`.
const MAX_ANSWER: usize = 32;
/// How often the relay looks for its end while the bridge is idle.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// The relay's buffers, and the pipe's.
const BUFFER: u32 = 64 * 1024;

/// The state root of a user without `LITEBOX_SHIM_STATE_ROOT`.
pub(super) fn default_state_root() -> PathBuf {
    std::env::temp_dir().join("containerd-shim-litebox")
}

/// Creates the state root `root`, owned by this user, with a DACL that only allows them (which
/// the directories below inherit), if it is missing; fails unless it is a directory, not a
/// reparse point, owned by this user; then restores that DACL: below it, nobody else can plant a
/// reparse point.
pub(super) fn private_root(root: &Path) -> io::Result<()> {
    let user = User::current()?;
    let sid = user.sid_string()?;
    let descriptor = SecurityDescriptor::parse(&format!("O:{sid}D:P(A;OICI;FA;;;{sid})"))?;
    if let Some(parent) = root.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let attributes = descriptor.attributes();
    // SAFETY: the path is NUL-terminated, and `attributes` and its descriptor outlive the call.
    if unsafe { CreateDirectoryW(wide(root.as_os_str()).as_ptr(), &raw const attributes) } == 0 {
        let error = io::Error::last_os_error();
        if !is(&error, ERROR_ALREADY_EXISTS) {
            return Err(error);
        }
    }
    let directory = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(root)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !owned_by(&directory, &user)?
    {
        return Err(io::Error::other(format!(
            "the state root {} is not a private directory of this user's",
            root.display()
        )));
    }
    let dacl = descriptor.dacl()?;
    // SAFETY: `directory` is open with `WRITE_DAC`, and `dacl` lives in `descriptor`.
    win32_result(unsafe {
        SetSecurityInfo(
            directory.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    })
}

/// Whether this user owns `file`, open with `READ_CONTROL`.
fn owned_by(file: &std::fs::File, user: &User) -> io::Result<bool> {
    let mut owner: PSID = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `file` is open with `READ_CONTROL`, and the pointers outlive the call.
    win32_result(unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &raw mut descriptor,
        )
    })?;
    // SAFETY: `owner` points into `descriptor`, which is freed only after.
    let is_ours = unsafe { EqualSid(owner, user.sid()) } != 0;
    // SAFETY: `GetSecurityInfo` allocated `descriptor` for the caller to free.
    unsafe { LocalFree(descriptor) };
    Ok(is_ours)
}

/// This process's user, in a `TOKEN_USER`.
struct User {
    token_user: Vec<u64>,
}

impl User {
    fn current() -> io::Result<Self> {
        let mut token = null_mut();
        // SAFETY: the process pseudo-handle needs no closing, and `token` outlives the call.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call succeeded, so this owns `token`.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut length = 0;
        // SAFETY: with no buffer, the call writes only `length`; it fails for want of room.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                null_mut(),
                0,
                &raw mut length,
            )
        };
        let mut token_user = vec![0u64; (length as usize).div_ceil(size_of::<u64>())];
        // SAFETY: `token_user` holds `length` bytes, aligned for a `TOKEN_USER`.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                token_user.as_mut_ptr().cast(),
                length,
                &raw mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { token_user })
    }

    fn sid(&self) -> PSID {
        // SAFETY: `token_user` holds a `TOKEN_USER`, whose SID points into it.
        unsafe { (*self.token_user.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    /// The SID, as SDDL names it.
    fn sid_string(&self) -> io::Result<String> {
        let mut string = null_mut();
        // SAFETY: the SID is valid, and `string` outlives the call.
        if unsafe { ConvertSidToStringSidW(self.sid(), &raw mut string) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call returned a NUL-terminated string for the caller to free.
        let sid = unsafe {
            let mut length = 0;
            while *string.add(length) != 0 {
                length += 1;
            }
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(string, length));
            LocalFree(string.cast());
            sid
        };
        Ok(sid)
    }
}

/// A security descriptor, from SDDL.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn parse(sddl: &str) -> io::Result<Self> {
        let mut descriptor = null_mut();
        // SAFETY: the SDDL is NUL-terminated, and `descriptor` outlives the call.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(OsStr::new(sddl)).as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }

    /// Attributes for an object with this descriptor, which must outlive them.
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_u32::<SECURITY_ATTRIBUTES>(),
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }

    /// The DACL, within this descriptor.
    fn dacl(&self) -> io::Result<*mut ACL> {
        let (mut present, mut defaulted, mut dacl) = (0, 0, null_mut());
        // SAFETY: the descriptor is valid, and the pointers outlive the call.
        if unsafe {
            GetSecurityDescriptorDacl(self.0, &raw mut present, &raw mut dacl, &raw mut defaulted)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if present == 0 {
            return Err(io::Error::other("the security descriptor has no DACL"));
        }
        Ok(dacl)
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the conversion allocated the descriptor for the caller to free.
        unsafe { LocalFree(self.0) };
    }
}

/// A running broker, in a Job Object that ends it and every runner when it or the daemon ends.
pub struct Broker {
    pid: u32,
    job: Arc<OwnedHandle>,
    ended: Arc<(Mutex<bool>, Condvar)>,
}

impl Broker {
    /// Spawns the broker serving the archive of `state` and the directory `binds`, allowing
    /// `egress`.
    pub fn spawn(state: &StateDir, binds: &[(PathBuf, String)], egress: &Egress) -> Result<Self> {
        let failed = |error: io::Error| internal(format!("cannot start the broker: {error}"));
        let runner = std::env::current_exe().map_err(failed)?;
        let mut command = Command::new(broker_program());
        broker_arguments(&mut command, state, binds, egress, &runner);
        command
            .env("TMP", state.temp())
            .env("TEMP", state.temp())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Not the bundle, which containerd removes.
            .current_dir(state.temp())
            // Suspended until in the job. Its own console, hidden, which its runners share, keeps
            // the daemon's console events away.
            .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
        let job = kill_on_close_job().map_err(failed)?;
        let mut broker = command.spawn().map_err(failed)?;
        drop(command);
        if let Err(error) = adopt(&job, &broker) {
            let _ = broker.kill();
            let _ = broker.wait();
            return Err(failed(error));
        }
        log_lines("stdout", broker.stdout.take().expect("piped"));
        log_lines("stderr", broker.stderr.take().expect("piped"));
        let pid = broker.id();
        let job = Arc::new(job);
        let ended = Arc::new((Mutex::new(false), Condvar::new()));
        let (reaper_job, reaper) = (Arc::clone(&job), Arc::clone(&ended));
        std::thread::spawn(move || {
            let status = broker.wait();
            // Whatever the broker left in its job goes with it.
            terminate(&reaper_job);
            log::info!("the broker exited: {status:?}");
            *reaper.0.lock().expect("not poisoned") = true;
            reaper.1.notify_all();
        });
        Ok(Self { pid, job, ended })
    }

    /// The broker's host PID, which containerd knows as the pid of every process.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    fn wait(&self, timeout: Duration) -> bool {
        let (ended, changed) = &*self.ended;
        let ended =
            changed.wait_timeout_while(ended.lock().expect("not poisoned"), timeout, |ended| {
                !*ended
            });
        *ended.expect("not poisoned").0
    }

    /// Ends the broker and everything below it.
    pub fn stop(&self) {
        terminate(&self.job);
        if !self.wait(STOP_TIMEOUT) {
            log::error!("the broker did not exit in time");
        }
    }

    /// Connects to the guest service through the broker's bridge of `state` (see the Linux
    /// version), then relays that stream to a ttrpc client.
    pub fn connect(&self, state: &StateDir) -> Result<GuestServiceClient> {
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let stream = loop {
            match handshake(&state.bridge()) {
                Ok(stream) => break stream,
                Err(_) if self.wait(Duration::ZERO) => {
                    return Err(internal(
                        "the broker exited before its guest service listened (see the shim's log)",
                    ));
                }
                Err(error) if Instant::now() > deadline => {
                    return Err(internal(format!(
                        "the guest service did not listen in time: {error}"
                    )));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        let client = relay(stream)
            .map_err(|error| internal(format!("cannot serve the connection: {error}")))?;
        Ok(GuestServiceClient::new(client))
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        terminate(&self.job);
    }
}

/// A Job Object that kills its processes once its last handle closes.
fn kill_on_close_job() -> io::Result<OwnedHandle> {
    // SAFETY: neither attributes nor a name.
    let job = unsafe { CreateJobObjectW(null(), null()) };
    if job.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so this owns `job`.
    let job = unsafe { OwnedHandle::from_raw_handle(job) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: `limits` outlives the call, which reads only it.
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            size_u32::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

/// Puts the suspended `child` in `job`, then resumes it: whatever it starts is in the job too.
fn adopt(job: &OwnedHandle, child: &Child) -> io::Result<()> {
    // SAFETY: both handles are open.
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), child.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // `Command` closed the thread's handle: find the thread.
    // SAFETY: plain call.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so this owns `snapshot`.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
    let mut entry = THREADENTRY32 {
        dwSize: size_u32::<THREADENTRY32>(),
        ..THREADENTRY32::default()
    };
    let mut resumed = false;
    // SAFETY: `entry` outlives the call, which writes only it.
    let mut more = unsafe { Thread32First(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    while more {
        if entry.th32OwnerProcessID == child.id() {
            // SAFETY: plain call.
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
            if thread.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the call succeeded, so this owns `thread`.
            let thread = unsafe { OwnedHandle::from_raw_handle(thread) };
            // SAFETY: `thread` is open with `THREAD_SUSPEND_RESUME`.
            if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
                return Err(io::Error::last_os_error());
            }
            resumed = true;
        }
        // SAFETY: as for `Thread32First`.
        more = unsafe { Thread32Next(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    }
    if resumed {
        Ok(())
    } else {
        Err(io::Error::other("the broker has no thread to resume"))
    }
}

fn terminate(job: &OwnedHandle) {
    // SAFETY: `job` is open.
    unsafe { TerminateJobObject(job.as_raw_handle(), 1) };
}

/// Connects to the guest service through the bridge at `path`: `CONNECT <port>\n`, answered
/// with `OK <host port>\n`; the bridge closes the stream while nothing listens yet. The stream is
/// nonblocking: a blocking receive can miss its end (a Winsock `AF_UNIX` bug).
fn handshake(path: &Path) -> io::Result<Socket> {
    let stream = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    stream.connect(&SockAddr::unix(path)?)?;
    (&stream).write_all(format!("CONNECT {GUEST_SERVICE_PORT}\n").as_bytes())?;
    stream.set_nonblocking(true)?;
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    // A byte at a time: what follows the line is the guest service's.
    let mut answer = Vec::new();
    let mut byte = [0];
    while answer.last() != Some(&b'\n') {
        if answer.len() == MAX_ANSWER {
            return Err(io::Error::other(format!("the bridge answered {answer:?}")));
        }
        match (&stream).read(&mut byte) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(_) => answer.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                poll(&stream, POLLRDNORM, left)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    if !answer.starts_with(b"OK ") {
        return Err(io::Error::other(format!("the bridge answered {answer:?}")));
    }
    Ok(stream)
}

/// Serves `stream` on a new private named pipe, which a ttrpc client opens: that client.
///
/// Two threads relay, until either side ends; then they end the other: a pipe read fails, and
/// the stream is shut down. The client's own threads end once its pipe does.
fn relay(stream: Socket) -> io::Result<ttrpc::Client> {
    let sid = User::current()?.sid_string()?;
    let descriptor = SecurityDescriptor::parse(&format!("D:P(A;;GA;;;{sid})"))?;
    let attributes = descriptor.attributes();
    let name = format!(
        r"\\.\pipe\litebox-shim-{}-{:016x}",
        std::process::id(),
        RandomState::new().build_hasher().finish()
    );
    // SAFETY: the name is NUL-terminated, and `attributes` and its descriptor outlive the call.
    let pipe = unsafe {
        CreateNamedPipeW(
            wide(OsStr::new(&name)).as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            BUFFER,
            BUFFER,
            0,
            &raw const attributes,
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so this owns `pipe`.
    let pipe = unsafe { OwnedHandle::from_raw_handle(pipe) };
    let client =
        ttrpc::Client::connect(&name).map_err(|error| io::Error::other(error.to_string()))?;
    accept(&pipe)?;
    let mut client_pid = 0;
    // SAFETY: `pipe` is open, and `client_pid` outlives the call.
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &raw mut client_pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if client_pid != std::process::id() {
        return Err(io::Error::other("another process opened the relay's pipe"));
    }
    let (pipe, stream) = (Arc::new(pipe), Arc::new(stream));
    let ended = Arc::new(AtomicBool::new(false));
    {
        let (pipe, stream, ended) = (Arc::clone(&pipe), Arc::clone(&stream), Arc::clone(&ended));
        std::thread::spawn(move || {
            if let Err(error) = to_bridge(&pipe, &stream, &ended) {
                log::debug!("the relay to the guest service ended: {error}");
            }
            ended.store(true, Ordering::Release);
            let _ = stream.shutdown(Shutdown::Both);
        });
    }
    std::thread::spawn(move || {
        if let Err(error) = to_pipe(&stream, &pipe, &ended) {
            log::debug!("the relay from the guest service ended: {error}");
        }
        ended.store(true, Ordering::Release);
        // SAFETY: `pipe` is open; the other thread's read, if any, fails.
        unsafe {
            CancelIoEx(pipe.as_raw_handle(), null());
            DisconnectNamedPipe(pipe.as_raw_handle());
        }
        let _ = stream.shutdown(Shutdown::Both);
    });
    Ok(client)
}

/// Completes the pipe's connection, which a client opened already.
fn accept(pipe: &OwnedHandle) -> io::Result<()> {
    let event = event()?;
    let mut overlapped = OVERLAPPED {
        hEvent: event.as_raw_handle(),
        ..OVERLAPPED::default()
    };
    // SAFETY: `overlapped` outlives the operation: it does not start, or is cancelled and waited
    // for below.
    if unsafe { ConnectNamedPipe(pipe.as_raw_handle(), &raw mut overlapped) } != 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if is(&error, ERROR_PIPE_CONNECTED) {
        return Ok(());
    }
    if is(&error, ERROR_IO_PENDING) {
        let mut moved = 0;
        // SAFETY: `overlapped` names the pending operation, which the wait ends.
        unsafe {
            CancelIoEx(pipe.as_raw_handle(), &raw const overlapped);
            GetOverlappedResult(
                pipe.as_raw_handle(),
                &raw const overlapped,
                &raw mut moved,
                1,
            );
        }
        return Err(io::Error::other("no client opened the relay's pipe"));
    }
    Err(error)
}

/// Relays the pipe's data to the bridge's `stream`, until the pipe ends.
fn to_bridge(pipe: &OwnedHandle, stream: &Socket, ended: &AtomicBool) -> io::Result<()> {
    let event = event()?;
    let mut buffer = vec![0; BUFFER as usize];
    while !ended.load(Ordering::Acquire) {
        let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
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
        let read = match read {
            Ok(read) => read,
            Err(error) if is(&error, ERROR_BROKEN_PIPE) => return Ok(()),
            Err(error) => return Err(error),
        };
        let mut data = &buffer[..read];
        let mut writer = stream;
        while !data.is_empty() {
            match writer.write(data) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(sent) => data = &data[sent..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if ended.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    poll(stream, POLLWRNORM, POLL_INTERVAL)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

/// Relays the bridge's `stream` to the pipe, until the stream ends or `ended`.
fn to_pipe(stream: &Socket, pipe: &OwnedHandle, ended: &AtomicBool) -> io::Result<()> {
    let event = event()?;
    let mut buffer = vec![0; BUFFER as usize];
    let mut reader = stream;
    while !ended.load(Ordering::Acquire) {
        if poll(stream, POLLRDNORM, POLL_INTERVAL)? == 0 {
            continue;
        }
        loop {
            let received = match reader.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            let mut data = &buffer[..received];
            while !data.is_empty() {
                let length = u32::try_from(data.len()).unwrap_or(u32::MAX);
                // SAFETY: `data` outlives the write, which `overlapped` waits for.
                let written = overlapped(pipe, &event, |overlapped| unsafe {
                    WriteFile(
                        pipe.as_raw_handle(),
                        data.as_ptr(),
                        length,
                        null_mut(),
                        overlapped,
                    )
                })?;
                data = &data[written..];
            }
        }
    }
    Ok(())
}

/// Starts an overlapped `operation` on `pipe` that signals `event`, then waits for its end: the
/// bytes it moved.
fn overlapped(
    pipe: &OwnedHandle,
    event: &OwnedHandle,
    operation: impl FnOnce(*mut OVERLAPPED) -> i32,
) -> io::Result<usize> {
    let mut overlapped = OVERLAPPED {
        hEvent: event.as_raw_handle(),
        ..OVERLAPPED::default()
    };
    if operation(&raw mut overlapped) == 0 {
        let error = io::Error::last_os_error();
        if !is(&error, ERROR_IO_PENDING) {
            return Err(error);
        }
    }
    let mut moved = 0;
    // SAFETY: `overlapped` names an operation on `pipe` that started; the wait ends it.
    if unsafe {
        GetOverlappedResult(
            pipe.as_raw_handle(),
            &raw const overlapped,
            &raw mut moved,
            1,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(moved as usize)
}

/// Waits up to `timeout` for `events` of `stream`: those that happened.
fn poll(stream: &Socket, events: i16, timeout: Duration) -> io::Result<i16> {
    let mut sockets = [WSAPOLLFD {
        fd: SOCKET::try_from(stream.as_raw_socket()).expect("a socket fits"),
        events,
        revents: 0,
    }];
    let timeout = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: `sockets` outlives the call, which writes only its entries' `revents`.
    if unsafe { WSAPoll(sockets.as_mut_ptr(), 1, timeout) } == SOCKET_ERROR {
        // SAFETY: plain call.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(sockets[0].revents)
}

/// A manual-reset event, for overlapped operations.
fn event() -> io::Result<OwnedHandle> {
    // SAFETY: neither attributes nor a name.
    let event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if event.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so this owns `event`.
    Ok(unsafe { OwnedHandle::from_raw_handle(event) })
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain([0]).collect()
}

fn is(error: &io::Error, code: WIN32_ERROR) -> bool {
    error.raw_os_error() == i32::try_from(code).ok()
}

fn win32_result(status: WIN32_ERROR) -> io::Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(
            i32::try_from(status).unwrap_or(i32::MAX),
        ))
    }
}

fn size_u32<T>() -> u32 {
    u32::try_from(size_of::<T>()).expect("a small structure")
}
