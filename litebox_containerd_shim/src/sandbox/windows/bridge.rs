// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Relays the broker's `AF_UNIX` socket to a named pipe for Windows ttrpc.

use std::ffi::OsStr;
use std::hash::{BuildHasher as _, RandomState};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::windows::io::{AsRawHandle as _, AsRawSocket as _, FromRawHandle as _, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use containerd_shim::protos::ttrpc;
use socket2::{Domain, SockAddr, Socket, Type};
use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Networking::WinSock::{
    POLLRDNORM, POLLWRNORM, SOCKET, SOCKET_ERROR, WSAGetLastError, WSAPOLLFD, WSAPoll,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FlushFileBuffers, PIPE_ACCESS_DUPLEX,
    ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::CreateEventW;

use super::is;
use super::security::{SecurityDescriptor, User, wide};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Also the pipe's buffer size.
const BUFFER: u32 = 64 * 1024;
/// How often a thread blocked on the socket checks `ended`.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The socket stays nonblocking: a blocking receive can miss its end (a Winsock `AF_UNIX` bug).
pub fn connect_bridge(path: &Path) -> io::Result<Socket> {
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.connect(&SockAddr::unix(path)?)?;
    socket.set_nonblocking(true)?;
    crate::sandbox::handshake(&mut Deadlined {
        socket: &socket,
        deadline: Instant::now() + HANDSHAKE_TIMEOUT,
    })?;
    Ok(socket)
}

pub fn client(socket: Socket) -> ttrpc::Result<ttrpc::Client> {
    relay(socket, |name| {
        ttrpc::Client::connect(name).map_err(|error| io::Error::other(error.to_string()))
    })
    .map_err(|error| ttrpc::Error::Others(error.to_string()))
}

/// Blocking I/O on a nonblocking socket, until a deadline.
struct Deadlined<'socket> {
    socket: &'socket Socket,
    deadline: Instant,
}

impl Deadlined<'_> {
    fn wait(&self, events: i16) -> io::Result<()> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        poll(self.socket, events, left).map(drop)
    }
}

impl Read for Deadlined<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.socket.read(buffer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait(POLLRDNORM)?;
                }
                read => return read,
            }
        }
    }
}

impl Write for Deadlined<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        loop {
            match self.socket.write(data) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait(POLLWRNORM)?;
                }
                written => return written,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `open` must open the pipe from this process: any other client is refused. Whichever side ends
/// first ends the other.
fn relay<T>(socket: Socket, open: impl FnOnce(&str) -> io::Result<T>) -> io::Result<T> {
    let name = format!(
        r"\\.\pipe\litebox-shim-{}-{:016x}",
        std::process::id(),
        RandomState::new().hash_one(Instant::now())
    );
    let pipe = owner_only_pipe(&name)?;
    let client = open(&name)?;
    accept(&pipe)?;
    let mut client_pid = 0;
    // SAFETY: `pipe` is open, and `client_pid` outlives the call.
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &raw mut client_pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if client_pid != std::process::id() {
        return Err(io::Error::other("another process opened the relay's pipe"));
    }
    let (pipe, socket) = (Arc::new(pipe), Arc::new(socket));
    let ended = Arc::new(AtomicBool::new(false));
    {
        let (pipe, socket, ended) = (Arc::clone(&pipe), Arc::clone(&socket), Arc::clone(&ended));
        std::thread::spawn(move || {
            if let Err(error) = to_bridge(&pipe, &socket, &ended) {
                log::debug!("the relay to the guest service ended: {error}");
            }
            ended.store(true, Ordering::Release);
            let _ = socket.shutdown(Shutdown::Both);
        });
    }
    std::thread::spawn(move || {
        match to_pipe(&socket, &pipe, &ended) {
            // `DisconnectNamedPipe` discards what the client has not read yet.
            // SAFETY: `pipe` is open.
            Ok(()) => unsafe {
                FlushFileBuffers(pipe.as_raw_handle());
            },
            Err(error) => log::debug!("the relay from the guest service ended: {error}"),
        }
        ended.store(true, Ordering::Release);
        // SAFETY: `pipe` is open; the other thread's read, if any, fails.
        unsafe {
            CancelIoEx(pipe.as_raw_handle(), null());
            DisconnectNamedPipe(pipe.as_raw_handle());
        }
        let _ = socket.shutdown(Shutdown::Both);
    });
    Ok(client)
}

pub(super) fn owner_only_pipe(name: &str) -> io::Result<OwnedHandle> {
    let sid = User::current()?.sid_string()?;
    let descriptor = SecurityDescriptor::parse(&format!("D:P(A;;GA;;;{sid})"))?;
    let attributes = descriptor.attributes();
    // SAFETY: the name is NUL-terminated, and `attributes` and its descriptor outlive the call.
    let pipe = unsafe {
        CreateNamedPipeW(
            wide(OsStr::new(name)).as_ptr(),
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
    Ok(unsafe { OwnedHandle::from_raw_handle(pipe) })
}

/// The client has opened the pipe already, so a pending connection fails.
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

fn to_bridge(pipe: &OwnedHandle, socket: &Socket, ended: &AtomicBool) -> io::Result<()> {
    let event = event()?;
    let mut buffer = vec![0; BUFFER as usize];
    let length = u32::try_from(buffer.len()).expect("the buffer is BUFFER long");
    while !ended.load(Ordering::Acquire) {
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
        let mut writer = socket;
        while !data.is_empty() {
            match writer.write(data) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(sent) => data = &data[sent..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if ended.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    poll(socket, POLLWRNORM, POLL_INTERVAL)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn to_pipe(socket: &Socket, pipe: &OwnedHandle, ended: &AtomicBool) -> io::Result<()> {
    let event = event()?;
    let mut buffer = vec![0; BUFFER as usize];
    let mut reader = socket;
    while !ended.load(Ordering::Acquire) {
        if poll(socket, POLLRDNORM, POLL_INTERVAL)? == 0 {
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
                let length = u32::try_from(data.len()).expect("a piece is BUFFER long at most");
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

/// Waits for `operation`, which starts an overlapped operation on `pipe` with `event`, to end.
pub(super) fn overlapped(
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

fn poll(socket: &Socket, events: i16, timeout: Duration) -> io::Result<i16> {
    let mut sockets = [WSAPOLLFD {
        fd: SOCKET::try_from(socket.as_raw_socket()).expect("a socket fits a SOCKET"),
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

pub(super) fn event() -> io::Result<OwnedHandle> {
    // SAFETY: neither attributes nor a name.
    let event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if event.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call succeeded, so this owns `event`.
    Ok(unsafe { OwnedHandle::from_raw_handle(event) })
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::path::PathBuf;

    use litebox_guest_service_protocol::GUEST_SERVICE_PORT;

    use super::*;

    fn bridge(dir: &Path, answer: &'static [u8]) -> PathBuf {
        let path = dir.join("bridge.sock");
        let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        listener.bind(&SockAddr::unix(&path).unwrap()).unwrap();
        listener.listen(1).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while request.last() != Some(&b'\n') {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            assert_eq!(
                request,
                format!("CONNECT {GUEST_SERVICE_PORT}\n").as_bytes()
            );
            stream.write_all(answer).unwrap();
            let mut buffer = [0; 4096];
            while let Ok(read @ 1..) = stream.read(&mut buffer) {
                stream.write_all(&buffer[..read]).unwrap();
            }
        });
        path
    }

    fn open(name: &str) -> io::Result<File> {
        OpenOptions::new().read(true).write(true).open(name)
    }

    #[test]
    fn a_silent_bridge_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let error = connect_bridge(&bridge(dir.path(), b"")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
    }

    #[test]
    fn the_relay_carries_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        let socket = connect_bridge(&bridge(dir.path(), b"OK 1\n")).unwrap();
        let mut pipe = relay(socket, open).unwrap();
        // One way at a time: a synchronous handle's reads and writes wait for each other.
        for length in [1, 1000, BUFFER as usize + 1] {
            let data: Vec<u8> = (0..=u8::MAX).cycle().take(length).collect();
            pipe.write_all(&data).unwrap();
            let mut echoed = vec![0; length];
            pipe.read_exact(&mut echoed).unwrap();
            assert!(echoed == data, "the echo of {length} bytes differs");
        }
    }
}
