// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The guest service's processes, and its ttrpc service.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use litebox_guest_service_protocol::guest_service::{
    CloseStdinRequest, CreateContainerRequest, Empty, ExecProcessRequest, Process,
    ReadStreamRequest, ReadStreamResponse, ReleaseProcessRequest, SignalProcessRequest,
    TtyWinResizeRequest, WaitProcessRequest, WaitProcessResponse, WriteStreamRequest,
    WriteStreamResponse,
};
use litebox_guest_service_protocol::guest_service_ttrpc::GuestService;
use ttrpc::{Code, TtrpcContext};

use crate::process::{self, ChildStdio, ExitStatus, Streams, status};

/// How long the end of the container may take to kill and reap every other guest process.
const KILL_TIMEOUT: Duration = Duration::from_secs(5);
/// The most bytes one read returns, as one pipe read does.
const MAX_READ: u32 = 64 * 1024;

/// A process of the container, by its exec ID.
struct Entry {
    pid: Option<libc::pid_t>,
    /// The init process and its stdio, until it starts.
    pending: Option<(Process, ChildStdio)>,
    terminal: bool,
    stdin: Option<Arc<File>>,
    stdout: Option<Arc<File>>,
    stderr: Option<Arc<File>>,
    /// Set once the streams close: transfers in flight stop.
    closed: Arc<AtomicBool>,
    exit: Option<ExitStatus>,
}

impl Entry {
    fn new(streams: Streams, terminal: bool) -> Self {
        Self {
            pid: None,
            pending: None,
            terminal,
            stdin: streams.stdin.map(Arc::new),
            stdout: Some(Arc::new(streams.stdout)),
            stderr: streams.stderr.map(Arc::new),
            closed: Arc::default(),
            exit: None,
        }
    }
}

#[derive(Default)]
struct Table {
    processes: HashMap<String, Entry>,
    /// Set once the container was created: the guest service runs one.
    created: bool,
    /// Set once the init process exited.
    ended: bool,
}

impl Table {
    fn get(&mut self, exec_id: &str) -> ttrpc::Result<&mut Entry> {
        self.processes
            .get_mut(exec_id)
            .ok_or_else(|| status(Code::NOT_FOUND, format!("no process {exec_id:?}")))
    }
}

#[derive(Default)]
pub struct Service {
    table: Mutex<Table>,
    /// Signaled when an exit is recorded.
    exited: Condvar,
}

impl Service {
    fn lock(&self) -> MutexGuard<'_, Table> {
        self.table.lock().expect("the table's lock is poisoned")
    }

    /// Reaps every child, for good: the guest service adopts every orphan of the guest.
    pub fn reap(&self) -> ! {
        loop {
            match process::wait_any(true) {
                Ok(Some((pid, status))) => {
                    let init = self.lock().get("").is_ok_and(|init| init.pid == Some(pid));
                    if init {
                        self.end_container();
                    }
                    self.record(pid, status);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                // No child yet.
                _ => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    /// Kills and reaps every other guest process, as the container ends with its init process.
    /// Kills again after each reap, since a kill may miss a child forked meanwhile.
    fn end_container(&self) {
        self.lock().ended = true;
        let deadline = Instant::now() + KILL_TIMEOUT;
        while Instant::now() < deadline {
            let _ = process::kill(-1, libc::SIGKILL);
            match process::wait_any(false) {
                Ok(Some((pid, status))) => self.record(pid, status),
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return,
                Err(_) => {}
            }
        }
        log!("guest processes survived the end of the container");
    }

    fn record(&self, pid: libc::pid_t, status: ExitStatus) {
        let mut table = self.lock();
        if let Some(entry) = table
            .processes
            .values_mut()
            .find(|entry| entry.pid == Some(pid) && entry.exit.is_none())
        {
            entry.exit = Some(status);
        }
        self.exited.notify_all();
    }

    fn read(&self, request: &ReadStreamRequest, stderr: bool) -> ttrpc::Result<ReadStreamResponse> {
        // No data would mean the stream's end.
        if request.len == 0 {
            return Err(status(Code::INVALID_ARGUMENT, "a read of no bytes"));
        }
        let (file, closed, terminal) = {
            let mut table = self.lock();
            let entry = table.get(&request.exec_id)?;
            let file = if stderr { &entry.stderr } else { &entry.stdout };
            let Some(file) = file.clone() else {
                return Ok(ReadStreamResponse::new());
            };
            (file, Arc::clone(&entry.closed), entry.terminal)
        };
        let mut data = vec![0; request.len.min(MAX_READ) as usize];
        let mut exited = false;
        loop {
            if closed.load(Ordering::SeqCst) {
                return Ok(ReadStreamResponse::new());
            }
            match (&*file).read(&mut data) {
                Ok(read) => {
                    data.truncate(read);
                    return Ok(ReadStreamResponse {
                        data,
                        ..Default::default()
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    process::wait_ready(&file, libc::POLLIN);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                // A terminal's manager fails so while no file is open on its subsidiary, which
                // the process may open again until it exited: one more read after the exit
                // was seen ends the output.
                Err(error) if terminal && error.raw_os_error() == Some(libc::EIO) => {
                    if exited {
                        return Ok(ReadStreamResponse::new());
                    }
                    // A released process exited.
                    exited = self
                        .lock()
                        .get(&request.exec_id)
                        .map_or(true, |entry| entry.exit.is_some());
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(status(Code::INTERNAL, format!("read: {error}"))),
            }
        }
    }
}

impl GuestService for Service {
    fn create_container(
        &self,
        _ctx: &TtrpcContext,
        request: CreateContainerRequest,
    ) -> ttrpc::Result<Empty> {
        let process = request
            .process
            .into_option()
            .ok_or_else(|| status(Code::INVALID_ARGUMENT, "no process"))?;
        let mut table = self.lock();
        if table.created {
            return Err(status(Code::ALREADY_EXISTS, "the container was created"));
        }
        let (streams, child) = Streams::new(&process)?;
        let mut entry = Entry::new(streams, process.terminal);
        entry.pending = Some((process, child));
        table.processes.insert(String::new(), entry);
        table.created = true;
        Ok(Empty::new())
    }

    fn start_container(&self, _ctx: &TtrpcContext, _request: Empty) -> ttrpc::Result<Empty> {
        let mut table = self.lock();
        let init = table.get("")?;
        let (process, child) = init
            .pending
            .take()
            .ok_or_else(|| status(Code::FAILED_PRECONDITION, "the container started"))?;
        // Under the table's lock, so that the reaper finds the pid.
        match process::spawn(&process, &child) {
            Ok(pid) => init.pid = Some(pid),
            Err(error) => {
                init.exit = Some(ExitStatus::Exited { code: 127 });
                // No process opened the terminal, so its manager would never report the end.
                if init.terminal {
                    init.stdin = None;
                    init.stdout = None;
                    init.closed.store(true, Ordering::SeqCst);
                }
                table.ended = true;
                self.exited.notify_all();
                return Err(error);
            }
        }
        Ok(Empty::new())
    }

    fn exec_process(
        &self,
        _ctx: &TtrpcContext,
        request: ExecProcessRequest,
    ) -> ttrpc::Result<Empty> {
        let process = request
            .process
            .into_option()
            .ok_or_else(|| status(Code::INVALID_ARGUMENT, "no process"))?;
        let mut table = self.lock();
        if table.ended || table.get("")?.pid.is_none() {
            return Err(status(
                Code::FAILED_PRECONDITION,
                "the container is not running",
            ));
        }
        if request.exec_id.is_empty() || table.processes.contains_key(&request.exec_id) {
            return Err(status(Code::ALREADY_EXISTS, "the exec ID is taken"));
        }
        let (streams, child) = Streams::new(&process)?;
        let pid = process::spawn(&process, &child)?;
        let mut entry = Entry::new(streams, process.terminal);
        entry.pid = Some(pid);
        table.processes.insert(request.exec_id, entry);
        Ok(Empty::new())
    }

    fn signal_process(
        &self,
        _ctx: &TtrpcContext,
        request: SignalProcessRequest,
    ) -> ttrpc::Result<Empty> {
        let signal = libc::c_int::try_from(request.signal)
            .map_err(|_| status(Code::INVALID_ARGUMENT, "bad signal"))?;
        let mut table = self.lock();
        let pid = if request.all {
            -1
        } else {
            match table.get(&request.exec_id)? {
                Entry {
                    pid: Some(pid),
                    exit: None,
                    ..
                } => *pid,
                _ => return Err(status(Code::NOT_FOUND, "the process is not running")),
            }
        };
        match process::kill(pid, signal) {
            Err(error) if error.raw_os_error() != Some(libc::ESRCH) => {
                Err(status(Code::INTERNAL, format!("kill: {error}")))
            }
            _ => Ok(Empty::new()),
        }
    }

    fn wait_process(
        &self,
        _ctx: &TtrpcContext,
        request: WaitProcessRequest,
    ) -> ttrpc::Result<WaitProcessResponse> {
        let mut table = self.lock();
        loop {
            if let Some(exit_status) = table.get(&request.exec_id)?.exit {
                let signal = match exit_status {
                    ExitStatus::Exited { .. } => 0,
                    ExitStatus::Signaled { signal } => signal.cast_signed(),
                };
                return Ok(WaitProcessResponse {
                    status: exit_status.unix_shell_exit_code(),
                    signal,
                    ..Default::default()
                });
            }
            table = self
                .exited
                .wait(table)
                .expect("the table's lock is poisoned");
        }
    }

    fn release_process(
        &self,
        _ctx: &TtrpcContext,
        request: ReleaseProcessRequest,
    ) -> ttrpc::Result<Empty> {
        let mut table = self.lock();
        let entry = table.get(&request.exec_id)?;
        if entry.exit.is_none() {
            return Err(status(Code::FAILED_PRECONDITION, "the process runs"));
        }
        entry.closed.store(true, Ordering::SeqCst);
        table.processes.remove(&request.exec_id);
        Ok(Empty::new())
    }

    fn write_stdin(
        &self,
        _ctx: &TtrpcContext,
        request: WriteStreamRequest,
    ) -> ttrpc::Result<WriteStreamResponse> {
        let (file, closed) = {
            let mut table = self.lock();
            let entry = table.get(&request.exec_id)?;
            let file = entry
                .stdin
                .clone()
                .ok_or_else(|| status(Code::FAILED_PRECONDITION, "stdin is closed"))?;
            (file, Arc::clone(&entry.closed))
        };
        let mut data = request.data.as_slice();
        while !data.is_empty() {
            if closed.load(Ordering::SeqCst) {
                return Err(status(Code::FAILED_PRECONDITION, "the streams are closed"));
            }
            match (&*file).write(data) {
                Ok(written) => data = &data[written..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    process::wait_ready(&file, libc::POLLOUT);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(status(Code::INTERNAL, format!("write: {error}"))),
            }
        }
        Ok(WriteStreamResponse {
            len: u32::try_from(request.data.len()).unwrap_or(u32::MAX),
            ..Default::default()
        })
    }

    fn read_stdout(
        &self,
        _ctx: &TtrpcContext,
        request: ReadStreamRequest,
    ) -> ttrpc::Result<ReadStreamResponse> {
        self.read(&request, false)
    }

    fn read_stderr(
        &self,
        _ctx: &TtrpcContext,
        request: ReadStreamRequest,
    ) -> ttrpc::Result<ReadStreamResponse> {
        self.read(&request, true)
    }

    fn close_stdin(&self, _ctx: &TtrpcContext, request: CloseStdinRequest) -> ttrpc::Result<Empty> {
        let mut table = self.lock();
        let entry = table.get(&request.exec_id)?;
        // Closing the manager would remove the subsidiary, which the process could not open then.
        if entry.terminal && entry.pending.is_some() {
            return Err(status(
                Code::FAILED_PRECONDITION,
                "the terminal's process has not started",
            ));
        }
        entry.stdin = None;
        // The manager closes, which hangs the terminal up, once the transfers let go of it.
        if entry.terminal {
            entry.stdout = None;
            entry.closed.store(true, Ordering::SeqCst);
        }
        Ok(Empty::new())
    }

    fn tty_win_resize(
        &self,
        _ctx: &TtrpcContext,
        request: TtyWinResizeRequest,
    ) -> ttrpc::Result<Empty> {
        let mut table = self.lock();
        let entry = table.get(&request.exec_id)?;
        let manager = entry
            .stdout
            .as_ref()
            .filter(|_| entry.terminal)
            .ok_or_else(|| status(Code::NOT_FOUND, "no terminal"))?;
        process::set_window_size(manager, request.row, request.column)
            .map_err(|error| status(Code::INTERNAL, format!("cannot resize: {error}")))?;
        Ok(Empty::new())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use litebox_guest_service_protocol::guest_service::{
        CloseStdinRequest, CreateContainerRequest, Empty, Process, ReadStreamRequest,
        ReleaseProcessRequest, WaitProcessRequest,
    };
    use litebox_guest_service_protocol::guest_service_ttrpc::{
        GuestServiceClient, create_guest_service,
    };
    use ttrpc::{Code, context};

    use super::Service;

    fn code<T: std::fmt::Debug>(result: ttrpc::Result<T>) -> Code {
        match result {
            Err(ttrpc::Error::RpcStatus(status)) => status.code(),
            other => panic!("{other:?}"),
        }
    }

    /// No process starts here: nothing reaps, and nothing calls `kill(-1)`.
    #[test]
    fn a_terminal_init_that_cannot_start_ends_its_output() {
        let dir = tempfile::tempdir().unwrap();
        let address = format!("unix://{}", dir.path().join("socket").display());
        let service = create_guest_service(Arc::new(Service::default()));
        let mut server = ttrpc::Server::new()
            .bind(&address)
            .unwrap()
            .register_service(service);
        server.start().unwrap();
        let client = GuestServiceClient::new(ttrpc::Client::connect(&address).unwrap());
        let deadline = || context::with_timeout(5_000_000_000);
        let process = Process {
            args: vec!["no-such-program".to_owned()],
            cwd: "/".to_owned(),
            terminal: true,
            ..Default::default()
        };
        let create = CreateContainerRequest {
            process: Some(process).into(),
            ..Default::default()
        };
        client.create_container(deadline(), &create).unwrap();
        let close = CloseStdinRequest::default();
        let closed = client.close_stdin(deadline(), &close);
        assert_eq!(code(closed), Code::FAILED_PRECONDITION);
        let started = client.start_container(deadline(), &Empty::new());
        assert_eq!(code(started), Code::NOT_FOUND);
        let wait = WaitProcessRequest::default();
        let exit = client.wait_process(deadline(), &wait).unwrap();
        assert_eq!((exit.status, exit.signal), (127, 0));
        // The output ends, although nothing opened the terminal.
        let read = ReadStreamRequest {
            len: 1024,
            ..Default::default()
        };
        let output = client.read_stdout(deadline(), &read).unwrap();
        assert_eq!(output.data, b"");
        let no_bytes = ReadStreamRequest::default();
        assert_eq!(
            code(client.read_stdout(deadline(), &no_bytes)),
            Code::INVALID_ARGUMENT
        );
        let again = client.create_container(deadline(), &create);
        assert_eq!(code(again), Code::ALREADY_EXISTS);
        let release = ReleaseProcessRequest::default();
        client.release_process(deadline(), &release).unwrap();
        server.shutdown();
    }
}
