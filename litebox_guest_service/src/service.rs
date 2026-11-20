// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The guest service's processes, and its ttrpc service.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};

use litebox_guest_service_protocol::guest_service::{
    CloseStdinRequest, CreateContainerRequest, Empty, ExecProcessRequest, Process,
    ReadStreamRequest, ReadStreamResponse, ReleaseProcessRequest, SignalProcessRequest,
    TtyWinResizeRequest, WaitProcessRequest, WaitProcessResponse, WriteStreamRequest,
    WriteStreamResponse,
};
use litebox_guest_service_protocol::guest_service_ttrpc_async::GuestService;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::{Notify, oneshot, watch};
use ttrpc::Code;
use ttrpc::r#async::TtrpcContext;

use crate::process::{self, ChildStdio, ExitStatus, Streams, status};

/// How long the end of the container may take to kill and reap every other guest process.
const KILL_TIMEOUT: Duration = Duration::from_secs(5);
/// The most bytes one read returns, as one pipe read does.
const MAX_READ: u32 = 64 * 1024;

type Stream = Arc<AsyncFd<File>>;

/// Set once a process's streams close: transfers in flight stop.
#[derive(Default)]
struct Closed(watch::Sender<bool>);

impl Closed {
    fn close(&self) {
        self.0.send_replace(true);
    }

    async fn wait(&self) {
        // It fails only without a sender, and `self` is one.
        let _ = self.0.subscribe().wait_for(|closed| *closed).await;
    }
}

/// A process of the container, by its exec ID.
struct Entry {
    pid: Option<libc::pid_t>,
    /// The init process and its stdio, until it starts.
    pending: Option<(Process, ChildStdio)>,
    terminal: bool,
    stdin: Option<Stream>,
    stdout: Option<Stream>,
    stderr: Option<Stream>,
    closed: Arc<Closed>,
    exit: Option<ExitStatus>,
}

impl Entry {
    /// Needs a runtime context, to register `streams`.
    fn new(streams: Streams, terminal: bool) -> ttrpc::Result<Self> {
        let watch = |file| {
            AsyncFd::new(file)
                .map(Arc::new)
                .map_err(|error| status(Code::INTERNAL, format!("cannot watch a stream: {error}")))
        };
        Ok(Self {
            pid: None,
            pending: None,
            terminal,
            stdin: streams.stdin.map(watch).transpose()?,
            stdout: Some(watch(streams.stdout)?),
            stderr: streams.stderr.map(watch).transpose()?,
            closed: Arc::default(),
            exit: None,
        })
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

    fn check_exec(&mut self, exec_id: &str) -> ttrpc::Result<()> {
        if self.ended || self.get("")?.pid.is_none() {
            return Err(status(
                Code::FAILED_PRECONDITION,
                "the container is not running",
            ));
        }
        if exec_id.is_empty() || self.processes.contains_key(exec_id) {
            return Err(status(Code::ALREADY_EXISTS, "the exec ID is taken"));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Service {
    shared: Arc<Shared>,
    /// Launches block until `execve`. They run one at a time on the launcher's thread, which
    /// starts with the service, so that no launch fails for want of a thread.
    launches: mpsc::Sender<Launch>,
}

type Launch = Box<dyn FnOnce(&Shared) + Send>;

#[derive(Default)]
struct Shared {
    table: Mutex<Table>,
    /// Notified when an exit is recorded.
    exited: Notify,
    /// Held by a launch from its checks to its pid's registration, and by the reaper from its
    /// lookup of a pid to the exit's record: the reaper finds every launched process, and the end
    /// of the container kills none before its `execve`, which would pass for started. Taken
    /// before `table`.
    launching: Mutex<()>,
}

impl Service {
    pub fn new(runtime: tokio::runtime::Handle) -> io::Result<Self> {
        let shared = Arc::<Shared>::default();
        let (launches, queue) = mpsc::channel::<Launch>();
        let state = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("launcher".to_owned())
            .spawn(move || {
                let _runtime = runtime.enter();
                for launch in queue {
                    launch(&state);
                }
            })?;
        Ok(Self { shared, launches })
    }

    fn lock(&self) -> MutexGuard<'_, Table> {
        self.shared.lock()
    }

    /// Reaps every child, for good: the guest service adopts every orphan of the guest.
    pub fn reap(&self) -> ! {
        self.shared.reap()
    }

    /// Runs `launch` to its end even if the request is dropped meanwhile.
    async fn launch(
        &self,
        launch: impl FnOnce(&Shared) -> ttrpc::Result<()> + Send + 'static,
    ) -> ttrpc::Result<Empty> {
        let (answer, answered) = oneshot::channel();
        self.launches
            .send(Box::new(move |shared| {
                let _ = answer.send(launch(shared));
            }))
            .expect("the launcher runs while the service does");
        answered.await.expect("the launcher runs every launch")?;
        Ok(Empty::new())
    }

    async fn read(
        &self,
        request: &ReadStreamRequest,
        stderr: bool,
    ) -> ttrpc::Result<ReadStreamResponse> {
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
            let read = tokio::select! {
                biased;
                () = closed.wait() => return Ok(ReadStreamResponse::new()),
                read = process::when_ready(&file, Interest::READABLE, |file| {
                    (&*file).read(&mut data)
                }) => read,
            };
            match read {
                Ok(read) => {
                    data.truncate(read);
                    return Ok(ReadStreamResponse {
                        data,
                        ..Default::default()
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                // A terminal's manager fails so while no file is open on its subsidiary, which
                // the process may open again until it exited: one more read after the exit
                // was seen ends the output.
                Err(error) if terminal && error.raw_os_error() == Some(libc::EIO) => {
                    if exited {
                        return Ok(ReadStreamResponse::new());
                    }
                    let exit = self.shared.exited.notified();
                    // A released process exited.
                    exited = self
                        .lock()
                        .get(&request.exec_id)
                        .map_or(true, |entry| entry.exit.is_some());
                    if !exited {
                        // A terminal opened again reports no readiness: retry meanwhile.
                        let _ = tokio::time::timeout(process::HANG_UP_RETRY, exit).await;
                    }
                }
                Err(error) => return Err(status(Code::INTERNAL, format!("read: {error}"))),
            }
        }
    }
}

impl Shared {
    /// Never held across an `.await`, nor for long: the reaper and the launcher take it too.
    fn lock(&self) -> MutexGuard<'_, Table> {
        self.table.lock().expect("the table's lock is poisoned")
    }

    fn launching(&self) -> MutexGuard<'_, ()> {
        self.launching
            .lock()
            .expect("the launches' lock is poisoned")
    }

    fn reap(&self) -> ! {
        loop {
            match process::wait_any(true) {
                Ok(Some((pid, status))) => {
                    // A launch midway registers its pid first; launches wait for the end of the
                    // container.
                    let _launching = self.launching();
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
        self.exited.notify_waiters();
    }

    fn start_init(&self, process: &Process, child: &ChildStdio) -> ttrpc::Result<()> {
        let _launching = self.launching();
        let spawned = process::spawn(process, child);
        let mut table = self.lock();
        let init = table.get("")?;
        match spawned {
            Ok(pid) => init.pid = Some(pid),
            Err(error) => {
                init.exit = Some(ExitStatus::Exited { code: 127 });
                // No process opened the terminal, so its manager would never report the end.
                if init.terminal {
                    init.stdin = None;
                    init.stdout = None;
                    init.closed.close();
                }
                table.ended = true;
                self.exited.notify_waiters();
                return Err(error);
            }
        }
        Ok(())
    }

    /// Opens the process's stdio only now, so that launches queued behind this one hold none.
    fn start_exec(&self, exec_id: String, process: &Process) -> ttrpc::Result<()> {
        let (streams, child) = Streams::new(process)?;
        let mut entry = Entry::new(streams, process.terminal)?;
        let _launching = self.launching();
        // The container may have ended since the request's check.
        self.lock().check_exec(&exec_id)?;
        entry.pid = Some(process::spawn(process, &child)?);
        self.lock().processes.insert(exec_id, entry);
        Ok(())
    }
}

// ttrpc enforces a request's deadline by dropping its handler: the table must be consistent at
// every `.await`.
#[async_trait::async_trait]
impl GuestService for Service {
    async fn create_container(
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
        let mut entry = Entry::new(streams, process.terminal)?;
        entry.pending = Some((process, child));
        table.processes.insert(String::new(), entry);
        table.created = true;
        Ok(Empty::new())
    }

    async fn start_container(&self, _ctx: &TtrpcContext, _request: Empty) -> ttrpc::Result<Empty> {
        let (process, child) = self
            .lock()
            .get("")?
            .pending
            .take()
            .ok_or_else(|| status(Code::FAILED_PRECONDITION, "the container started"))?;
        self.launch(move |shared| shared.start_init(&process, &child))
            .await
    }

    async fn exec_process(
        &self,
        _ctx: &TtrpcContext,
        request: ExecProcessRequest,
    ) -> ttrpc::Result<Empty> {
        let process = request
            .process
            .into_option()
            .ok_or_else(|| status(Code::INVALID_ARGUMENT, "no process"))?;
        self.lock().check_exec(&request.exec_id)?;
        let exec_id = request.exec_id;
        self.launch(move |shared| shared.start_exec(exec_id, &process))
            .await
    }

    async fn signal_process(
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

    async fn wait_process(
        &self,
        _ctx: &TtrpcContext,
        request: WaitProcessRequest,
    ) -> ttrpc::Result<WaitProcessResponse> {
        loop {
            // Before the check, so that it misses no exit recorded after.
            let exited = self.shared.exited.notified();
            let exit = self.lock().get(&request.exec_id)?.exit;
            if let Some(exit_status) = exit {
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
            exited.await;
        }
    }

    async fn release_process(
        &self,
        _ctx: &TtrpcContext,
        request: ReleaseProcessRequest,
    ) -> ttrpc::Result<Empty> {
        let mut table = self.lock();
        let entry = table.get(&request.exec_id)?;
        if entry.exit.is_none() {
            return Err(status(Code::FAILED_PRECONDITION, "the process runs"));
        }
        entry.closed.close();
        table.processes.remove(&request.exec_id);
        Ok(Empty::new())
    }

    async fn write_stdin(
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
            let written = tokio::select! {
                biased;
                () = closed.wait() => {
                    return Err(status(Code::FAILED_PRECONDITION, "the streams are closed"));
                }
                written = process::when_ready(&file, Interest::WRITABLE, |file| {
                    (&*file).write(data)
                }) => written,
            };
            match written {
                Ok(written) => data = &data[written..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(status(Code::INTERNAL, format!("write: {error}"))),
            }
        }
        Ok(WriteStreamResponse {
            len: u32::try_from(request.data.len()).unwrap_or(u32::MAX),
            ..Default::default()
        })
    }

    async fn read_stdout(
        &self,
        _ctx: &TtrpcContext,
        request: ReadStreamRequest,
    ) -> ttrpc::Result<ReadStreamResponse> {
        self.read(&request, false).await
    }

    async fn read_stderr(
        &self,
        _ctx: &TtrpcContext,
        request: ReadStreamRequest,
    ) -> ttrpc::Result<ReadStreamResponse> {
        self.read(&request, true).await
    }

    async fn close_stdin(
        &self,
        _ctx: &TtrpcContext,
        request: CloseStdinRequest,
    ) -> ttrpc::Result<Empty> {
        let mut table = self.lock();
        let entry = table.get(&request.exec_id)?;
        // Closing the manager would remove the subsidiary, which the process could not open then.
        if entry.terminal && entry.pid.is_none() && entry.exit.is_none() {
            return Err(status(
                Code::FAILED_PRECONDITION,
                "the terminal's process has not started",
            ));
        }
        entry.stdin = None;
        // The manager closes, which hangs the terminal up, once the transfers let go of it.
        if entry.terminal {
            entry.stdout = None;
            entry.closed.close();
        }
        Ok(Empty::new())
    }

    async fn tty_win_resize(
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
        process::set_window_size(manager.get_ref(), request.row, request.column)
            .map_err(|error| status(Code::INTERNAL, format!("cannot resize: {error}")))?;
        Ok(Empty::new())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use litebox_guest_service_protocol::guest_service::{
        CloseStdinRequest, CreateContainerRequest, Empty, ExecProcessRequest, Process,
        ReadStreamRequest, ReleaseProcessRequest, WaitProcessRequest, WriteStreamRequest,
    };
    use litebox_guest_service_protocol::guest_service_ttrpc_async::{
        GuestServiceClient, create_guest_service,
    };
    use ttrpc::r#async::{Client, Server};
    use ttrpc::{Code, context};

    use super::Service;

    fn code<T: std::fmt::Debug>(result: ttrpc::Result<T>) -> Code {
        match result {
            Err(ttrpc::Error::RpcStatus(status)) => status.code(),
            other => panic!("{other:?}"),
        }
    }

    fn deadline() -> context::Context {
        context::with_timeout(5_000_000_000)
    }

    fn process(args: &[&str]) -> Process {
        Process {
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            env: vec!["PATH=/usr/bin:/bin".to_owned()],
            cwd: "/".to_owned(),
            ..Default::default()
        }
    }

    fn create_request(process: Process) -> CreateContainerRequest {
        CreateContainerRequest {
            process: Some(process).into(),
            ..Default::default()
        }
    }

    /// Runs the service on one thread, as `run` does, but without the reaper, whose `kill(-1)`
    /// would reach the user's processes: tests reap what they start.
    fn with_client(test: impl AsyncFnOnce(Service, GuestServiceClient)) {
        let dir = tempfile::tempdir().unwrap();
        let address = format!("unix://{}", dir.path().join("socket").display());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let service = Service::new(tokio::runtime::Handle::current()).unwrap();
            let mut server = Server::new()
                .bind(&address)
                .unwrap()
                .register_service(create_guest_service(Arc::new(service.clone())));
            server.start().await.unwrap();
            let client = GuestServiceClient::new(Client::connect(&address).unwrap());
            test(service, client).await;
            server.shutdown().await.unwrap();
        });
    }

    /// Holds off launches, as the end of the container does, until the returned sender drops or
    /// 5 s pass.
    fn hold_launches(service: &Service) -> mpsc::Sender<()> {
        let (held, holding) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        let shared = Arc::clone(&service.shared);
        std::thread::spawn(move || {
            let _launching = shared.launching();
            held.send(()).unwrap();
            let _ = released.recv_timeout(Duration::from_secs(5));
        });
        holding.recv().unwrap();
        release
    }

    #[test]
    fn a_terminal_init_that_cannot_start_ends_its_output() {
        with_client(async |_, client| {
            let init = Process {
                terminal: true,
                ..process(&["no-such-program"])
            };
            let create = create_request(init);
            client.create_container(deadline(), &create).await.unwrap();
            let close = CloseStdinRequest::default();
            let closed = client.close_stdin(deadline(), &close).await;
            assert_eq!(code(closed), Code::FAILED_PRECONDITION);
            // The output ends, although nothing opened the terminal.
            let read = ReadStreamRequest {
                len: 1024,
                ..Default::default()
            };
            let (output, started) = tokio::join!(client.read_stdout(deadline(), &read), async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                client.start_container(deadline(), &Empty::new()).await
            });
            assert_eq!(code(started), Code::NOT_FOUND);
            assert_eq!(output.unwrap().data, b"");
            let wait = WaitProcessRequest::default();
            let exit = client.wait_process(deadline(), &wait).await.unwrap();
            assert_eq!((exit.status, exit.signal), (127, 0));
            let output = client.read_stdout(deadline(), &read).await;
            assert_eq!(output.unwrap().data, b"");
            let no_bytes = ReadStreamRequest::default();
            let read = client.read_stdout(deadline(), &no_bytes).await;
            assert_eq!(code(read), Code::INVALID_ARGUMENT);
            let again = client.create_container(deadline(), &create).await;
            assert_eq!(code(again), Code::ALREADY_EXISTS);
            let release = ReleaseProcessRequest::default();
            client.release_process(deadline(), &release).await.unwrap();
        });
    }

    #[test]
    fn transfers_go_on_while_a_process_launches() {
        with_client(async |service, client| {
            let init = process(&["sh", "-c", "read line; echo \"$line\""]);
            let create = create_request(init);
            client.create_container(deadline(), &create).await.unwrap();
            client
                .start_container(deadline(), &Empty::new())
                .await
                .unwrap();
            let release = hold_launches(&service);
            let exec = ExecProcessRequest {
                exec_id: "e".to_owned(),
                process: Some(process(&["no-such-program"])).into(),
                ..Default::default()
            };
            let execed = client.exec_process(deadline(), &exec);
            tokio::pin!(execed);
            let write = WriteStreamRequest {
                data: b"hello\n".to_vec(),
                ..Default::default()
            };
            let read = ReadStreamRequest {
                len: 1024,
                ..Default::default()
            };
            let echoed = async {
                client.write_stdin(deadline(), &write).await.unwrap();
                client.read_stdout(deadline(), &read).await
            };
            let output = tokio::select! {
                execed = &mut execed => panic!("the launch did not wait: {execed:?}"),
                output = echoed => output.unwrap(),
            };
            assert_eq!(output.data, b"hello\n");
            drop(release);
            assert_eq!(code(execed.await), Code::NOT_FOUND);
            let pid = service.lock().get("").unwrap().pid.unwrap();
            // SAFETY: waitpid accepts a null status.
            assert_eq!(unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) }, pid);
        });
    }
}
