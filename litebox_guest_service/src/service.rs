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
    ReadStreamRequest, ReadStreamResponse, ReleaseProcessRequest, RemoveContainerRequest,
    SignalProcessRequest, StartContainerRequest, TtyWinResizeRequest, WaitProcessRequest,
    WaitProcessResponse, WriteStreamRequest, WriteStreamResponse,
};
use litebox_guest_service_protocol::guest_service_ttrpc_async::GuestService;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::{oneshot, watch};
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

/// A process's exit, once recorded. Its release ends the waits for it.
#[derive(Default)]
struct Exit(watch::Sender<Option<ExitStatus>>);

impl Exit {
    fn get(&self) -> Option<ExitStatus> {
        *self.0.borrow()
    }

    fn set(&self, status: ExitStatus) {
        self.0.send_replace(Some(status));
    }

    fn subscribe(&self) -> watch::Receiver<Option<ExitStatus>> {
        self.0.subscribe()
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
    exit: Exit,
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
            exit: Exit::default(),
        })
    }
}

/// A container: its processes, by exec ID.
#[derive(Default)]
struct Container {
    processes: HashMap<String, Entry>,
    /// Set once the init process exited, or its launch failed.
    ended: bool,
}

impl Container {
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

#[derive(Default)]
struct Table {
    /// By container ID.
    containers: HashMap<String, Container>,
}

impl Table {
    fn container(&mut self, container_id: &str) -> ttrpc::Result<&mut Container> {
        self.containers
            .get_mut(container_id)
            .ok_or_else(|| status(Code::NOT_FOUND, format!("no container {container_id:?}")))
    }

    fn get(&mut self, container_id: &str, exec_id: &str) -> ttrpc::Result<&mut Entry> {
        self.container(container_id)?.get(exec_id)
    }

    /// The ID of the container whose running init process is `pid`: an exited one's may be reused.
    fn init_of(&self, pid: libc::pid_t) -> Option<String> {
        self.containers
            .iter()
            .find(|(_, container)| {
                (container.processes.get("")).is_some_and(|init| {
                    init.pid == Some(pid) && init.exit.get().is_none() && !container.ended
                })
            })
            .map(|(container_id, _)| container_id.clone())
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
        let (file, closed, terminal, mut exit) = {
            let mut table = self.lock();
            let entry = table.get(&request.container_id, &request.exec_id)?;
            let file = if stderr { &entry.stderr } else { &entry.stdout };
            let Some(file) = file.clone() else {
                return Ok(ReadStreamResponse::new());
            };
            let closed = Arc::clone(&entry.closed);
            (file, closed, entry.terminal, entry.exit.subscribe())
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
                    let recorded = exit.borrow_and_update().is_some();
                    // A released process exited.
                    exited = recorded || exit.has_changed().is_err();
                    if !exited {
                        // A terminal opened again reports no readiness: retry meanwhile.
                        let _ = tokio::time::timeout(process::HANG_UP_RETRY, exit.changed()).await;
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
                    let init_of = self.lock().init_of(pid);
                    if let Some(container_id) = init_of {
                        self.end_container(&container_id);
                    }
                    self.record(pid, status);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                // No child yet.
                _ => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    /// Kills and reaps every other guest process, as the container `container_id` ends with its
    /// init process. Kills again after each reap, since a kill may miss a child forked meanwhile.
    // TODO: kill only the container's processes once it has a PID namespace.
    fn end_container(&self, container_id: &str) {
        if let Ok(container) = self.lock().container(container_id) {
            container.ended = true;
        }
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
        let found = (table.containers.values_mut())
            .flat_map(|container| container.processes.values_mut())
            .find(|entry| entry.pid == Some(pid) && entry.exit.get().is_none());
        if let Some(entry) = found {
            entry.exit.set(status);
        }
    }

    fn start_init(
        &self,
        container_id: &str,
        process: &Process,
        child: &ChildStdio,
    ) -> ttrpc::Result<()> {
        let _launching = self.launching();
        let spawned = process::spawn(process, child);
        let mut table = self.lock();
        let container = table.container(container_id)?;
        let init = container.get("")?;
        match spawned {
            Ok(pid) => init.pid = Some(pid),
            Err(error) => {
                init.exit.set(ExitStatus::Exited { code: 127 });
                // No process opened the terminal, so its manager would never report the end.
                if init.terminal {
                    init.stdin = None;
                    init.stdout = None;
                    init.closed.close();
                }
                container.ended = true;
                return Err(error);
            }
        }
        Ok(())
    }

    /// Opens the process's stdio only now, so that launches queued behind this one hold none.
    fn start_exec(
        &self,
        container_id: &str,
        exec_id: String,
        process: &Process,
    ) -> ttrpc::Result<()> {
        let (streams, child) = Streams::new(process)?;
        let mut entry = Entry::new(streams, process.terminal)?;
        let _launching = self.launching();
        // The container may have ended since the request's check.
        self.lock().container(container_id)?.check_exec(&exec_id)?;
        entry.pid = Some(process::spawn(process, &child)?);
        let mut table = self.lock();
        table
            .container(container_id)?
            .processes
            .insert(exec_id, entry);
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
        if request.container_id.is_empty() {
            return Err(status(Code::INVALID_ARGUMENT, "no container ID"));
        }
        let mut table = self.lock();
        if table.containers.contains_key(&request.container_id) {
            return Err(status(Code::ALREADY_EXISTS, "the container exists"));
        }
        let (streams, child) = Streams::new(&process)?;
        let mut entry = Entry::new(streams, process.terminal)?;
        entry.pending = Some((process, child));
        let mut container = Container::default();
        container.processes.insert(String::new(), entry);
        table.containers.insert(request.container_id, container);
        Ok(Empty::new())
    }

    async fn start_container(
        &self,
        _ctx: &TtrpcContext,
        request: StartContainerRequest,
    ) -> ttrpc::Result<Empty> {
        let (process, child) = {
            let mut table = self.lock();
            table.container(&request.container_id)?;
            // TODO: run containers together once each has a PID namespace.
            let another_runs = table.containers.iter().any(|(container_id, container)| {
                *container_id != request.container_id
                    && (container.processes.get(""))
                        .is_some_and(|init| init.pending.is_none() && init.exit.get().is_none())
            });
            if another_runs {
                return Err(status(Code::FAILED_PRECONDITION, "another container runs"));
            }
            (table.get(&request.container_id, "")?.pending.take())
                .ok_or_else(|| status(Code::FAILED_PRECONDITION, "the container started"))?
        };
        let container_id = request.container_id;
        self.launch(move |shared| shared.start_init(&container_id, &process, &child))
            .await
    }

    async fn remove_container(
        &self,
        _ctx: &TtrpcContext,
        request: RemoveContainerRequest,
    ) -> ttrpc::Result<Empty> {
        let mut table = self.lock();
        let container = table.container(&request.container_id)?;
        // Not just the init: an end of the container that times out may leave processes running.
        let created = (container.processes.get("")).is_some_and(|init| init.pending.is_some());
        let exited = (container.processes.values()).all(|entry| entry.exit.get().is_some());
        let removable = created || exited;
        if !removable {
            return Err(status(Code::FAILED_PRECONDITION, "the container runs"));
        }
        for entry in container.processes.values() {
            entry.closed.close();
        }
        table.containers.remove(&request.container_id);
        Ok(Empty::new())
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
        self.lock()
            .container(&request.container_id)?
            .check_exec(&request.exec_id)?;
        let (container_id, exec_id) = (request.container_id, request.exec_id);
        self.launch(move |shared| shared.start_exec(&container_id, exec_id, &process))
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
        let entry = table.get(&request.container_id, &request.exec_id)?;
        let (Some(pid), None) = (entry.pid, entry.exit.get()) else {
            return Err(status(Code::NOT_FOUND, "the process is not running"));
        };
        // TODO: only the container's processes once it has a PID namespace.
        let pid = if request.all { -1 } else { pid };
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
        let mut exit = self
            .lock()
            .get(&request.container_id, &request.exec_id)?
            .exit
            .subscribe();
        // Fails once the process is released or its container removed.
        let waited = exit.wait_for(Option::is_some).await.map(|exit| *exit);
        let Ok(Some(exit_status)) = waited else {
            let exec_id = &request.exec_id;
            return Err(status(Code::NOT_FOUND, format!("no process {exec_id:?}")));
        };
        let signal = match exit_status {
            ExitStatus::Exited { .. } => 0,
            ExitStatus::Signaled { signal } => signal.cast_signed(),
        };
        Ok(WaitProcessResponse {
            status: exit_status.unix_shell_exit_code(),
            signal,
            ..Default::default()
        })
    }

    async fn release_process(
        &self,
        _ctx: &TtrpcContext,
        request: ReleaseProcessRequest,
    ) -> ttrpc::Result<Empty> {
        let mut table = self.lock();
        let container = table.container(&request.container_id)?;
        let entry = container.get(&request.exec_id)?;
        if entry.exit.get().is_none() {
            return Err(status(Code::FAILED_PRECONDITION, "the process runs"));
        }
        entry.closed.close();
        container.processes.remove(&request.exec_id);
        Ok(Empty::new())
    }

    async fn write_stdin(
        &self,
        _ctx: &TtrpcContext,
        request: WriteStreamRequest,
    ) -> ttrpc::Result<WriteStreamResponse> {
        let (file, closed) = {
            let mut table = self.lock();
            let entry = table.get(&request.container_id, &request.exec_id)?;
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
        let entry = table.get(&request.container_id, &request.exec_id)?;
        // Closing the manager would remove the subsidiary, which the process could not open then.
        if entry.terminal && entry.pid.is_none() && entry.exit.get().is_none() {
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
        let entry = table.get(&request.container_id, &request.exec_id)?;
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
        CloseStdinRequest, CreateContainerRequest, ExecProcessRequest, Process, ReadStreamRequest,
        ReleaseProcessRequest, RemoveContainerRequest, SignalProcessRequest, StartContainerRequest,
        WaitProcessRequest, WriteStreamRequest,
    };
    use litebox_guest_service_protocol::guest_service_ttrpc_async::{
        GuestServiceClient, create_guest_service,
    };
    use ttrpc::r#async::{Client, Server};
    use ttrpc::{Code, context};

    use super::Service;
    use crate::process::ExitStatus;

    const CONTAINER: &str = "c";

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

    fn create_request(container_id: &str, process: Process) -> CreateContainerRequest {
        CreateContainerRequest {
            container_id: container_id.to_owned(),
            process: Some(process).into(),
            ..Default::default()
        }
    }

    fn start_request(container_id: &str) -> StartContainerRequest {
        StartContainerRequest {
            container_id: container_id.to_owned(),
            ..Default::default()
        }
    }

    fn remove_request(container_id: &str) -> RemoveContainerRequest {
        RemoveContainerRequest {
            container_id: container_id.to_owned(),
            ..Default::default()
        }
    }

    fn read_request(container_id: &str) -> ReadStreamRequest {
        ReadStreamRequest {
            container_id: container_id.to_owned(),
            len: 1024,
            ..Default::default()
        }
    }

    fn write_request(container_id: &str, data: &[u8]) -> WriteStreamRequest {
        WriteStreamRequest {
            container_id: container_id.to_owned(),
            data: data.to_vec(),
            ..Default::default()
        }
    }

    /// The pid of the container's init process, once started.
    fn init_pid(service: &Service, container_id: &str) -> libc::pid_t {
        service.lock().get(container_id, "").unwrap().pid.unwrap()
    }

    /// Waits for the process `pid`, which the test started, to exit with a code.
    fn wait_exit(pid: libc::pid_t) -> ExitStatus {
        let mut status = 0;
        // SAFETY: `status` is a valid, writable int.
        assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "{status:#x}");
        let code = libc::WEXITSTATUS(status).cast_unsigned();
        ExitStatus::Exited { code }
    }

    /// Reaps `pid` as the reaper does, without the kills of a container's end.
    fn reap(service: &Service, pid: libc::pid_t) {
        let status = wait_exit(pid);
        end(service, pid);
        service.shared.record(pid, status);
    }

    /// Ends the container whose init is `pid`, as the reaper does, without the kills.
    fn end(service: &Service, pid: libc::pid_t) {
        let mut table = service.lock();
        if let Some(container_id) = table.init_of(pid) {
            table.container(&container_id).unwrap().ended = true;
        }
    }

    fn exec_request(exec_id: &str, process: Process) -> ExecProcessRequest {
        ExecProcessRequest {
            container_id: CONTAINER.to_owned(),
            exec_id: exec_id.to_owned(),
            process: Some(process).into(),
            ..Default::default()
        }
    }

    fn wait_request(exec_id: &str) -> WaitProcessRequest {
        WaitProcessRequest {
            container_id: CONTAINER.to_owned(),
            exec_id: exec_id.to_owned(),
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
            let create = create_request(CONTAINER, init);
            client.create_container(deadline(), &create).await.unwrap();
            let close = CloseStdinRequest {
                container_id: CONTAINER.to_owned(),
                ..Default::default()
            };
            let closed = client.close_stdin(deadline(), &close).await;
            assert_eq!(code(closed), Code::FAILED_PRECONDITION);
            // The output ends, although nothing opened the terminal.
            let read = read_request(CONTAINER);
            let (output, started) = tokio::join!(client.read_stdout(deadline(), &read), async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let start = start_request(CONTAINER);
                client.start_container(deadline(), &start).await
            });
            assert_eq!(code(started), Code::NOT_FOUND);
            assert_eq!(output.unwrap().data, b"");
            let exit = client.wait_process(deadline(), &wait_request("")).await;
            let exit = exit.unwrap();
            assert_eq!((exit.status, exit.signal), (127, 0));
            let output = client.read_stdout(deadline(), &read).await;
            assert_eq!(output.unwrap().data, b"");
            let no_bytes = ReadStreamRequest {
                container_id: CONTAINER.to_owned(),
                ..Default::default()
            };
            let read = client.read_stdout(deadline(), &no_bytes).await;
            assert_eq!(code(read), Code::INVALID_ARGUMENT);
            let again = client.create_container(deadline(), &create).await;
            assert_eq!(code(again), Code::ALREADY_EXISTS);
            let release = ReleaseProcessRequest {
                container_id: CONTAINER.to_owned(),
                ..Default::default()
            };
            client.release_process(deadline(), &release).await.unwrap();
        });
    }

    #[test]
    fn transfers_go_on_while_a_process_launches() {
        with_client(async |service, client| {
            let init = process(&["sh", "-c", "read line; echo \"$line\""]);
            let create = create_request(CONTAINER, init);
            client.create_container(deadline(), &create).await.unwrap();
            let start = start_request(CONTAINER);
            client.start_container(deadline(), &start).await.unwrap();
            let release = hold_launches(&service);
            let exec = exec_request("e", process(&["no-such-program"]));
            let execed = client.exec_process(deadline(), &exec);
            tokio::pin!(execed);
            let write = write_request(CONTAINER, b"hello\n");
            let read = read_request(CONTAINER);
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
            reap(&service, init_pid(&service, CONTAINER));
        });
    }

    #[test]
    fn requests_reach_the_container_they_name_which_run_one_at_a_time() {
        with_client(async |service, client| {
            let echo = || process(&["sh", "-c", "read line; echo \"$line\""]);
            for container_id in ["a", "b"] {
                let create = create_request(container_id, echo());
                client.create_container(deadline(), &create).await.unwrap();
            }
            let again = create_request("a", echo());
            let again = client.create_container(deadline(), &again).await;
            assert_eq!(code(again), Code::ALREADY_EXISTS);
            let unnamed = create_request("", echo());
            let unnamed = client.create_container(deadline(), &unnamed).await;
            assert_eq!(code(unnamed), Code::INVALID_ARGUMENT);
            client
                .start_container(deadline(), &start_request("a"))
                .await
                .unwrap();
            let both = client
                .start_container(deadline(), &start_request("b"))
                .await;
            assert_eq!(code(both), Code::FAILED_PRECONDITION);
            for container_id in ["a", "b"] {
                // `b` starts once `a` ended.
                if container_id == "b" {
                    let start = start_request(container_id);
                    client.start_container(deadline(), &start).await.unwrap();
                }
                let data = format!("{container_id}\n");
                let write = write_request(container_id, data.as_bytes());
                client.write_stdin(deadline(), &write).await.unwrap();
                let read = read_request(container_id);
                let output = client.read_stdout(deadline(), &read).await;
                assert_eq!(output.unwrap().data, data.as_bytes());
                reap(&service, init_pid(&service, container_id));
            }
            let missing = read_request("missing");
            let missing = client.read_stdout(deadline(), &missing).await;
            assert_eq!(code(missing), Code::NOT_FOUND);
        });
    }

    #[test]
    fn only_a_container_that_does_not_run_is_removed() {
        with_client(async |service, client| {
            let init = || process(&["sh", "-c", "read line"]);
            let create = create_request(CONTAINER, init());
            client.create_container(deadline(), &create).await.unwrap();
            let signal = SignalProcessRequest {
                container_id: CONTAINER.to_owned(),
                // Delivers none, should the check fail: the test runs outside a guest.
                signal: 0,
                all: true,
                ..Default::default()
            };
            let signaled = client.signal_process(deadline(), &signal).await;
            assert_eq!(code(signaled), Code::NOT_FOUND);
            // Removing a container that never started ends its transfers.
            let read = read_request(CONTAINER);
            let remove = remove_request(CONTAINER);
            let (output, removed) = tokio::join!(client.read_stdout(deadline(), &read), async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                client.remove_container(deadline(), &remove).await
            });
            removed.unwrap();
            assert_eq!(output.unwrap().data, b"");
            let gone = client.read_stdout(deadline(), &read).await;
            assert_eq!(code(gone), Code::NOT_FOUND);
            // Its ID names a new container.
            client.create_container(deadline(), &create).await.unwrap();
            let start = start_request(CONTAINER);
            client.start_container(deadline(), &start).await.unwrap();
            let running = client.remove_container(deadline(), &remove).await;
            assert_eq!(code(running), Code::FAILED_PRECONDITION);
            let exec = exec_request("e", init());
            client.exec_process(deadline(), &exec).await.unwrap();
            // Not while its init's exit awaits the end of the container.
            let write = write_request(CONTAINER, b"\n");
            client.write_stdin(deadline(), &write).await.unwrap();
            let pid = init_pid(&service, CONTAINER);
            let status = wait_exit(pid);
            end(&service, pid);
            let ending = client.remove_container(deadline(), &remove).await;
            assert_eq!(code(ending), Code::FAILED_PRECONDITION);
            // An ended init's pid no longer names it.
            assert_eq!(service.lock().init_of(pid), None);
            service.shared.record(pid, status);
            // Nor while a process survives the end, as when the kills time out.
            let survived = client.remove_container(deadline(), &remove).await;
            assert_eq!(code(survived), Code::FAILED_PRECONDITION);
            let write = WriteStreamRequest {
                exec_id: "e".to_owned(),
                ..write_request(CONTAINER, b"\n")
            };
            client.write_stdin(deadline(), &write).await.unwrap();
            let exec_pid = service.lock().get(CONTAINER, "e").unwrap().pid.unwrap();
            reap(&service, exec_pid);
            client.remove_container(deadline(), &remove).await.unwrap();
            let waited = client.wait_process(deadline(), &wait_request("")).await;
            assert_eq!(code(waited), Code::NOT_FOUND);
            let missing = client.remove_container(deadline(), &remove).await;
            assert_eq!(code(missing), Code::NOT_FOUND);
        });
    }

    #[test]
    fn a_wait_ends_with_its_container_s_removal_and_misses_the_next_with_its_id() {
        with_client(async |_, client| {
            let create = create_request(CONTAINER, process(&["sh", "-c", "read line"]));
            client.create_container(deadline(), &create).await.unwrap();
            let (remove, wait) = (remove_request(CONTAINER), wait_request(""));
            let (waited, ()) = tokio::join!(client.wait_process(deadline(), &wait), async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                client.remove_container(deadline(), &remove).await.unwrap();
                client.create_container(deadline(), &create).await.unwrap();
            });
            assert_eq!(code(waited), Code::NOT_FOUND);
            client.remove_container(deadline(), &remove).await.unwrap();
        });
    }
}
