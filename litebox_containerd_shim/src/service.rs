// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The shim and its `containerd.task.v2.Task` service, free of the host mechanics that the
//! [`broker`] backend provides.
//!
//! One daemon hosts at most one container. Every task's state is under one lock, and each event
//! is queued while that lock is held at the state transition it reports, so that events leave in
//! the order of their transitions. One publisher thread forwards them to containerd
//! ([`events`]).

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::fd::AsFd as _;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant, SystemTime};

use containerd_shim::api::{
    CheckpointTaskRequest, CloseIORequest, ConnectRequest, ConnectResponse, CreateTaskRequest,
    CreateTaskResponse, DeleteRequest, DeleteResponse, Empty, ExecProcessRequest, KillRequest,
    PauseRequest, PidsRequest, PidsResponse, ResizePtyRequest, ResumeRequest, ShutdownRequest,
    StartRequest, StartResponse, StateRequest, StateResponse, StatsRequest, StatsResponse, Status,
    UpdateTaskRequest, WaitRequest, WaitResponse,
};
use containerd_shim::protos::events::task::{
    TaskCreate, TaskDelete, TaskExecAdded, TaskExecStarted, TaskExit, TaskIO, TaskStart,
};
use containerd_shim::protos::protobuf::well_known_types::timestamp::Timestamp;
use containerd_shim::protos::protobuf::{MessageDyn, MessageField};
use containerd_shim::protos::topics;
use containerd_shim::protos::types::task::ProcessInfo;
use containerd_shim::publisher::RemotePublisher;
use containerd_shim::{Config, ExitSignal, Flags, StartOpts, Task, TtrpcContext, TtrpcResult};
use litebox_broker_protocol::ProcessId;
use oci_spec::runtime::Spec;

use crate::broker::{self, Prepared};
use crate::error::{Error, Kind, Result};
use crate::events::{self, Outgoing};
use crate::hooks::Hooks;
use crate::spec::{self, ContainerPlan, ProcessSpec};
use crate::stdio::{self, Loggers, TaskIo};

/// How long `Shutdown` waits for queued events to be published.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the init process's exit waits for the container's other processes to end.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long an exit waits for the process's output to end before it is reported.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// How often a waiting `Wait` checks whether its caller went away, which nothing notifies.
const CALLER_POLL: Duration = Duration::from_secs(1);
/// containerd's status for an exit whose status is unknown.
const UNKNOWN_STATUS: u32 = 255;
/// The status that the `delete` command reports, as for `SIGKILL`.
const KILLED_STATUS: u32 = 128 + 9;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().expect("shim state mutex poisoned")
}

fn timestamp(time: SystemTime) -> MessageField<Timestamp> {
    let since_epoch = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    MessageField::some(Timestamp {
        seconds: i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(since_epoch.subsec_nanos()).unwrap_or_default(),
        ..Default::default()
    })
}

pub(crate) struct Shim {
    exit: Arc<ExitSignal>,
    namespace: String,
    id: String,
}

impl containerd_shim::Shim for Shim {
    type T = Service;

    fn new(_runtime_id: &str, args: &Flags, _config: &mut Config) -> Self {
        Self {
            exit: Arc::default(),
            namespace: args.namespace.clone(),
            id: args.id.clone(),
        }
    }

    fn start_shim(&mut self, opts: StartOpts) -> containerd_shim::Result<String> {
        // One daemon per container: the grouping is always the container ID.
        let grouping = opts.id.clone();
        let (_, address) = containerd_shim::spawn(opts, &grouping, Vec::new())?;
        containerd_shim::util::write_address(&address)?;
        Ok(address)
    }

    /// Runs once the daemon is gone, which took its runners (by their parent-death signal) and
    /// its mounts (with its mount namespace) along.
    fn delete_shim(&mut self) -> containerd_shim::Result<DeleteResponse> {
        // containerd logs the action's stderr.
        if let Err(error) = run_orphaned_poststop(&self.id) {
            eprintln!("cannot run the poststop hooks: {error}");
        }
        Ok(DeleteResponse {
            exit_status: KILLED_STATUS,
            exited_at: timestamp(SystemTime::now()),
            ..Default::default()
        })
    }

    fn wait(&mut self) {
        self.exit.wait();
    }

    fn create_task_service(&self, publisher: RemotePublisher) -> Service {
        let (events, outgoing) = mpsc::channel();
        let namespace = self.namespace.clone();
        let address = std::env::var("TTRPC_ADDRESS").unwrap_or_default();
        std::thread::Builder::new()
            .name("litebox-events".to_owned())
            .spawn(move || events::publish_events(publisher, &address, &namespace, &outgoing))
            .expect("the shim starts its event publisher");
        Service {
            inner: Arc::new(Inner {
                state: Mutex::default(),
                changed: Condvar::new(),
                events,
                exit: Arc::clone(&self.exit),
                namespace: self.namespace.clone(),
                loggers: Arc::default(),
            }),
        }
    }
}

/// Runs the `poststop` hooks of the container `id`, whose bundle is the working directory, if its
/// daemon died before it deleted the container, as runc's `delete --force` does.
fn run_orphaned_poststop(id: &str) -> Result<()> {
    // containerd runs this action after every daemon's exit, but only a daemon that died before
    // it deleted the container leaves the socket directory.
    match std::fs::remove_dir_all(broker::SOCKET_DIR) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        // containerd removes the bundle afterwards.
        _ => {}
    }
    let config = std::fs::read("config.json")
        .map_err(|error| Error::io("cannot read config.json", &error))?;
    let (plan, _) = ContainerPlan::from_spec(&spec::parse_json::<Spec>("config.json", &config)?)?;
    let bundle =
        std::env::current_dir().map_err(|error| Error::io("cannot find the bundle", &error))?;
    let hooks = Hooks::new(plan, id, &bundle.to_string_lossy(), None);
    let stderr = io::stderr()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|error| Error::io("cannot duplicate stderr", &error))?;
    let stderr = File::from(stderr);
    for hook in &hooks.stages.poststop {
        if let Err(error) = hooks.run(&stderr, std::slice::from_ref(hook), "stopped") {
            eprintln!("{error}");
        }
    }
    Ok(())
}

pub(crate) struct Service {
    inner: Arc<Inner>,
}

struct Inner {
    state: Mutex<State>,
    /// Notified whenever a task stops or is deleted.
    changed: Condvar,
    events: mpsc::Sender<Outgoing>,
    exit: Arc<ExitSignal>,
    /// containerd's namespace of the container.
    namespace: String,
    /// Reaped before the daemon exits.
    loggers: Arc<Loggers>,
}

#[derive(Default)]
struct State {
    /// Set by the first `Create`: the broker core is one per process, so a daemon hosts one
    /// container.
    used: bool,
    container: Option<Container>,
}

struct Container {
    id: String,
    bundle: String,
    broker: Arc<broker::Container>,
    hooks: Arc<Hooks>,
    init: Process,
    execs: HashMap<String, Process>,
    /// The serial of the next exec process.
    next_serial: u64,
}

/// The init process or an exec process.
struct Process {
    /// Distinguishes this process from a later one with the same ID; the init's is 0.
    serial: u64,
    io: TaskIO,
    /// The runner's host process ID, once containerd was told of the process.
    pid: u32,
    phase: Phase,
    /// The broker process, once there is one.
    broker_id: Option<ProcessId>,
    stdio: Option<Arc<TaskIo>>,
    /// Whether `CloseIO` closed stdin before the pumps existed.
    stdin_closed: bool,
}

enum Phase {
    Created(Pending),
    Starting,
    Running,
    Stopped(Exit),
}

enum Pending {
    /// The init process's runner waits behind its gate.
    Init(Prepared),
    Exec(ProcessSpec),
}

#[derive(Clone, Copy)]
struct Exit {
    status: u32,
    at: SystemTime,
}

impl State {
    fn container(&mut self, id: &str) -> Result<&mut Container> {
        self.container
            .as_mut()
            .filter(|container| container.id == id)
            .ok_or_else(|| Error::not_found(format!("container {id} not found")))
    }
}

impl Container {
    fn process(&mut self, exec_id: &str) -> Result<&mut Process> {
        if exec_id.is_empty() {
            return Ok(&mut self.init);
        }
        self.execs
            .get_mut(exec_id)
            .ok_or_else(|| Error::not_found(format!("exec process {exec_id} not found")))
    }
}

impl Process {
    fn new(serial: u64, io: TaskIO, pending: Pending) -> Self {
        Self {
            serial,
            io,
            pid: 0,
            phase: Phase::Created(pending),
            broker_id: None,
            stdio: None,
            stdin_closed: false,
        }
    }

    /// Takes the init process's gated runner if it has not started.
    fn take_gated(&mut self) -> Option<Prepared> {
        match std::mem::replace(&mut self.phase, Phase::Starting) {
            Phase::Created(Pending::Init(prepared)) => Some(prepared),
            phase => {
                self.phase = phase;
                None
            }
        }
    }
}

fn task_io(stdin: &str, stdout: &str, stderr: &str) -> TaskIO {
    TaskIO {
        stdin: stdin.to_owned(),
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
        ..Default::default()
    }
}

impl Inner {
    /// Queues `event`; callers hold the state lock at the transition it reports.
    fn publish(&self, topic: &'static str, event: Box<dyn MessageDyn>) {
        if self.events.send(Outgoing::Event(topic, event)).is_err() {
            log::error!("cannot publish {topic}: the publisher stopped");
        }
    }

    fn create(self: &Arc<Self>, request: &CreateTaskRequest) -> Result<CreateTaskResponse> {
        if request.terminal {
            return Err(Error::unimplemented("terminals are not supported"));
        }
        if !request.checkpoint.is_empty() {
            return Err(Error::unimplemented("checkpoints are not supported"));
        }
        {
            let mut state = lock(&self.state);
            if state.used {
                return Err(Error::new(
                    Kind::AlreadyExists,
                    "this shim already created its container",
                ));
            }
            state.used = true;
        }
        let bundle = Path::new(&request.bundle);
        if !bundle.is_absolute() {
            return Err(Error::invalid("the bundle path must be absolute"));
        }
        let config = std::fs::read(bundle.join("config.json"))
            .map_err(|error| Error::io("cannot read config.json", &error))?;
        let (plan, init_spec) =
            ContainerPlan::from_spec(&spec::parse_json::<Spec>("config.json", &config)?)?;
        let host = stdio::open(
            &request.stdin,
            &request.stdout,
            &request.stderr,
            &request.id,
            &self.namespace,
            &self.loggers,
        )?;
        let (broker, init) = broker::Container::new(&plan, bundle, &request.rootfs)?;
        let gated = broker
            .spawn_gated(init)
            .inspect_err(|_| broker.remove_socket_dir())?;
        let pid = gated.pid();
        let hooks = Arc::new(Hooks::new(plan, &request.id, &request.bundle, Some(pid)));
        // Once the runner exists, so that hooks can configure its network namespace, and before
        // the init process's files are looked up, which hooks may install.
        let prepared = match hooks.run(broker.log(), &hooks.stages.create, "creating") {
            Ok(()) => broker.prepare_gated(gated, &init_spec, host),
            Err(error) => {
                gated.discard();
                Err(error)
            }
        };
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                // As the OCI runtime spec requires, so that hooks can undo what earlier ones did.
                hooks.run_logged(broker.log(), &hooks.stages.poststop, "stopped");
                broker.remove_socket_dir();
                return Err(error);
            }
        };
        let (process, stdio) = (prepared.process_id(), prepared.io());
        let exited = prepared.exit_waiter();
        let io = task_io(&request.stdin, &request.stdout, &request.stderr);
        let mut init = Process::new(0, io.clone(), Pending::Init(prepared));
        init.pid = pid;
        init.broker_id = Some(process);
        init.stdio = Some(stdio);
        let mut state = lock(&self.state);
        state.container = Some(Container {
            id: request.id.clone(),
            bundle: request.bundle.clone(),
            broker,
            hooks,
            init,
            execs: HashMap::new(),
            next_serial: 1,
        });
        let event = TaskCreate {
            container_id: request.id.clone(),
            bundle: request.bundle.clone(),
            rootfs: request.rootfs.clone(),
            io: MessageField::some(io),
            pid,
            ..Default::default()
        };
        self.publish(topics::TASK_CREATE_EVENT_TOPIC, Box::new(event));
        drop(state);
        // A runner that dies before `Start` ends the init process; once started, it reports its
        // own exit.
        let (inner, id) = (Arc::clone(self), request.id.clone());
        let watched = std::thread::Builder::new()
            .name("litebox-gated".to_owned())
            .spawn(move || {
                if exited() {
                    let _ = inner.end_gated(&id);
                }
            });
        if let Err(error) = watched {
            log::warn!("cannot watch the init process's runner: {error}");
        }
        Ok(CreateTaskResponse {
            pid,
            ..Default::default()
        })
    }

    fn start(self: &Arc<Self>, request: &StartRequest) -> Result<StartResponse> {
        let exec_id = request.exec_id.as_str();
        let (broker, hooks, pending, io) = {
            let mut state = lock(&self.state);
            let container = state.container(&request.id)?;
            let init_running = matches!(container.init.phase, Phase::Running);
            let broker = Arc::clone(&container.broker);
            let hooks = Arc::clone(&container.hooks);
            let process = container.process(exec_id)?;
            if !exec_id.is_empty() && !init_running {
                return Err(Error::precondition("the container is not running"));
            }
            let pending = match std::mem::replace(&mut process.phase, Phase::Starting) {
                Phase::Created(pending) => pending,
                phase => {
                    process.phase = phase;
                    return Err(Error::precondition("the process is not created"));
                }
            };
            (broker, hooks, pending, process.io.clone())
        };
        let prepared = match pending {
            Pending::Init(prepared) => Ok(prepared),
            Pending::Exec(spec) => stdio::open(
                &io.stdin,
                &io.stdout,
                &io.stderr,
                exec_id,
                &self.namespace,
                &self.loggers,
            )
            .and_then(|host| {
                broker
                    .create_process()
                    .and_then(|process| broker.prepare(process, &spec, host))
            }),
        };
        let started = prepared.and_then(|prepared| {
            let (pid, process, stdio) = (prepared.pid(), prepared.process_id(), prepared.io());
            prepared
                .start(&broker)
                .map(|started| (started, pid, process, stdio))
        });

        let mut state = lock(&self.state);
        let container = state.container(&request.id);
        let (started, pid, broker_process, stdio) = match started {
            Ok(started) => started,
            Err(error) => {
                // No exit is published: the caller learns of the failure from this response. The
                // init process, which containerd knows from `Create`, stops with the unknown
                // status, which `Wait` and `Delete` report.
                if let Ok(process) = container.and_then(|container| container.process(exec_id)) {
                    process.phase = Phase::Stopped(Exit {
                        status: UNKNOWN_STATUS,
                        at: SystemTime::now(),
                    });
                }
                self.changed.notify_all();
                return Err(error);
            }
        };
        let container = container?;
        let container_id = container.id.clone();
        let process = container.process(exec_id)?;
        process.phase = Phase::Running;
        process.pid = pid;
        process.broker_id = Some(broker_process);
        // A `CloseIO` that came before the pumps existed.
        if process.stdin_closed {
            stdio.close_stdin();
        }
        process.stdio = Some(stdio);
        let (topic, event): (_, Box<dyn MessageDyn>) = match exec_id {
            "" => (
                topics::TASK_START_EVENT_TOPIC,
                Box::new(TaskStart {
                    container_id,
                    pid,
                    ..Default::default()
                }),
            ),
            _ => (
                topics::TASK_EXEC_STARTED_EVENT_TOPIC,
                Box::new(TaskExecStarted {
                    container_id,
                    exec_id: exec_id.to_owned(),
                    pid,
                    ..Default::default()
                }),
            ),
        };
        self.publish(topic, event);
        drop(state);
        // Served only now, so that no exit precedes the start.
        let inner = Arc::clone(self);
        let exited = exec_id.to_owned();
        if let Err(error) = started.serve(&broker, move |status| inner.exited(&exited, status)) {
            log::error!("{error}");
            self.exited(exec_id, UNKNOWN_STATUS);
        }
        if exec_id.is_empty() {
            hooks.run_logged(broker.log(), &hooks.stages.poststart, "running");
        }
        Ok(StartResponse {
            pid,
            ..Default::default()
        })
    }

    /// Reports the exit of a process whose runner was reaped, once its output ended.
    ///
    /// The init process's exit ends the container, as the end of a PID namespace does: every
    /// other runner is killed, and its exit is reported after theirs, unless they do not end
    /// within [`CLOSE_TIMEOUT`].
    fn exited(&self, exec_id: &str, status: u32) {
        let found = {
            let mut state = lock(&self.state);
            state.container.as_mut().and_then(|container| {
                let broker = Arc::clone(&container.broker);
                let stdio = container.process(exec_id).ok()?.stdio.clone();
                Some((broker, stdio))
            })
        };
        let Some((broker, stdio)) = found else {
            return;
        };
        if exec_id.is_empty() {
            let deadline = Instant::now() + CLOSE_TIMEOUT;
            broker.close();
            let reaped = broker.wait_reaped(CLOSE_TIMEOUT);
            let remaining = deadline.saturating_duration_since(Instant::now());
            let (state, waited) = self
                .changed
                .wait_timeout_while(lock(&self.state), remaining, |state| {
                    state.container.as_ref().is_some_and(|container| {
                        container
                            .execs
                            .values()
                            .any(|exec| matches!(exec.phase, Phase::Starting | Phase::Running))
                    })
                })
                .expect("shim state mutex poisoned");
            drop(state);
            if !reaped || waited.timed_out() {
                log::warn!("processes of the container did not end in time");
            }
        }
        if let Some(stdio) = stdio {
            stdio.finish(DRAIN_TIMEOUT);
        }
        self.commit_exit(exec_id, status);
    }

    /// Stops a running (or, for the init process, starting) process with `status` and publishes
    /// its exit.
    fn commit_exit(&self, exec_id: &str, status: u32) {
        let mut state = lock(&self.state);
        if let Some(container) = state.container.as_mut() {
            let container_id = container.id.clone();
            if let Ok(process) = container.process(exec_id)
                && matches!(process.phase, Phase::Running | Phase::Starting)
            {
                let at = SystemTime::now();
                process.phase = Phase::Stopped(Exit { status, at });
                let event = TaskExit {
                    id: if exec_id.is_empty() {
                        container_id.clone()
                    } else {
                        exec_id.to_owned()
                    },
                    container_id,
                    pid: process.pid,
                    exit_status: status,
                    exited_at: timestamp(at),
                    ..Default::default()
                };
                self.publish(topics::TASK_EXIT_EVENT_TOPIC, Box::new(event));
            }
        }
        drop(state);
        self.changed.notify_all();
    }

    /// Ends the init process of the container `id` if it has not started, with its runner's
    /// status.
    fn end_gated(&self, id: &str) -> Result<()> {
        // Taken under the state lock, so that a concurrent `Start` either finds it gone or
        // already took it.
        let gated = lock(&self.state).container(id)?.init.take_gated();
        if let Some(prepared) = gated {
            self.commit_exit("", prepared.discard());
        }
        Ok(())
    }

    fn exec(&self, request: &ExecProcessRequest) -> Result<()> {
        if request.exec_id.is_empty() {
            return Err(Error::invalid("the exec ID is empty"));
        }
        if request.terminal {
            return Err(Error::unimplemented("terminals are not supported"));
        }
        let spec = request
            .spec
            .as_ref()
            .ok_or_else(|| Error::invalid("the exec process has no spec"))?;
        let spec = ProcessSpec::from_oci(&spec::parse_json::<oci_spec::runtime::Process>(
            "exec process spec",
            &spec.value,
        )?)?;
        let mut state = lock(&self.state);
        let container = state.container(&request.id)?;
        if !matches!(container.init.phase, Phase::Running) {
            return Err(Error::precondition("the container is not running"));
        }
        if container.execs.contains_key(&request.exec_id) {
            return Err(Error::new(
                Kind::AlreadyExists,
                format!("exec process {} already exists", request.exec_id),
            ));
        }
        let io = task_io(&request.stdin, &request.stdout, &request.stderr);
        let serial = container.next_serial;
        container.next_serial += 1;
        container.execs.insert(
            request.exec_id.clone(),
            Process::new(serial, io, Pending::Exec(spec)),
        );
        let event = TaskExecAdded {
            container_id: request.id.clone(),
            exec_id: request.exec_id.clone(),
            ..Default::default()
        };
        self.publish(topics::TASK_EXEC_ADDED_EVENT_TOPIC, Box::new(event));
        Ok(())
    }

    fn kill(&self, request: &KillRequest) -> Result<()> {
        let signal = spec::kill_signal(request.signal)?;
        let (broker, process) = {
            let mut state = lock(&self.state);
            let container = state.container(&request.id)?;
            let broker = Arc::clone(&container.broker);
            let process = container.process(&request.exec_id)?;
            // Nothing runs behind the gate yet: any signal ends it. Taken under this lock, so
            // that a concurrent `Start` either finds it gone or already took it.
            if signal != 0
                && let Some(prepared) = process.take_gated()
            {
                drop(state);
                let status = prepared.discard();
                self.commit_exit("", status);
                return Ok(());
            }
            match &process.phase {
                Phase::Stopped(_) => {
                    return Err(Error::not_found("the process has already exited"));
                }
                Phase::Starting => return Err(Error::precondition("the process is starting")),
                Phase::Created(Pending::Exec(_)) => {
                    return Err(Error::precondition("the exec process has not started"));
                }
                Phase::Created(Pending::Init(_)) => return Ok(()),
                Phase::Running => (
                    broker,
                    process.broker_id.ok_or_else(|| {
                        Error::internal("a running process has no broker process")
                    })?,
                ),
            }
        };
        broker.signal(process, signal, request.all && request.exec_id.is_empty())
    }

    fn delete(&self, request: &DeleteRequest) -> Result<DeleteResponse> {
        let response = |pid, exit: Exit| DeleteResponse {
            pid,
            exit_status: exit.status,
            exited_at: timestamp(exit.at),
            ..Default::default()
        };
        if !request.exec_id.is_empty() {
            let mut state = lock(&self.state);
            let container = state.container(&request.id)?;
            let process = container.process(&request.exec_id)?;
            let exit = match &process.phase {
                Phase::Stopped(exit) => *exit,
                Phase::Created(_) => Exit {
                    status: 0,
                    at: SystemTime::now(),
                },
                Phase::Starting | Phase::Running => {
                    return Err(Error::precondition("the exec process is running"));
                }
            };
            let pid = process.pid;
            container.execs.remove(&request.exec_id);
            drop(state);
            self.changed.notify_all();
            return Ok(response(pid, exit));
        }
        // Deleting a container that never started ends it, with its exit.
        self.end_gated(&request.id)?;
        let mut state = lock(&self.state);
        let container = state.container(&request.id)?;
        let Phase::Stopped(exit) = container.init.phase else {
            return Err(Error::precondition("the container is running"));
        };
        let Some(container) = state.container.take() else {
            return Err(Error::not_found("the container is gone"));
        };
        // Runners that outlived the init process's exit, and pumps that a surviving child kept.
        container.broker.close();
        for process in std::iter::once(&container.init).chain(container.execs.values()) {
            if let Some(stdio) = &process.stdio {
                stdio.abort();
            }
        }
        container.broker.remove_socket_dir();
        // `id` names an exec process, so it stays empty for the init process, as in runc's shims.
        let event = TaskDelete {
            container_id: container.id.clone(),
            pid: container.init.pid,
            exit_status: exit.status,
            exited_at: timestamp(exit.at),
            ..Default::default()
        };
        self.publish(topics::TASK_DELETE_EVENT_TOPIC, Box::new(event));
        drop(state);
        self.changed.notify_all();
        let hooks = &container.hooks;
        hooks.run_logged(container.broker.log(), &hooks.stages.poststop, "stopped");
        // As containerd's runc shim does, so that no logging binary outlives the container.
        if !self.loggers.wait_reaped() {
            log::warn!("a logging binary was not reaped in time");
        }
        Ok(response(container.init.pid, exit))
    }

    fn state(&self, request: &StateRequest) -> Result<StateResponse> {
        let mut state = lock(&self.state);
        let container = state.container(&request.id)?;
        let bundle = container.bundle.clone();
        let process = container.process(&request.exec_id)?;
        let (status, exit) = match &process.phase {
            Phase::Created(_) | Phase::Starting => (Status::CREATED, None),
            Phase::Running => (Status::RUNNING, None),
            Phase::Stopped(exit) => (Status::STOPPED, Some(*exit)),
        };
        Ok(StateResponse {
            id: request.id.clone(),
            bundle,
            pid: process.pid,
            status: status.into(),
            stdin: process.io.stdin.clone(),
            stdout: process.io.stdout.clone(),
            stderr: process.io.stderr.clone(),
            exit_status: exit.map_or(0, |exit| exit.status),
            exited_at: exit.map_or_else(MessageField::none, |exit| timestamp(exit.at)),
            exec_id: request.exec_id.clone(),
            ..Default::default()
        })
    }

    /// Waits until the process stops, until `deadline`, or until `caller_gone`, which is polled
    /// every [`CALLER_POLL`]. A process deleted meanwhile is not found, even if another one took
    /// its ID.
    fn wait(
        &self,
        request: &WaitRequest,
        deadline: Option<Instant>,
        caller_gone: impl Fn() -> bool,
    ) -> Result<WaitResponse> {
        let mut state = lock(&self.state);
        let serial = state
            .container(&request.id)?
            .process(&request.exec_id)?
            .serial;
        loop {
            let process = state.container(&request.id)?.process(&request.exec_id)?;
            if process.serial != serial {
                return Err(Error::not_found("the process was deleted"));
            }
            if let Phase::Stopped(exit) = process.phase {
                return Ok(WaitResponse {
                    exit_status: exit.status,
                    exited_at: timestamp(exit.at),
                    ..Default::default()
                });
            }
            let mut timeout = CALLER_POLL;
            if let Some(deadline) = deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(Error::new(
                        Kind::DeadlineExceeded,
                        "the process did not stop before the deadline",
                    ));
                }
                timeout = timeout.min(remaining);
            }
            if caller_gone() {
                return Err(Error::new(Kind::Cancelled, "the caller went away"));
            }
            state = self
                .changed
                .wait_timeout(state, timeout)
                .expect("shim state mutex poisoned")
                .0;
        }
    }

    fn pids(&self, request: &PidsRequest) -> Result<PidsResponse> {
        let broker = Arc::clone(&lock(&self.state).container(&request.id)?.broker);
        let processes = broker
            .pids()
            .into_iter()
            .map(|pid| ProcessInfo {
                pid,
                ..Default::default()
            })
            .collect();
        Ok(PidsResponse {
            processes,
            ..Default::default()
        })
    }

    fn close_io(&self, request: &CloseIORequest) -> Result<()> {
        if !request.stdin {
            return Ok(());
        }
        let mut state = lock(&self.state);
        let process = state.container(&request.id)?.process(&request.exec_id)?;
        match &process.stdio {
            Some(stdio) => stdio.close_stdin(),
            // Applied once the exec process starts.
            None => process.stdin_closed = true,
        }
        Ok(())
    }

    fn shutdown(&self) {
        if lock(&self.state).container.is_some() {
            return;
        }
        // Such as those of a container whose `Create` failed.
        if !self.loggers.wait_reaped() {
            log::warn!("exiting with a logging binary not yet reaped");
        }
        let (done, flushed) = mpsc::sync_channel(1);
        if self.events.send(Outgoing::Flush(done)).is_err()
            || flushed.recv_timeout(FLUSH_TIMEOUT).is_err()
        {
            log::warn!("exiting with events not yet published");
        }
        self.exit.signal();
    }
}

impl Task for Service {
    fn state(&self, _ctx: &TtrpcContext, request: StateRequest) -> TtrpcResult<StateResponse> {
        Ok(self.inner.state(&request)?)
    }

    fn create(
        &self,
        _ctx: &TtrpcContext,
        request: CreateTaskRequest,
    ) -> TtrpcResult<CreateTaskResponse> {
        log::info!("create {}", request.id);
        Ok(self.inner.create(&request)?)
    }

    fn start(&self, _ctx: &TtrpcContext, request: StartRequest) -> TtrpcResult<StartResponse> {
        log::info!("start {} {}", request.id, request.exec_id);
        Ok(self.inner.start(&request)?)
    }

    fn delete(&self, _ctx: &TtrpcContext, request: DeleteRequest) -> TtrpcResult<DeleteResponse> {
        log::info!("delete {} {}", request.id, request.exec_id);
        Ok(self.inner.delete(&request)?)
    }

    fn pids(&self, _ctx: &TtrpcContext, request: PidsRequest) -> TtrpcResult<PidsResponse> {
        Ok(self.inner.pids(&request)?)
    }

    fn kill(&self, _ctx: &TtrpcContext, request: KillRequest) -> TtrpcResult<Empty> {
        log::info!("kill {} {} {}", request.id, request.exec_id, request.signal);
        self.inner.kill(&request)?;
        Ok(Empty::new())
    }

    fn exec(&self, _ctx: &TtrpcContext, request: ExecProcessRequest) -> TtrpcResult<Empty> {
        log::info!("exec {} {}", request.id, request.exec_id);
        self.inner.exec(&request)?;
        Ok(Empty::new())
    }

    fn close_io(&self, _ctx: &TtrpcContext, request: CloseIORequest) -> TtrpcResult<Empty> {
        self.inner.close_io(&request)?;
        Ok(Empty::new())
    }

    fn wait(&self, ctx: &TtrpcContext, request: WaitRequest) -> TtrpcResult<WaitResponse> {
        // No deadline is 0, and one too far to represent is none either.
        let deadline = u64::try_from(ctx.timeout_nano)
            .ok()
            .filter(|nanos| *nanos > 0)
            .and_then(|nanos| Instant::now().checked_add(Duration::from_nanos(nanos)));
        // The server disconnects `cancel_rx` once it stops reading the caller's connection.
        let caller_gone = || {
            ctx.cancel_rx
                .try_recv()
                .is_err_and(|error| error.is_disconnected())
        };
        Ok(self.inner.wait(&request, deadline, caller_gone)?)
    }

    fn connect(
        &self,
        _ctx: &TtrpcContext,
        request: ConnectRequest,
    ) -> TtrpcResult<ConnectResponse> {
        let task_pid = lock(&self.inner.state)
            .container(&request.id)
            .map_or(0, |container| container.init.pid);
        Ok(ConnectResponse {
            shim_pid: std::process::id(),
            task_pid,
            ..Default::default()
        })
    }

    fn shutdown(&self, _ctx: &TtrpcContext, _request: ShutdownRequest) -> TtrpcResult<Empty> {
        self.inner.shutdown();
        Ok(Empty::new())
    }

    // The generated defaults answer `NOT_FOUND`, which containerd takes for a missing process.

    fn pause(&self, _ctx: &TtrpcContext, _request: PauseRequest) -> TtrpcResult<Empty> {
        Err(Error::unimplemented("pausing is not supported").into())
    }

    fn resume(&self, _ctx: &TtrpcContext, _request: ResumeRequest) -> TtrpcResult<Empty> {
        Err(Error::unimplemented("resuming is not supported").into())
    }

    fn checkpoint(
        &self,
        _ctx: &TtrpcContext,
        _request: CheckpointTaskRequest,
    ) -> TtrpcResult<Empty> {
        Err(Error::unimplemented("checkpoints are not supported").into())
    }

    fn update(&self, _ctx: &TtrpcContext, _request: UpdateTaskRequest) -> TtrpcResult<Empty> {
        Err(Error::unimplemented("updating resources is not supported").into())
    }

    fn stats(&self, _ctx: &TtrpcContext, _request: StatsRequest) -> TtrpcResult<StatsResponse> {
        Err(Error::unimplemented("statistics are not supported").into())
    }

    fn resize_pty(&self, _ctx: &TtrpcContext, _request: ResizePtyRequest) -> TtrpcResult<Empty> {
        Err(Error::unimplemented("terminals are not supported").into())
    }
}
