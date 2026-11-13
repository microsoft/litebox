// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The shim's `containerd.task.v2.Task` service. A daemon serves one container, whose processes
//! the guest service runs: the init process (exec ID "") and exec processes, which the guest
//! service knows by IDs the shim never reuses. Every process's pid is the broker's host pid. Each
//! event is queued at the change it reports, under the state's lock, or for `TaskDelete` under the
//! lifecycle's, so that events leave in order.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, mpsc};
use std::time::{Duration, SystemTime};

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
use containerd_shim::protos::ttrpc::{Code, context};
use containerd_shim::protos::types::task::ProcessInfo;
use containerd_shim::publisher::RemotePublisher;
use containerd_shim::{Config, ExitSignal, Flags, StartOpts, Task, TtrpcContext, TtrpcResult};
use litebox_guest_service_protocol::guest_service::{
    CreateContainerRequest, Empty as GuestEmpty, ExecProcessRequest as GuestExecRequest,
    Process as GuestProcess, ReleaseProcessRequest, SignalProcessRequest, TtyWinResizeRequest,
    WaitProcessRequest,
};
use litebox_guest_service_protocol::guest_service_ttrpc::GuestServiceClient;
use oci_spec::runtime::Spec;

use crate::hooks::Hooks;
use crate::rootfs::RootFs;
use crate::sandbox::{Broker, RootMount, StateDir};
use crate::stdio::{Host, Logger, Pumps};
use crate::{Result, error, internal, invalid, spec, unsupported};

/// How long an exit waits for the process's output to reach its host ends, which a child that
/// holds it can delay; how long the output may then stay without data, or last after an exec's
/// `Delete`, before the process is released; and how long the init's exit waits for the exec
/// processes' exits.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the guest service may take to answer a call made under the shim's locks, which it
/// must answer within it: one that does not is taken for dead.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
/// containerd's status for an unknown exit.
const UNKNOWN_STATUS: u32 = 255;
const KILLED_STATUS: u32 = 128 + 9;
/// `SIGSTOP` as the guest numbers signals (Linux's), whatever the host's number.
const STOP_SIGNAL: u32 = 19;

fn timestamp(at: SystemTime) -> MessageField<Timestamp> {
    let since_epoch = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    MessageField::some(Timestamp {
        seconds: i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(since_epoch.subsec_nanos()).unwrap_or_default(),
        ..Default::default()
    })
}

fn precondition(message: &str) -> crate::ttrpc::Error {
    error(Code::FAILED_PRECONDITION, message)
}

/// The guest service's failure while doing `what`, with its status's code and message (truncated,
/// so that the answer stays within ttrpc's limit).
fn guest_error(what: &str) -> impl FnOnce(crate::ttrpc::Error) -> crate::ttrpc::Error + '_ {
    move |failure| match failure {
        crate::ttrpc::Error::RpcStatus(status) => {
            let message = crate::truncated(&status.message).escape_debug();
            error(status.code(), format!("{what}: {message}"))
        }
        failure => internal(format!("{what}: {failure}")),
    }
}

/// A deadline of `timeout`.
fn deadline(timeout: Duration) -> context::Context {
    context::with_timeout(i64::try_from(timeout.as_nanos()).unwrap_or(i64::MAX))
}

/// Stops `broker` if `result` failed without the guest service's answer (a timeout, or a failed
/// connection): its processes then exit through their watchers.
fn stop_unless_answered<T>(broker: &Broker, result: Result<T>) -> Result<T> {
    if let Err(failure) = &result
        && !matches!(failure, crate::ttrpc::Error::RpcStatus(_))
    {
        log::error!(
            "a call failed without the guest service's answer: {failure}; stopping the broker"
        );
        broker.stop();
    }
    result
}

/// Sets `HOME` from the guest's `/etc/passwd` unless `process` sets it, as runc does.
fn set_home(process: &mut GuestProcess, passwd: &[u8], uid: u32) {
    if !process.env.iter().any(|entry| entry.starts_with("HOME=")) {
        process
            .env
            .push(format!("HOME={}", crate::rootfs::home(passwd, uid)));
    }
}

pub struct Shim {
    exit: Arc<ExitSignal>,
    namespace: String,
    id: String,
    bundle: String,
}

impl containerd_shim::Shim for Shim {
    type T = Service;

    fn new(_runtime_id: &str, args: &Flags, _config: &mut Config) -> Self {
        Self {
            exit: Arc::default(),
            namespace: args.namespace.clone(),
            id: args.id.clone(),
            bundle: args.bundle.clone(),
        }
    }

    fn start_shim(&mut self, opts: StartOpts) -> containerd_shim::Result<String> {
        let grouping = opts.id.clone();
        let (_, address) = containerd_shim::spawn(opts, &grouping, Vec::new())?;
        containerd_shim::util::write_address(&address)?;
        Ok(address)
    }

    /// containerd's cleanup after the daemon's death, whose guardian then killed the broker. As
    /// runc's shim and `delete --force`, it unmounts the root file system (once the daemon's
    /// mounters are gone: see [`RootMount`]) and runs the `poststop` hooks of a container whose
    /// `Create` began, after removing its state; a live daemon's locked state is left to its own
    /// cleanup.
    fn delete_shim(&mut self) -> containerd_shim::Result<DeleteResponse> {
        let mut state_dir = StateDir::new(&self.namespace, &self.id);
        if state_dir.try_lock() {
            // containerd logs the action's stderr.
            if let Err(error) = RootMount::unmount_leftovers(Path::new(&self.bundle)) {
                eprintln!("{error:?}");
            }
            state_dir.remove();
            match Spec::load(Path::new(&self.bundle).join("config.json")) {
                Ok(spec) => {
                    let hooks = Hooks::new(&spec, &self.id, &self.bundle, 0);
                    hooks.poststop(|error| eprintln!("{error}"));
                }
                Err(error) => eprintln!("cannot run the poststop hooks: {:?}", error.to_string()),
            }
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
        std::thread::spawn(move || publish_events(&publisher, &namespace, &outgoing));
        Service(Arc::new(Inner {
            lifecycle: Mutex::default(),
            state: Mutex::default(),
            changed: Condvar::new(),
            events,
            exit: Arc::clone(&self.exit),
            namespace: self.namespace.clone(),
        }))
    }
}

enum Outgoing {
    Event(&'static str, Box<dyn MessageDyn>),
    /// Acknowledged once the events before it left.
    Flush(mpsc::SyncSender<()>),
}

/// Publishes the events in order, each with a short retry.
fn publish_events(
    publisher: &RemotePublisher,
    namespace: &str,
    outgoing: &mpsc::Receiver<Outgoing>,
) {
    for message in outgoing {
        let (topic, event) = match message {
            Outgoing::Event(topic, event) => (topic, event),
            Outgoing::Flush(done) => {
                let _ = done.send(());
                continue;
            }
        };
        for attempt in 1..=3 {
            let timeout = context::with_timeout(5_000_000_000);
            match publisher.publish(timeout, topic, namespace, event.clone_box()) {
                Ok(()) => break,
                Err(error) => {
                    log::warn!("cannot publish {topic} (attempt {attempt}): {error}");
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }
    }
}

pub struct Service(Arc<Inner>);

struct Inner {
    /// Held by `Create`, `Start`, `Delete` and `Shutdown`, through their hooks and logging
    /// programs. A hook that starts, deletes or shuts down its own task waits for itself, as it
    /// would with runc.
    lifecycle: Mutex<()>,
    /// Held only briefly: never across a hook, a logging program's readiness or its reaping, so
    /// that they can call the shim.
    state: Mutex<Option<Container>>,
    /// Notified when a process stops or is deleted.
    changed: Condvar,
    events: mpsc::Sender<Outgoing>,
    exit: Arc<ExitSignal>,
    namespace: String,
}

struct Container {
    id: String,
    bundle: String,
    broker: Broker,
    state_dir: StateDir,
    hooks: Arc<Hooks>,
    client: Arc<GuestServiceClient>,
    /// The guest's `/etc/passwd`, for `HOME`.
    passwd: Vec<u8>,
    processes: HashMap<String, Process>,
    /// The last ID given to an exec process in the guest service.
    last_guest_id: u64,
}

struct Process {
    /// Its ID in the guest service, never reused, unlike containerd's exec IDs.
    guest_id: String,
    io: TaskIO,
    /// What an exec process runs, until it starts.
    spec: Option<GuestProcess>,
    started: bool,
    /// What a `Wait` that found the process holds on to.
    exit: Arc<OnceLock<Exit>>,
    /// Set by `CloseIO`.
    closing: Arc<AtomicBool>,
    /// Set by an exec process's `Delete`, which ends its watcher's wait for its output and its
    /// output's blocked writes to the host ends.
    deleted: Arc<AtomicBool>,
    /// The streams' threads, until the exit's watcher takes them.
    pumps: Option<Pumps>,
    /// Its `binary://` logging program, reaped when it is deleted.
    logger: Option<Logger>,
}

#[derive(Clone, Copy)]
struct Exit {
    status: u32,
    at: SystemTime,
}

impl Container {
    fn process(&mut self, exec_id: &str) -> Result<&mut Process> {
        self.processes
            .get_mut(exec_id)
            .ok_or_else(|| error(Code::NOT_FOUND, format!("process {exec_id:?} not found")))
    }
}

fn container<'a>(state: &'a mut Option<Container>, id: &str) -> Result<&'a mut Container> {
    state
        .as_mut()
        .filter(|container| container.id == id)
        .ok_or_else(|| error(Code::NOT_FOUND, format!("container {id} not found")))
}

fn task_io(stdin: &str, stdout: &str, stderr: &str, terminal: bool) -> TaskIO {
    TaskIO {
        stdin: stdin.to_owned(),
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
        terminal,
        ..Default::default()
    }
}

impl Process {
    fn new(guest_id: String, io: TaskIO, spec: Option<GuestProcess>) -> Self {
        Self {
            guest_id,
            io,
            spec,
            started: false,
            exit: Arc::default(),
            closing: Arc::default(),
            deleted: Arc::default(),
            pumps: None,
            logger: None,
        }
    }
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, Option<Container>> {
        self.state.lock().expect("the state's lock is poisoned")
    }

    fn lock_lifecycle(&self) -> MutexGuard<'_, ()> {
        self.lifecycle
            .lock()
            .expect("the lifecycle's lock is poisoned")
    }

    fn publish(&self, topic: &'static str, event: Box<dyn MessageDyn>) {
        if self.events.send(Outgoing::Event(topic, event)).is_err() {
            log::error!("cannot publish {topic}: the publisher stopped");
        }
    }

    /// Stops the process `exec_id` of `container` with `status`, publishing its exit if `publish`.
    fn stop(&self, container: &mut Container, exec_id: &str, status: u32, publish: bool) {
        let (id, pid) = (container.id.clone(), container.broker.pid());
        let Some(process) = container.processes.get_mut(exec_id) else {
            return;
        };
        let at = SystemTime::now();
        if process.exit.set(Exit { status, at }).is_err() {
            return;
        }
        if let Some(pumps) = &process.pumps {
            pumps.stop();
        }
        if publish {
            let event = TaskExit {
                id: if exec_id.is_empty() {
                    id.clone()
                } else {
                    exec_id.to_owned()
                },
                container_id: id,
                pid,
                exit_status: status,
                exited_at: timestamp(at),
                ..Default::default()
            };
            self.publish(topics::TASK_EXIT_EVENT_TOPIC, Box::new(event));
        }
        self.changed.notify_all();
    }

    fn create(self: &Arc<Self>, request: &CreateTaskRequest) -> Result<CreateTaskResponse> {
        let _lifecycle = self.lock_lifecycle();
        if self.lock().is_some() {
            return Err(error(
                Code::ALREADY_EXISTS,
                "this shim created its container already",
            ));
        }
        if !request.checkpoint.is_empty() || !request.parent_checkpoint.is_empty() {
            return Err(unsupported("checkpoints are not supported"));
        }
        let bundle = Path::new(&request.bundle);
        let spec = Spec::load(bundle.join("config.json"))
            .map_err(|failure| invalid(format!("invalid config.json: {failure}")))?;
        let mut plan = spec::plan(&spec)?;
        if plan.process.terminal != request.terminal {
            return Err(invalid("the request and the spec disagree on the terminal"));
        }
        let guest_service = crate::sandbox::guest_service();
        if !guest_service.is_file() {
            return Err(precondition(&format!(
                "the guest service {} does not exist: install a static litebox-guest-service next \
                 to the shim, or set LITEBOX_GUEST_SERVICE",
                guest_service.display()
            )));
        }
        let io = task_io(
            &request.stdin,
            &request.stdout,
            &request.stderr,
            request.terminal,
        );
        let host = Host::open(&io, &request.id, &self.namespace)?;
        let mut state_dir = StateDir::new(&self.namespace, &request.id);
        state_dir.create()?;
        let built = (|| {
            let mounted = (!request.rootfs.is_empty())
                .then(|| RootMount::new(bundle, &request.rootfs))
                .transpose()?;
            // TODO: let the broker serve the mounted root, not an archive of it (kept for Windows).
            let image = mounted
                .as_ref()
                .map_or_else(|| bundle.join(&plan.root), |root| root.path().to_owned());
            let fs = RootFs::build(&image, &guest_service, &plan.binds, &plan.process.cwd)?;
            // The working directory as runc resolves it in the image.
            plan.process.cwd.clone_from(&fs.cwd);
            set_home(&mut plan.process, &fs.passwd, plan.user.uid.into());
            fs.write_archive(&state_dir.archive(), plan.user)?;
            drop(mounted);
            let inner = Arc::clone(self);
            let exited = move || inner.broker_exited();
            let broker = Broker::spawn(&state_dir, &fs.binds, &plan.egress, plan.user, exited)?;
            Ok::<_, crate::ttrpc::Error>((fs, broker))
        })();
        let (fs, broker) = built.inspect_err(|_| state_dir.remove())?;
        // Once the broker runs, so that the hooks' state has its pid.
        let hooks = Hooks::new(&spec, &request.id, &request.bundle, broker.pid());
        let created = hooks.create().and_then(|()| broker.connect(&state_dir));
        let created = created.and_then(|client| {
            client
                .create_container(
                    deadline(CONTROL_TIMEOUT),
                    &CreateContainerRequest {
                        process: MessageField::some(plan.process),
                        ..Default::default()
                    },
                )
                .map_err(guest_error("cannot create the container"))?;
            Ok(client)
        });
        let client = match created {
            Ok(client) => Arc::new(client),
            Err(failure) => {
                broker.stop();
                state_dir.clear();
                drop(host);
                // As runc does when `create` fails.
                hooks.poststop(|error| log::warn!("{error}"));
                state_dir.remove();
                return Err(failure);
            }
        };
        let pid = broker.pid();
        let mut init = Process::new(String::new(), io.clone(), None);
        init.pumps = Some(Pumps::start(
            &client,
            "",
            host.files,
            request.terminal,
            Arc::clone(&init.closing),
            Arc::clone(&init.deleted),
        ));
        init.logger = host.logger;
        let mut state = self.lock();
        *state = Some(Container {
            id: request.id.clone(),
            bundle: request.bundle.clone(),
            broker,
            state_dir,
            hooks: Arc::new(hooks),
            client,
            passwd: fs.passwd,
            processes: HashMap::from([(String::new(), init)]),
            last_guest_id: 0,
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
        // The broker may have exited before the container was stored.
        self.broker_exited();
        Ok(CreateTaskResponse {
            pid,
            ..Default::default()
        })
    }

    /// Once the container's broker exited, stops its processes that have not started, as a
    /// failed `Start` does.
    fn broker_exited(&self) {
        let mut state = self.lock();
        let Some(container) = state
            .as_mut()
            .filter(|container| container.broker.wait(Duration::ZERO))
        else {
            return;
        };
        let created: Vec<String> = container
            .processes
            .iter()
            .filter(|(_, process)| !process.started)
            .map(|(exec_id, _)| exec_id.clone())
            .collect();
        for exec_id in created {
            self.stop(container, &exec_id, UNKNOWN_STATUS, exec_id.is_empty());
        }
    }

    fn start(self: &Arc<Self>, request: &StartRequest) -> Result<StartResponse> {
        let exec_id = request.exec_id.as_str();
        let _lifecycle = self.lock_lifecycle();
        let startable = |state: &mut Option<Container>| {
            let container = container(state, &request.id)?;
            let init_running = container
                .process("")
                .is_ok_and(|init| init.started && init.exit.get().is_none());
            let process = container.process(exec_id)?;
            if process.started || process.exit.get().is_some() {
                return Err(precondition("the process is not created"));
            }
            if !exec_id.is_empty() && !init_running {
                return Err(precondition("the container is not running"));
            }
            Ok(process.io.clone())
        };
        let mut state = self.lock();
        let io = startable(&mut state)?;
        // An exec's host ends, opened without the state's lock: its logging program may call the
        // shim before it is ready. The lifecycle's lock keeps the container and the process.
        let mut files = None;
        if !exec_id.is_empty() {
            drop(state);
            let host = Host::open(&io, &request.id, &self.namespace);
            state = self.lock();
            files = Some(host.and_then(|host| {
                // Reaped at its `Delete`, even if it does not start.
                container(&mut state, &request.id)?.process(exec_id)?.logger = host.logger;
                startable(&mut state)?;
                Ok(host.files)
            }));
        }
        let container = container(&mut state, &request.id)?;
        let (pid, client) = (container.broker.pid(), Arc::clone(&container.client));
        let hooks = Arc::clone(&container.hooks);
        // Borrowed apart from the broker, which stops if the guest service does not answer.
        container.process(exec_id)?;
        let broker = &container.broker;
        let process = container.processes.get_mut(exec_id).expect("found above");
        let guest_id = process.guest_id.clone();
        let started = match files {
            None => client
                .start_container(deadline(CONTROL_TIMEOUT), &GuestEmpty::new())
                .map(drop)
                .map_err(guest_error("cannot start the container")),
            Some(files) => files.and_then(|files| {
                let guest = process
                    .spec
                    .take()
                    .expect("a created exec process has a spec");
                let terminal = guest.terminal;
                let exec = GuestExecRequest {
                    exec_id: guest_id.clone(),
                    process: MessageField::some(guest),
                    ..Default::default()
                };
                let execed = client.exec_process(deadline(CONTROL_TIMEOUT), &exec);
                stop_unless_answered(broker, execed)
                    .map_err(guest_error("cannot start the process"))?;
                let closing = Arc::clone(&process.closing);
                let deleted = Arc::clone(&process.deleted);
                process.pumps = Some(Pumps::start(
                    &client, &guest_id, files, terminal, closing, deleted,
                ));
                Ok(())
            }),
        };
        if let Err(failure) = started {
            // containerd would take `NOT_FOUND` for a missing process, not a missing program.
            let (failure, status) = match failure {
                crate::ttrpc::Error::RpcStatus(status) if status.code() == Code::NOT_FOUND => {
                    (invalid(status.message), 127)
                }
                failure => (failure, UNKNOWN_STATUS),
            };
            // As with runc, an init process that cannot start exits, and the container with it;
            // an exec process is just gone.
            if exec_id.is_empty() {
                container.broker.stop();
                self.stop(container, exec_id, status, true);
            } else {
                self.stop(container, exec_id, UNKNOWN_STATUS, false);
            }
            return Err(failure);
        }
        let process = container.process(exec_id)?;
        process.started = true;
        let pumps = process.pumps.take().expect("a started process has pumps");
        let deleted = Arc::clone(&process.deleted);
        let (inner, watched) = (Arc::clone(self), exec_id.to_owned());
        std::thread::spawn(move || inner.watch(&client, &watched, guest_id, &pumps, &deleted));
        let event: (_, Box<dyn MessageDyn>) = if exec_id.is_empty() {
            let event = TaskStart {
                container_id: request.id.clone(),
                pid,
                ..Default::default()
            };
            (topics::TASK_START_EVENT_TOPIC, Box::new(event))
        } else {
            let event = TaskExecStarted {
                container_id: request.id.clone(),
                exec_id: exec_id.to_owned(),
                pid,
                ..Default::default()
            };
            (topics::TASK_EXEC_STARTED_EVENT_TOPIC, Box::new(event))
        };
        self.publish(event.0, event.1);
        drop(state);
        if exec_id.is_empty() {
            hooks.poststart();
        }
        Ok(StartResponse {
            pid,
            ..Default::default()
        })
    }

    /// Waits for the exit of the process `exec_id`, `guest_id` in the guest service, and publishes
    /// it once its output reached its host ends, or after [`DRAIN_TIMEOUT`]; the init's comes
    /// last. Then waits for the output's copiers to end (see [`Pumps::finish`]), or for the
    /// process's `Delete` (`deleted`), releases the process in the guest service, which ends what
    /// is left of its output, and stops the input. If the guest service fails to answer, the
    /// broker stops: before the exit is published if it fails to report it; not if the release
    /// fails because the container was deleted.
    fn watch(
        &self,
        client: &Arc<GuestServiceClient>,
        exec_id: &str,
        guest_id: String,
        pumps: &Pumps,
        deleted: &AtomicBool,
    ) {
        let request = WaitProcessRequest {
            exec_id: guest_id.clone(),
            ..Default::default()
        };
        let exit = client.wait_process(context::Context::default(), &request);
        let status = exit.as_ref().map_or(UNKNOWN_STATUS, |exit| {
            u32::try_from(exit.status)
                .ok()
                .filter(|status| *status <= 255)
                .unwrap_or(UNKNOWN_STATUS)
        });
        if !pumps.drain(DRAIN_TIMEOUT) {
            log::warn!("the output of process {exec_id:?} did not end by its exit");
        }
        let mut state = self.lock();
        if let Err(error) = &exit {
            log::error!("cannot wait for process {exec_id:?}: {error:?}; stopping the broker");
            if let Some(container) = state.as_ref() {
                container.broker.stop();
            }
        }
        if exec_id.is_empty() {
            let running_execs = |state: &mut Option<Container>| {
                state.as_ref().is_some_and(|container| {
                    container.processes.iter().any(|(id, process)| {
                        !id.is_empty() && process.started && process.exit.get().is_none()
                    })
                })
            };
            state = self
                .changed
                .wait_timeout_while(state, DRAIN_TIMEOUT, running_execs)
                .expect("not poisoned")
                .0;
        }
        if let Some(container) = state.as_mut() {
            self.stop(container, exec_id, status, true);
        }
        drop(state);
        if exit.is_ok() {
            if !pumps.finish(DRAIN_TIMEOUT, deleted) {
                log::warn!("the output of process {exec_id:?} did not end; releasing the process");
            }
            let release = ReleaseProcessRequest {
                exec_id: guest_id,
                ..Default::default()
            };
            let released = client.release_process(deadline(CONTROL_TIMEOUT), &release);
            let state = self.lock();
            // A deleted container's broker stopped, which ends the output and fails the release.
            let ours = state
                .as_ref()
                .filter(|container| Arc::ptr_eq(&container.client, client));
            if let (Err(error), Some(container)) = (released, ours) {
                log::error!("cannot release process {exec_id:?}: {error:?}; stopping the broker");
                container.broker.stop();
            }
        }
        pumps.stop();
    }

    fn exec(&self, request: &ExecProcessRequest) -> Result<()> {
        let process: oci_spec::runtime::Process = serde_json::from_slice(&request.spec.value)
            .map_err(|failure| invalid(format!("invalid exec process spec: {failure}")))?;
        // The request's terminal decides, as with runc.
        let (mut guest, uid) = spec::process(&process, request.terminal)?;
        let mut state = self.lock();
        let container = container(&mut state, &request.id)?;
        // A broker that ends after this check stops the new process through `broker_exited`.
        if container.broker.wait(Duration::ZERO)
            || !container
                .process("")
                .is_ok_and(|init| init.started && init.exit.get().is_none())
        {
            return Err(precondition("the container is not running"));
        }
        if request.exec_id.is_empty() || container.processes.contains_key(&request.exec_id) {
            return Err(error(
                Code::ALREADY_EXISTS,
                format!("exec process {:?} exists", request.exec_id),
            ));
        }
        let io = task_io(
            &request.stdin,
            &request.stdout,
            &request.stderr,
            request.terminal,
        );
        container.last_guest_id += 1;
        set_home(&mut guest, &container.passwd, uid);
        let process = Process::new(container.last_guest_id.to_string(), io, Some(guest));
        container.processes.insert(request.exec_id.clone(), process);
        let event = TaskExecAdded {
            container_id: request.id.clone(),
            exec_id: request.exec_id.clone(),
            ..Default::default()
        };
        self.publish(topics::TASK_EXEC_ADDED_EVENT_TOPIC, Box::new(event));
        Ok(())
    }

    fn kill(&self, request: &KillRequest) -> Result<()> {
        // LiteBox ends a process on a stop signal, and `SIGSTOP` cannot be caught.
        // TODO: forward it once LiteBox can stop a process.
        if request.signal == STOP_SIGNAL {
            return Err(unsupported("stopping processes is not supported yet"));
        }
        let mut state = self.lock();
        let container = container(&mut state, &request.id)?;
        let process = container.process(&request.exec_id)?;
        if process.exit.get().is_some() {
            return Err(error(Code::NOT_FOUND, "process already finished"));
        }
        if !process.started {
            if !request.exec_id.is_empty() {
                return Err(precondition("the process has not started"));
            }
            // A created container ends when killed.
            if request.signal != 0 {
                self.stop(container, "", KILLED_STATUS, true);
            }
            return Ok(());
        }
        let signal = SignalProcessRequest {
            exec_id: process.guest_id.clone(),
            signal: request.signal,
            all: request.all && request.exec_id.is_empty(),
            ..Default::default()
        };
        let signaled = container
            .client
            .signal_process(deadline(CONTROL_TIMEOUT), &signal);
        stop_unless_answered(&container.broker, signaled)
            .map(drop)
            .map_err(guest_error("cannot signal the process"))
    }

    fn delete(&self, request: &DeleteRequest) -> Result<DeleteResponse> {
        let _lifecycle = self.lock_lifecycle();
        let mut state = self.lock();
        let container = container(&mut state, &request.id)?;
        let pid = container.broker.pid();
        let process = container.process(&request.exec_id)?;
        let response = |exit: Exit, pid| DeleteResponse {
            pid,
            exit_status: exit.status,
            exited_at: timestamp(exit.at),
            ..Default::default()
        };
        if !request.exec_id.is_empty() {
            let exit = match process.exit.get() {
                Some(exit) => *exit,
                None if !process.started => Exit {
                    status: 0,
                    at: SystemTime::now(),
                },
                None => return Err(precondition("the process is running")),
            };
            let pid = if process.started { pid } else { 0 };
            // Its output ends within `DRAIN_TIMEOUT` (see `watch`), even if a child still writes
            // to it, as runc's shim ends an exec's output at its `Delete`.
            process.deleted.store(true, Ordering::SeqCst);
            let process = container.processes.remove(&request.exec_id);
            self.changed.notify_all();
            drop(state);
            // Reaps its logging program.
            drop(process);
            return Ok(response(exit, pid));
        }
        // Deleting a created container ends it.
        if !process.started {
            self.stop(container, "", KILLED_STATUS, true);
        }
        let Some(exit) = container.process("")?.exit.get().copied() else {
            return Err(precondition("the container is running"));
        };
        let mut container = state.take().expect("found above");
        drop(state);
        self.changed.notify_all();
        container.broker.stop();
        container.state_dir.clear();
        // The outputs of an init that never ran end with the broker.
        if let Some(pumps) = container
            .processes
            .get("")
            .and_then(|init| init.pumps.as_ref())
            && !pumps.drain(DRAIN_TIMEOUT)
        {
            log::warn!("the output of the init process did not end in time");
        }
        // Reaps their logging programs.
        container.processes.clear();
        container.hooks.poststop(|error| log::warn!("{error}"));
        container.state_dir.remove();
        let event = TaskDelete {
            container_id: container.id,
            pid,
            exit_status: exit.status,
            exited_at: timestamp(exit.at),
            ..Default::default()
        };
        self.publish(topics::TASK_DELETE_EVENT_TOPIC, Box::new(event));
        Ok(response(exit, pid))
    }

    fn wait(&self, request: &WaitRequest) -> Result<WaitResponse> {
        let mut state = self.lock();
        let exit = Arc::clone(
            &container(&mut state, &request.id)?
                .process(&request.exec_id)?
                .exit,
        );
        loop {
            if let Some(exit) = exit.get() {
                return Ok(WaitResponse {
                    exit_status: exit.status,
                    exited_at: timestamp(exit.at),
                    ..Default::default()
                });
            }
            let deleted = state
                .as_ref()
                .and_then(|container| container.processes.get(&request.exec_id))
                .is_none_or(|process| !Arc::ptr_eq(&process.exit, &exit));
            if deleted {
                return Err(error(Code::NOT_FOUND, "the process was deleted"));
            }
            state = self
                .changed
                .wait(state)
                .expect("the state's lock is poisoned");
        }
    }

    fn state(&self, request: &StateRequest) -> Result<StateResponse> {
        let mut state = self.lock();
        let container = container(&mut state, &request.id)?;
        let (bundle, pid) = (container.bundle.clone(), container.broker.pid());
        let process = container.process(&request.exec_id)?;
        let exit = process.exit.get();
        let status = match (exit, process.started) {
            (Some(_), _) => Status::STOPPED,
            (None, true) => Status::RUNNING,
            (None, false) => Status::CREATED,
        };
        Ok(StateResponse {
            id: request.id.clone(),
            bundle,
            pid: if request.exec_id.is_empty() || process.started {
                pid
            } else {
                0
            },
            status: status.into(),
            stdin: process.io.stdin.clone(),
            stdout: process.io.stdout.clone(),
            stderr: process.io.stderr.clone(),
            terminal: process.io.terminal,
            exit_status: exit.map_or(0, |exit| exit.status),
            exited_at: exit.map_or_else(MessageField::none, |exit| timestamp(exit.at)),
            exec_id: request.exec_id.clone(),
            ..Default::default()
        })
    }

    fn resize_pty(&self, request: &ResizePtyRequest) -> Result<()> {
        let mut state = self.lock();
        let container = container(&mut state, &request.id)?;
        let process = container.process(&request.exec_id)?;
        if process.exit.get().is_some() {
            return Err(error(Code::NOT_FOUND, "the process exited"));
        }
        // As with runc, one without a terminal, or an exec process not started, has none to
        // resize; the init's terminal exists from its `Create`.
        if !process.io.terminal || (!process.started && !request.exec_id.is_empty()) {
            return Ok(());
        }
        let resize = TtyWinResizeRequest {
            exec_id: process.guest_id.clone(),
            row: request.height,
            column: request.width,
            ..Default::default()
        };
        let resized = container
            .client
            .tty_win_resize(deadline(CONTROL_TIMEOUT), &resize);
        stop_unless_answered(&container.broker, resized)
            .map(drop)
            .map_err(guest_error("cannot resize the terminal"))
    }
}

impl Task for Service {
    fn state(&self, _ctx: &TtrpcContext, request: StateRequest) -> TtrpcResult<StateResponse> {
        self.0.state(&request)
    }

    fn create(
        &self,
        _ctx: &TtrpcContext,
        request: CreateTaskRequest,
    ) -> TtrpcResult<CreateTaskResponse> {
        log::info!("create {}", request.id);
        self.0.create(&request)
    }

    fn start(&self, _ctx: &TtrpcContext, request: StartRequest) -> TtrpcResult<StartResponse> {
        log::info!("start {} {:?}", request.id, request.exec_id);
        self.0.start(&request)
    }

    fn delete(&self, _ctx: &TtrpcContext, request: DeleteRequest) -> TtrpcResult<DeleteResponse> {
        log::info!("delete {} {:?}", request.id, request.exec_id);
        self.0.delete(&request)
    }

    /// The init process's pid, the broker's, until it stopped.
    // TODO: also list the runners, the host processes of guest processes.
    fn pids(&self, _ctx: &TtrpcContext, request: PidsRequest) -> TtrpcResult<PidsResponse> {
        let mut state = self.0.lock();
        let container = container(&mut state, &request.id)?;
        let pid = container.broker.pid();
        let running = container.process("")?.exit.get().is_none();
        let processes = running.then(|| ProcessInfo {
            pid,
            ..Default::default()
        });
        Ok(PidsResponse {
            processes: processes.into_iter().collect(),
            ..Default::default()
        })
    }

    fn kill(&self, _ctx: &TtrpcContext, request: KillRequest) -> TtrpcResult<Empty> {
        log::info!(
            "kill {} {:?} {}",
            request.id,
            request.exec_id,
            request.signal
        );
        self.0.kill(&request).map(|()| Empty::new())
    }

    fn exec(&self, _ctx: &TtrpcContext, request: ExecProcessRequest) -> TtrpcResult<Empty> {
        log::info!("exec {} {:?}", request.id, request.exec_id);
        self.0.exec(&request).map(|()| Empty::new())
    }

    fn close_io(&self, _ctx: &TtrpcContext, request: CloseIORequest) -> TtrpcResult<Empty> {
        let mut state = self.0.lock();
        let process = container(&mut state, &request.id)?.process(&request.exec_id)?;
        if request.stdin {
            process.closing.store(true, Ordering::SeqCst);
        }
        Ok(Empty::new())
    }

    fn wait(&self, _ctx: &TtrpcContext, request: WaitRequest) -> TtrpcResult<WaitResponse> {
        self.0.wait(&request)
    }

    fn connect(
        &self,
        _ctx: &TtrpcContext,
        request: ConnectRequest,
    ) -> TtrpcResult<ConnectResponse> {
        let mut state = self.0.lock();
        let task_pid =
            container(&mut state, &request.id).map_or(0, |container| container.broker.pid());
        Ok(ConnectResponse {
            shim_pid: std::process::id(),
            task_pid,
            ..Default::default()
        })
    }

    fn shutdown(&self, _ctx: &TtrpcContext, _request: ShutdownRequest) -> TtrpcResult<Empty> {
        let _lifecycle = self.0.lock_lifecycle();
        if self.0.lock().is_none() {
            let (done, flushed) = mpsc::sync_channel(1);
            if self.0.events.send(Outgoing::Flush(done)).is_ok() {
                let _ = flushed.recv_timeout(Duration::from_secs(5));
            }
            self.0.exit.signal();
        }
        Ok(Empty::new())
    }

    fn resize_pty(&self, _ctx: &TtrpcContext, request: ResizePtyRequest) -> TtrpcResult<Empty> {
        self.0.resize_pty(&request).map(|()| Empty::new())
    }

    // The generated defaults answer `NOT_FOUND`, which containerd takes for a missing process.

    // TODO: pause and resume once LiteBox can stop a process.
    fn pause(&self, _ctx: &TtrpcContext, _request: PauseRequest) -> TtrpcResult<Empty> {
        Err(unsupported("pausing is not supported yet"))
    }

    fn resume(&self, _ctx: &TtrpcContext, _request: ResumeRequest) -> TtrpcResult<Empty> {
        Err(unsupported("resuming is not supported yet"))
    }

    fn checkpoint(
        &self,
        _ctx: &TtrpcContext,
        _request: CheckpointTaskRequest,
    ) -> TtrpcResult<Empty> {
        Err(unsupported("checkpoints are not supported"))
    }

    /// Resources are ignored for now: the broker has no cgroups.
    // TODO: apply them once LiteBox can limit a container's.
    fn update(&self, _ctx: &TtrpcContext, request: UpdateTaskRequest) -> TtrpcResult<Empty> {
        container(&mut self.0.lock(), &request.id)?;
        Ok(Empty::new())
    }

    // TODO: report the broker's and its runners' CPU time and memory.
    fn stats(&self, _ctx: &TtrpcContext, _request: StatsRequest) -> TtrpcResult<StatsResponse> {
        Err(unsupported("statistics are not supported yet"))
    }
}
