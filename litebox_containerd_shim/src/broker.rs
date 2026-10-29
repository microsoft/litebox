// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The container's broker: its construction, its processes' runners and their associations,
//! and the [`ProcessLauncher`] that gives guest `fork` and `exec` children their runners.

use std::cell::Cell;
use std::ffi::CString;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use containerd_shim::protos::types::mount::Mount;
use litebox_broker_core::fs::composer::Composer;
use litebox_broker_core::fs::devices::Devices;
use litebox_broker_core::fs::in_mem::InMem;
use litebox_broker_core::fs::resolver::Resolver;
use litebox_broker_core::fs::{self, FileType, Mode, UserInfo};
use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_core::stdio::UnsupportedStdioProvider;
use litebox_broker_core::{
    BrokerCore, BrokerError, BrokerProcess, CallerCredential, ChildImage, ObjectRights,
    PolicyEngine, ProcessImage, SocketPolicy, signal,
};
use litebox_broker_host::{
    BrokerHostAssociation, BrokerHostError, ProcessLauncher, handle_process_operation,
    setup_connection,
};
use litebox_broker_platform_linux_userland::LinuxSyncPrimitivesProvider;
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::fs::{FileAccessMode, FileError, FileOpenFlags};
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, ProcessRequest, ProcessResponse,
};
use litebox_broker_protocol::process::{ProcessExitStatus, ProcessStartupData};
use litebox_broker_protocol::shared_buffer::{SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE};
use litebox_broker_protocol::signal::SignalTarget;
use litebox_broker_transport::channel::HostReceive;
use litebox_broker_transport::control_ring::{ControlRing, ControlRingLayout};
use litebox_broker_transport::shared_memory::SharedBufferPool;
use litebox_broker_transport_linux_userland::memfd::{MemfdProcessImage, MemfdSharedMemory};
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixControlRingHostCallLane, UnixControlRingHostCallLaneSource,
    UnixControlRingHostNotificationChannel, UnixControlRingHostShutdown,
    UnixStreamHostSetupChannel,
};
use litebox_broker_userland::builder::BrokerCoreBuilder;
use litebox_broker_userland::random::UserlandRandomProvider;
use litebox_broker_userland::readiness::ReadinessPublisherRuntime;
use litebox_common_linux::program_startup::{InheritedFd, LinuxProgramStartup};
use litebox_common_linux::signal::SigSet;

use crate::error::{Error, Result};
use crate::image_fs::{FileBind, ImageFs};
use crate::mounts;
use crate::runner::{Runner, Runners};
use crate::spec::{ContainerPlan, MountKind, ProcessSpec};
use crate::stdio::{self, TaskIo, Wake};

/// How long a runner may take to connect and set up its association, as the runner library
/// itself allows.
const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a runner may take to exit once its association ended, before it is killed.
const EXIT_GRACE: Duration = Duration::from_secs(5);
const SIGKILL: u32 = 9;
/// The largest guest `/etc/passwd` read for `HOME`; a longer one counts as having no entry.
const MAX_PASSWD_SIZE: usize = 1 << 20;
/// The directory of the runners' sockets in the bundle. It exists from the container's `Create`
/// until the daemon deletes the container or fails to create it.
pub(crate) const SOCKET_DIR: &str = "litebox";

fn broker_error(what: &str) -> impl FnOnce(BrokerError) -> Error + '_ {
    move |error| Error::internal(format!("{what}: {error}"))
}

/// containerd's exit status for `status`, which a guest may report: values outside what Linux
/// reports become 255.
fn exit_code(status: ProcessExitStatus) -> u32 {
    match status {
        ProcessExitStatus::Exited { code } if code <= 255 => code,
        ProcessExitStatus::Signaled { signal } if (1..=64).contains(&signal) => 128 + signal,
        _ => 255,
    }
}

/// Ends `process`, whose runner never ran a guest.
fn abandon(process: &BrokerProcess, error: BrokerError) {
    // Not abnormal, an expected shutdown, and the process's IDs are released.
    let _ = process.fail_start(error, false, true);
    process.retire(true);
}

/// One container's broker and runners.
pub(crate) struct Container {
    core: BrokerCore,
    /// A broker process that never runs: it owns the host ends of every task's stdio pipes and
    /// terminal managers, sends containerd's signals, and looks up the tasks' programs.
    authority: Arc<BrokerProcess>,
    wake: Arc<Wake>,
    runners: Arc<Runners>,
}

impl Container {
    /// Builds the broker for `plan` in `bundle`, whose root file system is made of containerd's
    /// mounts `rootfs`, returning it and the init process's broker process, which is process 1.
    /// The missing parent directories of file binds are created.
    pub(crate) fn new(
        plan: &ContainerPlan,
        bundle: &Path,
        rootfs: &[Mount],
    ) -> Result<(Arc<Self>, Arc<BrokerProcess>)> {
        let root = mounts::prepare(plan, bundle, rootfs)?;
        let runners = Runners::new(bundle.join(SOCKET_DIR), &plan.network)
            .map_err(|error| Error::io("cannot set up the runners", &error))?;
        let built = (|| {
            let core = build_core(plan, &root)?;
            let init = core
                .create_process(CallerCredential::HostGuaranteed, None)
                .map_err(broker_error("cannot create the init process"))?;
            let authority = core
                .create_process(CallerCredential::HostGuaranteed, None)
                .map_err(broker_error("cannot create the authority process"))?;
            let container = Arc::new(Self {
                core,
                authority,
                wake: Arc::default(),
                runners: Arc::clone(&runners),
            });
            for mount in &plan.mounts {
                match &mount.kind {
                    MountKind::Tmpfs { mode } => {
                        let mode = Mode::from_bits_truncate(*mode);
                        fs::chmod(
                            &container.authority,
                            &mount.destination,
                            UserInfo::ROOT,
                            mode,
                        )
                        .map_err(broker_error("cannot set up a tmpfs"))?
                        .map_err(|error| Error::io("cannot set up a tmpfs", &error))?;
                    }
                    // A file bind, as `compose` classifies it, whose parent directory is created
                    // as runc creates mount destinations.
                    MountKind::Bind { source, .. } if source.is_file() => {
                        let (parent, _) = mount
                            .destination
                            .rsplit_once('/')
                            .expect("mount destinations are absolute");
                        let unsupported = || {
                            Error::unimplemented(format!(
                                "the parent directory of the file bound at {} cannot be \
                                 created in the image that serves it, which is not supported",
                                mount.destination
                            ))
                        };
                        container
                            .create_dirs(parent)
                            .map_err(broker_error("cannot create a mount destination"))?
                            .map_err(|_| unsupported())?;
                        // A parent that only the `Composer` serves, as an ancestor of another
                        // mount's destination, hides the image that serves the file.
                        let status = fs::path_status(
                            &container.authority,
                            &mount.destination,
                            UserInfo::ROOT,
                            false,
                        )
                        .map_err(broker_error("cannot look up a mount destination"))?;
                        if !matches!(status, Ok(status) if status.file_type == FileType::RegularFile)
                        {
                            return Err(unsupported());
                        }
                    }
                    MountKind::Bind { .. } => {}
                }
            }
            Ok((container, init))
        })();
        built.inspect_err(|_| runners.remove_dir())
    }

    /// Creates the broker process of an exec process, a root process like the init process.
    pub(crate) fn create_process(&self) -> Result<Arc<BrokerProcess>> {
        self.core
            .create_process(CallerCredential::HostGuaranteed, None)
            .map_err(broker_error("cannot create the process"))
    }

    /// Spawns the runner of the init process `process`, which waits behind a gate, so that its
    /// process ID exists before [`Self::prepare_gated`] looks up its files.
    pub(crate) fn spawn_gated(&self, process: Arc<BrokerProcess>) -> Result<Gated> {
        match self.spawn(&process, true) {
            Ok(runner) => Ok(Gated { process, runner }),
            Err(error) => {
                abandon(&process, BrokerError::PeerClosed);
                Err(error)
            }
        }
    }

    /// Prepares the init process `gated` running `spec` with the host stdio `stdio`: its program
    /// and its stdio pumps. Its missing working directory is created, as runc does.
    pub(crate) fn prepare_gated(
        &self,
        gated: Gated,
        spec: &ProcessSpec,
        stdio: stdio::Host,
    ) -> Result<Prepared> {
        match self.load(&gated.process, spec, stdio, true) {
            Ok((io, startup)) => Ok(Prepared {
                process: gated.process,
                runner: gated.runner,
                io,
                startup,
            }),
            Err(error) => {
                gated.discard();
                Err(error)
            }
        }
    }

    /// Prepares the exec process `process` running `spec` with the host stdio `stdio`: its
    /// program, its stdio pumps and its runner.
    pub(crate) fn prepare(
        &self,
        process: Arc<BrokerProcess>,
        spec: &ProcessSpec,
        stdio: stdio::Host,
    ) -> Result<Prepared> {
        let prepared = self
            .load(&process, spec, stdio, false)
            .and_then(|(io, startup)| Ok((io, startup, self.spawn(&process, false)?)));
        match prepared {
            Ok((io, startup, runner)) => Ok(Prepared {
                process,
                runner,
                io,
                startup,
            }),
            Err(error) => {
                abandon(&process, BrokerError::PeerClosed);
                Err(error)
            }
        }
    }

    fn spawn(&self, process: &BrokerProcess, gated: bool) -> Result<Runner> {
        self.runners
            .spawn(process.id(), gated)
            .map_err(|error| Error::precondition(format!("cannot start a runner: {error}")))
    }

    /// Returns the stdio pumps and the startup data of the task `process` running `spec` with
    /// the host stdio `stdio`, creating its missing working directory with `create_cwd`.
    fn load(
        &self,
        process: &Arc<BrokerProcess>,
        spec: &ProcessSpec,
        stdio: stdio::Host,
        create_cwd: bool,
    ) -> Result<(Arc<TaskIo>, Vec<u8>)> {
        let (path, cwd) = self.locate(spec, create_cwd)?;
        let mut env = spec.env.clone();
        // As runc sets it.
        if !env.iter().any(|entry| entry.starts_with("HOME=")) {
            env.push(format!("HOME={}", self.home(spec.uid)?));
        }
        let (io, inherited) =
            TaskIo::start(&self.authority, &self.wake, process, stdio, spec.terminal)
                .map_err(|error| Error::io("cannot set up the standard streams", &error))?;
        let startup = encode_startup(spec, &env, path, cwd, inherited)?;
        Ok((Arc::new(io), startup))
    }

    /// Sends `signal` to the broker process `process`, or with `all` to every process of the
    /// container. `SIGKILL` kills runners directly, which works even for a runner stuck in the
    /// host.
    pub(crate) fn signal(&self, process: ProcessId, signal: u32, all: bool) -> Result<()> {
        if signal == SIGKILL {
            self.runners.kill((!all).then_some(process));
            return Ok(());
        }
        let targets = if all {
            self.runners.processes()
        } else {
            vec![process]
        };
        for target in targets {
            match signal::send(&self.authority, SignalTarget::Process(target), signal) {
                // A process of the container that is exiting already.
                Err(BrokerError::UnknownObject) if all => {}
                Err(BrokerError::UnknownObject) => {
                    return Err(Error::not_found("the process has already exited"));
                }
                result => result.map_err(broker_error("cannot send the signal"))?,
            }
        }
        Ok(())
    }

    /// Ends the container: no runner starts after this, and every runner is killed.
    pub(crate) fn close(&self) {
        self.runners.close();
    }

    /// Waits up to `timeout` until every runner of the container has been reaped.
    pub(crate) fn wait_reaped(&self, timeout: Duration) -> bool {
        self.runners.wait_reaped(timeout)
    }

    /// The host process IDs of every runner of the container.
    pub(crate) fn pids(&self) -> Vec<u32> {
        self.runners.pids()
    }

    pub(crate) fn remove_socket_dir(&self) {
        self.runners.remove_dir();
    }

    /// The shim's log, which hooks write to.
    pub(crate) fn log(&self) -> &std::fs::File {
        self.runners.log()
    }

    /// Returns the guest path of the program that `spec` runs and the physical guest path of its
    /// working directory, as the guest sees its files.
    ///
    /// The program is `args[0]` if it has a slash (relative to the working directory), or else
    /// the first executable file of that name in `PATH`. As on Linux, it keeps the path that
    /// found it rather than its symlinks' target. The guest applies relative paths to its working
    /// directory lexically, so that one is physical, as its `getcwd` reports it. With
    /// `create_cwd`, the missing parts of the working directory are created first, as runc does
    /// for the init process.
    fn locate(&self, spec: &ProcessSpec, create_cwd: bool) -> Result<(String, String)> {
        let user = UserInfo::ROOT;
        let lookup = |error: BrokerError| {
            Error::internal(format!("cannot look up the process's files: {error}"))
        };
        let is = |path: &str, file_type: FileType, executable: bool| -> Result<bool> {
            let execute = Mode::XUSR | Mode::XGRP | Mode::XOTH;
            let status = fs::path_status(&self.authority, path, user, true).map_err(lookup)?;
            Ok(matches!(status, Ok(status) if status.file_type == file_type
                && (!executable || status.mode.intersects(execute))))
        };
        let missing = || Error::invalid("the working directory is not a directory");
        if create_cwd
            && !is(&spec.cwd, FileType::Directory, false)?
            && let Err(error) = self.create_dirs(&spec.cwd).map_err(lookup)?
        {
            return Err(Error::invalid(format!(
                "cannot create the working directory: {error}"
            )));
        }
        if !is(&spec.cwd, FileType::Directory, false)? {
            return Err(missing());
        }
        let cwd = fs::resolve_path(&self.authority, &spec.cwd, user)
            .map_err(lookup)?
            .map_err(|_| missing())?;
        let absolute = |path: &str| {
            if path.starts_with('/') {
                path.to_owned()
            } else {
                format!("{}/{path}", cwd.trim_end_matches('/'))
            }
        };
        let program = &spec.args[0];
        if program.contains('/') {
            let path = absolute(program);
            return if is(&path, FileType::RegularFile, true)? {
                Ok((path, cwd))
            } else {
                Err(Error::invalid("the program is not an executable file"))
            };
        }
        for directory in spec.search_path().split(':') {
            let candidate = format!("{}/{program}", absolute(directory).trim_end_matches('/'));
            if is(&candidate, FileType::RegularFile, true)? {
                return Ok((candidate, cwd));
            }
        }
        Err(Error::invalid("the program was not found in PATH"))
    }

    /// Creates the missing directories of the absolute guest path `path` (mode 0755) as the guest
    /// sees its files, failing unless each is then a directory.
    fn create_dirs(
        &self,
        path: &str,
    ) -> std::result::Result<std::result::Result<(), FileError>, BrokerError> {
        let mut created = String::new();
        for component in path.split('/').filter(|component| !component.is_empty()) {
            created = format!("{created}/{component}");
            let mode = Mode::from_bits_truncate(0o755);
            let Err(error) = fs::mkdir(&self.authority, &created, UserInfo::ROOT, mode)? else {
                continue;
            };
            // Mount points and their ancestors refuse `mkdir`, but are directories.
            let status = fs::path_status(&self.authority, &created, UserInfo::ROOT, true)?;
            if !matches!(status, Ok(status) if status.file_type == FileType::Directory) {
                return Ok(Err(match error {
                    FileError::AlreadyExists => FileError::NotDirectory,
                    error => error,
                }));
            }
        }
        Ok(Ok(()))
    }

    /// The home directory of the first entry for `uid` in the guest's `/etc/passwd`, or `/`.
    fn home(&self, uid: u32) -> Result<String> {
        let failed =
            |error: BrokerError| Error::internal(format!("cannot read /etc/passwd: {error}"));
        let sink: Arc<dyn ReadinessSink> = Arc::<Wake>::clone(&self.wake);
        let opened = fs::open(
            &self.authority,
            "/etc/passwd",
            UserInfo::ROOT,
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONE,
            Mode::empty(),
            &sink,
        )
        .map_err(failed)?;
        let mut passwd = Vec::new();
        if let Ok(handle) = opened {
            // Only a regular file ends: a device such as `/dev/urandom` never does.
            let read = (|| {
                let status = fs::handle_status(&self.authority, handle).map_err(failed)?;
                if !matches!(status, Ok(status) if status.file_type == FileType::RegularFile) {
                    return Ok(());
                }
                let mut buffer = vec![0; 16 * 1024];
                loop {
                    match fs::read(&self.authority, handle, &mut buffer, None).map_err(failed)? {
                        Ok(0) => return Ok(()),
                        Ok(read) if passwd.len() + read <= MAX_PASSWD_SIZE => {
                            passwd.extend_from_slice(&buffer[..read]);
                        }
                        _ => {
                            passwd.clear();
                            return Ok(());
                        }
                    }
                }
            })();
            let _ = self.authority.close_object_reference(handle);
            read?;
        }
        let home = String::from_utf8_lossy(&passwd).lines().find_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            (fields.get(2).and_then(|field| field.parse().ok()) == Some(uid))
                .then(|| fields.get(5).copied().unwrap_or_default().to_owned())
        });
        Ok(home.unwrap_or_else(|| "/".to_owned()))
    }

    /// Accepts `runner`'s connection and sets up and activates its association for `process`,
    /// whose runner receives `startup` and the memory image `image`.
    fn attach(
        &self,
        process: &Arc<BrokerProcess>,
        runner: &mut Runner,
        startup: Vec<u8>,
        image: Option<&ChildImage>,
    ) -> io::Result<Active> {
        process.install_shutdown(Arc::new(runner.killer()));
        runner.open_gate()?;
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let stream = runner.accept(deadline)?;
        let mut channel = UnixStreamHostSetupChannel::from_host_guaranteed(stream, deadline);
        let buffers = Arc::new(
            SharedBufferPool::new(
                MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE)?,
                SHARED_BUFFER_LAYOUT,
            )
            .map_err(|error| io::Error::other(format!("{error:?}")))?,
        );
        // The runner library expects the multi-lane layout.
        let layout = ControlRingLayout::MULTI_LANE;
        let ring = ControlRing::new(MemfdSharedMemory::create_control_ring(layout)?, layout)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        let image = match image {
            Some(image) => Some(
                &image
                    .image()
                    .as_any()
                    .downcast_ref::<Image>()
                    .ok_or_else(|| io::Error::other("a foreign process image"))?
                    .0,
            ),
            None => None,
        };
        let readiness = Arc::new(ReadinessPublisherRuntime::new());
        let association = setup_connection(
            &self.core,
            Some(Arc::clone(process)),
            Some(ProcessStartupData { payload: startup }),
            &mut channel,
            Arc::clone(&buffers),
            readiness.clone(),
            |_| false,
            |channel| {
                channel.send_memfd(buffers.memory(), Some(deadline))?;
                channel.send_memfd(ring.memory(), Some(deadline))?;
                channel.send_process_image(image, Some(deadline))
            },
        )
        .map_err(|error| match error {
            BrokerHostError::Channel(error) => error,
            error => io::Error::other(error.to_string()),
        })?
        .map_err(|end| io::Error::other(format!("the runner ended its setup: {end:?}")))?;
        let (lanes, notifications, shutdown) = channel.into_active(ring)?;
        association
            .activate_process()
            .map_err(|error| io::Error::other(format!("cannot start the process: {error}")))?;
        Ok(Active {
            association,
            readiness,
            lanes,
            notifications,
            shutdown,
        })
    }

    /// Attaches `runner` to `process`, or on failure kills it and fails the process's start.
    fn start(
        &self,
        process: Arc<BrokerProcess>,
        mut runner: Runner,
        startup: Vec<u8>,
        image: Option<&ChildImage>,
    ) -> io::Result<Started> {
        match self.attach(&process, &mut runner, startup, image) {
            Ok(active) => Ok(Started {
                process,
                runner,
                active,
            }),
            Err(error) => {
                drop(runner);
                abandon(&process, BrokerError::PeerClosed);
                Err(error)
            }
        }
    }

    /// Serves an association until it ends, returning whether it ended abnormally and the exit
    /// status that the guest reported and the broker accepted, if any.
    ///
    /// One thread publishes readiness, and one serves each call lane the runner uses. Any thread
    /// that stops, even by a panic, ends the association, which releases every other one.
    fn serve(self: &Arc<Self>, active: Active) -> (bool, Option<ProcessExitStatus>) {
        let Active {
            association,
            readiness,
            mut lanes,
            mut notifications,
            shutdown,
        } = active;
        let abnormal = AtomicBool::new(false);
        let report = Mutex::new(None);
        let end = || {
            association.request_cancellation();
            association.association_ending();
            readiness.close();
            let _ = shutdown.shutdown();
        };
        // A runner that closes its connection ends its association normally.
        let fail = |error: Option<&io::Error>| {
            let peer_closed = error.is_some_and(|error| {
                matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                )
            });
            if !peer_closed {
                abnormal.store(true, Ordering::Relaxed);
            }
        };
        let serve_lane = |mut lane: UnixControlRingHostCallLane| loop {
            let request = match lane.recv_request() {
                Ok(HostReceive::Message(request)) => request,
                Ok(HostReceive::PeerClosed) => return,
                Ok(HostReceive::ProtocolViolation) => return fail(None),
                Err(error) => return fail(Some(&error)),
            };
            let reported = Cell::new(None);
            let result = association.execute_request_with(
                request,
                |process, operation, buffers| {
                    if let BrokerOperation::Process(ProcessRequest::ReportExitStatus(status)) =
                        operation
                    {
                        reported.set(Some(*status));
                    }
                    handle_process_operation(self, process, operation, buffers)
                },
                |response| {
                    // Only a report that the broker accepted counts.
                    if response.result == BrokerResult::Process(ProcessResponse::ReportExitStatus) {
                        *report.lock().expect("report mutex poisoned") = reported.get();
                    }
                    lane.send_response(response)
                },
            );
            match result {
                Ok(()) => {}
                Err(BrokerHostError::AssociationFailed) => return,
                Err(BrokerHostError::Channel(error)) => return fail(Some(&error)),
                Err(_) => return fail(None),
            }
        };
        let served = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::thread::scope(|scope| {
                let _ending = Ending(&end);
                let publisher = std::thread::Builder::new()
                    .name("litebox-notify".to_owned())
                    .spawn_scoped(scope, || {
                        let _ending = Ending(&end);
                        let _ = readiness.run(&mut notifications);
                    });
                if publisher.is_err() {
                    return fail(None);
                }
                loop {
                    match lanes.next_lane() {
                        Ok(Some(lane)) => {
                            let spawned = std::thread::Builder::new()
                                .name("litebox-lane".to_owned())
                                .spawn_scoped(scope, || {
                                    let _ending = Ending(&end);
                                    serve_lane(lane);
                                });
                            if spawned.is_err() {
                                return fail(None);
                            }
                        }
                        Ok(None) => return,
                        Err(error) => return fail(Some(&error)),
                    }
                }
            });
        }));
        let abnormal = served.is_err() || abnormal.load(Ordering::Relaxed);
        let report = *report
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (abnormal, report)
    }
}

/// Ends an association when dropped, including by an unwind.
struct Ending<F: Fn()>(F);

impl<F: Fn()> Drop for Ending<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// An activated association.
struct Active {
    association: BrokerHostAssociation<MemfdSharedMemory>,
    readiness: Arc<ReadinessPublisherRuntime>,
    lanes: UnixControlRingHostCallLaneSource,
    notifications: UnixControlRingHostNotificationChannel,
    shutdown: UnixControlRingHostShutdown,
}

/// The init process with its gated runner, before its files are looked up.
pub(crate) struct Gated {
    process: Arc<BrokerProcess>,
    runner: Runner,
}

impl Gated {
    /// The runner's host process ID.
    pub(crate) fn pid(&self) -> u32 {
        self.runner.pid()
    }

    /// Kills and reaps the runner.
    pub(crate) fn discard(self) {
        drop(self.runner);
        abandon(&self.process, BrokerError::PeerClosed);
    }
}

/// A task whose runner is spawned but not yet attached.
pub(crate) struct Prepared {
    process: Arc<BrokerProcess>,
    runner: Runner,
    io: Arc<TaskIo>,
    startup: Vec<u8>,
}

impl Prepared {
    /// The runner's host process ID.
    pub(crate) fn pid(&self) -> u32 {
        self.runner.pid()
    }

    pub(crate) fn process_id(&self) -> ProcessId {
        self.process.id()
    }

    pub(crate) fn io(&self) -> Arc<TaskIo> {
        Arc::clone(&self.io)
    }

    /// Returns a function that waits until the runner exits, without reaping it, and returns
    /// whether it did.
    pub(crate) fn exit_waiter(&self) -> impl FnOnce() -> bool + Send + 'static {
        self.runner.exit_waiter()
    }

    /// Opens the runner's gate and activates its association.
    pub(crate) fn start(self, container: &Container) -> Result<Started> {
        container
            .start(self.process, self.runner, self.startup, None)
            .map_err(|error| {
                self.io.abort();
                Error::io("cannot start the process", &error)
            })
    }

    /// Kills and reaps the runner, and returns its exit status.
    pub(crate) fn discard(mut self) -> u32 {
        let (status, _) = self.runner.wait(Duration::ZERO);
        drop(self.runner);
        abandon(&self.process, BrokerError::PeerClosed);
        self.io.abort();
        exit_code(runner_status(status))
    }
}

/// A process whose association is active but not yet served.
pub(crate) struct Started {
    process: Arc<BrokerProcess>,
    runner: Runner,
    active: Active,
}

impl Started {
    /// Serves the process on a thread of its own, which reaps its runner, completes its exit and
    /// calls `on_exit` with its containerd exit status.
    pub(crate) fn serve(
        self,
        container: &Arc<Container>,
        on_exit: impl FnOnce(u32) + Send + 'static,
    ) -> Result<()> {
        let process = Arc::clone(&self.process);
        let container = Arc::clone(container);
        std::thread::Builder::new()
            .name("litebox-serve".to_owned())
            .spawn(move || {
                let Self {
                    process,
                    mut runner,
                    active,
                } = self;
                let (mut abnormal, report) = container.serve(active);
                let (status, killed) = runner.wait(EXIT_GRACE);
                // Only the runners this shim kills may die by a signal.
                abnormal |= killed
                    || status
                        .signal()
                        .is_some_and(|signal| signal != libc::SIGKILL);
                let status = runner_status(status);
                drop(runner);
                // As the userland launcher retires processes; a report the guest made takes
                // precedence over `status`.
                let _ = process.fail_start(BrokerError::PeerClosed, abnormal, false);
                process.retire(!abnormal);
                let _ = process.complete_exit(status);
                on_exit(exit_code(report.unwrap_or(status)));
            })
            .map(drop)
            .map_err(|error| {
                // Dropping the closure killed and reaped the runner.
                process.retire(false);
                let _ = process.complete_exit(ProcessExitStatus::Unknown);
                Error::io("cannot serve the process", &error)
            })
    }
}

fn runner_status(status: std::process::ExitStatus) -> ProcessExitStatus {
    match (status.code(), status.signal()) {
        (Some(code), _) => ProcessExitStatus::Exited {
            code: code.cast_unsigned(),
        },
        (None, Some(signal)) => ProcessExitStatus::Signaled {
            signal: signal.cast_unsigned(),
        },
        (None, None) => ProcessExitStatus::Unknown,
    }
}

impl ProcessLauncher for Container {
    fn launch(
        self: Arc<Self>,
        process: Arc<BrokerProcess>,
        startup: ProcessStartupData,
        image: Option<ChildImage>,
    ) -> std::result::Result<(), BrokerError> {
        let runner = match self.runners.spawn(process.id(), false) {
            Ok(runner) => runner,
            Err(error) => {
                log::debug!("cannot start a child's runner: {error}");
                abandon(&process, BrokerError::PeerClosed);
                return Err(BrokerError::PeerClosed);
            }
        };
        let started = self.start(process, runner, startup.payload, image.as_ref());
        // A started runner holds its own copy of the image.
        drop(image);
        let served = started
            .map_err(|error| log::debug!("a child's runner did not start: {error}"))
            .and_then(|started| {
                started
                    .serve(&self, |_| {})
                    .map_err(|error| log::warn!("{error}"))
            });
        served.map_err(|()| BrokerError::PeerClosed)
    }

    fn launch_existing(
        self: Arc<Self>,
        _parent_process_id: ProcessId,
        process: Arc<BrokerProcess>,
        _startup: ProcessStartupData,
        _runner_descriptor: Vec<u8>,
    ) -> std::result::Result<(), BrokerError> {
        // Runners start with native fork disabled, so they never ask to adopt a clone.
        abandon(&process, BrokerError::PolicyDenied);
        Err(BrokerError::PolicyDenied)
    }

    fn create_image(
        &self,
        _capacity: u64,
    ) -> std::result::Result<Box<dyn ProcessImage>, BrokerError> {
        MemfdProcessImage::create()
            .map(|image| Box::new(Image(image)) as Box<dyn ProcessImage>)
            .map_err(|_| BrokerError::OutOfMemory)
    }
}

/// A child's memory image, which its runner receives as a sealed memfd.
struct Image(MemfdProcessImage);

impl ProcessImage for Image {
    fn write(&mut self, offset: u64, data: &[u8]) -> std::result::Result<(), BrokerError> {
        self.0
            .write(offset, data)
            .map_err(|_| BrokerError::OutOfMemory)
    }

    fn write_from_shared(
        &mut self,
        offset: u64,
        memory: &dyn std::any::Any,
        range: std::ops::Range<usize>,
    ) -> Option<std::result::Result<(), BrokerError>> {
        let memory = memory.downcast_ref::<MemfdSharedMemory>()?;
        Some(
            self.0
                .write_from_shared(offset, memory, range)
                .map_err(|_| BrokerError::OutOfMemory),
        )
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// The broker for `plan` with the root directory `root`, whose sockets are confined to the
/// container's own guest network.
fn build_core(plan: &ContainerPlan, root: &Path) -> Result<BrokerCore> {
    let composer = compose(plan, root)?;
    let policy = PolicyEngine::with_host_guaranteed_rights(ObjectRights::all())
        .with_socket_policy(SocketPolicy::guest_network())
        .with_process_duplication_enabled(true);
    BrokerCoreBuilder::new(policy)
        .with_file_service(Arc::new(Resolver::<LinuxSyncPrimitivesProvider, _>::new(
            composer,
        )))
        .build()
        .map_err(|error| Error::io("cannot build the broker", &error))
}

/// The container's file system for `plan`: the host directory `root` and each directory bind
/// source served as an image, each file bind served by the image that serves its parent
/// directory, the plan's tmpfs mounts, and LiteBox's devices at `/dev`.
///
/// Mounts are served at their lexical destinations. A missing part of the destination of a
/// directory bind or tmpfs is served as a directory; a file bind needs its parent directory in
/// the image that serves it, which [`Container::new`] creates.
fn compose(plan: &ContainerPlan, root: &Path) -> Result<Composer> {
    enum Served<'a> {
        Image {
            host: &'a Path,
            read_only: bool,
            files: Vec<FileBind>,
        },
        Tmpfs,
    }
    // By destination, with the root's as the empty string, so that every destination extends
    // that of the mounts above it.
    let mut served = vec![(
        "",
        Served::Image {
            host: root,
            read_only: plan.root_read_only,
            files: Vec::new(),
        },
    )];
    let mut files = Vec::new();
    for mount in &plan.mounts {
        let destination = mount.destination.as_str();
        let MountKind::Bind { source, read_only } = &mount.kind else {
            served.push((destination, Served::Tmpfs));
            continue;
        };
        let read_only = *read_only;
        match std::fs::metadata(source) {
            Ok(metadata) if metadata.is_dir() => served.push((
                destination,
                Served::Image {
                    host: source,
                    read_only,
                    files: Vec::new(),
                },
            )),
            Ok(metadata) if metadata.is_file() => files.push((destination, source, read_only)),
            Ok(_) => {
                return Err(Error::unimplemented(format!(
                    "the source of the mount at {destination} is neither a directory nor a \
                     regular file, which is not supported"
                )));
            }
            Err(error) => {
                return Err(Error::invalid(format!(
                    "cannot inspect the source of the mount at {destination}: {error}"
                )));
            }
        }
    }
    for (destination, source, read_only) in files {
        // As on Linux, a file is not a directory.
        if let Some(mount) = plan.mounts.iter().find(|mount| {
            below(&mount.destination, destination).is_some_and(|rest| !rest.is_empty())
        }) {
            return Err(Error::invalid(format!(
                "the mount at {} is below the file bound at {destination}",
                mount.destination
            )));
        }
        let (parent, name) = destination
            .rsplit_once('/')
            .expect("mount destinations are absolute");
        let (dir, owner) = served
            .iter_mut()
            .filter_map(|(base, owner)| Some((base.len(), below(parent, base)?, owner)))
            .max_by_key(|(length, ..)| *length)
            .map(|(_, dir, owner)| (dir, owner))
            .expect("the root serves every destination");
        let Served::Image { files, .. } = owner else {
            return Err(Error::unimplemented(format!(
                "the file bound at {destination} is in a tmpfs, which is not supported"
            )));
        };
        files.push(FileBind {
            dir: dir.into(),
            name: name.to_owned(),
            source: source.clone(),
            read_only,
        });
    }
    let mut composer = Composer::builder();
    for (destination, served) in served {
        let destination = if destination.is_empty() {
            "/"
        } else {
            destination
        };
        composer = match served {
            Served::Image {
                host,
                read_only,
                files,
            } => composer
                .try_mount_nestable(destination, |allocators| {
                    ImageFs::new(host, read_only, &files, allocators)
                })
                .map_err(|error| Error::io(&format!("cannot serve {destination}"), &error))?,
            Served::Tmpfs => composer.mount(destination, InMem::<LinuxSyncPrimitivesProvider>::new),
        };
    }
    // `/dev/std*` belong to no task: each task has its own descriptors 0 to 2.
    composer
        .mount("/dev", |allocator| {
            Devices::new(
                allocator,
                Arc::new(UnsupportedStdioProvider),
                Arc::new(UserlandRandomProvider),
            )
        })
        .build()
        .map_err(|error| Error::invalid(format!("cannot compose the file system: {error}")))
}

/// The guest path `path` relative to `base`, if it is or is below `base`.
fn below<'a>(path: &'a str, base: &str) -> Option<&'a str> {
    path.strip_prefix(base)
        .filter(|rest| rest.is_empty() || rest.starts_with('/'))
        .map(|rest| rest.trim_start_matches('/'))
}

fn encode_startup(
    spec: &ProcessSpec,
    env: &[String],
    path: String,
    cwd: String,
    inherited_fds: Vec<InheritedFd>,
) -> Result<Vec<u8>> {
    let strings = |values: &[String]| {
        values
            .iter()
            .map(|value| CString::new(value.as_str()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::invalid("a process argument or variable contains a NUL byte"))
    };
    LinuxProgramStartup {
        uid: spec.uid,
        euid: spec.uid,
        gid: spec.gid,
        egid: spec.gid,
        blocked_signals: SigSet::empty(),
        ignored_signals: SigSet::empty(),
        umask: spec.umask,
        #[cfg(target_arch = "aarch64")]
        sve_vl_inherit: false,
        path,
        cwd,
        argv: strings(&spec.args)?,
        envp: strings(env)?,
        inherited_fds,
    }
    .encode()
    .map_err(|error| Error::invalid(format!("cannot start the process: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reported_exit_statuses_never_overflow() {
        let cases = [
            (ProcessExitStatus::Exited { code: 3 }, 3),
            (ProcessExitStatus::Exited { code: 256 }, 255),
            (ProcessExitStatus::Exited { code: u32::MAX }, 255),
            (ProcessExitStatus::Signaled { signal: 9 }, 137),
            (ProcessExitStatus::Signaled { signal: 64 }, 192),
            (ProcessExitStatus::Signaled { signal: 0 }, 255),
            (ProcessExitStatus::Signaled { signal: 65 }, 255),
            (ProcessExitStatus::Signaled { signal: u32::MAX }, 255),
            (ProcessExitStatus::Unknown, 255),
        ];
        for (status, code) in cases {
            assert_eq!(exit_code(status), code, "{status:?}");
        }
    }
}
