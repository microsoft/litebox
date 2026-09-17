// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Reusable ownership for one out-of-process LiteBox runner.

use std::ffi::{OsStr, OsString};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerProcess};
use litebox_broker_host::{BrokerHostExtensionError, copy_shared_buffer};
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult};
use litebox_broker_protocol::process::{
    MAX_PROCESS_BOOTSTRAP_SIZE, ProcessBootstrapFormat, ProcessBootstrapVersion, ProcessStartToken,
    StartedProcess,
};
use litebox_broker_protocol::{ObjectHandle, ProcessId, ThreadId};
use litebox_broker_transport::shared_memory::{SharedBufferPool, SharedMemory};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;

#[cfg(target_os = "linux")]
use linux::PlatformRunnerEndpoint;
#[cfg(all(windows, target_arch = "x86_64"))]
use windows::PlatformRunnerEndpoint;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);
const CHILD_ARGUMENT: &str = "--child";
const MAX_PENDING_CHILD_STARTS: usize = crate::WORKER_COUNT - 1;
const _: () = assert!(MAX_PENDING_CHILD_STARTS > 0);

/// Configuration for starting one out-of-process runner.
///
/// Dynamically started descendants use the same executable with the hidden
/// `--child` argument instead of the root arguments.
#[derive(Clone)]
pub struct RunnerConfig {
    executable: PathBuf,
    arguments: Vec<OsString>,
    proxy_url: Option<String>,
}

impl RunnerConfig {
    /// Creates runner configuration with opaque arguments passed after the
    /// broker transport arguments.
    #[must_use]
    pub fn new(executable: PathBuf, arguments: Vec<OsString>) -> Self {
        Self {
            executable,
            arguments,
            proxy_url: None,
        }
    }

    /// Configures the HTTP proxy URL passed to the runner.
    #[must_use]
    pub fn with_proxy_url(mut self, proxy_url: String) -> Self {
        self.proxy_url = Some(proxy_url);
        self
    }

    fn arguments(&self, control_channel: &OsStr) -> Vec<OsString> {
        let mut arguments = vec![
            OsString::from("--unstable"),
            OsString::from("--broker-control-channel"),
            control_channel.to_os_string(),
        ];
        if let Some(proxy_url) = &self.proxy_url {
            arguments.push(OsString::from("--broker-proxy-url"));
            arguments.push(OsString::from(proxy_url));
        }
        arguments.extend(self.arguments.iter().cloned());
        arguments
    }

    fn child(&self) -> Self {
        Self {
            executable: self.executable.clone(),
            arguments: vec![OsString::from(CHILD_ARGUMENT)],
            proxy_url: self.proxy_url.clone(),
        }
    }
}

/// One out-of-process runner and its dedicated broker control endpoint.
///
/// Dropping an instance before [`Self::run_to_completion`] completes
/// terminates and reaps the runner.
pub struct RunnerInstance {
    runner: Child,
    endpoint: PlatformRunnerEndpoint,
    child_config: RunnerConfig,
}

impl RunnerInstance {
    /// Creates the runner's dedicated control endpoint and starts the runner.
    pub fn start(config: RunnerConfig) -> IoResult<Self> {
        let endpoint = PlatformRunnerEndpoint::create()?;
        let runner = Command::new(&config.executable)
            .args(config.arguments(endpoint.control_channel()))
            .spawn()?;
        let child_config = config.child();
        Ok(Self {
            runner,
            endpoint,
            child_config,
        })
    }

    /// Serves the runner's broker association and waits for its host process.
    ///
    /// Association failure terminates the runner before it is reaped. A
    /// non-successful runner exit is returned as ordinary instance data for the
    /// caller to interpret.
    pub fn run_to_completion(mut self, broker: &BrokerCore) -> IoResult<ExitStatus> {
        let children = RunnerChildren::new(self.child_config.clone(), broker.clone());
        let association_result = self.endpoint.serve(&mut self.runner, Arc::clone(&children));
        self.endpoint.close();
        if association_result.is_err() {
            let _ = self.runner.kill();
        }
        let runner_status = self.runner.wait();
        children.wait_for_drain();
        let runner_status = runner_status?;
        association_result?;
        Ok(runner_status)
    }

    fn run_child_to_completion(
        mut self,
        child: ChildRunner,
        children: Arc<RunnerChildren>,
    ) -> IoResult<ExitStatus> {
        let association_result = self.endpoint.serve_child(&mut self.runner, child, children);
        self.endpoint.close();
        if association_result.is_err() {
            let _ = self.runner.kill();
        }
        let runner_status = self.runner.wait()?;
        association_result?;
        Ok(runner_status)
    }
}

impl Drop for RunnerInstance {
    fn drop(&mut self) {
        self.endpoint.close();
        if !matches!(self.runner.try_wait(), Ok(Some(_status))) {
            let _ = self.runner.kill();
            let _ = self.runner.wait();
        }
    }
}

pub(crate) struct RunnerChildren {
    pub(crate) broker: BrokerCore,
    config: RunnerConfig,
    state: Mutex<RunnerChildrenState>,
    drained: Condvar,
}

pub(crate) struct ChildRunner {
    pub(crate) process: Arc<BrokerProcess>,
    pub(crate) inherited_objects: Vec<ObjectHandle>,
    pub(crate) format: ProcessBootstrapFormat,
    pub(crate) version: ProcessBootstrapVersion,
    pub(crate) bootstrap: Vec<u8>,
}

struct RunnerChildrenState {
    launches: Vec<(ProcessStartToken, Arc<ChildLaunch>)>,
    active_instances: usize,
}

struct ChildLaunch {
    parent_id: ProcessId,
    process: Arc<BrokerProcess>,
    state: Mutex<ChildLaunchState>,
    changed: Condvar,
}

#[derive(Clone, Copy)]
enum ChildLaunchState {
    Starting,
    Ready {
        initial_thread_id: Option<ThreadId>,
        start_result_delivered: bool,
    },
    Committed,
    Aborted(ErrorCode),
}

impl RunnerChildren {
    fn new(config: RunnerConfig, broker: BrokerCore) -> Arc<Self> {
        Arc::new(Self {
            broker,
            config,
            state: Mutex::new(RunnerChildrenState {
                launches: Vec::new(),
                active_instances: 0,
            }),
            drained: Condvar::new(),
        })
    }

    pub(crate) fn handle_operation<Memory: SharedMemory>(
        self: &Arc<Self>,
        process: &BrokerProcess,
        operation: &BrokerOperation,
        shared_buffers: &SharedBufferPool<Memory>,
    ) -> Option<Result<BrokerResult, BrokerHostExtensionError>> {
        match operation {
            BrokerOperation::StartProcess(request) => Some(
                copy_shared_buffer(
                    shared_buffers,
                    request.bootstrap.buffer,
                    MAX_PROCESS_BOOTSTRAP_SIZE,
                )
                .and_then(|bootstrap| {
                    self.start_process(
                        process,
                        request.bootstrap.format,
                        request.bootstrap.version,
                        bootstrap,
                        request.inherited_objects.as_slice(),
                    )
                    .map_err(process_extension_error)
                })
                .map(BrokerResult::ProcessStarted),
            ),
            BrokerOperation::AcknowledgeProcessStart(token) => Some(
                self.acknowledge_process_start(process.id(), *token)
                    .map(|()| BrokerResult::ProcessStartAcknowledged)
                    .map_err(process_extension_error),
            ),
            BrokerOperation::ProcessReady(request) => Some(
                self.process_ready(process.id(), request.initial_thread_id)
                    .map(|()| BrokerResult::ProcessReady)
                    .map_err(process_extension_error),
            ),
            _ => None,
        }
    }

    pub(crate) fn response_sent(&self, parent_id: ProcessId, result: &BrokerResult) {
        let BrokerResult::ProcessStarted(started) = result else {
            return;
        };
        let Some(launch) = self.find_launch(started.token) else {
            return;
        };
        if launch.parent_id == parent_id {
            launch.mark_start_result_delivered();
        }
    }

    fn start_process(
        self: &Arc<Self>,
        parent: &BrokerProcess,
        format: ProcessBootstrapFormat,
        version: ProcessBootstrapVersion,
        bootstrap: Vec<u8>,
        requested_inherited_objects: &[litebox_broker_protocol::ObjectHandle],
    ) -> Result<StartedProcess, ErrorCode> {
        if !parent.is_running() {
            return Err(ErrorCode::ProtocolState);
        }
        let (process, inherited_objects) = parent
            .create_child(requested_inherited_objects)
            .map_err(ErrorCode::from)?;
        let child_id = process.id();
        let launch = Arc::new(ChildLaunch {
            parent_id: parent.id(),
            process: Arc::clone(&process),
            state: Mutex::new(ChildLaunchState::Starting),
            changed: Condvar::new(),
        });
        let token = match (|| {
            loop {
                let mut token = [0; 8];
                getrandom::fill(&mut token).map_err(|_| ErrorCode::Internal)?;
                let token = ProcessStartToken(u64::from_ne_bytes(token));
                let mut state = self
                    .state
                    .lock()
                    .expect("runner child state mutex poisoned");
                state
                    .launches
                    .try_reserve(1)
                    .map_err(|_| ErrorCode::OutOfMemory)?;
                if parent.is_cancellation_requested() {
                    return Err(ErrorCode::PeerClosed);
                }
                if state.launches.len() >= MAX_PENDING_CHILD_STARTS {
                    return Err(ErrorCode::ResourceExhausted);
                }
                if state
                    .launches
                    .iter()
                    .any(|(candidate, _)| *candidate == token)
                {
                    continue;
                }
                let active_instances = state
                    .active_instances
                    .checked_add(1)
                    .ok_or(ErrorCode::ResourceExhausted)?;
                state.launches.push((token, Arc::clone(&launch)));
                state.active_instances = active_instances;
                return Ok(token);
            }
        })() {
            Ok(token) => token,
            Err(error) => {
                BrokerProcess::finish(process);
                return Err(error);
            }
        };

        let children = Arc::clone(self);
        let config = self.config.clone();
        let thread_launch = Arc::clone(&launch);
        let thread = std::thread::Builder::new()
            .name(format!("litebox-runner-{}", child_id.0))
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    RunnerInstance::start(config).and_then(|instance| {
                        instance.run_child_to_completion(
                            ChildRunner {
                                process,
                                inherited_objects,
                                format,
                                version,
                                bootstrap,
                            },
                            Arc::clone(&children),
                        )
                    })
                }));
                match outcome {
                    Ok(result) => children.child_finished(token, &thread_launch, result, false),
                    Err(_) => children.child_finished(
                        token,
                        &thread_launch,
                        Err(IoError::other("child runner thread panicked")),
                        true,
                    ),
                }
            });
        if thread.is_err() {
            self.remove_launch(token);
            BrokerProcess::finish(Arc::clone(&launch.process));
            self.finish_instance();
            return Err(ErrorCode::OutOfMemory);
        }
        drop(thread);

        let initial_thread_id = launch.wait_until_ready()?;
        Ok(StartedProcess {
            token,
            process_id: child_id,
            initial_thread_id,
        })
    }

    fn acknowledge_process_start(
        &self,
        parent_id: ProcessId,
        token: ProcessStartToken,
    ) -> Result<(), ErrorCode> {
        let launch = self.find_launch(token).ok_or(ErrorCode::UnknownObject)?;
        if launch.parent_id != parent_id {
            return Err(ErrorCode::UnknownObject);
        }
        launch.commit()?;
        self.remove_launch(token);
        Ok(())
    }

    fn process_ready(
        &self,
        child_id: ProcessId,
        initial_thread_id: Option<ThreadId>,
    ) -> Result<(), ErrorCode> {
        let launch = self
            .find_child_launch(child_id)
            .ok_or(ErrorCode::ProtocolState)?;
        launch.ready_and_wait(initial_thread_id)
    }

    pub(crate) fn association_ended(&self, process_id: ProcessId) {
        loop {
            let launch = {
                let mut state = self
                    .state
                    .lock()
                    .expect("runner child state mutex poisoned");
                state
                    .launches
                    .iter()
                    .position(|(_, launch)| {
                        launch.parent_id == process_id || launch.process.id() == process_id
                    })
                    .map(|index| state.launches.swap_remove(index).1)
            };
            let Some(launch) = launch else {
                break;
            };
            launch.abort(ErrorCode::PeerClosed);
        }
    }

    fn find_launch(&self, token: ProcessStartToken) -> Option<Arc<ChildLaunch>> {
        self.state
            .lock()
            .expect("runner child state mutex poisoned")
            .launches
            .iter()
            .find_map(|(candidate, launch)| (*candidate == token).then(|| Arc::clone(launch)))
    }

    fn find_child_launch(&self, child_id: ProcessId) -> Option<Arc<ChildLaunch>> {
        self.state
            .lock()
            .expect("runner child state mutex poisoned")
            .launches
            .iter()
            .find_map(|(_, launch)| (launch.process.id() == child_id).then(|| Arc::clone(launch)))
    }

    fn remove_launch(&self, token: ProcessStartToken) {
        let mut state = self
            .state
            .lock()
            .expect("runner child state mutex poisoned");
        if let Some(index) = state
            .launches
            .iter()
            .position(|(candidate, _)| *candidate == token)
        {
            state.launches.swap_remove(index);
        }
    }

    fn child_finished(
        &self,
        token: ProcessStartToken,
        launch: &ChildLaunch,
        result: IoResult<ExitStatus>,
        panicked: bool,
    ) {
        if result.is_err() || result.is_ok_and(|status| !status.success()) {
            launch.abort(ErrorCode::PeerClosed);
        }
        self.remove_launch(token);
        if !panicked {
            BrokerProcess::finish(Arc::clone(&launch.process));
        }
        self.finish_instance();
    }

    fn finish_instance(&self) {
        let mut state = self
            .state
            .lock()
            .expect("runner child state mutex poisoned");
        state.active_instances = state
            .active_instances
            .checked_sub(1)
            .expect("runner child count must remain balanced");
        if state.active_instances == 0 {
            self.drained.notify_all();
        }
    }

    fn wait_for_drain(&self) {
        let mut state = self
            .state
            .lock()
            .expect("runner child state mutex poisoned");
        while state.active_instances != 0 {
            state = self
                .drained
                .wait(state)
                .expect("runner child state mutex poisoned");
        }
    }
}

const fn process_extension_error(error: ErrorCode) -> BrokerHostExtensionError {
    match error {
        ErrorCode::PolicyDenied
        | ErrorCode::UnknownObject
        | ErrorCode::InvalidRights
        | ErrorCode::ResourceExhausted
        | ErrorCode::WouldBlock
        | ErrorCode::PeerClosed
        | ErrorCode::OutOfMemory
        | ErrorCode::UnsupportedOperation => BrokerHostExtensionError::Respond(error),
        _ => BrokerHostExtensionError::Abort(error),
    }
}

impl ChildLaunch {
    fn wait_until_ready(&self) -> Result<Option<ThreadId>, ErrorCode> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        loop {
            match *state {
                ChildLaunchState::Starting => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("child launch mutex poisoned");
                }
                ChildLaunchState::Ready {
                    initial_thread_id, ..
                } => return Ok(initial_thread_id),
                ChildLaunchState::Committed => return Err(ErrorCode::ProtocolState),
                ChildLaunchState::Aborted(error) => return Err(error),
            }
        }
    }

    fn ready_and_wait(&self, initial_thread_id: Option<ThreadId>) -> Result<(), ErrorCode> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        if !matches!(*state, ChildLaunchState::Starting) {
            return Err(ErrorCode::ProtocolState);
        }
        *state = ChildLaunchState::Ready {
            initial_thread_id,
            start_result_delivered: false,
        };
        self.changed.notify_all();
        loop {
            match *state {
                ChildLaunchState::Ready { .. } => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("child launch mutex poisoned");
                }
                ChildLaunchState::Committed => return Ok(()),
                ChildLaunchState::Aborted(error) => return Err(error),
                ChildLaunchState::Starting => unreachable!("ready state cannot regress"),
            }
        }
    }

    fn commit(&self) -> Result<(), ErrorCode> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        if !matches!(
            *state,
            ChildLaunchState::Ready {
                start_result_delivered: true,
                ..
            }
        ) {
            return Err(match *state {
                ChildLaunchState::Aborted(error) => error,
                _ => ErrorCode::ProtocolState,
            });
        }
        self.process.commit_start().map_err(ErrorCode::from)?;
        *state = ChildLaunchState::Committed;
        self.changed.notify_all();
        Ok(())
    }

    fn mark_start_result_delivered(&self) {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        if let ChildLaunchState::Ready {
            start_result_delivered,
            ..
        } = &mut *state
        {
            *start_result_delivered = true;
        }
    }

    fn abort(&self, error: ErrorCode) {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        if matches!(
            *state,
            ChildLaunchState::Starting | ChildLaunchState::Ready { .. }
        ) {
            *state = ChildLaunchState::Aborted(error);
            self.changed.notify_all();
        }
    }
}

fn accept_runner_channel<Channel>(
    deadline: Instant,
    channel_name: &'static str,
    mut runner_status: impl FnMut() -> IoResult<Option<String>>,
    mut try_accept: impl FnMut() -> IoResult<Channel>,
) -> IoResult<Channel> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(IoError::new(
                ErrorKind::TimedOut,
                format!("timed out waiting for runner {channel_name} channel"),
            ));
        }
        if let Some(status) = runner_status()? {
            return Err(IoError::new(
                ErrorKind::BrokenPipe,
                format!("runner {status} before connecting its {channel_name} channel"),
            ));
        }
        match try_accept() {
            Ok(channel) => return Ok(channel),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        std::thread::sleep(remaining.min(ACCEPT_RETRY_DELAY));
    }
}
