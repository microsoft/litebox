// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Reusable ownership for one out-of-process LiteBox runner.

use std::ffi::{OsStr, OsString};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::sync::{
    Arc, Condvar, Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerError, BrokerProcess};
use litebox_broker_host::{BrokerHostExtensionError, copy_shared_buffer};
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult};
use litebox_broker_protocol::process::{
    MAX_PROCESS_BOOTSTRAP_SIZE, ProcessBootstrapFormat, ProcessBootstrapVersion, ProcessStartToken,
    StartedProcess,
};
use litebox_broker_protocol::{ObjectHandle, ProcessId, ThreadId};
use litebox_broker_transport::shared_memory::{SharedBufferPool, SharedMemory};

use crate::runtime::AssociationFailureCause;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;

#[cfg(target_os = "linux")]
use linux::PlatformRunnerEndpoint;
#[cfg(all(windows, target_arch = "x86_64"))]
use windows::PlatformRunnerEndpoint;

const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_START_RECEIPT_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_START_INTERNAL_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_START_ACKNOWLEDGEMENT_PUBLICATION_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_START_SUPERVISOR_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_EXIT_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(10);
const CHILD_ARGUMENT: &str = "--child";
const MAX_PENDING_CHILD_STARTS: usize = crate::WORKER_COUNT - 1;
const _: () = assert!(MAX_PENDING_CHILD_STARTS > 0);
const _: () = assert!(crate::runtime::LIFECYCLE_CONTROL_WORKER_COUNT > MAX_PENDING_CHILD_STARTS);
const _: () = assert!(crate::runtime::LIFECYCLE_CONTROL_QUEUE_CAPACITY >= MAX_PENDING_CHILD_STARTS);

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
    runner: Arc<Mutex<Child>>,
    shutdown: Arc<RunnerShutdown>,
    endpoint: PlatformRunnerEndpoint,
    child_config: RunnerConfig,
}

struct ChildRunResult {
    result: IoResult<ExitStatus>,
    runner_success: Option<bool>,
    runner_signal: Option<i32>,
    runner_exit_code: Option<i32>,
    termination_provenance: ChildTerminationProvenance,
    association_panicked: bool,
    shutdown_observation_failed: bool,
}

struct RunnerShutdown {
    runner: Arc<Mutex<Child>>,
    state: Mutex<RunnerShutdownState>,
    changed: Condvar,
    termination_dispatched: AtomicBool,
}

#[derive(Clone, Copy, Default)]
struct ChildTerminationProvenance(u8);

impl ChildTerminationProvenance {
    const BROKER_TERMINATION: u8 = 1;
    const REPORTED_START_FAILURE: u8 = 2;

    const fn new(broker_termination: bool, reported_start_failure: bool) -> Self {
        let mut value = 0;
        if broker_termination {
            value |= Self::BROKER_TERMINATION;
        }
        if reported_start_failure {
            value |= Self::REPORTED_START_FAILURE;
        }
        Self(value)
    }

    const fn broker_termination(self) -> bool {
        self.0 & Self::BROKER_TERMINATION != 0
    }

    const fn reported_start_failure(self) -> bool {
        self.0 & Self::REPORTED_START_FAILURE != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunnerShutdownState {
    Active,
    Firing,
    Fired,
    Retired,
}

impl RunnerShutdown {
    fn shutdown(&self) {
        let mut state = self.state.lock().expect("runner shutdown mutex poisoned");
        loop {
            match *state {
                RunnerShutdownState::Active => {
                    *state = RunnerShutdownState::Firing;
                    break;
                }
                RunnerShutdownState::Firing => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("runner shutdown mutex poisoned");
                }
                RunnerShutdownState::Fired | RunnerShutdownState::Retired => return,
            }
        }
        drop(state);
        let termination_dispatched = {
            // Serialize observation and termination so collecting an exit
            // status can never expose a reusable PID between the check and
            // the kill request.
            let mut runner = self.runner.lock().expect("runner process mutex poisoned");
            match runner.try_wait() {
                Ok(Some(_)) => false,
                Ok(None) => runner.kill().is_ok(),
                Err(_) => {
                    let _ = runner.kill();
                    false
                }
            }
        };
        if termination_dispatched {
            self.termination_dispatched.store(true, Ordering::Release);
        }
        let mut state = self.state.lock().expect("runner shutdown mutex poisoned");
        debug_assert_eq!(*state, RunnerShutdownState::Firing);
        *state = RunnerShutdownState::Fired;
        self.changed.notify_all();
    }

    fn retire(&self) {
        let mut state = self.state.lock().expect("runner shutdown mutex poisoned");
        while *state == RunnerShutdownState::Firing {
            state = self
                .changed
                .wait(state)
                .expect("runner shutdown mutex poisoned");
        }
        *state = RunnerShutdownState::Retired;
        self.changed.notify_all();
    }

    fn has_exited(&self) -> IoResult<bool> {
        runner_has_exited(&self.runner)
    }

    fn termination_was_dispatched(&self) -> bool {
        self.termination_dispatched.load(Ordering::Acquire)
    }

    fn wait_for_exit(&self, timeout: Duration) -> IoResult<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.has_exited()? {
                return Ok(true);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            std::thread::sleep(remaining.min(ACCEPT_RETRY_DELAY));
        }
    }
}

impl RunnerInstance {
    /// Creates the runner's dedicated control endpoint and starts the runner.
    pub fn start(config: RunnerConfig) -> IoResult<Self> {
        let endpoint = PlatformRunnerEndpoint::create()?;
        let runner = Arc::new(Mutex::new(
            Command::new(&config.executable)
                .args(config.arguments(endpoint.control_channel()))
                .spawn()?,
        ));
        let shutdown = Arc::new(RunnerShutdown {
            runner: Arc::clone(&runner),
            state: Mutex::new(RunnerShutdownState::Active),
            changed: Condvar::new(),
            termination_dispatched: AtomicBool::new(false),
        });
        let child_config = config.child();
        Ok(Self {
            runner,
            shutdown,
            endpoint,
            child_config,
        })
    }

    /// Serves the runner's broker association and waits for its host process.
    ///
    /// Association failure terminates the runner before it is reaped. A
    /// non-successful runner exit is returned as ordinary instance data for the
    /// caller to interpret.
    ///
    /// # Panics
    ///
    /// Panics if another runner owner poisoned the process mutex.
    pub fn run_to_completion(mut self, broker: &BrokerCore) -> IoResult<ExitStatus> {
        let children = RunnerChildren::new(self.child_config.clone(), broker.clone());
        let mut association_result = self.endpoint.serve(&self.runner, Arc::clone(&children));
        self.endpoint.close();
        let runner_exited = if association_result.result.is_ok() {
            self.shutdown
                .wait_for_exit(PROCESS_EXIT_OBSERVATION_TIMEOUT)
        } else {
            self.shutdown.has_exited()
        };
        if !matches!(runner_exited, Ok(true)) {
            self.shutdown.shutdown();
        }
        self.shutdown.retire();
        let runner_status = wait_for_runner_exit(&self.runner);
        let root_abnormal = association_result.abnormal
            || association_result.panicked
            || runner_exited.is_err()
            || runner_status.is_err()
            || runner_status.as_ref().is_ok_and(|status| {
                runner_signal_is_abnormal(
                    runner_exit_signal(*status),
                    self.shutdown.termination_was_dispatched(),
                ) || runner_exit_code_is_crash(status.code())
            });
        if let Some(process) = association_result.process.take() {
            finish_child_process(&process, root_abnormal);
        }
        children.wait_for_drain();
        let runner_status = runner_status?;
        runner_exited?;
        association_result.result?;
        Ok(runner_status)
    }

    fn run_child_to_completion(
        mut self,
        child: ChildRunner,
        children: Arc<RunnerChildren>,
    ) -> ChildRunResult {
        let launch = Arc::clone(&child.launch);
        launch.install_shutdown(Arc::clone(&self.shutdown));
        let association_result = self.endpoint.serve_child(&self.runner, child, children);
        self.endpoint.close();
        let shutdown_request = launch.shutdown_request();
        let shutdown_was_expected = shutdown_request.was_expected();
        if association_result.abnormal {
            launch.mark_abnormal();
        }
        let runner_exited = if !shutdown_was_expected
            && matches!(
                association_result.failure_cause,
                AssociationFailureCause::None | AssociationFailureCause::PeerClosed
            )
            && !association_result.panicked
        {
            self.shutdown
                .wait_for_exit(PROCESS_EXIT_OBSERVATION_TIMEOUT)
        } else {
            self.shutdown.has_exited()
        };
        let shutdown_observation_failed = match runner_exited {
            Ok(true) => {
                if association_result.failure_cause == AssociationFailureCause::Other {
                    launch.mark_abnormal();
                }
                false
            }
            Ok(false) => {
                if !shutdown_was_expected
                    || association_result.failure_cause == AssociationFailureCause::Other
                {
                    launch.mark_abnormal();
                }
                launch.mark_shutdown_expected();
                self.shutdown.shutdown();
                false
            }
            Err(_) => {
                launch.mark_abnormal();
                self.shutdown.shutdown();
                true
            }
        };
        self.shutdown.retire();
        let runner_status = wait_for_runner_exit(&self.runner);
        if runner_status.is_err() {
            launch.mark_abnormal();
        }
        let runner_success = runner_status.as_ref().ok().map(ExitStatus::success);
        let runner_signal = runner_status
            .as_ref()
            .ok()
            .copied()
            .and_then(runner_exit_signal);
        let runner_exit_code = runner_status.as_ref().ok().and_then(ExitStatus::code);
        let termination_provenance = ChildTerminationProvenance::new(
            self.shutdown.termination_was_dispatched(),
            shutdown_request.expected_start_failure_was_reported(),
        );
        let result = runner_status.and_then(|status| {
            association_result.result?;
            Ok(status)
        });
        ChildRunResult {
            result,
            runner_success,
            runner_signal,
            runner_exit_code,
            termination_provenance,
            association_panicked: association_result.panicked,
            shutdown_observation_failed,
        }
    }
}

impl Drop for RunnerInstance {
    fn drop(&mut self) {
        self.endpoint.close();
        self.shutdown.shutdown();
        self.shutdown.retire();
        let _ = wait_for_runner_exit(&self.runner);
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
    pub(crate) launch: Arc<ChildLaunch>,
    pub(crate) inherited_objects: Vec<ObjectHandle>,
    pub(crate) format: ProcessBootstrapFormat,
    pub(crate) version: ProcessBootstrapVersion,
    pub(crate) bootstrap: Vec<u8>,
}

struct RunnerChildrenState {
    launches: Vec<(ProcessStartToken, Arc<ChildLaunch>)>,
    associations: Vec<(ProcessId, AssociationFailure)>,
    active_instances: usize,
    active_watchdogs: usize,
}

pub(crate) type AssociationFailure = Arc<dyn Fn() + Send + Sync>;

pub(crate) struct ChildLaunch {
    parent_id: ProcessId,
    process: Arc<BrokerProcess>,
    state: Mutex<ChildLaunchData>,
    changed: Condvar,
}

#[derive(Clone, Copy)]
enum ChildLaunchPhase {
    Starting,
    Ready { initial_thread_id: Option<ThreadId> },
    Committing,
    Committed,
    Aborted(ErrorCode),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StartResultPublication {
    NotStarted,
    Publishing,
    Delivered,
}

struct ChildLaunchData {
    phase: ChildLaunchPhase,
    publication: StartResultPublication,
    shutdown: Option<Arc<RunnerShutdown>>,
    association_failure: Option<AssociationFailure>,
    shutdown_request: ShutdownRequest,
    abnormal: bool,
    receipt: ReceiptState,
    resolution_watchdog: DeadlineState,
    acknowledgement_publication_watchdog: DeadlineState,
    start_failure_publication_watchdog: DeadlineState,
    active_control_callbacks: usize,
    pinned_initial_thread_id: Option<ThreadId>,
    runner_finished: bool,
    finalization_taken: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShutdownRequest {
    None,
    Expected,
    ExpectedStartFailurePending,
    ExpectedStartFailure,
    Unexpected,
}

impl ShutdownRequest {
    const fn was_expected(self) -> bool {
        matches!(
            self,
            Self::Expected | Self::ExpectedStartFailurePending | Self::ExpectedStartFailure
        )
    }

    const fn expected_start_failure_was_reported(self) -> bool {
        matches!(
            self,
            Self::ExpectedStartFailurePending | Self::ExpectedStartFailure
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReceiptState {
    AwaitingAcknowledgement,
    AcknowledgementAdmitted,
    TimeoutPending,
    Draining,
    Resolved,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DeadlineState {
    Unarmed,
    Armed(Instant),
    Disarmed,
    Fired,
}

enum ProcessStartAcknowledgement {
    Acknowledged,
    Failed(ErrorCode),
}

struct ReceiptExpiration {
    shutdown: Option<Arc<RunnerShutdown>>,
    association_failure: Option<AssociationFailure>,
    fail_parent: bool,
    commit_supervision_deadline: Option<Instant>,
}

enum ReceiptResolution {
    Resolved(Option<bool>),
    DeferredToDrain,
}

impl RunnerChildren {
    fn new(config: RunnerConfig, broker: BrokerCore) -> Arc<Self> {
        Arc::new(Self {
            broker,
            config,
            state: Mutex::new(RunnerChildrenState {
                launches: Vec::new(),
                associations: Vec::new(),
                active_instances: 0,
                active_watchdogs: 0,
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
            BrokerOperation::AcknowledgeProcessStart(token) => {
                Some(match self.resolve_acknowledgement(process.id(), *token) {
                    Ok(ProcessStartAcknowledgement::Acknowledged) => {
                        Ok(BrokerResult::ProcessStartAcknowledged)
                    }
                    Ok(ProcessStartAcknowledgement::Failed(error)) => {
                        Ok(BrokerResult::ProcessStartFailed(error))
                    }
                    Err(error) => Err(BrokerHostExtensionError::Abort(error)),
                })
            }
            BrokerOperation::ProcessReady(request) => Some(
                self.process_ready(process.id(), request.initial_thread_id)
                    .map(|()| BrokerResult::ProcessReady)
                    .map_err(process_extension_error),
            ),
            BrokerOperation::ReportProcessStartFailure(error) => Some(
                self.report_process_start_failure(process.id(), *error)
                    .map(|()| BrokerResult::ProcessStartFailed(*error))
                    .map_err(process_extension_error),
            ),
            _ => None,
        }
    }

    pub(crate) fn response_sent(
        &self,
        process_id: ProcessId,
        operation: &BrokerOperation,
        result: &BrokerResult,
    ) {
        match (operation, result) {
            (_, BrokerResult::ProcessStarted(started)) => {
                let Some(launch) = self.find_launch(started.token) else {
                    return;
                };
                if launch.parent_id == process_id {
                    launch.mark_start_result_delivered();
                }
            }
            (
                BrokerOperation::AcknowledgeProcessStart(token),
                BrokerResult::ProcessStartAcknowledged | BrokerResult::ProcessStartFailed(_),
            ) => {
                let Some(launch) = self.find_launch(*token) else {
                    return;
                };
                if launch.parent_id != process_id {
                    return;
                }
                if let ReceiptResolution::Resolved(finalization) = launch.resolve_receipt() {
                    self.remove_launch(*token);
                    if let Some(abnormal) = finalization {
                        self.finish_child_launch(&launch, abnormal);
                    }
                }
            }
            (
                BrokerOperation::ReportProcessStartFailure(error),
                BrokerResult::ProcessStartFailed(reported),
            ) if error == reported => {
                if let Some(launch) = self.find_child_launch(process_id) {
                    launch.start_failure_response_sent(*error);
                }
            }
            _ => {}
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
            state: Mutex::new(ChildLaunchData {
                phase: ChildLaunchPhase::Starting,
                publication: StartResultPublication::NotStarted,
                shutdown: None,
                association_failure: None,
                shutdown_request: ShutdownRequest::None,
                abnormal: false,
                receipt: ReceiptState::AwaitingAcknowledgement,
                resolution_watchdog: DeadlineState::Unarmed,
                acknowledgement_publication_watchdog: DeadlineState::Unarmed,
                start_failure_publication_watchdog: DeadlineState::Unarmed,
                active_control_callbacks: 0,
                pinned_initial_thread_id: None,
                runner_finished: false,
                finalization_taken: false,
            }),
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
                    RunnerInstance::start(config).map(|instance| {
                        instance.run_child_to_completion(
                            ChildRunner {
                                process,
                                launch: Arc::clone(&thread_launch),
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
                    Ok(Ok(result)) => children.child_finished(token, &thread_launch, result, false),
                    Ok(Err(error)) => children.child_finished(
                        token,
                        &thread_launch,
                        ChildRunResult {
                            result: Err(error),
                            runner_success: None,
                            runner_signal: None,
                            runner_exit_code: None,
                            termination_provenance: ChildTerminationProvenance::default(),
                            association_panicked: false,
                            shutdown_observation_failed: false,
                        },
                        false,
                    ),
                    Err(_) => children.child_finished(
                        token,
                        &thread_launch,
                        ChildRunResult {
                            result: Err(IoError::other("child runner thread panicked")),
                            runner_success: None,
                            runner_signal: None,
                            runner_exit_code: None,
                            termination_provenance: ChildTerminationProvenance::default(),
                            association_panicked: false,
                            shutdown_observation_failed: false,
                        },
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
        let receipt_deadline = launch.begin_start_result_publication()?;
        if self
            .arm_initial_receipt_deadline(token, &launch, receipt_deadline)
            .is_err()
        {
            if let Some(expiration) = launch.expire_initial_receipt_deadline() {
                self.apply_receipt_expiration(
                    token,
                    &launch,
                    expiration,
                    self.find_association_failure(launch.parent_id),
                );
            }
            return Err(ErrorCode::OutOfMemory);
        }
        Ok(StartedProcess {
            token,
            process_id: child_id,
            initial_thread_id,
        })
    }

    pub(crate) fn admit_acknowledgement(
        self: &Arc<Self>,
        parent_id: ProcessId,
        token: ProcessStartToken,
    ) -> Result<(), ErrorCode> {
        let launch = self.find_launch(token).ok_or(ErrorCode::UnknownObject)?;
        if launch.parent_id != parent_id {
            return Err(ErrorCode::UnknownObject);
        }
        launch.admit_acknowledgement()?;
        if self
            .arm_internal_resolution_watchdog(token, &launch)
            .is_err()
        {
            if let Some(expiration) = launch.fail_internal_resolution_watchdog() {
                self.apply_receipt_expiration(
                    token,
                    &launch,
                    expiration,
                    self.find_association_failure(launch.parent_id),
                );
            }
            return Err(ErrorCode::Internal);
        }
        if self
            .arm_acknowledgement_publication_watchdog(token, &launch)
            .is_err()
        {
            if let Some(expiration) = launch.fail_internal_resolution_watchdog() {
                self.apply_receipt_expiration(
                    token,
                    &launch,
                    expiration,
                    self.find_association_failure(launch.parent_id),
                );
            }
            return Err(ErrorCode::Internal);
        }
        Ok(())
    }

    fn resolve_acknowledgement(
        &self,
        parent_id: ProcessId,
        token: ProcessStartToken,
    ) -> Result<ProcessStartAcknowledgement, ErrorCode> {
        let launch = self.find_launch(token).ok_or(ErrorCode::PeerClosed)?;
        if launch.parent_id != parent_id {
            return Err(ErrorCode::UnknownObject);
        }
        launch.resolve_acknowledgement()
    }

    fn process_ready(
        &self,
        child_id: ProcessId,
        initial_thread_id: Option<ThreadId>,
    ) -> Result<(), ErrorCode> {
        let launch = self
            .find_child_launch(child_id)
            .ok_or(ErrorCode::PeerClosed)?;
        launch.ready_and_wait(initial_thread_id)
    }

    fn report_process_start_failure(
        self: &Arc<Self>,
        child_id: ProcessId,
        error: ErrorCode,
    ) -> Result<(), ErrorCode> {
        let (token, launch) = self
            .find_child_launch_entry(child_id)
            .ok_or(ErrorCode::PeerClosed)?;
        launch.report_start_failure(error)?;
        if self
            .arm_start_failure_publication_watchdog(token, &launch)
            .is_err()
        {
            if let Some(expiration) = launch.fail_start_failure_publication_watchdog() {
                self.apply_receipt_expiration(token, &launch, expiration, None);
            }
            return Err(ErrorCode::Internal);
        }
        Ok(())
    }

    pub(crate) fn association_ending(&self, process_id: ProcessId) -> Vec<Arc<ChildLaunch>> {
        let draining = self
            .state
            .lock()
            .expect("runner child state mutex poisoned")
            .launches
            .iter()
            .filter(|(_, launch)| launch.parent_id == process_id)
            .map(|(_, launch)| Arc::clone(launch))
            .collect::<Vec<_>>();
        for launch in &draining {
            launch.abort(ErrorCode::PeerClosed, false, true);
            launch.begin_receipt_drain();
        }

        let child_launch = {
            self.state
                .lock()
                .expect("runner child state mutex poisoned")
                .launches
                .iter()
                .find_map(|(_, launch)| {
                    (launch.process.id() == process_id).then(|| Arc::clone(launch))
                })
        };
        if let Some(launch) = child_launch {
            launch.association_closed();
        }
        draining
    }

    pub(crate) fn association_ended(&self, process_id: ProcessId, draining: Vec<Arc<ChildLaunch>>) {
        self.unregister_association(process_id);
        for launch in draining {
            self.remove_launch_by_process_id(launch.process.id());
            if let Some(abnormal) = launch.finish_receipt_drain() {
                self.finish_child_launch(&launch, abnormal);
            }
        }
    }

    pub(crate) fn register_association(
        &self,
        process_id: ProcessId,
        failure: AssociationFailure,
    ) -> IoResult<()> {
        let mut state = self
            .state
            .lock()
            .expect("runner child state mutex poisoned");
        state
            .associations
            .try_reserve(1)
            .map_err(|_| IoError::other("failed to reserve broker association registration"))?;
        if state
            .associations
            .iter()
            .any(|(candidate, _)| *candidate == process_id)
        {
            return Err(IoError::other(
                "a broker process already has a live association",
            ));
        }
        state.associations.push((process_id, failure));
        Ok(())
    }

    pub(crate) fn install_child_association_failure(
        &self,
        process_id: ProcessId,
        failure: AssociationFailure,
    ) {
        if let Some(launch) = self.find_child_launch(process_id) {
            launch.install_association_failure(failure);
        }
    }

    fn unregister_association(&self, process_id: ProcessId) {
        let mut state = self
            .state
            .lock()
            .expect("runner child state mutex poisoned");
        if let Some(index) = state
            .associations
            .iter()
            .position(|(candidate, _)| *candidate == process_id)
        {
            state.associations.swap_remove(index);
        }
    }

    fn find_association_failure(&self, process_id: ProcessId) -> Option<AssociationFailure> {
        self.state
            .lock()
            .expect("runner child state mutex poisoned")
            .associations
            .iter()
            .find_map(|(candidate, failure)| {
                (*candidate == process_id).then(|| Arc::clone(failure))
            })
    }

    fn arm_initial_receipt_deadline(
        self: &Arc<Self>,
        token: ProcessStartToken,
        launch: &Arc<ChildLaunch>,
        deadline: Instant,
    ) -> Result<(), ()> {
        let launch = Arc::clone(launch);
        let parent_failure = self.find_association_failure(launch.parent_id);
        self.spawn_watchdog(
            format!("litebox-start-receipt-{}", launch.process.id().0),
            move |children| {
                let Some(expiration) = launch.wait_for_initial_receipt_deadline(deadline) else {
                    return;
                };
                children.apply_receipt_expiration(token, &launch, expiration, parent_failure);
            },
        )
    }

    fn arm_internal_resolution_watchdog(
        self: &Arc<Self>,
        token: ProcessStartToken,
        launch: &Arc<ChildLaunch>,
    ) -> Result<(), ()> {
        let launch = Arc::clone(launch);
        let parent_failure = self.find_association_failure(launch.parent_id);
        self.spawn_watchdog(
            format!("litebox-start-resolution-{}", launch.process.id().0),
            move |children| {
                let Some(expiration) = launch.wait_for_internal_resolution_timeout() else {
                    return;
                };
                children.apply_receipt_expiration(token, &launch, expiration, parent_failure);
            },
        )
    }

    fn arm_acknowledgement_publication_watchdog(
        self: &Arc<Self>,
        token: ProcessStartToken,
        launch: &Arc<ChildLaunch>,
    ) -> Result<(), ()> {
        let launch = Arc::clone(launch);
        let parent_failure = self.find_association_failure(launch.parent_id);
        self.spawn_watchdog(
            format!("litebox-start-ack-publication-{}", launch.process.id().0),
            move |children| {
                let Some(expiration) = launch.wait_for_acknowledgement_publication_timeout() else {
                    return;
                };
                children.apply_receipt_expiration(token, &launch, expiration, parent_failure);
            },
        )
    }

    fn arm_start_failure_publication_watchdog(
        self: &Arc<Self>,
        token: ProcessStartToken,
        launch: &Arc<ChildLaunch>,
    ) -> Result<(), ()> {
        let launch = Arc::clone(launch);
        self.spawn_watchdog(
            format!(
                "litebox-start-failure-publication-{}",
                launch.process.id().0
            ),
            move |children| {
                let Some(expiration) = launch.wait_for_start_failure_publication_timeout() else {
                    return;
                };
                children.apply_receipt_expiration(token, &launch, expiration, None);
            },
        )
    }

    fn spawn_watchdog(
        self: &Arc<Self>,
        name: String,
        watchdog: impl FnOnce(&Arc<Self>) + Send + 'static,
    ) -> Result<(), ()> {
        {
            let mut state = self
                .state
                .lock()
                .expect("runner child state mutex poisoned");
            state.active_watchdogs = state.active_watchdogs.checked_add(1).ok_or(())?;
        }
        let children = Arc::clone(self);
        if let Ok(thread) = std::thread::Builder::new().name(name).spawn(move || {
            let _completion = WatchdogCompletion {
                children: Arc::clone(&children),
            };
            watchdog(&children);
        }) {
            drop(thread);
            Ok(())
        } else {
            self.finish_watchdog();
            Err(())
        }
    }

    fn apply_receipt_expiration(
        &self,
        token: ProcessStartToken,
        launch: &ChildLaunch,
        expiration: ReceiptExpiration,
        parent_failure: Option<AssociationFailure>,
    ) {
        let fail_parent = expiration.fail_parent;
        let commit_supervision_deadline = expiration.commit_supervision_deadline;
        if let Some(association_failure) = expiration.association_failure {
            association_failure();
        }
        if let Some(shutdown) = expiration.shutdown {
            shutdown.shutdown();
        }
        let parent_failed = if fail_parent {
            if let Some(parent_failure) = parent_failure {
                parent_failure();
                true
            } else {
                false
            }
        } else {
            true
        };
        if let Some(abnormal) = launch.complete_timeout_callback() {
            self.finish_child_launch(launch, abnormal);
        }
        if fail_parent && !parent_failed {
            self.remove_launch(token);
            if let Some(abnormal) = launch.finish_receipt_drain() {
                self.finish_child_launch(launch, abnormal);
            }
        }
        if let Some(deadline) = commit_supervision_deadline
            && !launch.wait_for_commit_resolution(deadline)
        {
            std::process::abort();
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
        self.find_child_launch_entry(child_id)
            .map(|(_, launch)| launch)
    }

    fn find_child_launch_entry(
        &self,
        child_id: ProcessId,
    ) -> Option<(ProcessStartToken, Arc<ChildLaunch>)> {
        self.state
            .lock()
            .expect("runner child state mutex poisoned")
            .launches
            .iter()
            .find_map(|(token, launch)| {
                (launch.process.id() == child_id).then(|| (*token, Arc::clone(launch)))
            })
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

    fn remove_launch_by_process_id(&self, process_id: ProcessId) {
        let mut state = self
            .state
            .lock()
            .expect("runner child state mutex poisoned");
        if let Some(index) = state
            .launches
            .iter()
            .position(|(_, launch)| launch.process.id() == process_id)
        {
            state.launches.swap_remove(index);
        }
    }

    fn child_finished(
        &self,
        token: ProcessStartToken,
        launch: &ChildLaunch,
        result: ChildRunResult,
        thread_panicked: bool,
    ) {
        let unexpected_runner_failure = result.runner_success == Some(false)
            && result.runner_signal.is_none()
            && !launch.commit_was_claimed()
            && !result.termination_provenance.reported_start_failure()
            && !runner_exit_code_is_expected_shutdown(
                result.runner_exit_code,
                result.termination_provenance.broker_termination(),
            );
        let unexpected_crash = runner_signal_is_abnormal(
            result.runner_signal,
            result.termination_provenance.broker_termination(),
        );
        let abnormal = thread_panicked
            || result.association_panicked
            || result.shutdown_observation_failed
            || unexpected_crash
            || runner_exit_code_is_crash(result.runner_exit_code)
            || unexpected_runner_failure;
        if result.result.is_err() || result.runner_success != Some(true) {
            launch.abort(ErrorCode::PeerClosed, abnormal, false);
        } else {
            // Any clean host exit before commit still aborts creation.
            launch.abort(ErrorCode::PeerClosed, false, false);
        }
        if !launch.retains_published_receipt() {
            self.remove_launch(token);
            if let ReceiptResolution::Resolved(finalization) = launch.resolve_receipt() {
                debug_assert!(finalization.is_none());
            }
        }
        if let Some(abnormal) = launch.runner_finished(abnormal) {
            self.finish_child_launch(launch, abnormal);
        }
    }

    fn finish_child_launch(&self, launch: &ChildLaunch, abnormal: bool) {
        finish_child_process(&launch.process, abnormal);
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
        if state.active_instances == 0 && state.active_watchdogs == 0 {
            self.drained.notify_all();
        }
    }

    fn finish_watchdog(&self) {
        let mut state = self
            .state
            .lock()
            .expect("runner child state mutex poisoned");
        state.active_watchdogs = state
            .active_watchdogs
            .checked_sub(1)
            .expect("runner watchdog count must remain balanced");
        if state.active_instances == 0 && state.active_watchdogs == 0 {
            self.drained.notify_all();
        }
    }

    fn wait_for_drain(&self) {
        let mut state = self
            .state
            .lock()
            .expect("runner child state mutex poisoned");
        while state.active_instances != 0 || state.active_watchdogs != 0 {
            state = self
                .drained
                .wait(state)
                .expect("runner child state mutex poisoned");
        }
    }
}

struct WatchdogCompletion {
    children: Arc<RunnerChildren>,
}

impl Drop for WatchdogCompletion {
    fn drop(&mut self) {
        self.children.finish_watchdog();
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

const fn process_start_failure_is_expected(error: ErrorCode) -> bool {
    matches!(
        error,
        ErrorCode::UnsupportedOperation
            | ErrorCode::PolicyDenied
            | ErrorCode::InvalidRights
            | ErrorCode::ResourceExhausted
            | ErrorCode::WouldBlock
            | ErrorCode::OutOfMemory
    )
}

impl ChildLaunch {
    fn wait_until_ready(&self) -> Result<Option<ThreadId>, ErrorCode> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        loop {
            match state.phase {
                ChildLaunchPhase::Starting => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("child launch mutex poisoned");
                }
                ChildLaunchPhase::Ready { initial_thread_id } => return Ok(initial_thread_id),
                ChildLaunchPhase::Committing | ChildLaunchPhase::Committed => {
                    return Err(ErrorCode::ProtocolState);
                }
                ChildLaunchPhase::Aborted(error) => return Err(error),
            }
        }
    }

    fn ready_and_wait(&self, initial_thread_id: Option<ThreadId>) -> Result<(), ErrorCode> {
        if let Some(thread_id) = initial_thread_id {
            self.process
                .pin_startup_thread(thread_id)
                .map_err(|error| match error {
                    BrokerError::UnknownObject => ErrorCode::ProtocolState,
                    error => ErrorCode::from(error),
                })?;
        }
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        if !matches!(state.phase, ChildLaunchPhase::Starting) {
            let error = match state.phase {
                ChildLaunchPhase::Aborted(error) => error,
                _ => ErrorCode::ProtocolState,
            };
            drop(state);
            if let Some(thread_id) = initial_thread_id {
                let _ = self.process.release_startup_thread(thread_id);
            }
            return Err(error);
        }
        state.pinned_initial_thread_id = initial_thread_id;
        state.phase = ChildLaunchPhase::Ready { initial_thread_id };
        self.changed.notify_all();
        loop {
            match state.phase {
                ChildLaunchPhase::Committed
                    if state.pinned_initial_thread_id.is_none()
                        && state.active_control_callbacks == 0 =>
                {
                    return Ok(());
                }
                ChildLaunchPhase::Ready { .. }
                | ChildLaunchPhase::Committing
                | ChildLaunchPhase::Committed => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("child launch mutex poisoned");
                }
                ChildLaunchPhase::Aborted(error) => return Err(error),
                ChildLaunchPhase::Starting => unreachable!("ready state cannot regress"),
            }
        }
    }

    fn begin_start_result_publication(&self) -> Result<Instant, ErrorCode> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        match state.phase {
            ChildLaunchPhase::Ready { .. }
                if state.publication == StartResultPublication::NotStarted =>
            {
                state.publication = StartResultPublication::Publishing;
                Ok(Instant::now() + PROCESS_START_RECEIPT_TIMEOUT)
            }
            ChildLaunchPhase::Aborted(error) => Err(error),
            _ => Err(ErrorCode::ProtocolState),
        }
    }

    fn report_start_failure(&self, error: ErrorCode) -> Result<(), ErrorCode> {
        if !process_start_failure_is_expected(error) {
            return Err(ErrorCode::ProtocolState);
        }
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        match state.phase {
            ChildLaunchPhase::Starting => {}
            ChildLaunchPhase::Aborted(error) => return Err(error),
            _ => return Err(ErrorCode::ProtocolState),
        }
        state.phase = ChildLaunchPhase::Aborted(error);
        state.shutdown_request = ShutdownRequest::ExpectedStartFailurePending;
        arm_deadline(
            &mut state.start_failure_publication_watchdog,
            PROCESS_START_ACKNOWLEDGEMENT_PUBLICATION_TIMEOUT,
        );
        self.changed.notify_all();
        Ok(())
    }

    fn start_failure_response_sent(&self, error: ErrorCode) {
        let (association_failure, shutdown) = {
            let mut state = self.state.lock().expect("child launch mutex poisoned");
            complete_deadline(&mut state.start_failure_publication_watchdog);
            let actions = if matches!(state.phase, ChildLaunchPhase::Aborted(cause) if cause == error)
                && state.shutdown_request == ShutdownRequest::ExpectedStartFailurePending
            {
                state.shutdown_request = ShutdownRequest::ExpectedStartFailure;
                (
                    state.association_failure.as_ref().map(Arc::clone),
                    state.shutdown.clone(),
                )
            } else {
                (None, None)
            };
            self.changed.notify_all();
            actions
        };
        if let Some(association_failure) = association_failure {
            association_failure();
        }
        if let Some(shutdown) = shutdown {
            shutdown.shutdown();
        }
    }

    fn admit_acknowledgement(&self) -> Result<(), ErrorCode> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        if state.publication == StartResultPublication::NotStarted {
            return Err(ErrorCode::ProtocolState);
        }
        match state.receipt {
            ReceiptState::AwaitingAcknowledgement => {}
            ReceiptState::TimeoutPending | ReceiptState::Draining | ReceiptState::Resolved => {
                return Err(ErrorCode::PeerClosed);
            }
            ReceiptState::AcknowledgementAdmitted => return Err(ErrorCode::UnknownObject),
        }
        state.receipt = ReceiptState::AcknowledgementAdmitted;
        if state.publication == StartResultPublication::Delivered
            && matches!(
                state.phase,
                ChildLaunchPhase::Ready { .. } | ChildLaunchPhase::Aborted(_)
            )
        {
            arm_deadline(
                &mut state.resolution_watchdog,
                PROCESS_START_INTERNAL_RESOLUTION_TIMEOUT,
            );
            self.changed.notify_all();
        }
        Ok(())
    }

    fn resolve_acknowledgement(&self) -> Result<ProcessStartAcknowledgement, ErrorCode> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        loop {
            match state.receipt {
                ReceiptState::AcknowledgementAdmitted => {}
                ReceiptState::TimeoutPending | ReceiptState::Draining | ReceiptState::Resolved => {
                    return Err(ErrorCode::PeerClosed);
                }
                ReceiptState::AwaitingAcknowledgement => return Err(ErrorCode::ProtocolState),
            }
            if state.publication == StartResultPublication::NotStarted {
                return Err(ErrorCode::ProtocolState);
            }
            match (state.phase, state.publication) {
                (
                    ChildLaunchPhase::Ready { .. } | ChildLaunchPhase::Aborted(_),
                    StartResultPublication::Publishing,
                ) => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("child launch mutex poisoned");
                }
                (ChildLaunchPhase::Ready { .. }, StartResultPublication::Delivered) => {
                    debug_assert!(matches!(state.resolution_watchdog, DeadlineState::Armed(_)));
                    state.phase = ChildLaunchPhase::Committing;
                    drop(state);
                    let commit_result = self.process.commit_start().map_err(ErrorCode::from);
                    state = self.state.lock().expect("child launch mutex poisoned");
                    match commit_result {
                        Ok(()) => {
                            state.phase = ChildLaunchPhase::Committed;
                            complete_acknowledgement_resolution(&mut state);
                            self.changed.notify_all();
                            return Ok(ProcessStartAcknowledgement::Acknowledged);
                        }
                        Err(error) => {
                            state.phase = ChildLaunchPhase::Aborted(error);
                            state.abnormal |= error == ErrorCode::Internal;
                            complete_acknowledgement_resolution(&mut state);
                            self.changed.notify_all();
                            return Ok(ProcessStartAcknowledgement::Failed(error));
                        }
                    }
                }
                (ChildLaunchPhase::Aborted(error), StartResultPublication::Delivered) => {
                    debug_assert!(matches!(
                        state.resolution_watchdog,
                        DeadlineState::Armed(_) | DeadlineState::Fired
                    ));
                    complete_acknowledgement_resolution(&mut state);
                    self.changed.notify_all();
                    return Ok(ProcessStartAcknowledgement::Failed(error));
                }
                (ChildLaunchPhase::Starting, _) => return Err(ErrorCode::ProtocolState),
                (ChildLaunchPhase::Committing | ChildLaunchPhase::Committed, _) => {
                    return Err(ErrorCode::ProtocolState);
                }
                (_, StartResultPublication::NotStarted) => {
                    unreachable!("publication state was checked before phase dispatch")
                }
            }
        }
    }

    fn mark_start_result_delivered(&self) {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        if state.publication == StartResultPublication::Publishing {
            state.publication = StartResultPublication::Delivered;
            if state.receipt == ReceiptState::AcknowledgementAdmitted
                && matches!(
                    state.phase,
                    ChildLaunchPhase::Ready { .. } | ChildLaunchPhase::Aborted(_)
                )
            {
                arm_deadline(
                    &mut state.resolution_watchdog,
                    PROCESS_START_INTERNAL_RESOLUTION_TIMEOUT,
                );
            }
            self.changed.notify_all();
        }
    }

    fn install_shutdown(&self, shutdown: Arc<RunnerShutdown>) {
        let shutdown = {
            let mut state = self.state.lock().expect("child launch mutex poisoned");
            state.shutdown = Some(Arc::clone(&shutdown));
            (state.shutdown_request != ShutdownRequest::None).then_some(shutdown)
        };
        if let Some(shutdown) = shutdown {
            shutdown.shutdown();
        }
    }

    fn install_association_failure(&self, failure: AssociationFailure) {
        let failure = {
            let mut state = self.state.lock().expect("child launch mutex poisoned");
            state.association_failure = Some(Arc::clone(&failure));
            (state.shutdown_request != ShutdownRequest::None).then_some(failure)
        };
        if let Some(failure) = failure {
            failure();
        }
    }

    fn abort(&self, error: ErrorCode, abnormal: bool, expected_shutdown: bool) {
        let (association_failure, shutdown) = {
            let mut state = self.state.lock().expect("child launch mutex poisoned");
            state.abnormal |= abnormal;
            match state.phase {
                ChildLaunchPhase::Starting | ChildLaunchPhase::Ready { .. } => {
                    state.phase = ChildLaunchPhase::Aborted(error);
                    let newly_requested = state.shutdown_request == ShutdownRequest::None;
                    if newly_requested {
                        state.shutdown_request = if expected_shutdown {
                            ShutdownRequest::Expected
                        } else {
                            ShutdownRequest::Unexpected
                        };
                    }
                    self.changed.notify_all();
                    (
                        newly_requested
                            .then(|| state.association_failure.as_ref().map(Arc::clone))
                            .flatten(),
                        state.shutdown.clone(),
                    )
                }
                ChildLaunchPhase::Aborted(_) => match state.shutdown_request {
                    ShutdownRequest::None => {
                        state.shutdown_request = if expected_shutdown {
                            ShutdownRequest::Expected
                        } else {
                            ShutdownRequest::Unexpected
                        };
                        (
                            state.association_failure.as_ref().map(Arc::clone),
                            state.shutdown.clone(),
                        )
                    }
                    ShutdownRequest::ExpectedStartFailurePending => {
                        state.shutdown_request = ShutdownRequest::ExpectedStartFailure;
                        (
                            state.association_failure.as_ref().map(Arc::clone),
                            state.shutdown.clone(),
                        )
                    }
                    ShutdownRequest::Expected
                    | ShutdownRequest::ExpectedStartFailure
                    | ShutdownRequest::Unexpected => (None, None),
                },
                ChildLaunchPhase::Committing | ChildLaunchPhase::Committed => (None, None),
            }
        };
        if let Some(association_failure) = association_failure {
            association_failure();
        }
        if let Some(shutdown) = shutdown {
            shutdown.shutdown();
        }
    }

    fn association_closed(&self) {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        state.association_failure = None;
        if matches!(
            state.phase,
            ChildLaunchPhase::Starting | ChildLaunchPhase::Ready { .. }
        ) {
            state.phase = ChildLaunchPhase::Aborted(ErrorCode::PeerClosed);
            self.changed.notify_all();
        }
    }

    fn mark_shutdown_expected(&self) {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        if state.shutdown_request == ShutdownRequest::None {
            state.shutdown_request = ShutdownRequest::Expected;
        }
    }

    fn mark_abnormal(&self) {
        self.state
            .lock()
            .expect("child launch mutex poisoned")
            .abnormal = true;
    }

    fn shutdown_request(&self) -> ShutdownRequest {
        self.state
            .lock()
            .expect("child launch mutex poisoned")
            .shutdown_request
    }

    fn commit_was_claimed(&self) -> bool {
        matches!(
            self.state
                .lock()
                .expect("child launch mutex poisoned")
                .phase,
            ChildLaunchPhase::Committing | ChildLaunchPhase::Committed
        )
    }

    fn retains_published_receipt(&self) -> bool {
        let state = self.state.lock().expect("child launch mutex poisoned");
        state.publication != StartResultPublication::NotStarted
            && state.receipt != ReceiptState::Resolved
    }

    fn resolve_receipt(&self) -> ReceiptResolution {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        if matches!(
            state.receipt,
            ReceiptState::TimeoutPending | ReceiptState::Draining
        ) {
            return ReceiptResolution::DeferredToDrain;
        }
        state.receipt = ReceiptState::Resolved;
        complete_deadline(&mut state.resolution_watchdog);
        complete_deadline(&mut state.acknowledgement_publication_watchdog);
        complete_deadline(&mut state.start_failure_publication_watchdog);
        self.changed.notify_all();
        ReceiptResolution::Resolved(self.release_startup_pin_and_take_finalization(state))
    }

    fn begin_receipt_drain(&self) {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        if state.receipt != ReceiptState::Resolved {
            state.receipt = ReceiptState::Draining;
            if !matches!(state.phase, ChildLaunchPhase::Committing) {
                complete_deadline(&mut state.resolution_watchdog);
            }
            complete_deadline(&mut state.acknowledgement_publication_watchdog);
            complete_deadline(&mut state.start_failure_publication_watchdog);
            self.changed.notify_all();
        }
    }

    fn finish_receipt_drain(&self) -> Option<bool> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        state.receipt = ReceiptState::Resolved;
        complete_deadline(&mut state.resolution_watchdog);
        complete_deadline(&mut state.acknowledgement_publication_watchdog);
        complete_deadline(&mut state.start_failure_publication_watchdog);
        self.changed.notify_all();
        self.release_startup_pin_and_take_finalization(state)
    }

    fn expire_initial_receipt_deadline(&self) -> Option<ReceiptExpiration> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        let (error, abnormal) = match (state.receipt, state.publication) {
            (ReceiptState::AwaitingAcknowledgement, _) => (ErrorCode::PeerClosed, false),
            (ReceiptState::AcknowledgementAdmitted, StartResultPublication::Publishing) => {
                (ErrorCode::Internal, true)
            }
            _ => return None,
        };
        expire_launch(&mut state, error, abnormal, true, &self.changed)
    }

    fn wait_for_initial_receipt_deadline(&self, deadline: Instant) -> Option<ReceiptExpiration> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        loop {
            if !matches!(
                (state.receipt, state.publication),
                (ReceiptState::AwaitingAcknowledgement, _)
                    | (
                        ReceiptState::AcknowledgementAdmitted,
                        StartResultPublication::Publishing
                    )
            ) {
                return None;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let (next, _) = self
                .changed
                .wait_timeout(state, remaining)
                .expect("child launch mutex poisoned");
            state = next;
        }
        let (error, abnormal) = match (state.receipt, state.publication) {
            (ReceiptState::AwaitingAcknowledgement, _) => (ErrorCode::PeerClosed, false),
            (ReceiptState::AcknowledgementAdmitted, StartResultPublication::Publishing) => {
                (ErrorCode::Internal, true)
            }
            _ => return None,
        };
        expire_launch(&mut state, error, abnormal, true, &self.changed)
    }

    fn wait_for_internal_resolution_timeout(&self) -> Option<ReceiptExpiration> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        loop {
            match state.resolution_watchdog {
                DeadlineState::Unarmed => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("child launch mutex poisoned");
                }
                DeadlineState::Armed(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        state.resolution_watchdog = DeadlineState::Fired;
                        return expire_internal_resolution(&mut state, &self.changed);
                    }
                    let (next, _) = self
                        .changed
                        .wait_timeout(state, remaining)
                        .expect("child launch mutex poisoned");
                    state = next;
                }
                DeadlineState::Disarmed | DeadlineState::Fired => return None,
            }
        }
    }

    fn wait_for_acknowledgement_publication_timeout(&self) -> Option<ReceiptExpiration> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        loop {
            match state.acknowledgement_publication_watchdog {
                DeadlineState::Unarmed => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("child launch mutex poisoned");
                }
                DeadlineState::Armed(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        state.acknowledgement_publication_watchdog = DeadlineState::Fired;
                        return expire_launch(
                            &mut state,
                            ErrorCode::PeerClosed,
                            false,
                            true,
                            &self.changed,
                        );
                    }
                    let (next, _) = self
                        .changed
                        .wait_timeout(state, remaining)
                        .expect("child launch mutex poisoned");
                    state = next;
                }
                DeadlineState::Disarmed | DeadlineState::Fired => return None,
            }
        }
    }

    fn wait_for_start_failure_publication_timeout(&self) -> Option<ReceiptExpiration> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        loop {
            match state.start_failure_publication_watchdog {
                DeadlineState::Armed(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        state.start_failure_publication_watchdog = DeadlineState::Fired;
                        return expire_start_failure_publication(&mut state, &self.changed);
                    }
                    let (next, _) = self
                        .changed
                        .wait_timeout(state, remaining)
                        .expect("child launch mutex poisoned");
                    state = next;
                }
                DeadlineState::Unarmed | DeadlineState::Disarmed | DeadlineState::Fired => {
                    return None;
                }
            }
        }
    }

    fn fail_start_failure_publication_watchdog(&self) -> Option<ReceiptExpiration> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        if !matches!(
            state.start_failure_publication_watchdog,
            DeadlineState::Armed(_)
        ) {
            return None;
        }
        state.start_failure_publication_watchdog = DeadlineState::Fired;
        expire_start_failure_publication(&mut state, &self.changed)
    }

    fn fail_internal_resolution_watchdog(&self) -> Option<ReceiptExpiration> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        complete_deadline(&mut state.resolution_watchdog);
        complete_deadline(&mut state.acknowledgement_publication_watchdog);
        complete_deadline(&mut state.start_failure_publication_watchdog);
        expire_launch(&mut state, ErrorCode::Internal, true, true, &self.changed)
    }

    fn complete_timeout_callback(&self) -> Option<bool> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        state.active_control_callbacks = state
            .active_control_callbacks
            .checked_sub(1)
            .expect("process-start timeout callback count must remain balanced");
        self.changed.notify_all();
        take_finalization(&mut state)
    }

    fn wait_for_commit_resolution(&self, deadline: Instant) -> bool {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        while matches!(state.phase, ChildLaunchPhase::Committing) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let (next, wait_result) = self
                .changed
                .wait_timeout(state, remaining)
                .expect("child launch mutex poisoned");
            state = next;
            if wait_result.timed_out() && matches!(state.phase, ChildLaunchPhase::Committing) {
                return false;
            }
        }
        true
    }

    fn release_startup_pin_and_take_finalization(
        &self,
        mut state: MutexGuard<'_, ChildLaunchData>,
    ) -> Option<bool> {
        let pinned_thread_id = state.pinned_initial_thread_id.take();
        if pinned_thread_id.is_none() {
            return take_finalization(&mut state);
        }
        state.active_control_callbacks = state
            .active_control_callbacks
            .checked_add(1)
            .expect("process-start control callback count must remain bounded");
        drop(state);

        let release_failed = self
            .process
            .release_startup_thread(pinned_thread_id.expect("thread pin was checked"))
            .is_err();
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        state.active_control_callbacks = state
            .active_control_callbacks
            .checked_sub(1)
            .expect("process-start control callback count must remain balanced");
        state.abnormal |= release_failed;
        self.changed.notify_all();
        take_finalization(&mut state)
    }

    fn runner_finished(&self, abnormal: bool) -> Option<bool> {
        let mut state = self.state.lock().expect("child launch mutex poisoned");
        state.abnormal |= abnormal;
        state.runner_finished = true;
        take_finalization(&mut state)
    }
}

fn expire_launch(
    state: &mut ChildLaunchData,
    error: ErrorCode,
    abnormal: bool,
    fail_parent: bool,
    changed: &Condvar,
) -> Option<ReceiptExpiration> {
    if matches!(
        state.receipt,
        ReceiptState::TimeoutPending | ReceiptState::Draining | ReceiptState::Resolved
    ) {
        return None;
    }
    state.active_control_callbacks += 1;
    state.receipt = ReceiptState::TimeoutPending;
    state.abnormal |= abnormal;
    complete_deadline(&mut state.resolution_watchdog);
    complete_deadline(&mut state.acknowledgement_publication_watchdog);
    complete_deadline(&mut state.start_failure_publication_watchdog);
    let (association_failure, shutdown) = match state.phase {
        ChildLaunchPhase::Starting | ChildLaunchPhase::Ready { .. } => {
            state.phase = ChildLaunchPhase::Aborted(error);
            if state.shutdown_request == ShutdownRequest::None {
                state.shutdown_request = ShutdownRequest::Expected;
            }
            (
                state.association_failure.as_ref().map(Arc::clone),
                state.shutdown.clone(),
            )
        }
        ChildLaunchPhase::Aborted(_) => {
            if state.shutdown_request == ShutdownRequest::None {
                state.shutdown_request = ShutdownRequest::Expected;
                (
                    state.association_failure.as_ref().map(Arc::clone),
                    state.shutdown.clone(),
                )
            } else {
                (None, None)
            }
        }
        ChildLaunchPhase::Committing | ChildLaunchPhase::Committed => (None, None),
    };
    changed.notify_all();
    Some(ReceiptExpiration {
        shutdown,
        association_failure,
        fail_parent,
        commit_supervision_deadline: None,
    })
}

fn expire_start_failure_publication(
    state: &mut ChildLaunchData,
    changed: &Condvar,
) -> Option<ReceiptExpiration> {
    if !matches!(state.phase, ChildLaunchPhase::Aborted(_))
        || state.shutdown_request != ShutdownRequest::ExpectedStartFailurePending
    {
        return None;
    }
    state.active_control_callbacks += 1;
    state.shutdown_request = ShutdownRequest::ExpectedStartFailure;
    changed.notify_all();
    Some(ReceiptExpiration {
        shutdown: state.shutdown.clone(),
        association_failure: state.association_failure.as_ref().map(Arc::clone),
        fail_parent: false,
        commit_supervision_deadline: None,
    })
}

fn expire_internal_resolution(
    state: &mut ChildLaunchData,
    changed: &Condvar,
) -> Option<ReceiptExpiration> {
    let committing_drain = state.receipt == ReceiptState::Draining
        && matches!(state.phase, ChildLaunchPhase::Committing);
    if state.receipt != ReceiptState::AcknowledgementAdmitted && !committing_drain {
        return None;
    }
    state.active_control_callbacks += 1;
    state.abnormal = true;
    let (association_failure, shutdown, fail_parent, commit_supervision_deadline) =
        match state.phase {
            ChildLaunchPhase::Ready { .. } | ChildLaunchPhase::Aborted(_) => {
                state.phase = ChildLaunchPhase::Aborted(ErrorCode::Internal);
                if state.shutdown_request == ShutdownRequest::None {
                    state.shutdown_request = ShutdownRequest::Expected;
                }
                (
                    state.association_failure.as_ref().map(Arc::clone),
                    state.shutdown.clone(),
                    false,
                    None,
                )
            }
            ChildLaunchPhase::Committing => {
                state.receipt = ReceiptState::TimeoutPending;
                complete_deadline(&mut state.acknowledgement_publication_watchdog);
                (
                    None,
                    None,
                    true,
                    Some(Instant::now() + PROCESS_START_SUPERVISOR_SHUTDOWN_TIMEOUT),
                )
            }
            ChildLaunchPhase::Starting | ChildLaunchPhase::Committed => {
                state.active_control_callbacks -= 1;
                return None;
            }
        };
    changed.notify_all();
    Some(ReceiptExpiration {
        shutdown,
        association_failure,
        fail_parent,
        commit_supervision_deadline,
    })
}

fn arm_deadline(state: &mut DeadlineState, timeout: Duration) {
    if *state == DeadlineState::Unarmed {
        *state = DeadlineState::Armed(Instant::now() + timeout);
    }
}

fn complete_deadline(state: &mut DeadlineState) {
    if matches!(state, DeadlineState::Unarmed | DeadlineState::Armed(_)) {
        *state = DeadlineState::Disarmed;
    }
}

fn complete_acknowledgement_resolution(state: &mut ChildLaunchData) {
    complete_deadline(&mut state.resolution_watchdog);
    if state.receipt == ReceiptState::AcknowledgementAdmitted {
        arm_deadline(
            &mut state.acknowledgement_publication_watchdog,
            PROCESS_START_ACKNOWLEDGEMENT_PUBLICATION_TIMEOUT,
        );
    }
}

fn take_finalization(state: &mut ChildLaunchData) -> Option<bool> {
    if state.finalization_taken
        || state.active_control_callbacks != 0
        || state.receipt != ReceiptState::Resolved
    {
        return None;
    }
    if !state.runner_finished {
        return None;
    }
    state.runner_finished = false;
    state.finalization_taken = true;
    Some(state.abnormal)
}

fn finish_child_process(process: &Arc<BrokerProcess>, abnormal: bool) {
    if abnormal {
        Arc::clone(process).finish_abnormal();
    } else {
        Arc::clone(process).finish();
    }
}

#[cfg(target_os = "linux")]
fn runner_exit_signal(status: ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;

    status.signal()
}

#[cfg(all(windows, target_arch = "x86_64"))]
const fn runner_exit_signal(_status: ExitStatus) -> Option<i32> {
    None
}

#[cfg(not(any(target_os = "linux", all(windows, target_arch = "x86_64"))))]
const fn runner_exit_signal(_status: ExitStatus) -> Option<i32> {
    None
}

#[cfg(target_os = "linux")]
const fn runner_signal_is_abnormal(signal: Option<i32>, broker_termination: bool) -> bool {
    matches!(signal, Some(signal) if signal != libc::SIGKILL || !broker_termination)
}

#[cfg(not(target_os = "linux"))]
const fn runner_signal_is_abnormal(_signal: Option<i32>, _broker_termination: bool) -> bool {
    false
}

#[cfg(all(windows, target_arch = "x86_64"))]
const fn runner_exit_code_is_crash(exit_code: Option<i32>) -> bool {
    matches!(exit_code, Some(code) if code as u32 >= 0x8000_0000)
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
const fn runner_exit_code_is_crash(_exit_code: Option<i32>) -> bool {
    false
}

#[cfg(all(windows, target_arch = "x86_64"))]
const fn runner_exit_code_is_expected_shutdown(
    exit_code: Option<i32>,
    broker_termination: bool,
) -> bool {
    broker_termination && matches!(exit_code, Some(1))
}

#[cfg(all(windows, target_arch = "x86_64"))]
const _: () = {
    let access_violation = 0xc000_0005_u32 as i32;
    let breakpoint = 0x8000_0003_u32 as i32;
    assert!(runner_exit_code_is_crash(Some(access_violation)));
    assert!(runner_exit_code_is_crash(Some(breakpoint)));
    assert!(!runner_exit_code_is_expected_shutdown(
        Some(access_violation),
        true
    ));
    assert!(runner_exit_code_is_expected_shutdown(Some(1), true));
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
const fn runner_exit_code_is_expected_shutdown(
    _exit_code: Option<i32>,
    _broker_termination: bool,
) -> bool {
    false
}

fn accept_runner_channel<Channel>(
    deadline: Instant,
    channel_name: &'static str,
    mut runner_status: impl FnMut() -> IoResult<Option<String>>,
    mut try_accept: impl FnMut() -> IoResult<Channel>,
) -> IoResult<Channel> {
    loop {
        if let Some(status) = runner_status()? {
            return Err(IoError::new(
                ErrorKind::BrokenPipe,
                format!("runner {status} before connecting its {channel_name} channel"),
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(IoError::new(
                ErrorKind::TimedOut,
                format!("timed out waiting for runner {channel_name} channel"),
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

fn runner_has_exited(runner: &Arc<Mutex<Child>>) -> IoResult<bool> {
    // A pre-authentication caller stops accepting before acting on `true`;
    // post-authentication callers no longer rely on PID-based authentication.
    runner
        .lock()
        .expect("runner process mutex poisoned")
        .try_wait()
        .map(|status| status.is_some())
}

fn wait_for_runner_exit(runner: &Arc<Mutex<Child>>) -> IoResult<ExitStatus> {
    loop {
        if let Some(status) = runner
            .lock()
            .expect("runner process mutex poisoned")
            .try_wait()?
        {
            return Ok(status);
        }
        std::thread::sleep(ACCEPT_RETRY_DELAY);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChildLaunch, ChildLaunchData, ChildLaunchPhase, DeadlineState,
        PROCESS_START_RECEIPT_TIMEOUT, PROCESS_START_SUPERVISOR_SHUTDOWN_TIMEOUT,
        ProcessStartAcknowledgement, ReceiptResolution, ReceiptState, RunnerChildren,
        RunnerChildrenState, RunnerConfig, ShutdownRequest, StartResultPublication,
    };
    use litebox_broker_core::test_support::TestBrokerCoreBuilder;
    use litebox_broker_core::{BrokerCore, CallerCredential, ObjectRights, PolicyEngine};
    use litebox_broker_protocol::ProcessId;
    use litebox_broker_protocol::error::ErrorCode;
    use litebox_broker_protocol::message::{BrokerOperation, BrokerResult};
    use litebox_broker_protocol::process::ProcessStartToken;
    use std::path::PathBuf;
    use std::sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::{Duration, Instant};

    fn launch_with_broker(publication: StartResultPublication) -> (BrokerCore, Arc<ChildLaunch>) {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let parent = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let (process, _) = parent.create_child(&[]).unwrap();
        parent.finish();
        (
            broker,
            Arc::new(ChildLaunch {
                parent_id: ProcessId(1),
                process,
                state: Mutex::new(ChildLaunchData {
                    phase: ChildLaunchPhase::Ready {
                        initial_thread_id: None,
                    },
                    publication,
                    shutdown: None,
                    association_failure: None,
                    shutdown_request: ShutdownRequest::None,
                    abnormal: false,
                    receipt: ReceiptState::AwaitingAcknowledgement,
                    resolution_watchdog: DeadlineState::Unarmed,
                    acknowledgement_publication_watchdog: DeadlineState::Unarmed,
                    start_failure_publication_watchdog: DeadlineState::Unarmed,
                    active_control_callbacks: 0,
                    pinned_initial_thread_id: None,
                    runner_finished: false,
                    finalization_taken: false,
                }),
                changed: Condvar::new(),
            }),
        )
    }

    fn launch(publication: StartResultPublication) -> Arc<ChildLaunch> {
        launch_with_broker(publication).1
    }

    #[test]
    fn publication_captures_an_absolute_receipt_deadline() {
        let launch = launch(StartResultPublication::NotStarted);
        let before = Instant::now();

        let deadline = launch.begin_start_result_publication().unwrap();
        let after = Instant::now();

        assert!(deadline >= before + PROCESS_START_RECEIPT_TIMEOUT);
        assert!(deadline <= after + PROCESS_START_RECEIPT_TIMEOUT);
    }

    #[test]
    fn acknowledgement_ingress_claims_receipt_before_worker_resolution() {
        let (broker, launch) = launch_with_broker(StartResultPublication::Delivered);
        let token = ProcessStartToken(7);
        let parent_id = launch.parent_id;
        let children = Arc::new(RunnerChildren {
            broker,
            config: RunnerConfig::new(PathBuf::new(), Vec::new()),
            state: Mutex::new(RunnerChildrenState {
                launches: vec![(token, Arc::clone(&launch))],
                associations: Vec::new(),
                active_instances: 1,
                active_watchdogs: 0,
            }),
            drained: Condvar::new(),
        });

        children.admit_acknowledgement(parent_id, token).unwrap();

        assert_eq!(children.state.lock().unwrap().active_watchdogs, 2);
        assert!(matches!(
            launch.state.lock().unwrap().receipt,
            ReceiptState::AcknowledgementAdmitted
        ));
        assert!(launch.expire_initial_receipt_deadline().is_none());
        assert!(matches!(
            children.resolve_acknowledgement(parent_id, token),
            Ok(ProcessStartAcknowledgement::Acknowledged)
        ));
        children.response_sent(
            parent_id,
            &BrokerOperation::AcknowledgeProcessStart(token),
            &BrokerResult::ProcessStartAcknowledged,
        );
        Arc::clone(&launch.process).finish();
        children.finish_instance();
        children.wait_for_drain();
        assert_eq!(children.state.lock().unwrap().active_watchdogs, 0);
    }

    #[test]
    fn reported_bootstrap_rejection_selects_normal_rollback() {
        let launch = launch(StartResultPublication::NotStarted);
        launch.state.lock().unwrap().phase = ChildLaunchPhase::Starting;

        launch
            .report_start_failure(ErrorCode::UnsupportedOperation)
            .unwrap();

        assert!(matches!(
            launch.wait_until_ready(),
            Err(ErrorCode::UnsupportedOperation)
        ));
        assert!(
            launch
                .shutdown_request()
                .expected_start_failure_was_reported()
        );
        assert!(!launch.state.lock().unwrap().abnormal);
        launch.start_failure_response_sent(ErrorCode::UnsupportedOperation);
        assert!(launch.shutdown_request().was_expected());
        assert_eq!(launch.runner_finished(false), None);
        assert!(matches!(
            launch.resolve_receipt(),
            ReceiptResolution::Resolved(Some(false))
        ));
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn acknowledgement_waits_for_publication_bookkeeping() {
        let launch = launch(StartResultPublication::Publishing);
        launch.admit_acknowledgement().unwrap();
        let waiting = Arc::clone(&launch);
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker =
            std::thread::spawn(move || sender.send(waiting.resolve_acknowledgement()).unwrap());

        assert!(receiver.recv_timeout(Duration::from_millis(20)).is_err());
        assert!(matches!(
            launch.state.lock().unwrap().resolution_watchdog,
            DeadlineState::Unarmed
        ));
        launch.mark_start_result_delivered();
        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            Ok(ProcessStartAcknowledgement::Acknowledged)
        ));
        worker.join().unwrap();
        assert!(launch.process.is_running());
        assert!(matches!(
            launch.state.lock().unwrap().resolution_watchdog,
            DeadlineState::Disarmed
        ));
        assert!(matches!(
            launch
                .state
                .lock()
                .unwrap()
                .acknowledgement_publication_watchdog,
            DeadlineState::Armed(_)
        ));

        launch.resolve_receipt();
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn acknowledgement_interrupted_by_drain_returns_peer_closed() {
        let launch = launch(StartResultPublication::Publishing);
        launch.admit_acknowledgement().unwrap();
        let waiting = Arc::clone(&launch);
        let worker = std::thread::spawn(move || waiting.resolve_acknowledgement());

        std::thread::sleep(Duration::from_millis(20));
        launch.begin_receipt_drain();

        assert!(matches!(worker.join().unwrap(), Err(ErrorCode::PeerClosed)));
        launch.finish_receipt_drain();
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn process_ready_interrupted_by_abort_returns_the_abort_cause() {
        let ready = launch(StartResultPublication::NotStarted);
        ready.state.lock().unwrap().phase = ChildLaunchPhase::Starting;
        ready.abort(ErrorCode::PeerClosed, false, true);
        assert!(matches!(
            ready.ready_and_wait(None),
            Err(ErrorCode::PeerClosed)
        ));
        ready.resolve_receipt();
        Arc::clone(&ready.process).finish();
    }

    #[test]
    fn failure_report_interrupted_by_abort_returns_the_abort_cause() {
        let failed = launch(StartResultPublication::NotStarted);
        failed.state.lock().unwrap().phase = ChildLaunchPhase::Starting;
        failed.abort(ErrorCode::PeerClosed, false, true);
        assert!(matches!(
            failed.report_start_failure(ErrorCode::UnsupportedOperation),
            Err(ErrorCode::PeerClosed)
        ));
        failed.resolve_receipt();
        Arc::clone(&failed.process).finish();
    }

    #[test]
    fn delivery_arms_the_resolution_watchdog_before_the_worker_resumes() {
        let launch = launch(StartResultPublication::Publishing);
        launch.admit_acknowledgement().unwrap();

        assert!(matches!(
            launch.state.lock().unwrap().resolution_watchdog,
            DeadlineState::Unarmed
        ));
        launch.mark_start_result_delivered();
        assert!(matches!(
            launch.state.lock().unwrap().resolution_watchdog,
            DeadlineState::Armed(_)
        ));

        launch.begin_receipt_drain();
        launch.finish_receipt_drain();
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn acknowledgement_publication_timeout_retains_receipt_for_drain() {
        let launch = launch(StartResultPublication::Delivered);
        launch.admit_acknowledgement().unwrap();
        assert!(matches!(
            launch.resolve_acknowledgement(),
            Ok(ProcessStartAcknowledgement::Acknowledged)
        ));
        launch
            .state
            .lock()
            .unwrap()
            .acknowledgement_publication_watchdog = DeadlineState::Armed(Instant::now());

        let expiration = launch
            .wait_for_acknowledgement_publication_timeout()
            .unwrap();
        assert!(expiration.fail_parent);
        let state = launch.state.lock().unwrap();
        assert!(matches!(state.receipt, ReceiptState::TimeoutPending));
        assert!(matches!(
            state.acknowledgement_publication_watchdog,
            DeadlineState::Fired
        ));
        assert!(!state.abnormal);
        drop(state);

        assert_eq!(launch.complete_timeout_callback(), None);
        launch.begin_receipt_drain();
        launch.finish_receipt_drain();
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn start_failure_publication_timeout_terminates_the_child() {
        let launch = launch(StartResultPublication::NotStarted);
        launch.state.lock().unwrap().phase = ChildLaunchPhase::Starting;
        launch
            .report_start_failure(ErrorCode::UnsupportedOperation)
            .unwrap();
        launch
            .state
            .lock()
            .unwrap()
            .start_failure_publication_watchdog = DeadlineState::Armed(Instant::now());

        let expiration = launch.wait_for_start_failure_publication_timeout().unwrap();

        assert!(!expiration.fail_parent);
        assert!(launch.shutdown_request().was_expected());
        assert!(matches!(
            launch
                .state
                .lock()
                .unwrap()
                .start_failure_publication_watchdog,
            DeadlineState::Fired
        ));
        assert_eq!(launch.complete_timeout_callback(), None);
        assert_eq!(launch.runner_finished(false), None);
        assert!(matches!(
            launch.resolve_receipt(),
            ReceiptResolution::Resolved(Some(false))
        ));
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn precommit_resolution_timeout_returns_typed_internal_failure() {
        let launch = launch(StartResultPublication::Delivered);
        launch.admit_acknowledgement().unwrap();
        launch.state.lock().unwrap().resolution_watchdog = DeadlineState::Armed(Instant::now());

        let expiration = launch.wait_for_internal_resolution_timeout().unwrap();
        assert!(!expiration.fail_parent);
        let state = launch.state.lock().unwrap();
        assert!(matches!(
            state.phase,
            ChildLaunchPhase::Aborted(ErrorCode::Internal)
        ));
        assert!(matches!(
            state.receipt,
            ReceiptState::AcknowledgementAdmitted
        ));
        assert!(matches!(
            state.acknowledgement_publication_watchdog,
            DeadlineState::Unarmed
        ));
        assert!(state.abnormal);
        drop(state);
        assert_eq!(launch.complete_timeout_callback(), None);

        assert!(matches!(
            launch.resolve_acknowledgement(),
            Ok(ProcessStartAcknowledgement::Failed(ErrorCode::Internal))
        ));
        assert!(matches!(
            launch
                .state
                .lock()
                .unwrap()
                .acknowledgement_publication_watchdog,
            DeadlineState::Armed(_)
        ));
        launch.resolve_receipt();
        Arc::clone(&launch.process).finish_abnormal();
    }

    #[test]
    fn child_abort_fails_an_installed_active_association() {
        let launch = launch(StartResultPublication::NotStarted);
        let failed = Arc::new(AtomicBool::new(false));
        let recorded = Arc::clone(&failed);
        launch.install_association_failure(Arc::new(move || {
            recorded.store(true, Ordering::Release);
        }));

        launch.abort(ErrorCode::PeerClosed, false, true);

        assert!(failed.load(Ordering::Acquire));
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn supervisor_wait_observes_commit_resolution() {
        let launch = launch(StartResultPublication::Delivered);
        launch.state.lock().unwrap().phase = ChildLaunchPhase::Committing;
        let waiting = Arc::clone(&launch);
        let worker = std::thread::spawn(move || {
            waiting.wait_for_commit_resolution(Instant::now() + Duration::from_secs(1))
        });

        std::thread::sleep(Duration::from_millis(20));
        launch.state.lock().unwrap().phase = ChildLaunchPhase::Committed;
        launch.changed.notify_all();

        assert!(worker.join().unwrap());
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn receipt_drain_keeps_commit_supervision_armed() {
        let launch = launch(StartResultPublication::Delivered);
        launch.admit_acknowledgement().unwrap();
        {
            let mut state = launch.state.lock().unwrap();
            state.phase = ChildLaunchPhase::Committing;
            state.resolution_watchdog = DeadlineState::Armed(Instant::now());
        }
        launch.begin_receipt_drain();
        assert!(matches!(
            launch.state.lock().unwrap().resolution_watchdog,
            DeadlineState::Armed(_)
        ));

        let before = Instant::now();
        let expiration = launch.wait_for_internal_resolution_timeout().unwrap();
        let after = Instant::now();
        let deadline = expiration.commit_supervision_deadline.unwrap();
        assert!(deadline >= before + PROCESS_START_SUPERVISOR_SHUTDOWN_TIMEOUT);
        assert!(deadline <= after + PROCESS_START_SUPERVISOR_SHUTDOWN_TIMEOUT);
        {
            let mut state = launch.state.lock().unwrap();
            state.phase = ChildLaunchPhase::Aborted(ErrorCode::Internal);
        }
        launch.changed.notify_all();
        assert_eq!(launch.complete_timeout_callback(), None);
        launch.finish_receipt_drain();
        Arc::clone(&launch.process).finish_abnormal();
    }

    #[test]
    fn published_abort_returns_typed_start_failure() {
        let launch = launch(StartResultPublication::Publishing);
        launch.abort(ErrorCode::PeerClosed, false, false);
        launch.mark_start_result_delivered();
        launch.admit_acknowledgement().unwrap();

        assert!(matches!(
            launch.resolve_acknowledgement(),
            Ok(ProcessStartAcknowledgement::Failed(ErrorCode::PeerClosed))
        ));
        launch.resolve_receipt();
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn acknowledgement_before_publication_is_protocol_violation() {
        let launch = launch(StartResultPublication::NotStarted);

        assert!(matches!(
            launch.admit_acknowledgement(),
            Err(ErrorCode::ProtocolState)
        ));
        launch.resolve_receipt();
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn published_receipt_defers_process_finalization() {
        let launch = launch(StartResultPublication::Delivered);
        launch.abort(ErrorCode::PeerClosed, false, false);

        assert_eq!(launch.runner_finished(false), None);
        assert!(matches!(
            launch.resolve_receipt(),
            ReceiptResolution::Resolved(Some(false))
        ));
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn receipt_resolution_releases_the_initial_thread_pin() {
        let launch = launch(StartResultPublication::Delivered);
        let thread_id = launch.process.create_thread().unwrap();
        launch.process.pin_startup_thread(thread_id).unwrap();
        launch.state.lock().unwrap().pinned_initial_thread_id = Some(thread_id);

        launch.resolve_receipt();

        assert_eq!(launch.process.exit_thread(thread_id), Ok(()));
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn process_ready_waits_until_the_initial_thread_pin_is_released() {
        let launch = launch(StartResultPublication::Delivered);
        launch.state.lock().unwrap().phase = ChildLaunchPhase::Starting;
        let thread_id = launch.process.create_thread().unwrap();
        let waiting = Arc::clone(&launch);
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            sender
                .send(waiting.ready_and_wait(Some(thread_id)))
                .unwrap();
        });

        let mut state = launch.state.lock().unwrap();
        while !matches!(state.phase, ChildLaunchPhase::Ready { .. }) {
            state = launch.changed.wait(state).unwrap();
        }
        state.phase = ChildLaunchPhase::Committed;
        launch.changed.notify_all();
        drop(state);
        assert!(receiver.recv_timeout(Duration::from_millis(20)).is_err());

        launch.resolve_receipt();
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            Ok(())
        );
        worker.join().unwrap();
        assert_eq!(launch.process.exit_thread(thread_id), Ok(()));
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn acknowledgement_admission_preserves_the_publication_deadline() {
        let launch = launch(StartResultPublication::Publishing);
        launch.admit_acknowledgement().unwrap();

        let _expiration = launch.expire_initial_receipt_deadline().unwrap();
        let state = launch.state.lock().unwrap();
        assert!(matches!(
            state.phase,
            ChildLaunchPhase::Aborted(ErrorCode::Internal)
        ));
        assert!(state.abnormal);
        drop(state);
        assert_eq!(launch.complete_timeout_callback(), None);
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn receipt_timeout_defers_finalization_until_association_drain() {
        let launch = launch(StartResultPublication::Delivered);

        assert_eq!(launch.runner_finished(false), None);
        let _expiration = launch.expire_initial_receipt_deadline().unwrap();
        assert!(matches!(
            launch.resolve_receipt(),
            ReceiptResolution::DeferredToDrain
        ));
        assert_eq!(launch.complete_timeout_callback(), None);
        launch.begin_receipt_drain();
        assert_eq!(launch.finish_receipt_drain(), Some(false));
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn unpublished_launch_waits_for_receipt_drain_before_finalization() {
        let launch = launch(StartResultPublication::NotStarted);

        launch.begin_receipt_drain();
        assert_eq!(launch.runner_finished(false), None);
        assert_eq!(launch.finish_receipt_drain(), Some(false));
        Arc::clone(&launch.process).finish();
    }

    #[test]
    fn deferred_finalization_uses_the_latest_abnormal_disposition() {
        let launch = launch(StartResultPublication::Publishing);
        launch.admit_acknowledgement().unwrap();

        assert_eq!(launch.runner_finished(false), None);
        let _expiration = launch.expire_initial_receipt_deadline().unwrap();
        assert_eq!(launch.complete_timeout_callback(), None);
        launch.begin_receipt_drain();
        assert_eq!(launch.finish_receipt_drain(), Some(true));
        Arc::clone(&launch.process).finish_abnormal();
    }

    #[test]
    fn acknowledgement_send_does_not_steal_a_timed_out_receipt_from_drain() {
        let (broker, launch) = launch_with_broker(StartResultPublication::Delivered);
        let token = ProcessStartToken(7);
        let parent_id = launch.parent_id;
        let children = RunnerChildren {
            broker,
            config: RunnerConfig::new(PathBuf::new(), Vec::new()),
            state: Mutex::new(RunnerChildrenState {
                launches: vec![(token, Arc::clone(&launch))],
                associations: Vec::new(),
                active_instances: 1,
                active_watchdogs: 0,
            }),
            drained: Condvar::new(),
        };

        assert_eq!(launch.runner_finished(false), None);
        let _expiration = launch.expire_initial_receipt_deadline().unwrap();
        children.response_sent(
            parent_id,
            &BrokerOperation::AcknowledgeProcessStart(token),
            &BrokerResult::ProcessStartAcknowledged,
        );

        assert!(children.find_launch(token).is_some());
        assert_eq!(launch.complete_timeout_callback(), None);
        let draining = children.association_ending(parent_id);
        assert_eq!(draining.len(), 1);
        children.association_ended(parent_id, draining);
        assert!(children.find_launch(token).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shutdown_can_terminate_while_the_launch_owner_waits() {
        use super::{RunnerShutdown, RunnerShutdownState, wait_for_runner_exit};
        use std::process::Command;

        let child = Arc::new(Mutex::new(
            Command::new("sh")
                .args(["-c", "exec sleep 30"])
                .spawn()
                .unwrap(),
        ));
        let shutdown = RunnerShutdown {
            runner: Arc::clone(&child),
            state: Mutex::new(RunnerShutdownState::Active),
            changed: Condvar::new(),
            termination_dispatched: AtomicBool::new(false),
        };
        let waiting = Arc::clone(&child);
        let (finished, completion) = mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            let status = wait_for_runner_exit(&waiting).unwrap();
            finished.send(status).unwrap();
        });

        shutdown.shutdown();
        assert!(shutdown.termination_was_dispatched());
        assert!(
            !completion
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .success()
        );
        waiter.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shutdown_after_observed_exit_records_no_termination() {
        use super::{RunnerShutdown, RunnerShutdownState, wait_for_runner_exit};
        use std::process::Command;

        let child = Arc::new(Mutex::new(
            Command::new("sh").args(["-c", "exit 1"]).spawn().unwrap(),
        ));
        let shutdown = RunnerShutdown {
            runner: Arc::clone(&child),
            state: Mutex::new(RunnerShutdownState::Active),
            changed: Condvar::new(),
            termination_dispatched: AtomicBool::new(false),
        };
        assert!(shutdown.wait_for_exit(Duration::from_secs(1)).unwrap());

        shutdown.shutdown();
        shutdown.retire();

        assert!(!shutdown.termination_was_dispatched());
        assert!(!wait_for_runner_exit(&child).unwrap().success());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn signal_termination_is_distinct_from_an_ordinary_nonzero_exit() {
        use super::{runner_exit_signal, runner_signal_is_abnormal};
        use std::process::Command;

        let signaled = Command::new("sh")
            .args(["-c", "kill -SEGV $$"])
            .status()
            .unwrap();
        let nonzero = Command::new("sh").args(["-c", "exit 7"]).status().unwrap();

        let signal = runner_exit_signal(signaled);
        assert!(signal.is_some());
        assert!(runner_exit_signal(nonzero).is_none());
        assert!(runner_signal_is_abnormal(signal, true));
        assert!(!runner_signal_is_abnormal(Some(libc::SIGKILL), true));
    }
}
