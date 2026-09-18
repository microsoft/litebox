// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Coordination for broker-requested runner process starts.

use std::io::{Error as IoError, Result as IoResult};
use std::process::ExitStatus;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerError, BrokerProcess};
use litebox_broker_host::{RequestFailure, copy_shared_buffer};
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult};
use litebox_broker_protocol::process::{
    InheritedProcessObjects, MAX_PROCESS_BOOTSTRAP_SIZE, ProcessBootstrapFormat,
    ProcessBootstrapVersion, ProcessStartToken, ProcessStartupData, StartedProcess,
};
use litebox_broker_protocol::{ProcessId, ThreadId};
use litebox_broker_transport::shared_memory::{SharedBufferPool, SharedMemory};

use super::{
    PROCESS_EXIT_OBSERVATION_TIMEOUT, RunnerConfig, RunnerInstance, RunnerShutdown,
    runner_exit_code_is_crash, runner_exit_code_is_expected_shutdown, runner_exit_signal,
    runner_signal_is_abnormal, wait_for_runner_exit,
};
use crate::runtime::AssociationFailureCause;

const PROCESS_START_RECEIPT_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_START_INTERNAL_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_START_ACKNOWLEDGEMENT_PUBLICATION_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_START_SUPERVISOR_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PENDING_PROCESS_STARTS: usize = crate::WORKER_COUNT - 1;
const _: () = assert!(MAX_PENDING_PROCESS_STARTS > 0);
const _: () =
    assert!(crate::runtime::PROCESS_START_CONTROL_WORKER_COUNT > MAX_PENDING_PROCESS_STARTS);
const _: () =
    assert!(crate::runtime::PROCESS_START_CONTROL_QUEUE_CAPACITY >= MAX_PENDING_PROCESS_STARTS);

/// Shared coordination for runner process starts and active associations.
pub(crate) struct RunnerProcessManager {
    broker: BrokerCore,
    process_start_config: RunnerConfig,
    state: Mutex<RunnerProcessManagerInner>,
    drained: Condvar,
}

/// Startup context for a runner whose broker process was created by its parent.
pub(crate) struct RunnerStartup {
    process: Arc<BrokerProcess>,
    start: Arc<ProcessStart>,
    data: ProcessStartupData,
}

impl RunnerStartup {
    pub(crate) fn into_process_and_data(self) -> (Arc<BrokerProcess>, ProcessStartupData) {
        (self.process, self.data)
    }
}

struct RunnerCompletion {
    result: IoResult<ExitStatus>,
    runner_success: Option<bool>,
    runner_signal: Option<i32>,
    runner_exit_code: Option<i32>,
    termination_provenance: TerminationProvenance,
    association_panicked: bool,
    shutdown_observation_failed: bool,
}

#[derive(Clone, Copy, Default)]
struct TerminationProvenance(u8);

impl TerminationProvenance {
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

struct RunnerProcessManagerInner {
    starts: Vec<(ProcessStartToken, Arc<ProcessStart>)>,
    associations: Vec<(ProcessId, AssociationFailure)>,
    active_instances: usize,
    active_watchdogs: usize,
}

pub(crate) type AssociationFailure = Arc<dyn Fn() + Send + Sync>;

pub(crate) struct ProcessStartDrain {
    starts: Vec<Arc<ProcessStart>>,
}

struct ProcessStart {
    parent_id: ProcessId,
    process: Arc<BrokerProcess>,
    state: Mutex<ProcessStartInner>,
    changed: Condvar,
}

#[derive(Clone, Copy)]
enum ProcessStartPhase {
    Starting,
    Ready { initial_thread_id: Option<ThreadId> },
    Committing,
    Committed,
    CompletingStart,
    StartComplete,
    Aborted(ErrorCode),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StartResultPublication {
    NotStarted,
    Publishing,
    Delivered,
}

struct ProcessStartInner {
    phase: ProcessStartPhase,
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

impl RunnerInstance {
    fn run_started_process_to_completion(
        mut self,
        startup: RunnerStartup,
        process_manager: Arc<RunnerProcessManager>,
    ) -> RunnerCompletion {
        let start = Arc::clone(&startup.start);
        start.install_shutdown(Arc::clone(&self.shutdown));
        let association_result = self
            .endpoint
            .serve(&self.runner, Some(startup), process_manager);
        self.endpoint.close();
        let shutdown_request = start.shutdown_request();
        let shutdown_was_expected = shutdown_request.was_expected();
        if association_result.abnormal {
            start.mark_abnormal();
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
                    start.mark_abnormal();
                }
                false
            }
            Ok(false) => {
                if !shutdown_was_expected
                    || association_result.failure_cause == AssociationFailureCause::Other
                {
                    start.mark_abnormal();
                }
                start.mark_shutdown_expected();
                self.shutdown.shutdown();
                false
            }
            Err(_) => {
                start.mark_abnormal();
                self.shutdown.shutdown();
                true
            }
        };
        self.shutdown.retire();
        let runner_status = wait_for_runner_exit(&self.runner);
        if runner_status.is_err() {
            start.mark_abnormal();
        }
        let runner_success = runner_status.as_ref().ok().map(ExitStatus::success);
        let runner_signal = runner_status
            .as_ref()
            .ok()
            .copied()
            .and_then(runner_exit_signal);
        let runner_exit_code = runner_status.as_ref().ok().and_then(ExitStatus::code);
        let termination_provenance = TerminationProvenance::new(
            self.shutdown.termination_was_dispatched(),
            shutdown_request.expected_start_failure_was_reported(),
        );
        let result = runner_status.and_then(|status| {
            association_result.result?;
            Ok(status)
        });
        RunnerCompletion {
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

impl RunnerProcessManager {
    pub(super) fn new(process_start_config: RunnerConfig, broker: BrokerCore) -> Arc<Self> {
        Arc::new(Self {
            broker,
            process_start_config,
            state: Mutex::new(RunnerProcessManagerInner {
                starts: Vec::new(),
                associations: Vec::new(),
                active_instances: 0,
                active_watchdogs: 0,
            }),
            drained: Condvar::new(),
        })
    }

    pub(crate) fn broker(&self) -> BrokerCore {
        self.broker.clone()
    }

    pub(crate) fn handle_operation<Memory: SharedMemory>(
        self: &Arc<Self>,
        process: &BrokerProcess,
        operation: &BrokerOperation,
        shared_buffers: &SharedBufferPool<Memory>,
    ) -> Option<Result<BrokerResult, RequestFailure>> {
        match operation {
            BrokerOperation::StartProcess(request) => Some(
                copy_shared_buffer(shared_buffers, request.buffer, MAX_PROCESS_BOOTSTRAP_SIZE)
                    .and_then(|bootstrap| {
                        self.start_process(
                            process,
                            request.format,
                            request.version,
                            bootstrap,
                            request.inherited_objects,
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
                    Err(error) => Err(RequestFailure::Abort(error)),
                })
            }
            BrokerOperation::ReportProcessReady(initial_thread_id) => Some(
                self.process_ready(process.id(), *initial_thread_id)
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
                let Some(start) = self.find_start(started.token) else {
                    return;
                };
                if start.parent_id == process_id {
                    start.mark_start_result_delivered();
                }
            }
            (
                BrokerOperation::AcknowledgeProcessStart(token),
                BrokerResult::ProcessStartAcknowledged | BrokerResult::ProcessStartFailed(_),
            ) => {
                let Some(start) = self.find_start(*token) else {
                    return;
                };
                if start.parent_id != process_id {
                    return;
                }
                if let ReceiptResolution::Resolved(finalization) = start.resolve_receipt() {
                    self.remove_start(*token);
                    if let Some(abnormal) = finalization {
                        self.finish_process_start(&start, abnormal);
                    }
                }
            }
            (
                BrokerOperation::ReportProcessStartFailure(error),
                BrokerResult::ProcessStartFailed(reported),
            ) if error == reported => {
                if let Some(start) = self.find_process_start(process_id) {
                    start.start_failure_response_sent(*error);
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
        requested_inherited_objects: InheritedProcessObjects,
    ) -> Result<StartedProcess, ErrorCode> {
        if !parent.is_running() {
            return Err(ErrorCode::ProtocolState);
        }
        let (process, inherited_objects) = parent
            .create_child(requested_inherited_objects.as_slice())
            .map_err(ErrorCode::from)?;
        let inherited_objects = InheritedProcessObjects::new(&inherited_objects)
            .expect("child handle count must match the bounded inheritance request");
        let process_id = process.id();
        let start = Arc::new(ProcessStart {
            parent_id: parent.id(),
            process: Arc::clone(&process),
            state: Mutex::new(ProcessStartInner {
                phase: ProcessStartPhase::Starting,
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
                    .expect("runner process manager state mutex poisoned");
                state
                    .starts
                    .try_reserve(1)
                    .map_err(|_| ErrorCode::OutOfMemory)?;
                if parent.is_cancellation_requested() {
                    return Err(ErrorCode::PeerClosed);
                }
                if state.starts.len() >= MAX_PENDING_PROCESS_STARTS {
                    return Err(ErrorCode::ResourceExhausted);
                }
                if state
                    .starts
                    .iter()
                    .any(|(candidate, _)| *candidate == token)
                {
                    continue;
                }
                let active_instances = state
                    .active_instances
                    .checked_add(1)
                    .ok_or(ErrorCode::ResourceExhausted)?;
                state.starts.push((token, Arc::clone(&start)));
                state.active_instances = active_instances;
                return Ok(token);
            }
        })() {
            Ok(token) => token,
            Err(error) => {
                process.cleanup(true);
                return Err(error);
            }
        };

        let process_manager = Arc::clone(self);
        let config = self.process_start_config.clone();
        let thread_start = Arc::clone(&start);
        let thread = std::thread::Builder::new()
            .name(format!("litebox-runner-{}", process_id.0))
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    RunnerInstance::start(config).map(|instance| {
                        instance.run_started_process_to_completion(
                            RunnerStartup {
                                process,
                                start: Arc::clone(&thread_start),
                                data: ProcessStartupData {
                                    format,
                                    version,
                                    payload: bootstrap,
                                    inherited_objects,
                                },
                            },
                            Arc::clone(&process_manager),
                        )
                    })
                }));
                match outcome {
                    Ok(Ok(result)) => {
                        process_manager.runner_finished(token, &thread_start, result, false);
                    }
                    Ok(Err(error)) => process_manager.runner_finished(
                        token,
                        &thread_start,
                        RunnerCompletion {
                            result: Err(error),
                            runner_success: None,
                            runner_signal: None,
                            runner_exit_code: None,
                            termination_provenance: TerminationProvenance::default(),
                            association_panicked: false,
                            shutdown_observation_failed: false,
                        },
                        false,
                    ),
                    Err(_) => process_manager.runner_finished(
                        token,
                        &thread_start,
                        RunnerCompletion {
                            result: Err(IoError::other("runner process thread panicked")),
                            runner_success: None,
                            runner_signal: None,
                            runner_exit_code: None,
                            termination_provenance: TerminationProvenance::default(),
                            association_panicked: false,
                            shutdown_observation_failed: false,
                        },
                        true,
                    ),
                }
            });
        if thread.is_err() {
            self.remove_start(token);
            start.process.cleanup(true);
            self.finish_instance();
            return Err(ErrorCode::OutOfMemory);
        }
        drop(thread);

        let initial_thread_id = start.wait_until_ready()?;
        let receipt_deadline = start.begin_start_result_publication()?;
        if self
            .arm_initial_receipt_deadline(token, &start, receipt_deadline)
            .is_err()
        {
            if let Some(expiration) = start.expire_initial_receipt_deadline() {
                self.apply_receipt_expiration(
                    token,
                    &start,
                    expiration,
                    self.find_association_failure(start.parent_id),
                );
            }
            return Err(ErrorCode::OutOfMemory);
        }
        Ok(StartedProcess {
            token,
            process_id,
            initial_thread_id,
        })
    }

    pub(crate) fn admit_acknowledgement(
        self: &Arc<Self>,
        parent_id: ProcessId,
        token: ProcessStartToken,
    ) -> Result<(), ErrorCode> {
        let start = self.find_start(token).ok_or(ErrorCode::UnknownObject)?;
        if start.parent_id != parent_id {
            return Err(ErrorCode::UnknownObject);
        }
        start.admit_acknowledgement()?;
        if self
            .arm_internal_resolution_watchdog(token, &start)
            .is_err()
        {
            if let Some(expiration) = start.fail_internal_resolution_watchdog() {
                self.apply_receipt_expiration(
                    token,
                    &start,
                    expiration,
                    self.find_association_failure(start.parent_id),
                );
            }
            return Err(ErrorCode::Internal);
        }
        if self
            .arm_acknowledgement_publication_watchdog(token, &start)
            .is_err()
        {
            if let Some(expiration) = start.fail_internal_resolution_watchdog() {
                self.apply_receipt_expiration(
                    token,
                    &start,
                    expiration,
                    self.find_association_failure(start.parent_id),
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
        let start = self.find_start(token).ok_or(ErrorCode::PeerClosed)?;
        if start.parent_id != parent_id {
            return Err(ErrorCode::UnknownObject);
        }
        start.resolve_acknowledgement()
    }

    fn process_ready(
        &self,
        process_id: ProcessId,
        initial_thread_id: Option<ThreadId>,
    ) -> Result<(), ErrorCode> {
        let start = self
            .find_process_start(process_id)
            .ok_or(ErrorCode::PeerClosed)?;
        start.ready_and_wait(initial_thread_id)
    }

    fn report_process_start_failure(
        self: &Arc<Self>,
        process_id: ProcessId,
        error: ErrorCode,
    ) -> Result<(), ErrorCode> {
        let (token, start) = self
            .find_process_start_entry(process_id)
            .ok_or(ErrorCode::PeerClosed)?;
        start.report_start_failure(error)?;
        if self
            .arm_start_failure_publication_watchdog(token, &start)
            .is_err()
        {
            if let Some(expiration) = start.fail_start_failure_publication_watchdog() {
                self.apply_receipt_expiration(token, &start, expiration, None);
            }
            return Err(ErrorCode::Internal);
        }
        Ok(())
    }

    pub(crate) fn association_ending(&self, process_id: ProcessId) -> ProcessStartDrain {
        let draining = self
            .state
            .lock()
            .expect("runner process manager state mutex poisoned")
            .starts
            .iter()
            .filter(|(_, start)| start.parent_id == process_id)
            .map(|(_, start)| Arc::clone(start))
            .collect::<Vec<_>>();
        for start in &draining {
            start.abort(ErrorCode::PeerClosed, false, true);
            start.begin_receipt_drain();
        }

        let process_start = {
            self.state
                .lock()
                .expect("runner process manager state mutex poisoned")
                .starts
                .iter()
                .find_map(|(_, start)| {
                    (start.process.id() == process_id).then(|| Arc::clone(start))
                })
        };
        if let Some(start) = process_start {
            start.association_closed();
        }
        ProcessStartDrain { starts: draining }
    }

    pub(crate) fn association_ended(&self, process_id: ProcessId, draining: ProcessStartDrain) {
        self.unregister_association(process_id);
        for start in draining.starts {
            self.remove_start_by_process_id(start.process.id());
            if let Some(abnormal) = start.finish_receipt_drain() {
                self.finish_process_start(&start, abnormal);
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
            .expect("runner process manager state mutex poisoned");
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

    pub(crate) fn install_process_association_failure(
        &self,
        process_id: ProcessId,
        failure: AssociationFailure,
    ) {
        if let Some(start) = self.find_process_start(process_id) {
            start.install_association_failure(failure);
        }
    }

    fn unregister_association(&self, process_id: ProcessId) {
        let mut state = self
            .state
            .lock()
            .expect("runner process manager state mutex poisoned");
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
            .expect("runner process manager state mutex poisoned")
            .associations
            .iter()
            .find_map(|(candidate, failure)| {
                (*candidate == process_id).then(|| Arc::clone(failure))
            })
    }

    fn arm_initial_receipt_deadline(
        self: &Arc<Self>,
        token: ProcessStartToken,
        start: &Arc<ProcessStart>,
        deadline: Instant,
    ) -> Result<(), ()> {
        let start = Arc::clone(start);
        let parent_failure = self.find_association_failure(start.parent_id);
        self.spawn_watchdog(
            format!("litebox-start-receipt-{}", start.process.id().0),
            move |process_manager| {
                let Some(expiration) = start.wait_for_initial_receipt_deadline(deadline) else {
                    return;
                };
                process_manager.apply_receipt_expiration(token, &start, expiration, parent_failure);
            },
        )
    }

    fn arm_internal_resolution_watchdog(
        self: &Arc<Self>,
        token: ProcessStartToken,
        start: &Arc<ProcessStart>,
    ) -> Result<(), ()> {
        let start = Arc::clone(start);
        let parent_failure = self.find_association_failure(start.parent_id);
        self.spawn_watchdog(
            format!("litebox-start-resolution-{}", start.process.id().0),
            move |process_manager| {
                let Some(expiration) = start.wait_for_internal_resolution_timeout() else {
                    return;
                };
                process_manager.apply_receipt_expiration(token, &start, expiration, parent_failure);
            },
        )
    }

    fn arm_acknowledgement_publication_watchdog(
        self: &Arc<Self>,
        token: ProcessStartToken,
        start: &Arc<ProcessStart>,
    ) -> Result<(), ()> {
        let start = Arc::clone(start);
        let parent_failure = self.find_association_failure(start.parent_id);
        self.spawn_watchdog(
            format!("litebox-start-ack-publication-{}", start.process.id().0),
            move |process_manager| {
                let Some(expiration) = start.wait_for_acknowledgement_publication_timeout() else {
                    return;
                };
                process_manager.apply_receipt_expiration(token, &start, expiration, parent_failure);
            },
        )
    }

    fn arm_start_failure_publication_watchdog(
        self: &Arc<Self>,
        token: ProcessStartToken,
        start: &Arc<ProcessStart>,
    ) -> Result<(), ()> {
        let start = Arc::clone(start);
        self.spawn_watchdog(
            format!("litebox-start-failure-publication-{}", start.process.id().0),
            move |process_manager| {
                let Some(expiration) = start.wait_for_start_failure_publication_timeout() else {
                    return;
                };
                process_manager.apply_receipt_expiration(token, &start, expiration, None);
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
                .expect("runner process manager state mutex poisoned");
            state.active_watchdogs = state.active_watchdogs.checked_add(1).ok_or(())?;
        }
        let process_manager = Arc::clone(self);
        if let Ok(thread) = std::thread::Builder::new().name(name).spawn(move || {
            let _completion = WatchdogCompletion {
                process_manager: Arc::clone(&process_manager),
            };
            watchdog(&process_manager);
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
        start: &ProcessStart,
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
        if let Some(abnormal) = start.complete_timeout_callback() {
            self.finish_process_start(start, abnormal);
        }
        if fail_parent && !parent_failed {
            self.remove_start(token);
            if let Some(abnormal) = start.finish_receipt_drain() {
                self.finish_process_start(start, abnormal);
            }
        }
        if let Some(deadline) = commit_supervision_deadline
            && !start.wait_for_commit_resolution(deadline)
        {
            std::process::abort();
        }
    }

    fn find_start(&self, token: ProcessStartToken) -> Option<Arc<ProcessStart>> {
        self.state
            .lock()
            .expect("runner process manager state mutex poisoned")
            .starts
            .iter()
            .find_map(|(candidate, start)| (*candidate == token).then(|| Arc::clone(start)))
    }

    fn find_process_start(&self, process_id: ProcessId) -> Option<Arc<ProcessStart>> {
        self.find_process_start_entry(process_id)
            .map(|(_, start)| start)
    }

    fn find_process_start_entry(
        &self,
        process_id: ProcessId,
    ) -> Option<(ProcessStartToken, Arc<ProcessStart>)> {
        self.state
            .lock()
            .expect("runner process manager state mutex poisoned")
            .starts
            .iter()
            .find_map(|(token, start)| {
                (start.process.id() == process_id).then(|| (*token, Arc::clone(start)))
            })
    }

    fn remove_start(&self, token: ProcessStartToken) {
        let mut state = self
            .state
            .lock()
            .expect("runner process manager state mutex poisoned");
        if let Some(index) = state
            .starts
            .iter()
            .position(|(candidate, _)| *candidate == token)
        {
            state.starts.swap_remove(index);
        }
    }

    fn remove_start_by_process_id(&self, process_id: ProcessId) {
        let mut state = self
            .state
            .lock()
            .expect("runner process manager state mutex poisoned");
        if let Some(index) = state
            .starts
            .iter()
            .position(|(_, start)| start.process.id() == process_id)
        {
            state.starts.swap_remove(index);
        }
    }

    fn runner_finished(
        &self,
        token: ProcessStartToken,
        start: &ProcessStart,
        result: RunnerCompletion,
        thread_panicked: bool,
    ) {
        let unexpected_runner_failure = result.runner_success == Some(false)
            && result.runner_signal.is_none()
            && !start.commit_was_claimed()
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
            start.abort(ErrorCode::PeerClosed, abnormal, false);
        } else {
            // Any clean host exit before commit still aborts creation.
            start.abort(ErrorCode::PeerClosed, false, false);
        }
        if !start.retains_published_receipt() {
            self.remove_start(token);
            if let ReceiptResolution::Resolved(finalization) = start.resolve_receipt() {
                debug_assert!(finalization.is_none());
            }
        }
        if let Some(abnormal) = start.runner_finished(abnormal) {
            self.finish_process_start(start, abnormal);
        }
    }

    fn finish_process_start(&self, start: &ProcessStart, abnormal: bool) {
        start.process.cleanup(!abnormal);
        self.finish_instance();
    }

    fn finish_instance(&self) {
        let mut state = self
            .state
            .lock()
            .expect("runner process manager state mutex poisoned");
        state.active_instances = state
            .active_instances
            .checked_sub(1)
            .expect("runner instance count must remain balanced");
        if state.active_instances == 0 && state.active_watchdogs == 0 {
            self.drained.notify_all();
        }
    }

    fn finish_watchdog(&self) {
        let mut state = self
            .state
            .lock()
            .expect("runner process manager state mutex poisoned");
        state.active_watchdogs = state
            .active_watchdogs
            .checked_sub(1)
            .expect("runner watchdog count must remain balanced");
        if state.active_instances == 0 && state.active_watchdogs == 0 {
            self.drained.notify_all();
        }
    }

    pub(super) fn wait_for_drain(&self) {
        let mut state = self
            .state
            .lock()
            .expect("runner process manager state mutex poisoned");
        while state.active_instances != 0 || state.active_watchdogs != 0 {
            state = self
                .drained
                .wait(state)
                .expect("runner process manager state mutex poisoned");
        }
    }
}

struct WatchdogCompletion {
    process_manager: Arc<RunnerProcessManager>,
}

impl Drop for WatchdogCompletion {
    fn drop(&mut self) {
        self.process_manager.finish_watchdog();
    }
}

const fn process_extension_error(error: ErrorCode) -> RequestFailure {
    match error {
        ErrorCode::PolicyDenied
        | ErrorCode::UnknownObject
        | ErrorCode::InvalidRights
        | ErrorCode::ResourceExhausted
        | ErrorCode::WouldBlock
        | ErrorCode::PeerClosed
        | ErrorCode::OutOfMemory
        | ErrorCode::UnsupportedOperation => RequestFailure::Respond(error),
        _ => RequestFailure::Abort(error),
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

impl ProcessStart {
    fn wait_until_ready(&self) -> Result<Option<ThreadId>, ErrorCode> {
        let mut state = self.state.lock().expect("process start mutex poisoned");
        loop {
            match state.phase {
                ProcessStartPhase::Starting => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("process start mutex poisoned");
                }
                ProcessStartPhase::Ready { initial_thread_id } => return Ok(initial_thread_id),
                ProcessStartPhase::Committing
                | ProcessStartPhase::Committed
                | ProcessStartPhase::CompletingStart
                | ProcessStartPhase::StartComplete => {
                    return Err(ErrorCode::ProtocolState);
                }
                ProcessStartPhase::Aborted(error) => return Err(error),
            }
        }
    }

    fn ready_and_wait(&self, initial_thread_id: Option<ThreadId>) -> Result<(), ErrorCode> {
        self.process
            .mark_start_ready(initial_thread_id)
            .map_err(|error| match error {
                BrokerError::UnknownObject => ErrorCode::ProtocolState,
                error => ErrorCode::from(error),
            })?;
        let mut state = self.state.lock().expect("process start mutex poisoned");
        if !matches!(state.phase, ProcessStartPhase::Starting) {
            return Err(match state.phase {
                ProcessStartPhase::Aborted(error) => error,
                _ => ErrorCode::ProtocolState,
            });
        }
        state.phase = ProcessStartPhase::Ready { initial_thread_id };
        self.changed.notify_all();
        loop {
            match state.phase {
                ProcessStartPhase::StartComplete if state.active_control_callbacks == 0 => {
                    return Ok(());
                }
                ProcessStartPhase::Ready { .. }
                | ProcessStartPhase::Committing
                | ProcessStartPhase::Committed
                | ProcessStartPhase::CompletingStart
                | ProcessStartPhase::StartComplete => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("process start mutex poisoned");
                }
                ProcessStartPhase::Aborted(error) => return Err(error),
                ProcessStartPhase::Starting => unreachable!("ready state cannot regress"),
            }
        }
    }

    fn begin_start_result_publication(&self) -> Result<Instant, ErrorCode> {
        let mut state = self.state.lock().expect("process start mutex poisoned");
        match state.phase {
            ProcessStartPhase::Ready { .. }
                if state.publication == StartResultPublication::NotStarted =>
            {
                state.publication = StartResultPublication::Publishing;
                Ok(Instant::now() + PROCESS_START_RECEIPT_TIMEOUT)
            }
            ProcessStartPhase::Aborted(error) => Err(error),
            _ => Err(ErrorCode::ProtocolState),
        }
    }

    fn report_start_failure(&self, error: ErrorCode) -> Result<(), ErrorCode> {
        if !process_start_failure_is_expected(error) {
            return Err(ErrorCode::ProtocolState);
        }
        let mut state = self.state.lock().expect("process start mutex poisoned");
        match state.phase {
            ProcessStartPhase::Starting => {}
            ProcessStartPhase::Aborted(error) => return Err(error),
            _ => return Err(ErrorCode::ProtocolState),
        }
        state.phase = ProcessStartPhase::Aborted(error);
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
            let mut state = self.state.lock().expect("process start mutex poisoned");
            complete_deadline(&mut state.start_failure_publication_watchdog);
            let actions = if matches!(state.phase, ProcessStartPhase::Aborted(cause) if cause == error)
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
        let mut state = self.state.lock().expect("process start mutex poisoned");
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
                ProcessStartPhase::Ready { .. } | ProcessStartPhase::Aborted(_)
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
        let mut state = self.state.lock().expect("process start mutex poisoned");
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
                    ProcessStartPhase::Ready { .. } | ProcessStartPhase::Aborted(_),
                    StartResultPublication::Publishing,
                ) => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("process start mutex poisoned");
                }
                (ProcessStartPhase::Ready { .. }, StartResultPublication::Delivered) => {
                    debug_assert!(matches!(state.resolution_watchdog, DeadlineState::Armed(_)));
                    state.phase = ProcessStartPhase::Committing;
                    drop(state);
                    let commit_result = self.process.commit_start().map_err(ErrorCode::from);
                    state = self.state.lock().expect("process start mutex poisoned");
                    match commit_result {
                        Ok(()) => {
                            state.phase = ProcessStartPhase::Committed;
                            complete_acknowledgement_resolution(&mut state);
                            self.changed.notify_all();
                            return Ok(ProcessStartAcknowledgement::Acknowledged);
                        }
                        Err(error) => {
                            state.phase = ProcessStartPhase::Aborted(error);
                            state.abnormal |= error == ErrorCode::Internal;
                            complete_acknowledgement_resolution(&mut state);
                            self.changed.notify_all();
                            return Ok(ProcessStartAcknowledgement::Failed(error));
                        }
                    }
                }
                (ProcessStartPhase::Aborted(error), StartResultPublication::Delivered) => {
                    debug_assert!(matches!(
                        state.resolution_watchdog,
                        DeadlineState::Armed(_) | DeadlineState::Fired
                    ));
                    complete_acknowledgement_resolution(&mut state);
                    self.changed.notify_all();
                    return Ok(ProcessStartAcknowledgement::Failed(error));
                }
                (ProcessStartPhase::Starting, _) => return Err(ErrorCode::ProtocolState),
                (
                    ProcessStartPhase::Committing
                    | ProcessStartPhase::Committed
                    | ProcessStartPhase::CompletingStart
                    | ProcessStartPhase::StartComplete,
                    _,
                ) => {
                    return Err(ErrorCode::ProtocolState);
                }
                (_, StartResultPublication::NotStarted) => {
                    unreachable!("publication state was checked before phase dispatch")
                }
            }
        }
    }

    fn mark_start_result_delivered(&self) {
        let mut state = self.state.lock().expect("process start mutex poisoned");
        if state.publication == StartResultPublication::Publishing {
            state.publication = StartResultPublication::Delivered;
            if state.receipt == ReceiptState::AcknowledgementAdmitted
                && matches!(
                    state.phase,
                    ProcessStartPhase::Ready { .. } | ProcessStartPhase::Aborted(_)
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
            let mut state = self.state.lock().expect("process start mutex poisoned");
            state.shutdown = Some(Arc::clone(&shutdown));
            (state.shutdown_request != ShutdownRequest::None).then_some(shutdown)
        };
        if let Some(shutdown) = shutdown {
            shutdown.shutdown();
        }
    }

    fn install_association_failure(&self, failure: AssociationFailure) {
        let failure = {
            let mut state = self.state.lock().expect("process start mutex poisoned");
            state.association_failure = Some(Arc::clone(&failure));
            (state.shutdown_request != ShutdownRequest::None).then_some(failure)
        };
        if let Some(failure) = failure {
            failure();
        }
    }

    fn abort(&self, error: ErrorCode, abnormal: bool, expected_shutdown: bool) {
        let (association_failure, shutdown) = {
            let mut state = self.state.lock().expect("process start mutex poisoned");
            state.abnormal |= abnormal;
            match state.phase {
                ProcessStartPhase::Starting | ProcessStartPhase::Ready { .. } => {
                    state.phase = ProcessStartPhase::Aborted(error);
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
                ProcessStartPhase::Aborted(_) => match state.shutdown_request {
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
                ProcessStartPhase::Committing
                | ProcessStartPhase::Committed
                | ProcessStartPhase::CompletingStart
                | ProcessStartPhase::StartComplete => (None, None),
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
        let mut state = self.state.lock().expect("process start mutex poisoned");
        state.association_failure = None;
        if matches!(
            state.phase,
            ProcessStartPhase::Starting | ProcessStartPhase::Ready { .. }
        ) {
            state.phase = ProcessStartPhase::Aborted(ErrorCode::PeerClosed);
            self.changed.notify_all();
        }
    }

    fn mark_shutdown_expected(&self) {
        let mut state = self.state.lock().expect("process start mutex poisoned");
        if state.shutdown_request == ShutdownRequest::None {
            state.shutdown_request = ShutdownRequest::Expected;
        }
    }

    fn mark_abnormal(&self) {
        self.state
            .lock()
            .expect("process start mutex poisoned")
            .abnormal = true;
    }

    fn shutdown_request(&self) -> ShutdownRequest {
        self.state
            .lock()
            .expect("process start mutex poisoned")
            .shutdown_request
    }

    fn commit_was_claimed(&self) -> bool {
        matches!(
            self.state
                .lock()
                .expect("process start mutex poisoned")
                .phase,
            ProcessStartPhase::Committing
                | ProcessStartPhase::Committed
                | ProcessStartPhase::CompletingStart
                | ProcessStartPhase::StartComplete
        )
    }

    fn retains_published_receipt(&self) -> bool {
        let state = self.state.lock().expect("process start mutex poisoned");
        state.publication != StartResultPublication::NotStarted
            && state.receipt != ReceiptState::Resolved
    }

    fn resolve_receipt(&self) -> ReceiptResolution {
        let mut state = self.state.lock().expect("process start mutex poisoned");
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
        ReceiptResolution::Resolved(self.complete_process_start_and_take_finalization(state))
    }

    fn begin_receipt_drain(&self) {
        let mut state = self.state.lock().expect("process start mutex poisoned");
        if state.receipt != ReceiptState::Resolved {
            state.receipt = ReceiptState::Draining;
            if !matches!(state.phase, ProcessStartPhase::Committing) {
                complete_deadline(&mut state.resolution_watchdog);
            }
            complete_deadline(&mut state.acknowledgement_publication_watchdog);
            complete_deadline(&mut state.start_failure_publication_watchdog);
            self.changed.notify_all();
        }
    }

    fn finish_receipt_drain(&self) -> Option<bool> {
        let mut state = self.state.lock().expect("process start mutex poisoned");
        state.receipt = ReceiptState::Resolved;
        complete_deadline(&mut state.resolution_watchdog);
        complete_deadline(&mut state.acknowledgement_publication_watchdog);
        complete_deadline(&mut state.start_failure_publication_watchdog);
        self.changed.notify_all();
        self.complete_process_start_and_take_finalization(state)
    }

    fn expire_initial_receipt_deadline(&self) -> Option<ReceiptExpiration> {
        let mut state = self.state.lock().expect("process start mutex poisoned");
        let (error, abnormal) = match (state.receipt, state.publication) {
            (ReceiptState::AwaitingAcknowledgement, _) => (ErrorCode::PeerClosed, false),
            (ReceiptState::AcknowledgementAdmitted, StartResultPublication::Publishing) => {
                (ErrorCode::Internal, true)
            }
            _ => return None,
        };
        expire_start(&mut state, error, abnormal, true, &self.changed)
    }

    fn wait_for_initial_receipt_deadline(&self, deadline: Instant) -> Option<ReceiptExpiration> {
        let mut state = self.state.lock().expect("process start mutex poisoned");
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
                .expect("process start mutex poisoned");
            state = next;
        }
        let (error, abnormal) = match (state.receipt, state.publication) {
            (ReceiptState::AwaitingAcknowledgement, _) => (ErrorCode::PeerClosed, false),
            (ReceiptState::AcknowledgementAdmitted, StartResultPublication::Publishing) => {
                (ErrorCode::Internal, true)
            }
            _ => return None,
        };
        expire_start(&mut state, error, abnormal, true, &self.changed)
    }

    fn wait_for_internal_resolution_timeout(&self) -> Option<ReceiptExpiration> {
        let mut state = self.state.lock().expect("process start mutex poisoned");
        loop {
            match state.resolution_watchdog {
                DeadlineState::Unarmed => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("process start mutex poisoned");
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
                        .expect("process start mutex poisoned");
                    state = next;
                }
                DeadlineState::Disarmed | DeadlineState::Fired => return None,
            }
        }
    }

    fn wait_for_acknowledgement_publication_timeout(&self) -> Option<ReceiptExpiration> {
        let mut state = self.state.lock().expect("process start mutex poisoned");
        loop {
            match state.acknowledgement_publication_watchdog {
                DeadlineState::Unarmed => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("process start mutex poisoned");
                }
                DeadlineState::Armed(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        state.acknowledgement_publication_watchdog = DeadlineState::Fired;
                        return expire_start(
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
                        .expect("process start mutex poisoned");
                    state = next;
                }
                DeadlineState::Disarmed | DeadlineState::Fired => return None,
            }
        }
    }

    fn wait_for_start_failure_publication_timeout(&self) -> Option<ReceiptExpiration> {
        let mut state = self.state.lock().expect("process start mutex poisoned");
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
                        .expect("process start mutex poisoned");
                    state = next;
                }
                DeadlineState::Unarmed | DeadlineState::Disarmed | DeadlineState::Fired => {
                    return None;
                }
            }
        }
    }

    fn fail_start_failure_publication_watchdog(&self) -> Option<ReceiptExpiration> {
        let mut state = self.state.lock().expect("process start mutex poisoned");
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
        let mut state = self.state.lock().expect("process start mutex poisoned");
        complete_deadline(&mut state.resolution_watchdog);
        complete_deadline(&mut state.acknowledgement_publication_watchdog);
        complete_deadline(&mut state.start_failure_publication_watchdog);
        expire_start(&mut state, ErrorCode::Internal, true, true, &self.changed)
    }

    fn complete_timeout_callback(&self) -> Option<bool> {
        let mut state = self.state.lock().expect("process start mutex poisoned");
        state.active_control_callbacks = state
            .active_control_callbacks
            .checked_sub(1)
            .expect("process-start timeout callback count must remain balanced");
        self.changed.notify_all();
        take_finalization(&mut state)
    }

    fn wait_for_commit_resolution(&self, deadline: Instant) -> bool {
        let mut state = self.state.lock().expect("process start mutex poisoned");
        while matches!(state.phase, ProcessStartPhase::Committing) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let (next, wait_result) = self
                .changed
                .wait_timeout(state, remaining)
                .expect("process start mutex poisoned");
            state = next;
            if wait_result.timed_out() && matches!(state.phase, ProcessStartPhase::Committing) {
                return false;
            }
        }
        true
    }

    fn complete_process_start_and_take_finalization(
        &self,
        mut state: MutexGuard<'_, ProcessStartInner>,
    ) -> Option<bool> {
        if !matches!(state.phase, ProcessStartPhase::Committed) {
            return take_finalization(&mut state);
        }
        state.phase = ProcessStartPhase::CompletingStart;
        state.active_control_callbacks = state
            .active_control_callbacks
            .checked_add(1)
            .expect("process-start control callback count must remain bounded");
        drop(state);

        let completion_failed = self.process.complete_start().is_err();
        let mut state = self.state.lock().expect("process start mutex poisoned");
        state.active_control_callbacks = state
            .active_control_callbacks
            .checked_sub(1)
            .expect("process-start control callback count must remain balanced");
        state.abnormal |= completion_failed;
        state.phase = ProcessStartPhase::StartComplete;
        self.changed.notify_all();
        take_finalization(&mut state)
    }

    fn runner_finished(&self, abnormal: bool) -> Option<bool> {
        let mut state = self.state.lock().expect("process start mutex poisoned");
        state.abnormal |= abnormal;
        state.runner_finished = true;
        take_finalization(&mut state)
    }
}

fn expire_start(
    state: &mut ProcessStartInner,
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
        ProcessStartPhase::Starting | ProcessStartPhase::Ready { .. } => {
            state.phase = ProcessStartPhase::Aborted(error);
            if state.shutdown_request == ShutdownRequest::None {
                state.shutdown_request = ShutdownRequest::Expected;
            }
            (
                state.association_failure.as_ref().map(Arc::clone),
                state.shutdown.clone(),
            )
        }
        ProcessStartPhase::Aborted(_) => {
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
        ProcessStartPhase::Committing
        | ProcessStartPhase::Committed
        | ProcessStartPhase::CompletingStart
        | ProcessStartPhase::StartComplete => (None, None),
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
    state: &mut ProcessStartInner,
    changed: &Condvar,
) -> Option<ReceiptExpiration> {
    if !matches!(state.phase, ProcessStartPhase::Aborted(_))
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
    state: &mut ProcessStartInner,
    changed: &Condvar,
) -> Option<ReceiptExpiration> {
    let committing_drain = state.receipt == ReceiptState::Draining
        && matches!(state.phase, ProcessStartPhase::Committing);
    if state.receipt != ReceiptState::AcknowledgementAdmitted && !committing_drain {
        return None;
    }
    state.active_control_callbacks += 1;
    state.abnormal = true;
    let (association_failure, shutdown, fail_parent, commit_supervision_deadline) =
        match state.phase {
            ProcessStartPhase::Ready { .. } | ProcessStartPhase::Aborted(_) => {
                state.phase = ProcessStartPhase::Aborted(ErrorCode::Internal);
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
            ProcessStartPhase::Committing => {
                state.receipt = ReceiptState::TimeoutPending;
                complete_deadline(&mut state.acknowledgement_publication_watchdog);
                (
                    None,
                    None,
                    true,
                    Some(Instant::now() + PROCESS_START_SUPERVISOR_SHUTDOWN_TIMEOUT),
                )
            }
            ProcessStartPhase::Starting
            | ProcessStartPhase::Committed
            | ProcessStartPhase::CompletingStart
            | ProcessStartPhase::StartComplete => {
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

fn complete_acknowledgement_resolution(state: &mut ProcessStartInner) {
    complete_deadline(&mut state.resolution_watchdog);
    if state.receipt == ReceiptState::AcknowledgementAdmitted {
        arm_deadline(
            &mut state.acknowledgement_publication_watchdog,
            PROCESS_START_ACKNOWLEDGEMENT_PUBLICATION_TIMEOUT,
        );
    }
}

fn take_finalization(state: &mut ProcessStartInner) -> Option<bool> {
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

#[cfg(test)]
mod tests {
    use super::{
        DeadlineState, PROCESS_START_RECEIPT_TIMEOUT, PROCESS_START_SUPERVISOR_SHUTDOWN_TIMEOUT,
        ProcessStart, ProcessStartAcknowledgement, ProcessStartInner, ProcessStartPhase,
        ReceiptResolution, ReceiptState, RunnerConfig, RunnerProcessManager,
        RunnerProcessManagerInner, ShutdownRequest, StartResultPublication,
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

    fn start_with_broker_in_phase(
        publication: StartResultPublication,
        phase: ProcessStartPhase,
    ) -> (BrokerCore, Arc<ProcessStart>) {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let parent = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let (process, _) = parent.create_child(&[]).unwrap();
        parent.cleanup(true);
        if let ProcessStartPhase::Ready { initial_thread_id } = phase {
            process.mark_start_ready(initial_thread_id).unwrap();
        }
        (
            broker,
            Arc::new(ProcessStart {
                parent_id: ProcessId(1),
                process,
                state: Mutex::new(ProcessStartInner {
                    phase,
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
                    runner_finished: false,
                    finalization_taken: false,
                }),
                changed: Condvar::new(),
            }),
        )
    }

    fn start_with_broker(publication: StartResultPublication) -> (BrokerCore, Arc<ProcessStart>) {
        start_with_broker_in_phase(
            publication,
            ProcessStartPhase::Ready {
                initial_thread_id: None,
            },
        )
    }

    fn start(publication: StartResultPublication) -> Arc<ProcessStart> {
        start_with_broker(publication).1
    }

    fn starting_process(publication: StartResultPublication) -> Arc<ProcessStart> {
        start_with_broker_in_phase(publication, ProcessStartPhase::Starting).1
    }

    #[test]
    fn publication_captures_an_absolute_receipt_deadline() {
        let start = start(StartResultPublication::NotStarted);
        let before = Instant::now();

        let deadline = start.begin_start_result_publication().unwrap();
        let after = Instant::now();

        assert!(deadline >= before + PROCESS_START_RECEIPT_TIMEOUT);
        assert!(deadline <= after + PROCESS_START_RECEIPT_TIMEOUT);
    }

    #[test]
    fn acknowledgement_ingress_claims_receipt_before_worker_resolution() {
        let (broker, start) = start_with_broker(StartResultPublication::Delivered);
        let token = ProcessStartToken(7);
        let parent_id = start.parent_id;
        let process_manager = Arc::new(RunnerProcessManager {
            broker,
            process_start_config: RunnerConfig::new(PathBuf::new(), Vec::new()),
            state: Mutex::new(RunnerProcessManagerInner {
                starts: vec![(token, Arc::clone(&start))],
                associations: Vec::new(),
                active_instances: 1,
                active_watchdogs: 0,
            }),
            drained: Condvar::new(),
        });

        process_manager
            .admit_acknowledgement(parent_id, token)
            .unwrap();

        assert_eq!(process_manager.state.lock().unwrap().active_watchdogs, 2);
        assert!(matches!(
            start.state.lock().unwrap().receipt,
            ReceiptState::AcknowledgementAdmitted
        ));
        assert!(start.expire_initial_receipt_deadline().is_none());
        assert!(matches!(
            process_manager.resolve_acknowledgement(parent_id, token),
            Ok(ProcessStartAcknowledgement::Acknowledged)
        ));
        process_manager.response_sent(
            parent_id,
            &BrokerOperation::AcknowledgeProcessStart(token),
            &BrokerResult::ProcessStartAcknowledged,
        );
        start.process.cleanup(true);
        process_manager.finish_instance();
        process_manager.wait_for_drain();
        assert_eq!(process_manager.state.lock().unwrap().active_watchdogs, 0);
    }

    #[test]
    fn reported_bootstrap_rejection_selects_normal_rollback() {
        let start = starting_process(StartResultPublication::NotStarted);

        start
            .report_start_failure(ErrorCode::UnsupportedOperation)
            .unwrap();

        assert!(matches!(
            start.wait_until_ready(),
            Err(ErrorCode::UnsupportedOperation)
        ));
        assert!(
            start
                .shutdown_request()
                .expected_start_failure_was_reported()
        );
        assert!(!start.state.lock().unwrap().abnormal);
        start.start_failure_response_sent(ErrorCode::UnsupportedOperation);
        assert!(start.shutdown_request().was_expected());
        assert_eq!(start.runner_finished(false), None);
        assert!(matches!(
            start.resolve_receipt(),
            ReceiptResolution::Resolved(Some(false))
        ));
        start.process.cleanup(true);
    }

    #[test]
    fn acknowledgement_waits_for_publication_bookkeeping() {
        let start = start(StartResultPublication::Publishing);
        start.admit_acknowledgement().unwrap();
        let waiting = Arc::clone(&start);
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker =
            std::thread::spawn(move || sender.send(waiting.resolve_acknowledgement()).unwrap());

        assert!(receiver.recv_timeout(Duration::from_millis(20)).is_err());
        assert!(matches!(
            start.state.lock().unwrap().resolution_watchdog,
            DeadlineState::Unarmed
        ));
        start.mark_start_result_delivered();
        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            Ok(ProcessStartAcknowledgement::Acknowledged)
        ));
        worker.join().unwrap();
        assert!(start.process.is_running());
        assert!(matches!(
            start.state.lock().unwrap().resolution_watchdog,
            DeadlineState::Disarmed
        ));
        assert!(matches!(
            start
                .state
                .lock()
                .unwrap()
                .acknowledgement_publication_watchdog,
            DeadlineState::Armed(_)
        ));

        start.resolve_receipt();
        start.process.cleanup(true);
    }

    #[test]
    fn acknowledgement_interrupted_by_drain_returns_peer_closed() {
        let start = start(StartResultPublication::Publishing);
        start.admit_acknowledgement().unwrap();
        let waiting = Arc::clone(&start);
        let worker = std::thread::spawn(move || waiting.resolve_acknowledgement());

        std::thread::sleep(Duration::from_millis(20));
        start.begin_receipt_drain();

        assert!(matches!(worker.join().unwrap(), Err(ErrorCode::PeerClosed)));
        start.finish_receipt_drain();
        start.process.cleanup(true);
    }

    #[test]
    fn process_ready_interrupted_by_abort_returns_the_abort_cause() {
        let ready = starting_process(StartResultPublication::NotStarted);
        ready.abort(ErrorCode::PeerClosed, false, true);
        assert!(matches!(
            ready.ready_and_wait(None),
            Err(ErrorCode::PeerClosed)
        ));
        ready.resolve_receipt();
        ready.process.cleanup(true);
    }

    #[test]
    fn failure_report_interrupted_by_abort_returns_the_abort_cause() {
        let failed = starting_process(StartResultPublication::NotStarted);
        failed.abort(ErrorCode::PeerClosed, false, true);
        assert!(matches!(
            failed.report_start_failure(ErrorCode::UnsupportedOperation),
            Err(ErrorCode::PeerClosed)
        ));
        failed.resolve_receipt();
        failed.process.cleanup(true);
    }

    #[test]
    fn delivery_arms_the_resolution_watchdog_before_the_worker_resumes() {
        let start = start(StartResultPublication::Publishing);
        start.admit_acknowledgement().unwrap();

        assert!(matches!(
            start.state.lock().unwrap().resolution_watchdog,
            DeadlineState::Unarmed
        ));
        start.mark_start_result_delivered();
        assert!(matches!(
            start.state.lock().unwrap().resolution_watchdog,
            DeadlineState::Armed(_)
        ));

        start.begin_receipt_drain();
        start.finish_receipt_drain();
        start.process.cleanup(true);
    }

    #[test]
    fn acknowledgement_publication_timeout_retains_receipt_for_drain() {
        let start = start(StartResultPublication::Delivered);
        start.admit_acknowledgement().unwrap();
        assert!(matches!(
            start.resolve_acknowledgement(),
            Ok(ProcessStartAcknowledgement::Acknowledged)
        ));
        start
            .state
            .lock()
            .unwrap()
            .acknowledgement_publication_watchdog = DeadlineState::Armed(Instant::now());

        let expiration = start
            .wait_for_acknowledgement_publication_timeout()
            .unwrap();
        assert!(expiration.fail_parent);
        let state = start.state.lock().unwrap();
        assert!(matches!(state.receipt, ReceiptState::TimeoutPending));
        assert!(matches!(
            state.acknowledgement_publication_watchdog,
            DeadlineState::Fired
        ));
        assert!(!state.abnormal);
        drop(state);

        assert_eq!(start.complete_timeout_callback(), None);
        start.begin_receipt_drain();
        start.finish_receipt_drain();
        start.process.cleanup(true);
    }

    #[test]
    fn start_failure_publication_timeout_terminates_the_runner() {
        let start = starting_process(StartResultPublication::NotStarted);
        start
            .report_start_failure(ErrorCode::UnsupportedOperation)
            .unwrap();
        start
            .state
            .lock()
            .unwrap()
            .start_failure_publication_watchdog = DeadlineState::Armed(Instant::now());

        let expiration = start.wait_for_start_failure_publication_timeout().unwrap();

        assert!(!expiration.fail_parent);
        assert!(start.shutdown_request().was_expected());
        assert!(matches!(
            start
                .state
                .lock()
                .unwrap()
                .start_failure_publication_watchdog,
            DeadlineState::Fired
        ));
        assert_eq!(start.complete_timeout_callback(), None);
        assert_eq!(start.runner_finished(false), None);
        assert!(matches!(
            start.resolve_receipt(),
            ReceiptResolution::Resolved(Some(false))
        ));
        start.process.cleanup(true);
    }

    #[test]
    fn precommit_resolution_timeout_returns_typed_internal_failure() {
        let start = start(StartResultPublication::Delivered);
        start.admit_acknowledgement().unwrap();
        start.state.lock().unwrap().resolution_watchdog = DeadlineState::Armed(Instant::now());

        let expiration = start.wait_for_internal_resolution_timeout().unwrap();
        assert!(!expiration.fail_parent);
        let state = start.state.lock().unwrap();
        assert!(matches!(
            state.phase,
            ProcessStartPhase::Aborted(ErrorCode::Internal)
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
        assert_eq!(start.complete_timeout_callback(), None);

        assert!(matches!(
            start.resolve_acknowledgement(),
            Ok(ProcessStartAcknowledgement::Failed(ErrorCode::Internal))
        ));
        assert!(matches!(
            start
                .state
                .lock()
                .unwrap()
                .acknowledgement_publication_watchdog,
            DeadlineState::Armed(_)
        ));
        start.resolve_receipt();
        start.process.cleanup(false);
    }

    #[test]
    fn process_start_abort_fails_an_installed_active_association() {
        let start = start(StartResultPublication::NotStarted);
        let failed = Arc::new(AtomicBool::new(false));
        let recorded = Arc::clone(&failed);
        start.install_association_failure(Arc::new(move || {
            recorded.store(true, Ordering::Release);
        }));

        start.abort(ErrorCode::PeerClosed, false, true);

        assert!(failed.load(Ordering::Acquire));
        start.process.cleanup(true);
    }

    #[test]
    fn supervisor_wait_observes_commit_resolution() {
        let start = start(StartResultPublication::Delivered);
        start.state.lock().unwrap().phase = ProcessStartPhase::Committing;
        let waiting = Arc::clone(&start);
        let worker = std::thread::spawn(move || {
            waiting.wait_for_commit_resolution(Instant::now() + Duration::from_secs(1))
        });

        std::thread::sleep(Duration::from_millis(20));
        start.state.lock().unwrap().phase = ProcessStartPhase::Committed;
        start.changed.notify_all();

        assert!(worker.join().unwrap());
        start.process.cleanup(true);
    }

    #[test]
    fn receipt_drain_keeps_commit_supervision_armed() {
        let start = start(StartResultPublication::Delivered);
        start.admit_acknowledgement().unwrap();
        {
            let mut state = start.state.lock().unwrap();
            state.phase = ProcessStartPhase::Committing;
            state.resolution_watchdog = DeadlineState::Armed(Instant::now());
        }
        start.begin_receipt_drain();
        assert!(matches!(
            start.state.lock().unwrap().resolution_watchdog,
            DeadlineState::Armed(_)
        ));

        let before = Instant::now();
        let expiration = start.wait_for_internal_resolution_timeout().unwrap();
        let after = Instant::now();
        let deadline = expiration.commit_supervision_deadline.unwrap();
        assert!(deadline >= before + PROCESS_START_SUPERVISOR_SHUTDOWN_TIMEOUT);
        assert!(deadline <= after + PROCESS_START_SUPERVISOR_SHUTDOWN_TIMEOUT);
        {
            let mut state = start.state.lock().unwrap();
            state.phase = ProcessStartPhase::Aborted(ErrorCode::Internal);
        }
        start.changed.notify_all();
        assert_eq!(start.complete_timeout_callback(), None);
        start.finish_receipt_drain();
        start.process.cleanup(false);
    }

    #[test]
    fn published_abort_returns_typed_start_failure() {
        let start = start(StartResultPublication::Publishing);
        start.abort(ErrorCode::PeerClosed, false, false);
        start.mark_start_result_delivered();
        start.admit_acknowledgement().unwrap();

        assert!(matches!(
            start.resolve_acknowledgement(),
            Ok(ProcessStartAcknowledgement::Failed(ErrorCode::PeerClosed))
        ));
        start.resolve_receipt();
        start.process.cleanup(true);
    }

    #[test]
    fn acknowledgement_before_publication_is_protocol_violation() {
        let start = start(StartResultPublication::NotStarted);

        assert!(matches!(
            start.admit_acknowledgement(),
            Err(ErrorCode::ProtocolState)
        ));
        start.resolve_receipt();
        start.process.cleanup(true);
    }

    #[test]
    fn published_receipt_defers_process_finalization() {
        let start = start(StartResultPublication::Delivered);
        start.abort(ErrorCode::PeerClosed, false, false);

        assert_eq!(start.runner_finished(false), None);
        assert!(matches!(
            start.resolve_receipt(),
            ReceiptResolution::Resolved(Some(false))
        ));
        start.process.cleanup(true);
    }

    #[test]
    fn receipt_resolution_completes_process_start() {
        let start = starting_process(StartResultPublication::Delivered);
        let thread_id = start.process.create_thread().unwrap();
        start.process.mark_start_ready(Some(thread_id)).unwrap();
        start.process.commit_start().unwrap();
        start.state.lock().unwrap().phase = ProcessStartPhase::Committed;

        start.resolve_receipt();
        start.resolve_receipt();

        let state = start.state.lock().unwrap();
        assert!(matches!(state.phase, ProcessStartPhase::StartComplete));
        assert!(!state.abnormal);
        drop(state);
        assert_eq!(start.process.exit_thread(thread_id), Ok(()));
        start.process.cleanup(true);
    }

    #[test]
    fn process_ready_waits_until_process_start_is_complete() {
        let start = starting_process(StartResultPublication::Delivered);
        let thread_id = start.process.create_thread().unwrap();
        let waiting = Arc::clone(&start);
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            sender
                .send(waiting.ready_and_wait(Some(thread_id)))
                .unwrap();
        });

        let mut state = start.state.lock().unwrap();
        while !matches!(state.phase, ProcessStartPhase::Ready { .. }) {
            state = start.changed.wait(state).unwrap();
        }
        start.process.commit_start().unwrap();
        state.phase = ProcessStartPhase::Committed;
        start.changed.notify_all();
        drop(state);
        assert!(receiver.recv_timeout(Duration::from_millis(20)).is_err());

        start.resolve_receipt();
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            Ok(())
        );
        worker.join().unwrap();
        assert_eq!(start.process.exit_thread(thread_id), Ok(()));
        start.process.cleanup(true);
    }

    #[test]
    fn acknowledgement_admission_preserves_the_publication_deadline() {
        let start = start(StartResultPublication::Publishing);
        start.admit_acknowledgement().unwrap();

        let _expiration = start.expire_initial_receipt_deadline().unwrap();
        let state = start.state.lock().unwrap();
        assert!(matches!(
            state.phase,
            ProcessStartPhase::Aborted(ErrorCode::Internal)
        ));
        assert!(state.abnormal);
        drop(state);
        assert_eq!(start.complete_timeout_callback(), None);
        start.process.cleanup(true);
    }

    #[test]
    fn receipt_timeout_defers_finalization_until_association_drain() {
        let start = start(StartResultPublication::Delivered);

        assert_eq!(start.runner_finished(false), None);
        let _expiration = start.expire_initial_receipt_deadline().unwrap();
        assert!(matches!(
            start.resolve_receipt(),
            ReceiptResolution::DeferredToDrain
        ));
        assert_eq!(start.complete_timeout_callback(), None);
        start.begin_receipt_drain();
        assert_eq!(start.finish_receipt_drain(), Some(false));
        start.process.cleanup(true);
    }

    #[test]
    fn unpublished_start_waits_for_receipt_drain_before_finalization() {
        let start = start(StartResultPublication::NotStarted);

        start.begin_receipt_drain();
        assert_eq!(start.runner_finished(false), None);
        assert_eq!(start.finish_receipt_drain(), Some(false));
        start.process.cleanup(true);
    }

    #[test]
    fn deferred_finalization_uses_the_latest_abnormal_disposition() {
        let start = start(StartResultPublication::Publishing);
        start.admit_acknowledgement().unwrap();

        assert_eq!(start.runner_finished(false), None);
        let _expiration = start.expire_initial_receipt_deadline().unwrap();
        assert_eq!(start.complete_timeout_callback(), None);
        start.begin_receipt_drain();
        assert_eq!(start.finish_receipt_drain(), Some(true));
        start.process.cleanup(false);
    }

    #[test]
    fn acknowledgement_send_does_not_steal_a_timed_out_receipt_from_drain() {
        let (broker, start) = start_with_broker(StartResultPublication::Delivered);
        let token = ProcessStartToken(7);
        let parent_id = start.parent_id;
        let process_manager = RunnerProcessManager {
            broker,
            process_start_config: RunnerConfig::new(PathBuf::new(), Vec::new()),
            state: Mutex::new(RunnerProcessManagerInner {
                starts: vec![(token, Arc::clone(&start))],
                associations: Vec::new(),
                active_instances: 1,
                active_watchdogs: 0,
            }),
            drained: Condvar::new(),
        };

        assert_eq!(start.runner_finished(false), None);
        let _expiration = start.expire_initial_receipt_deadline().unwrap();
        process_manager.response_sent(
            parent_id,
            &BrokerOperation::AcknowledgeProcessStart(token),
            &BrokerResult::ProcessStartAcknowledged,
        );

        assert!(process_manager.find_start(token).is_some());
        assert_eq!(start.complete_timeout_callback(), None);
        let draining = process_manager.association_ending(parent_id);
        assert_eq!(draining.starts.len(), 1);
        process_manager.association_ended(parent_id, draining);
        assert!(process_manager.find_start(token).is_none());
    }
}
