// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared coordination for out-of-process runner instances.

use std::io::{Error as IoError, Result as IoResult};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerError, BrokerProcess};
use litebox_broker_host::{RequestFailure, copy_shared_buffer};
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult};
use litebox_broker_protocol::process::{
    InheritedProcessObjects, MAX_PROCESS_BOOTSTRAP_SIZE, ProcessBootstrapFormat,
    ProcessBootstrapVersion, ProcessStartupData, StartedProcess,
};
use litebox_broker_protocol::{ProcessId, ThreadId};
use litebox_broker_transport::shared_memory::{SharedBufferPool, SharedMemory};

use super::{
    RunnerCompletion, RunnerConfig, RunnerInstance, RunnerShutdown, TerminationProvenance,
    runner_exit_code_is_crash, runner_exit_code_is_expected_shutdown, runner_signal_is_abnormal,
};

const PROCESS_START_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PENDING_PROCESS_STARTS: usize = crate::WORKER_COUNT;
const _: () = assert!(MAX_PENDING_PROCESS_STARTS > 0);

/// Shared ownership and coordination for runner processes and associations.
pub(crate) struct RunnerProcessManager {
    broker: BrokerCore,
    started_runner_config: RunnerConfig,
    state: Mutex<RunnerProcessManagerState>,
    drained: Condvar,
}

/// Startup context for a runner whose broker process was created by its parent.
pub(crate) struct RunnerStartup {
    process: Arc<BrokerProcess>,
    transaction: Arc<ProcessStartTransaction>,
    data: ProcessStartupData,
}

impl RunnerStartup {
    pub(super) fn transaction(&self) -> Arc<ProcessStartTransaction> {
        Arc::clone(&self.transaction)
    }

    pub(crate) fn into_process_and_data(self) -> (Arc<BrokerProcess>, ProcessStartupData) {
        (self.process, self.data)
    }
}

struct RunnerProcessManagerState {
    transactions: Vec<Arc<ProcessStartTransaction>>,
    associations: Vec<(ProcessId, AssociationFailure)>,
    active_instances: usize,
}

pub(crate) type AssociationFailure = Arc<dyn Fn() + Send + Sync>;

/// State for one blocking `StartProcess` request.
pub(super) struct ProcessStartTransaction {
    parent_id: ProcessId,
    process: Arc<BrokerProcess>,
    state: Mutex<ProcessStartTransactionState>,
    changed: Condvar,
}

#[derive(Clone, Copy)]
enum ProcessStartPhase {
    Starting,
    Ready { initial_thread_id: Option<ThreadId> },
    Completing { cancellation: Option<ErrorCode> },
    Running,
    Failed(ErrorCode),
}

struct ProcessStartTransactionState {
    phase: ProcessStartPhase,
    shutdown: Option<Arc<RunnerShutdown>>,
    association_failure: Option<AssociationFailure>,
    shutdown_request: ShutdownRequest,
    abnormal: bool,
    start_completed: bool,
    finalization: FinalizationState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FinalizationState {
    Active,
    ProtocolFinished,
    RunnerFinished,
    Finalized,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ShutdownRequest {
    None,
    Expected,
    ExpectedStartFailure,
    Unexpected,
}

impl ShutdownRequest {
    pub(super) const fn was_expected(self) -> bool {
        matches!(self, Self::Expected | Self::ExpectedStartFailure)
    }

    pub(super) const fn expected_start_failure_was_reported(self) -> bool {
        matches!(self, Self::ExpectedStartFailure)
    }
}

impl RunnerProcessManager {
    pub(super) fn new(started_runner_config: RunnerConfig, broker: BrokerCore) -> Arc<Self> {
        Arc::new(Self {
            broker,
            started_runner_config,
            state: Mutex::new(RunnerProcessManagerState {
                transactions: Vec::new(),
                associations: Vec::new(),
                active_instances: 0,
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
        let transaction = Arc::new(ProcessStartTransaction {
            parent_id: parent.id(),
            process: Arc::clone(&process),
            state: Mutex::new(ProcessStartTransactionState {
                phase: ProcessStartPhase::Starting,
                shutdown: None,
                association_failure: None,
                shutdown_request: ShutdownRequest::None,
                abnormal: false,
                start_completed: false,
                finalization: FinalizationState::Active,
            }),
            changed: Condvar::new(),
        });

        let registration = {
            let mut state = self
                .state
                .lock()
                .expect("runner process manager state mutex poisoned");
            if state.transactions.try_reserve(1).is_err() {
                Err(ErrorCode::OutOfMemory)
            } else if parent.is_cancellation_requested() {
                Err(ErrorCode::PeerClosed)
            } else if state.transactions.len() >= MAX_PENDING_PROCESS_STARTS {
                Err(ErrorCode::ResourceExhausted)
            } else if let Some(active_instances) = state.active_instances.checked_add(1) {
                state.active_instances = active_instances;
                state.transactions.push(Arc::clone(&transaction));
                Ok(())
            } else {
                Err(ErrorCode::ResourceExhausted)
            }
        };
        if let Err(error) = registration {
            process.cleanup(true);
            return Err(error);
        }

        let process_manager = Arc::clone(self);
        let config = self.started_runner_config.clone();
        let thread_transaction = Arc::clone(&transaction);
        let thread = std::thread::Builder::new()
            .name(format!("litebox-runner-{}", process_id.0))
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    RunnerInstance::start(config).map(|instance| {
                        instance.run_started_process_to_completion(
                            RunnerStartup {
                                process,
                                transaction: Arc::clone(&thread_transaction),
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
                        process_manager.runner_finished(&thread_transaction, result, false);
                    }
                    Ok(Err(error)) => process_manager.runner_finished(
                        &thread_transaction,
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
                        &thread_transaction,
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
            self.remove_transaction(process_id);
            transaction.process.cleanup(true);
            self.finish_instance();
            return Err(ErrorCode::OutOfMemory);
        }
        drop(thread);

        let deadline = Instant::now() + PROCESS_START_TIMEOUT;
        let result = transaction
            .wait_until_ready(deadline)
            .and_then(|initial_thread_id| {
                if parent.is_cancellation_requested() {
                    transaction.abort(ErrorCode::PeerClosed, false, true);
                    return Err(ErrorCode::PeerClosed);
                }
                transaction.complete_start()?;
                Ok(StartedProcess {
                    process_id,
                    initial_thread_id,
                })
            });
        self.remove_transaction(process_id);
        if let Some(abnormal) = transaction.protocol_finished() {
            self.finish_transaction(&transaction, abnormal);
        }
        result
    }

    fn process_ready(
        &self,
        process_id: ProcessId,
        initial_thread_id: Option<ThreadId>,
    ) -> Result<(), ErrorCode> {
        self.find_transaction(process_id)
            .ok_or(ErrorCode::PeerClosed)?
            .ready_and_wait(initial_thread_id)
    }

    fn report_process_start_failure(
        &self,
        process_id: ProcessId,
        error: ErrorCode,
    ) -> Result<(), ErrorCode> {
        self.find_transaction(process_id)
            .ok_or(ErrorCode::PeerClosed)?
            .report_start_failure(error)
    }

    pub(crate) fn association_ending(&self, process_id: ProcessId) {
        let (children, transaction) = {
            let state = self
                .state
                .lock()
                .expect("runner process manager state mutex poisoned");
            let children = state
                .transactions
                .iter()
                .filter(|transaction| transaction.parent_id == process_id)
                .cloned()
                .collect::<Vec<_>>();
            let transaction = state
                .transactions
                .iter()
                .find(|transaction| transaction.process.id() == process_id)
                .cloned();
            (children, transaction)
        };
        for child in children {
            child.abort(ErrorCode::PeerClosed, false, true);
        }
        if let Some(transaction) = transaction {
            transaction.association_closed();
        }
    }

    pub(crate) fn association_ended(&self, process_id: ProcessId) {
        self.unregister_association(process_id);
    }

    pub(crate) fn register_association(
        &self,
        process_id: ProcessId,
        failure: AssociationFailure,
    ) -> IoResult<()> {
        let transaction = {
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
            state.associations.push((process_id, failure.clone()));
            state
                .transactions
                .iter()
                .find(|transaction| transaction.process.id() == process_id)
                .cloned()
        };
        if let Some(transaction) = transaction {
            transaction.install_association_failure(failure);
        }
        Ok(())
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

    fn find_transaction(&self, process_id: ProcessId) -> Option<Arc<ProcessStartTransaction>> {
        self.state
            .lock()
            .expect("runner process manager state mutex poisoned")
            .transactions
            .iter()
            .find(|transaction| transaction.process.id() == process_id)
            .cloned()
    }

    fn remove_transaction(&self, process_id: ProcessId) {
        let mut state = self
            .state
            .lock()
            .expect("runner process manager state mutex poisoned");
        if let Some(index) = state
            .transactions
            .iter()
            .position(|transaction| transaction.process.id() == process_id)
        {
            state.transactions.swap_remove(index);
        }
    }

    fn runner_finished(
        &self,
        transaction: &ProcessStartTransaction,
        result: RunnerCompletion,
        thread_panicked: bool,
    ) {
        let unexpected_runner_failure = result.runner_success == Some(false)
            && result.runner_signal.is_none()
            && !transaction.start_completed()
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
            transaction.abort(ErrorCode::PeerClosed, abnormal, false);
        } else if !transaction.start_completed() {
            transaction.abort(ErrorCode::PeerClosed, false, false);
        }
        if let Some(abnormal) = transaction.runner_finished(abnormal) {
            self.finish_transaction(transaction, abnormal);
        }
    }

    fn finish_transaction(&self, transaction: &ProcessStartTransaction, abnormal: bool) {
        transaction.process.cleanup(!abnormal);
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
        if state.active_instances == 0 {
            self.drained.notify_all();
        }
    }

    pub(super) fn wait_for_drain(&self) {
        let mut state = self
            .state
            .lock()
            .expect("runner process manager state mutex poisoned");
        while state.active_instances != 0 {
            state = self
                .drained
                .wait(state)
                .expect("runner process manager state mutex poisoned");
        }
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

impl ProcessStartTransaction {
    fn wait_until_ready(&self, deadline: Instant) -> Result<Option<ThreadId>, ErrorCode> {
        let mut state = self
            .state
            .lock()
            .expect("process start transaction mutex poisoned");
        loop {
            match state.phase {
                ProcessStartPhase::Starting => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        drop(state);
                        self.abort(ErrorCode::Internal, true, true);
                        return Err(ErrorCode::Internal);
                    }
                    let (next, wait_result) = self
                        .changed
                        .wait_timeout(state, remaining)
                        .expect("process start transaction mutex poisoned");
                    state = next;
                    if wait_result.timed_out() && matches!(state.phase, ProcessStartPhase::Starting)
                    {
                        drop(state);
                        self.abort(ErrorCode::Internal, true, true);
                        return Err(ErrorCode::Internal);
                    }
                }
                ProcessStartPhase::Ready { initial_thread_id } => return Ok(initial_thread_id),
                ProcessStartPhase::Completing { .. } | ProcessStartPhase::Running => {
                    return Err(ErrorCode::ProtocolState);
                }
                ProcessStartPhase::Failed(error) => return Err(error),
            }
        }
    }

    fn ready_and_wait(&self, initial_thread_id: Option<ThreadId>) -> Result<(), ErrorCode> {
        let mut state = self
            .state
            .lock()
            .expect("process start transaction mutex poisoned");
        if !matches!(state.phase, ProcessStartPhase::Starting) {
            return Err(match state.phase {
                ProcessStartPhase::Failed(error) => error,
                _ => ErrorCode::ProtocolState,
            });
        }
        self.process
            .mark_start_ready(initial_thread_id)
            .map_err(|error| match error {
                BrokerError::UnknownObject => ErrorCode::ProtocolState,
                error => ErrorCode::from(error),
            })?;
        state.phase = ProcessStartPhase::Ready { initial_thread_id };
        self.changed.notify_all();
        loop {
            match state.phase {
                ProcessStartPhase::Ready { .. } | ProcessStartPhase::Completing { .. } => {
                    state = self
                        .changed
                        .wait(state)
                        .expect("process start transaction mutex poisoned");
                }
                ProcessStartPhase::Running => return Ok(()),
                ProcessStartPhase::Failed(error) => return Err(error),
                ProcessStartPhase::Starting => unreachable!("ready state cannot regress"),
            }
        }
    }

    fn report_start_failure(&self, error: ErrorCode) -> Result<(), ErrorCode> {
        if !process_start_failure_is_expected(error) {
            return Err(ErrorCode::ProtocolState);
        }
        let mut state = self
            .state
            .lock()
            .expect("process start transaction mutex poisoned");
        match state.phase {
            ProcessStartPhase::Starting => {}
            ProcessStartPhase::Failed(error) => return Err(error),
            _ => return Err(ErrorCode::ProtocolState),
        }
        state.phase = ProcessStartPhase::Failed(error);
        state.shutdown_request = ShutdownRequest::ExpectedStartFailure;
        self.changed.notify_all();
        Ok(())
    }

    fn complete_start(&self) -> Result<(), ErrorCode> {
        {
            let mut state = self
                .state
                .lock()
                .expect("process start transaction mutex poisoned");
            match state.phase {
                ProcessStartPhase::Ready { .. } => {
                    state.phase = ProcessStartPhase::Completing { cancellation: None };
                }
                ProcessStartPhase::Failed(error) => return Err(error),
                _ => return Err(ErrorCode::ProtocolState),
            }
        }

        let completion = self.process.complete_start().map_err(ErrorCode::from);
        let (result, association_failure, shutdown) = {
            let mut state = self
                .state
                .lock()
                .expect("process start transaction mutex poisoned");
            let ProcessStartPhase::Completing { cancellation } = state.phase else {
                unreachable!("process completion phase cannot change independently");
            };
            match completion {
                Ok(()) => {
                    state.start_completed = true;
                    if let Some(error) = cancellation {
                        state.phase = ProcessStartPhase::Failed(error);
                        (Err(error), None, None)
                    } else {
                        state.phase = ProcessStartPhase::Running;
                        (Ok(()), None, None)
                    }
                }
                Err(error) => {
                    state.phase = ProcessStartPhase::Failed(error);
                    state.abnormal |= error == ErrorCode::Internal;
                    if state.shutdown_request == ShutdownRequest::None {
                        state.shutdown_request = ShutdownRequest::Expected;
                    }
                    (
                        Err(error),
                        state.association_failure.as_ref().map(Arc::clone),
                        state.shutdown.clone(),
                    )
                }
            }
        };
        self.changed.notify_all();
        if let Some(association_failure) = association_failure {
            association_failure();
        }
        if let Some(shutdown) = shutdown {
            shutdown.shutdown();
        }
        result
    }

    pub(super) fn install_shutdown(&self, shutdown: Arc<RunnerShutdown>) {
        let shutdown = {
            let mut state = self
                .state
                .lock()
                .expect("process start transaction mutex poisoned");
            state.shutdown = Some(Arc::clone(&shutdown));
            (state.shutdown_request != ShutdownRequest::None).then_some(shutdown)
        };
        if let Some(shutdown) = shutdown {
            shutdown.shutdown();
        }
    }

    fn install_association_failure(&self, failure: AssociationFailure) {
        let failure = {
            let mut state = self
                .state
                .lock()
                .expect("process start transaction mutex poisoned");
            state.association_failure = Some(Arc::clone(&failure));
            (state.shutdown_request != ShutdownRequest::None).then_some(failure)
        };
        if let Some(failure) = failure {
            failure();
        }
    }

    fn abort(&self, error: ErrorCode, abnormal: bool, expected_shutdown: bool) {
        let (association_failure, shutdown) = {
            let mut state = self
                .state
                .lock()
                .expect("process start transaction mutex poisoned");
            state.abnormal |= abnormal;
            let should_terminate = match &mut state.phase {
                ProcessStartPhase::Starting | ProcessStartPhase::Ready { .. } => {
                    state.phase = ProcessStartPhase::Failed(error);
                    true
                }
                ProcessStartPhase::Completing { cancellation } => {
                    if cancellation.is_none() {
                        *cancellation = Some(error);
                        true
                    } else {
                        false
                    }
                }
                ProcessStartPhase::Failed(_) | ProcessStartPhase::Running => false,
            };
            if should_terminate && state.shutdown_request == ShutdownRequest::None {
                state.shutdown_request = if expected_shutdown {
                    ShutdownRequest::Expected
                } else {
                    ShutdownRequest::Unexpected
                };
            }
            self.changed.notify_all();
            if should_terminate {
                (
                    state.association_failure.as_ref().map(Arc::clone),
                    state.shutdown.clone(),
                )
            } else {
                (None, None)
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
        let mut state = self
            .state
            .lock()
            .expect("process start transaction mutex poisoned");
        state.association_failure = None;
        match &mut state.phase {
            ProcessStartPhase::Starting | ProcessStartPhase::Ready { .. } => {
                state.phase = ProcessStartPhase::Failed(ErrorCode::PeerClosed);
            }
            ProcessStartPhase::Completing { cancellation } => {
                if cancellation.is_none() {
                    *cancellation = Some(ErrorCode::PeerClosed);
                }
            }
            ProcessStartPhase::Failed(_) | ProcessStartPhase::Running => {}
        }
        self.changed.notify_all();
    }

    pub(super) fn mark_shutdown_expected(&self) {
        let mut state = self
            .state
            .lock()
            .expect("process start transaction mutex poisoned");
        if state.shutdown_request == ShutdownRequest::None {
            state.shutdown_request = ShutdownRequest::Expected;
        }
    }

    pub(super) fn mark_abnormal(&self) {
        self.state
            .lock()
            .expect("process start transaction mutex poisoned")
            .abnormal = true;
    }

    pub(super) fn shutdown_request(&self) -> ShutdownRequest {
        self.state
            .lock()
            .expect("process start transaction mutex poisoned")
            .shutdown_request
    }

    fn start_completed(&self) -> bool {
        self.state
            .lock()
            .expect("process start transaction mutex poisoned")
            .start_completed
    }

    fn protocol_finished(&self) -> Option<bool> {
        let mut state = self
            .state
            .lock()
            .expect("process start transaction mutex poisoned");
        match state.finalization {
            FinalizationState::Active => {
                state.finalization = FinalizationState::ProtocolFinished;
                None
            }
            FinalizationState::RunnerFinished => {
                state.finalization = FinalizationState::Finalized;
                Some(state.abnormal)
            }
            FinalizationState::ProtocolFinished | FinalizationState::Finalized => None,
        }
    }

    fn runner_finished(&self, abnormal: bool) -> Option<bool> {
        let mut state = self
            .state
            .lock()
            .expect("process start transaction mutex poisoned");
        state.abnormal |= abnormal;
        match state.finalization {
            FinalizationState::Active => {
                state.finalization = FinalizationState::RunnerFinished;
                None
            }
            FinalizationState::ProtocolFinished => {
                state.finalization = FinalizationState::Finalized;
                Some(state.abnormal)
            }
            FinalizationState::RunnerFinished | FinalizationState::Finalized => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FinalizationState, PROCESS_START_TIMEOUT, ProcessStartPhase, ProcessStartTransaction,
        ProcessStartTransactionState, RunnerConfig, RunnerProcessManager,
        RunnerProcessManagerState, ShutdownRequest,
    };
    use litebox_broker_core::test_support::TestBrokerCoreBuilder;
    use litebox_broker_core::{BrokerCore, CallerCredential, ObjectRights, PolicyEngine};
    use litebox_broker_protocol::error::ErrorCode;
    use std::path::PathBuf;
    use std::sync::{Arc, Condvar, Mutex, mpsc};
    use std::time::{Duration, Instant};

    fn starting_transaction() -> (BrokerCore, Arc<ProcessStartTransaction>) {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let parent = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let parent_id = parent.id();
        let (process, _) = parent.create_child(&[]).unwrap();
        parent.cleanup(true);
        (
            broker,
            Arc::new(ProcessStartTransaction {
                parent_id,
                process,
                state: Mutex::new(ProcessStartTransactionState {
                    phase: ProcessStartPhase::Starting,
                    shutdown: None,
                    association_failure: None,
                    shutdown_request: ShutdownRequest::None,
                    abnormal: false,
                    start_completed: false,
                    finalization: FinalizationState::Active,
                }),
                changed: Condvar::new(),
            }),
        )
    }

    #[test]
    fn ready_report_waits_for_broker_start_completion() {
        let (_broker, transaction) = starting_transaction();
        let ready = Arc::clone(&transaction);
        let waiter = std::thread::spawn(move || ready.ready_and_wait(None));

        assert_eq!(
            transaction
                .wait_until_ready(Instant::now() + Duration::from_secs(1))
                .unwrap(),
            None
        );
        transaction.complete_start().unwrap();

        waiter.join().unwrap().unwrap();
        assert!(transaction.process.is_running());
        transaction.process.cleanup(true);
    }

    #[test]
    fn reported_start_failure_wakes_the_parent_request() {
        let (_broker, transaction) = starting_transaction();

        transaction
            .report_start_failure(ErrorCode::UnsupportedOperation)
            .unwrap();

        assert_eq!(
            transaction.wait_until_ready(Instant::now() + Duration::from_secs(1)),
            Err(ErrorCode::UnsupportedOperation)
        );
        assert!(transaction.shutdown_request().was_expected());
        transaction.process.cleanup(true);
    }

    #[test]
    fn startup_timeout_aborts_the_transaction() {
        let (_broker, transaction) = starting_transaction();
        let deadline = Instant::now() + Duration::from_millis(1);

        assert_eq!(
            transaction.wait_until_ready(deadline),
            Err(ErrorCode::Internal)
        );
        assert!(matches!(
            transaction.state.lock().unwrap().phase,
            ProcessStartPhase::Failed(ErrorCode::Internal)
        ));
        transaction.process.cleanup(true);
    }

    #[test]
    fn parent_abort_releases_a_ready_child() {
        let (_broker, transaction) = starting_transaction();
        let ready = Arc::clone(&transaction);
        let waiter = std::thread::spawn(move || ready.ready_and_wait(None));
        transaction
            .wait_until_ready(Instant::now() + Duration::from_secs(1))
            .unwrap();

        transaction.abort(ErrorCode::PeerClosed, false, true);

        assert_eq!(waiter.join().unwrap(), Err(ErrorCode::PeerClosed));
        transaction.process.cleanup(true);
    }

    #[test]
    fn finalization_waits_for_protocol_and_runner_completion() {
        let (_broker, transaction) = starting_transaction();

        assert_eq!(transaction.protocol_finished(), None);
        assert_eq!(transaction.runner_finished(false), Some(false));
        assert_eq!(transaction.runner_finished(false), None);
        transaction.process.cleanup(true);
    }

    #[test]
    fn ending_parent_association_aborts_pending_children() {
        let (broker, transaction) = starting_transaction();
        let parent_id = transaction.parent_id;
        let manager = RunnerProcessManager {
            broker,
            started_runner_config: RunnerConfig::new(PathBuf::new(), Vec::new()),
            state: Mutex::new(RunnerProcessManagerState {
                transactions: vec![Arc::clone(&transaction)],
                associations: Vec::new(),
                active_instances: 1,
            }),
            drained: Condvar::new(),
        };

        manager.association_ending(parent_id);

        assert_eq!(
            transaction.wait_until_ready(Instant::now() + PROCESS_START_TIMEOUT),
            Err(ErrorCode::PeerClosed)
        );
        transaction.process.cleanup(true);
    }

    #[test]
    fn association_registration_installs_pending_failure_callback() {
        let (broker, transaction) = starting_transaction();
        let process_id = transaction.process.id();
        let manager = RunnerProcessManager {
            broker,
            started_runner_config: RunnerConfig::new(PathBuf::new(), Vec::new()),
            state: Mutex::new(RunnerProcessManagerState {
                transactions: vec![Arc::clone(&transaction)],
                associations: Vec::new(),
                active_instances: 1,
            }),
            drained: Condvar::new(),
        };
        let (failed, failure) = mpsc::sync_channel(1);

        manager
            .register_association(
                process_id,
                Arc::new(move || {
                    let _ = failed.send(());
                }),
            )
            .unwrap();
        transaction.abort(ErrorCode::Internal, true, true);

        failure.recv_timeout(Duration::from_secs(1)).unwrap();
        transaction.process.cleanup(true);
    }
}
