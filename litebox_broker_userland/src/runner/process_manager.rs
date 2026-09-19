// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared coordination for out-of-process runner instances.

use std::io::{Error as IoError, Result as IoResult};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerProcess};
use litebox_broker_host::{RequestFailure, read_shared_buffer};
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult};
use litebox_broker_protocol::process::{
    InheritedProcessObjects, MAX_PROCESS_BOOTSTRAP_SIZE, ProcessBootstrapFormat,
    ProcessBootstrapVersion, ProcessIdentity, ProcessStartupData,
};
use litebox_broker_protocol::{ProcessId, ThreadId};
use litebox_broker_transport::shared_memory::{SharedBufferPool, SharedMemory};

use super::{
    RunnerCompletion, RunnerConfig, RunnerInstance, RunnerShutdown, TerminationProvenance,
    runner_exit_code_is_crash, runner_signal_is_abnormal,
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
    initial_thread_id: ThreadId,
    transaction: Arc<ProcessStartTransaction>,
    data: ProcessStartupData,
}

impl RunnerStartup {
    pub(super) fn transaction(&self) -> Arc<ProcessStartTransaction> {
        Arc::clone(&self.transaction)
    }

    pub(crate) fn into_process_and_data(
        self,
    ) -> ((Arc<BrokerProcess>, ThreadId), ProcessStartupData) {
        ((self.process, self.initial_thread_id), self.data)
    }
}

struct RunnerProcessManagerState {
    transactions: Vec<Arc<ProcessStartTransaction>>,
    associations: Vec<(ProcessId, AssociationFailure)>,
    active_instances: usize,
}

pub(crate) type AssociationFailure = Arc<dyn Fn() + Send + Sync>;

/// State for one blocking `StartChildProcess` request.
pub(super) struct ProcessStartTransaction {
    parent_id: ProcessId,
    process: Arc<BrokerProcess>,
    initial_thread_id: ThreadId,
    state: Mutex<ProcessStartTransactionState>,
    changed: Condvar,
}

#[derive(Clone, Copy)]
enum ProcessStartPhase {
    Starting,
    Running,
    Failed(ErrorCode),
}

struct ProcessStartTransactionState {
    phase: ProcessStartPhase,
    shutdown: Option<Arc<RunnerShutdown>>,
    association_failure: Option<AssociationFailure>,
    shutdown_request: ShutdownRequest,
    abnormal: bool,
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
    Unexpected,
}

impl ShutdownRequest {
    pub(super) const fn was_expected(self) -> bool {
        matches!(self, Self::Expected)
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
            BrokerOperation::StartChildProcess(request) => Some(
                read_shared_buffer(shared_buffers, request.buffer, MAX_PROCESS_BOOTSTRAP_SIZE)
                    .and_then(|bootstrap| {
                        self.start_child_process(
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
            _ => None,
        }
    }

    fn start_child_process(
        self: &Arc<Self>,
        parent: &BrokerProcess,
        format: ProcessBootstrapFormat,
        version: ProcessBootstrapVersion,
        bootstrap: Vec<u8>,
        requested_inherited_objects: InheritedProcessObjects,
    ) -> Result<ProcessIdentity, ErrorCode> {
        if !parent.is_running() {
            return Err(ErrorCode::ProtocolState);
        }
        let process = self
            .broker
            .create_process(parent.caller_credential())
            .map_err(ErrorCode::from)?;
        let inherited_objects = match parent
            .duplicate_object_references_to(requested_inherited_objects.as_slice(), &process)
        {
            Ok(inherited_objects) => inherited_objects,
            Err(error) => {
                process.cleanup(true);
                return Err(ErrorCode::from(error));
            }
        };
        let initial_thread_id = match process.create_thread() {
            Ok(initial_thread_id) => initial_thread_id,
            Err(error) => {
                process.cleanup(true);
                return Err(ErrorCode::from(error));
            }
        };
        let inherited_objects = InheritedProcessObjects::new(&inherited_objects)
            .expect("child handle count must match the bounded inheritance request");
        let process_id = process.id();
        let transaction = Arc::new(ProcessStartTransaction {
            parent_id: parent.id(),
            process: Arc::clone(&process),
            initial_thread_id,
            state: Mutex::new(ProcessStartTransactionState {
                phase: ProcessStartPhase::Starting,
                shutdown: None,
                association_failure: None,
                shutdown_request: ShutdownRequest::None,
                abnormal: false,
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
                                initial_thread_id,
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
                    Ok(Err(_error)) => process_manager.runner_finished(
                        &thread_transaction,
                        RunnerCompletion {
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
            .wait_until_running(deadline)
            .map(|()| ProcessIdentity {
                process_id,
                initial_thread_id: transaction.initial_thread_id,
            });
        self.remove_transaction(process_id);
        if let Some(abnormal) = transaction.protocol_finished() {
            self.finish_transaction(&transaction, abnormal);
        }
        result
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
        has_parent_transaction: bool,
        activate_process: impl FnOnce() -> Result<(), ErrorCode>,
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
        let activation = if has_parent_transaction {
            let Some(transaction) = transaction else {
                self.unregister_association(process_id);
                return Err(IoError::other("process has no pending parent transaction"));
            };
            transaction.install_association_failure(failure);
            transaction.activate(activate_process)
        } else if transaction.is_some() {
            self.unregister_association(process_id);
            return Err(IoError::other(
                "process without a parent transaction matched a pending transaction",
            ));
        } else {
            activate_process()
        };
        if let Err(error) = activation {
            self.unregister_association(process_id);
            return Err(IoError::other(format!(
                "failed to activate broker process association: {error}"
            )));
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
        let unexpected_crash = runner_signal_is_abnormal(
            result.runner_signal,
            result.termination_provenance.broker_termination(),
        );
        let abnormal = thread_panicked
            || result.association_panicked
            || result.shutdown_observation_failed
            || unexpected_crash
            || runner_exit_code_is_crash(result.runner_exit_code);
        transaction.abort(ErrorCode::PeerClosed, abnormal, false);
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

impl ProcessStartTransaction {
    fn wait_until_running(&self, deadline: Instant) -> Result<(), ErrorCode> {
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
                ProcessStartPhase::Running => return Ok(()),
                ProcessStartPhase::Failed(error) => return Err(error),
            }
        }
    }

    fn activate(
        &self,
        activate_process: impl FnOnce() -> Result<(), ErrorCode>,
    ) -> Result<(), ErrorCode> {
        let mut state = self
            .state
            .lock()
            .expect("process start transaction mutex poisoned");
        match state.phase {
            ProcessStartPhase::Starting => {}
            ProcessStartPhase::Failed(error) => return Err(error),
            ProcessStartPhase::Running => return Err(ErrorCode::ProtocolState),
        }
        match activate_process() {
            Ok(()) => {
                state.phase = ProcessStartPhase::Running;
                self.changed.notify_all();
                Ok(())
            }
            Err(error) => {
                state.phase = ProcessStartPhase::Failed(error);
                state.abnormal |= error == ErrorCode::Internal;
                if state.shutdown_request == ShutdownRequest::None {
                    state.shutdown_request = ShutdownRequest::Expected;
                }
                self.changed.notify_all();
                Err(error)
            }
        }
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
            let should_terminate = match state.phase {
                ProcessStartPhase::Starting => {
                    state.phase = ProcessStartPhase::Failed(error);
                    true
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
        match state.phase {
            ProcessStartPhase::Starting => {
                state.phase = ProcessStartPhase::Failed(ErrorCode::PeerClosed);
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
    use std::sync::{Arc, Condvar, Mutex};
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
        let process = broker.create_process(parent.caller_credential()).unwrap();
        let initial_thread_id = process.create_thread().unwrap();
        parent.cleanup(true);
        (
            broker,
            Arc::new(ProcessStartTransaction {
                parent_id,
                process,
                initial_thread_id,
                state: Mutex::new(ProcessStartTransactionState {
                    phase: ProcessStartPhase::Starting,
                    shutdown: None,
                    association_failure: None,
                    shutdown_request: ShutdownRequest::None,
                    abnormal: false,
                    finalization: FinalizationState::Active,
                }),
                changed: Condvar::new(),
            }),
        )
    }

    #[test]
    fn association_activation_wakes_the_parent_request() {
        let (_broker, transaction) = starting_transaction();
        let waiting = Arc::clone(&transaction);
        let waiter = std::thread::spawn(move || {
            waiting.wait_until_running(Instant::now() + Duration::from_secs(1))
        });

        let process = Arc::clone(&transaction.process);
        transaction
            .activate(move || process.complete_start().map_err(ErrorCode::from))
            .unwrap();
        waiter.join().unwrap().unwrap();
        assert!(transaction.process.is_running());
        assert!(
            transaction
                .process
                .owns_thread(transaction.initial_thread_id)
        );
        transaction.process.cleanup(true);
    }

    #[test]
    fn startup_timeout_aborts_the_transaction() {
        let (_broker, transaction) = starting_transaction();
        let deadline = Instant::now() + Duration::from_millis(1);

        assert_eq!(
            transaction.wait_until_running(deadline),
            Err(ErrorCode::Internal)
        );
        assert!(matches!(
            transaction.state.lock().unwrap().phase,
            ProcessStartPhase::Failed(ErrorCode::Internal)
        ));
        transaction.process.cleanup(true);
    }

    #[test]
    fn parent_abort_prevents_association_activation() {
        let (_broker, transaction) = starting_transaction();

        transaction.abort(ErrorCode::PeerClosed, false, true);

        assert_eq!(
            transaction.activate(|| panic!("aborted transaction must not activate its process")),
            Err(ErrorCode::PeerClosed)
        );
        assert_eq!(
            transaction.wait_until_running(Instant::now() + Duration::from_secs(1)),
            Err(ErrorCode::PeerClosed)
        );
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
            transaction.wait_until_running(Instant::now() + PROCESS_START_TIMEOUT),
            Err(ErrorCode::PeerClosed)
        );
        transaction.process.cleanup(true);
    }

    #[test]
    fn association_registration_activates_the_process() {
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
        let process = Arc::clone(&transaction.process);
        manager
            .register_association(process_id, Arc::new(|| {}), true, move || {
                process.complete_start().map_err(ErrorCode::from)
            })
            .unwrap();

        assert!(transaction.process.is_running());
        transaction.process.cleanup(true);
    }

    #[test]
    fn association_registration_activates_process_without_parent_transaction() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let process_id = process.id();
        let manager = RunnerProcessManager {
            broker,
            started_runner_config: RunnerConfig::new(PathBuf::new(), Vec::new()),
            state: Mutex::new(RunnerProcessManagerState {
                transactions: Vec::new(),
                associations: Vec::new(),
                active_instances: 0,
            }),
            drained: Condvar::new(),
        };
        let process_for_activation = Arc::clone(&process);

        manager
            .register_association(process_id, Arc::new(|| {}), false, move || {
                process_for_activation
                    .complete_start()
                    .map_err(ErrorCode::from)
            })
            .unwrap();

        assert!(process.is_running());
        process.cleanup(true);
    }

    #[test]
    fn late_parented_association_requires_its_transaction() {
        let (broker, transaction) = starting_transaction();
        let process_id = transaction.process.id();
        let manager = RunnerProcessManager {
            broker,
            started_runner_config: RunnerConfig::new(PathBuf::new(), Vec::new()),
            state: Mutex::new(RunnerProcessManagerState {
                transactions: Vec::new(),
                associations: Vec::new(),
                active_instances: 1,
            }),
            drained: Condvar::new(),
        };
        let process = Arc::clone(&transaction.process);

        assert!(
            manager
                .register_association(process_id, Arc::new(|| {}), true, move || {
                    process.complete_start().map_err(ErrorCode::from)
                })
                .is_err()
        );
        assert!(!transaction.process.is_running());
        transaction.process.cleanup(true);
    }
}
