// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Child runner launch support backed by broker-owned process lifecycle state.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerError, BrokerProcess, ProcessLifecycleSink};
use litebox_broker_host::{RequestFailure, read_shared_buffer};
use litebox_broker_protocol::ThreadId;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult};
use litebox_broker_protocol::process::{
    InheritedProcessObjects, MAX_PROCESS_BOOTSTRAP_SIZE, ProcessBootstrapFormat,
    ProcessBootstrapVersion, ProcessIdentity, ProcessStartupData,
};
use litebox_broker_transport::shared_memory::{SharedBufferPool, SharedMemory};

use super::{
    RunnerCompletion, RunnerConfig, RunnerInstance, runner_exit_code_is_crash,
    runner_signal_is_abnormal,
};

const PROCESS_START_TIMEOUT: Duration = Duration::from_secs(5);

/// Immutable service used to launch child runners.
pub(crate) struct RunnerLauncher {
    broker: BrokerCore,
    started_runner_config: RunnerConfig,
    lifecycle: Arc<ProcessLifecycleRuntime>,
}

/// Startup context for a runner whose broker process was created by its parent.
pub(crate) struct RunnerStartup {
    pub(super) process: Arc<BrokerProcess>,
    initial_thread_id: ThreadId,
    data: ProcessStartupData,
}

impl RunnerStartup {
    pub(crate) fn into_process_and_data(
        self,
    ) -> ((Arc<BrokerProcess>, ThreadId), ProcessStartupData) {
        ((self.process, self.initial_thread_id), self.data)
    }
}

#[derive(Default)]
struct ProcessLifecycleRuntime {
    state: Mutex<()>,
    changed: Condvar,
}

impl ProcessLifecycleSink for ProcessLifecycleRuntime {
    fn changed(&self) {
        self.notify();
    }
}

impl ProcessLifecycleRuntime {
    fn notify(&self) {
        let _state = self.state.lock().expect("process lifecycle mutex poisoned");
        self.changed.notify_all();
    }

    fn wait_for_start(&self, process: &BrokerProcess, timeout: Duration) -> Result<(), ErrorCode> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().expect("process lifecycle mutex poisoned");
        loop {
            if let Some(result) = process.startup_result() {
                return result.map_err(ErrorCode::from);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                drop(state);
                process.fail_start(BrokerError::Internal, true, true);
                return Err(ErrorCode::Internal);
            }
            let (next_state, wait_result) = self
                .changed
                .wait_timeout(state, remaining)
                .expect("process lifecycle mutex poisoned");
            state = next_state;
            if wait_result.timed_out() && process.startup_result().is_none() {
                drop(state);
                process.fail_start(BrokerError::Internal, true, true);
                return Err(ErrorCode::Internal);
            }
        }
    }

    fn wait_for_drain(&self, broker: &BrokerCore) {
        let mut state = self.state.lock().expect("process lifecycle mutex poisoned");
        while broker.has_processes() {
            state = self
                .changed
                .wait(state)
                .expect("process lifecycle mutex poisoned");
        }
    }
}

impl RunnerLauncher {
    pub(super) fn new(started_runner_config: RunnerConfig, broker: BrokerCore) -> Arc<Self> {
        let lifecycle = Arc::new(ProcessLifecycleRuntime::default());
        let broker = broker.with_process_lifecycle_sink(lifecycle.clone());
        Arc::new(Self {
            broker,
            started_runner_config,
            lifecycle,
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
            .create_process(parent.caller_credential(), Some(parent.id()))
            .map_err(ErrorCode::from)?;
        let inherited_objects = match parent
            .duplicate_object_references_to(requested_inherited_objects.as_slice(), &process)
        {
            Ok(inherited_objects) => inherited_objects,
            Err(error) => {
                process.retire(true);
                return Err(ErrorCode::from(error));
            }
        };
        let initial_thread_id = match process.create_thread() {
            Ok(initial_thread_id) => initial_thread_id,
            Err(error) => {
                process.retire(true);
                return Err(ErrorCode::from(error));
            }
        };
        let inherited_objects = InheritedProcessObjects::new(&inherited_objects)
            .expect("child handle count must match the bounded inheritance request");
        let process_id = process.id();
        if parent.is_cancellation_requested() {
            process.retire(true);
            return Err(ErrorCode::PeerClosed);
        }

        let launcher = Arc::clone(self);
        let config = self.started_runner_config.clone();
        let runner_process = Arc::clone(&process);
        let thread = std::thread::Builder::new()
            .name(format!("litebox-runner-{}", process_id.0))
            .spawn(move || {
                let completion_process = Arc::clone(&runner_process);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    RunnerInstance::start(config).map(|instance| {
                        instance.run_started_process_to_completion(
                            RunnerStartup {
                                process: runner_process,
                                initial_thread_id,
                                data: ProcessStartupData {
                                    format,
                                    version,
                                    payload: bootstrap,
                                    inherited_objects,
                                },
                            },
                            Arc::clone(&launcher),
                        )
                    })
                }));
                let (result, thread_panicked) = match outcome {
                    Ok(Ok(result)) => (result, false),
                    Ok(Err(_error)) => (RunnerCompletion::default(), false),
                    Err(_) => (RunnerCompletion::default(), true),
                };
                Self::runner_finished(&completion_process, result, thread_panicked);
            });
        if thread.is_err() {
            process.retire(true);
            return Err(ErrorCode::OutOfMemory);
        }
        drop(thread);

        self.lifecycle
            .wait_for_start(&process, PROCESS_START_TIMEOUT)
            .map(|()| ProcessIdentity {
                process_id,
                initial_thread_id,
            })
    }

    fn runner_finished(process: &BrokerProcess, result: RunnerCompletion, thread_panicked: bool) {
        let unexpected_crash =
            runner_signal_is_abnormal(result.runner_signal, result.broker_termination);
        let abnormal = thread_panicked
            || unexpected_crash
            || runner_exit_code_is_crash(result.runner_exit_code);
        process.fail_start(BrokerError::PeerClosed, abnormal, false);
        process.retire(!abnormal);
    }

    pub(super) fn wait_for_drain(&self) {
        self.lifecycle.wait_for_drain(&self.broker);
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
