// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Child runner launch support backed by broker-owned process lifecycle state.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerError, BrokerProcess, ProcessLifecycleSink};
use litebox_broker_host::ProcessLauncher;
use litebox_broker_protocol::ThreadId;
use litebox_broker_protocol::process::ProcessStartupData;

use crate::runner::{RunnerCompletion, RunnerConfig, RunnerInstance};

const PROCESS_START_TIMEOUT: Duration = Duration::from_secs(5);

/// Userland implementation that starts one out-of-process runner per process.
pub(crate) struct UserlandProcessLauncher {
    broker: BrokerCore,
    started_runner_config: RunnerConfig,
    lifecycle: Arc<ProcessLifecycleNotifier>,
}

/// Pending association for a runner whose broker process was created by its parent.
pub(crate) struct PendingRunnerAssociation {
    pub(super) process: Arc<BrokerProcess>,
    initial_thread_id: ThreadId,
    data: ProcessStartupData,
}

impl PendingRunnerAssociation {
    pub(crate) fn into_process_and_startup(
        self,
    ) -> ((Arc<BrokerProcess>, ThreadId), ProcessStartupData) {
        ((self.process, self.initial_thread_id), self.data)
    }
}

#[derive(Default)]
struct ProcessLifecycleNotifier {
    state: Mutex<()>,
    changed: Condvar,
}

impl ProcessLifecycleSink for ProcessLifecycleNotifier {
    fn changed(&self) {
        self.notify();
    }
}

impl ProcessLifecycleNotifier {
    fn notify(&self) {
        let _state = self.state.lock().expect("process lifecycle mutex poisoned");
        self.changed.notify_all();
    }

    fn wait_for_start(
        &self,
        process: &BrokerProcess,
        timeout: Duration,
    ) -> Result<(), BrokerError> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().expect("process lifecycle mutex poisoned");
        loop {
            if let Some(result) = process.startup_result() {
                return result;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                drop(state);
                process.fail_start(BrokerError::Internal, true, true);
                return Err(BrokerError::Internal);
            }
            let (next_state, wait_result) = self
                .changed
                .wait_timeout(state, remaining)
                .expect("process lifecycle mutex poisoned");
            state = next_state;
            if wait_result.timed_out() && process.startup_result().is_none() {
                drop(state);
                process.fail_start(BrokerError::Internal, true, true);
                return Err(BrokerError::Internal);
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

impl UserlandProcessLauncher {
    pub(super) fn new(started_runner_config: RunnerConfig, broker: BrokerCore) -> Arc<Self> {
        let lifecycle = Arc::new(ProcessLifecycleNotifier::default());
        let broker = broker.with_process_lifecycle_sink(lifecycle.clone());
        Arc::new(Self {
            broker,
            started_runner_config,
            lifecycle,
        })
    }

    pub(super) fn broker(&self) -> BrokerCore {
        self.broker.clone()
    }

    pub(super) fn wait_for_drain(&self) {
        self.lifecycle.wait_for_drain(&self.broker);
    }

    fn runner_finished(process: &BrokerProcess, result: RunnerCompletion, thread_panicked: bool) {
        let abnormal = result.is_abnormal(thread_panicked);
        process.fail_start(BrokerError::PeerClosed, abnormal, false);
        process.retire(!abnormal);
    }
}

impl ProcessLauncher for UserlandProcessLauncher {
    fn launch(
        self: Arc<Self>,
        process: Arc<BrokerProcess>,
        initial_thread_id: ThreadId,
        data: ProcessStartupData,
    ) -> Result<(), BrokerError> {
        let process_id = process.id();
        let broker = self.broker.clone();
        let launcher = Arc::clone(&self);
        let config = self.started_runner_config.clone();
        let runner_process = Arc::clone(&process);
        let thread = std::thread::Builder::new()
            .name(format!("litebox-runner-{}", process_id.0))
            .spawn(move || {
                let completion_process = Arc::clone(&runner_process);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    RunnerInstance::start(config).map(|instance| {
                        instance.run_started_process_to_completion(
                            PendingRunnerAssociation {
                                process: runner_process,
                                initial_thread_id,
                                data,
                            },
                            broker,
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
            return Err(BrokerError::OutOfMemory);
        }
        drop(thread);

        self.lifecycle
            .wait_for_start(&process, PROCESS_START_TIMEOUT)
    }
}
