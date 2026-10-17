// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner launch support backed by broker-owned process lifecycle state.

use std::collections::HashMap;
use std::io::{Error as IoError, Result as IoResult};
use std::process::ExitStatus;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use litebox_broker_core::{
    BrokerCore, BrokerError, BrokerProcess, CallerCredential, ChildImage, ProcessLifecycleSink,
};
use litebox_broker_host::ProcessLauncher;
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::process::{ProcessExitStatus, ProcessStartupData};

use crate::runner::{RunnerCompletion, RunnerConfig, RunnerInstance, RunnerProcess};

/// Userland implementation that starts one out-of-process runner per process.
pub(crate) struct UserlandProcessLauncher {
    broker: BrokerCore,
    started_runner_config: RunnerConfig,
    lifecycle: Arc<ProcessLifecycleNotifier>,
    runners: Mutex<HashMap<ProcessId, std::sync::Weak<Mutex<RunnerProcess>>>>,
}

/// Pending association for a broker-created runner process.
pub(crate) struct PendingRunnerAssociation {
    pub(super) process: Arc<BrokerProcess>,
    data: Option<ProcessStartupData>,
    image: Option<ChildImage>,
}

impl PendingRunnerAssociation {
    fn new(
        process: Arc<BrokerProcess>,
        data: Option<ProcessStartupData>,
        image: Option<ChildImage>,
    ) -> Self {
        Self {
            process,
            data,
            image,
        }
    }

    /// Takes the memory image to pass to the runner during setup.
    pub(crate) fn take_image(&mut self) -> Option<ChildImage> {
        self.image.take()
    }

    pub(crate) fn into_process_and_startup(
        self,
    ) -> (Arc<BrokerProcess>, Option<ProcessStartupData>) {
        (self.process, self.data)
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
        deadline: Instant,
    ) -> Result<(), BrokerError> {
        let mut state = self.state.lock().expect("process lifecycle mutex poisoned");
        loop {
            if let Some(result) = process.startup_result() {
                return result;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                drop(state);
                return process.fail_start(BrokerError::PeerClosed, true, true);
            }
            let (next_state, wait_result) = self
                .changed
                .wait_timeout(state, remaining)
                .expect("process lifecycle mutex poisoned");
            state = next_state;
            if wait_result.timed_out() {
                drop(state);
                return process.fail_start(BrokerError::PeerClosed, true, true);
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
    fn new(started_runner_config: RunnerConfig, broker: BrokerCore) -> Arc<Self> {
        let lifecycle = Arc::new(ProcessLifecycleNotifier::default());
        let broker = broker.with_process_lifecycle_sink(lifecycle.clone());
        Arc::new(Self {
            broker,
            started_runner_config,
            lifecycle,
            runners: Mutex::new(HashMap::new()),
        })
    }

    fn wait_for_drain(&self) {
        self.lifecycle.wait_for_drain(&self.broker);
    }

    pub(crate) fn run_root(config: RunnerConfig, broker: &BrokerCore) -> IoResult<ExitStatus> {
        let launcher = Self::new(config.without_initial_arguments(), broker.clone());
        let process = launcher
            .broker
            .create_process(CallerCredential::HostGuaranteed, None)
            .map_err(broker_io_error)?;
        let association = PendingRunnerAssociation::new(Arc::clone(&process), None, None);
        let (completion_sender, completion_receiver) = sync_channel(1);
        let startup =
            Arc::clone(&launcher).launch_runner(association, config, Some(completion_sender));
        if let Err(error) = startup {
            drop(process);
            launcher.wait_for_drain();
            let fallback = broker_io_error(error);
            return match completion_receiver.recv() {
                Ok(Err(error)) => Err(error),
                Ok(Ok(_)) | Err(_) => Err(fallback),
            };
        }
        let result = completion_receiver
            .recv()
            .unwrap_or_else(|_| Err(IoError::other("root runner completion channel closed")));
        drop(process);
        launcher.wait_for_drain();
        result
    }

    fn launch_runner(
        self: Arc<Self>,
        association: PendingRunnerAssociation,
        config: RunnerConfig,
        completion_sender: Option<SyncSender<IoResult<ExitStatus>>>,
    ) -> Result<(), BrokerError> {
        let process = Arc::clone(&association.process);
        let Ok(instance) = RunnerInstance::start(config) else {
            let _ = process.fail_start(BrokerError::PeerClosed, false, false);
            process.retire(true);
            return Err(BrokerError::PeerClosed);
        };
        self.launch_runner_instance(association, instance, completion_sender)
    }

    fn launch_runner_instance(
        self: Arc<Self>,
        association: PendingRunnerAssociation,
        instance: RunnerInstance,
        completion_sender: Option<SyncSender<IoResult<ExitStatus>>>,
    ) -> Result<(), BrokerError> {
        let process = Arc::clone(&association.process);
        let process_id = process.id();
        self.runners
            .lock()
            .expect("runner registry mutex poisoned")
            .insert(process_id, Arc::downgrade(&instance.runner_process()));
        let setup_deadline = instance.setup_deadline();
        let broker = self.broker.clone();
        let launcher = Arc::clone(&self);
        let association_launcher = Arc::clone(&launcher);
        let completion_process = Arc::clone(&process);
        let thread = std::thread::Builder::new()
            .name(format!("litebox-runner-{}", process_id.0))
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    instance.run_process_to_completion(association, broker, association_launcher)
                }));
                let (completion, thread_panicked) = match outcome {
                    Ok(completion) => (completion, false),
                    Err(_) => (RunnerCompletion::panicked(), true),
                };
                let abnormal = completion.is_abnormal(thread_panicked);
                Self::runner_finished(
                    &completion_process,
                    completion.process_exit_status(),
                    abnormal,
                );
                launcher
                    .runners
                    .lock()
                    .expect("runner registry mutex poisoned")
                    .remove(&process_id);
                if let Some(completion_sender) = completion_sender {
                    let _ = completion_sender.send(completion.into_result());
                }
            });
        if thread.is_err() {
            self.runners
                .lock()
                .expect("runner registry mutex poisoned")
                .remove(&process_id);
            let _ = process.fail_start(BrokerError::OutOfMemory, false, true);
            process.retire(true);
            return Err(BrokerError::OutOfMemory);
        }
        drop(thread);

        self.lifecycle.wait_for_start(&process, setup_deadline)
    }

    fn runner_finished(process: &BrokerProcess, exit_status: ProcessExitStatus, abnormal: bool) {
        let _ = process.fail_start(BrokerError::PeerClosed, abnormal, false);
        process.retire(!abnormal);
        let _ = process.complete_exit(exit_status);
    }
}

impl ProcessLauncher for UserlandProcessLauncher {
    fn launch(
        self: Arc<Self>,
        process: Arc<BrokerProcess>,
        data: ProcessStartupData,
        image: Option<ChildImage>,
    ) -> Result<(), BrokerError> {
        let config = self.started_runner_config.clone();
        self.launch_runner(
            PendingRunnerAssociation::new(process, Some(data), image),
            config,
            None,
        )
    }

    fn launch_existing(
        self: Arc<Self>,
        parent_process_id: litebox_broker_protocol::ProcessId,
        process: Arc<BrokerProcess>,
        startup: ProcessStartupData,
        launch_descriptor: Vec<u8>,
    ) -> Result<(), BrokerError> {
        #[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
        {
            let adoption = (|| {
                let parent = self
                    .runners
                    .lock()
                    .expect("runner registry mutex poisoned")
                    .get(&parent_process_id)
                    .and_then(std::sync::Weak::upgrade)
                    .ok_or(BrokerError::PeerClosed)?;
                RunnerInstance::adopt(&parent, &launch_descriptor)
                    .map_err(|_| BrokerError::PolicyDenied)
            })();
            let instance = match adoption {
                Ok(instance) => instance,
                Err(error) => {
                    let _ = process.fail_start(error, false, true);
                    process.retire(true);
                    return Err(error);
                }
            };
            self.launch_runner_instance(
                PendingRunnerAssociation::new(process, Some(startup), None),
                instance,
                None,
            )
        }
        #[cfg(not(any(target_os = "linux", all(windows, target_arch = "x86_64"))))]
        {
            let _ = startup;
            let _ = launch_descriptor;
            let _ = process.fail_start(BrokerError::UnsupportedOperation, false, true);
            process.retire(true);
            Err(BrokerError::UnsupportedOperation)
        }
    }

    fn create_image(
        &self,
        capacity: u64,
    ) -> Result<Box<dyn litebox_broker_core::ProcessImage>, BrokerError> {
        crate::runner::create_image(capacity)
    }
}

fn broker_io_error(error: BrokerError) -> IoError {
    IoError::other(error)
}
