// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner launch support backed by broker-owned process lifecycle state.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::process::ExitStatus;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use litebox_broker_core::{
    BrokerCore, BrokerError, BrokerProcess, CallerCredential, ChildImage, ProcessLifecycleSink,
};
use litebox_broker_host::ProcessLauncher;
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::process::{CpuTime, ProcessExitStatus, ProcessStartupData};

use crate::runner::{
    ChildConnection, RunnerCompletion, RunnerConfig, RunnerInstance, RunnerProcess,
    SharedObjectSenders, SupervisedRunners,
};

/// Userland implementation that starts one out-of-process runner per process.
pub(crate) struct UserlandProcessLauncher {
    broker: BrokerCore,
    started_runner_config: RunnerConfig,
    lifecycle: Arc<ProcessLifecycleNotifier>,
    runners: Mutex<RunnerRegistry>,
    /// Delivers host objects to the runners whose associations this launcher serves.
    pub(crate) shared_object_senders: SharedObjectSenders,
}

/// Runners this broker supervises.
///
/// A host process ID is registered from the moment its runner is spawned or adopted until the
/// runner has been reaped, so adoption can never claim a supervised runner. Registrations are
/// counted per host process ID, because the OS may reuse a reaped runner's ID for a new runner
/// before the old registration is removed.
#[derive(Default)]
struct RunnerRegistry {
    by_process: HashMap<ProcessId, std::sync::Weak<Mutex<RunnerProcess>>>,
    host_process_ids: SupervisedRunners,
}

impl RunnerRegistry {
    fn register(&mut self, host_process_id: u32) {
        *self.host_process_ids.entry(host_process_id).or_default() += 1;
    }

    fn remove(&mut self, process_id: ProcessId, host_process_id: u32) {
        self.by_process.remove(&process_id);
        if let Entry::Occupied(mut registrations) = self.host_process_ids.entry(host_process_id) {
            *registrations.get_mut() -= 1;
            if *registrations.get() == 0 {
                registrations.remove();
            }
        }
    }
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
            runners: Mutex::new(RunnerRegistry::default()),
            shared_object_senders: SharedObjectSenders::new(),
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
        let instance = {
            // Registration under the lock that adoption holds keeps the new runner's host
            // process ID from appearing unsupervised to a concurrent adoption.
            let mut runners = self.runners.lock().expect("runner registry mutex poisoned");
            RunnerInstance::start(config).inspect(|instance| {
                runners.register(instance.host_process_id());
            })
        };
        let Ok(instance) = instance else {
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
        let host_process_id = instance.host_process_id();
        self.runners
            .lock()
            .expect("runner registry mutex poisoned")
            .by_process
            .insert(process_id, Arc::downgrade(&instance.runner_process()));
        let setup_deadline = instance.setup_deadline();
        let broker = self.broker.clone();
        let launcher = Arc::clone(&self);
        let completion_process = Arc::clone(&process);
        let thread = std::thread::Builder::new()
            .name(format!("litebox-runner-{}", process_id.0))
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    instance.run_process_to_completion(association, broker, Arc::clone(&launcher))
                }));
                let (completion, thread_panicked) = match outcome {
                    Ok(completion) => (completion, false),
                    Err(_) => (RunnerCompletion::panicked(), true),
                };
                let abnormal = completion.is_abnormal(thread_panicked);
                Self::runner_finished(
                    &completion_process,
                    completion.process_exit_status(),
                    completion.cpu_time(),
                    abnormal,
                );
                // The instance reaped its runner before being consumed or dropped.
                // TODO: Release the host process ID only after deregistering it. The runner is
                // reaped before this removal, outside the registry lock, so the OS can reuse its
                // PID in between. Counted registrations keep a runner spawned with that PID
                // registered, but a native fork clone given it is refused adoption and its fork
                // fails. This is tolerable for now: Linux allocates PIDs sequentially, so reuse
                // within the window requires cycling through `pid_max`, and the window spans
                // only in-memory bookkeeping.
                launcher
                    .runners
                    .lock()
                    .expect("runner registry mutex poisoned")
                    .remove(process_id, host_process_id);
                if let Some(completion_sender) = completion_sender {
                    let _ = completion_sender.send(completion.into_result());
                }
            });
        if thread.is_err() {
            // Dropping the unstarted closure dropped, and so reaped, the instance.
            self.runners
                .lock()
                .expect("runner registry mutex poisoned")
                .remove(process_id, host_process_id);
            let _ = process.fail_start(BrokerError::OutOfMemory, false, true);
            process.retire(true);
            return Err(BrokerError::OutOfMemory);
        }
        drop(thread);

        self.lifecycle.wait_for_start(&process, setup_deadline)
    }

    fn runner_finished(
        process: &BrokerProcess,
        exit_status: ProcessExitStatus,
        cpu_time: CpuTime,
        abnormal: bool,
    ) {
        let _ = process.fail_start(BrokerError::PeerClosed, abnormal, false);
        process.retire(!abnormal);
        let _ = process.complete_exit(exit_status, cpu_time);
    }
}

impl ProcessLauncher for UserlandProcessLauncher {
    type ChildConnection = ChildConnection;

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

    fn deliver_child_connection(
        &self,
        parent: &BrokerProcess,
    ) -> Result<(ChildConnection, litebox_broker_protocol::SharedObjectToken), BrokerError> {
        crate::runner::deliver_child_connection(&self.shared_object_senders, parent.id())
    }

    fn launch_existing(
        self: Arc<Self>,
        parent_process_id: litebox_broker_protocol::ProcessId,
        process: Arc<BrokerProcess>,
        startup: ProcessStartupData,
        runner_descriptor: Vec<u8>,
        connection: Option<ChildConnection>,
    ) -> Result<(), BrokerError> {
        // Authenticating may wait for the clone, so it precedes the registry lock.
        let rejected = |error: IoError| {
            litebox_util_log::warn!("rejected native fork runner: {error}");
            clone_adoption_error(&error)
        };
        let adoption = RunnerInstance::authenticate_clone(runner_descriptor, connection)
            .map_err(rejected)
            .and_then(|clone| {
                let mut runners = self.runners.lock().expect("runner registry mutex poisoned");
                let adoption = runners
                    .by_process
                    .get(&parent_process_id)
                    .and_then(std::sync::Weak::upgrade)
                    .ok_or(BrokerError::PeerClosed)
                    .and_then(|parent| {
                        RunnerInstance::adopt(&parent, clone, &runners.host_process_ids)
                            .map_err(rejected)
                    });
                // TODO: Reap Linux clones that are never adopted. CLONE_PARENT makes them this
                // broker's children, so their parent runner's cleanup leaves zombies here.
                if let Ok(instance) = &adoption {
                    runners.register(instance.host_process_id());
                }
                adoption
            });
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
    fn create_image(
        &self,
        capacity: u64,
    ) -> Result<Box<dyn litebox_broker_core::ProcessImage>, BrokerError> {
        crate::runner::create_image(capacity)
    }
}

/// Returns the error that the parent of a native clone that could not be adopted receives, which
/// its guest's fork reports, for an adoption that failed with `error`.
///
/// A clone that died or stalled, or the broker running out of descriptors, is a transient failure
/// (`EAGAIN`), and the broker running out of memory is reported as such (`ENOMEM`). Any other
/// failure is denied (`EPERM`).
fn clone_adoption_error(error: &IoError) -> BrokerError {
    if crate::runner::is_out_of_descriptors(error) {
        return BrokerError::ResourceExhausted;
    }
    match error.kind() {
        ErrorKind::UnexpectedEof
        | ErrorKind::BrokenPipe
        | ErrorKind::ConnectionReset
        | ErrorKind::TimedOut
        | ErrorKind::WouldBlock => BrokerError::ResourceExhausted,
        ErrorKind::OutOfMemory => BrokerError::OutOfMemory,
        _ => BrokerError::PolicyDenied,
    }
}

fn broker_io_error(error: BrokerError) -> IoError {
    IoError::other(error)
}
