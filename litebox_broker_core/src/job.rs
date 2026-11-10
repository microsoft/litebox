// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Jobs.
//!
//! A job groups processes for accounting and lifecycle. It counts its
//! processes' threads against their task limits, publishes their lifecycle
//! changes, and terminates them all on request.
//!
//! A root process belongs to the job it is created in (see
//! [`BrokerCore::create_process`](crate::BrokerCore::create_process)). A child
//! belongs to its parent's job. A process never moves to another job.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::AtomicUsize;

use hashbrown::HashMap;
use spin::rwlock::RwLock;

use crate::{BrokerError, BrokerProcess, ProcessKey, ProcessLifecycleSink, Result};

/// A group of processes that share thread accounting and are terminated
/// together.
pub struct Job {
    /// Lock order: a PID namespace's registry, then this lock, then the
    /// namespace's ID allocator.
    state: RwLock<JobState>,
    /// The number of threads in this job. A process can't create a thread
    /// once this count reaches its task limit.
    pub(crate) threads: AtomicUsize,
    /// PID namespaces that this job's processes have created and that still
    /// exist.
    pub(crate) pid_namespaces: Arc<AtomicUsize>,
    lifecycle_sink: Option<Arc<dyn ProcessLifecycleSink>>,
}

struct JobState {
    /// The job's processes that remain registered.
    processes: HashMap<ProcessKey, Weak<BrokerProcess>>,
    /// Whether the job is terminating. A terminating job refuses new
    /// processes.
    terminating: bool,
}

impl Job {
    /// Creates an empty job. If `lifecycle_sink` is given, the job publishes
    /// its processes' lifecycle changes to it.
    #[must_use]
    pub fn new(lifecycle_sink: Option<Arc<dyn ProcessLifecycleSink>>) -> Arc<Self> {
        Arc::new(Self {
            state: RwLock::new(JobState {
                processes: HashMap::new(),
                terminating: false,
            }),
            threads: AtomicUsize::new(0),
            pid_namespaces: Arc::new(AtomicUsize::new(0)),
            lifecycle_sink,
        })
    }

    /// Returns whether this job still has any registered processes.
    #[must_use]
    pub fn has_processes(&self) -> bool {
        !self.state.read().processes.is_empty()
    }

    /// Terminates this job. The job refuses new processes, and it requests an
    /// expected shutdown of each of its processes' runners. A runner whose
    /// termination action isn't installed yet shuts down once it is
    /// installed.
    pub fn terminate(&self) {
        let processes = {
            let mut state = self.state.write();
            state.terminating = true;
            state
                .processes
                .values()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>()
        };
        // Release the lock first, because dropping a process's last reference
        // removes it from this job, which takes the lock. Skip released
        // processes.
        for process in processes {
            if !process.is_released() {
                process.request_expected_shutdown();
            }
        }
    }

    /// Runs `create` and adds the process it returns to this job.
    ///
    /// Returns `PeerClosed` without running `create` if this job is
    /// terminating.
    pub(crate) fn add(
        &self,
        create: impl FnOnce() -> Result<Arc<BrokerProcess>>,
    ) -> Result<Arc<BrokerProcess>> {
        let mut state = self.state.write();
        if state.terminating {
            return Err(BrokerError::PeerClosed);
        }
        state
            .processes
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        let process = create()?;
        state
            .processes
            .insert(process.key(), Arc::downgrade(&process));
        Ok(process)
    }

    /// Removes the process `key` from this job. Called when the process is
    /// cleaned up.
    pub(crate) fn remove(&self, key: ProcessKey) {
        self.state.write().processes.remove(&key);
    }

    /// Publishes a change in the lifecycle of one of this job's processes.
    pub(crate) fn lifecycle_changed(&self) {
        if let Some(sink) = &self.lifecycle_sink {
            sink.changed();
        }
    }
}
