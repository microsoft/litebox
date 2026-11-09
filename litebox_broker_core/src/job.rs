// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Jobs.
//!
//! A job groups processes for accounting and lifecycle, as a Linux cgroup or
//! a Windows job object does: it counts its processes' threads against their
//! task limits, publishes their lifecycle changes, and terminates them all on
//! request. A root process is in the job it is created in (see
//! [`BrokerCore::create_process`](crate::BrokerCore::create_process)), and a
//! child in its parent's, so no process leaves its job, however it forks or
//! detaches.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::AtomicUsize;

use hashbrown::HashMap;
use spin::rwlock::RwLock;

use crate::{BrokerError, BrokerProcess, ProcessKey, ProcessLifecycleSink, Result};

/// A group of processes that are accounted for, and end, together.
pub struct Job {
    /// Lock order: a PID namespace's registry, then this lock, then the
    /// namespace's ID allocator.
    members: RwLock<Members>,
    /// The job's threads, which bound its processes' tasks.
    pub(crate) threads: AtomicUsize,
    lifecycle_sink: Option<Arc<dyn ProcessLifecycleSink>>,
}

struct Members {
    /// The job's processes that remain registered.
    processes: HashMap<ProcessKey, Weak<BrokerProcess>>,
    /// Whether the job is terminating, and so refuses new processes.
    terminating: bool,
}

impl Job {
    /// Creates an empty job, which publishes its processes' lifecycle changes
    /// to `lifecycle_sink`, if given.
    #[must_use]
    pub fn new(lifecycle_sink: Option<Arc<dyn ProcessLifecycleSink>>) -> Arc<Self> {
        Arc::new(Self {
            members: RwLock::new(Members {
                processes: HashMap::new(),
                terminating: false,
            }),
            threads: AtomicUsize::new(0),
            lifecycle_sink,
        })
    }

    /// Returns whether any of this job's processes remains registered.
    #[must_use]
    pub fn has_processes(&self) -> bool {
        !self.members.read().processes.is_empty()
    }

    /// Terminates this job: it refuses new processes, and the runner of each
    /// of its processes is shut down, as expected, now or once the runner's
    /// termination action is installed.
    pub fn terminate(&self) {
        let processes = {
            let mut members = self.members.write();
            members.terminating = true;
            members
                .processes
                .values()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>()
        };
        // Released processes are left alone, and the lock is released first,
        // since a final process drop leaves its job.
        for process in processes {
            if !process.is_released() {
                process.request_expected_shutdown();
            }
        }
    }

    /// Adds the process that `create` returns, unless this job is
    /// terminating, in which case it returns `PeerClosed` without running
    /// `create`.
    pub(crate) fn add(
        &self,
        create: impl FnOnce() -> Result<Arc<BrokerProcess>>,
    ) -> Result<Arc<BrokerProcess>> {
        let mut members = self.members.write();
        if members.terminating {
            return Err(BrokerError::PeerClosed);
        }
        members
            .processes
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        let process = create()?;
        members
            .processes
            .insert(process.key(), Arc::downgrade(&process));
        Ok(process)
    }

    /// Removes the process `key`, as it is cleaned up.
    pub(crate) fn remove(&self, key: ProcessKey) {
        self.members.write().processes.remove(&key);
    }

    /// Publishes a change in the lifecycle of one of this job's processes.
    pub(crate) fn lifecycle_changed(&self) {
        if let Some(sink) = &self.lifecycle_sink {
            sink.changed();
        }
    }
}
