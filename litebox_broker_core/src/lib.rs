// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker authority core independent of protocol envelopes and channels.
//!
//! `litebox_broker_core` owns broker-side object identity, reference lifetime,
//! rights checks, handle validity checks, and policy calls. It may use
//! shared semantic DTOs from `litebox_broker_protocol` for values that both the
//! local core and broker understand, such as handles and readiness state. It
//! deliberately has no dependency on protocol envelopes, channel traits, wire
//! codecs, Unix sockets, shared-memory rings, kernel traps, or any other
//! channel implementation.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod error;
pub mod event;
pub mod fs;
mod id;
pub mod pipe;
mod policy;
mod process;
pub mod random;
pub mod readiness;
pub mod socket;
pub mod stdio;

#[cfg(test)]
mod test_platform;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use hashbrown::HashMap;
use litebox_broker_protocol::{ObjectHandle, ProcessId, ThreadId};
use spin::{Mutex, rwlock::RwLock};

pub use error::BrokerError;
use fs::FileService;
use id::{IdAllocator, MAX_ALLOCATED_ID};
pub use policy::{
    DestinationPortRange, DestinationRule, Ipv4Cidr, MAX_DESTINATION_RULES, PolicyEngine,
    PolicyProfile, SocketPolicy, SocketPolicyError,
};
pub use process::{
    AssociationCancellation, BrokerProcess, BrokerThread, CallerCredential, ObjectRights,
    ProcessLifecycleSink, ProcessShutdown,
};
use process::{ObjectReference, ProcessParent, ProcessRoot};
use random::RandomProvider;
use socket::{BrokerSocketPorts, SocketProvider};
use stdio::StdioProvider;

/// BrokerCore result type.
pub type Result<T> = core::result::Result<T, BrokerError>;

/// Broker-wide ceilings and per-process quotas for broker-owned authority state.
///
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BrokerCoreLimits {
    /// Maximum broker processes that have not completed core teardown.
    pub max_processes: usize,
    /// Maximum live object references across all processes.
    pub max_references: usize,
    /// Maximum live object references owned by one process.
    pub max_references_per_process: usize,
    /// Maximum total capacity in bytes reserved by live pipes across all processes.
    pub max_total_pipe_capacity: usize,
    /// Maximum capacity in bytes reserved by live pipes created by one process.
    pub max_pipe_capacity_per_process: usize,
    /// Maximum live platform socket resources across all processes.
    pub max_sockets: usize,
    /// Maximum live platform socket resources owned by one process.
    pub max_sockets_per_process: usize,
    /// Maximum live broker-allocated thread IDs.
    pub max_threads: usize,
    /// Maximum live broker-allocated thread IDs owned by one process.
    pub max_threads_per_process: usize,
}

impl BrokerCoreLimits {
    /// Conservative default authority-state limits.
    pub const DEFAULT: Self = Self {
        max_processes: 1024,
        max_references: 4096,
        max_references_per_process: 1024,
        max_total_pipe_capacity: 64 * 1024 * 1024,
        max_pipe_capacity_per_process: 16 * 1024 * 1024,
        max_sockets: 1024,
        max_sockets_per_process: 256,
        max_threads: 4096,
        max_threads_per_process: 1024,
    };

    /// Creates a broker core limit set.
    ///
    /// The reference and pipe-capacity process quotas initially match their
    /// broker-wide limits. Use [`Self::with_process_quotas`] to override them.
    pub const fn new(max_references: usize, max_total_pipe_capacity: usize) -> Self {
        Self {
            max_processes: Self::DEFAULT.max_processes,
            max_references,
            max_references_per_process: max_references,
            max_total_pipe_capacity,
            max_pipe_capacity_per_process: max_total_pipe_capacity,
            max_sockets: Self::DEFAULT.max_sockets,
            max_sockets_per_process: Self::DEFAULT.max_sockets_per_process,
            max_threads: Self::DEFAULT.max_threads,
            max_threads_per_process: Self::DEFAULT.max_threads_per_process,
        }
    }

    /// Creates a broker core limit set with explicit socket limits.
    ///
    /// The reference and pipe-capacity process quotas initially match their
    /// broker-wide limits. Use [`Self::with_process_quotas`] to override them.
    pub const fn new_with_all_limits(
        max_references: usize,
        max_total_pipe_capacity: usize,
        max_sockets: usize,
        max_sockets_per_process: usize,
    ) -> Self {
        Self {
            max_processes: Self::DEFAULT.max_processes,
            max_references,
            max_references_per_process: max_references,
            max_total_pipe_capacity,
            max_pipe_capacity_per_process: max_total_pipe_capacity,
            max_sockets,
            max_sockets_per_process,
            max_threads: Self::DEFAULT.max_threads,
            max_threads_per_process: Self::DEFAULT.max_threads_per_process,
        }
    }

    /// Returns these limits with explicit per-process reference and pipe-capacity quotas.
    ///
    /// A quota above its broker-wide limit is accepted; the broker-wide limit
    /// still applies, so the effective limit is the smaller value.
    #[must_use]
    pub const fn with_process_quotas(
        self,
        max_references_per_process: usize,
        max_pipe_capacity_per_process: usize,
    ) -> Self {
        Self {
            max_references_per_process,
            max_pipe_capacity_per_process,
            ..self
        }
    }

    /// Returns these limits with an explicit broker process limit.
    #[must_use]
    pub const fn with_process_limit(self, max_processes: usize) -> Self {
        Self {
            max_processes,
            ..self
        }
    }

    /// Returns these limits with explicit broker-wide and per-process thread quotas.
    ///
    /// A per-process quota above the broker-wide limit is accepted; the
    /// broker-wide limit still applies.
    #[must_use]
    pub const fn with_thread_quotas(
        self,
        max_threads: usize,
        max_threads_per_process: usize,
    ) -> Self {
        Self {
            max_threads,
            max_threads_per_process,
            ..self
        }
    }
}

impl Default for BrokerCoreLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Channel-independent broker authority handle.
///
/// A broker process may construct only one broker core for its process
/// lifetime. Constructors return [`BrokerError::BrokerCoreAlreadyExists`] if a
/// core has already been constructed.
#[derive(Clone)]
pub struct BrokerCore {
    pub(crate) policy: Arc<PolicyEngine>,
    pub(crate) limits: BrokerCoreLimits,
    pub(crate) ids: Arc<Mutex<IdAllocator>>,
    pub(crate) processes: Arc<RwLock<HashMap<ProcessId, Weak<BrokerProcess>>>>,
    /// Number of broker threads created and not normally retired.
    pub(crate) active_thread_count: Arc<AtomicUsize>,
    pub(crate) next_reference_handle: Arc<RwLock<u64>>,
    pub(crate) references: Arc<RwLock<HashMap<ObjectHandle, ObjectReference>>>,
    pub(crate) pending_references: Arc<AtomicUsize>,
    pub(crate) reserved_pipe_capacity: Arc<AtomicUsize>,
    pub(crate) reserved_sockets: Arc<AtomicUsize>,
    pub(crate) random_provider: Arc<dyn RandomProvider>,
    pub(crate) stdio_provider: Arc<dyn StdioProvider>,
    pub(crate) socket_provider: Arc<dyn SocketProvider>,
    pub(crate) fs: Arc<dyn FileService>,
    pub(crate) socket_ports: BrokerSocketPorts,
    pub(crate) process_lifecycle_sink: Arc<dyn ProcessLifecycleSink>,
}

static BROKER_CORE_CREATED: AtomicBool = AtomicBool::new(false);

struct NoopProcessLifecycleSink;

impl ProcessLifecycleSink for NoopProcessLifecycleSink {
    fn changed(&self) {}
}

impl BrokerCore {
    /// Creates the broker core with broker-wide service providers.
    pub fn new(
        policy: PolicyEngine,
        socket_provider: Arc<dyn SocketProvider>,
        random_provider: Arc<dyn RandomProvider>,
        stdio_provider: Arc<dyn StdioProvider>,
        fs: Arc<dyn FileService>,
    ) -> Result<Self> {
        Self::new_with_limits(
            policy,
            BrokerCoreLimits::DEFAULT,
            socket_provider,
            random_provider,
            stdio_provider,
            fs,
        )
    }

    /// Creates the broker core with explicit limits and service providers.
    pub fn new_with_limits(
        policy: PolicyEngine,
        limits: BrokerCoreLimits,
        socket_provider: Arc<dyn SocketProvider>,
        random_provider: Arc<dyn RandomProvider>,
        stdio_provider: Arc<dyn StdioProvider>,
        fs: Arc<dyn FileService>,
    ) -> Result<Self> {
        let ids = IdAllocator::new(MAX_ALLOCATED_ID)?;
        BROKER_CORE_CREATED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| BrokerError::BrokerCoreAlreadyExists)?;

        Ok(Self {
            policy: Arc::new(policy),
            limits,
            ids: Arc::new(Mutex::new(ids)),
            processes: Arc::new(RwLock::new(HashMap::new())),
            active_thread_count: Arc::new(AtomicUsize::new(0)),
            next_reference_handle: Arc::new(RwLock::new(1)),
            references: Arc::new(RwLock::new(HashMap::new())),
            pending_references: Arc::new(AtomicUsize::new(0)),
            reserved_pipe_capacity: Arc::new(AtomicUsize::new(0)),
            reserved_sockets: Arc::new(AtomicUsize::new(0)),
            random_provider,
            stdio_provider,
            socket_provider,
            fs,
            socket_ports: BrokerSocketPorts::default(),
            process_lifecycle_sink: Arc::new(NoopProcessLifecycleSink),
        })
    }

    /// Returns a broker handle that publishes process lifecycle changes to `sink`.
    #[must_use]
    pub fn with_process_lifecycle_sink(&self, sink: Arc<dyn ProcessLifecycleSink>) -> Self {
        Self {
            process_lifecycle_sink: sink,
            ..self.clone()
        }
    }

    /// Returns whether any broker process remains registered.
    #[must_use]
    pub fn has_processes(&self) -> bool {
        !self.processes.read().is_empty()
    }

    /// Returns the configured authority-state limits.
    #[must_use]
    pub const fn limits(&self) -> BrokerCoreLimits {
        self.limits
    }

    pub(crate) fn allocate_reference_handle(&self) -> Result<ObjectHandle> {
        let mut next_reference_handle = self.next_reference_handle.write();
        let handle = ObjectHandle(*next_reference_handle);
        *next_reference_handle = handle
            .0
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(handle)
    }

    pub(crate) fn allocate_reference_handle_pair(&self) -> Result<(ObjectHandle, ObjectHandle)> {
        let mut next_reference_handle = self.next_reference_handle.write();
        let first = ObjectHandle(*next_reference_handle);
        let second = ObjectHandle(
            first
                .0
                .checked_add(1)
                .ok_or(BrokerError::ResourceExhausted)?,
        );
        *next_reference_handle = second
            .0
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok((first, second))
    }

    /// Allocates one authenticated process awaiting association activation.
    ///
    /// # Panics
    ///
    /// Panics if the shared ID allocator violates its range or uniqueness
    /// invariants.
    pub(crate) fn create_process(
        &self,
        caller_credential: CallerCredential,
        parent_id: Option<ProcessId>,
    ) -> Result<Arc<BrokerProcess>> {
        let allocate_process = |parent: Option<ProcessParent>, root: Option<Arc<ProcessRoot>>| {
            let mut processes = self.processes.write();
            if processes.len() >= self.limits.max_processes {
                return Err(BrokerError::ResourceExhausted);
            }
            processes
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            let raw_id = self.ids.lock().allocate()?;
            let id = ProcessId(raw_id);
            let process = if let Some(root) = root {
                Arc::new(BrokerProcess::new(
                    self.clone(),
                    id,
                    root,
                    parent,
                    caller_credential,
                ))
            } else {
                assert!(parent.is_none(), "a root process cannot have a parent");
                Arc::new_cyclic(|root_process| {
                    BrokerProcess::new(
                        self.clone(),
                        id,
                        Arc::new(ProcessRoot::new(root_process.clone())),
                        None,
                        caller_credential,
                    )
                })
            };
            assert!(
                processes.insert(id, Arc::downgrade(&process)).is_none(),
                "the ID allocator returned an occupied process ID"
            );
            Ok(process)
        };

        if let Some(parent_id) = parent_id {
            let parent = self
                .processes
                .read()
                .get(&parent_id)
                .and_then(Weak::upgrade)
                .ok_or(BrokerError::UnknownObject)?;
            return parent.with_live_owner(|root| {
                allocate_process(Some(ProcessParent::new(&parent)), Some(root))
            })?;
        }
        allocate_process(None, None)
    }

    /// Allocates one process and its initial thread.
    ///
    /// If initial-thread creation fails, the process is retired before the
    /// error is returned.
    ///
    /// # Panics
    ///
    /// Panics if the shared ID allocator violates its range or uniqueness
    /// invariants.
    pub fn create_process_with_initial_thread(
        &self,
        caller_credential: CallerCredential,
        parent_id: Option<ProcessId>,
    ) -> Result<(Arc<BrokerProcess>, ThreadId)> {
        let process = self.create_process(caller_credential, parent_id)?;
        match process.create_thread() {
            Ok(initial_thread_id) => Ok((process, initial_thread_id)),
            Err(error) => {
                process.retire(true);
                Err(error)
            }
        }
    }
}
