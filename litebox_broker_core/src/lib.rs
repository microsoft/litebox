// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker authority core independent of protocol envelopes and channels.
//!
//! `litebox_broker_core` owns broker-side object identity, reference lifetime,
//! rights checks, handle validity checks, and policy calls. It may use
//! shared semantic DTOs from `litebox_broker_protocol` for values that both the
//! local core and broker understand, such as handles and readiness state. It
//! deliberately has no dependency on protocol envelopes, channel traits, wire
//! codecs, Unix-socket transports, shared-memory rings, kernel traps, or any
//! other channel implementation.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod channel;
mod error;
pub mod event;
pub mod fs;
mod id;
pub mod job;
mod object;
pub mod pid_namespace;
pub mod pipe;
mod policy;
mod process;
pub mod process_group;
mod pseudo_terminal;
mod quota;
pub mod random;
pub mod readiness;
pub mod readiness_queue;
pub mod shared_futex;
pub mod signal;
pub mod socket;
pub mod stdio;
pub mod terminal;
pub mod timer;
pub mod transfer;
pub mod unix_socket;
pub mod vsock_socket;

#[cfg(test)]
mod test_platform;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use hashbrown::HashMap;
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use spin::{Mutex, rwlock::RwLock};

pub use error::BrokerError;
use fs::FileService;
use job::Job;
use object::ObjectReference;
pub use object::ObjectRights;
use pid_namespace::PidNamespace;
pub use policy::{
    DestinationPortRange, DestinationRule, Ipv4Cidr, MAX_DESTINATION_RULES, PolicyEngine,
    PolicyProfile, SocketPolicy, SocketPolicyError, VsockPolicy, VsockPortRange,
};
pub use process::{
    AssociationCancellation, BrokerProcess, CallerCredential, ChildImage, ProcessImage, ProcessKey,
    ProcessLifecycleSink, ProcessShutdown, ResourceLimitEnforcement,
};
use random::RandomProvider;
use socket::{BrokerSocketPorts, SocketProvider};
use timer::TimerProvider;
use vsock_socket::VsockProvider;

/// BrokerCore result type.
pub type Result<T> = core::result::Result<T, BrokerError>;

/// Broker-wide ceilings and per-process quotas for broker-owned authority state.
///
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BrokerCoreLimits {
    /// Maximum broker processes, across every PID namespace, that have not
    /// completed core teardown.
    pub max_processes: usize,
    /// Maximum live object references across all processes.
    pub max_references: usize,
    /// Maximum live object references owned by one process.
    pub max_references_per_process: usize,
    /// Maximum total capacity in bytes reserved by live pipes across all processes.
    pub max_total_pipe_capacity: usize,
    /// Maximum capacity in bytes reserved by live pipes created by one process.
    pub max_pipe_capacity_per_process: usize,
    /// Maximum total bytes queued in Unix sockets across all processes.
    pub max_total_unix_socket_bytes: usize,
    /// Maximum bytes queued in Unix sockets created by one process.
    pub max_unix_socket_bytes_per_process: usize,
    /// Maximum live platform socket resources across all processes.
    pub max_sockets: usize,
    /// Maximum live platform socket resources charged to one process: those it
    /// creates and those accepted through its listeners.
    pub max_sockets_per_process: usize,
    /// Maximum readiness queue entries across all processes.
    pub max_readiness_queue_entries: usize,
    /// Maximum readiness queue entries added by one process.
    pub max_readiness_queue_entries_per_process: usize,
    /// Maximum live broker-allocated thread IDs.
    pub max_threads: usize,
    /// Maximum live broker-allocated thread IDs owned by one process.
    pub max_threads_per_process: usize,
    /// Maximum size in bytes of one pending child's memory image.
    pub max_child_image_size: u64,
    /// Maximum total size in bytes of child memory images held by the broker.
    pub max_total_child_image_size: u64,
}

impl BrokerCoreLimits {
    /// Conservative default authority-state limits.
    pub const DEFAULT: Self = Self {
        max_processes: 1024,
        max_references: 4096,
        max_references_per_process: 1024,
        max_total_pipe_capacity: 64 * 1024 * 1024,
        max_pipe_capacity_per_process: 16 * 1024 * 1024,
        max_total_unix_socket_bytes: 64 * 1024 * 1024,
        max_unix_socket_bytes_per_process: 16 * 1024 * 1024,
        max_sockets: 1024,
        max_sockets_per_process: 256,
        max_readiness_queue_entries: 16384,
        max_readiness_queue_entries_per_process: 4096,
        max_threads: 4096,
        max_threads_per_process: 1024,
        max_child_image_size: 1024 * 1024 * 1024,
        max_total_child_image_size: 4 * 1024 * 1024 * 1024,
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
            max_total_unix_socket_bytes: Self::DEFAULT.max_total_unix_socket_bytes,
            max_unix_socket_bytes_per_process: Self::DEFAULT.max_unix_socket_bytes_per_process,
            max_sockets: Self::DEFAULT.max_sockets,
            max_sockets_per_process: Self::DEFAULT.max_sockets_per_process,
            max_readiness_queue_entries: Self::DEFAULT.max_readiness_queue_entries,
            max_readiness_queue_entries_per_process: Self::DEFAULT
                .max_readiness_queue_entries_per_process,
            max_threads: Self::DEFAULT.max_threads,
            max_threads_per_process: Self::DEFAULT.max_threads_per_process,
            max_child_image_size: Self::DEFAULT.max_child_image_size,
            max_total_child_image_size: Self::DEFAULT.max_total_child_image_size,
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
            max_total_unix_socket_bytes: Self::DEFAULT.max_total_unix_socket_bytes,
            max_unix_socket_bytes_per_process: Self::DEFAULT.max_unix_socket_bytes_per_process,
            max_sockets,
            max_sockets_per_process,
            max_readiness_queue_entries: Self::DEFAULT.max_readiness_queue_entries,
            max_readiness_queue_entries_per_process: Self::DEFAULT
                .max_readiness_queue_entries_per_process,
            max_threads: Self::DEFAULT.max_threads,
            max_threads_per_process: Self::DEFAULT.max_threads_per_process,
            max_child_image_size: Self::DEFAULT.max_child_image_size,
            max_total_child_image_size: Self::DEFAULT.max_total_child_image_size,
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

    /// Returns these limits with explicit broker-wide and per-process quotas
    /// for bytes queued in Unix sockets.
    ///
    /// A per-process quota above the broker-wide limit is accepted; the
    /// broker-wide limit still applies.
    #[must_use]
    pub const fn with_unix_socket_limits(
        self,
        max_total_unix_socket_bytes: usize,
        max_unix_socket_bytes_per_process: usize,
    ) -> Self {
        Self {
            max_total_unix_socket_bytes,
            max_unix_socket_bytes_per_process,
            ..self
        }
    }

    /// Returns these limits with explicit broker-wide and per-process quotas
    /// for readiness queue entries.
    ///
    /// A per-process quota above the broker-wide limit is accepted; the
    /// broker-wide limit still applies.
    #[must_use]
    pub const fn with_readiness_queue_limits(
        self,
        max_readiness_queue_entries: usize,
        max_readiness_queue_entries_per_process: usize,
    ) -> Self {
        Self {
            max_readiness_queue_entries,
            max_readiness_queue_entries_per_process,
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

    /// Returns these limits with explicit per-child and broker-wide child
    /// memory image size limits.
    ///
    /// A per-child limit above the broker-wide limit is accepted; the
    /// broker-wide limit still applies.
    #[must_use]
    pub const fn with_child_image_size_limits(
        self,
        max_child_image_size: u64,
        max_total_child_image_size: u64,
    ) -> Self {
        Self {
            max_child_image_size,
            max_total_child_image_size,
            ..self
        }
    }
}

impl Default for BrokerCoreLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The broker's kernel: the state that every process shares, whatever its PID
/// namespace, file service or job. It holds the policy, limits and service
/// providers, the object table, the process tree lock, and the counters behind
/// broker-wide limits.
///
/// A broker process may construct only one core for its process lifetime.
/// [`Self::new`] returns [`BrokerError::BrokerCoreAlreadyExists`] if a core has
/// already been constructed.
pub struct BrokerCore {
    pub(crate) policy: PolicyEngine,
    pub(crate) limits: BrokerCoreLimits,
    /// The next [`ProcessKey`] to allocate.
    pub(crate) next_process_key: AtomicU64,
    /// The next [`PidNamespaceId`](pid_namespace::PidNamespaceId) to allocate.
    pub(crate) next_pid_namespace_id: AtomicU64,
    /// Number of processes registered in any PID namespace.
    pub(crate) live_processes: AtomicUsize,
    /// Serializes changes to the process tree, namely parent and child links,
    /// exits and their collection, and process group and session membership,
    /// and selections over it.
    ///
    /// Lock order: a PID namespace's root lock, then this lock, then process
    /// state locks, then a PID namespace's registry and ID allocator, then
    /// process tree nodes.
    pub(crate) process_tree_lock: Arc<Mutex<()>>,
    /// Number of broker threads created and not normally retired.
    pub(crate) active_thread_count: AtomicUsize,
    pub(crate) next_reference_handle: RwLock<u64>,
    pub(crate) references: RwLock<HashMap<ObjectHandle, ObjectReference>>,
    pub(crate) pending_references: AtomicUsize,
    pub(crate) reserved_pipe_capacity: Arc<AtomicUsize>,
    pub(crate) reserved_sockets: Arc<AtomicUsize>,
    pub(crate) readiness_queue_entries: Arc<AtomicUsize>,
    pub(crate) unix_sockets: Arc<unix_socket::UnixSockets>,
    /// Futex wait queues in shared memory, across every process.
    pub(crate) shared_futexes: Arc<shared_futex::SharedFutexes>,
    /// Bytes of child memory images held by the broker.
    pub(crate) reserved_child_image_size: Arc<AtomicU64>,
    pub(crate) random_provider: Arc<dyn RandomProvider>,
    pub(crate) socket_provider: Arc<dyn SocketProvider>,
    pub(crate) vsock_provider: Option<Arc<dyn VsockProvider>>,
    pub(crate) timer_provider: Arc<dyn TimerProvider>,
    pub(crate) socket_ports: BrokerSocketPorts,
}

static BROKER_CORE_CREATED: AtomicBool = AtomicBool::new(false);

impl BrokerCore {
    /// Creates the broker core with broker-wide limits and service providers.
    ///
    /// Without a `vsock_provider`, creating a vsock socket fails as unsupported
    /// before the policy is checked, so it reports `EAFNOSUPPORT` as Linux
    /// without vsock does (a stand-in provider would report `EACCES` first).
    pub fn new(
        policy: PolicyEngine,
        limits: BrokerCoreLimits,
        socket_provider: Arc<dyn SocketProvider>,
        vsock_provider: Option<Arc<dyn VsockProvider>>,
        random_provider: Arc<dyn RandomProvider>,
        timer_provider: Arc<dyn TimerProvider>,
    ) -> Result<Arc<Self>> {
        BROKER_CORE_CREATED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| BrokerError::BrokerCoreAlreadyExists)?;

        Ok(Arc::new(Self {
            policy,
            limits,
            next_process_key: AtomicU64::new(1),
            next_pid_namespace_id: AtomicU64::new(1),
            live_processes: AtomicUsize::new(0),
            process_tree_lock: Arc::new(Mutex::new(())),
            active_thread_count: AtomicUsize::new(0),
            next_reference_handle: RwLock::new(1),
            references: RwLock::new(HashMap::new()),
            pending_references: AtomicUsize::new(0),
            reserved_pipe_capacity: Arc::new(AtomicUsize::new(0)),
            reserved_sockets: Arc::new(AtomicUsize::new(0)),
            readiness_queue_entries: Arc::new(AtomicUsize::new(0)),
            unix_sockets: Arc::new(unix_socket::UnixSockets::new(&limits)),
            shared_futexes: Arc::default(),
            reserved_child_image_size: Arc::new(AtomicU64::new(0)),
            random_provider,
            socket_provider,
            vsock_provider,
            timer_provider,
            socket_ports: BrokerSocketPorts::default(),
        }))
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

    /// Creates a root process, one with no parent, and its initial thread. The
    /// process is in `pid_namespace` and `job` and opens files through `fs`;
    /// its descendants share all three.
    ///
    /// The first process created in a PID namespace is its init. With
    /// `terminal`, the new process's session acquires it as its controlling
    /// terminal: the terminal then signals that session's foreground process
    /// group, initially the new process's group, and its members open it as
    /// `/dev/tty`.
    ///
    /// Returns `PeerClosed` if `job` is terminating. If initial-thread creation
    /// fails, the process is discarded before the error is returned.
    ///
    /// # Panics
    ///
    /// Panics if the namespace's ID allocator violates its range or
    /// uniqueness invariants.
    pub fn create_process(
        self: &Arc<Self>,
        caller_credential: CallerCredential,
        pid_namespace: &Arc<PidNamespace>,
        fs: &Arc<dyn FileService>,
        job: &Arc<Job>,
        terminal: Option<Arc<dyn terminal::TerminalEndpoint>>,
    ) -> Result<Arc<BrokerProcess>> {
        // Roots in a namespace are created one at a time, so the first one
        // registered is the first to start, which makes it init.
        let roots = pid_namespace.roots.lock();
        let process = self.allocate_root(caller_credential, pid_namespace, fs, job)?;
        let started = process.create_initial_thread();
        if started.is_ok() {
            pid_namespace.record_init(process.key());
        }
        drop(roots);
        if let Err(error) = started {
            process.discard(error);
            return Err(error);
        }
        if let Some(terminal) = terminal {
            process_group::acquire(&process, &terminal);
        }
        Ok(process)
    }

    /// Allocates a root process as [`Self::create_process`] does, but
    /// without an initial thread.
    pub(crate) fn allocate_root(
        self: &Arc<Self>,
        caller_credential: CallerCredential,
        pid_namespace: &Arc<PidNamespace>,
        fs: &Arc<dyn FileService>,
        job: &Arc<Job>,
    ) -> Result<Arc<BrokerProcess>> {
        let _tree = self.process_tree_lock.lock();
        self.register_process(caller_credential, pid_namespace, fs, job, None)
    }

    /// Counts and registers one process, without an initial thread, in
    /// `pid_namespace` and `job`, opening files through `fs`. With `parent`,
    /// the process is its child, and `parent` must have the same three.
    ///
    /// The caller holds the process tree lock, which orders a new child link
    /// against the parent's exit. Returns `PeerClosed` if `job` is
    /// terminating.
    pub(crate) fn register_process(
        self: &Arc<Self>,
        caller_credential: CallerCredential,
        pid_namespace: &Arc<PidNamespace>,
        fs: &Arc<dyn FileService>,
        job: &Arc<Job>,
        parent: Option<&Arc<BrokerProcess>>,
    ) -> Result<Arc<BrokerProcess>> {
        // Counts the process until cleanup removes it from the registry.
        self.live_processes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
                (live < self.limits.max_processes).then_some(live + 1)
            })
            .map_err(|_| BrokerError::ResourceExhausted)?;
        let process =
            self.register_counted_process(caller_credential, pid_namespace, fs, job, parent);
        if process.is_err() {
            self.live_processes.fetch_sub(1, Ordering::Relaxed);
        }
        process
    }

    fn register_counted_process(
        self: &Arc<Self>,
        caller_credential: CallerCredential,
        pid_namespace: &Arc<PidNamespace>,
        fs: &Arc<dyn FileService>,
        job: &Arc<Job>,
        parent: Option<&Arc<BrokerProcess>>,
    ) -> Result<Arc<BrokerProcess>> {
        let mut processes = pid_namespace.processes.write();
        processes
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        job.add(|| {
            let key = ProcessKey::allocate(&self.next_process_key)?;
            if let Some(parent) = parent {
                parent.reserve_child()?;
            }
            let id = ProcessId(pid_namespace.ids.lock().allocate()?);
            let process = Arc::new(BrokerProcess::new(
                Arc::clone(self),
                Arc::clone(pid_namespace),
                Arc::clone(fs),
                Arc::clone(job),
                id,
                key,
                parent,
                caller_credential,
            ));
            assert!(
                processes.insert(id, Arc::downgrade(&process)).is_none(),
                "the ID allocator returned an occupied process ID"
            );
            if let Some(parent) = parent {
                parent.add_child(Arc::clone(&process));
            }
            Ok(process)
        })
    }
}
