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
mod object;
mod pid_namespace;
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

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use alloc::vec::Vec;
use hashbrown::HashMap;
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use spin::{Mutex, rwlock::RwLock};

pub use error::BrokerError;
use fs::FileService;
use object::ObjectReference;
pub use object::ObjectRights;
pub use pid_namespace::{PidNamespace, PidNamespaceId};
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

/// Every registered process in a PID namespace by ID. A process removes
/// itself when it finally drops.
pub(crate) type ProcessRegistry = RwLock<HashMap<ProcessId, Weak<BrokerProcess>>>;

/// Returns every existing process in `registry`.
pub(crate) fn registered_processes(registry: &ProcessRegistry) -> Vec<Arc<BrokerProcess>> {
    // The registry lock is released before any process can drop, since a
    // final process drop removes itself from the registry.
    let mut processes = registry
        .read()
        .values()
        .filter_map(Weak::upgrade)
        .collect::<Vec<_>>();
    processes.retain(|process| !process.is_released());
    processes
}

/// The broker-wide state that every container shares: the policy, limits and
/// service providers, the object table, the process tree, and the counters
/// behind broker-wide limits.
///
/// A broker process may construct only one kernel for its process lifetime.
/// [`Self::new`] returns [`BrokerError::BrokerKernelAlreadyExists`] if a kernel
/// has already been constructed.
pub struct BrokerKernel {
    pub(crate) policy: PolicyEngine,
    pub(crate) limits: BrokerCoreLimits,
    /// The next [`ProcessKey`] to allocate.
    pub(crate) next_process_key: AtomicU64,
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

static BROKER_KERNEL_CREATED: AtomicBool = AtomicBool::new(false);

impl BrokerKernel {
    /// Creates the broker kernel with broker-wide limits and service providers.
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
        BROKER_KERNEL_CREATED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| BrokerError::BrokerKernelAlreadyExists)?;

        Ok(Arc::new(Self {
            policy,
            limits,
            next_process_key: AtomicU64::new(1),
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
}

/// A container's handle on the [broker kernel](BrokerKernel), which processes
/// hold: a container has its own terminal, process and thread counts, a PID
/// namespace and a file service, either of which other containers may share,
/// and shares the kernel with every other container.
#[derive(Clone)]
pub struct BrokerCore {
    pub(crate) kernel: Arc<BrokerKernel>,
    /// The PID namespace of this handle's container.
    pub(crate) pid_namespace: Arc<PidNamespace>,
    pub(crate) fs: Arc<dyn FileService>,
    pub(crate) container: Arc<Container>,
    pub(crate) process_lifecycle_sink: Arc<dyn ProcessLifecycleSink>,
}

/// The state of one container, which all its handles share.
pub(crate) struct Container {
    /// The container's terminal, which the session of the container's first
    /// root process acquires when that process starts.
    pub(crate) terminal: Mutex<Option<Arc<dyn terminal::TerminalEndpoint>>>,
    /// The container's processes that remain registered.
    processes: AtomicUsize,
    /// The container's threads, which bound its processes' tasks.
    pub(crate) threads: AtomicUsize,
    /// Whether the container is terminating, and so refuses new processes.
    /// Set and read under its PID namespace's registry lock.
    terminating: AtomicBool,
}

struct NoopProcessLifecycleSink;

impl ProcessLifecycleSink for NoopProcessLifecycleSink {
    fn changed(&self) {}
}

impl BrokerCore {
    /// Returns a handle for a new container on `kernel`, whose root processes,
    /// and so all their descendants, are in `pid_namespace` and use `fs`.
    /// Containers that share a namespace see one another's processes.
    ///
    /// `terminal` becomes the controlling terminal of the session of the
    /// container's first root process: the terminal then signals that
    /// session's foreground process group, initially that process's group, and
    /// its members open it as `/dev/tty`.
    #[must_use]
    pub fn new(
        kernel: Arc<BrokerKernel>,
        pid_namespace: Arc<PidNamespace>,
        fs: Arc<dyn FileService>,
        terminal: Option<Arc<dyn terminal::TerminalEndpoint>>,
    ) -> Self {
        Self {
            kernel,
            pid_namespace,
            fs,
            container: Arc::new(Container {
                terminal: Mutex::new(terminal),
                processes: AtomicUsize::new(0),
                threads: AtomicUsize::new(0),
                terminating: AtomicBool::new(false),
            }),
            process_lifecycle_sink: Arc::new(NoopProcessLifecycleSink),
        }
    }

    /// Returns the broker kernel that this container shares.
    #[must_use]
    pub const fn kernel(&self) -> &Arc<BrokerKernel> {
        &self.kernel
    }

    /// Returns the PID namespace of this handle's container.
    #[must_use]
    pub const fn pid_namespace(&self) -> &Arc<PidNamespace> {
        &self.pid_namespace
    }

    /// Returns a handle on this container that publishes process lifecycle
    /// changes to `sink`.
    #[must_use]
    pub fn with_process_lifecycle_sink(&self, sink: Arc<dyn ProcessLifecycleSink>) -> Self {
        Self {
            process_lifecycle_sink: sink,
            ..self.clone()
        }
    }

    /// Returns the process `id` in this view's PID namespace, or
    /// `UnknownObject` if none exists.
    ///
    /// A process whose exit was collected or discarded, or that never started,
    /// no longer exists.
    pub(crate) fn registered_process(&self, id: ProcessId) -> Result<Arc<BrokerProcess>> {
        // The registry lock is released before the process can drop, since a
        // final process drop removes itself from the registry.
        let process = self
            .pid_namespace
            .processes
            .read()
            .get(&id)
            .and_then(Weak::upgrade);
        process
            .filter(|process| !process.is_released())
            .ok_or(BrokerError::UnknownObject)
    }

    /// Returns every existing process in this view's PID namespace.
    pub(crate) fn registered_processes(&self) -> Vec<Arc<BrokerProcess>> {
        registered_processes(&self.pid_namespace.processes)
    }

    /// Returns whether any of this container's processes remains registered,
    /// whatever other containers share its PID namespace.
    #[must_use]
    pub fn has_processes(&self) -> bool {
        self.container.processes.load(Ordering::Acquire) != 0
    }

    /// Terminates this container: it refuses new processes, and the runner
    /// of each of its processes is shut down, as expected, now or once the
    /// runner's termination action is installed.
    ///
    /// Other containers' processes, even in a shared PID namespace, are
    /// unaffected.
    pub fn terminate_container(&self) {
        {
            // Under the registry lock, so every process registered in the
            // container before this is in the snapshot below.
            let _processes = self.pid_namespace.processes.write();
            self.container.terminating.store(true, Ordering::Relaxed);
        }
        for process in self.registered_processes() {
            if Arc::ptr_eq(&process.core.container, &self.container) {
                process.request_expected_shutdown();
            }
        }
    }

    /// Allocates one authenticated process without an initial thread, as a
    /// child of the process `parent_id` if given, in the parent's container,
    /// and otherwise in this one.
    ///
    /// Returns `PeerClosed` if the parent's owner died, the parent exited or
    /// the container is terminating.
    ///
    /// # Panics
    ///
    /// Panics if the shared ID allocator violates its range or uniqueness
    /// invariants.
    pub(crate) fn allocate_process(
        &self,
        caller_credential: CallerCredential,
        parent_id: Option<ProcessId>,
    ) -> Result<Arc<BrokerProcess>> {
        let register_process = |parent: Option<&Arc<BrokerProcess>>| {
            // A child is in its parent's container, whichever handle creates
            // it.
            let core = parent.map_or(self, |parent| &parent.core);
            let mut processes = self.pid_namespace.processes.write();
            if core.container.terminating.load(Ordering::Relaxed) {
                return Err(BrokerError::PeerClosed);
            }
            processes
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            let key = ProcessKey::allocate(&self.kernel.next_process_key)?;
            if let Some(parent) = parent {
                parent.reserve_child()?;
            }
            let raw_id = self.pid_namespace.ids.lock().allocate()?;
            let id = ProcessId(raw_id);
            let process = Arc::new(BrokerProcess::new(
                core.clone(),
                id,
                key,
                parent,
                caller_credential,
            ));
            assert!(
                processes.insert(id, Arc::downgrade(&process)).is_none(),
                "the ID allocator returned an occupied process ID"
            );
            // Until cleanup removes the process from the registry.
            core.container.processes.fetch_add(1, Ordering::Relaxed);
            if let Some(parent) = parent {
                parent.add_child(Arc::clone(&process));
            }
            Ok(process)
        };
        // Counts the process until cleanup removes it from the registry.
        let allocate_process = |parent: Option<&Arc<BrokerProcess>>| {
            self.kernel
                .live_processes
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
                    (live < self.kernel.limits.max_processes).then_some(live + 1)
                })
                .map_err(|_| BrokerError::ResourceExhausted)?;
            let process = register_process(parent);
            if process.is_err() {
                self.kernel.live_processes.fetch_sub(1, Ordering::Relaxed);
            }
            process
        };

        // The tree lock orders the new link against the parent's exit.
        let _tree = self.kernel.process_tree_lock.lock();
        let Some(parent_id) = parent_id else {
            return allocate_process(None);
        };
        let parent = self.registered_process(parent_id)?;
        parent.with_live_owner(|| allocate_process(Some(&parent)))?
    }

    /// Creates one process and its initial thread, as a child of the process
    /// `parent_id` if given, in the parent's container, and otherwise in this
    /// one.
    ///
    /// Returns `PeerClosed` if the parent's owner died, the parent exited or
    /// the container is terminating. If initial-thread creation fails, the
    /// process is discarded before the
    /// error is returned. The first process created in a PID namespace is its
    /// init, and the session of the container's first root process gets the
    /// container's [terminal](Self::new).
    ///
    /// # Panics
    ///
    /// Panics if the shared ID allocator violates its range or uniqueness
    /// invariants.
    pub fn create_process(
        &self,
        caller_credential: CallerCredential,
        parent_id: Option<ProcessId>,
    ) -> Result<Arc<BrokerProcess>> {
        // Roots in a namespace are created one at a time, so the first one
        // registered is the first to start, which makes it init and gives it
        // its container's terminal.
        let roots = parent_id.is_none().then(|| self.pid_namespace.roots.lock());
        let process = self.allocate_process(caller_credential, parent_id)?;
        let started = process.create_initial_thread();
        let terminal = if started.is_ok() && parent_id.is_none() {
            self.pid_namespace.record_init(process.key());
            self.container.terminal.lock().take()
        } else {
            None
        };
        drop(roots);
        match started {
            Ok(()) => {
                if let Some(terminal) = terminal {
                    process_group::acquire(&process, &terminal);
                }
                Ok(process)
            }
            Err(error) => {
                let _ = process.fail_start(error, false, true);
                process.retire(true);
                Err(error)
            }
        }
    }
}
