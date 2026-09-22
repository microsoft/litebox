// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::event::EventObject;
use crate::fs::File;
use crate::pipe::PipeObject;
use crate::socket::SocketObject;
use crate::{BrokerCore, BrokerError, Result};
use hashbrown::HashMap;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::{ObjectHandle, ProcessId, ThreadId};
use spin::{Mutex, rwlock::RwLock};

/// Platform-provided notification destination for broker-process lifecycle changes.
pub trait ProcessLifecycleSink: Send + Sync {
    /// Wakes waiters after authoritative process state changes.
    fn changed(&self);
}

/// Host runner shutdown action installed into a broker process.
pub type ProcessShutdown = Arc<dyn Fn() + Send + Sync>;

/// Stable handle to the initial process in one process tree.
pub(crate) struct ProcessRoot {
    process: Weak<BrokerProcess>,
}

impl ProcessRoot {
    pub(crate) const fn new(process: Weak<BrokerProcess>) -> Self {
        Self { process }
    }

    fn process(&self) -> Option<Arc<BrokerProcess>> {
        self.process.upgrade()
    }
}

/// Caller identity information supplied by the broker entry layer.
///
/// The first userland proof of concept does not authenticate Unix-socket peers,
/// but BrokerCore still accepts an explicit credential value so authenticated
/// servers or hosts can plumb identity through the same process-creation seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CallerCredential {
    /// The trusted broker entry layer authenticated and bound the caller.
    HostGuaranteed,
    /// Explicit deployment mode for the initial unauthenticated userland POC.
    Unauthenticated,
}

/// Cancellation state shared by potentially blocking operations in one broker
/// association.
#[derive(Debug, Default)]
pub struct AssociationCancellation {
    cancelled: AtomicBool,
}

impl AssociationCancellation {
    /// Returns whether the broker association is ending.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

bitflags::bitflags! {
    /// Broker rights attached to an object reference.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct ObjectRights: u32 {
        /// Right to observe or consume object state, including readiness and file reads.
        const WAIT = 1 << 0;
        /// Right to mutate object state, such as file contents or event readiness credits.
        const WRITE = 1 << 1;
    }
}

pub(crate) struct ObjectReference {
    pub(crate) object: Arc<RwLock<ObjectEntry>>,
    pub(crate) owner: ProcessId,
    pub(crate) rights: ObjectRights,
    process_reference_index: usize,
}

pub(crate) enum ObjectEntry {
    Reserved,
    Event(EventObject),
    File(File),
    Pipe(PipeObject),
    Socket(SocketObject),
}

struct ProcessReferences {
    handles: Vec<ObjectHandle>,
    pending_handles: usize,
}

pub(crate) struct ProcessParent {
    process: Weak<BrokerProcess>,
}

impl ProcessParent {
    pub(crate) fn new(process: &Arc<BrokerProcess>) -> Self {
        Self {
            process: Arc::downgrade(process),
        }
    }
}

/// Broker-owned state for one guest thread.
///
/// Execution remains platform-local. This object owns the authoritative
/// broker identity and is the extension point for execution-control state when
/// a broker platform needs to manage thread execution.
pub struct BrokerThread {
    id: ThreadId,
}

impl BrokerThread {
    const fn new(id: ThreadId) -> Self {
        Self { id }
    }

    /// Returns the assigned thread ID.
    #[must_use]
    pub const fn id(&self) -> ThreadId {
        self.id
    }
}

/// Broker-owned state for one authenticated guest process.
///
/// User mode cannot choose the process ID. The broker entry layer authenticates
/// the caller, then [`BrokerCore`] creates and registers this object before
/// serving its association.
pub struct BrokerProcess {
    pub(crate) core: BrokerCore,
    /// Assigned process ID and internal authority.
    pub(crate) id: ProcessId,
    root: Arc<ProcessRoot>,
    state: Mutex<BrokerProcessState>,
    /// Broker-entry-authenticated caller credential for this process.
    pub(crate) caller_credential: CallerCredential,
    /// Handles of the live object references owned by this process.
    references: Mutex<ProcessReferences>,
    /// Authoritative broker threads owned by this process.
    threads: Mutex<HashMap<ThreadId, BrokerThread>>,
    /// Pipe capacity charged to this process by live pipe objects.
    pub(crate) reserved_pipe_capacity: Arc<AtomicUsize>,
    /// Socket quota held by pending, live, and closing in-flight resources.
    pub(crate) reserved_sockets: Arc<AtomicUsize>,
    /// Cancellation state for potentially blocking operations in this process.
    pub(crate) cancellation: AssociationCancellation,
}

struct BrokerProcessState {
    record: ProcessRecordState,
    /// Immediate wait parent; `None` on a non-root means future zombies auto-reap.
    parent: Option<ProcessParent>,
    owner_alive: bool,
    retirement: ProcessRetirement,
    shutdown_request: ProcessShutdownRequest,
    shutdown: Option<ProcessShutdown>,
}

/// Origin of a process entering the starting state.
///
/// Design section 5.2 calls [`Self::Duplication`] `Fork` and
/// [`Self::ImageReplacement`] `Exec`; broker core uses host-neutral names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "later process lifecycle PRs construct these kinds"
    )
)]
pub(crate) enum ProcessStartKind {
    /// Existing runner association startup.
    Association,
    /// Child creation by duplicating an existing process image.
    Duplication,
    /// Child creation by replacing a virtual child's process image.
    ImageReplacement,
}

/// Origin of a request concerning one process record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "later request dispatch PRs consume the origin classification"
    )
)]
pub(crate) enum ProcessRequestOrigin {
    /// Transport or host notification that must be handled in every state.
    Lifecycle,
    /// Operation initiated by guest execution.
    Guest,
}

/// Authoritative lifecycle state of one broker process record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "later process lifecycle PRs construct these states"
    )
)]
pub(crate) enum ProcessRecordState {
    /// Identity reserved, with no host process selected yet.
    Reserved,
    /// Host process setup is in progress.
    Starting(ProcessStartKind),
    /// A virtual child is executing in its owner's address space.
    VirtualRunning,
    /// The process is published and may issue guest-originated operations.
    Running,
    /// Startup failed and host cleanup is still pending.
    Failed(BrokerError),
    /// The process exited and has a waitable status.
    Zombie,
    /// A failed host process has been confirmed dead.
    Collected,
    /// A zombie's waitable status was consumed.
    Reaped,
    /// An unused reservation expired.
    Expired,
}

impl ProcessRecordState {
    /// Returns whether requests from this origin can be considered in this state.
    ///
    /// Guest operations still require operation-specific authorization. This
    /// filter does not model the setup channel's `AcknowledgeInstall`
    /// restriction or the parked-versus-released component of a running child.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "later request dispatch PRs apply the operation-specific checks"
        )
    )]
    fn admits_request_origin(self, origin: ProcessRequestOrigin) -> bool {
        match origin {
            ProcessRequestOrigin::Lifecycle => true,
            ProcessRequestOrigin::Guest => matches!(
                self,
                Self::Starting(_) | Self::VirtualRunning | Self::Running
            ),
        }
    }

    fn transition(&mut self, next: Self) -> Result<()> {
        let allowed = matches!(
            (*self, next),
            (
                Self::Reserved,
                Self::VirtualRunning
                    | Self::Starting(
                        ProcessStartKind::Duplication | ProcessStartKind::ImageReplacement
                    )
                    | Self::Expired,
            ) | (
                Self::Starting(ProcessStartKind::Association | ProcessStartKind::Duplication),
                Self::Running | Self::Failed(_),
            ) | (
                Self::Starting(ProcessStartKind::ImageReplacement),
                Self::Running | Self::VirtualRunning | Self::Zombie,
            ) | (
                Self::VirtualRunning,
                Self::Starting(ProcessStartKind::ImageReplacement) | Self::Zombie,
            ) | (Self::Running, Self::Zombie)
                | (Self::Zombie, Self::Reaped)
                | (Self::Failed(_), Self::Collected)
        );
        if !allowed {
            return Err(BrokerError::Internal);
        }
        *self = next;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessRetirement {
    Active { abnormal: bool },
    Retired { release_ids: bool },
    Cleaned,
}

impl ProcessRetirement {
    fn mark_abnormal(&mut self) {
        match self {
            Self::Active { abnormal } => *abnormal = true,
            Self::Retired { release_ids } => *release_ids = false,
            Self::Cleaned => {}
        }
    }

    fn retire(&mut self, release_ids: bool) {
        let release_ids = match *self {
            Self::Active { abnormal } => release_ids && !abnormal,
            Self::Retired {
                release_ids: current,
            } => current && release_ids,
            Self::Cleaned => return,
        };
        *self = Self::Retired { release_ids };
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessShutdownRequest {
    None,
    Expected,
    Unexpected,
}

impl BrokerProcess {
    /// Creates authenticated broker process state.
    pub(crate) fn new(
        core: BrokerCore,
        id: ProcessId,
        root: Arc<ProcessRoot>,
        parent: Option<ProcessParent>,
        caller_credential: CallerCredential,
    ) -> Self {
        Self {
            core,
            id,
            root,
            state: Mutex::new(BrokerProcessState {
                record: ProcessRecordState::Starting(ProcessStartKind::Association),
                parent,
                owner_alive: true,
                retirement: ProcessRetirement::Active { abnormal: false },
                shutdown_request: ProcessShutdownRequest::None,
                shutdown: None,
            }),
            caller_credential,
            references: Mutex::new(ProcessReferences {
                handles: Vec::new(),
                pending_handles: 0,
            }),
            threads: Mutex::new(HashMap::new()),
            reserved_pipe_capacity: Arc::new(AtomicUsize::new(0)),
            reserved_sockets: Arc::new(AtomicUsize::new(0)),
            cancellation: AssociationCancellation::default(),
        }
    }

    /// Returns the assigned process ID.
    #[must_use]
    pub const fn id(&self) -> ProcessId {
        self.id
    }

    /// Returns the credential authenticated for this process association.
    #[must_use]
    pub const fn caller_credential(&self) -> CallerCredential {
        self.caller_credential
    }

    /// Returns whether this process completed broker startup.
    #[must_use]
    pub fn is_running(&self) -> bool {
        let state = self.state.lock();
        matches!(state.record, ProcessRecordState::Running)
            && matches!(state.retirement, ProcessRetirement::Active { .. })
    }

    /// Returns the completed startup outcome, or `None` while startup is pending.
    pub fn startup_result(&self) -> Option<Result<()>> {
        match self.state.lock().record {
            ProcessRecordState::Reserved | ProcessRecordState::Starting(_) => None,
            ProcessRecordState::Running | ProcessRecordState::VirtualRunning => Some(Ok(())),
            ProcessRecordState::Failed(error) => Some(Err(error)),
            ProcessRecordState::Zombie
            | ProcessRecordState::Collected
            | ProcessRecordState::Reaped
            | ProcessRecordState::Expired => Some(Err(BrokerError::PeerClosed)),
        }
    }

    /// Completes startup after the process association becomes active.
    pub fn complete_start(&self) -> Result<()> {
        {
            let mut state = self.state.lock();
            if !matches!(state.retirement, ProcessRetirement::Active { .. }) {
                return Err(BrokerError::PeerClosed);
            }
            match state.record {
                ProcessRecordState::Starting(_) => {}
                ProcessRecordState::Running => return Err(BrokerError::Internal),
                ProcessRecordState::Failed(error) => return Err(error),
                _ => return Err(BrokerError::PeerClosed),
            }
            state.record.transition(ProcessRecordState::Running)?;
        }
        self.core.process_lifecycle_sink.changed();
        Ok(())
    }

    /// Installs the host runner termination action.
    pub fn install_shutdown(&self, shutdown: ProcessShutdown) {
        let shutdown = {
            let mut state = self.state.lock();
            state.shutdown = Some(Arc::clone(&shutdown));
            (state.shutdown_request != ProcessShutdownRequest::None).then_some(shutdown)
        };
        if let Some(shutdown) = shutdown {
            shutdown();
        }
    }

    /// Fails pending startup and returns the authoritative startup outcome.
    pub fn fail_start(
        &self,
        error: BrokerError,
        abnormal: bool,
        expected_shutdown: bool,
    ) -> Result<()> {
        let shutdown = {
            let mut state = self.state.lock();
            match state.record {
                ProcessRecordState::Starting(
                    ProcessStartKind::Association | ProcessStartKind::Duplication,
                ) => {}
                ProcessRecordState::Starting(ProcessStartKind::ImageReplacement) => {
                    return Err(BrokerError::Internal);
                }
                ProcessRecordState::Running => return Ok(()),
                ProcessRecordState::Failed(error) => return Err(error),
                _ => return Err(BrokerError::PeerClosed),
            }
            if abnormal {
                state.retirement.mark_abnormal();
            }
            state.record.transition(ProcessRecordState::Failed(error))?;
            if state.shutdown_request == ProcessShutdownRequest::None {
                state.shutdown_request = if expected_shutdown {
                    ProcessShutdownRequest::Expected
                } else {
                    ProcessShutdownRequest::Unexpected
                };
            }
            state.shutdown.clone()
        };
        self.core.process_lifecycle_sink.changed();
        if let Some(shutdown) = shutdown {
            shutdown();
        }
        Err(error)
    }

    /// Returns whether the first runner shutdown request was expected.
    #[must_use]
    pub fn shutdown_was_expected(&self) -> bool {
        self.state.lock().shutdown_request == ProcessShutdownRequest::Expected
    }

    /// Marks process retirement as abnormal.
    pub fn mark_abnormal(&self) {
        self.state.lock().retirement.mark_abnormal();
    }

    /// Records final retirement disposition without releasing resources early.
    pub fn retire(&self, release_ids: bool) {
        {
            let mut state = self.state.lock();
            state.retirement.retire(release_ids);
            state.shutdown = None;
        }
    }

    /// Applies owner-death handling to every direct child process.
    ///
    /// Reserved children expire, starting children take their rejecting branch,
    /// virtual children become zombies, and live or zombie children reparent to
    /// the tree root. Zombies are reaped immediately when the root owner is gone.
    pub fn handle_owner_death(self: &Arc<Self>) {
        {
            let mut state = self.state.lock();
            if !state.owner_alive {
                return;
            }
            state.owner_alive = false;
        }
        let processes = {
            let processes = self.core.processes.read();
            processes
                .values()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>()
        };

        let root = self.root.process();
        // Serializing reparenting with the root's owner-death mark prevents a
        // child from being attached to the root after the root's scan passed it.
        let root_state = root.as_ref().map(|root| root.state.lock());
        let live_root = root
            .as_ref()
            .zip(root_state.as_ref())
            .and_then(|(root, state)| {
                (state.owner_alive && matches!(state.retirement, ProcessRetirement::Active { .. }))
                    .then(|| Arc::clone(root))
            });
        let owner = Arc::downgrade(self);
        let mut changed = false;
        let mut shutdowns = Vec::new();
        for child in &processes {
            if !Arc::ptr_eq(&child.root, &self.root)
                || child.id == self.id
                || root.as_ref().is_some_and(|root| Arc::ptr_eq(child, root))
            {
                continue;
            }
            let (child_changed, shutdown) = child.handle_parent_death(&owner, live_root.as_ref());
            changed |= child_changed;
            if let Some(shutdown) = shutdown {
                shutdowns.push(shutdown);
            }
        }
        drop(root_state);
        drop(live_root);
        drop(root);
        drop(processes);
        if changed {
            self.core.process_lifecycle_sink.changed();
        }
        for shutdown in shutdowns {
            shutdown();
        }
    }

    pub(crate) fn with_live_owner<T>(
        &self,
        operation: impl FnOnce(Arc<ProcessRoot>) -> T,
    ) -> Result<T> {
        let state = self.state.lock();
        if !state.owner_alive || !matches!(state.retirement, ProcessRetirement::Active { .. }) {
            return Err(BrokerError::PeerClosed);
        }
        Ok(operation(Arc::clone(&self.root)))
    }

    fn handle_parent_death(
        &self,
        owner: &Weak<BrokerProcess>,
        live_root: Option<&Arc<BrokerProcess>>,
    ) -> (bool, Option<ProcessShutdown>) {
        let mut state = self.state.lock();
        if !state
            .parent
            .as_ref()
            .is_some_and(|parent| Weak::ptr_eq(&parent.process, owner))
        {
            return (false, None);
        }

        let mut shutdown = None;
        let reparent = match state.record {
            ProcessRecordState::Reserved => {
                state
                    .record
                    .transition(ProcessRecordState::Expired)
                    .expect("reserved child expiration must be a valid transition");
                false
            }
            ProcessRecordState::Starting(
                ProcessStartKind::Association | ProcessStartKind::Duplication,
            ) => {
                state
                    .record
                    .transition(ProcessRecordState::Failed(BrokerError::PeerClosed))
                    .expect("starting child rejection must be a valid transition");
                if state.shutdown_request == ProcessShutdownRequest::None {
                    state.shutdown_request = ProcessShutdownRequest::Expected;
                }
                shutdown.clone_from(&state.shutdown);
                false
            }
            ProcessRecordState::Starting(ProcessStartKind::ImageReplacement) => {
                state
                    .record
                    .transition(ProcessRecordState::Zombie)
                    .expect("image replacement rejection must create a zombie");
                if state.shutdown_request == ProcessShutdownRequest::None {
                    state.shutdown_request = ProcessShutdownRequest::Expected;
                }
                shutdown.clone_from(&state.shutdown);
                true
            }
            ProcessRecordState::VirtualRunning => {
                state
                    .record
                    .transition(ProcessRecordState::Zombie)
                    .expect("virtual child owner death must create a zombie");
                true
            }
            ProcessRecordState::Running | ProcessRecordState::Zombie => true,
            ProcessRecordState::Failed(_)
            | ProcessRecordState::Collected
            | ProcessRecordState::Reaped
            | ProcessRecordState::Expired => return (false, None),
        };

        if reparent {
            state.parent = live_root.map(ProcessParent::new);
            if live_root.is_none() && state.record == ProcessRecordState::Zombie {
                state
                    .record
                    .transition(ProcessRecordState::Reaped)
                    .expect("orphaned zombie reaping must be a valid transition");
            }
        }
        (true, shutdown)
    }

    /// Duplicates object references into another process.
    ///
    /// Each duplicate retains its source reference's rights. Returned handles
    /// follow the requested source order. If duplication fails, references
    /// already created by this call are removed from the target before the
    /// error is returned.
    pub fn duplicate_object_references_to(
        &self,
        handles: &[ObjectHandle],
        target: &BrokerProcess,
    ) -> Result<Vec<ObjectHandle>> {
        let mut duplicates = Vec::new();
        duplicates
            .try_reserve_exact(handles.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        for handle in handles {
            let duplicate = self
                .object_reference_rights(*handle)
                .and_then(|rights| self.duplicate_object_reference_to(*handle, target, rights));
            match duplicate {
                Ok(duplicate) => duplicates.push(duplicate),
                Err(error) => {
                    for duplicate in duplicates.drain(..).rev() {
                        if target.close_object_reference(duplicate).is_err() {
                            return Err(BrokerError::Internal);
                        }
                    }
                    return Err(error);
                }
            }
        }
        Ok(duplicates)
    }

    /// Creates a broker thread belonging to this process.
    ///
    /// # Panics
    ///
    /// Panics if the shared ID allocator violates its range or uniqueness
    /// invariants.
    pub fn create_thread(&self) -> Result<ThreadId> {
        let mut threads = self.threads.lock();
        if threads.len() >= self.core.limits.max_threads_per_process {
            return Err(BrokerError::ResourceExhausted);
        }
        threads
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        self.core
            .active_thread_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < self.core.limits.max_threads).then(|| count + 1)
            })
            .map_err(|_| BrokerError::ResourceExhausted)?;
        let raw_id = match self.core.ids.lock().allocate() {
            Ok(id) => id,
            Err(error) => {
                self.core
                    .active_thread_count
                    .fetch_sub(1, Ordering::Relaxed);
                return Err(error);
            }
        };
        let thread = BrokerThread::new(ThreadId(raw_id));
        let thread_id = thread.id();
        assert!(
            threads.insert(thread_id, thread).is_none(),
            "the ID allocator returned an occupied thread ID"
        );
        Ok(thread_id)
    }

    /// Records broker thread exit after its local task teardown completes.
    pub fn exit_thread(&self, thread_id: ThreadId) -> Result<()> {
        let mut threads = self.threads.lock();
        let thread = threads
            .remove(&thread_id)
            .ok_or(BrokerError::UnknownObject)?;
        drop(threads);
        self.core
            .active_thread_count
            .fetch_sub(1, Ordering::Relaxed);
        self.core.ids.lock().release(thread.id().0);
        Ok(())
    }

    /// Requests cooperative cancellation of potentially blocking operations
    /// because this association is ending.
    pub fn request_cancellation(&self) {
        self.cancellation.cancel();
    }

    /// Returns whether association teardown requested cancellation.
    #[must_use]
    pub fn is_cancellation_requested(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub(crate) fn create_object_reference(&self, object: ObjectEntry) -> Result<ObjectHandle> {
        let rights = self
            .core
            .policy
            .principal_object_rights(self.caller_credential)?;
        let object = Arc::new(RwLock::new(object));
        self.create_object_reference_with_rights(object, rights)
    }

    fn create_object_reference_with_rights(
        &self,
        object: Arc<RwLock<ObjectEntry>>,
        rights: ObjectRights,
    ) -> Result<ObjectHandle> {
        let mut process_references = self.references.lock();
        self.prepare_process_references(&mut process_references, 1)?;
        let mut references = self.core.references.write();
        let preparation = (|| {
            let pending = self.core.pending_references.load(Ordering::Relaxed);
            if references
                .len()
                .checked_add(pending)
                .is_none_or(|count| count >= self.core.limits.max_references)
            {
                return Err(BrokerError::ResourceExhausted);
            }
            references
                .try_reserve(
                    pending
                        .checked_add(1)
                        .ok_or(BrokerError::ResourceExhausted)?,
                )
                .map_err(|_| BrokerError::OutOfMemory)?;
            let handle = self.core.allocate_reference_handle()?;
            if references.contains_key(&handle) {
                return Err(BrokerError::Internal);
            }
            Ok(handle)
        })();
        let handle = match preparation {
            Ok(handle) => handle,
            Err(error) => {
                drop(references);
                drop(process_references);
                return Err(error);
            }
        };
        self.insert_object_reference(
            &mut references,
            &mut process_references.handles,
            handle,
            object,
            rights,
        );

        Ok(handle)
    }

    /// Duplicates a supported object reference into another process.
    ///
    /// The returned handle is owned by `target` and refers to the same
    /// underlying event, file, or pipe endpoint. `rights` must be nonempty, allowed by
    /// the target's policy, and no broader than the source reference's rights.
    /// The source reference is unchanged. Socket references are not supported
    /// because their readiness registration is currently bound to one process
    /// and handle.
    ///
    /// Pipe capacity remains charged to the process that created the pipe.
    /// Child creation must call this operation explicitly according to the
    /// guest operating system's inheritance semantics.
    pub fn duplicate_object_reference_to(
        &self,
        handle: ObjectHandle,
        target: &BrokerProcess,
        rights: ObjectRights,
    ) -> Result<ObjectHandle> {
        if rights.is_empty() {
            return Err(BrokerError::InvalidRights);
        }

        let object = {
            let references = self.core.references.read();
            let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
            if reference.owner != self.id {
                return Err(BrokerError::UnknownObject);
            }
            if !reference.rights.contains(rights) {
                return Err(BrokerError::InvalidRights);
            }
            Arc::clone(&reference.object)
        };

        {
            let object = object.read();
            match &*object {
                ObjectEntry::Event(_) | ObjectEntry::File(_) | ObjectEntry::Pipe(_) => {}
                ObjectEntry::Socket(_) => return Err(BrokerError::UnsupportedOperation),
                ObjectEntry::Reserved => return Err(BrokerError::Internal),
            }
        }

        let target_rights = target
            .core
            .policy
            .principal_object_rights(target.caller_credential)?;
        if !target_rights.contains(rights) {
            return Err(BrokerError::PolicyDenied);
        }
        target.create_object_reference_with_rights(object, rights)
    }

    fn object_reference_rights(&self, handle: ObjectHandle) -> Result<ObjectRights> {
        let references = self.core.references.read();
        let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
        if reference.owner != self.id {
            return Err(BrokerError::UnknownObject);
        }
        Ok(reference.rights)
    }

    pub(crate) fn create_object_reference_pair(
        &self,
        first: ObjectEntry,
        second: ObjectEntry,
    ) -> Result<(ObjectHandle, ObjectHandle)> {
        let rights = self
            .core
            .policy
            .principal_object_rights(self.caller_credential)?;
        let first = Arc::new(RwLock::new(first));
        let second = Arc::new(RwLock::new(second));
        let mut process_references = self.references.lock();
        self.prepare_process_references(&mut process_references, 2)?;
        let mut references = self.core.references.write();
        let preparation = (|| {
            let pending = self.core.pending_references.load(Ordering::Relaxed);
            if references
                .len()
                .checked_add(pending)
                .and_then(|count| count.checked_add(2))
                .is_none_or(|count| count > self.core.limits.max_references)
            {
                return Err(BrokerError::ResourceExhausted);
            }
            references
                .try_reserve(
                    pending
                        .checked_add(2)
                        .ok_or(BrokerError::ResourceExhausted)?,
                )
                .map_err(|_| BrokerError::OutOfMemory)?;
            let (first_handle, second_handle) = self.core.allocate_reference_handle_pair()?;
            if first_handle == second_handle
                || references.contains_key(&first_handle)
                || references.contains_key(&second_handle)
            {
                return Err(BrokerError::Internal);
            }
            Ok((first_handle, second_handle))
        })();
        let (first_handle, second_handle) = match preparation {
            Ok(handles) => handles,
            Err(error) => {
                drop(references);
                drop(process_references);
                return Err(error);
            }
        };
        for (handle, object) in [(first_handle, first), (second_handle, second)] {
            self.insert_object_reference(
                &mut references,
                &mut process_references.handles,
                handle,
                object,
                rights,
            );
        }
        Ok((first_handle, second_handle))
    }

    pub(crate) fn reserve_object_reference(
        &self,
        rights: ObjectRights,
    ) -> Result<PendingObjectReference<'_>> {
        let object = Arc::new(RwLock::new(ObjectEntry::Reserved));
        let mut process_references = self.references.lock();
        let next_process_pending = self.prepare_process_references(&mut process_references, 1)?;
        let mut references = self.core.references.write();
        let pending_references = self.core.pending_references.load(Ordering::Relaxed);
        if references
            .len()
            .checked_add(pending_references)
            .is_none_or(|count| count >= self.core.limits.max_references)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        let handle = self.core.allocate_reference_handle()?;
        if references.contains_key(&handle) {
            return Err(BrokerError::Internal);
        }
        references
            .try_reserve(
                pending_references
                    .checked_add(1)
                    .ok_or(BrokerError::ResourceExhausted)?,
            )
            .map_err(|_| BrokerError::OutOfMemory)?;
        self.core
            .pending_references
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |pending| {
                pending.checked_add(1)
            })
            .map_err(|_| BrokerError::ResourceExhausted)?;
        process_references.pending_handles = next_process_pending;
        Ok(PendingObjectReference {
            process: self,
            handle,
            rights,
            object,
            active: true,
        })
    }

    fn prepare_process_references(
        &self,
        process_references: &mut ProcessReferences,
        additional: usize,
    ) -> Result<usize> {
        let pending_and_additional = process_references
            .pending_handles
            .checked_add(additional)
            .ok_or(BrokerError::ResourceExhausted)?;
        if process_references
            .handles
            .len()
            .checked_add(pending_and_additional)
            .is_none_or(|count| count > self.core.limits.max_references_per_process)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        process_references
            .handles
            .try_reserve(pending_and_additional)
            .map_err(|_| BrokerError::OutOfMemory)?;
        Ok(pending_and_additional)
    }

    fn insert_object_reference(
        &self,
        references: &mut HashMap<ObjectHandle, ObjectReference>,
        reference_handles: &mut Vec<ObjectHandle>,
        handle: ObjectHandle,
        object: Arc<RwLock<ObjectEntry>>,
        rights: ObjectRights,
    ) {
        let process_reference_index = reference_handles.len();
        references.insert(
            handle,
            ObjectReference {
                object,
                owner: self.id,
                rights,
                process_reference_index,
            },
        );
        reference_handles.push(handle);
    }

    /// Returns an authorized object lease without holding the reference-table lock.
    ///
    /// Callers explicitly choose the object-lock lifetime. Socket operations use
    /// that control to release all broker locks before calling an external
    /// platform implementation, then reacquire only the object lock if they need
    /// to update broker-owned state.
    pub(crate) fn authorized_object(
        &self,
        handle: ObjectHandle,
        required_rights: ObjectRights,
    ) -> Result<Arc<RwLock<ObjectEntry>>> {
        let references = self.core.references.read();
        let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
        if reference.owner != self.id {
            return Err(BrokerError::UnknownObject);
        }
        if !reference.rights.contains(required_rights) {
            return Err(BrokerError::InvalidRights);
        }
        Ok(Arc::clone(&reference.object))
    }

    pub(crate) fn authorized_object_with_any_rights(
        &self,
        handle: ObjectHandle,
        allowed_rights: ObjectRights,
    ) -> Result<Arc<RwLock<ObjectEntry>>> {
        debug_assert!(!allowed_rights.is_empty());
        let references = self.core.references.read();
        let reference = references.get(&handle).ok_or(BrokerError::UnknownObject)?;
        if reference.owner != self.id {
            return Err(BrokerError::UnknownObject);
        }
        if !reference.rights.intersects(allowed_rights) {
            return Err(BrokerError::InvalidRights);
        }
        Ok(Arc::clone(&reference.object))
    }

    /// Returns the current readiness of a broker-owned object.
    pub fn check_readiness(&self, handle: ObjectHandle) -> Result<ReadinessFlags> {
        let object = self.authorized_object(handle, ObjectRights::WAIT)?;
        let socket = {
            let object = object.read();
            match &*object {
                ObjectEntry::Event(event) => return Ok(event.readiness()),
                ObjectEntry::File(_) => return Err(BrokerError::InvalidRights),
                ObjectEntry::Pipe(pipe) => return Ok(pipe.readiness()),
                ObjectEntry::Socket(socket) => socket.resource(),
                ObjectEntry::Reserved => return Err(BrokerError::Internal),
            }
        };
        Ok(socket.readiness())
    }

    /// Closes one object reference owned by this process.
    ///
    /// The underlying object is released when this was the last live reference.
    /// Destruction happens after releasing the process-wide reference-table
    /// lock, so an object may safely release platform resources.
    pub fn close_object_reference(&self, handle: ObjectHandle) -> Result<()> {
        let reference = self.remove_object_reference(handle)?;
        drop(reference);
        Ok(())
    }

    fn remove_object_reference(&self, handle: ObjectHandle) -> Result<ObjectReference> {
        let mut process_references = self.references.lock();
        let reference_handles = &mut process_references.handles;
        let mut references = self.core.references.write();
        let reference = references
            .remove(&handle)
            .ok_or(BrokerError::UnknownObject)?;
        let index = reference.process_reference_index;
        // Keep fallible validation in a nested scope so `?` and early returns
        // reach the shared rollback below instead of dropping the removed
        // reference while either reference-index lock is held.
        let removal_result = (|| {
            if reference.owner != self.id {
                return Err(BrokerError::UnknownObject);
            }
            if reference_handles.get(index) != Some(&handle) {
                return Err(BrokerError::Internal);
            }
            let last_index = reference_handles
                .len()
                .checked_sub(1)
                .ok_or(BrokerError::Internal)?;
            if index != last_index {
                let moved_handle = *reference_handles
                    .get(last_index)
                    .ok_or(BrokerError::Internal)?;
                let moved_reference = references
                    .get_mut(&moved_handle)
                    .ok_or(BrokerError::Internal)?;
                if moved_reference.owner != self.id
                    || moved_reference.process_reference_index != last_index
                {
                    return Err(BrokerError::Internal);
                }
                moved_reference.process_reference_index = index;
            }
            reference_handles.swap_remove(index);
            Ok(())
        })();

        if let Err(error) = removal_result {
            let replaced_reference = references.insert(handle, reference);
            drop(references);
            drop(process_references);
            if replaced_reference.is_some() {
                return Err(BrokerError::Internal);
            }
            return Err(error);
        }
        Ok(reference)
    }

    /// Cleans up this process, optionally releasing its numeric IDs for reuse.
    ///
    /// Set `release_ids` only after fully accounted teardown. Final process
    /// drop otherwise retains IDs after an unwind or uncertain retirement.
    /// Calling this method more than once is harmless.
    pub fn cleanup(&self, release_ids: bool) {
        let release_ids = {
            let mut state = self.state.lock();
            let release_ids = match state.retirement {
                ProcessRetirement::Active { abnormal } => release_ids && !abnormal,
                ProcessRetirement::Retired {
                    release_ids: decided,
                } => release_ids && decided,
                ProcessRetirement::Cleaned => return,
            };
            state.retirement = ProcessRetirement::Cleaned;
            release_ids
        };

        let mut invariant_fault = self.references.lock().pending_handles != 0;
        loop {
            let Some(handle) = self.references.lock().handles.pop() else {
                break;
            };
            // Do not restore an inconsistent handle: retrying it forever would
            // prevent later valid references from being released.
            let reference = {
                let mut references = self.core.references.write();
                let Some(reference) = references.get(&handle) else {
                    invariant_fault = true;
                    continue;
                };
                if reference.owner != self.id {
                    invariant_fault = true;
                    continue;
                }
                let Some(reference) = references.remove(&handle) else {
                    invariant_fault = true;
                    continue;
                };
                reference
            };
            // Object destruction may release platform resources and must never
            // run while either reference index lock is held.
            drop(reference);
        }

        loop {
            let stale = {
                let references = self.core.references.read();
                references
                    .iter()
                    .find_map(|(handle, reference)| (reference.owner == self.id).then_some(*handle))
            };
            let Some(handle) = stale else {
                break;
            };
            invariant_fault = true;
            let reference = self.core.references.write().remove(&handle);
            drop(reference);
        }
        debug_assert!(
            !self
                .core
                .references
                .read()
                .values()
                .any(|reference| reference.owner == self.id)
        );

        self.core.socket_provider.close_process(self.id);

        if self.core.processes.write().remove(&self.id).is_none() {
            invariant_fault = true;
        }

        let threads = core::mem::take(&mut *self.threads.lock());
        if release_ids && !invariant_fault {
            self.core
                .active_thread_count
                .fetch_sub(threads.len(), Ordering::Relaxed);
            let mut ids = self.core.ids.lock();
            for thread in threads.into_values() {
                ids.release(thread.id().0);
            }
            ids.release(self.id.0);
        }
        self.core.process_lifecycle_sink.changed();
    }
}

pub(crate) struct PendingObjectReference<'process> {
    process: &'process BrokerProcess,
    handle: ObjectHandle,
    rights: ObjectRights,
    object: Arc<RwLock<ObjectEntry>>,
    active: bool,
}

impl PendingObjectReference<'_> {
    pub(crate) const fn handle(&self) -> ObjectHandle {
        self.handle
    }

    pub(crate) fn commit(mut self, object: ObjectEntry) -> Result<ObjectHandle> {
        if !matches!(&*self.object.read(), ObjectEntry::Reserved) {
            return Err(BrokerError::Internal);
        }
        let mut process_references = self.process.references.lock();
        let mut references = self.process.core.references.write();
        if references.contains_key(&self.handle) {
            drop(references);
            drop(process_references);
            return Err(BrokerError::Internal);
        }
        if !release_pending_reference(
            &self.process.core.pending_references,
            &mut process_references,
        ) {
            self.active = false;
            drop(references);
            drop(process_references);
            return Err(BrokerError::Internal);
        }
        self.active = false;
        *self.object.write() = object;
        self.process.insert_object_reference(
            &mut references,
            &mut process_references.handles,
            self.handle,
            Arc::clone(&self.object),
            self.rights,
        );
        Ok(self.handle)
    }
}

impl Drop for PendingObjectReference<'_> {
    fn drop(&mut self) {
        if self.active {
            let mut process_references = self.process.references.lock();
            let released = release_pending_reference(
                &self.process.core.pending_references,
                &mut process_references,
            );
            self.active = false;
            assert!(
                released,
                "pending object reference counters are inconsistent"
            );
        }
    }
}

fn release_pending_reference(
    core_pending_references: &AtomicUsize,
    process_references: &mut ProcessReferences,
) -> bool {
    let next_pending_handles = process_references.pending_handles.checked_sub(1);
    let core_released = core_pending_references
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |pending| {
            pending.checked_sub(1)
        })
        .is_ok();
    if let Some(next_pending_handles) = next_pending_handles {
        process_references.pending_handles = next_pending_handles;
    }
    next_pending_handles.is_some() && core_released
}

impl Drop for BrokerProcess {
    fn drop(&mut self) {
        let release_ids = {
            let state = self.state.lock();
            matches!(
                state.retirement,
                ProcessRetirement::Retired { release_ids: true }
            )
        };
        self.cleanup(release_ids);
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{
        BrokerProcess, ProcessLifecycleSink, ProcessRecordState, ProcessReferences,
        ProcessRequestOrigin, ProcessStartKind, release_pending_reference,
    };
    use crate::test_platform::TestPlatform;
    use crate::test_support::{TestBrokerCoreBuilder, TestStdioProvider};
    use crate::{
        BrokerCore, BrokerCoreLimits, BrokerError, CallerCredential, ObjectRights, PolicyEngine,
        SocketPolicy,
    };
    use litebox_broker_protocol::event::{EventConsumeMode, EventConsumption};
    use litebox_broker_protocol::fs::{
        FileAccessMode, FileError, FileMode, FileOpenFlags, FileSeekWhence, FileType, FileUser,
    };
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::stdio::StdioOutputStream;
    use litebox_broker_protocol::{ObjectHandle, ProcessId};
    use std::{sync::Arc, vec, vec::Vec};

    const TEST_MAX_REFERENCES: usize = 4;
    const TEST_MAX_PIPE_CAPACITY: usize = 8;
    const TEST_MAX_REFERENCES_PER_PROCESS: usize = 2;
    const TEST_MAX_PIPE_CAPACITY_PER_PROCESS: usize = 4;
    const ROOT: FileUser = FileUser { user: 0, group: 0 };

    #[derive(Default)]
    struct TestProcessLifecycleSink {
        changes: AtomicUsize,
    }

    impl ProcessLifecycleSink for TestProcessLifecycleSink {
        fn changed(&self) {
            self.changes.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn parent_id(process: &BrokerProcess) -> Option<ProcessId> {
        process
            .state
            .lock()
            .parent
            .as_ref()
            .and_then(|parent| parent.process.upgrade())
            .map(|parent| parent.id())
    }

    fn process_record_states() -> [ProcessRecordState; 11] {
        use ProcessRecordState as State;
        use ProcessStartKind as Start;

        [
            State::Reserved,
            State::Starting(Start::Association),
            State::Starting(Start::Duplication),
            State::Starting(Start::ImageReplacement),
            State::VirtualRunning,
            State::Running,
            State::Failed(BrokerError::PeerClosed),
            State::Zombie,
            State::Collected,
            State::Reaped,
            State::Expired,
        ]
    }

    #[test]
    fn process_record_state_transition_matrix() {
        use ProcessRecordState as State;
        use ProcessStartKind as Start;

        let failed = State::Failed(BrokerError::PeerClosed);
        let states = process_record_states();
        let allowed = [
            (State::Reserved, State::VirtualRunning),
            (State::Reserved, State::Starting(Start::Duplication)),
            (State::Reserved, State::Starting(Start::ImageReplacement)),
            (State::Reserved, State::Expired),
            (State::Starting(Start::Association), State::Running),
            (State::Starting(Start::Association), failed),
            (State::Starting(Start::Duplication), State::Running),
            (State::Starting(Start::Duplication), failed),
            (State::Starting(Start::ImageReplacement), State::Running),
            (
                State::Starting(Start::ImageReplacement),
                State::VirtualRunning,
            ),
            (State::Starting(Start::ImageReplacement), State::Zombie),
            (
                State::VirtualRunning,
                State::Starting(Start::ImageReplacement),
            ),
            (State::VirtualRunning, State::Zombie),
            (State::Running, State::Zombie),
            (State::Zombie, State::Reaped),
            (failed, State::Collected),
        ];

        for initial in states {
            for next in states {
                let expected = allowed.contains(&(initial, next));
                let mut current = initial;
                assert_eq!(
                    current.transition(next).is_ok(),
                    expected,
                    "{initial:?} -> {next:?}"
                );
                assert_eq!(current, if expected { next } else { initial });
            }
        }
    }

    #[test]
    fn request_origin_classification_preserves_lifecycle_notifications() {
        use ProcessRecordState as State;
        use ProcessRequestOrigin as Origin;

        for state in process_record_states() {
            assert!(state.admits_request_origin(Origin::Lifecycle), "{state:?}");
            assert_eq!(
                state.admits_request_origin(Origin::Guest),
                matches!(
                    state,
                    State::Starting(_) | State::VirtualRunning | State::Running
                ),
                "{state:?}"
            );
        }
    }

    #[test]
    fn generic_startup_failure_rejects_image_replacement() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        process.state.lock().record =
            ProcessRecordState::Starting(ProcessStartKind::ImageReplacement);

        assert_eq!(
            process.fail_start(BrokerError::PeerClosed, false, true),
            Err(BrokerError::Internal)
        );
        assert_eq!(
            process.state.lock().record,
            ProcessRecordState::Starting(ProcessStartKind::ImageReplacement)
        );
    }

    #[test]
    fn process_and_thread_ids_share_one_numeric_namespace() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let first = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let thread = first.create_thread().unwrap();
        let second = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();

        assert_eq!(first.id().0, 1);
        assert_eq!(thread.0, 2);
        assert_eq!(second.id().0, 3);
    }

    #[test]
    fn parent_teardown_fails_a_starting_child() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let parent = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        parent.complete_start().unwrap();
        let child = broker
            .create_process(parent.caller_credential(), Some(parent.id()))
            .unwrap();
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let shutdown_count = Arc::clone(&shutdowns);
        child.install_shutdown(Arc::new(move || {
            shutdown_count.fetch_add(1, Ordering::Relaxed);
        }));

        parent.handle_owner_death();

        assert_eq!(parent_id(&child), Some(parent.id()));
        assert_eq!(child.startup_result(), Some(Err(BrokerError::PeerClosed)));
        assert_eq!(child.complete_start(), Err(BrokerError::PeerClosed));
        assert_eq!(shutdowns.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn owner_death_reparents_live_and_zombie_children_to_the_tree_root() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let root = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        let parent = broker
            .create_process(CallerCredential::Unauthenticated, Some(root.id()))
            .unwrap();
        parent.complete_start().unwrap();

        let running = broker
            .create_process(CallerCredential::Unauthenticated, Some(parent.id()))
            .unwrap();
        running.complete_start().unwrap();
        let zombie = broker
            .create_process(CallerCredential::Unauthenticated, Some(parent.id()))
            .unwrap();
        zombie.complete_start().unwrap();
        zombie
            .state
            .lock()
            .record
            .transition(ProcessRecordState::Zombie)
            .unwrap();
        let virtual_child = broker
            .create_process(CallerCredential::Unauthenticated, Some(parent.id()))
            .unwrap();
        virtual_child.state.lock().record = ProcessRecordState::VirtualRunning;
        let reserved = broker
            .create_process(CallerCredential::Unauthenticated, Some(parent.id()))
            .unwrap();
        reserved.state.lock().record = ProcessRecordState::Reserved;

        parent.handle_owner_death();

        assert!(!parent.state.lock().owner_alive);
        assert_eq!(parent_id(&running), Some(root.id()));
        assert_eq!(running.state.lock().record, ProcessRecordState::Running);
        assert_eq!(parent_id(&zombie), Some(root.id()));
        assert_eq!(zombie.state.lock().record, ProcessRecordState::Zombie);
        assert_eq!(parent_id(&virtual_child), Some(root.id()));
        assert_eq!(
            virtual_child.state.lock().record,
            ProcessRecordState::Zombie
        );
        assert_eq!(reserved.state.lock().record, ProcessRecordState::Expired);
        assert!(matches!(
            broker.create_process(CallerCredential::Unauthenticated, Some(parent.id())),
            Err(BrokerError::PeerClosed)
        ));
    }

    #[test]
    fn root_owner_death_auto_reaps_orphaned_zombies() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let root = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();

        let running = broker
            .create_process(CallerCredential::Unauthenticated, Some(root.id()))
            .unwrap();
        running.complete_start().unwrap();
        let zombie = broker
            .create_process(CallerCredential::Unauthenticated, Some(root.id()))
            .unwrap();
        zombie.complete_start().unwrap();
        zombie
            .state
            .lock()
            .record
            .transition(ProcessRecordState::Zombie)
            .unwrap();
        let virtual_child = broker
            .create_process(CallerCredential::Unauthenticated, Some(root.id()))
            .unwrap();
        virtual_child.state.lock().record = ProcessRecordState::VirtualRunning;
        let replacing = broker
            .create_process(CallerCredential::Unauthenticated, Some(root.id()))
            .unwrap();
        replacing.state.lock().record =
            ProcessRecordState::Starting(ProcessStartKind::ImageReplacement);
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let shutdown_count = Arc::clone(&shutdowns);
        replacing.install_shutdown(Arc::new(move || {
            shutdown_count.fetch_add(1, Ordering::Relaxed);
        }));

        root.handle_owner_death();

        assert_eq!(parent_id(&running), None);
        assert_eq!(running.state.lock().record, ProcessRecordState::Running);
        assert_eq!(parent_id(&zombie), None);
        assert_eq!(zombie.state.lock().record, ProcessRecordState::Reaped);
        assert_eq!(parent_id(&virtual_child), None);
        assert_eq!(
            virtual_child.state.lock().record,
            ProcessRecordState::Reaped
        );
        assert_eq!(parent_id(&replacing), None);
        assert_eq!(replacing.state.lock().record, ProcessRecordState::Reaped);
        assert_eq!(shutdowns.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn later_owner_death_observes_that_the_tree_root_is_gone() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let root = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        let parent = broker
            .create_process(CallerCredential::Unauthenticated, Some(root.id()))
            .unwrap();
        parent.complete_start().unwrap();
        let child = broker
            .create_process(CallerCredential::Unauthenticated, Some(parent.id()))
            .unwrap();
        child.complete_start().unwrap();
        child
            .state
            .lock()
            .record
            .transition(ProcessRecordState::Zombie)
            .unwrap();

        root.handle_owner_death();
        parent.handle_owner_death();

        assert_eq!(parent_id(&parent), None);
        assert_eq!(parent_id(&child), None);
        assert_eq!(child.state.lock().record, ProcessRecordState::Reaped);
    }

    #[test]
    fn recycled_root_process_id_does_not_resurrect_the_root_within_its_tree() {
        let mut broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        broker.ids =
            alloc::sync::Arc::new(spin::Mutex::new(crate::id::IdAllocator::new(3).unwrap()));
        let root = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        let parent = broker
            .create_process(CallerCredential::Unauthenticated, Some(root.id()))
            .unwrap();
        parent.complete_start().unwrap();
        let zombie = broker
            .create_process(CallerCredential::Unauthenticated, Some(parent.id()))
            .unwrap();
        zombie.complete_start().unwrap();
        zombie
            .state
            .lock()
            .record
            .transition(ProcessRecordState::Zombie)
            .unwrap();

        root.handle_owner_death();
        root.cleanup(true);
        let replacement = broker
            .create_process(CallerCredential::Unauthenticated, Some(parent.id()))
            .unwrap();
        assert_eq!(replacement.id(), root.id());
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let shutdown_count = Arc::clone(&shutdowns);
        replacement.install_shutdown(Arc::new(move || {
            shutdown_count.fetch_add(1, Ordering::Relaxed);
        }));

        parent.handle_owner_death();

        assert_eq!(
            replacement.startup_result(),
            Some(Err(BrokerError::PeerClosed))
        );
        assert_eq!(shutdowns.load(Ordering::Relaxed), 1);
        assert_eq!(parent_id(&zombie), None);
        assert_eq!(zombie.state.lock().record, ProcessRecordState::Reaped);
    }

    #[test]
    fn owner_death_does_not_lock_processes_from_other_trees() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let root = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        let parent = broker
            .create_process(CallerCredential::Unauthenticated, Some(root.id()))
            .unwrap();
        parent.complete_start().unwrap();
        let other_root = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        other_root.complete_start().unwrap();

        let (locked_sender, locked_receiver) = std::sync::mpsc::sync_channel(0);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
        let locked_root = Arc::clone(&other_root);
        let lock_thread = std::thread::spawn(move || {
            let _state = locked_root.state.lock();
            locked_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
        });
        locked_receiver.recv().unwrap();

        let (done_sender, done_receiver) = std::sync::mpsc::sync_channel(1);
        let dying_parent = Arc::clone(&parent);
        let owner_death_thread = std::thread::spawn(move || {
            dying_parent.handle_owner_death();
            done_sender.send(()).unwrap();
        });
        let completed_without_other_tree = done_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .is_ok();

        release_sender.send(()).unwrap();
        lock_thread.join().unwrap();
        owner_death_thread.join().unwrap();
        assert!(completed_without_other_tree);
    }

    #[test]
    fn retirement_waits_for_the_final_process_owner() {
        let sink = Arc::new(TestProcessLifecycleSink::default());
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_limits(BrokerCoreLimits::DEFAULT.with_process_limit(1))
        .build()
        .unwrap()
        .with_process_lifecycle_sink(sink.clone());
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let retained = Arc::clone(&process);
        process.complete_start().unwrap();
        assert_eq!(
            process.fail_start(BrokerError::PeerClosed, true, true),
            Ok(())
        );
        assert!(!process.shutdown_was_expected());
        process.retire(true);
        assert_eq!(process.complete_start(), Err(BrokerError::PeerClosed));
        drop(process);

        assert!(matches!(
            broker.create_process(CallerCredential::Unauthenticated, None),
            Err(BrokerError::ResourceExhausted)
        ));
        assert_eq!(sink.changes.load(Ordering::Relaxed), 1);

        drop(retained);

        assert_eq!(sink.changes.load(Ordering::Relaxed), 2);
        assert!(
            broker
                .create_process(CallerCredential::Unauthenticated, None)
                .is_ok()
        );
    }

    #[test]
    fn failed_reference_inheritance_rolls_back_target_references() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let source = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let target = broker
            .create_process(source.caller_credential(), None)
            .unwrap();
        let source_handle = crate::event::create(&source, 1).unwrap();

        assert_eq!(
            source
                .duplicate_object_references_to(&[source_handle, ObjectHandle(u64::MAX)], &target,),
            Err(BrokerError::UnknownObject)
        );
        assert!(target.references.lock().handles.is_empty());
        assert_eq!(
            source.check_readiness(source_handle).unwrap(),
            ReadinessFlags::READ | ReadinessFlags::WRITE
        );
    }

    #[test]
    fn released_thread_id_is_reused_after_rotation() {
        let mut broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        broker.ids =
            alloc::sync::Arc::new(spin::Mutex::new(crate::id::IdAllocator::new(2).unwrap()));
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let first = process.create_thread().unwrap();

        process.exit_thread(first).unwrap();

        assert_eq!(process.create_thread().unwrap(), first);
    }

    #[test]
    fn process_cannot_release_another_process_thread_id() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let first = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let second = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let thread = first.create_thread().unwrap();

        assert_eq!(second.exit_thread(thread), Err(BrokerError::UnknownObject));
        assert_eq!(first.exit_thread(thread), Ok(()));
    }

    #[test]
    fn thread_quotas_are_global_and_per_process() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_limits(BrokerCoreLimits::DEFAULT.with_thread_quotas(2, 1))
        .build()
        .unwrap();
        let first = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let second = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let third = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let first_thread = first.create_thread().unwrap();
        let second_thread = second.create_thread().unwrap();

        assert_eq!(first.create_thread(), Err(BrokerError::ResourceExhausted));
        assert_eq!(third.create_thread(), Err(BrokerError::ResourceExhausted));

        first.exit_thread(first_thread).unwrap();
        assert!(third.create_thread().is_ok());
        second.exit_thread(second_thread).unwrap();
    }

    #[test]
    fn process_limit_is_released_after_normal_teardown() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_limits(BrokerCoreLimits::DEFAULT.with_process_limit(1))
        .build()
        .unwrap();
        let first = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();

        assert!(matches!(
            broker.create_process(CallerCredential::Unauthenticated, None),
            Err(BrokerError::ResourceExhausted)
        ));

        first.cleanup(true);
        assert!(
            broker
                .create_process(CallerCredential::Unauthenticated, None)
                .is_ok()
        );
    }

    #[test]
    fn finish_removes_process_and_releases_owned_ids() {
        let mut broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        broker.ids =
            alloc::sync::Arc::new(spin::Mutex::new(crate::id::IdAllocator::new(2).unwrap()));
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let process_id = process.id();
        let thread_id = process.create_thread().unwrap();
        assert_eq!(broker.active_thread_count.load(Ordering::Relaxed), 1);
        let registered = broker
            .processes
            .read()
            .get(&process_id)
            .and_then(alloc::sync::Weak::upgrade)
            .unwrap();
        assert!(Arc::ptr_eq(&process, &registered));
        drop(registered);

        process.cleanup(true);
        assert!(!broker.processes.read().contains_key(&process_id));
        assert_eq!(broker.active_thread_count.load(Ordering::Relaxed), 0);

        let replacement = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        assert_eq!(replacement.id(), process_id);
        assert_eq!(replacement.create_thread().unwrap(), thread_id);
    }

    #[test]
    fn fallback_drop_retains_process_and_thread_ids_and_quota() {
        let mut broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_limits(BrokerCoreLimits::DEFAULT.with_thread_quotas(1, 1))
        .build()
        .unwrap();
        broker.ids =
            alloc::sync::Arc::new(spin::Mutex::new(crate::id::IdAllocator::new(4).unwrap()));
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let process_id = process.id();
        let thread_id = process.create_thread().unwrap();

        drop(process);
        assert_eq!(broker.active_thread_count.load(Ordering::Relaxed), 1);

        let first_replacement = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let second_replacement = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        assert_ne!(first_replacement.id(), process_id);
        assert_ne!(first_replacement.id().0, thread_id.0);
        assert_ne!(second_replacement.id(), process_id);
        assert_ne!(second_replacement.id().0, thread_id.0);
        assert_eq!(
            first_replacement.create_thread(),
            Err(BrokerError::ResourceExhausted)
        );
        assert!(matches!(
            broker.create_process(CallerCredential::Unauthenticated, None),
            Err(BrokerError::ResourceExhausted)
        ));
    }

    #[test]
    fn drop_sweeps_unindexed_references_and_leaves_id_occupied() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let process_id = process.id();
        crate::event::create(&process, 1).unwrap();
        process.references.lock().handles.clear();

        drop(process);

        assert!(broker.references.read().is_empty());
        let replacement = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        assert_ne!(replacement.id(), process_id);
    }

    #[test]
    fn pending_reference_release_checks_both_counters() {
        let core_pending_references = AtomicUsize::new(1);
        let mut process_references = ProcessReferences {
            handles: Vec::new(),
            pending_handles: 1,
        };
        assert!(release_pending_reference(
            &core_pending_references,
            &mut process_references
        ));
        assert_eq!(core_pending_references.load(Ordering::Relaxed), 0);
        assert_eq!(process_references.pending_handles, 0);

        assert!(!release_pending_reference(
            &core_pending_references,
            &mut process_references
        ));
        assert_eq!(core_pending_references.load(Ordering::Relaxed), 0);
        assert_eq!(process_references.pending_handles, 0);
    }

    fn check_supported_references_duplicate_between_processes(broker: &BrokerCore) {
        let source = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let target = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let denied_target = broker
            .create_process(CallerCredential::HostGuaranteed, None)
            .unwrap();

        let event = crate::event::create(&source, 1).unwrap();
        let duplicated_event = source
            .duplicate_object_reference_to(event, &target, ObjectRights::WAIT)
            .unwrap();
        assert_ne!(duplicated_event, event);
        assert_eq!(
            source.duplicate_object_reference_to(event, &denied_target, ObjectRights::WAIT),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(source.close_object_reference(event), Ok(()));
        assert_eq!(
            crate::event::add(&target, duplicated_event, 1),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            crate::event::consume(&target, duplicated_event, EventConsumeMode::One),
            Ok(EventConsumption {
                value: 1,
                readiness: ReadinessFlags::WRITE,
            })
        );
        assert_eq!(
            target.duplicate_object_reference_to(duplicated_event, &source, ObjectRights::WRITE),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(target.close_object_reference(duplicated_event), Ok(()));

        let (reader, writer) = crate::pipe::create(&source, 4, 2).unwrap();
        let duplicated_writer = source
            .duplicate_object_reference_to(writer, &target, ObjectRights::WRITE)
            .unwrap();
        assert_eq!(source.close_object_reference(writer), Ok(()));
        assert_eq!(crate::pipe::write(&target, duplicated_writer, &[1]), Ok(1));
        assert_eq!(
            crate::pipe::read(&source, reader, 1),
            Ok(std::vec::Vec::from([1]))
        );

        let event = crate::event::create(&target, 0).unwrap();
        assert_eq!(
            source.duplicate_object_reference_to(reader, &target, ObjectRights::WAIT),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(broker.references.read().len(), 3);

        assert_eq!(target.close_object_reference(event), Ok(()));
        assert_eq!(target.close_object_reference(duplicated_writer), Ok(()));
        assert_eq!(source.close_object_reference(reader), Ok(()));
        assert!(broker.references.read().is_empty());
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_file_reference_lifecycle(broker: &BrokerCore, stdio_provider: &TestStdioProvider) {
        let source = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let target = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let mode = FileMode::from_bits(0o600).unwrap();
        let file = crate::fs::open(
            &source,
            "/file",
            ROOT,
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE,
            mode,
        )
        .unwrap()
        .unwrap();

        assert_eq!(crate::fs::write(&source, file, b"abcdef", None), Ok(Ok(6)));
        assert_eq!(
            crate::fs::seek(&source, file, 0, FileSeekWhence::RelativeToBeginning),
            Ok(Ok(0))
        );

        let event = crate::event::create(&source, 0).unwrap();
        let mut byte = [0];
        assert_eq!(
            crate::fs::read(&source, event, &mut byte, None),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            crate::event::consume(&source, file, EventConsumeMode::One),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            source.check_readiness(file),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            crate::fs::open(
                &source,
                "/uncommitted",
                ROOT,
                FileAccessMode::ReadWrite,
                FileOpenFlags::CREATE,
                mode,
            ),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(source.close_object_reference(event), Ok(()));
        assert_eq!(
            crate::fs::path_status(&source, "/uncommitted", ROOT),
            Ok(Err(FileError::NoSuchFileOrDirectory))
        );

        let mut first = [0; 2];
        assert_eq!(crate::fs::read(&source, file, &mut first, None), Ok(Ok(2)));
        assert_eq!(&first, b"ab");

        let duplicate = source
            .duplicate_object_reference_to(file, &target, ObjectRights::WAIT)
            .unwrap();
        let mut second = [0; 2];
        assert_eq!(
            crate::fs::read(&target, duplicate, &mut second, None),
            Ok(Ok(2))
        );
        assert_eq!(&second, b"cd");

        let mut explicit = [0; 2];
        assert_eq!(
            crate::fs::read(&source, file, &mut explicit, Some(0)),
            Ok(Ok(2))
        );
        assert_eq!(&explicit, b"ab");
        let mut final_bytes = [0; 2];
        assert_eq!(
            crate::fs::read(&source, file, &mut final_bytes, None),
            Ok(Ok(2))
        );
        assert_eq!(&final_bytes, b"ef");

        let status = crate::fs::handle_status(&target, duplicate)
            .unwrap()
            .unwrap();
        assert_eq!(status.file_type, FileType::RegularFile);
        assert_eq!(status.size, 6);
        assert_eq!(source.close_object_reference(file), Ok(()));
        assert_eq!(
            crate::fs::seek(&target, duplicate, 0, FileSeekWhence::RelativeToBeginning),
            Ok(Ok(0))
        );
        assert_eq!(
            crate::fs::read(&target, duplicate, &mut byte, None),
            Ok(Ok(1))
        );
        assert_eq!(&byte, b"a");
        assert_eq!(target.close_object_reference(duplicate), Ok(()));
        assert_eq!(crate::fs::unlink(&source, "/file", ROOT), Ok(Ok(())));

        let directory = crate::fs::open(
            &source,
            "/",
            ROOT,
            FileAccessMode::ReadOnly,
            FileOpenFlags::DIRECTORY,
            FileMode::default(),
        )
        .unwrap()
        .unwrap();
        let entries = crate::fs::read_directory(&source, directory)
            .unwrap()
            .unwrap();
        assert!(entries.iter().any(|entry| entry.name == "."));
        assert!(entries.iter().any(|entry| entry.name == "dev"));
        assert_eq!(source.close_object_reference(directory), Ok(()));

        let write_only_directory = crate::fs::open(
            &source,
            "/",
            ROOT,
            FileAccessMode::WriteOnly,
            FileOpenFlags::DIRECTORY,
            FileMode::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            crate::fs::read_directory(&source, write_only_directory),
            Ok(Err(FileError::NotForReading))
        );
        assert_eq!(source.close_object_reference(write_only_directory), Ok(()));

        let random = crate::fs::open(
            &source,
            "/dev/urandom",
            ROOT,
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONE,
            FileMode::default(),
        )
        .unwrap()
        .unwrap();
        let mut random_bytes =
            vec![0; litebox_broker_protocol::random::MAX_RANDOM_TRANSFER_SIZE as usize + 1];
        assert_eq!(
            crate::fs::read(&source, random, &mut random_bytes, None),
            Ok(Ok(random_bytes.len()))
        );
        assert!(random_bytes.iter().all(|byte| *byte == 0x5a));
        assert_eq!(source.close_object_reference(random), Ok(()));

        let write_only_random = broker
            .fs
            .open(
                &source,
                "/dev/urandom",
                ROOT,
                FileAccessMode::WriteOnly,
                FileOpenFlags::NONE,
                FileMode::default(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            broker.fs.read(&source, &write_only_random, &mut [0], None),
            Ok(Err(FileError::NotForReading))
        );

        let read_only_null = broker
            .fs
            .open(
                &source,
                "/dev/null",
                ROOT,
                FileAccessMode::ReadOnly,
                FileOpenFlags::NONE,
                FileMode::default(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            broker.fs.write(&source, &read_only_null, &[0], None),
            Ok(Err(FileError::NotForWriting))
        );

        let stdout = crate::fs::open(
            &source,
            "/dev/stdout",
            ROOT,
            FileAccessMode::WriteOnly,
            FileOpenFlags::NONE,
            FileMode::default(),
        )
        .unwrap()
        .unwrap();
        let duplicated_stdout = source
            .duplicate_object_reference_to(stdout, &target, ObjectRights::WRITE)
            .unwrap();
        source.request_cancellation();
        assert_eq!(
            crate::fs::write(&source, stdout, b"source", None),
            Ok(Err(FileError::Io))
        );
        let stdio_input =
            vec![b'x'; litebox_broker_protocol::stdio::MAX_STDIO_TRANSFER_SIZE as usize + 1];
        assert_eq!(
            crate::fs::write(&target, duplicated_stdout, &stdio_input, None),
            Ok(Ok(
                litebox_broker_protocol::stdio::MAX_STDIO_TRANSFER_SIZE as usize
            ))
        );
        assert_eq!(
            stdio_provider.writes(),
            vec![(
                StdioOutputStream::Stdout,
                stdio_input[..litebox_broker_protocol::stdio::MAX_STDIO_TRANSFER_SIZE as usize]
                    .to_vec()
            )]
        );
        assert_eq!(source.close_object_reference(stdout), Ok(()));
        assert_eq!(target.close_object_reference(duplicated_stdout), Ok(()));
    }

    #[test]
    fn object_reference_lifecycle_uses_public_core_constructor_once() {
        let socket_provider = Arc::new(crate::socket::tests::TestSocketProvider::default());
        let fs = crate::fs::composer::Composer::builder()
            .mount("/", crate::fs::in_mem::InMem::<TestPlatform>::new)
            .mount("/dev", crate::fs::devices::Devices::new)
            .build()
            .unwrap();
        let stdio_provider = Arc::new(TestStdioProvider::default());
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_socket_policy(SocketPolicy::guest_network()),
        )
        .with_limits(
            BrokerCoreLimits::new_with_all_limits(
                TEST_MAX_REFERENCES,
                TEST_MAX_PIPE_CAPACITY,
                2,
                1,
            )
            .with_process_quotas(
                TEST_MAX_REFERENCES_PER_PROCESS,
                TEST_MAX_PIPE_CAPACITY_PER_PROCESS,
            ),
        )
        .with_socket_provider(socket_provider.clone())
        .with_random_provider(Arc::new(crate::random::TestRandomProvider))
        .with_stdio_provider(stdio_provider.clone())
        .with_file_service(Arc::new(
            crate::fs::resolver::Resolver::<TestPlatform, _>::new(fs),
        ))
        .build()
        .unwrap();

        check_event_reference_lifecycle(&broker);
        check_process_drop_releases_references(&broker);
        check_pipe_lifecycle(&broker);
        check_pipe_reader_closure(&broker);
        check_corrupt_index_fails_without_mutation(&broker);
        check_corrupt_index_does_not_break_teardown(&broker);
        check_reference_quota_is_per_process(&broker);
        check_pending_references_count_toward_process_quota(&broker);
        check_pipe_capacity_quota_is_per_process(&broker);
        check_pipe_capacity_outlives_process_for_in_flight_object(&broker);
        check_supported_references_duplicate_between_processes(&broker);
        check_file_reference_lifecycle(&broker, &stdio_provider);
        crate::socket::tests::check_socket_lifecycle(&broker, &socket_provider);
        check_pair_handle_exhaustion(&broker);

        assert!(broker.references.read().is_empty());
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_event_reference_lifecycle(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let other = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let handle = crate::event::create(&process, 0).unwrap();
        let unknown_handle = ObjectHandle(handle.0.checked_add(1).unwrap());

        assert_ne!(unknown_handle, handle);
        assert_eq!(
            process.check_readiness(unknown_handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(
            other.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );

        assert_eq!(process.check_readiness(handle), Ok(ReadinessFlags::WRITE));
        assert_eq!(
            crate::event::add(&process, handle, 1),
            Ok(ReadinessFlags::READ | ReadinessFlags::WRITE)
        );
        assert_eq!(
            crate::event::consume(&process, handle, EventConsumeMode::One),
            Ok(EventConsumption {
                value: 1,
                readiness: ReadinessFlags::WRITE,
            })
        );
        let second_handle = crate::event::create(&process, 0).unwrap();
        assert_eq!(
            crate::event::create(&process, 0),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            crate::pipe::create(&process, 4, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(process.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        // Closing the older handle exercises swap-removing a non-last entry.
        assert_eq!(process.close_object_reference(handle), Ok(()));
        assert_eq!(
            process.close_object_reference(handle),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(process.close_object_reference(second_handle), Ok(()));
        assert!(broker.references.read().is_empty());
    }

    fn check_process_drop_releases_references(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let first = crate::event::create(&process, 0).unwrap();
        let second = crate::event::create(&process, 0).unwrap();
        assert_ne!(first, second);
        {
            let references = broker.references.read();
            assert_eq!(references.len(), 2);
        }

        drop(process);

        {
            let references = broker.references.read();
            assert!(references.is_empty());
        }
    }

    fn check_pipe_lifecycle(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        assert_eq!(
            crate::pipe::create(&process, 5, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        let (reader, writer) = crate::pipe::create(&process, 4, 2).unwrap();
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(
            process.check_readiness(reader),
            Ok(ReadinessFlags::default())
        );
        assert_eq!(
            crate::pipe::read(&process, reader, 1),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(crate::pipe::write(&process, writer, &[1, 2]), Ok(2));
        assert_eq!(crate::pipe::write(&process, writer, &[3, 4, 5]), Ok(2));
        assert_eq!(
            crate::pipe::write(&process, writer, &[5]),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(
            crate::pipe::read(&process, reader, 3),
            Ok(std::vec::Vec::from([1, 2, 3]))
        );
        assert_eq!(crate::pipe::write(&process, writer, &[5, 6]), Ok(2));
        assert_eq!(process.close_object_reference(writer), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(
            process.check_readiness(reader),
            Ok(ReadinessFlags::READ | ReadinessFlags::HANGUP)
        );
        assert_eq!(
            crate::pipe::read(&process, reader, 4),
            Ok(std::vec::Vec::from([4, 5, 6]))
        );
        assert_eq!(
            crate::pipe::read(&process, reader, 1),
            Ok(std::vec::Vec::new())
        );
        assert_eq!(process.close_object_reference(reader), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_pipe_reader_closure(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let (reader, writer) = crate::pipe::create(&process, 4, 2).unwrap();
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 4);
        assert_eq!(process.close_object_reference(reader), Ok(()));
        assert_eq!(crate::pipe::write(&process, writer, &[]), Ok(0));
        assert_eq!(
            crate::pipe::write(&process, writer, &[1]),
            Err(BrokerError::PeerClosed)
        );
        assert_eq!(
            process.check_readiness(writer),
            Ok(ReadinessFlags::WRITE | ReadinessFlags::ERROR)
        );
        assert_eq!(process.close_object_reference(writer), Ok(()));
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_corrupt_index_fails_without_mutation(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let older = crate::event::create(&process, 0).unwrap();
        let newer = crate::event::create(&process, 0).unwrap();
        {
            let mut references = broker.references.write();
            references.get_mut(&older).unwrap().process_reference_index = usize::MAX;
        }

        assert_eq!(
            process.close_object_reference(older),
            Err(BrokerError::Internal)
        );
        {
            let mut references = broker.references.write();
            references.get_mut(&older).unwrap().process_reference_index = 0;
        }
        assert_eq!(process.close_object_reference(older), Ok(()));
        assert_eq!(process.close_object_reference(newer), Ok(()));
    }

    fn check_corrupt_index_does_not_break_teardown(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let _older = crate::event::create(&process, 0).unwrap();
        let newer = crate::event::create(&process, 0).unwrap();
        broker
            .references
            .write()
            .get_mut(&newer)
            .unwrap()
            .process_reference_index = usize::MAX;

        drop(process);

        assert!(broker.references.read().is_empty());
    }

    fn check_reference_quota_is_per_process(broker: &BrokerCore) {
        let greedy = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let neighbor = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();

        let greedy_first = crate::event::create(&greedy, 0).unwrap();
        let greedy_second = crate::event::create(&greedy, 0).unwrap();
        assert_eq!(
            crate::event::create(&greedy, 0),
            Err(BrokerError::ResourceExhausted)
        );

        let neighbor_first = crate::event::create(&neighbor, 0).unwrap();
        let neighbor_second = crate::event::create(&neighbor, 0).unwrap();
        assert_eq!(broker.references.read().len(), TEST_MAX_REFERENCES);

        let latecomer = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        assert_eq!(
            crate::event::create(&latecomer, 0),
            Err(BrokerError::ResourceExhausted)
        );

        assert_eq!(greedy.close_object_reference(greedy_first), Ok(()));
        let latecomer_handle = crate::event::create(&latecomer, 0).unwrap();

        assert_eq!(greedy.close_object_reference(greedy_second), Ok(()));
        assert_eq!(neighbor.close_object_reference(neighbor_first), Ok(()));
        assert_eq!(neighbor.close_object_reference(neighbor_second), Ok(()));
        assert_eq!(latecomer.close_object_reference(latecomer_handle), Ok(()));
        assert!(broker.references.read().is_empty());
    }

    fn check_pending_references_count_toward_process_quota(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let neighbor = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();

        let first = process
            .reserve_object_reference(ObjectRights::WAIT)
            .unwrap();
        let second = process
            .reserve_object_reference(ObjectRights::WAIT)
            .unwrap();
        assert!(matches!(
            process.reserve_object_reference(ObjectRights::WAIT),
            Err(BrokerError::ResourceExhausted)
        ));

        let neighbor_handle = crate::event::create(&neighbor, 0).unwrap();
        drop(first);
        drop(second);
        assert_eq!(neighbor.close_object_reference(neighbor_handle), Ok(()));
        assert!(broker.references.read().is_empty());
        assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
    }

    fn check_pipe_capacity_quota_is_per_process(broker: &BrokerCore) {
        let greedy = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let neighbor = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();

        let (greedy_reader, greedy_writer) =
            crate::pipe::create(&greedy, TEST_MAX_PIPE_CAPACITY_PER_PROCESS as u64, 2).unwrap();
        assert_eq!(
            crate::pipe::create(&greedy, 1, 1),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            greedy.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_PIPE_CAPACITY_PER_PROCESS
        );

        let (neighbor_reader, neighbor_writer) =
            crate::pipe::create(&neighbor, TEST_MAX_PIPE_CAPACITY_PER_PROCESS as u64, 2).unwrap();
        assert_eq!(
            broker.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_PIPE_CAPACITY
        );

        let latecomer = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        assert_eq!(
            crate::pipe::create(&latecomer, 1, 1),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(latecomer.reserved_pipe_capacity.load(Ordering::Relaxed), 0);

        assert_eq!(greedy.close_object_reference(greedy_reader), Ok(()));
        assert_eq!(greedy.close_object_reference(greedy_writer), Ok(()));
        assert_eq!(greedy.reserved_pipe_capacity.load(Ordering::Relaxed), 0);

        assert_eq!(neighbor.close_object_reference(neighbor_reader), Ok(()));
        assert_eq!(neighbor.close_object_reference(neighbor_writer), Ok(()));
        assert_eq!(neighbor.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_pipe_capacity_outlives_process_for_in_flight_object(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let (reader, _writer) =
            crate::pipe::create(&process, TEST_MAX_PIPE_CAPACITY_PER_PROCESS as u64, 2).unwrap();
        let object = process
            .authorized_object(reader, ObjectRights::WAIT)
            .unwrap();
        let process_capacity = Arc::clone(&process.reserved_pipe_capacity);

        drop(process);

        assert!(broker.references.read().is_empty());
        assert_eq!(
            process_capacity.load(Ordering::Relaxed),
            TEST_MAX_PIPE_CAPACITY_PER_PROCESS
        );
        assert_eq!(
            broker.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_PIPE_CAPACITY_PER_PROCESS
        );

        drop(object);

        assert_eq!(process_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
    }

    fn check_pair_handle_exhaustion(broker: &BrokerCore) {
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        {
            let mut next_reference_handle = broker.next_reference_handle.write();
            *next_reference_handle = u64::MAX - 1;
        }
        assert_eq!(
            crate::pipe::create(&process, 4, 2),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(*broker.next_reference_handle.read(), u64::MAX - 1);
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        let handle = crate::event::create(&process, 0).unwrap();
        assert_eq!(handle, ObjectHandle(u64::MAX - 1));
        assert_eq!(process.close_object_reference(handle), Ok(()));
        assert_eq!(
            crate::event::create(&process, 0),
            Err(BrokerError::ResourceExhausted)
        );
    }
}
