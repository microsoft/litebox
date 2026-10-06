// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::any::Any;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::object::{self, ObjectEntry, ObjectReference, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::signal::ProcessSignals;
use crate::{BrokerCore, BrokerError, Result};
use hashbrown::{HashMap, HashSet};
use litebox_broker_protocol::fs::{FileOpenFlags, FileStatusFlags, SetStatusFlagsRequest};
use litebox_broker_protocol::process::{
    ChildExit, ChildSelector, ProcessExitStatus, ProcessIdentity, ProcessInfo,
};
use litebox_broker_protocol::process_group::ProcessGroupMembership;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::{ObjectHandle, ProcessId, ThreadId};
use spin::{Mutex, Once, rwlock::RwLock};

/// Platform-provided notification destination for broker-process lifecycle changes.
pub trait ProcessLifecycleSink: Send + Sync {
    /// Wakes waiters after authoritative process state changes.
    fn changed(&self);
}

/// Host runner shutdown action installed into a broker process.
pub type ProcessShutdown = Arc<dyn Fn() + Send + Sync>;

/// Platform storage for a pending child's memory image.
///
/// The image is a byte array, zero wherever it was not written, whose layout
/// only the parent and the child's runner understand.
pub trait ProcessImage: Send {
    /// Writes `data` at `offset`, extending the image as needed.
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<()>;

    /// Copies the bytes at `range` in the shared memory `memory` to `offset`,
    /// extending the image as needed.
    ///
    /// Returns `None` if the image cannot read `memory`'s type directly, so
    /// the caller must copy the bytes through [`Self::write`] instead.
    fn write_from_shared(
        &mut self,
        _offset: u64,
        _memory: &dyn Any,
        _range: Range<usize>,
    ) -> Option<Result<()>> {
        None
    }

    /// Returns the image so the platform that created it can recover its
    /// concrete type when starting the child.
    fn as_any(&self) -> &dyn Any;
}

/// A pending child's memory image.
///
/// The image holds its share of the broker-wide child image budget until it is
/// dropped.
pub struct ChildImage {
    image: Box<dyn ProcessImage>,
    /// Image bytes counted in `budget`.
    reserved: u64,
    budget: Arc<AtomicU64>,
}

impl ChildImage {
    fn new(image: Box<dyn ProcessImage>, budget: Arc<AtomicU64>) -> Self {
        Self {
            image,
            reserved: 0,
            budget,
        }
    }

    /// Returns the platform image.
    #[must_use]
    pub fn image(&self) -> &dyn ProcessImage {
        &*self.image
    }

    /// Counts image bytes up to `end` in the budget, which must stay within
    /// `limit`.
    fn reserve(&mut self, end: u64, limit: u64) -> Result<()> {
        let Some(growth) = end.checked_sub(self.reserved).filter(|growth| *growth > 0) else {
            return Ok(());
        };
        self.budget
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
                reserved.checked_add(growth).filter(|total| *total <= limit)
            })
            .map_err(|_| BrokerError::ResourceExhausted)?;
        self.reserved = end;
        Ok(())
    }
}

impl Drop for ChildImage {
    fn drop(&mut self) {
        self.budget
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |reserved| {
                reserved.checked_sub(self.reserved)
            })
            .expect("reserved child image size must include every live image");
    }
}

/// A pending child taken for startup, with its memory image if one was written.
type ChildWithImage = (Arc<BrokerProcess>, Option<ChildImage>);

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

/// Cancellation state of one broker association.
///
/// Once the association starts ending, potentially blocking operations stop
/// waiting and the process accepts no new lifecycle operations.
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

struct ProcessReferences {
    handles: Vec<ObjectHandle>,
    pending_handles: usize,
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
    /// ID assigned to the initial thread when process creation completes.
    initial_thread_id: Once<ThreadId>,
    /// Process that created this one, if any.
    creator: Option<ProcessId>,
    /// This process's place in the process tree.
    ///
    /// No other lock is taken while this one is held. Changes are serialized
    /// by the core's process tree lock.
    links: Mutex<ProcessLinks>,
    state: Mutex<BrokerProcessState>,
    /// Broker-entry-authenticated caller credential for this process.
    pub(crate) caller_credential: CallerCredential,
    /// Handles of the live object references owned by this process.
    references: Mutex<ProcessReferences>,
    /// Authoritative broker threads owned by this process.
    threads: Mutex<HashSet<ThreadId>>,
    /// Pipe capacity charged to this process by live pipe objects.
    pub(crate) reserved_pipe_capacity: Arc<AtomicUsize>,
    /// Socket quota held by pending, live, and closing in-flight resources.
    pub(crate) reserved_sockets: Arc<AtomicUsize>,
    /// Signals and child exits this process has not taken.
    pub(crate) signals: Arc<ProcessSignals>,
    /// Cancellation state of this process's association.
    pub(crate) cancellation: AssociationCancellation,
}

/// A process's place in the process tree.
struct ProcessLinks {
    /// Process group and session.
    membership: ProcessGroupMembership,
    /// Process that reaps this one, if any.
    ///
    /// This starts as the creator. Once the parent exits, it becomes the
    /// nearest ancestor that adopts orphans, or none.
    parent: Option<Weak<BrokerProcess>>,
    /// Children not yet reaped, in the order this process gained them.
    ///
    /// Each keeps its child, and thus a zombie's exit status, alive.
    children: Vec<Arc<BrokerProcess>>,
    /// Whether children are reaped as soon as they exit.
    reap_children: bool,
    /// Whether this process adopts the orphaned children of its exiting
    /// descendants.
    adopts_orphans: bool,
    /// Exit status, once this process exited.
    exit_status: Option<ProcessExitStatus>,
    /// Whether this process no longer exists for other processes, because it
    /// was reaped or never started.
    released: bool,
}

struct BrokerProcessState {
    status: ProcessStatus,
    /// Final termination status reported by the running process.
    reported_exit_status: Option<ProcessExitStatus>,
    /// Child retained until this process requests startup.
    pending_child_process: Option<PendingChild>,
    /// Whether a starting child continues after its parent dies.
    continue_startup_on_parent_death: bool,
    retirement: ProcessRetirement,
    shutdown_request: ProcessShutdownRequest,
    shutdown: Option<ProcessShutdown>,
}

/// A child retained until its parent requests startup.
struct PendingChild {
    process: Arc<BrokerProcess>,
    /// Memory image the child starts from, once written.
    image: Option<ChildImage>,
}

/// Broker-visible status of one process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessStatus {
    /// Host process setup is in progress.
    Starting,
    /// The process is published and may issue guest-originated operations.
    Running,
    /// Exit is releasing the process's resources before its status becomes
    /// observable.
    Exiting,
    /// Startup failed and host cleanup is still pending.
    Failed(BrokerError),
    /// The process exited and retains its exit status.
    Zombie(ProcessExitStatus),
}

impl ProcessStatus {
    fn transition(&mut self, next: Self) -> Result<()> {
        let allowed = matches!(
            (*self, next),
            (Self::Starting, Self::Running | Self::Failed(_))
                | (Self::Starting | Self::Running, Self::Exiting)
                | (Self::Exiting, Self::Zombie(_))
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
    ///
    /// A child of `creator` starts in its group and session, while a root
    /// process leads its own.
    pub(crate) fn new(
        core: BrokerCore,
        id: ProcessId,
        creator: Option<&Arc<BrokerProcess>>,
        caller_credential: CallerCredential,
    ) -> Self {
        let membership = creator.map_or(
            ProcessGroupMembership {
                process_group: id,
                session: id,
            },
            |creator| creator.membership(),
        );
        Self {
            core,
            id,
            initial_thread_id: Once::new(),
            creator: creator.map(|creator| creator.id),
            links: Mutex::new(ProcessLinks {
                membership,
                parent: creator.map(Arc::downgrade),
                children: Vec::new(),
                reap_children: false,
                adopts_orphans: false,
                exit_status: None,
                released: false,
            }),
            state: Mutex::new(BrokerProcessState {
                status: ProcessStatus::Starting,
                reported_exit_status: None,
                pending_child_process: None,
                continue_startup_on_parent_death: false,
                retirement: ProcessRetirement::Active { abnormal: false },
                shutdown_request: ProcessShutdownRequest::None,
                shutdown: None,
            }),
            caller_credential,
            references: Mutex::new(ProcessReferences {
                handles: Vec::new(),
                pending_handles: 0,
            }),
            threads: Mutex::new(HashSet::new()),
            reserved_pipe_capacity: Arc::new(AtomicUsize::new(0)),
            reserved_sockets: Arc::new(AtomicUsize::new(0)),
            signals: Arc::new(ProcessSignals::new()),
            cancellation: AssociationCancellation::default(),
        }
    }

    /// Returns the assigned process ID.
    #[must_use]
    pub const fn id(&self) -> ProcessId {
        self.id
    }

    /// Returns the ID assigned to this process's initial thread.
    ///
    /// This is immutable creation metadata. Live thread ownership remains
    /// authoritative in the process thread set.
    ///
    /// # Panics
    ///
    /// Panics if called on crate-internal process state before process creation
    /// initializes the initial thread.
    #[must_use]
    pub fn initial_thread_id(&self) -> ThreadId {
        *self
            .initial_thread_id
            .get()
            .expect("broker process creation did not initialize its initial thread ID")
    }

    pub(crate) fn set_initial_thread_id(&self, initial_thread_id: ThreadId) {
        assert!(
            self.initial_thread_id.get().is_none(),
            "broker process initial thread ID was initialized twice"
        );
        self.initial_thread_id.call_once(|| initial_thread_id);
    }

    /// Returns the credential authenticated for this process association.
    #[must_use]
    pub const fn caller_credential(&self) -> CallerCredential {
        self.caller_credential
    }

    /// Prepares a newly created child for duplication startup.
    ///
    /// The child must have been created directly from this running process.
    /// Holding the parent state lock while marking the child ensures parent
    /// death either rejects ordinary startup or lets prepared startup continue.
    pub fn prepare_duplication_child(&self, child: &BrokerProcess) -> Result<()> {
        if !self.core.policy.process_duplication_enabled() {
            return Err(BrokerError::PolicyDenied);
        }
        if core::ptr::eq(self, child) || !Arc::ptr_eq(&self.core.processes, &child.core.processes) {
            return Err(BrokerError::Internal);
        }

        let state = self.state.lock();
        if !self.accepts_operations(&state) {
            return Err(BrokerError::PeerClosed);
        }
        let mut child_state = child.state.lock();
        if !child.awaits_startup(&child_state)
            || !child.is_child_of(self)
            || child_state.continue_startup_on_parent_death
        {
            return Err(BrokerError::Internal);
        }
        child_state.continue_startup_on_parent_death = true;
        Ok(())
    }

    /// Allocates and retains one pending child process.
    ///
    /// The child is this process's child from the start, so its exit is
    /// reported here even if it exits before starting its own runner.
    pub fn allocate_child_process(&self) -> Result<ProcessIdentity> {
        if !self.core.policy.process_duplication_enabled() {
            return Err(BrokerError::PolicyDenied);
        }
        {
            let state = self.state.lock();
            if !self.accepts_operations(&state) {
                return Err(BrokerError::PeerClosed);
            }
            if state.pending_child_process.is_some() {
                return Err(BrokerError::WouldBlock);
            }
        }

        let child = self
            .core
            .create_process(self.caller_credential, Some(self.id))?;
        let result = {
            let mut state = self.state.lock();
            if !self.accepts_operations(&state) {
                Err(BrokerError::PeerClosed)
            } else if state.pending_child_process.is_some() {
                Err(BrokerError::WouldBlock)
            } else {
                let child_state = child.state.lock();
                if !child.awaits_startup(&child_state) || !child.is_child_of(self) {
                    Err(BrokerError::Internal)
                } else {
                    drop(child_state);
                    state.pending_child_process = Some(PendingChild {
                        process: Arc::clone(&child),
                        image: None,
                    });
                    Ok(ProcessIdentity {
                        process_id: child.id(),
                        initial_thread_id: child.initial_thread_id(),
                    })
                }
            }
        };
        if result.is_err() {
            child.discard();
        }
        result
    }

    /// Discards a child that never started, as if it had never been created.
    fn discard(&self) {
        let _ = self.fail_start(BrokerError::PeerClosed, false, true);
        self.retire(true);
    }

    /// Takes the pending child selected for startup.
    pub fn take_child_process(&self, child_process_id: ProcessId) -> Result<Arc<BrokerProcess>> {
        self.take_child_process_with_image(child_process_id)
            .map(|(child, _)| child)
    }

    /// Takes the pending child selected for startup with its memory image, if
    /// one was written.
    pub fn take_child_process_with_image(
        &self,
        child_process_id: ProcessId,
    ) -> Result<ChildWithImage> {
        let mut state = self.state.lock();
        self.pending_child(&mut state, child_process_id)?;
        let PendingChild { process, image } = state
            .pending_child_process
            .take()
            .ok_or(BrokerError::Internal)?;
        Ok((process, image))
    }

    /// Lets `write` store `length` bytes at `offset` in the memory image of
    /// the pending child selected by `child_process_id`.
    ///
    /// The first write creates the image with `create`, given the broker's
    /// child image size limit, which the image never grows past. All child
    /// images together stay within the broker's total child image size limit.
    pub fn write_child_memory<E: From<BrokerError>>(
        &self,
        child_process_id: ProcessId,
        offset: u64,
        length: u64,
        create: impl FnOnce(u64) -> Result<Box<dyn ProcessImage>>,
        write: impl FnOnce(&mut dyn ProcessImage) -> core::result::Result<(), E>,
    ) -> core::result::Result<(), E> {
        let limits = self.core.limits;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= limits.max_child_image_size)
            .ok_or(BrokerError::ResourceExhausted)?;
        // The state lock keeps the child pending while its image is written.
        let mut state = self.state.lock();
        let pending = self.pending_child(&mut state, child_process_id)?;
        let image = match &mut pending.image {
            Some(image) => image,
            None => pending.image.insert(ChildImage::new(
                create(limits.max_child_image_size)?,
                Arc::clone(&self.core.reserved_child_image_size),
            )),
        };
        image.reserve(end, limits.max_total_child_image_size)?;
        write(&mut *image.image)
    }

    /// Returns the pending child selected by `child_process_id` while it
    /// awaits startup.
    fn pending_child<'a>(
        &self,
        state: &'a mut BrokerProcessState,
        child_process_id: ProcessId,
    ) -> Result<&'a mut PendingChild> {
        if !self.accepts_operations(state) {
            return Err(BrokerError::PeerClosed);
        }
        let pending = state
            .pending_child_process
            .as_mut()
            .filter(|pending| pending.process.id() == child_process_id)
            .ok_or(BrokerError::UnknownObject)?;
        if !pending
            .process
            .awaits_startup(&pending.process.state.lock())
        {
            return Err(BrokerError::PeerClosed);
        }
        Ok(pending)
    }

    /// Records the exit of the pending child selected by `child_process_id`.
    ///
    /// A child may run in this process's runner before starting its own, as a
    /// Linux `vfork` child does until `execve`. If it exits there, it becomes
    /// a zombie retaining `exit_status`, like a started child after
    /// [`Self::complete_exit`].
    pub fn exit_child_process(
        &self,
        child_process_id: ProcessId,
        exit_status: ProcessExitStatus,
    ) -> Result<()> {
        let child = self.take_child_process(child_process_id)?;
        // The child never had a runner, so its teardown is fully accounted.
        child.retire(true);
        let release_thread_ids = {
            let mut state = child.state.lock();
            // Owner death fails the child if it takes the child lock first.
            if let ProcessStatus::Failed(error) = state.status {
                return Err(error);
            }
            state.status.transition(ProcessStatus::Exiting)?;
            matches!(
                state.retirement,
                ProcessRetirement::Retired { release_ids: true }
            )
        };
        child.finish_exit(exit_status, release_thread_ids)
    }

    /// Discards the pending child selected by `child_process_id`, as if it
    /// had never been created.
    pub fn cancel_child_process(&self, child_process_id: ProcessId) -> Result<()> {
        self.take_child_process(child_process_id)?.discard();
        Ok(())
    }

    /// Records the final termination status reported by this running process.
    ///
    /// A runner observes its guest's termination more precisely than its host
    /// exit status can convey, such as a guest killed by a signal. The latest
    /// report replaces the host status once [`Self::complete_exit`] runs.
    pub fn report_exit_status(&self, exit_status: ProcessExitStatus) -> Result<()> {
        let mut state = self.state.lock();
        if !self.accepts_operations(&state) {
            return Err(BrokerError::PeerClosed);
        }
        state.reported_exit_status = Some(exit_status);
        Ok(())
    }

    /// Sets whether this running process's children are reaped as soon as
    /// they exit.
    ///
    /// Each child applies the setting in effect when it exits, so children
    /// that already exited are kept until reaped.
    pub fn set_child_reaping(&self, enabled: bool) -> Result<()> {
        self.update_links(|links| links.reap_children = enabled)
    }

    /// Sets whether this running process adopts the orphaned children of its
    /// exiting descendants.
    ///
    /// When a process exits, its children move to its nearest ancestor that
    /// adopts orphans. Without one, they have no parent and are reaped as soon
    /// as they exit.
    pub fn set_orphan_adoption(&self, enabled: bool) -> Result<()> {
        self.update_links(|links| links.adopts_orphans = enabled)
    }

    /// Updates this running process's place in the process tree.
    fn update_links(&self, update: impl FnOnce(&mut ProcessLinks)) -> Result<()> {
        let _tree = self.core.process_tree.lock();
        if !self.accepts_operations(&self.state.lock()) {
            return Err(BrokerError::PeerClosed);
        }
        update(&mut self.links.lock());
        Ok(())
    }

    /// Reaps this running process's oldest exited child that `selector`
    /// matches, returning its exit.
    ///
    /// Returns `WouldBlock` if only live children match, and `UnknownObject`
    /// if none does. Each matching child's exit or removal is then posted to
    /// this process's signals.
    pub fn reap_child(&self, selector: ChildSelector) -> Result<ChildExit> {
        let _tree = self.core.process_tree.lock();
        if !self.accepts_operations(&self.state.lock()) {
            return Err(BrokerError::PeerClosed);
        }
        // This process's links are released while its children's are read,
        // since no other lock is taken while one is held.
        let mut children = core::mem::take(&mut self.links.lock().children);
        let mut matched = false;
        let exited = children.iter().position(|child| {
            let links = child.links.lock();
            let selected = match selector {
                ChildSelector::Any => true,
                ChildSelector::Process(id) => child.id == id,
                ChildSelector::ProcessGroup(id) => links.membership.process_group == id,
            };
            matched |= selected;
            selected && links.exit_status.is_some()
        });
        let reaped = exited.map(|index| children.remove(index));
        self.links.lock().children = children;
        let Some(child) = reaped else {
            return Err(if matched {
                BrokerError::WouldBlock
            } else {
                BrokerError::UnknownObject
            });
        };
        let mut links = child.links.lock();
        links.released = true;
        Ok(ChildExit {
            process_id: child.id,
            exit_status: links.exit_status.ok_or(BrokerError::Internal)?,
        })
    }

    /// Returns the place in the process tree of the process `target`.
    ///
    /// Returns `UnknownObject` if no such process exists.
    pub fn process_info(&self, target: ProcessId) -> Result<ProcessInfo> {
        let target = self.core.registered_process(target)?;
        // While the links reference a parent, it has yet to finish exiting,
        // so it is still registered; once an adoption replaces it, it may be
        // reaped. Upgrade it under the links, and drop it only after them.
        let (parent, membership) = {
            let links = target.links.lock();
            (
                links.parent.as_ref().and_then(Weak::upgrade),
                links.membership,
            )
        };
        Ok(ProcessInfo {
            creator: target.creator,
            parent: parent.as_ref().map(|parent| parent.id),
            membership,
        })
    }

    /// Duplicates object references into the pending child selected by
    /// `child_process_id`, as a Linux child inherits its parent's descriptors.
    ///
    /// Returned handles follow the requested order and belong to the child,
    /// which releases them when it terminates. If duplication fails, the
    /// child receives none of them.
    ///
    /// Since the child can now change these objects, this process's
    /// references first start publishing readiness through `readiness_sink`,
    /// as [`Self::register_readiness`] describes.
    pub fn duplicate_object_references_to_child(
        &self,
        child_process_id: ProcessId,
        handles: &[ObjectHandle],
        readiness_sink: &Arc<dyn ReadinessSink>,
    ) -> Result<Vec<ObjectHandle>> {
        // A registration left behind by a later failure only publishes
        // readiness the process does not need.
        self.register_readiness(readiness_sink)?;
        // Hold the state lock so the child stays pending, since a child
        // removed from its slot may release its references before receiving
        // these.
        let state = self.state.lock();
        if !self.accepts_operations(&state) {
            return Err(BrokerError::PeerClosed);
        }
        let child = &state
            .pending_child_process
            .as_ref()
            .filter(|pending| pending.process.id() == child_process_id)
            .ok_or(BrokerError::UnknownObject)?
            .process;
        if !child.awaits_startup(&child.state.lock()) {
            return Err(BrokerError::PeerClosed);
        }
        self.duplicate_object_references_to(handles, child)
    }

    /// Returns this process's group and session.
    pub(crate) fn membership(&self) -> ProcessGroupMembership {
        self.links.lock().membership
    }

    /// Moves this process into another group or session.
    ///
    /// Callers hold the core's process tree lock.
    pub(crate) fn set_membership(&self, membership: ProcessGroupMembership) {
        self.links.lock().membership = membership;
    }

    /// Returns whether another process created this one.
    pub(crate) const fn has_creator(&self) -> bool {
        self.creator.is_some()
    }

    /// Returns whether this process was reaped or never started, so it no
    /// longer exists for other processes.
    pub(crate) fn is_released(&self) -> bool {
        self.links.lock().released
    }

    /// Reserves room for one more child.
    ///
    /// Callers hold the core's process tree lock.
    pub(crate) fn reserve_child(&self) -> Result<()> {
        self.links
            .lock()
            .children
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)
    }

    /// Adds a newly created child, for which [`Self::reserve_child`] made
    /// room.
    ///
    /// Callers hold the core's process tree lock.
    pub(crate) fn add_child(&self, child: Arc<BrokerProcess>) {
        self.links.lock().children.push(child);
    }

    /// Returns the pending child selected by `child_process_id`.
    pub(crate) fn pending_child_process(
        &self,
        child_process_id: ProcessId,
    ) -> Result<Arc<BrokerProcess>> {
        let mut state = self.state.lock();
        Ok(Arc::clone(
            &self.pending_child(&mut state, child_process_id)?.process,
        ))
    }

    /// Returns whether this process completed broker startup.
    #[must_use]
    pub fn is_running(&self) -> bool {
        let state = self.state.lock();
        matches!(state.status, ProcessStatus::Running)
            && matches!(state.retirement, ProcessRetirement::Active { .. })
    }

    /// Returns the completed startup outcome, or `None` while startup is pending.
    pub fn startup_result(&self) -> Option<Result<()>> {
        match self.state.lock().status {
            ProcessStatus::Starting => None,
            // A process exits only after it runs, possibly before starting its
            // own runner.
            ProcessStatus::Running | ProcessStatus::Exiting | ProcessStatus::Zombie(_) => {
                Some(Ok(()))
            }
            ProcessStatus::Failed(error) => Some(Err(error)),
        }
    }

    /// Completes startup after the process association becomes active.
    pub fn complete_start(&self) -> Result<()> {
        {
            let mut state = self.state.lock();
            if !self.is_active(&state) {
                return Err(BrokerError::PeerClosed);
            }
            match state.status {
                ProcessStatus::Starting => {}
                ProcessStatus::Running => return Err(BrokerError::Internal),
                ProcessStatus::Failed(error) => return Err(error),
                ProcessStatus::Exiting | ProcessStatus::Zombie(_) => {
                    return Err(BrokerError::PeerClosed);
                }
            }
            state.status.transition(ProcessStatus::Running)?;
            state.continue_startup_on_parent_death = false;
        }
        self.core.process_lifecycle_sink.changed();
        Ok(())
    }

    /// Publishes one runner termination outcome.
    ///
    /// Exit releases object references, socket state, and, after clean
    /// retirement, thread IDs. A zombie keeps only its process ID, registry
    /// entry, and exit status, and remains until its parent reaps it and
    /// runner supervision releases it. Only the first completion releases
    /// resources and records its status; later or concurrent completions
    /// return without effect.
    ///
    /// A status reported through [`Self::report_exit_status`] takes precedence
    /// over `exit_status`.
    pub fn complete_exit(&self, exit_status: ProcessExitStatus) -> Result<()> {
        let (exit_status, release_thread_ids) = {
            let mut state = self.state.lock();
            match state.status {
                ProcessStatus::Running => {}
                ProcessStatus::Exiting | ProcessStatus::Zombie(_) => return Ok(()),
                ProcessStatus::Starting => return Err(BrokerError::WouldBlock),
                ProcessStatus::Failed(error) => return Err(error),
            }
            // Only the caller that claims the exit releases resources.
            state.status.transition(ProcessStatus::Exiting)?;
            (
                state.reported_exit_status.unwrap_or(exit_status),
                matches!(
                    state.retirement,
                    ProcessRetirement::Retired { release_ids: true }
                ),
            )
        };
        self.finish_exit(exit_status, release_thread_ids)
    }

    /// Releases the resources of a process whose exit this caller claimed,
    /// then makes it a zombie retaining `exit_status`.
    ///
    /// The exit is reported to the parent, which keeps the zombie until it
    /// reaps it. This process's children move to the nearest of its
    /// ancestors that adopts orphans, if any.
    fn finish_exit(&self, exit_status: ProcessExitStatus, release_thread_ids: bool) -> Result<()> {
        // Like Linux, release resources before the exit becomes observable, so
        // a parent that reaps the child sees its pipes and sockets closed.
        if self.release_references() {
            self.state.lock().retirement.mark_abnormal();
        } else if release_thread_ids {
            self.release_threads(true);
        }
        // Children that cannot start without this process fail, as when its
        // owner dies.
        self.handle_owner_death();
        {
            let _tree = self.core.process_tree.lock();
            self.state
                .lock()
                .status
                .transition(ProcessStatus::Zombie(exit_status))?;
            let (parent, children) = {
                let mut links = self.links.lock();
                links.exit_status = Some(exit_status);
                (
                    links.parent.as_ref().and_then(Weak::upgrade),
                    core::mem::take(&mut links.children),
                )
            };
            let adopter = Self::nearest_adopter(parent.clone()).filter(|adopter| {
                // Without room for the orphans, they are left without a
                // parent.
                adopter
                    .links
                    .lock()
                    .children
                    .try_reserve(children.len())
                    .is_ok()
            });
            for child in children {
                Self::adopt(adopter.as_ref(), child);
            }
            self.report_exit(parent.as_deref(), exit_status);
        }
        self.core.process_lifecycle_sink.changed();
        Ok(())
    }

    /// Returns the nearest of `ancestor` and its ancestors that adopts
    /// orphans.
    ///
    /// Callers hold the core's process tree lock.
    fn nearest_adopter(mut ancestor: Option<Arc<Self>>) -> Option<Arc<Self>> {
        while let Some(process) = ancestor {
            let links = process.links.lock();
            if links.adopts_orphans {
                drop(links);
                return Some(process);
            }
            let parent = links.parent.as_ref().and_then(Weak::upgrade);
            drop(links);
            ancestor = parent;
        }
        None
    }

    /// Makes `parent`, which has room for it, the parent of the orphan
    /// `child`, or leaves `child` without one.
    ///
    /// A zombie reports its exit to its new parent as if it just exited.
    /// Callers hold the core's process tree lock.
    fn adopt(parent: Option<&Arc<Self>>, child: Arc<Self>) {
        let exit_status = {
            let mut links = child.links.lock();
            links.parent = parent.map(Arc::downgrade);
            links.exit_status
        };
        if let Some(parent) = parent {
            parent.links.lock().children.push(Arc::clone(&child));
        }
        if let Some(exit_status) = exit_status {
            child.report_exit(parent.map(|parent| &**parent), exit_status);
        }
    }

    /// Reports this zombie's exit to `parent`, which keeps this process
    /// unless it reaps children as soon as they exit. Without a parent, this
    /// process is reaped at once.
    ///
    /// Callers hold the core's process tree lock.
    fn report_exit(&self, parent: Option<&Self>, exit_status: ProcessExitStatus) {
        let mut reaped = parent.is_none();
        // The last reference may run this process's teardown, so it drops
        // only after the parent's links are released.
        let mut removed = None;
        if let Some(parent) = parent {
            {
                let mut links = parent.links.lock();
                if links.reap_children {
                    reaped = true;
                    let index = links
                        .children
                        .iter()
                        .position(|child| core::ptr::eq(Arc::as_ptr(child), self));
                    removed = index.map(|index| links.children.remove(index));
                }
            }
            parent.signals.post_child_exit(ChildExit {
                process_id: self.id,
                exit_status,
            });
        }
        if reaped {
            self.links.lock().released = true;
        }
        drop(removed);
    }

    /// Removes this process, whose startup failed, from the process tree,
    /// telling its parent, whose reaps may have found it live.
    ///
    /// Callers hold the core's process tree lock.
    fn release_unstarted(&self) {
        let parent = {
            let mut links = self.links.lock();
            links.released = true;
            links.parent.take().as_ref().and_then(Weak::upgrade)
        };
        let Some(parent) = parent else {
            return;
        };
        let removed = {
            let mut links = parent.links.lock();
            let index = links
                .children
                .iter()
                .position(|child| core::ptr::eq(Arc::as_ptr(child), self));
            index.map(|index| links.children.remove(index))
        };
        if removed.is_some() {
            parent.signals.post_child_removed();
        }
        drop(removed);
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
    ///
    /// A process whose startup failed leaves the process tree, as if it had
    /// never been created, except that its parent learns it was removed.
    pub fn fail_start(
        &self,
        error: BrokerError,
        abnormal: bool,
        expected_shutdown: bool,
    ) -> Result<()> {
        let shutdown = {
            let _tree = self.core.process_tree.lock();
            let shutdown = {
                let mut state = self.state.lock();
                match state.status {
                    ProcessStatus::Starting => {}
                    ProcessStatus::Running | ProcessStatus::Exiting | ProcessStatus::Zombie(_) => {
                        return Ok(());
                    }
                    ProcessStatus::Failed(error) => return Err(error),
                }
                if abnormal {
                    state.retirement.mark_abnormal();
                }
                state.status.transition(ProcessStatus::Failed(error))?;
                state.continue_startup_on_parent_death = false;
                if state.shutdown_request == ProcessShutdownRequest::None {
                    state.shutdown_request = if expected_shutdown {
                        ProcessShutdownRequest::Expected
                    } else {
                        ProcessShutdownRequest::Unexpected
                    };
                }
                state.shutdown.clone()
            };
            self.release_unstarted();
            shutdown
        };
        // Release the child's references before publishing the failure.
        if self.release_references() {
            self.state.lock().retirement.mark_abnormal();
        }
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

    /// Records final retirement disposition without releasing resources early.
    pub fn retire(&self, release_ids: bool) {
        let mut state = self.state.lock();
        state.retirement.retire(release_ids);
        state.shutdown = None;
    }

    /// Applies owner-death handling to every direct child process.
    ///
    /// Ordinary startup fails and prepared duplication startup continues.
    /// Calling this method more than once is harmless.
    pub fn handle_owner_death(&self) {
        self.cancellation.cancel();
        let pending_child_process = self.state.lock().pending_child_process.take();
        let mut shutdowns = Vec::new();
        let changed = {
            // Child creation checks cancellation under the tree lock, so once
            // this lock is taken every child created for a live owner is
            // listed.
            let _tree = self.core.process_tree.lock();
            let mut children = core::mem::take(&mut self.links.lock().children);
            let count = children.len();
            children.retain(|child| {
                let (failed, shutdown) = child.handle_parent_death();
                shutdowns.extend(shutdown);
                !failed
            });
            let changed = children.len() != count;
            self.links.lock().children = children;
            changed
        };
        if changed {
            self.core.process_lifecycle_sink.changed();
        }
        for shutdown in shutdowns {
            shutdown();
        }
        if let Some(PendingChild { process: child, .. }) = pending_child_process {
            child.discard();
        }
    }

    pub(crate) fn with_live_owner<T>(&self, operation: impl FnOnce() -> T) -> Result<T> {
        let state = self.state.lock();
        if !self.is_active(&state) {
            return Err(BrokerError::PeerClosed);
        }
        Ok(operation())
    }

    /// Returns whether this process's association is live and its process is
    /// not retired.
    ///
    /// Callers hold the state lock, which orders this check against
    /// [`Self::handle_owner_death`].
    fn is_active(&self, state: &BrokerProcessState) -> bool {
        !self.cancellation.is_cancelled()
            && matches!(state.retirement, ProcessRetirement::Active { .. })
    }

    /// Returns whether this active process is running and accepts
    /// guest-originated operations.
    fn accepts_operations(&self, state: &BrokerProcessState) -> bool {
        self.is_active(state) && matches!(state.status, ProcessStatus::Running)
    }

    /// Returns whether this active process is still waiting to start.
    fn awaits_startup(&self, state: &BrokerProcessState) -> bool {
        self.is_active(state) && matches!(state.status, ProcessStatus::Starting)
    }

    pub(crate) fn is_child_of(&self, parent: &BrokerProcess) -> bool {
        // The weak reference keeps the parent's allocation, so its address
        // cannot be reused by another process.
        self.links
            .lock()
            .parent
            .as_ref()
            .is_some_and(|own_parent| core::ptr::eq(own_parent.as_ptr(), parent))
    }

    /// Fails ordinary startup after the parent's owner dies, returning
    /// whether it failed and the runner shutdown to run.
    ///
    /// A child whose startup failed leaves the process tree. Callers hold the
    /// core's process tree lock and remove the child from its parent.
    fn handle_parent_death(&self) -> (bool, Option<ProcessShutdown>) {
        let mut state = self.state.lock();
        if state.status != ProcessStatus::Starting || state.continue_startup_on_parent_death {
            return (false, None);
        }
        state
            .status
            .transition(ProcessStatus::Failed(BrokerError::PeerClosed))
            .expect("starting child rejection must be a valid transition");
        if state.shutdown_request == ProcessShutdownRequest::None {
            state.shutdown_request = ProcessShutdownRequest::Expected;
        }
        let mut links = self.links.lock();
        links.released = true;
        links.parent = None;
        (true, state.shutdown.clone())
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
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
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
        let thread_id = ThreadId(raw_id);
        assert!(
            threads.insert(thread_id),
            "the ID allocator returned an occupied thread ID"
        );
        Ok(thread_id)
    }

    /// Records broker thread exit after its local task teardown completes.
    pub fn exit_thread(&self, thread_id: ThreadId) -> Result<()> {
        let mut threads = self.threads.lock();
        if !threads.remove(&thread_id) {
            return Err(BrokerError::UnknownObject);
        }
        drop(threads);
        self.core
            .active_thread_count
            .fetch_sub(1, Ordering::Relaxed);
        self.core.ids.lock().release(thread_id.0);
        Ok(())
    }

    /// Cancels this process's association because it is ending.
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
            None,
        );

        Ok(handle)
    }

    /// Duplicates a supported object reference into another process.
    ///
    /// The returned handle is owned by `target` and refers to the same
    /// underlying event, file, or pipe endpoint. `rights` must be nonempty, allowed by
    /// the target's policy, and no broader than the source reference's rights.
    /// The source reference is unchanged. Socket and process references are
    /// not supported because their readiness registration is currently bound
    /// to one process and handle.
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

        if !object.read().is_duplicable() {
            return Err(BrokerError::UnsupportedOperation);
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

    /// Publishes readiness of all of this process's references through
    /// `readiness_sink` for object kinds that need it, skipping references
    /// that already publish readiness.
    ///
    /// Pipe references start publishing once the process shares objects,
    /// since only then can another process change them. Sharing one reference
    /// can expose objects behind others, such as a pipe's other endpoint, so
    /// all of them register. Connection setup calls this for references
    /// duplicated into the process before it connected, including files whose
    /// readiness changes outside broker requests, and
    /// [`Self::duplicate_object_references_to_child`] before sharing more.
    pub fn register_readiness(&self, readiness_sink: &Arc<dyn ReadinessSink>) -> Result<()> {
        let process_references = self.references.lock();
        let mut references = self.core.references.write();
        for &handle in &process_references.handles {
            let reference = references
                .get_mut(&handle)
                .filter(|reference| reference.owner == self.id)
                .ok_or(BrokerError::UnknownObject)?;
            if reference.readiness.is_none() {
                reference.readiness = reference.object.read().watch(handle, readiness_sink)?;
            }
        }
        Ok(())
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
                None,
            );
        }
        Ok((first_handle, second_handle))
    }

    pub(crate) fn reserve_object_reference(
        &self,
        rights: ObjectRights,
    ) -> Result<PendingObjectReference<'_>> {
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
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |pending| {
                pending.checked_add(1)
            })
            .map_err(|_| BrokerError::ResourceExhausted)?;
        process_references.pending_handles = next_process_pending;
        Ok(PendingObjectReference {
            process: self,
            handle,
            rights,
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
        readiness: Option<ReadinessRegistration>,
    ) {
        let process_reference_index = reference_handles.len();
        references.insert(
            handle,
            ObjectReference {
                object,
                owner: self.id,
                rights,
                process_reference_index,
                readiness,
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
        object::readiness(&object)
    }

    /// Returns the access mode and status flags of a broker-owned object.
    pub fn get_status_flags(&self, handle: ObjectHandle) -> Result<FileStatusFlags> {
        let object = self
            .authorized_object_with_any_rights(handle, ObjectRights::WAIT | ObjectRights::WRITE)?;
        object::get_status_flags(self, &object)
    }

    /// Changes status flags of a broker-owned object, which every reference to the object
    /// shares.
    ///
    /// Fails with [`BrokerError::UnsupportedOperation`] if `request.mask` has flags outside
    /// [`FileOpenFlags::STATUS`].
    pub fn set_status_flags(&self, request: SetStatusFlagsRequest) -> Result<()> {
        if !FileOpenFlags::STATUS.contains(request.mask) {
            return Err(BrokerError::UnsupportedOperation);
        }
        let object = self.authorized_object_with_any_rights(
            request.handle,
            ObjectRights::WAIT | ObjectRights::WRITE,
        )?;
        object::set_status_flags(self, &object, request.mask, request.flags)
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
    /// Calling this method more than once is harmless. It never takes the
    /// core's process tree lock, so a process may drop while that lock is
    /// held.
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

        let mut invariant_fault = self.release_references();
        if self.core.processes.write().remove(&self.id).is_none() {
            invariant_fault = true;
        }
        let release_ids = release_ids && !invariant_fault;
        self.release_threads(release_ids);
        if release_ids {
            self.core.ids.lock().release(self.id.0);
        }
        self.core.process_lifecycle_sink.changed();
    }

    /// Releases every object reference and provider socket state owned by this
    /// process, returning whether an accounting fault was observed.
    ///
    /// Calling this method more than once is harmless.
    fn release_references(&self) -> bool {
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
        invariant_fault
    }

    /// Removes every thread owned by this process, optionally releasing their
    /// IDs and global thread accounting.
    fn release_threads(&self, release_ids: bool) {
        let threads = core::mem::take(&mut *self.threads.lock());
        if release_ids {
            self.core
                .active_thread_count
                .fetch_sub(threads.len(), Ordering::Relaxed);
            let mut ids = self.core.ids.lock();
            for thread_id in threads {
                ids.release(thread_id.0);
            }
        }
    }
}

pub(crate) struct PendingObjectReference<'process> {
    process: &'process BrokerProcess,
    handle: ObjectHandle,
    rights: ObjectRights,
    active: bool,
}

impl PendingObjectReference<'_> {
    pub(crate) const fn handle(&self) -> ObjectHandle {
        self.handle
    }

    pub(crate) fn commit(self, object: ObjectEntry) -> Result<ObjectHandle> {
        self.commit_with_readiness(object, None)
    }

    /// Commits `object`, whose reference publishes readiness through
    /// `readiness`, if any.
    pub(crate) fn commit_with_readiness(
        mut self,
        object: ObjectEntry,
        readiness: Option<ReadinessRegistration>,
    ) -> Result<ObjectHandle> {
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
        self.process.insert_object_reference(
            &mut references,
            &mut process_references.handles,
            self.handle,
            Arc::new(RwLock::new(object)),
            self.rights,
            readiness,
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
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |pending| {
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
    use core::any::Any;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{
        BrokerProcess, ProcessImage, ProcessLifecycleSink, ProcessReferences, ProcessStatus,
        Result, release_pending_reference,
    };
    use crate::readiness::ReadinessSink;
    use crate::stdio::StdioOutputStream;
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
    use litebox_broker_protocol::process::{ChildExit, ChildSelector, ProcessExitStatus};
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::signal::SignalEvent;
    use litebox_broker_protocol::{ObjectHandle, ProcessId};
    use std::{boxed::Box, sync::Arc, vec, vec::Vec};

    const TEST_MAX_REFERENCES: usize = 4;
    const TEST_MAX_PIPE_CAPACITY: usize = 8;
    const TEST_MAX_REFERENCES_PER_PROCESS: usize = 2;
    const TEST_MAX_PIPE_CAPACITY_PER_PROCESS: usize = 4;
    const ROOT: FileUser = FileUser { user: 0, group: 0 };
    const EXITED: ProcessExitStatus = ProcessExitStatus::Exited { code: 23 };
    const SIGNALED: ProcessExitStatus = ProcessExitStatus::Signaled { signal: 11 };

    fn child_exit(child: &BrokerProcess, exit_status: ProcessExitStatus) -> ChildExit {
        ChildExit {
            process_id: child.id(),
            exit_status,
        }
    }

    fn child_exited(child: &BrokerProcess, exit_status: ProcessExitStatus) -> SignalEvent {
        SignalEvent::ChildExited(child_exit(child, exit_status))
    }

    /// Creates a starting child of `parent`.
    fn child_of(parent: &BrokerProcess) -> Arc<BrokerProcess> {
        parent
            .core
            .create_process(parent.caller_credential(), Some(parent.id()))
            .unwrap()
    }

    /// Starts `process` if it is starting, then has it exit with
    /// `exit_status`.
    fn run_to_exit(process: &BrokerProcess, exit_status: ProcessExitStatus) {
        if process.startup_result().is_none() {
            process.complete_start().unwrap();
        }
        process.retire(true);
        process.complete_exit(exit_status).unwrap();
    }

    /// Opens `process`'s signals, through which it learns of child exits.
    fn open_signals(
        process: &BrokerProcess,
    ) -> (
        ObjectHandle,
        Arc<crate::readiness::tests::TestReadinessSink>,
    ) {
        let sink = readiness_sink();
        (crate::signal::open(process, sink.clone()).unwrap(), sink)
    }

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
            .links
            .lock()
            .parent
            .as_ref()
            .and_then(alloc::sync::Weak::upgrade)
            .map(|parent| parent.id())
    }

    fn prepared_duplication(parent: &Arc<BrokerProcess>) -> Arc<BrokerProcess> {
        let child = parent
            .core
            .create_process(parent.caller_credential(), Some(parent.id()))
            .unwrap();
        parent.prepare_duplication_child(&child).unwrap();
        child
    }

    fn process_statuses() -> [ProcessStatus; 5] {
        use ProcessStatus as State;

        [
            State::Starting,
            State::Running,
            State::Exiting,
            State::Failed(BrokerError::PeerClosed),
            State::Zombie(EXITED),
        ]
    }

    #[test]
    fn process_status_transition_matrix() {
        use ProcessStatus as State;

        let failed = State::Failed(BrokerError::PeerClosed);
        let states = process_statuses();
        let allowed = [
            (State::Starting, State::Running),
            (State::Starting, State::Exiting),
            (State::Starting, failed),
            (State::Running, State::Exiting),
            (State::Exiting, State::Zombie(EXITED)),
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

    fn readiness_sink() -> Arc<crate::readiness::tests::TestReadinessSink> {
        Arc::new(crate::readiness::tests::TestReadinessSink::default())
    }

    /// Returns the pipe wakeups `sink` received, which republish so a sink
    /// cannot drop them as unchanged.
    fn take_republished(
        sink: &crate::readiness::tests::TestReadinessSink,
    ) -> std::vec::Vec<(ObjectHandle, ReadinessFlags)> {
        core::mem::take(&mut *sink.republished.lock().unwrap())
    }

    #[test]
    fn pipe_readiness_reaches_every_process_holding_an_endpoint() {
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .build()
        .unwrap();
        let parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        parent.complete_start().unwrap();
        let parent_sink = readiness_sink();
        let child_sink = readiness_sink();
        let (reader, writer) = crate::pipe::create(&parent, 4, 2, FileOpenFlags::NONE).unwrap();
        let identity = parent.allocate_child_process().unwrap();
        // Sharing only the write end still lets the child wake the parent's reader.
        let child_writer = parent
            .duplicate_object_references_to_child(
                identity.process_id,
                &[writer],
                &(parent_sink.clone() as Arc<dyn ReadinessSink>),
            )
            .unwrap()[0];
        let child = parent.take_child_process(identity.process_id).unwrap();
        for _ in 0..2 {
            child
                .register_readiness(&(child_sink.clone() as Arc<dyn ReadinessSink>))
                .unwrap();
        }
        child.complete_start().unwrap();

        assert_eq!(crate::pipe::write(&child, child_writer, &[1, 2, 3]), Ok(3));
        assert_eq!(
            take_republished(&parent_sink),
            [(reader, ReadinessFlags::READ)]
        );
        assert_eq!(take_republished(&child_sink), []);

        // Freeing space that an atomic write still cannot use leaves `WRITE`
        // unchanged but must still wake writers.
        assert_eq!(
            crate::pipe::write(&parent, writer, &[4, 5]),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(
            crate::pipe::read(&parent, reader, 1),
            Ok(std::vec::Vec::from([1]))
        );
        assert_eq!(
            take_republished(&parent_sink),
            [(writer, ReadinessFlags::WRITE)]
        );
        assert_eq!(
            take_republished(&child_sink),
            [(child_writer, ReadinessFlags::WRITE)]
        );

        assert_eq!(parent.close_object_reference(writer), Ok(()));
        assert_eq!(*parent_sink.retired.lock().unwrap(), [writer]);
        assert_eq!(take_republished(&parent_sink), []);
        assert_eq!(take_republished(&child_sink), []);

        assert_eq!(child.close_object_reference(child_writer), Ok(()));
        let hangup = ReadinessFlags::READ | ReadinessFlags::HANGUP;
        assert_eq!(take_republished(&parent_sink), [(reader, hangup)]);
        assert_eq!(take_republished(&child_sink), []);
        assert_eq!(*child_sink.retired.lock().unwrap(), [child_writer]);

        assert_eq!(parent.close_object_reference(reader), Ok(()));
        assert_eq!(*parent_sink.retired.lock().unwrap(), [writer, reader]);
        assert_eq!(take_republished(&parent_sink), []);
        assert_eq!(take_republished(&child_sink), []);
    }

    #[test]
    fn zombie_remains_until_reaped() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_limits(BrokerCoreLimits::DEFAULT.with_process_limit(2))
        .build()
        .unwrap();
        let root = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        let (signals, sink) = open_signals(&root);
        let child = child_of(&root);
        let child_id = child.id();
        assert_eq!(
            root.reap_child(ChildSelector::Any),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(root.check_readiness(signals), Ok(ReadinessFlags::default()));
        child.complete_start().unwrap();
        let (read, write) = crate::pipe::create(&root, 1, 1, FileOpenFlags::NONE).unwrap();
        root.duplicate_object_reference_to(write, &child, ObjectRights::WRITE)
            .unwrap();
        root.close_object_reference(write).unwrap();

        child.retire(true);
        child.complete_exit(EXITED).unwrap();
        child.complete_exit(SIGNALED).unwrap();
        drop(child);

        assert_eq!(
            *sink.republished.lock().unwrap(),
            [(signals, ReadinessFlags::READ)]
        );
        assert_eq!(
            crate::signal::take(&root, signals),
            Ok(SignalEvent::ChildExited(ChildExit {
                process_id: child_id,
                exit_status: EXITED,
            }))
        );
        assert!(
            root.check_readiness(read)
                .unwrap()
                .contains(ReadinessFlags::HANGUP)
        );
        assert_eq!(broker.active_thread_count.load(Ordering::Relaxed), 0);
        assert!(broker.processes.read().contains_key(&child_id));
        assert!(matches!(
            broker.allocate_process(CallerCredential::Unauthenticated, None),
            Err(BrokerError::ResourceExhausted)
        ));
        assert_eq!(
            root.process_info(child_id).map(|info| info.parent),
            Ok(Some(root.id()))
        );

        assert_eq!(
            root.reap_child(ChildSelector::Process(child_id)),
            Ok(ChildExit {
                process_id: child_id,
                exit_status: EXITED,
            })
        );

        assert!(!broker.processes.read().contains_key(&child_id));
        assert_eq!(root.process_info(child_id), Err(BrokerError::UnknownObject));
        assert_eq!(
            root.reap_child(ChildSelector::Any),
            Err(BrokerError::UnknownObject)
        );
        assert!(
            broker
                .allocate_process(CallerCredential::Unauthenticated, None)
                .is_ok()
        );
    }

    #[test]
    fn reaping_selects_the_oldest_exited_matching_child() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let root = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        let first = child_of(&root);
        let second = child_of(&root);
        let third = child_of(&root);
        let pending = child_of(&root);
        crate::process_group::set(&root, third.id(), third.id()).unwrap();
        let other = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let reap = |selector| root.reap_child(selector);

        // A child that has not started counts as live.
        assert_eq!(reap(ChildSelector::Any), Err(BrokerError::WouldBlock));
        run_to_exit(&third, SIGNALED);
        run_to_exit(&second, EXITED);
        run_to_exit(&first, EXITED);
        assert_eq!(
            reap(ChildSelector::Process(other.id())),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            reap(ChildSelector::ProcessGroup(other.id())),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            reap(ChildSelector::ProcessGroup(third.id())),
            Ok(child_exit(&third, SIGNALED))
        );
        assert_eq!(
            reap(ChildSelector::ProcessGroup(third.id())),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            reap(ChildSelector::Process(second.id())),
            Ok(child_exit(&second, EXITED))
        );
        assert_eq!(
            reap(ChildSelector::ProcessGroup(root.id())),
            Ok(child_exit(&first, EXITED))
        );
        assert_eq!(
            reap(ChildSelector::Process(pending.id())),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(reap(ChildSelector::Any), Err(BrokerError::WouldBlock));

        // Only a running process reaps.
        assert_eq!(
            pending.reap_child(ChildSelector::Any),
            Err(BrokerError::PeerClosed)
        );
        run_to_exit(&pending, EXITED);
        assert_eq!(reap(ChildSelector::Any), Ok(child_exit(&pending, EXITED)));
        assert_eq!(reap(ChildSelector::Any), Err(BrokerError::UnknownObject));
    }

    #[test]
    fn orphans_move_to_the_nearest_adopting_ancestor() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let root = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        let adopter = child_of(&root);
        adopter.complete_start().unwrap();
        let middle = child_of(&adopter);
        middle.complete_start().unwrap();
        let exiting = child_of(&middle);
        exiting.complete_start().unwrap();
        let running = child_of(&exiting);
        running.complete_start().unwrap();
        let zombie = child_of(&exiting);
        run_to_exit(&zombie, SIGNALED);
        root.set_orphan_adoption(true).unwrap();
        adopter.set_orphan_adoption(true).unwrap();
        let (signals, _) = open_signals(&adopter);

        run_to_exit(&exiting, EXITED);

        // The adopter learns of the adopted zombie's exit, and reaps it after
        // its own children.
        assert_eq!(parent_id(&running), Some(adopter.id()));
        assert_eq!(parent_id(&zombie), Some(adopter.id()));
        assert_eq!(
            crate::signal::take(&adopter, signals),
            Ok(child_exited(&zombie, SIGNALED))
        );
        assert_eq!(
            middle.reap_child(ChildSelector::Any),
            Ok(child_exit(&exiting, EXITED))
        );
        assert_eq!(
            adopter.reap_child(ChildSelector::Any),
            Ok(child_exit(&zombie, SIGNALED))
        );
        assert_eq!(
            adopter.reap_child(ChildSelector::Any),
            Err(BrokerError::WouldBlock)
        );
        let info = root.process_info(running.id()).unwrap();
        assert_eq!(info.creator, Some(exiting.id()));
        assert_eq!(info.parent, Some(adopter.id()));

        // Once the adopter exits, the next adopting ancestor adopts.
        run_to_exit(&adopter, EXITED);
        assert_eq!(parent_id(&running), Some(root.id()));
        assert_eq!(parent_id(&middle), Some(root.id()));
        run_to_exit(&running, EXITED);
        assert_eq!(
            root.reap_child(ChildSelector::Any),
            Ok(child_exit(&adopter, EXITED))
        );
        assert_eq!(
            root.reap_child(ChildSelector::Any),
            Ok(child_exit(&running, EXITED))
        );
        assert_eq!(
            root.reap_child(ChildSelector::Any),
            Err(BrokerError::WouldBlock)
        );
    }

    #[test]
    fn orphans_without_an_adopter_are_reaped_when_they_exit() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let root = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        let zombie = child_of(&root);
        let zombie_id = zombie.id();
        run_to_exit(&zombie, EXITED);
        drop(zombie);
        let running = child_of(&root);
        let running_id = running.id();
        running.complete_start().unwrap();

        root.handle_owner_death();
        root.complete_exit(EXITED).unwrap();

        // The exited root and its zombie child no longer exist.
        assert!(!broker.processes.read().contains_key(&zombie_id));
        assert_eq!(
            running.process_info(root.id()),
            Err(BrokerError::UnknownObject)
        );
        let info = running.process_info(running_id).unwrap();
        assert_eq!(info.creator, Some(root.id()));
        assert_eq!(info.parent, None);
        running.retire(true);
        running.complete_exit(EXITED).unwrap();
        drop(running);
        assert!(!broker.processes.read().contains_key(&running_id));
    }

    #[test]
    fn exit_in_progress_is_neither_observable_nor_repeated() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let root = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        let (signals, sink) = open_signals(&root);
        let child = child_of(&root);
        child.complete_start().unwrap();
        let (read, write) = crate::pipe::create(&root, 1, 1, FileOpenFlags::NONE).unwrap();
        root.duplicate_object_reference_to(write, &child, ObjectRights::WRITE)
            .unwrap();
        root.close_object_reference(write).unwrap();
        // Another caller has claimed the exit and is still releasing resources.
        child.state.lock().status = ProcessStatus::Exiting;

        child.complete_exit(EXITED).unwrap();

        assert_eq!(child.state.lock().status, ProcessStatus::Exiting);
        assert!(
            !root
                .check_readiness(read)
                .unwrap()
                .contains(ReadinessFlags::HANGUP)
        );
        assert_eq!(
            root.reap_child(ChildSelector::Any),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(root.check_readiness(signals), Ok(ReadinessFlags::default()));
        assert!(sink.republished.lock().unwrap().is_empty());
    }

    #[test]
    fn reported_exit_status_replaces_runner_status() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let root = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        let child = child_of(&root);
        assert_eq!(
            child.report_exit_status(SIGNALED),
            Err(BrokerError::PeerClosed)
        );
        child.complete_start().unwrap();

        child.report_exit_status(SIGNALED).unwrap();
        child.retire(true);
        child.complete_exit(EXITED).unwrap();

        assert_eq!(
            root.reap_child(ChildSelector::Any),
            Ok(child_exit(&child, SIGNALED))
        );
    }

    #[test]
    fn children_apply_reaping_setting_when_they_terminate() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let root = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        let (signals, sink) = open_signals(&root);
        let zombie = child_of(&root);
        let reaped = child_of(&root);
        let failed = child_of(&root);
        assert_eq!(zombie.set_child_reaping(true), Err(BrokerError::PeerClosed));

        run_to_exit(&zombie, EXITED);
        root.set_child_reaping(true).unwrap();
        run_to_exit(&reaped, SIGNALED);
        assert_eq!(
            failed.fail_start(BrokerError::PeerClosed, false, true),
            Err(BrokerError::PeerClosed)
        );

        // Both exits are notified, coalescing into the first, but only the
        // one before reaping was enabled is kept. A failed child is removed.
        assert_eq!(
            *sink.republished.lock().unwrap(),
            [
                (signals, ReadinessFlags::READ),
                (signals, ReadinessFlags::READ)
            ]
        );
        assert_eq!(
            crate::signal::take(&root, signals),
            Ok(child_exited(&zombie, EXITED))
        );
        assert_eq!(
            crate::signal::take(&root, signals),
            Ok(SignalEvent::ChildRemoved)
        );
        assert_eq!(
            crate::signal::take(&root, signals),
            Err(BrokerError::WouldBlock)
        );
        for child in [&reaped, &failed] {
            assert_eq!(
                root.process_info(child.id()),
                Err(BrokerError::UnknownObject)
            );
        }
        assert_eq!(
            root.reap_child(ChildSelector::Any),
            Ok(child_exit(&zombie, EXITED))
        );
        assert_eq!(
            root.reap_child(ChildSelector::Any),
            Err(BrokerError::UnknownObject)
        );
    }

    #[test]
    fn startup_failure_is_not_published_as_process_exit() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let root = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        let (signals, sink) = open_signals(&root);
        let child = child_of(&root);
        let child_id = child.id();

        assert_eq!(
            child.fail_start(BrokerError::PeerClosed, false, false),
            Err(BrokerError::PeerClosed)
        );
        assert_eq!(child.complete_exit(EXITED), Err(BrokerError::PeerClosed));
        assert_eq!(
            child.state.lock().status,
            ProcessStatus::Failed(BrokerError::PeerClosed)
        );
        // The parent learns the child is gone, but not that it exited.
        assert_eq!(sink.republished.lock().unwrap().len(), 1);
        assert_eq!(
            crate::signal::take(&root, signals),
            Ok(SignalEvent::ChildRemoved)
        );
        assert_eq!(
            crate::signal::take(&root, signals),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(
            root.reap_child(ChildSelector::Any),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(root.process_info(child_id), Err(BrokerError::UnknownObject));
        child.retire(true);
        drop(child);

        assert!(!broker.processes.read().contains_key(&child_id));
    }

    #[test]
    fn process_duplication_policy_is_enforced_at_admission() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        parent.complete_start().unwrap();
        let child = broker
            .allocate_process(parent.caller_credential(), Some(parent.id()))
            .unwrap();

        assert!(matches!(
            parent.prepare_duplication_child(&child),
            Err(BrokerError::PolicyDenied)
        ));
        child.complete_start().unwrap();
    }

    #[test]
    fn child_process_allocation_is_policy_gated() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        parent.complete_start().unwrap();
        assert_eq!(
            parent.allocate_child_process(),
            Err(BrokerError::PolicyDenied)
        );
    }

    #[test]
    fn child_process_allocation_allows_one_pending_child() {
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .with_limits(BrokerCoreLimits::DEFAULT.with_process_limit(2))
        .build()
        .unwrap();
        let parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        parent.complete_start().unwrap();
        let identity = parent.allocate_child_process().unwrap();
        let process_id = identity.process_id;
        assert_eq!(
            parent.allocate_child_process(),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(parent.references.lock().handles, []);
        assert!(matches!(
            parent.take_child_process(ProcessId(process_id.0 + 1)),
            Err(BrokerError::UnknownObject)
        ));

        let child = parent.take_child_process(process_id).unwrap();
        assert_eq!(child.id(), process_id);
        assert_eq!(child.initial_thread_id(), identity.initial_thread_id);
        assert_eq!(parent_id(&child), Some(parent.id()));
        assert_eq!(child.startup_result(), None);
        child.complete_start().unwrap();
        assert!(child.is_running());
    }

    #[test]
    fn cancelled_child_process_vanishes() {
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .build()
        .unwrap();
        let parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        parent.complete_start().unwrap();
        let (signals, _) = open_signals(&parent);
        let process_id = parent.allocate_child_process().unwrap().process_id;
        let child = parent.pending_child_process(process_id).unwrap();
        assert_eq!(
            parent.cancel_child_process(ProcessId(process_id.0 + 1)),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            parent.reap_child(ChildSelector::Any),
            Err(BrokerError::WouldBlock)
        );

        parent.cancel_child_process(process_id).unwrap();

        // A reap that found the child live learns it is gone.
        assert_eq!(
            crate::signal::take(&parent, signals),
            Ok(SignalEvent::ChildRemoved)
        );
        assert_eq!(child.startup_result(), Some(Err(BrokerError::PeerClosed)));
        assert_eq!(
            parent.process_info(process_id),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            parent.reap_child(ChildSelector::Any),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            parent.cancel_child_process(process_id),
            Err(BrokerError::UnknownObject)
        );
        drop(child);
        assert!(!broker.processes.read().contains_key(&process_id));
        // The pending slot is free again.
        parent.allocate_child_process().unwrap();
    }

    #[test]
    fn adopted_child_that_fails_to_start_is_reported_removed() {
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .build()
        .unwrap();
        let root = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        root.set_orphan_adoption(true).unwrap();
        let parent = child_of(&root);
        parent.complete_start().unwrap();
        let starting = prepared_duplication(&parent);
        run_to_exit(&parent, EXITED);
        assert_eq!(parent_id(&starting), Some(root.id()));
        assert_eq!(
            root.reap_child(ChildSelector::Any),
            Ok(child_exit(&parent, EXITED))
        );
        assert_eq!(
            root.reap_child(ChildSelector::Any),
            Err(BrokerError::WouldBlock)
        );
        let (signals, _) = open_signals(&root);
        assert_eq!(
            crate::signal::take(&root, signals),
            Ok(child_exited(&parent, EXITED))
        );

        assert_eq!(
            starting.fail_start(BrokerError::PeerClosed, false, true),
            Err(BrokerError::PeerClosed)
        );

        assert_eq!(
            crate::signal::take(&root, signals),
            Ok(SignalEvent::ChildRemoved)
        );
        assert_eq!(
            root.reap_child(ChildSelector::Any),
            Err(BrokerError::UnknownObject)
        );
    }

    #[test]
    fn owner_death_fails_and_retires_pending_child_process() {
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .build()
        .unwrap();
        let parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        parent.complete_start().unwrap();
        let process_id = parent.allocate_child_process().unwrap().process_id;
        let child = broker
            .processes
            .read()
            .get(&process_id)
            .and_then(alloc::sync::Weak::upgrade)
            .unwrap();

        parent.handle_owner_death();

        assert_eq!(child.startup_result(), Some(Err(BrokerError::PeerClosed)));
        assert!(child.is_released());
        assert!(parent.links.lock().children.is_empty());
        assert!(matches!(
            parent.take_child_process(process_id),
            Err(BrokerError::PeerClosed)
        ));
    }

    #[test]
    fn pending_child_exit_leaves_waitable_zombie_without_starting() {
        let lifecycle = Arc::new(TestProcessLifecycleSink::default());
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .build()
        .unwrap()
        .with_process_lifecycle_sink(lifecycle.clone());
        let parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        parent.complete_start().unwrap();
        let (signals, sink) = open_signals(&parent);
        let process_id = parent.allocate_child_process().unwrap().process_id;
        let changes = lifecycle.changes.load(Ordering::Relaxed);
        let threads = broker.active_thread_count.load(Ordering::Relaxed);

        assert_eq!(parent.exit_child_process(process_id, EXITED), Ok(()));

        let exit = ChildExit {
            process_id,
            exit_status: EXITED,
        };
        assert_eq!(
            crate::signal::take(&parent, signals),
            Ok(SignalEvent::ChildExited(exit))
        );
        assert_eq!(lifecycle.changes.load(Ordering::Relaxed), changes + 1);
        assert_eq!(
            *sink.republished.lock().unwrap(),
            [(signals, ReadinessFlags::READ)]
        );
        assert_eq!(
            broker.active_thread_count.load(Ordering::Relaxed),
            threads - 1
        );
        assert_eq!(
            parent.exit_child_process(process_id, SIGNALED),
            Err(BrokerError::UnknownObject)
        );

        // The zombie stays until reaped.
        assert!(broker.processes.read().contains_key(&process_id));
        assert_eq!(parent.reap_child(ChildSelector::Any), Ok(exit));
        assert!(!broker.processes.read().contains_key(&process_id));
    }

    #[test]
    fn pending_child_memory_image_is_created_once_and_taken_with_child() {
        type Writes = Arc<std::sync::Mutex<Vec<(u64, Vec<u8>)>>>;
        struct TestImage(Writes);

        impl ProcessImage for TestImage {
            fn write(&mut self, offset: u64, data: &[u8]) -> Result<()> {
                self.0.lock().unwrap().push((offset, data.to_vec()));
                Ok(())
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .with_limits(BrokerCoreLimits::DEFAULT.with_child_image_size_limits(8, 8))
        .build()
        .unwrap();
        let parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        parent.complete_start().unwrap();
        let process_id = parent.allocate_child_process().unwrap().process_id;
        let writes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let created = AtomicUsize::new(0);
        let create = |capacity| {
            assert_eq!(capacity, 8);
            created.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(TestImage(Arc::clone(&writes))) as Box<dyn ProcessImage>)
        };
        let write = |process_id, offset, data: &[u8]| {
            parent.write_child_memory(process_id, offset, data.len() as u64, create, |image| {
                image.write(offset, data)
            })
        };

        assert_eq!(
            write(ProcessId(process_id.0 + 1), 0, &[1]),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            write(process_id, 7, &[1, 2]),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            write(process_id, u64::MAX, &[1]),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(created.load(Ordering::Relaxed), 0);
        assert_eq!(write(process_id, 6, &[1, 2]), Ok(()));
        assert_eq!(write(process_id, 0, &[3]), Ok(()));
        assert_eq!(created.load(Ordering::Relaxed), 1);
        assert_eq!(broker.reserved_child_image_size.load(Ordering::Relaxed), 8);

        let (child, image) = parent.take_child_process_with_image(process_id).unwrap();
        assert_eq!(child.id(), process_id);
        let image = image.unwrap();
        assert!(image.image().as_any().downcast_ref::<TestImage>().is_some());
        drop(image);
        assert_eq!(*writes.lock().unwrap(), [(6, vec![1, 2]), (0, vec![3])]);
        assert_eq!(Arc::strong_count(&writes), 1);
        assert_eq!(broker.reserved_child_image_size.load(Ordering::Relaxed), 0);
        assert_eq!(write(process_id, 0, &[1]), Err(BrokerError::UnknownObject));
        child.complete_start().unwrap();
    }

    #[test]
    fn child_images_share_the_broker_image_budget() {
        struct TestImage;

        impl ProcessImage for TestImage {
            fn write(&mut self, _offset: u64, _data: &[u8]) -> Result<()> {
                Ok(())
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .with_limits(BrokerCoreLimits::DEFAULT.with_child_image_size_limits(8, 12))
        .build()
        .unwrap();
        let pending_child = || {
            let parent = broker
                .allocate_process(CallerCredential::Unauthenticated, None)
                .unwrap();
            parent.complete_start().unwrap();
            let child = parent.allocate_child_process().unwrap().process_id;
            (parent, child)
        };
        let write = |parent: &BrokerProcess, child, offset, length| {
            parent.write_child_memory::<BrokerError>(
                child,
                offset,
                length,
                |_| Ok(Box::new(TestImage)),
                |_| Ok(()),
            )
        };
        let reserved = || broker.reserved_child_image_size.load(Ordering::Relaxed);
        let (first, first_child) = pending_child();
        let (second, second_child) = pending_child();

        assert_eq!(write(&first, first_child, 0, 8), Ok(()));
        // Rewriting bytes the image already holds takes no more of the budget.
        assert_eq!(write(&first, first_child, 2, 4), Ok(()));
        assert_eq!(write(&second, second_child, 0, 4), Ok(()));
        assert_eq!(
            write(&second, second_child, 4, 1),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(reserved(), 12);

        // A taken image keeps its share until it is dropped.
        let (child, image) = first.take_child_process_with_image(first_child).unwrap();
        assert_eq!(
            write(&second, second_child, 4, 1),
            Err(BrokerError::ResourceExhausted)
        );
        drop(image);
        assert_eq!(reserved(), 4);
        assert_eq!(write(&second, second_child, 4, 4), Ok(()));
        assert_eq!(reserved(), 8);
        child.complete_start().unwrap();

        second.exit_child_process(second_child, EXITED).unwrap();
        assert_eq!(reserved(), 0);
    }

    #[test]
    fn pending_child_exit_after_owner_death_is_rejected() {
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .build()
        .unwrap();
        let parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        parent.complete_start().unwrap();
        let identity = parent.allocate_child_process().unwrap();

        parent.handle_owner_death();

        assert_eq!(
            parent.exit_child_process(identity.process_id, EXITED),
            Err(BrokerError::PeerClosed)
        );
        assert!(parent.links.lock().children.is_empty());
    }

    #[test]
    fn pending_child_receives_references_until_it_terminates() {
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .build()
        .unwrap();
        let parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        parent.complete_start().unwrap();
        let child_id = parent.allocate_child_process().unwrap().process_id;
        let child = broker
            .processes
            .read()
            .get(&child_id)
            .and_then(alloc::sync::Weak::upgrade)
            .unwrap();
        let sink: Arc<dyn ReadinessSink> = readiness_sink();
        let first = crate::event::create(&parent, 1).unwrap();
        let second = crate::event::create(&parent, 0).unwrap();

        assert_eq!(
            parent.duplicate_object_references_to_child(ProcessId(child_id.0 + 1), &[first], &sink),
            Err(BrokerError::UnknownObject)
        );
        // A signals reference is not duplicable, so the child receives nothing.
        let signals = crate::signal::open(&parent, readiness_sink()).unwrap();
        assert_eq!(
            parent.duplicate_object_references_to_child(child_id, &[first, signals], &sink),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(child.references.lock().handles, []);

        let duplicates = parent
            .duplicate_object_references_to_child(child_id, &[first, second], &sink)
            .unwrap();
        assert_eq!(child.references.lock().handles, duplicates);
        assert_eq!(
            child.check_readiness(duplicates[0]),
            Ok(ReadinessFlags::READ | ReadinessFlags::WRITE)
        );
        assert_eq!(
            child.check_readiness(duplicates[1]),
            Ok(ReadinessFlags::WRITE)
        );

        parent.exit_child_process(child_id, EXITED).unwrap();
        assert_eq!(child.references.lock().handles, []);
        assert_eq!(
            parent.duplicate_object_references_to_child(child_id, &[first], &sink),
            Err(BrokerError::UnknownObject)
        );

        // A child that fails to start also releases them while its parent still holds it.
        let identity = parent.allocate_child_process().unwrap();
        parent
            .duplicate_object_references_to_child(identity.process_id, &[first], &sink)
            .unwrap();
        let failed = parent.take_child_process(identity.process_id).unwrap();
        assert_eq!(
            failed.fail_start(BrokerError::PeerClosed, false, true),
            Err(BrokerError::PeerClosed)
        );
        assert_eq!(failed.references.lock().handles, []);
        assert_eq!(
            parent.check_readiness(first),
            Ok(ReadinessFlags::READ | ReadinessFlags::WRITE)
        );
    }

    #[test]
    fn duplication_preparation_validates_the_created_child() {
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .build()
        .unwrap();
        let owner = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        owner.complete_start().unwrap();
        let other_owner = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        other_owner.complete_start().unwrap();
        let child = broker
            .create_process(owner.caller_credential(), Some(owner.id()))
            .unwrap();

        assert_eq!(
            other_owner.prepare_duplication_child(&child),
            Err(BrokerError::Internal)
        );
        assert_eq!(child.startup_result(), None);
        owner.prepare_duplication_child(&child).unwrap();
        assert_eq!(
            owner.prepare_duplication_child(&child),
            Err(BrokerError::Internal)
        );
        child.complete_start().unwrap();
        assert!(child.is_running());
        assert_eq!(
            owner.prepare_duplication_child(&owner),
            Err(BrokerError::Internal)
        );
    }

    #[test]
    fn duplication_children_publish_independently() {
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .build()
        .unwrap();
        let parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        parent.complete_start().unwrap();
        let first_child = prepared_duplication(&parent);
        let second_child = prepared_duplication(&parent);

        first_child.complete_start().unwrap();
        second_child.complete_start().unwrap();

        assert!(first_child.is_running());
        assert!(second_child.is_running());
    }

    #[test]
    fn duplication_publication_survives_parent_teardown_and_rejects_child_failure() {
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .build()
        .unwrap();

        let cancelled_parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        cancelled_parent.complete_start().unwrap();
        let cancelled_child = prepared_duplication(&cancelled_parent);
        let unprepared_child = broker
            .allocate_process(
                cancelled_parent.caller_credential(),
                Some(cancelled_parent.id()),
            )
            .unwrap();
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let shutdown_count = Arc::clone(&shutdowns);
        cancelled_child.install_shutdown(Arc::new(move || {
            shutdown_count.fetch_add(1, Ordering::Relaxed);
        }));
        cancelled_parent.request_cancellation();

        cancelled_child.complete_start().unwrap();
        assert_eq!(cancelled_child.state.lock().status, ProcessStatus::Running);
        assert_eq!(shutdowns.load(Ordering::Relaxed), 0);
        assert!(matches!(
            cancelled_parent.prepare_duplication_child(&unprepared_child),
            Err(BrokerError::PeerClosed)
        ));

        let dead_parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        dead_parent.complete_start().unwrap();
        let dead_child = prepared_duplication(&dead_parent);
        dead_parent.handle_owner_death();

        dead_child.complete_start().unwrap();
        assert_eq!(dead_child.state.lock().status, ProcessStatus::Running);

        let live_parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        live_parent.complete_start().unwrap();
        let failed_child = prepared_duplication(&live_parent);
        assert_eq!(
            failed_child.fail_start(BrokerError::PeerClosed, false, true),
            Err(BrokerError::PeerClosed)
        );
        assert_eq!(failed_child.complete_start(), Err(BrokerError::PeerClosed));
    }

    #[test]
    fn process_and_thread_ids_share_one_numeric_namespace() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let first = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let thread = first.create_thread().unwrap();
        let second = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        parent.complete_start().unwrap();
        let child = broker
            .allocate_process(parent.caller_credential(), Some(parent.id()))
            .unwrap();
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let shutdown_count = Arc::clone(&shutdowns);
        child.install_shutdown(Arc::new(move || {
            shutdown_count.fetch_add(1, Ordering::Relaxed);
        }));

        parent.handle_owner_death();

        assert_eq!(child.startup_result(), Some(Err(BrokerError::PeerClosed)));
        assert_eq!(child.complete_start(), Err(BrokerError::PeerClosed));
        assert_eq!(shutdowns.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn owner_death_rejects_new_children() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let parent = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        parent.complete_start().unwrap();

        parent.handle_owner_death();

        assert!(matches!(
            broker.allocate_process(CallerCredential::Unauthenticated, Some(parent.id())),
            Err(BrokerError::PeerClosed)
        ));
    }

    #[test]
    fn owner_death_locks_only_direct_children() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let root = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        root.complete_start().unwrap();
        let parent = broker
            .allocate_process(CallerCredential::Unauthenticated, Some(root.id()))
            .unwrap();
        parent.complete_start().unwrap();

        let (locked_sender, locked_receiver) = std::sync::mpsc::sync_channel(0);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
        let locked_root = Arc::clone(&root);
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
        let completed_without_non_child = done_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .is_ok();

        release_sender.send(()).unwrap();
        lock_thread.join().unwrap();
        owner_death_thread.join().unwrap();
        assert!(completed_without_non_child);
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
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            broker.allocate_process(CallerCredential::Unauthenticated, None),
            Err(BrokerError::ResourceExhausted)
        ));
        assert_eq!(sink.changes.load(Ordering::Relaxed), 1);

        drop(retained);

        assert_eq!(sink.changes.load(Ordering::Relaxed), 2);
        assert!(
            broker
                .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let target = broker
            .allocate_process(source.caller_credential(), None)
            .unwrap();
        let source_handle = crate::event::create(&source, 1).unwrap();

        assert_eq!(
            source
                .duplicate_object_references_to(&[source_handle, ObjectHandle(u64::MAX)], &target,),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(target.references.lock().handles, []);
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
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let second = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let second = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let third = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();

        assert!(matches!(
            broker.allocate_process(CallerCredential::Unauthenticated, None),
            Err(BrokerError::ResourceExhausted)
        ));

        first.cleanup(true);
        assert!(
            broker
                .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let process_id = process.id();
        let thread_id = process.create_thread().unwrap();

        drop(process);
        assert_eq!(broker.active_thread_count.load(Ordering::Relaxed), 1);

        let first_replacement = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let second_replacement = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            broker.allocate_process(CallerCredential::Unauthenticated, None),
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let process_id = process.id();
        crate::event::create(&process, 1).unwrap();
        process.references.lock().handles.clear();

        drop(process);

        assert!(broker.references.read().is_empty());
        let replacement = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let target = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let denied_target = broker
            .allocate_process(CallerCredential::HostGuaranteed, None)
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

        let (reader, writer) = crate::pipe::create(&source, 4, 2, FileOpenFlags::NONE).unwrap();
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let target = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let mode = FileMode::from_bits(0o600).unwrap();
        let sink = readiness_sink();
        let readiness: Arc<dyn ReadinessSink> = sink.clone();
        let file = crate::fs::open(
            &source,
            "/file",
            ROOT,
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE,
            mode,
            &readiness,
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
                &readiness,
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
            &readiness,
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
            &readiness,
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
            &readiness,
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
                "/dev/urandom",
                ROOT,
                FileAccessMode::WriteOnly,
                FileOpenFlags::NONE,
                FileMode::default(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            broker.fs.read(&write_only_random, &mut [0], None),
            Ok(Err(FileError::NotForReading))
        );

        let read_only_null = broker
            .fs
            .open(
                "/dev/null",
                ROOT,
                FileAccessMode::ReadOnly,
                FileOpenFlags::NONE,
                FileMode::default(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            broker.fs.write(&read_only_null, &[0], None),
            Ok(Err(FileError::NotForWriting))
        );

        let stdout = crate::fs::open(
            &source,
            "/dev/stdout",
            ROOT,
            FileAccessMode::WriteOnly,
            FileOpenFlags::NONE,
            FileMode::default(),
            &readiness,
        )
        .unwrap()
        .unwrap();
        let duplicated_stdout = source
            .duplicate_object_reference_to(stdout, &target, ObjectRights::WRITE)
            .unwrap();
        assert_eq!(
            crate::fs::write(&source, stdout, b"source", None),
            Ok(Ok(6))
        );
        assert_eq!(
            crate::fs::write(&target, duplicated_stdout, b"target", None),
            Ok(Ok(6))
        );
        assert_eq!(
            stdio_provider.writes(),
            vec![
                (StdioOutputStream::Stdout, b"source".to_vec()),
                (StdioOutputStream::Stdout, b"target".to_vec()),
            ]
        );
        assert_eq!(source.close_object_reference(stdout), Ok(()));
        assert_eq!(target.close_object_reference(duplicated_stdout), Ok(()));

        let stdin = crate::fs::open(
            &source,
            "/dev/stdin",
            ROOT,
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONE,
            FileMode::default(),
            &readiness,
        )
        .unwrap()
        .unwrap();
        let duplicated_stdin = source
            .duplicate_object_reference_to(stdin, &target, ObjectRights::WAIT)
            .unwrap();
        let target_sink = readiness_sink();
        target
            .register_readiness(&(target_sink.clone() as Arc<dyn ReadinessSink>))
            .unwrap();
        assert_eq!(
            crate::fs::read(&source, stdin, &mut byte, None),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(source.check_readiness(stdin), Ok(ReadinessFlags::default()));
        take_republished(&sink);
        stdio_provider.push_input(b"x");
        assert_eq!(take_republished(&sink), [(stdin, ReadinessFlags::READ)]);
        assert_eq!(
            take_republished(&target_sink),
            [(duplicated_stdin, ReadinessFlags::READ)]
        );
        assert_eq!(
            target.check_readiness(duplicated_stdin),
            Ok(ReadinessFlags::READ)
        );
        assert_eq!(
            crate::fs::read(&target, duplicated_stdin, &mut byte, None),
            Ok(Ok(1))
        );
        assert_eq!(&byte, b"x");
        stdio_provider.close_input();
        assert_eq!(crate::fs::read(&source, stdin, &mut byte, None), Ok(Ok(0)));
        assert_eq!(source.close_object_reference(stdin), Ok(()));
        assert_eq!(target.close_object_reference(duplicated_stdin), Ok(()));
        assert!(sink.retired.lock().unwrap().contains(&stdin));
        assert!(
            target_sink
                .retired
                .lock()
                .unwrap()
                .contains(&duplicated_stdin)
        );
    }

    #[test]
    fn object_reference_lifecycle_uses_public_core_constructor_once() {
        let socket_provider = Arc::new(crate::socket::tests::TestSocketProvider::default());
        let stdio_provider = Arc::new(TestStdioProvider::default().with_open_input());
        let fs = crate::fs::composer::Composer::builder()
            .mount("/", crate::fs::in_mem::InMem::<TestPlatform>::new)
            .mount("/dev", |allocator| {
                crate::fs::devices::Devices::new(
                    allocator,
                    stdio_provider.clone(),
                    Arc::new(crate::random::TestRandomProvider),
                )
            })
            .build()
            .unwrap();
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let other = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            crate::pipe::create(&process, 4, 2, FileOpenFlags::NONE),
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
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        assert_eq!(
            crate::pipe::create(&process, 5, 2, FileOpenFlags::NONE),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(broker.reserved_pipe_capacity.load(Ordering::Relaxed), 0);
        let (reader, writer) = crate::pipe::create(&process, 4, 2, FileOpenFlags::NONE).unwrap();
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let (reader, writer) = crate::pipe::create(&process, 4, 2, FileOpenFlags::NONE).unwrap();
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
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let neighbor = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let neighbor = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let neighbor = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();

        let (greedy_reader, greedy_writer) = crate::pipe::create(
            &greedy,
            TEST_MAX_PIPE_CAPACITY_PER_PROCESS as u64,
            2,
            FileOpenFlags::NONE,
        )
        .unwrap();
        assert_eq!(
            crate::pipe::create(&greedy, 1, 1, FileOpenFlags::NONE),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            greedy.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_PIPE_CAPACITY_PER_PROCESS
        );

        let (neighbor_reader, neighbor_writer) = crate::pipe::create(
            &neighbor,
            TEST_MAX_PIPE_CAPACITY_PER_PROCESS as u64,
            2,
            FileOpenFlags::NONE,
        )
        .unwrap();
        assert_eq!(
            broker.reserved_pipe_capacity.load(Ordering::Relaxed),
            TEST_MAX_PIPE_CAPACITY
        );

        let latecomer = broker
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        assert_eq!(
            crate::pipe::create(&latecomer, 1, 1, FileOpenFlags::NONE),
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let (reader, _writer) = crate::pipe::create(
            &process,
            TEST_MAX_PIPE_CAPACITY_PER_PROCESS as u64,
            2,
            FileOpenFlags::NONE,
        )
        .unwrap();
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
            .allocate_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        {
            let mut next_reference_handle = broker.next_reference_handle.write();
            *next_reference_handle = u64::MAX - 1;
        }
        assert_eq!(
            crate::pipe::create(&process, 4, 2, FileOpenFlags::NONE),
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
