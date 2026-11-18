// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-backed guest process creation, the process tree, process groups
//! and sessions, and signals between processes.

use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox_broker_protocol::authority::Term;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{FileOpenFlags, FileStatusFlags};
use litebox_broker_protocol::process::{
    ChildCompletion, ChildExit, ChildSelector, CpuTime, HostName, HostNameKind, HostNames,
    MAX_CHILD_MEMORY_WRITE_SIZE, PidNamespaceOptions, ProcessExitStatus, ProcessIdentity,
    ProcessInfo, ResourceKind, ResourceLimit, ThreadInfo,
};
use litebox_broker_protocol::process_group::{ProcessGroupError, ProcessGroupMembership};
use litebox_broker_protocol::signal::{SignalEvent, SignalTarget};
use litebox_broker_protocol::{
    ObjectHandle, ProcessGroupId, ProcessId, SharedObjectToken, ThreadId,
};
use litebox_platform::time::TimeProvider;

use crate::LiteBox;
use crate::broker::{
    BrokerControl, BrokerPollableRegistry, error::BrokerControlError, readiness_events,
};
use crate::credential::{CredentialError, encode_terms};
use crate::event::{
    Events, IOPollable, counter::EventCounter, observer::Observer, polling::Pollee,
    readiness_queue::ReadinessQueue, timer::Timer,
};
use crate::fs::File;
use crate::fs::errors::StatusFlagsError;
use crate::inet_socket::InetSocket;
use crate::pipes::PipeEnd;
use crate::sync::RawSyncPrimitivesProvider;
use crate::unix_socket::UnixSocket;
use crate::vsock_socket::VsockSocket;

/// Error returned by the broker-backed process service.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProcessError {
    /// This LiteBox process has no broker process service.
    #[error("process creation is unavailable")]
    Unavailable,
    /// The broker association failed.
    #[error("process service failed")]
    ServiceFailed,
    /// The operation is denied by policy or by process group rules.
    #[error("process operation is denied")]
    PolicyDenied,
    /// Another pending child process already exists.
    #[error("a child process is already pending")]
    Busy,
    /// Process capacity is exhausted.
    #[error("process capacity is exhausted")]
    ResourceExhausted,
    /// Memory capacity is exhausted.
    #[error("process memory is exhausted")]
    OutOfMemory,
    /// The child process is invalid or no longer available.
    #[error("invalid child process")]
    InvalidChild,
    /// A source reference for inheritance is no longer available.
    #[error("invalid inheritance source")]
    InvalidInheritanceSource,
    /// No process has the target process ID.
    #[error("no such process")]
    NoSuchProcess,
    /// The file is not this process's controlling terminal.
    #[error("not the controlling terminal")]
    NotControllingTerminal,
    /// No process group has the target process group ID.
    #[error("no such process group")]
    NoSuchProcessGroup,
    /// The target process group is in another session than this process.
    #[error("process group is in another session")]
    NotInSession,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Allocates one pending child process.
    ///
    /// The child goes into the PID namespace for this process's children (see
    /// [`Self::create_children_pid_namespace`]), unless `new_pid_namespace`
    /// gives options, in which case it is the first process of a new
    /// namespace with those options, nested in this process's. The child's
    /// parent is this process, or this process's parent if `sibling` is set.
    ///
    /// Fails with [`ProcessError::InvalidChild`] if the child's namespace has
    /// ended, and with [`ProcessError::ResourceExhausted`] at a process limit
    /// or a namespace count or nesting limit.
    pub fn allocate_child_process(
        &self,
        new_pid_namespace: Option<PidNamespaceOptions>,
        sibling: bool,
    ) -> Result<PendingChild, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        let identity = broker.allocate_child_process(new_pid_namespace, sibling)?;
        Ok(PendingChild {
            broker,
            identity,
            pending: true,
        })
    }

    /// Makes the children this process creates from now on go into a new PID
    /// namespace with `options`, nested in this process's. The first of them
    /// becomes the namespace's first process.
    ///
    /// Fails with [`ProcessError::Unavailable`] if this process's children
    /// already go to another PID namespace, and with
    /// [`ProcessError::ResourceExhausted`] at a namespace count or nesting
    /// limit.
    pub fn create_children_pid_namespace(
        &self,
        options: PidNamespaceOptions,
    ) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.create_children_pid_namespace(options)?)
    }

    /// Reports this process's final termination status, which its parent
    /// collects once this process's runner exits.
    pub fn report_exit_status(&self, exit_status: ProcessExitStatus) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.report_exit_status(exit_status)?)
    }

    /// Sets whether this process retains its children's exits until it
    /// collects them, rather than discarding each when the child terminates.
    ///
    /// Each child applies the setting in effect when it terminates, so a
    /// change does not affect children that already terminated.
    pub fn set_child_exit_retention(&self, enabled: bool) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.set_child_exit_retention(enabled)?)
    }

    /// Sets whether this process adopts the children of its exiting
    /// descendants.
    ///
    /// The children of an exiting process move to its nearest running ancestor
    /// that adopts them, or are left without a parent, which discards each
    /// one's exit as it terminates.
    pub fn set_orphan_adoption(&self, enabled: bool) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.set_orphan_adoption(enabled)?)
    }

    /// Collects the exit of the oldest of this process's terminated children
    /// that `selector` matches, in the order this process gained them,
    /// removing the child from the process tree.
    ///
    /// Returns `None` if every matching child is live, and
    /// [`ProcessError::NoSuchProcess`] if no child matches. Each child that
    /// terminates, or leaves without terminating, such as a child whose
    /// startup failed, is also reported through [`Signals`]. An opened child's
    /// exit is collected with [`Process::collect_exit`].
    pub fn collect_child_exit(
        &self,
        selector: ChildSelector,
    ) -> Result<Option<ChildExit>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        match broker.collect_child_exit(selector) {
            Ok(exit) => Ok(Some(exit)),
            Err(BrokerControlError::Broker(ErrorCode::WouldBlock)) => Ok(None),
            Err(error) => Err(no_such_process(error)),
        }
    }

    /// Returns the place of process `process_id` in the process tree.
    pub fn process_info(&self, process_id: ProcessId) -> Result<ProcessInfo, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        broker.process_info(process_id).map_err(no_such_process)
    }

    /// Returns the process thread `thread_id` belongs to.
    ///
    /// Returns [`ProcessError::NoSuchProcess`] if no thread has the ID.
    pub fn thread_info(&self, thread_id: ThreadId) -> Result<ThreadInfo, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        broker.thread_info(thread_id).map_err(no_such_process)
    }

    /// Returns the CPU time used by the children whose exits this process
    /// collected, including the time they collected from their own children.
    pub fn children_cpu_time(&self) -> Result<CpuTime, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.children_cpu_time()?)
    }

    /// Returns the limit on `resource` of this process or of its pending
    /// child `process_id`.
    ///
    /// Returns [`ProcessError::InvalidChild`] if `process_id` is neither.
    pub fn get_resource_limit(
        &self,
        process_id: ProcessId,
        resource: ResourceKind,
    ) -> Result<ResourceLimit, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.get_resource_limit(process_id, resource)?)
    }

    /// Replaces the limit on `resource` of this process or of its pending
    /// child `process_id` with `limit`, returning the previous limit.
    ///
    /// Returns [`ProcessError::InvalidChild`] if `process_id` is neither, and
    /// [`ProcessError::PolicyDenied`] if `limit` raises the hard limit.
    pub fn set_resource_limit(
        &self,
        process_id: ProcessId,
        resource: ResourceKind,
        limit: ResourceLimit,
    ) -> Result<ResourceLimit, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.set_resource_limit(process_id, resource, limit)?)
    }

    /// Returns the host names of this process or of its pending child
    /// `process_id`, both from one moment.
    ///
    /// Returns [`ProcessError::InvalidChild`] if `process_id` is neither.
    pub fn get_host_names(&self, process_id: ProcessId) -> Result<HostNames, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.get_host_names(process_id)?)
    }

    /// Replaces the `kind` name of this process or of its pending child
    /// `process_id` with `name`, for every process that shares its host names.
    ///
    /// Returns [`ProcessError::InvalidChild`] if `process_id` is neither.
    pub fn set_host_name(
        &self,
        process_id: ProcessId,
        kind: HostNameKind,
        name: &HostName,
    ) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.set_host_name(process_id, kind, name)?)
    }

    /// Replaces the host names of this process or of its pending child
    /// `process_id` with a copy that no other process shares.
    ///
    /// Returns [`ProcessError::InvalidChild`] if `process_id` is neither.
    pub fn copy_host_names(&self, process_id: ProcessId) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.copy_host_names(process_id)?)
    }

    /// Returns the parent-exit signal of this process or of its pending child
    /// `process_id`, or 0 for none.
    ///
    /// Returns [`ProcessError::InvalidChild`] if `process_id` is neither.
    pub fn get_parent_exit_signal(&self, process_id: ProcessId) -> Result<u32, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.get_parent_exit_signal(process_id)?)
    }

    /// Sets the parent-exit signal of this process or of its pending child
    /// `process_id` to `signal`, or clears it if `signal` is 0.
    ///
    /// When the process's parent exits, the process moves to a new parent or
    /// to none, and then receives `signal` through [`Signals`], sent from the
    /// exiting parent. No signal is sent if the parent is the first process of
    /// a PID namespace that ends with it, since that shuts the process down.
    /// The setting is kept, so every later move sends the signal again. A new
    /// process has none.
    ///
    /// Returns [`ProcessError::InvalidChild`] if `process_id` is neither, and
    /// [`ProcessError::Unavailable`] if `signal` is above
    /// [`MAX_SIGNAL`](litebox_broker_protocol::signal::MAX_SIGNAL).
    pub fn set_parent_exit_signal(
        &self,
        process_id: ProcessId,
        signal: u32,
    ) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.set_parent_exit_signal(process_id, signal)?)
    }

    /// Sends `signal` to the processes or thread `target` selects, or only
    /// checks that one exists if `signal` is zero.
    ///
    /// Each target process takes the signal through [`Signals`]. A signal
    /// already pending for a target is not sent again. Returns
    /// [`ProcessError::NoSuchProcess`] if no process or thread is targeted. An
    /// opened process is signalled with [`Process::send_signal`].
    pub fn send_signal(&self, target: SignalTarget, signal: u32) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        broker.send_signal(target, signal).map_err(signal_error)
    }

    /// Moves process `process_id`, which is this process or one of its
    /// children, into `process_group`, creating the group if it is
    /// `process_id`.
    ///
    /// Returns [`ProcessError::PolicyDenied`] if the process is in another
    /// session than this process or leads a session, or if `process_group` is
    /// neither `process_id` nor an existing group in this process's session.
    /// Returns [`ProcessError::NoSuchProcess`] if `process_id` names neither
    /// this process nor one of its children.
    pub fn set_process_group(
        &self,
        process_id: ProcessId,
        process_group: ProcessGroupId,
    ) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        broker
            .set_process_group(process_id, process_group)
            .map_err(no_such_process)
    }

    /// Makes process `process_id`, which is this process or its pending
    /// child, the leader of a new session and of a new process group in it.
    ///
    /// Returns [`ProcessError::PolicyDenied`] if a process group already has
    /// the ID `process_id`.
    pub fn create_session(&self, process_id: ProcessId) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        broker.create_session(process_id).map_err(no_such_process)
    }

    /// Returns the foreground process group of the session that `terminal`
    /// controls and the session, given this process's controlling terminal or
    /// a pseudo-terminal manager.
    ///
    /// Returns [`ProcessError::NotControllingTerminal`] if `terminal` is
    /// neither this process's controlling terminal nor the manager of a
    /// session's controlling terminal.
    pub fn get_foreground_group(
        &self,
        terminal: &File<Platform>,
    ) -> Result<ProcessGroupMembership, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.get_foreground_group(terminal.handle())??)
    }

    /// Moves `process_group` into the foreground of this process's controlling
    /// terminal `terminal`, so the terminal's events go to its members.
    ///
    /// Returns, in order of precedence,
    /// [`ProcessError::NotControllingTerminal`] if `terminal` is not this
    /// process's controlling terminal, [`ProcessError::NoSuchProcessGroup`] if
    /// no process group has the ID `process_group`, and
    /// [`ProcessError::NotInSession`] if the process group is in another
    /// session.
    pub fn set_foreground_group(
        &self,
        terminal: &File<Platform>,
        process_group: ProcessGroupId,
    ) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker.set_foreground_group(terminal.handle(), process_group)??)
    }

    /// Makes `terminal`, or the subsidiary of pseudo-terminal manager
    /// `terminal`, the controlling terminal of the session that process
    /// `process_id` leads, with the leader's group in the foreground.
    /// `process_id` must be this process or its pending child.
    ///
    /// Does nothing if the terminal already controls the session. Otherwise
    /// returns [`ProcessError::PolicyDenied`] if the process leads no session,
    /// the session already has a controlling terminal, the terminal controls
    /// another session, or `terminal` is not open for reading. Returns
    /// [`ProcessError::NotControllingTerminal`] if `terminal` is not a
    /// terminal, and [`ProcessError::NoSuchProcess`] if `process_id` names
    /// neither this process nor its pending child.
    pub fn set_controlling_terminal(
        &self,
        process_id: ProcessId,
        terminal: &File<Platform>,
    ) -> Result<(), ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(broker
            .set_controlling_terminal(process_id, terminal.handle())
            .map_err(no_such_process)??)
    }

    /// Opens the signals other processes send to this process and the exits
    /// of its children, including those before it is opened.
    ///
    /// A process may hold only one [`Signals`] at a time.
    pub fn open_signals(&self) -> Result<Signals<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        let handle = broker.open_signals()?;
        Ok(Signals::new(self, broker, handle))
    }

    /// Opens process `process_id`, which may be a pending child, with the
    /// status flags `flags`, within [`FileOpenFlags::STATUS`].
    ///
    /// Returns [`ProcessError::NoSuchProcess`] if no such process exists or
    /// it was released.
    pub fn open_process(
        &self,
        process_id: ProcessId,
        flags: FileOpenFlags,
    ) -> Result<Process<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        let handle = broker
            .open_process_handle(process_id, flags)
            .map_err(no_such_process)?;
        Ok(Process::new(self, broker, handle))
    }

    /// Returns the process this process inherited from its parent as `handle`
    /// through [`PendingChild::inherit`].
    ///
    /// The [`Process`] owns `handle`, so callers adopt each handle once and
    /// share the [`Process`] for every other use.
    pub fn adopt_inherited_process(
        &self,
        handle: ObjectHandle,
    ) -> Result<Process<Platform>, ProcessError> {
        let broker = self.broker_control().ok_or(ProcessError::Unavailable)?;
        Ok(Process::new(self, broker, handle))
    }
}

/// A descriptor a pending child process can inherit through [`PendingChild::inherit`].
///
/// This identifies only the object. The shim records guest-specific details, such as the
/// descriptor number, in the child's startup payload alongside the handle `inherit` returns.
pub enum InheritableFd<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// A file, adopted with [`LiteBox::adopt_inherited_file`].
    File(Arc<File<Platform>>),
    /// A pipe end, adopted with [`LiteBox::adopt_inherited_pipe`].
    Pipe(Arc<PipeEnd<Platform>>),
    /// A Unix socket, adopted with [`LiteBox::adopt_inherited_unix_socket`].
    UnixSocket(Arc<UnixSocket<Platform>>),
    /// An IPv4 socket, adopted with [`LiteBox::adopt_inherited_inet_socket`].
    InetSocket(Arc<InetSocket<Platform>>),
    /// A vsock socket, adopted with [`LiteBox::adopt_inherited_vsock_socket`].
    VsockSocket(Arc<VsockSocket<Platform>>),
    /// An event counter, adopted with [`LiteBox::adopt_inherited_event_counter`].
    EventCounter(Arc<EventCounter<Platform>>),
    /// A timer, adopted with [`LiteBox::adopt_inherited_timer`].
    Timer(Arc<Timer<Platform>>),
    /// A readiness queue, adopted with [`LiteBox::adopt_inherited_readiness_queue`].
    ReadinessQueue(Arc<ReadinessQueue<Platform>>),
    /// A process, adopted with [`LiteBox::adopt_inherited_process`].
    Process(Arc<Process<Platform>>),
}

/// A child process that has not started.
///
/// Dropping it before it starts or exits discards the child, as if it had
/// never been created, except that its parent learns it was removed.
/// Starting or exiting takes an exclusive borrow so no other use of this
/// allocation can race the broker taking it and reusing its numeric ID.
pub struct PendingChild {
    broker: Arc<dyn BrokerControl>,
    identity: ProcessIdentity,
    /// Cleared once the broker takes the child for start or exit, even if it fails afterwards.
    pending: bool,
}

impl PendingChild {
    /// Returns the broker-assigned process and initial thread IDs, and the
    /// child's ID in its own PID namespace.
    pub fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    /// Replaces this child's authority, inherited from its creator, as
    /// [`LiteBox::restrict_authority`] replaces the creator's. The creator's
    /// authority does not change.
    ///
    /// Fails with [`CredentialError::InvalidChild`] once the child has started
    /// or exited.
    pub fn restrict_authority(&mut self, terms: &[Term]) -> Result<(), CredentialError> {
        if !self.pending {
            return Err(CredentialError::InvalidChild);
        }
        let terms = encode_terms(terms)?;
        self.broker
            .restrict_child_authority(self.identity.process_id, &terms)
            .map_err(|error| match error {
                BrokerControlError::Broker(ErrorCode::UnknownObject | ErrorCode::PeerClosed) => {
                    CredentialError::InvalidChild
                }
                error => error.into(),
            })
    }

    /// Returns whether this handle still refers to a pending allocation.
    /// This is local state, not a liveness query.
    pub fn is_pending(&self) -> bool {
        self.pending
    }

    /// Starts this pending child process in a fresh runner.
    ///
    /// If this fails while the child [is still pending](Self::is_pending),
    /// the broker did not take the child, which holds none of the references
    /// [`Self::inherit`] gave it, so the caller may inherit and start again,
    /// or exit it. Otherwise the child is gone.
    pub fn start(&mut self, payload: &[u8]) -> Result<(), ProcessError> {
        let process_id = self.pending_id()?;
        match self.broker.start_child_process(process_id, payload) {
            Ok(outcome) => self.finish(outcome),
            Err(error) => Err(self.start_rejected(error)),
        }
    }

    /// Asks the broker for the control connection through which a native clone of this runner
    /// will associate as this child, before [`Self::start_with_existing_runner`] starts it.
    ///
    /// The broker keeps its end with this child and delivers the runner's end out of band. This
    /// returns the token under which the caller takes it from its platform. Deployments whose
    /// clones connect otherwise report [`ProcessError::Unavailable`].
    pub fn request_child_connection(&self) -> Result<SharedObjectToken, ProcessError> {
        Ok(self.broker.request_child_connection(self.pending_id()?)?)
    }

    /// Starts this pending child in an already-created platform runner.
    ///
    /// `runner_descriptor` encodes the host runner's platform-specific identity and, where the
    /// platform needs one, its control endpoint. `payload` contains the guest startup state.
    /// Failure leaves the child as [`Self::start`] describes.
    pub fn start_with_existing_runner(
        &mut self,
        runner_descriptor: &[u8],
        payload: &[u8],
    ) -> Result<(), ProcessError> {
        let process_id = self.pending_id()?;
        match self
            .broker
            .start_child_with_existing_runner(process_id, runner_descriptor, payload)
        {
            Ok(outcome) => self.finish(outcome),
            Err(error) => Err(self.start_rejected(error)),
        }
    }

    /// Gives this pending child process its own references to the objects
    /// `fds` refer to, returning the child's handles in the same order.
    ///
    /// Like descriptors a Linux child inherits, each child reference shares
    /// its object's state, such as a file's offset, a pipe's buffer, or an
    /// event counter's count.
    /// Descriptors sharing an open file description get the same handle. The
    /// child adopts each handle as the [`InheritableFd`] variant describes and
    /// releases its references when it terminates. If this fails, the child
    /// receives none of them. [`Self::release_inherited`] releases them early.
    /// Losing the child or the process service invalidates this handle; an
    /// [`invalid source`](ProcessError::InvalidInheritanceSource) does not.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns fewer handles than were duplicated.
    pub fn inherit<Platform: RawSyncPrimitivesProvider + TimeProvider>(
        &mut self,
        fds: &[InheritableFd<Platform>],
    ) -> Result<Vec<ObjectHandle>, ProcessError> {
        // `fds` holds the objects, which keeps their handles open until the child has its own.
        let mut fd_handles = Vec::new();
        for fd in fds {
            let handle = match fd {
                InheritableFd::File(file) => file.handle(),
                InheritableFd::Pipe(pipe) => pipe.handle(),
                InheritableFd::UnixSocket(socket) => socket.handle(),
                InheritableFd::InetSocket(socket) => socket.handle(),
                InheritableFd::VsockSocket(socket) => socket.handle(),
                InheritableFd::EventCounter(counter) => counter.handle(),
                InheritableFd::Timer(timer) => timer.handle(),
                InheritableFd::ReadinessQueue(queue) => queue.handle(),
                InheritableFd::Process(process) => process.handle(),
            };
            fd_handles.push(handle);
        }
        let mut handles = fd_handles.clone();
        handles.sort_unstable();
        handles.dedup();
        let process_id = self.pending_id()?;
        let inherited = match self.broker.duplicate_objects_to_child(process_id, &handles) {
            Ok(inherited) => inherited,
            Err(BrokerControlError::Broker(ErrorCode::UnknownObject)) => {
                return Err(ProcessError::InvalidInheritanceSource);
            }
            Err(error) => return Err(self.rejected(error)),
        };
        Ok(fd_handles
            .iter()
            .map(|handle| {
                let index = handles
                    .binary_search(handle)
                    .expect("every descriptor handle was duplicated");
                inherited[index]
            })
            .collect())
    }

    /// Releases every reference [`Self::inherit`] gave this pending child, so
    /// that it may inherit afresh.
    ///
    /// On failure the handle is invalidated. If the broker has not already
    /// lost the child or the association, LiteBox also requests cancellation.
    pub fn release_inherited(&mut self) -> Result<(), ProcessError> {
        let process_id = self.pending_id()?;
        match self.broker.release_child_objects(process_id) {
            Ok(()) => Ok(()),
            Err(error) => {
                let error = self.rejected(error);
                if self.pending {
                    // This allocation might still hold the staged references.
                    let _ = self.broker.cancel_child_process(process_id);
                    self.pending = false;
                }
                Err(error)
            }
        }
    }

    /// Writes `data` at `offset` of this pending child process's memory image,
    /// which the child's runner receives when the child starts.
    ///
    /// The image is zero-filled where nothing was written.
    pub fn write_memory(&self, offset: u64, data: &[u8]) -> Result<(), ProcessError> {
        let mut offset = offset;
        for chunk in data.chunks(MAX_CHILD_MEMORY_WRITE_SIZE as usize) {
            self.broker
                .write_child_memory(self.pending_id()?, offset, chunk)?;
            offset = offset
                .checked_add(chunk.len() as u64)
                .ok_or(ProcessError::ResourceExhausted)?;
        }
        Ok(())
    }

    /// Records that this pending child process exited without starting a
    /// runner, retaining `exit_status` until it is collected.
    pub fn exit(&mut self, exit_status: ProcessExitStatus) -> Result<(), ProcessError> {
        let process_id = self.pending_id()?;
        match self.broker.exit_child_process(process_id, exit_status) {
            Ok(outcome) => self.finish(outcome),
            Err(error) => Err(self.rejected(error)),
        }
    }

    fn pending_id(&self) -> Result<ProcessId, ProcessError> {
        self.pending
            .then_some(self.identity.process_id)
            .ok_or(ProcessError::InvalidChild)
    }

    fn rejected(&mut self, error: BrokerControlError) -> ProcessError {
        let error = ProcessError::from(error);
        if matches!(
            error,
            ProcessError::InvalidChild | ProcessError::ServiceFailed
        ) {
            // The allocation is gone or its disposition is unknown. Don't send
            // another request (including cancellation) against its numeric ID.
            self.pending = false;
        }
        error
    }

    fn start_rejected(&mut self, error: BrokerControlError) -> ProcessError {
        let error = self.rejected(error);
        if self.pending {
            // Roll back before allowing a retry; preserve the original start error.
            let _ = self.release_inherited();
        }
        error
    }

    fn finish(&mut self, outcome: ChildCompletion) -> Result<(), ProcessError> {
        self.pending = false;
        outcome.map_err(|error| BrokerControlError::Broker(error).into())
    }
}

impl Drop for PendingChild {
    fn drop(&mut self) {
        if self.pending {
            // Failure means the child is already gone or the process service failed.
            let _ = self.broker.cancel_child_process(self.identity.process_id);
        }
    }
}

/// The signals other processes send to this process, and the exits of its
/// children.
///
/// It reports [`Events::IN`] while either is pending.
pub struct Signals<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Signals<Platform> {
    fn new(
        litebox: &LiteBox<Platform>,
        broker: Arc<dyn BrokerControl>,
        handle: ObjectHandle,
    ) -> Self {
        let pollable_registry = litebox.broker_pollable_registry();
        let pollee = Arc::new(Pollee::new());
        pollable_registry.register_pollable(handle, &pollee);
        Self {
            broker,
            handle,
            pollable_registry,
            pollee,
        }
    }

    /// Takes the lowest-numbered signal pending for this process, or else, for
    /// one of its threads in no particular order, that thread's lowest-numbered
    /// pending signal, or else a pending child exit, or else a pending child
    /// removal, or returns `None` if none is pending.
    ///
    /// Child events are coalesced: while one is pending, later events of its
    /// kind are not reported, so a taker collects child exits until none
    /// remains.
    pub fn take(&self) -> Result<Option<SignalEvent>, ProcessError> {
        match self.broker.take_signal(self.handle) {
            Ok(event) => Ok(Some(event)),
            Err(BrokerControlError::Broker(ErrorCode::WouldBlock)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for Signals<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for Signals<Platform> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        self.broker
            .check_readiness(self.handle)
            .map_or(Events::ERR, readiness_events)
    }
}

/// A reference to one process, rather than to its ID.
///
/// It never refers to a later process that reuses the ID, and it keeps
/// neither the process nor its ID from going away. It reports
/// [`Events::IN`] once the process's exit is observable, and also
/// [`Events::HUP`] once the process is released (its exit was collected or
/// discarded, or it never started) or otherwise leaves the broker.
///
/// Each [`LiteBox::open_process`] call opens a separate broker object with its
/// own status flags, which copies inherited through [`PendingChild::inherit`]
/// share.
pub struct Process<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
    pollable_registry: Arc<BrokerPollableRegistry<Platform>>,
    pollee: Arc<Pollee<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Process<Platform> {
    fn new(
        litebox: &LiteBox<Platform>,
        broker: Arc<dyn BrokerControl>,
        handle: ObjectHandle,
    ) -> Self {
        let pollable_registry = litebox.broker_pollable_registry();
        let pollee = Arc::new(Pollee::new());
        pollable_registry.register_pollable(handle, &pollee);
        Self {
            broker,
            handle,
            pollable_registry,
            pollee,
        }
    }

    /// The broker handle this `Process` owns.
    pub(crate) fn handle(&self) -> ObjectHandle {
        self.handle
    }

    /// Sends `signal` to the process, or only checks that it exists if
    /// `signal` is zero.
    ///
    /// The process takes the signal through [`Signals`]. Returns
    /// [`ProcessError::NoSuchProcess`] if the process was released or left the
    /// broker, or the caller's PID namespace doesn't see it.
    pub fn send_signal(&self, signal: u32) -> Result<(), ProcessError> {
        self.broker
            .send_signal(SignalTarget::ProcessHandle(self.handle), signal)
            .map_err(signal_error)
    }

    /// Collects the process's exit, removing it from the process tree, if it
    /// is a terminated child of the caller.
    ///
    /// Returns `None` if the child is live, and [`ProcessError::NoSuchProcess`]
    /// if the process isn't the caller's child, such as once its exit was
    /// collected.
    pub fn collect_exit(&self) -> Result<Option<ChildExit>, ProcessError> {
        match self
            .broker
            .collect_child_exit(ChildSelector::ProcessHandle(self.handle))
        {
            Ok(exit) => Ok(Some(exit)),
            Err(BrokerControlError::Broker(ErrorCode::WouldBlock)) => Ok(None),
            Err(error) => Err(no_such_process(error)),
        }
    }

    /// Returns the access mode and status flags.
    pub fn get_status_flags(&self) -> Result<FileStatusFlags, StatusFlagsError> {
        Ok(self.broker.get_status_flags(self.handle)?)
    }

    /// Changes the status flags in `mask`, within [`FileOpenFlags::STATUS`],
    /// to their values in `flags`.
    ///
    /// Every reference that shares this one's broker object, including those
    /// in other processes, sees the change.
    pub fn set_status_flags(
        &self,
        mask: FileOpenFlags,
        flags: FileOpenFlags,
    ) -> Result<(), StatusFlagsError> {
        Ok(self.broker.set_status_flags(self.handle, mask, flags)?)
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> Drop for Process<Platform> {
    fn drop(&mut self) {
        self.pollable_registry.unregister_pollable(self.handle);
        let _ = self.broker.close_object(self.handle);
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for Process<Platform> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        self.broker
            .check_readiness(self.handle)
            .map_or(Events::ERR, readiness_events)
    }
}

/// Converts an error from a request that targets processes by ID.
fn no_such_process(error: BrokerControlError) -> ProcessError {
    match error {
        BrokerControlError::Broker(ErrorCode::UnknownObject) => ProcessError::NoSuchProcess,
        error => error.into(),
    }
}

/// Converts an error from a signal request, whose process handle target
/// fails with `PeerClosed` once its process is gone.
fn signal_error(error: BrokerControlError) -> ProcessError {
    match error {
        BrokerControlError::Broker(ErrorCode::PeerClosed) => ProcessError::NoSuchProcess,
        error => no_such_process(error),
    }
}

impl From<ProcessGroupError> for ProcessError {
    fn from(error: ProcessGroupError) -> Self {
        match error {
            ProcessGroupError::NotControllingTerminal => Self::NotControllingTerminal,
            ProcessGroupError::NoSuchProcessGroup => Self::NoSuchProcessGroup,
            ProcessGroupError::NotInSession => Self::NotInSession,
            _ => Self::ServiceFailed,
        }
    }
}

impl From<BrokerControlError> for ProcessError {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::AssociationFailed => Self::ServiceFailed,
            BrokerControlError::Broker(ErrorCode::UnsupportedOperation) => Self::Unavailable,
            BrokerControlError::Broker(ErrorCode::PolicyDenied) => Self::PolicyDenied,
            BrokerControlError::Broker(ErrorCode::WouldBlock) => Self::Busy,
            BrokerControlError::Broker(ErrorCode::ResourceExhausted) => Self::ResourceExhausted,
            BrokerControlError::Broker(ErrorCode::OutOfMemory) => Self::OutOfMemory,
            BrokerControlError::Broker(
                ErrorCode::UnknownObject | ErrorCode::PeerClosed | ErrorCode::ProtocolState,
            ) => Self::InvalidChild,
            BrokerControlError::Broker(error) => {
                panic!("process service returned unexpected error: {error}")
            }
            BrokerControlError::Fault => unreachable!("process requests copy no bytes"),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use litebox_broker_local::test_support::test_broker_local;
    use litebox_broker_protocol::message::{
        BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult, ProcessRequest,
        ProcessResponse, SignalRequest,
    };
    use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
    use litebox_broker_protocol::signal::SendSignalRequest;
    use litebox_broker_protocol::{ProcessId, ThreadId};
    use litebox_broker_transport::channel::LocalCallChannel;
    use litebox_broker_transport::shared_memory::HeapSharedMemory;

    use super::*;
    use crate::platform::mock::MockPlatform;

    #[test]
    fn dropping_a_pending_child_cancels_it() {
        let counts = Arc::new(ChildCounts::default());
        let litebox = LiteBox::new_with_broker_local(
            MockPlatform::new(),
            test_broker_local(ChildChannel(counts.clone()), test_shared_memory()),
        );

        drop(litebox.allocate_child_process(None, false).unwrap());
        assert_eq!(counts.cancels.load(Ordering::SeqCst), 1);

        let mut child = litebox.allocate_child_process(None, false).unwrap();
        child.exit(ProcessExitStatus::Exited { code: 0 }).unwrap();
        drop(child);
        assert_eq!(counts.cancels.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn child_taken_by_a_failed_launch_is_no_longer_pending() {
        let counts = Arc::new(ChildCounts::default());
        let litebox = LiteBox::new_with_broker_local(
            MockPlatform::new(),
            test_broker_local(ChildChannel(counts.clone()), test_shared_memory()),
        );
        let mut child = litebox.allocate_child_process(None, false).unwrap();
        // The same error can occur on either side of the broker taking the child.
        assert_eq!(child.start(&[]), Err(ProcessError::ResourceExhausted));
        // A child the broker did not take releases what it inherited, and stays pending.
        assert!(child.is_pending());
        assert_eq!(counts.releases.load(Ordering::SeqCst), 1);
        child.restrict_authority(&[]).unwrap();
        assert_eq!(
            child.start_with_existing_runner(&[], &[]),
            Err(ProcessError::ResourceExhausted)
        );
        assert!(!child.is_pending());
        assert_eq!(counts.releases.load(Ordering::SeqCst), 1);
        let mut replacement = litebox.allocate_child_process(None, false).unwrap();
        assert_eq!(
            child.identity().process_id,
            replacement.identity().process_id
        );
        assert_eq!(
            child.restrict_authority(&[]),
            Err(CredentialError::InvalidChild)
        );
        assert_eq!(child.release_inherited(), Err(ProcessError::InvalidChild));
        drop(child);
        assert_eq!(counts.cancels.load(Ordering::SeqCst), 0);
        replacement.restrict_authority(&[]).unwrap();
        drop(replacement);
        assert_eq!(counts.cancels.load(Ordering::SeqCst), 1);
        assert_eq!(counts.releases.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn losing_the_child_during_release_invalidates_it_without_cancelling_by_id() {
        let counts = Arc::new(ChildCounts::default());
        counts.fail_releases.store(true, Ordering::SeqCst);
        let litebox = LiteBox::new_with_broker_local(
            MockPlatform::new(),
            test_broker_local(ChildChannel(counts.clone()), test_shared_memory()),
        );

        let mut child = litebox.allocate_child_process(None, false).unwrap();
        assert_eq!(child.release_inherited(), Err(ProcessError::InvalidChild));
        assert!(!child.is_pending());
        assert_eq!(counts.cancels.load(Ordering::SeqCst), 0);
        assert_eq!(
            child.exit(ProcessExitStatus::Exited { code: 0 }),
            Err(ProcessError::InvalidChild)
        );
        drop(child);
        assert_eq!(counts.cancels.load(Ordering::SeqCst), 0);

        // A rejected start reports its own error, even when the child is discarded.
        let mut child = litebox.allocate_child_process(None, false).unwrap();
        assert_eq!(child.start(&[]), Err(ProcessError::ResourceExhausted));
        assert!(!child.is_pending());
        drop(child);
        assert_eq!(counts.cancels.load(Ordering::SeqCst), 0);
        assert_eq!(counts.releases.load(Ordering::SeqCst), 2);
    }

    /// What [`ChildChannel`] observed of its pending child.
    #[derive(Default)]
    struct ChildCounts {
        cancels: AtomicUsize,
        releases: AtomicUsize,
        /// Whether the broker reports that the child is no longer pending when asked to release
        /// its objects.
        fail_releases: AtomicBool,
    }

    /// Serves one pending child at a time, counting its cancellations and releases.
    struct ChildChannel(Arc<ChildCounts>);

    impl LocalCallChannel for ChildChannel {
        type Error = ();

        fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Self::Error> {
            let child = ProcessId(3);
            let BrokerOperation::Process(operation) = request.operation else {
                panic!("unexpected operation {:?}", request.operation);
            };
            let response = match operation {
                ProcessRequest::AllocateChild(_) => {
                    ProcessResponse::AllocateChild(ProcessIdentity {
                        process_id: child,
                        initial_thread_id: ThreadId(4),
                        own_process_id: child,
                    })
                }
                ProcessRequest::ExitChild(request) if request.child_process_id == child => {
                    ProcessResponse::ExitChild
                }
                ProcessRequest::RestrictChildAuthority(request)
                    if request.child_process_id == child =>
                {
                    ProcessResponse::RestrictChildAuthority
                }
                ProcessRequest::StartChild(_) => {
                    return Ok(BrokerResponse {
                        request_id: request.request_id,
                        result: BrokerResult::Error(ErrorCode::ResourceExhausted),
                    });
                }
                ProcessRequest::StartChildWithExistingRunner(_) => {
                    ProcessResponse::ChildConsumed(ErrorCode::ResourceExhausted)
                }
                ProcessRequest::CancelChild(process_id) if process_id == child => {
                    self.0.cancels.fetch_add(1, Ordering::SeqCst);
                    ProcessResponse::CancelChild
                }
                ProcessRequest::ReleaseChildObjects(process_id) if process_id == child => {
                    self.0.releases.fetch_add(1, Ordering::SeqCst);
                    if self.0.fail_releases.load(Ordering::SeqCst) {
                        return Ok(BrokerResponse {
                            request_id: request.request_id,
                            result: BrokerResult::Error(ErrorCode::PeerClosed),
                        });
                    }
                    ProcessResponse::ReleaseChildObjects
                }
                operation => panic!("unexpected process operation {operation:?}"),
            };
            let result = BrokerResult::Process(response);
            Ok(BrokerResponse {
                request_id: request.request_id,
                result,
            })
        }
    }

    fn test_shared_memory() -> Arc<HeapSharedMemory> {
        Arc::new(HeapSharedMemory::new(SHARED_BUFFER_POOL_SIZE))
    }

    #[test]
    fn signalling_a_gone_process_by_handle_finds_no_such_process() {
        let litebox = LiteBox::new_with_broker_local(
            MockPlatform::new(),
            test_broker_local(GoneProcessChannel, test_shared_memory()),
        );
        let process = litebox
            .open_process(ProcessId(3), FileOpenFlags::NONE)
            .unwrap();

        assert_eq!(process.send_signal(0), Err(ProcessError::NoSuchProcess));
        assert_eq!(
            litebox.send_signal(SignalTarget::ProcessHandle(process.handle()), 0),
            Err(ProcessError::NoSuchProcess)
        );
    }

    /// Opens handles to a process that is gone by the time it is signalled.
    struct GoneProcessChannel;

    impl LocalCallChannel for GoneProcessChannel {
        type Error = ();

        fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Self::Error> {
            let handle = ObjectHandle(5);
            let result = match request.operation {
                BrokerOperation::Process(ProcessRequest::OpenProcessHandle(_)) => {
                    BrokerResult::Process(ProcessResponse::OpenProcessHandle(handle))
                }
                BrokerOperation::Signal(SignalRequest::Send(SendSignalRequest {
                    target: SignalTarget::ProcessHandle(target),
                    ..
                })) if target == handle => BrokerResult::Error(ErrorCode::PeerClosed),
                BrokerOperation::CloseObject(target) if target == handle => {
                    BrokerResult::ObjectClosed
                }
                operation => panic!("unexpected operation {operation:?}"),
            };
            Ok(BrokerResponse {
                request_id: request.request_id,
                result,
            })
        }
    }
}
