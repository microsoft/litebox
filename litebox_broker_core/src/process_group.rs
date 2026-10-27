// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process groups and sessions.
//!
//! Every process belongs to one process group, and every process group to one
//! session, each identified by the ID of the process that created it. A child
//! process starts in its creator's group and session, while a root process
//! leads its own. A group or session exists while any process, including an
//! exited one whose exit is not yet collected, belongs to it, and its ID is
//! not reused until then, nor while a terminal can still signal the group.
//!
//! A terminal can control one session, signalling its foreground group and
//! serving its members as `/dev/tty`. The broker's terminal controls the first
//! root process's session, and a session leader without one acquires a
//! terminal it opens for reading or names explicitly. The foreground group
//! starts as the leader's group, and processes in the session can change it.
//! The session loses its terminal when the terminal hangs up, which tells the
//! leader, or when the leader exits, which tells the foreground group.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use litebox_broker_protocol::process_group::{ProcessGroupError, ProcessGroupMembership};
use litebox_broker_protocol::terminal::TerminalEvents;
use litebox_broker_protocol::{ObjectHandle, ProcessGroupId, ProcessId, SessionId};
use spin::Mutex;

use crate::id::IdAllocator;
use crate::terminal::{TerminalEndpoint, TerminalEventSink};
use crate::{BrokerError, BrokerProcess, ProcessRegistry, Result};

/// Result of a process group operation that can fail in a way the guest ABI
/// reports.
pub type ProcessGroupResult<T> = core::result::Result<T, ProcessGroupError>;

/// Moves the process `target` into `process_group`, creating the group if it
/// is `target`'s ID.
///
/// `target` must be the caller or one of its children, or this returns
/// `UnknownObject`. Returns `PolicyDenied` if `target` is in another session
/// than the caller or leads a session, or if `process_group` is neither
/// `target`'s ID nor an existing group in the caller's session.
pub fn set(
    process: &BrokerProcess,
    target: ProcessId,
    process_group: ProcessGroupId,
) -> Result<()> {
    let _tree = process.core.process_tree_lock.lock();
    let target = process.core.registered_process(target)?;
    if !core::ptr::eq(Arc::as_ptr(&target), process) && !target.is_child_of(process) {
        return Err(BrokerError::UnknownObject);
    }
    let session = process.membership().session;
    let membership = target.membership();
    if membership.session != session || membership.session == target.id().into() {
        return Err(BrokerError::PolicyDenied);
    }
    let joined = ProcessGroupMembership {
        process_group,
        session,
    };
    if process_group != target.id().into()
        && !process
            .core
            .registered_processes()
            .iter()
            .any(|member| member.membership() == joined)
    {
        return Err(BrokerError::PolicyDenied);
    }
    target.set_membership(joined);
    Ok(())
}

/// Makes the process `target` the leader of a new session and of a new process
/// group in it.
///
/// `target` must be the caller or its pending child, or this returns
/// `UnknownObject`. Returns `PolicyDenied` if a process group already has
/// `target`'s ID.
pub fn create_session(process: &BrokerProcess, target: ProcessId) -> Result<()> {
    let _tree = process.core.process_tree_lock.lock();
    let processes = process.core.registered_processes();
    let create = |target: &BrokerProcess| {
        let id = target.id();
        if processes
            .iter()
            .any(|member| member.membership().process_group == id.into())
        {
            return Err(BrokerError::PolicyDenied);
        }
        target.set_membership(ProcessGroupMembership {
            process_group: id.into(),
            session: id.into(),
        });
        Ok(())
    };
    if target == process.id() {
        create(process)
    } else {
        // The child cannot start, and so gain children in its old session,
        // before it moves.
        process.with_pending_child(target, |child| create(child))?
    }
}

/// Which terminal controls which session.
///
/// Associating a terminal or changing a foreground group also holds the
/// process tree lock, which orders it against membership changes. Lock order:
/// the process tree lock and process state locks, then this table, then the
/// process registry and the ID allocator. No process or terminal endpoint is
/// dropped while this table is locked, since either can lead to a terminal
/// hanging up, which locks it.
#[derive(Default)]
pub(crate) struct ControllingTerminals(Mutex<Vec<Association>>);

/// A terminal controlling a session, or that controlled it until hanging up.
///
/// Retains the IDs of the session and of its foreground group, so they cannot
/// name another session or group while the terminal can still signal these.
/// Like Linux, a session whose terminal hung up keeps its foreground group,
/// which hears the session's leader leave, until the session acquires another
/// terminal.
struct Association {
    /// The terminal, or `None` once it hung up.
    terminal: Option<Arc<dyn TerminalEndpoint>>,
    session: SessionId,
    foreground: ProcessGroupId,
}

impl Association {
    fn is(&self, terminal: *const dyn TerminalEndpoint) -> bool {
        self.terminal
            .as_ref()
            .is_some_and(|this| core::ptr::addr_eq(Arc::as_ptr(this), terminal))
    }

    fn foreground_group(&self) -> ProcessGroupMembership {
        ProcessGroupMembership {
            process_group: self.foreground,
            session: self.session,
        }
    }

    /// Releases the IDs that this association retained, returning its
    /// terminal, if it has not hung up.
    fn release(self, ids: &Mutex<IdAllocator>) -> Option<Arc<dyn TerminalEndpoint>> {
        let mut ids = ids.lock();
        ids.release(self.foreground.0);
        ids.release(self.session.0);
        self.terminal
    }
}

/// Returns the controlling terminal of `process`'s session, if any.
pub(crate) fn controlling_terminal(process: &BrokerProcess) -> Option<Arc<dyn TerminalEndpoint>> {
    let _tree = process.core.process_tree_lock.lock();
    let session = process.membership().session;
    process
        .core
        .controlling_terminals
        .0
        .lock()
        .iter()
        .find(|association| association.session == session)
        .and_then(|association| association.terminal.clone())
}

/// Makes `terminal` the controlling terminal of the session that `process`
/// leads, with `process`'s group in the foreground, returning whether it was
/// not already.
///
/// Fails with `PolicyDenied` unless `process` leads a session that has no
/// other controlling terminal, has neither exited nor failed to start, and
/// `terminal` controls no other session and is `readable`. Callers hold the
/// process tree lock, and then attach a sink to a newly associated `terminal`
/// (see [`attach`]).
fn associate(
    process: &BrokerProcess,
    terminal: &Arc<dyn TerminalEndpoint>,
    readable: bool,
) -> Result<bool> {
    let membership = process.membership();
    // A leader that left its session no longer ends its terminal's control.
    let leads = membership.session == process.id().into() && !process.has_left();
    let mut associations = process.core.controlling_terminals.0.lock();
    let session_association = associations
        .iter()
        .position(|association| association.session == membership.session);
    let session_terminal =
        session_association.and_then(|index| associations[index].terminal.as_ref());
    if leads
        && session_terminal.is_some_and(|session_terminal| {
            core::ptr::addr_eq(Arc::as_ptr(session_terminal), Arc::as_ptr(terminal))
        })
    {
        return Ok(false);
    }
    if !leads
        || session_terminal.is_some()
        || associations
            .iter()
            .any(|association| association.is(Arc::as_ptr(terminal)))
        || !readable
    {
        return Err(BrokerError::PolicyDenied);
    }
    if session_association.is_none() {
        associations
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
    }
    {
        let mut ids = process.core.ids.lock();
        ids.retain(membership.process_group.0);
        ids.retain(membership.session.0);
    }
    let association = Association {
        terminal: Some(Arc::clone(terminal)),
        session: membership.session,
        foreground: membership.process_group,
    };
    match session_association {
        // The session's hung-up terminal no longer has a foreground group to
        // hang up.
        Some(index) => {
            core::mem::replace(&mut associations[index], association).release(&process.core.ids);
        }
        None => associations.push(association),
    }
    Ok(true)
}

/// Attaches a sink that delivers `terminal`'s events to the session it
/// controls, if `terminal` has none yet, and ends that control if `terminal`
/// has already hung up.
///
/// Endpoints may post events while attaching, which takes the process tree
/// lock, so callers do not hold it.
fn attach(process: &BrokerProcess, terminal: &Arc<dyn TerminalEndpoint>) {
    terminal.attach(Arc::new(TerminalSink {
        tree_lock: Arc::clone(&process.core.process_tree_lock),
        processes: Arc::downgrade(&process.core.processes),
        terminals: Arc::downgrade(&process.core.controlling_terminals),
        terminal: Arc::downgrade(terminal),
    }));
}

/// Makes `terminal` the controlling terminal of the session that `process`
/// leads, if it can be, as when the first root process starts or a session
/// leader opens a terminal for reading.
///
/// A pseudo-terminal manager never becomes a controlling terminal this way.
pub(crate) fn acquire(process: &BrokerProcess, terminal: &Arc<dyn TerminalEndpoint>) {
    if terminal.subsidiary().is_some() {
        return;
    }
    let associated = {
        let _tree = process.core.process_tree_lock.lock();
        associate(process, terminal, true)
    };
    if matches!(associated, Ok(true)) {
        attach(process, terminal);
    }
}

/// Makes the terminal that the open handle `terminal` refers to the
/// controlling terminal of the session that the process `target` leads, with
/// `target`'s group in the foreground. A pseudo-terminal manager's handle
/// refers to its subsidiary.
///
/// `target` must be the caller or its pending child, or this returns
/// `UnknownObject`. Does nothing if the terminal already controls `target`'s
/// session. Otherwise returns `PolicyDenied` if `target` leads no session, its
/// session already has a controlling terminal, the terminal controls another
/// session, or `terminal` is not open for reading. A session whose terminal
/// hung up can acquire another. Fails with
/// [`ProcessGroupError::NotControllingTerminal`] if `terminal` refers to no
/// terminal.
pub fn set_controlling_terminal(
    process: &BrokerProcess,
    target: ProcessId,
    terminal: ObjectHandle,
) -> Result<ProcessGroupResult<()>> {
    let Some((terminal, readable)) = crate::fs::handle_terminal_access(process, terminal)? else {
        return Ok(Err(ProcessGroupError::NotControllingTerminal));
    };
    let terminal = terminal.subsidiary().unwrap_or(terminal);
    let associated = {
        let _tree = process.core.process_tree_lock.lock();
        if target == process.id() {
            associate(process, &terminal, readable)
        } else {
            // The child cannot start, and so leave its session, before the
            // terminal controls it.
            process.with_pending_child(target, |child| associate(child, &terminal, readable))?
        }
    }?;
    if associated {
        attach(process, &terminal);
    }
    Ok(Ok(()))
}

/// Delivers a terminal's events to the session it controls, if any.
struct TerminalSink {
    tree_lock: Arc<Mutex<()>>,
    processes: Weak<ProcessRegistry>,
    terminals: Weak<ControllingTerminals>,
    /// The terminal, which holds this sink.
    terminal: Weak<dyn TerminalEndpoint>,
}

impl TerminalEventSink for TerminalSink {
    fn post(&self, events: TerminalEvents) {
        let (Some(terminals), Some(processes)) =
            (self.terminals.upgrade(), self.processes.upgrade())
        else {
            return;
        };
        let targets = {
            // The foreground group and its members cannot change while they
            // are selected.
            let _tree = self.tree_lock.lock();
            let Some(foreground) = terminals
                .0
                .lock()
                .iter()
                .find(|association| association.is(self.terminal.as_ptr()))
                .map(Association::foreground_group)
            else {
                return;
            };
            let mut targets = crate::registered_processes(&processes);
            targets.retain(|target| target.membership() == foreground);
            targets
        };
        for target in targets {
            target.signals.post_terminal_events(events);
        }
    }

    /// Ends the terminal's control of its session, if any, and tells the
    /// session's leader. The session keeps its foreground group until its
    /// leader leaves (see [`leader_left`]).
    ///
    /// Like process exit, which can close a manager, this never takes the
    /// process tree lock.
    fn hang_up(&self) {
        let (Some(terminals), Some(processes)) =
            (self.terminals.upgrade(), self.processes.upgrade())
        else {
            return;
        };
        let (_terminal, leader) = {
            let mut associations = terminals.0.lock();
            let Some(association) = associations
                .iter_mut()
                .find(|association| association.is(self.terminal.as_ptr()))
            else {
                return;
            };
            // The session's retained ID cannot yet name another process.
            let leader = processes
                .read()
                .get(&ProcessId(association.session.0))
                .and_then(Weak::upgrade);
            (association.terminal.take(), leader)
        };
        if let Some(leader) = leader {
            leader.signals.post_terminal_events(TerminalEvents::HANGUP);
        }
    }
}

/// Ends the control of the session that `process` leads by its terminal, as
/// `process` exits or fails to start, hanging up the session's foreground
/// group, even if the terminal already hung up.
///
/// Callers hold the process tree lock.
pub(crate) fn leader_left(process: &BrokerProcess) {
    let session = process.membership().session;
    if session != process.id().into() {
        return;
    }
    let association = {
        let mut associations = process.core.controlling_terminals.0.lock();
        let Some(index) = associations
            .iter()
            .position(|association| association.session == session)
        else {
            return;
        };
        associations.swap_remove(index)
    };
    let foreground = association.foreground_group();
    drop(association.release(&process.core.ids));
    for target in process.core.registered_processes() {
        if target.membership() == foreground {
            target.signals.post_terminal_events(TerminalEvents::HANGUP);
        }
    }
}

/// Ends the control of the session that `process` led by its terminal, if it
/// still has one as `process` is cleaned up, which happens when `process` never
/// left through [`leader_left`], as when a root process's connection fails
/// before it starts.
///
/// Signals nobody, since only a started session can have other members, and
/// takes no process tree lock, so a process can be cleaned up under it.
pub(crate) fn leader_cleaned_up(process: &BrokerProcess) {
    let session = process.id().into();
    let association = {
        let mut associations = process.core.controlling_terminals.0.lock();
        let Some(index) = associations
            .iter()
            .position(|association| association.session == session)
        else {
            return;
        };
        associations.swap_remove(index)
    };
    drop(association.release(&process.core.ids));
}

/// Returns the foreground process group of the caller's controlling terminal,
/// given an open handle `terminal` to it, or of any session's controlling
/// terminal, given its pseudo-terminal manager.
pub fn get_foreground_group(
    process: &BrokerProcess,
    terminal: ObjectHandle,
) -> Result<ProcessGroupResult<ProcessGroupMembership>> {
    let Some(terminal) = crate::fs::handle_terminal(process, terminal)? else {
        return Ok(Err(ProcessGroupError::NotControllingTerminal));
    };
    let (terminal, manager) = match terminal.subsidiary() {
        Some(subsidiary) => (subsidiary, true),
        None => (terminal, false),
    };
    let _tree = process.core.process_tree_lock.lock();
    let session = process.membership().session;
    Ok(process
        .core
        .controlling_terminals
        .0
        .lock()
        .iter()
        .find(|association| {
            association.is(Arc::as_ptr(&terminal)) && (manager || association.session == session)
        })
        .map(Association::foreground_group)
        .ok_or(ProcessGroupError::NotControllingTerminal))
}

/// Makes `process_group` the foreground group of the caller's controlling
/// terminal, given an open handle `terminal` to it or to its pseudo-terminal
/// manager.
///
/// Fails with [`ProcessGroupError::NotControllingTerminal`] if `terminal` does
/// not refer to the caller's controlling terminal, then with
/// [`ProcessGroupError::NoSuchProcessGroup`] if no process is in
/// `process_group`, and then with [`ProcessGroupError::NotInSession`] if
/// `process_group` is in another session.
pub fn set_foreground_group(
    process: &BrokerProcess,
    terminal: ObjectHandle,
    process_group: ProcessGroupId,
) -> Result<ProcessGroupResult<()>> {
    let Some(terminal) = crate::fs::handle_terminal(process, terminal)? else {
        return Ok(Err(ProcessGroupError::NotControllingTerminal));
    };
    let terminal = terminal.subsidiary().unwrap_or(terminal);
    let _tree = process.core.process_tree_lock.lock();
    let session = process.membership().session;
    let group_session = process
        .core
        .registered_processes()
        .iter()
        .map(|member| member.membership())
        .find(|membership| membership.process_group == process_group)
        .map(|membership| membership.session);
    let mut associations = process.core.controlling_terminals.0.lock();
    let Some(association) = associations.iter_mut().find(|association| {
        association.is(Arc::as_ptr(&terminal)) && association.session == session
    }) else {
        return Ok(Err(ProcessGroupError::NotControllingTerminal));
    };
    match group_session {
        None => return Ok(Err(ProcessGroupError::NoSuchProcessGroup)),
        Some(group_session) if group_session != session => {
            return Ok(Err(ProcessGroupError::NotInSession));
        }
        Some(_) => {}
    }
    let mut ids = process.core.ids.lock();
    ids.retain(process_group.0);
    ids.release(association.foreground.0);
    association.foreground = process_group;
    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use litebox_broker_protocol::fs::{
        FileAccessMode, FileError, FileMode, FileOpenFlags, FileUser,
    };
    use litebox_broker_protocol::process::{ChildSelector, ProcessExitStatus};
    use litebox_broker_protocol::process_group::{ProcessGroupError, ProcessGroupMembership};
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::signal::SignalEvent;
    use litebox_broker_protocol::terminal::{TerminalEvents, TerminalOperation, TerminalResponse};
    use litebox_broker_protocol::{ObjectHandle, ProcessGroupId, ProcessId};

    use crate::fs::FileResult;
    use crate::fs::composer::Composer;
    use crate::fs::devices::Devices;
    use crate::fs::resolver::Resolver;
    use crate::id::IdAllocator;
    use crate::random::TestRandomProvider;
    use crate::readiness::ReadinessSink;
    use crate::readiness::tests::TestReadinessSink;
    use crate::stdio::{StdioProvider as _, StdioStream};
    use crate::test_platform::TestPlatform;
    use crate::test_support::{TestBrokerCoreBuilder, TestStdioProvider};
    use crate::{
        BrokerCore, BrokerError, BrokerProcess, CallerCredential, ObjectRights, PolicyEngine,
        Result,
    };

    fn broker() -> BrokerCore {
        TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .build()
        .unwrap()
    }

    fn process(broker: &BrokerCore, parent: Option<&BrokerProcess>) -> Arc<BrokerProcess> {
        broker
            .create_process(
                CallerCredential::Unauthenticated,
                parent.map(BrokerProcess::id),
            )
            .unwrap()
    }

    fn get(process: &BrokerProcess, target: ProcessId) -> Result<ProcessGroupMembership> {
        process.process_info(target).map(|info| info.membership)
    }

    fn membership(
        process_group: &BrokerProcess,
        session: &BrokerProcess,
    ) -> ProcessGroupMembership {
        ProcessGroupMembership {
            process_group: process_group.id().into(),
            session: session.id().into(),
        }
    }

    #[test]
    fn setting_groups_follows_the_session_rules() {
        let broker = broker();
        let root = process(&broker, None);
        let first = process(&broker, Some(&root));
        let second = process(&broker, Some(&root));
        let grandchild = process(&broker, Some(&first));
        let other = process(&broker, None);

        // Only the caller and its children can move, and not session leaders.
        assert_eq!(
            super::set(&root, root.id(), root.id().into()),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(
            super::set(&root, grandchild.id(), grandchild.id().into()),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            super::set(&root, other.id(), other.id().into()),
            Err(BrokerError::UnknownObject)
        );

        // A process creates its own group or joins one in its session.
        super::set(&root, first.id(), first.id().into()).unwrap();
        super::set(&root, second.id(), first.id().into()).unwrap();
        assert_eq!(get(&root, second.id()), Ok(membership(&first, &root)));
        super::set(&second, second.id(), root.id().into()).unwrap();
        assert_eq!(get(&root, second.id()), Ok(membership(&root, &root)));
        assert_eq!(
            super::set(&second, second.id(), ProcessGroupId(u32::MAX)),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(
            super::set(&second, second.id(), other.id().into()),
            Err(BrokerError::PolicyDenied)
        );
        super::set(&first, grandchild.id(), root.id().into()).unwrap();

        // A child in another session cannot move.
        super::create_session(&grandchild, grandchild.id()).unwrap();
        assert_eq!(
            super::set(&first, grandchild.id(), first.id().into()),
            Err(BrokerError::PolicyDenied)
        );
    }

    #[test]
    fn sessions_are_created_by_processes_not_leading_a_group() {
        let broker = broker();
        let root = process(&broker, None);
        root.complete_start().unwrap();
        let child = process(&broker, Some(&root));

        assert_eq!(
            super::create_session(&root, root.id()),
            Err(BrokerError::PolicyDenied)
        );
        // Only the caller and its pending child can be targeted.
        assert_eq!(
            super::create_session(&root, child.id()),
            Err(BrokerError::UnknownObject)
        );
        let pending = root.allocate_child_process().unwrap().process_id;
        super::create_session(&root, pending).unwrap();
        assert_eq!(
            get(&root, pending),
            Ok(ProcessGroupMembership {
                process_group: pending.into(),
                session: pending.into(),
            })
        );

        // A group keeps its ID while another process is in it.
        super::set(&root, child.id(), child.id().into()).unwrap();
        let grandchild = process(&broker, Some(&child));
        super::set(&child, child.id(), root.id().into()).unwrap();
        assert_eq!(
            super::create_session(&child, child.id()),
            Err(BrokerError::PolicyDenied)
        );
        super::set(&child, grandchild.id(), root.id().into()).unwrap();
        super::create_session(&child, child.id()).unwrap();
        assert_eq!(get(&root, child.id()), Ok(membership(&child, &child)));
    }

    #[test]
    fn group_and_session_ids_are_not_reused_while_in_use() {
        let mut broker = broker();
        broker.ids = Arc::new(spin::Mutex::new(IdAllocator::new(3).unwrap()));
        let allocate = |parent: Option<&BrokerProcess>| {
            broker.allocate_process(
                CallerCredential::Unauthenticated,
                parent.map(BrokerProcess::id),
            )
        };
        let leader = allocate(None).unwrap();
        leader.complete_start().unwrap();
        let member = allocate(Some(&leader)).unwrap();
        member.complete_start().unwrap();
        let leader_id = leader.id();
        leader.retire(true);
        leader
            .complete_exit(ProcessExitStatus::Exited { code: 0 })
            .unwrap();
        drop(leader);
        let other = allocate(None).unwrap();

        // The leader's ID stays allocated while its group and session exist.
        assert_eq!(
            allocate(None).map(|process| process.id()),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            get(&other, member.id()),
            Ok(ProcessGroupMembership {
                process_group: leader_id.into(),
                session: leader_id.into(),
            })
        );
        super::create_session(&member, member.id()).unwrap();
        assert_eq!(allocate(None).unwrap().id(), leader_id);
    }

    #[test]
    fn terminal_events_reach_only_the_first_root_group_and_coalesce() {
        let stdio = TestStdioProvider::default().with_controlling_terminal();
        let broker = broker().with_terminal(stdio.terminal().unwrap());
        let root = process(&broker, None);
        let child = process(&broker, Some(&root));
        let background = process(&broker, Some(&root));
        super::set(&root, background.id(), background.id().into()).unwrap();
        let other_root = process(&broker, None);
        let handles = [&root, &child, &background, &other_root].map(|process| {
            crate::signal::open(process, Arc::new(TestReadinessSink::default())).unwrap()
        });
        stdio.post_terminal_events(TerminalEvents::INTERRUPT);
        stdio.post_terminal_events(TerminalEvents::INTERRUPT);
        stdio.post_terminal_events(TerminalEvents::RESIZE);
        for (process, handle) in [(&root, handles[0]), (&child, handles[1])] {
            assert_eq!(process.check_readiness(handle), Ok(ReadinessFlags::READ));
            assert_eq!(
                crate::signal::take(process, handle),
                Ok(SignalEvent::Terminal(
                    TerminalEvents::INTERRUPT | TerminalEvents::RESIZE
                ))
            );
            assert_eq!(
                crate::signal::take(process, handle),
                Err(BrokerError::WouldBlock)
            );
        }
        for (process, handle) in [(&background, handles[2]), (&other_root, handles[3])] {
            assert_eq!(
                crate::signal::take(process, handle),
                Err(BrokerError::WouldBlock)
            );
        }
    }

    /// Returns a broker with a terminal, where `/other/stdout` is another
    /// terminal, and the providers of both terminals.
    fn terminal_broker() -> (BrokerCore, Arc<TestStdioProvider>) {
        let (broker, stdio, _other) = terminal_broker_with_other();
        (broker, stdio)
    }

    fn terminal_broker_with_other() -> (BrokerCore, Arc<TestStdioProvider>, Arc<TestStdioProvider>)
    {
        let stdio = Arc::new(TestStdioProvider::default().with_controlling_terminal());
        let devices = |stdio: Arc<TestStdioProvider>| {
            move |allocator| Devices::new(allocator, stdio, Arc::new(TestRandomProvider))
        };
        let other = Arc::new(TestStdioProvider::default().with_terminal(StdioStream::Stdout));
        let fs = Composer::builder()
            .mount("/dev", devices(Arc::clone(&stdio)))
            .mount("/other", devices(Arc::clone(&other)))
            .build()
            .unwrap();
        let broker = TestBrokerCoreBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .with_file_service(Arc::new(Resolver::<TestPlatform, _>::new(fs)))
        .build()
        .unwrap()
        .with_terminal(stdio.terminal().unwrap());
        (broker, stdio, other)
    }

    fn open(process: &BrokerProcess, path: &str, flags: FileOpenFlags) -> ObjectHandle {
        open_for(process, path, FileAccessMode::ReadWrite, flags).unwrap()
    }

    fn open_for(
        process: &BrokerProcess,
        path: &str,
        access: FileAccessMode,
        flags: FileOpenFlags,
    ) -> FileResult<ObjectHandle> {
        let sink: Arc<dyn ReadinessSink> = Arc::new(TestReadinessSink::default());
        crate::fs::open(
            process,
            path,
            FileUser::ROOT,
            access,
            flags,
            FileMode::empty(),
            &sink,
        )
        .unwrap()
    }

    fn signals(process: &BrokerProcess) -> ObjectHandle {
        crate::signal::open(process, Arc::new(TestReadinessSink::default())).unwrap()
    }

    fn assert_signalled(process: &BrokerProcess, handle: ObjectHandle, events: TerminalEvents) {
        assert_eq!(
            crate::signal::take(process, handle),
            Ok(SignalEvent::Terminal(events))
        );
        assert_eq!(
            crate::signal::take(process, handle),
            Err(BrokerError::WouldBlock)
        );
    }

    fn assert_not_signalled(process: &BrokerProcess, handle: ObjectHandle) {
        assert_eq!(
            crate::signal::take(process, handle),
            Err(BrokerError::WouldBlock)
        );
    }

    #[test]
    fn the_session_moves_terminal_events_to_its_foreground_group() {
        let (broker, stdio) = terminal_broker();
        let root = process(&broker, None);
        let job = process(&broker, Some(&root));
        super::set(&root, job.id(), job.id().into()).unwrap();
        let detached = process(&broker, Some(&root));
        super::create_session(&detached, detached.id()).unwrap();
        let other_root = process(&broker, None);
        let [root_tty, job_tty] =
            [&root, &job].map(|process| open(process, "/dev/tty", FileOpenFlags::NONE));

        // The first root's group starts in the foreground.
        assert_eq!(
            super::get_foreground_group(&job, job_tty),
            Ok(Ok(membership(&root, &root)))
        );
        // A terminal controls only its session, which alone can open it as
        // `/dev/tty`.
        for process in [&detached, &other_root] {
            assert_eq!(
                open_for(
                    process,
                    "/dev/tty",
                    FileAccessMode::ReadWrite,
                    FileOpenFlags::NONE
                ),
                Err(FileError::NoSuchDevice)
            );
        }
        let other = |process| {
            open(
                process,
                "/other/stdout",
                FileOpenFlags::NO_CONTROLLING_TERMINAL,
            )
        };
        for (process, terminal) in [
            (&detached, other(&detached)),
            (&other_root, other(&other_root)),
            (&root, other(&root)),
            (&root, open(&root, "/dev/stdout", FileOpenFlags::NONE)),
            (&root, open(&root, "/dev/tty", FileOpenFlags::PATH)),
        ] {
            assert_eq!(
                super::get_foreground_group(process, terminal),
                Ok(Err(ProcessGroupError::NotControllingTerminal))
            );
            assert_eq!(
                super::set_foreground_group(process, terminal, root.id().into()),
                Ok(Err(ProcessGroupError::NotControllingTerminal))
            );
        }
        // Only an existing group in the session can be in the foreground.
        for (process_group, error) in [
            (detached.id().into(), ProcessGroupError::NotInSession),
            (other_root.id().into(), ProcessGroupError::NotInSession),
            (
                ProcessGroupId(u32::MAX),
                ProcessGroupError::NoSuchProcessGroup,
            ),
        ] {
            assert_eq!(
                super::set_foreground_group(&root, root_tty, process_group),
                Ok(Err(error))
            );
        }
        assert_eq!(
            super::set_foreground_group(&job, job_tty, job.id().into()),
            Ok(Ok(()))
        );
        assert_eq!(
            super::get_foreground_group(&root, root_tty),
            Ok(Ok(membership(&job, &root)))
        );

        let handles = [&root, &job].map(|process| {
            crate::signal::open(process, Arc::new(TestReadinessSink::default())).unwrap()
        });
        stdio.post_terminal_events(TerminalEvents::INTERRUPT);
        assert_eq!(
            crate::signal::take(&job, handles[1]),
            Ok(SignalEvent::Terminal(TerminalEvents::INTERRUPT))
        );
        assert_eq!(
            crate::signal::take(&root, handles[0]),
            Err(BrokerError::WouldBlock)
        );
    }

    #[test]
    fn the_foreground_group_keeps_its_id_while_in_the_foreground() {
        let (mut broker, _stdio) = terminal_broker();
        broker.ids = Arc::new(spin::Mutex::new(IdAllocator::new(3).unwrap()));
        let allocate = |parent: Option<&BrokerProcess>| {
            broker.allocate_process(
                CallerCredential::Unauthenticated,
                parent.map(BrokerProcess::id),
            )
        };
        let root = allocate(None).unwrap();
        root.complete_start().unwrap();
        let terminal = broker.terminal.lock().take().unwrap();
        super::acquire(&root, &terminal);
        let tty = open(&root, "/dev/tty", FileOpenFlags::NONE);
        let job = allocate(Some(&root)).unwrap();
        job.complete_start().unwrap();
        let job_id = job.id();
        super::set(&root, job_id, job_id.into()).unwrap();
        assert_eq!(
            super::set_foreground_group(&root, tty, job_id.into()),
            Ok(Ok(()))
        );
        job.retire(true);
        job.complete_exit(ProcessExitStatus::Exited { code: 0 })
            .unwrap();
        drop(job);
        root.collect_child_exit(ChildSelector::Process(job_id))
            .unwrap();
        let other = allocate(None).unwrap();

        // The exited job's group stays in the foreground until the session
        // moves another group there.
        assert_eq!(
            allocate(None).map(|process| process.id()),
            Err(BrokerError::ResourceExhausted)
        );
        assert_eq!(
            super::set_foreground_group(&root, tty, root.id().into()),
            Ok(Ok(()))
        );
        assert_eq!(allocate(None).unwrap().id(), job_id);
        drop(other);
    }

    #[test]
    fn a_session_leader_acquires_a_terminal_it_opens_for_reading() {
        let (broker, _stdio, other) = terminal_broker_with_other();
        let root = process(&broker, None);
        let leader = process(&broker, None);
        let member = process(&broker, Some(&leader));
        let second = process(&broker, None);
        let open_other =
            |process, access, flags| open_for(process, "/other/stdout", access, flags).unwrap();
        let no_tty = |process: &BrokerProcess| {
            open_for(
                process,
                "/dev/tty",
                FileAccessMode::ReadWrite,
                FileOpenFlags::NONE,
            )
        };

        // Only a session leader without a terminal acquires one, by opening it
        // for reading without `NO_CONTROLLING_TERMINAL`.
        let member_terminal = open_other(&member, FileAccessMode::ReadWrite, FileOpenFlags::NONE);
        open_other(&leader, FileAccessMode::WriteOnly, FileOpenFlags::NONE);
        open_other(
            &leader,
            FileAccessMode::ReadWrite,
            FileOpenFlags::NO_CONTROLLING_TERMINAL,
        );
        open_other(&root, FileAccessMode::ReadWrite, FileOpenFlags::NONE);
        assert_eq!(no_tty(&member), Err(FileError::NoSuchDevice));
        assert_eq!(
            super::get_foreground_group(&member, member_terminal),
            Ok(Err(ProcessGroupError::NotControllingTerminal))
        );
        open_other(&leader, FileAccessMode::ReadOnly, FileOpenFlags::NONE);
        assert_eq!(
            super::get_foreground_group(&member, member_terminal),
            Ok(Ok(membership(&leader, &leader)))
        );
        // A terminal controls one session at a time.
        open_other(&second, FileAccessMode::ReadWrite, FileOpenFlags::NONE);
        assert_eq!(no_tty(&second), Err(FileError::NoSuchDevice));

        // The session's members reach it as `/dev/tty`, and it signals the
        // session's foreground group.
        let tty = open(&member, "/dev/tty", FileOpenFlags::NONE);
        assert_eq!(crate::fs::write(&member, tty, b"tty", None), Ok(Ok(3)));
        assert_eq!(other.terminal_writes(), [b"tty".to_vec()]);
        let handles = [&leader, &member, &root, &second].map(|process| signals(process));
        other.post_terminal_events(TerminalEvents::INTERRUPT);
        assert_signalled(&leader, handles[0], TerminalEvents::INTERRUPT);
        assert_signalled(&member, handles[1], TerminalEvents::INTERRUPT);
        assert_not_signalled(&root, handles[2]);
        assert_not_signalled(&second, handles[3]);
    }

    #[test]
    fn setting_the_controlling_terminal_follows_the_session_rules() {
        let (broker, _stdio) = terminal_broker();
        let root = process(&broker, None);
        root.complete_start().unwrap();
        let leader = process(&broker, None);
        leader.complete_start().unwrap();
        let member = process(&broker, Some(&leader));
        let second = process(&broker, None);
        let other = |process| {
            open(
                process,
                "/other/stdout",
                FileOpenFlags::NO_CONTROLLING_TERMINAL,
            )
        };

        // Only a session leader without a terminal can acquire one that
        // controls no other session, through a handle open for reading.
        for (process, target, terminal) in [
            (&member, member.id(), other(&member)),
            (&root, root.id(), other(&root)),
            (
                &leader,
                leader.id(),
                open_for(
                    &leader,
                    "/other/stdout",
                    FileAccessMode::WriteOnly,
                    FileOpenFlags::NONE,
                )
                .unwrap(),
            ),
        ] {
            assert_eq!(
                super::set_controlling_terminal(process, target, terminal),
                Err(BrokerError::PolicyDenied)
            );
        }
        assert_eq!(
            super::set_controlling_terminal(&leader, member.id(), other(&leader)),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            super::set_controlling_terminal(
                &leader,
                leader.id(),
                open(&leader, "/dev/stdout", FileOpenFlags::NONE)
            ),
            Ok(Err(ProcessGroupError::NotControllingTerminal))
        );
        let terminal = other(&leader);
        for _ in 0..2 {
            assert_eq!(
                super::set_controlling_terminal(&leader, leader.id(), terminal),
                Ok(Ok(()))
            );
        }
        assert_eq!(
            super::get_foreground_group(&member, other(&member)),
            Ok(Ok(membership(&leader, &leader)))
        );
        assert_eq!(
            super::set_controlling_terminal(&second, second.id(), other(&second)),
            Err(BrokerError::PolicyDenied)
        );

        // A pending child that leads a session can acquire a terminal before
        // it starts, here through a pseudo-terminal manager.
        let manager = open(&root, "/dev/ptmx", FileOpenFlags::NONE);
        let pending = root.allocate_child_process().unwrap().process_id;
        assert_eq!(
            super::set_controlling_terminal(&root, pending, manager),
            Err(BrokerError::PolicyDenied)
        );
        super::create_session(&root, pending).unwrap();
        assert_eq!(
            super::set_controlling_terminal(&root, pending, manager),
            Ok(Ok(()))
        );
        assert_eq!(
            super::get_foreground_group(&root, manager),
            Ok(Ok(ProcessGroupMembership {
                process_group: pending.into(),
                session: pending.into(),
            }))
        );
    }

    #[test]
    fn a_pseudo_terminal_controls_a_session_until_its_manager_closes() {
        let (broker, _stdio) = terminal_broker();
        let root = process(&broker, None);
        let leader = process(&broker, Some(&root));
        leader.complete_start().unwrap();
        super::create_session(&leader, leader.id()).unwrap();
        let job = process(&broker, Some(&leader));
        job.complete_start().unwrap();
        super::set(&leader, job.id(), job.id().into()).unwrap();
        let manager = open(&root, "/dev/ptmx", FileOpenFlags::NONE);
        assert_eq!(
            crate::fs::terminal_control(
                &root,
                manager,
                TerminalOperation::SetSubsidiaryLock(false)
            ),
            Ok(Ok(TerminalResponse::Done))
        );

        // Opening a manager never acquires it, while opening its subsidiary
        // does.
        let leader_manager = open(&leader, "/dev/ptmx", FileOpenFlags::NONE);
        assert_eq!(
            super::get_foreground_group(&leader, leader_manager),
            Ok(Err(ProcessGroupError::NotControllingTerminal))
        );
        let subsidiary = open(&leader, "/dev/pts/0", FileOpenFlags::NONE);
        // Through the manager, any process can see the foreground group, but
        // only the session's processes can change it.
        assert_eq!(
            super::get_foreground_group(&root, manager),
            Ok(Ok(membership(&leader, &leader)))
        );
        assert_eq!(
            super::set_foreground_group(&root, manager, job.id().into()),
            Ok(Err(ProcessGroupError::NotControllingTerminal))
        );
        let job_manager = root
            .duplicate_object_references_to(&[manager], &job)
            .unwrap()[0];
        assert_eq!(
            super::set_foreground_group(&job, job_manager, job.id().into()),
            Ok(Ok(()))
        );
        assert_eq!(
            super::get_foreground_group(&leader, subsidiary),
            Ok(Ok(membership(&job, &leader)))
        );

        // `/dev/tty` reaches the subsidiary, and the manager's input signals
        // the foreground group.
        let tty = open(&job, "/dev/tty", FileOpenFlags::NONE);
        assert_eq!(crate::fs::write(&job, tty, b"out", None), Ok(Ok(3)));
        let mut output = [0; 8];
        assert_eq!(
            crate::fs::read(&root, manager, &mut output, None),
            Ok(Ok(3))
        );
        assert_eq!(&output[..3], b"out");
        let handles = [&leader, &job].map(|process| signals(process));
        assert_eq!(crate::fs::write(&root, manager, b"\x03", None), Ok(Ok(1)));
        assert_not_signalled(&leader, handles[0]);
        assert_signalled(&job, handles[1], TerminalEvents::INTERRUPT);

        // Closing the manager hangs up the subsidiary, which tells the leader
        // and stops controlling the session.
        root.close_object_reference(manager).unwrap();
        job.close_object_reference(job_manager).unwrap();
        assert_signalled(&leader, handles[0], TerminalEvents::HANGUP);
        assert_not_signalled(&job, handles[1]);
        assert_eq!(
            super::get_foreground_group(&leader, subsidiary),
            Ok(Err(ProcessGroupError::NotControllingTerminal))
        );
        assert_eq!(
            open_for(
                &job,
                "/dev/tty",
                FileAccessMode::ReadWrite,
                FileOpenFlags::NONE
            ),
            Err(FileError::NoSuchDevice)
        );

        // Like Linux, the session keeps its foreground group, which hears the
        // leader leave.
        leader.retire(true);
        leader
            .complete_exit(ProcessExitStatus::Exited { code: 0 })
            .unwrap();
        assert_signalled(&job, handles[1], TerminalEvents::HANGUP);
    }

    #[test]
    fn dev_tty_holds_a_pseudo_terminal_open_and_hangs_up_late_sessions() {
        let (broker, _stdio) = terminal_broker();
        let root = process(&broker, None);
        let [leader, late] = [(); 2].map(|()| {
            let leader = process(&broker, Some(&root));
            super::create_session(&leader, leader.id()).unwrap();
            leader
        });
        let manager = open(&root, "/dev/ptmx", FileOpenFlags::NONE);
        assert_eq!(
            crate::fs::terminal_control(
                &root,
                manager,
                TerminalOperation::SetSubsidiaryLock(false)
            ),
            Ok(Ok(TerminalResponse::Done))
        );
        let subsidiary = open(&leader, "/dev/pts/0", FileOpenFlags::NONE);

        // `/dev/tty` keeps the subsidiary open after its other files close.
        let tty = open(&leader, "/dev/tty", FileOpenFlags::NONE);
        leader.close_object_reference(subsidiary).unwrap();
        let mut output = [0; 8];
        assert_eq!(
            crate::fs::read(&root, manager, &mut output, None),
            Err(BrokerError::WouldBlock)
        );
        leader.close_object_reference(tty).unwrap();
        assert_eq!(
            crate::fs::read(&root, manager, &mut output, None),
            Ok(Err(FileError::Io))
        );

        // A subsidiary that starts controlling a session after hanging up
        // hangs up that session too.
        let late_subsidiary = open(&late, "/dev/pts/0", FileOpenFlags::NO_CONTROLLING_TERMINAL);
        let handles = [&leader, &late].map(|process| signals(process));
        root.close_object_reference(manager).unwrap();
        assert_signalled(&leader, handles[0], TerminalEvents::HANGUP);
        assert_not_signalled(&late, handles[1]);
        assert_eq!(
            super::set_controlling_terminal(&late, late.id(), late_subsidiary),
            Ok(Ok(()))
        );
        assert_signalled(&late, handles[1], TerminalEvents::HANGUP);
        assert_eq!(
            super::get_foreground_group(&late, late_subsidiary),
            Ok(Err(ProcessGroupError::NotControllingTerminal))
        );

        // The session can then acquire another terminal.
        let manager = open(&root, "/dev/ptmx", FileOpenFlags::NONE);
        assert_eq!(
            crate::fs::terminal_control(
                &root,
                manager,
                TerminalOperation::SetSubsidiaryLock(false)
            ),
            Ok(Ok(TerminalResponse::Done))
        );
        let next = open(&late, "/dev/pts/1", FileOpenFlags::NONE);
        assert_eq!(
            super::get_foreground_group(&late, next),
            Ok(Ok(membership(&late, &late)))
        );
    }

    #[test]
    fn a_root_dropped_before_starting_releases_its_terminal() {
        let (broker, _stdio, other) = terminal_broker_with_other();
        let broker = broker.with_terminal(other.terminal().unwrap());
        // As when the root's connection fails before it starts.
        let root = process(&broker, None);
        root.retire(true);
        drop(root);
        let next = process(&broker, None);
        open(&next, "/other/stdout", FileOpenFlags::NONE);
        let tty = open(&next, "/dev/tty", FileOpenFlags::NONE);
        assert_eq!(
            super::get_foreground_group(&next, tty),
            Ok(Ok(membership(&next, &next)))
        );
    }

    #[test]
    fn the_foreground_group_hears_its_session_leader_exit() {
        let (broker, _stdio) = terminal_broker();
        let _root = process(&broker, None);
        let leader = process(&broker, None);
        leader.complete_start().unwrap();
        let [member, background] = [(); 2].map(|()| {
            let child = process(&broker, Some(&leader));
            child.complete_start().unwrap();
            child
        });
        super::set(&leader, background.id(), background.id().into()).unwrap();
        let member_terminal = open(&member, "/other/stdout", FileOpenFlags::NONE);
        let leader_terminal = open(&leader, "/other/stdout", FileOpenFlags::NONE);
        let terminal = crate::fs::handle_terminal(&leader, leader_terminal)
            .unwrap()
            .unwrap();
        let handles = [&member, &background].map(|process| signals(process));

        leader.retire(true);
        leader
            .complete_exit(ProcessExitStatus::Exited { code: 0 })
            .unwrap();
        assert_signalled(&member, handles[0], TerminalEvents::HANGUP);
        assert_not_signalled(&background, handles[1]);
        // A leader that left cannot acquire it again, as when an open races
        // its exit, so the session lost its terminal, which another session
        // can acquire.
        super::acquire(&leader, &terminal);
        assert_eq!(
            super::get_foreground_group(&member, member_terminal),
            Ok(Err(ProcessGroupError::NotControllingTerminal))
        );
        let next = process(&broker, None);
        open(&next, "/other/stdout", FileOpenFlags::NONE);
        let tty = open(&next, "/dev/tty", FileOpenFlags::NONE);
        assert_eq!(
            super::get_foreground_group(&next, tty),
            Ok(Ok(membership(&next, &next)))
        );
    }
}
