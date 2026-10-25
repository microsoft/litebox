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
//! The broker's terminal controls the first root process's session and
//! signals its foreground group, which starts as that process's group and
//! which processes in the session can change.

use alloc::sync::{Arc, Weak};

use litebox_broker_protocol::fs::FileError;
use litebox_broker_protocol::process_group::ProcessGroupMembership;
use litebox_broker_protocol::terminal::TerminalEvents;
use litebox_broker_protocol::{ProcessGroupId, ProcessId, SessionId};
use spin::{Mutex, Once};

use crate::fs::FileResult;
use crate::id::IdAllocator;
use crate::terminal::{TerminalEndpoint, TerminalEventSink};
use crate::{BrokerError, BrokerProcess, ProcessRegistry, Result};

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

/// The broker's guest terminal, which controls the session of the first root
/// process.
pub(crate) struct ControllingTerminal {
    endpoint: Arc<dyn TerminalEndpoint>,
    /// Set when the first root process attaches the terminal.
    sink: Once<Arc<TerminalSink>>,
}

impl ControllingTerminal {
    pub(crate) fn new(endpoint: Arc<dyn TerminalEndpoint>) -> Self {
        Self {
            endpoint,
            sink: Once::new(),
        }
    }

    /// Makes the terminal control `process`'s session, with `process`'s group
    /// in the foreground, unless it already controls a session.
    pub(crate) fn attach(&self, process: &BrokerProcess) {
        self.sink.call_once(|| {
            // The group's IDs cannot be released before they are retained.
            let _tree = process.core.process_tree_lock.lock();
            let membership = process.membership();
            {
                let mut ids = process.core.ids.lock();
                ids.retain(membership.process_group.0);
                ids.retain(membership.session.0);
            }
            let sink = Arc::new(TerminalSink {
                processes: Arc::downgrade(&process.core.processes),
                tree_lock: Arc::clone(&process.core.process_tree_lock),
                ids: Arc::clone(&process.core.ids),
                session: membership.session,
                foreground: Mutex::new(membership.process_group),
            });
            self.endpoint.attach(sink.clone());
            sink
        });
    }
}

/// Delivers a terminal's events to its foreground process group.
///
/// The sink keeps the IDs of that group and of the terminal's session
/// reserved, so they cannot name another group or session while the terminal
/// can still signal this one.
struct TerminalSink {
    processes: Weak<ProcessRegistry>,
    tree_lock: Arc<Mutex<()>>,
    ids: Arc<Mutex<IdAllocator>>,
    session: SessionId,
    /// Changes only under the process tree lock.
    foreground: Mutex<ProcessGroupId>,
}

impl TerminalEventSink for TerminalSink {
    fn post(&self, events: TerminalEvents) {
        let targets = {
            // The foreground group and its members cannot change while they
            // are selected.
            let _tree = self.tree_lock.lock();
            let Some(processes) = self.processes.upgrade() else {
                return;
            };
            let foreground = ProcessGroupMembership {
                process_group: *self.foreground.lock(),
                session: self.session,
            };
            let mut targets = crate::registered_processes(&processes);
            targets.retain(|target| target.membership() == foreground);
            targets
        };
        for target in targets {
            target.signals.post_terminal_events(events);
        }
    }
}

impl Drop for TerminalSink {
    fn drop(&mut self) {
        let mut ids = self.ids.lock();
        ids.release(self.foreground.get_mut().0);
        ids.release(self.session.0);
    }
}

/// Returns the sink of `terminal` if it is the caller's controlling terminal.
fn controlling_terminal<'a>(
    process: &'a BrokerProcess,
    terminal: &Arc<dyn TerminalEndpoint>,
) -> FileResult<&'a TerminalSink> {
    process
        .core
        .terminal
        .as_ref()
        .filter(|controlling| {
            core::ptr::addr_eq(Arc::as_ptr(&controlling.endpoint), Arc::as_ptr(terminal))
        })
        .and_then(|controlling| controlling.sink.get())
        .filter(|sink| process.membership().session == sink.session)
        .map(|sink| &**sink)
        .ok_or(FileError::NotControllingTerminal)
}

/// Returns the foreground process group of `terminal`, which must be the
/// caller's controlling terminal.
pub(crate) fn foreground_group(
    process: &BrokerProcess,
    terminal: &Arc<dyn TerminalEndpoint>,
) -> FileResult<ProcessGroupMembership> {
    let _tree = process.core.process_tree_lock.lock();
    let sink = controlling_terminal(process, terminal)?;
    Ok(ProcessGroupMembership {
        process_group: *sink.foreground.lock(),
        session: sink.session,
    })
}

/// Makes `process_group`, an existing group in the caller's session, the
/// foreground group of `terminal`, which must be the caller's controlling
/// terminal.
pub(crate) fn set_foreground_group(
    process: &BrokerProcess,
    terminal: &Arc<dyn TerminalEndpoint>,
    process_group: ProcessGroupId,
) -> FileResult<()> {
    let _tree = process.core.process_tree_lock.lock();
    let sink = controlling_terminal(process, terminal)?;
    let session = process
        .core
        .registered_processes()
        .iter()
        .map(|member| member.membership())
        .find(|membership| membership.process_group == process_group)
        .ok_or(FileError::NoSuchProcessGroup)?
        .session;
    if session != sink.session {
        return Err(FileError::ProcessGroupNotInSession);
    }
    let mut current = sink.foreground.lock();
    let mut ids = process.core.ids.lock();
    ids.retain(process_group.0);
    ids.release(current.0);
    *current = process_group;
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use litebox_broker_protocol::fs::FileError;
    use litebox_broker_protocol::process::{ChildSelector, ProcessExitStatus};
    use litebox_broker_protocol::process_group::ProcessGroupMembership;
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::signal::SignalEvent;
    use litebox_broker_protocol::terminal::TerminalEvents;
    use litebox_broker_protocol::{ProcessGroupId, ProcessId};

    use crate::id::IdAllocator;
    use crate::readiness::tests::TestReadinessSink;
    use crate::test_support::TestBrokerCoreBuilder;
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
        use crate::stdio::StdioProvider as _;
        use crate::test_support::TestStdioProvider;

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

    #[test]
    fn the_session_moves_terminal_events_to_its_foreground_group() {
        use crate::stdio::StdioProvider as _;
        use crate::test_support::TestStdioProvider;

        let stdio = TestStdioProvider::default().with_controlling_terminal();
        let terminal = stdio.terminal().unwrap();
        let broker = broker().with_terminal(Arc::clone(&terminal));
        let root = process(&broker, None);
        let job = process(&broker, Some(&root));
        super::set(&root, job.id(), job.id().into()).unwrap();
        let detached = process(&broker, Some(&root));
        super::create_session(&detached, detached.id()).unwrap();
        let other_root = process(&broker, None);
        let other_terminal = TestStdioProvider::default()
            .with_controlling_terminal()
            .terminal()
            .unwrap();

        // The first root's group starts in the foreground.
        assert_eq!(
            super::foreground_group(&job, &terminal),
            Ok(membership(&root, &root))
        );
        // Only the broker's terminal is a controlling terminal, and only of
        // the first root's session.
        for (process, terminal) in [
            (&detached, &terminal),
            (&other_root, &terminal),
            (&root, &other_terminal),
        ] {
            assert_eq!(
                super::foreground_group(process, terminal),
                Err(FileError::NotControllingTerminal)
            );
            assert_eq!(
                super::set_foreground_group(process, terminal, root.id().into()),
                Err(FileError::NotControllingTerminal)
            );
        }
        // Only an existing group in the session can be in the foreground.
        for (process_group, error) in [
            (detached.id().into(), FileError::ProcessGroupNotInSession),
            (other_root.id().into(), FileError::ProcessGroupNotInSession),
            (ProcessGroupId(u32::MAX), FileError::NoSuchProcessGroup),
        ] {
            assert_eq!(
                super::set_foreground_group(&root, &terminal, process_group),
                Err(error)
            );
        }
        super::set_foreground_group(&job, &terminal, job.id().into()).unwrap();
        assert_eq!(
            super::foreground_group(&root, &terminal),
            Ok(membership(&job, &root))
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
        use crate::stdio::StdioProvider as _;
        use crate::test_support::TestStdioProvider;

        let stdio = TestStdioProvider::default().with_controlling_terminal();
        let terminal = stdio.terminal().unwrap();
        let mut broker = broker().with_terminal(Arc::clone(&terminal));
        broker.ids = Arc::new(spin::Mutex::new(IdAllocator::new(3).unwrap()));
        let allocate = |parent: Option<&BrokerProcess>| {
            broker.allocate_process(
                CallerCredential::Unauthenticated,
                parent.map(BrokerProcess::id),
            )
        };
        let root = allocate(None).unwrap();
        root.complete_start().unwrap();
        broker.terminal.as_ref().unwrap().attach(&root);
        let job = allocate(Some(&root)).unwrap();
        job.complete_start().unwrap();
        let job_id = job.id();
        super::set(&root, job_id, job_id.into()).unwrap();
        super::set_foreground_group(&root, &terminal, job_id.into()).unwrap();
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
        super::set_foreground_group(&root, &terminal, root.id().into()).unwrap();
        assert_eq!(allocate(None).unwrap().id(), job_id);
        drop(other);
    }
}
