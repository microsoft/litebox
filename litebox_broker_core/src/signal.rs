// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Signals sent between broker processes, and child event notifications.
//!
//! Every process has pending signals that any process may send to, and learns
//! of its children's exits and removals alongside them. A process opens a handle to take
//! these events, which becomes readable while any is pending. Events that
//! occur before the process opens its handle stay pending until it takes
//! them.

use alloc::sync::Arc;
use alloc::vec;

use litebox_broker_protocol::process::ChildExit;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::signal::{MAX_SIGNAL, PendingSignal, SignalEvent, SignalTarget};
use litebox_broker_protocol::terminal::TerminalEvents;
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use spin::Mutex;

use crate::object::{ObjectEntry, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::{BrokerError, BrokerProcess, Result};

/// Opens the caller's signals, returning a handle that becomes readable while
/// any event is pending.
///
/// A process may hold only one such handle at a time; opening another fails
/// with `ResourceExhausted`. Fails with `PolicyDenied` if the caller may not
/// wait on objects, since taking signals needs that right.
pub fn open(
    process: &BrokerProcess,
    readiness_sink: Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let rights = process.require_object_rights(ObjectRights::WAIT)?;
    let reference = process.reserve_object_reference(rights)?;
    let readiness = ReadinessRegistration::new(reference.handle(), readiness_sink);
    {
        let mut state = process.signals.0.lock();
        if state.readiness.is_some() {
            return Err(BrokerError::ResourceExhausted);
        }
        state.readiness = Some(readiness);
    }
    reference.commit(ObjectEntry::Signals(SignalsObject {
        signals: Arc::clone(&process.signals),
    }))
}

/// Sends `signal` to the processes `target` selects, or only checks that one
/// exists if `signal` is zero.
///
/// A signal already pending for a target is not sent again. Returns
/// `UnknownObject` if no process is targeted.
pub fn send(process: &BrokerProcess, target: SignalTarget, signal: u32) -> Result<()> {
    if signal > MAX_SIGNAL {
        return Err(BrokerError::UnsupportedOperation);
    }
    let targets = match target {
        SignalTarget::Process(id) => vec![process.pid_namespace().registered_process(id)?],
        SignalTarget::ProcessGroup(process_group) => {
            // Members cannot move between groups while they are selected.
            let _tree = process.core.process_tree_lock.lock();
            let own = process.membership();
            // Groups can span nested namespaces, so look in the top-level one.
            let mut targets = process.pid_namespace().top_level().registered_processes();
            targets.retain(|target| {
                target
                    .membership()
                    .belongs_to_group(process_group, process.pid_namespace(), &own)
            });
            targets
        }
        SignalTarget::All => {
            let mut targets = process.pid_namespace().registered_processes();
            let pid_namespace = process.pid_namespace();
            targets.retain(|target| {
                target.key() != process.key() && !pid_namespace.is_first_process(target)
            });
            targets
        }
    };
    if targets.is_empty() {
        return Err(BrokerError::UnknownObject);
    }
    if let Some(index) = signal.checked_sub(1) {
        for target in &targets {
            // A sender that the target's namespace doesn't see is 0.
            let sender = process
                .process_id_in_namespace(target.pid_namespace())
                .unwrap_or(ProcessId(0));
            target.signals.send(index as usize, sender);
        }
    }
    Ok(())
}

/// Takes the caller's lowest-numbered pending signal, or else its pending
/// child exit, or else its pending child removal.
///
/// Returns `WouldBlock` if no event is pending.
pub fn take(process: &BrokerProcess, handle: ObjectHandle) -> Result<SignalEvent> {
    let object = process.authorized_object(handle, ObjectRights::WAIT)?;
    let object = object.read();
    object.as_signals()?.signals.take()
}

impl ObjectEntry {
    fn as_signals(&self) -> Result<&SignalsObject> {
        match self {
            Self::Signals(signals) => Ok(signals),
            _ => Err(BrokerError::InvalidRights),
        }
    }
}

/// The pending signals and child events of one process.
pub(crate) struct ProcessSignals(Mutex<ProcessSignalsState>);

struct ProcessSignalsState {
    /// The terminal events posted since the process last took them.
    terminal_events: TerminalEvents,
    /// The sender of each pending signal, indexed by signal number minus one,
    /// or `None` if that signal isn't pending. A sender is the process ID the
    /// receiver sees, which is 0 if the receiver can't see the sender.
    ///
    /// A signal sent again while it's pending merges into the pending one,
    /// which keeps its first sender unless a later sender is 0. A merged
    /// signal that any invisible sender sent is thus still reported as coming
    /// from outside the receiver's view.
    senders: [Option<ProcessId>; MAX_SIGNAL as usize],
    /// The earliest child exit since the process last took one.
    ///
    /// Like a pending signal, later exits coalesce into it. The process
    /// collects its children's exits separately, so only the notification
    /// coalesces.
    child_exit: Option<ChildExit>,
    /// Whether a child left the process without exiting since the process
    /// last took this event.
    child_removed: bool,
    /// Publication for the process's open handle, if any.
    readiness: Option<ReadinessRegistration>,
}

impl ProcessSignals {
    pub(crate) fn new() -> Self {
        Self(Mutex::new(ProcessSignalsState {
            terminal_events: TerminalEvents::empty(),
            senders: [None; MAX_SIGNAL as usize],
            child_exit: None,
            child_removed: false,
            readiness: None,
        }))
    }

    fn send(&self, index: usize, sender: ProcessId) {
        let mut state = self.0.lock();
        match &mut state.senders[index] {
            Some(pending) => {
                if sender == ProcessId(0) {
                    *pending = sender;
                }
            }
            pending @ None => {
                *pending = Some(sender);
                state.republish();
            }
        }
    }

    /// Notifies the process that its child exited, unless an earlier exit
    /// is still pending.
    pub(crate) fn post_child_exit(&self, exit: ChildExit) {
        let mut state = self.0.lock();
        if state.child_exit.is_some() {
            return;
        }
        state.child_exit = Some(exit);
        state.republish();
    }

    /// Notifies the process that a child left it without exiting, unless an
    /// earlier removal is still pending.
    pub(crate) fn post_child_removed(&self) {
        let mut state = self.0.lock();
        if state.child_removed {
            return;
        }

        state.child_removed = true;
        state.republish();
    }

    pub(crate) fn post_terminal_events(&self, events: TerminalEvents) {
        let mut state = self.0.lock();
        state.terminal_events |= events;
        state.republish();
    }

    fn take(&self) -> Result<SignalEvent> {
        let mut state = self.0.lock();
        let terminal_events = core::mem::take(&mut state.terminal_events);
        if !terminal_events.is_empty() {
            return Ok(SignalEvent::Terminal(terminal_events));
        }
        let signal = state
            .senders
            .iter_mut()
            .enumerate()
            .find_map(|(index, sender)| Some((index, sender.take()?)));
        if let Some((index, sender)) = signal {
            return Ok(SignalEvent::Signal(PendingSignal {
                signal: u32::try_from(index + 1).expect("signal numbers fit in u32"),
                sender,
            }));
        }
        if let Some(exit) = state.child_exit.take() {
            return Ok(SignalEvent::ChildExited(exit));
        }
        if core::mem::take(&mut state.child_removed) {
            return Ok(SignalEvent::ChildRemoved);
        }
        Err(BrokerError::WouldBlock)
    }

    fn readiness(&self) -> ReadinessFlags {
        let state = self.0.lock();
        if state.child_exit.is_some()
            || !state.terminal_events.is_empty()
            || state.child_removed
            || state.senders.iter().any(Option::is_some)
        {
            ReadinessFlags::READ
        } else {
            ReadinessFlags::default()
        }
    }
}

impl ProcessSignalsState {
    /// Republishes readiness after an event becomes pending, since a waiter
    /// that took the previous events may not have observed readiness change
    /// since.
    fn republish(&self) {
        if let Some(readiness) = &self.readiness {
            readiness.republish(ReadinessFlags::READ);
        }
    }
}

/// A process's handle to its own pending signals.
pub(crate) struct SignalsObject {
    signals: Arc<ProcessSignals>,
}

impl SignalsObject {
    pub(crate) fn readiness(&self) -> ReadinessFlags {
        self.signals.readiness()
    }
}

impl Drop for SignalsObject {
    fn drop(&mut self) {
        let readiness = self.signals.0.lock().readiness.take();
        if let Some(readiness) = readiness {
            readiness.retire();
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use litebox_broker_protocol::fs::FileOpenFlags;
    use litebox_broker_protocol::process::{ChildExit, CpuTime, ProcessExitStatus};
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::signal::{PendingSignal, SignalEvent, SignalTarget};
    use litebox_broker_protocol::{ObjectHandle, ProcessGroupId, ProcessId};

    use crate::readiness::tests::TestReadinessSink;
    use crate::test_support::{TestBroker, TestBrokerBuilder};
    use crate::{BrokerError, BrokerProcess, CallerCredential, ObjectRights, PolicyEngine};

    fn broker() -> TestBroker {
        TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap()
    }

    fn process(broker: &TestBroker) -> Arc<BrokerProcess> {
        broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap()
    }

    fn pending(signal: u32, sender: ProcessId) -> SignalEvent {
        SignalEvent::Signal(PendingSignal { signal, sender })
    }

    fn to(process: &BrokerProcess) -> SignalTarget {
        SignalTarget::Process(process.id())
    }

    #[test]
    fn signals_stay_pending_until_taken() {
        let broker = broker();
        let target = process(&broker);
        let first = process(&broker);
        let second = process(&broker);

        // Signals sent before the target opens its handle stay pending, and
        // repeated signals keep their first sender.
        super::send(&first, to(&target), 10).unwrap();
        super::send(&second, to(&target), 10).unwrap();
        super::send(&second, to(&target), 64).unwrap();
        super::send(&second, to(&target), 2).unwrap();
        let sink = Arc::new(TestReadinessSink::default());
        let handle = super::open(&target, sink.clone()).unwrap();
        assert_eq!(target.check_readiness(handle), Ok(ReadinessFlags::READ));
        assert_eq!(super::take(&target, handle), Ok(pending(2, second.id())));
        assert_eq!(super::take(&target, handle), Ok(pending(10, first.id())));
        assert_eq!(super::take(&target, handle), Ok(pending(64, second.id())));
        assert_eq!(super::take(&target, handle), Err(BrokerError::WouldBlock));
        assert_eq!(
            target.check_readiness(handle),
            Ok(ReadinessFlags::default())
        );
        assert!(sink.republished.lock().unwrap().is_empty());

        // A signal sent while the handle is open republishes readiness, but
        // one already pending does not.
        super::send(&first, to(&target), 15).unwrap();
        super::send(&second, to(&target), 15).unwrap();
        assert_eq!(
            *sink.republished.lock().unwrap(),
            [(handle, ReadinessFlags::READ)]
        );
        assert_eq!(super::take(&target, handle), Ok(pending(15, first.id())));

        // Signals are taken only through a signals handle.
        let event = crate::event::create(&target, 0, FileOpenFlags::NONE).unwrap();
        assert_eq!(super::take(&target, event), Err(BrokerError::InvalidRights));

        target.close_object_reference(handle).unwrap();
        assert_eq!(*sink.retired.lock().unwrap(), [handle]);
        super::send(&first, to(&target), 15).unwrap();
        assert_eq!(sink.republished.lock().unwrap().len(), 1);
    }

    #[test]
    fn sending_checks_the_target_and_signal() {
        let broker = broker();
        let sender = process(&broker);
        let target = process(&broker);
        let handle = super::open(&target, Arc::new(TestReadinessSink::default())).unwrap();

        // Signal zero only checks that the target exists.
        super::send(&sender, to(&target), 0).unwrap();
        assert_eq!(super::take(&target, handle), Err(BrokerError::WouldBlock));
        assert_eq!(
            super::send(&sender, SignalTarget::Process(ProcessId(u32::MAX)), 0),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            super::send(&sender, SignalTarget::Process(ProcessId(u32::MAX)), 9),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            super::send(&sender, to(&target), 65),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_eq!(super::take(&target, handle), Err(BrokerError::WouldBlock));

        // A process can signal itself.
        super::send(&target, to(&target), 1).unwrap();
        assert_eq!(super::take(&target, handle), Ok(pending(1, target.id())));
    }

    #[test]
    fn signals_reach_process_groups_and_all_processes() {
        let broker = broker();
        let root = process(&broker);
        let other = process(&broker);
        // No process other than the caller and the first process exists yet.
        assert_eq!(
            super::send(&other, SignalTarget::All, 0),
            Err(BrokerError::UnknownObject)
        );
        let first = root.create_child().unwrap();
        let second = root.create_child().unwrap();
        crate::process_group::set(&root, second.id(), second.id().into()).unwrap();
        let sink = Arc::new(TestReadinessSink::default());
        let handles = [&root, &other, &first, &second]
            .map(|process| (process, super::open(process, sink.clone()).unwrap()));
        let take_all = || {
            handles
                .iter()
                .filter_map(|(process, handle)| match super::take(process, *handle) {
                    Ok(SignalEvent::Signal(signal)) => Some((process.id(), signal.signal)),
                    _ => None,
                })
                .collect::<std::vec::Vec<_>>()
        };

        super::send(&other, SignalTarget::ProcessGroup(root.id().into()), 10).unwrap();
        assert_eq!(take_all(), [(root.id(), 10), (first.id(), 10)]);
        super::send(&other, SignalTarget::ProcessGroup(second.id().into()), 0).unwrap();
        super::send(&other, SignalTarget::ProcessGroup(second.id().into()), 12).unwrap();
        assert_eq!(take_all(), [(second.id(), 12)]);
        assert_eq!(
            super::send(
                &other,
                SignalTarget::ProcessGroup(ProcessGroupId(u32::MAX)),
                0
            ),
            Err(BrokerError::UnknownObject)
        );

        // The namespace's first process and the sender are spared.
        super::send(&first, SignalTarget::All, 15).unwrap();
        assert_eq!(take_all(), [(other.id(), 15), (second.id(), 15)]);
        super::send(&root, SignalTarget::All, 15).unwrap();
        assert_eq!(
            take_all(),
            [(other.id(), 15), (first.id(), 15), (second.id(), 15)]
        );
        assert_eq!(
            super::send(&root, SignalTarget::All, 65),
            Err(BrokerError::UnsupportedOperation)
        );
    }

    #[test]
    fn child_events_coalesce_and_follow_pending_signals() {
        let broker = broker();
        let parent = process(&broker);
        let sink = Arc::new(TestReadinessSink::default());
        let handle = super::open(&parent, sink.clone()).unwrap();
        let exit = |id, code| ChildExit {
            process_id: ProcessId(id),
            exit_status: ProcessExitStatus::Exited { code },
            cpu_time: CpuTime::default(),
            children_cpu_time: CpuTime::default(),
        };

        // Later child events coalesce into pending ones, and only a newly
        // pending event republishes readiness.
        parent.signals.post_child_removed();
        parent.signals.post_child_removed();
        parent.signals.post_child_exit(exit(100, 1));
        parent.signals.post_child_exit(exit(101, 2));
        super::send(&parent, to(&parent), 17).unwrap();
        assert_eq!(
            *sink.republished.lock().unwrap(),
            [(handle, ReadinessFlags::READ); 3]
        );

        // Signals are taken first, then the child exit, then the removal.
        assert_eq!(super::take(&parent, handle), Ok(pending(17, parent.id())));
        assert_eq!(
            super::take(&parent, handle),
            Ok(SignalEvent::ChildExited(exit(100, 1)))
        );
        assert_eq!(parent.check_readiness(handle), Ok(ReadinessFlags::READ));
        assert_eq!(super::take(&parent, handle), Ok(SignalEvent::ChildRemoved));
        assert_eq!(super::take(&parent, handle), Err(BrokerError::WouldBlock));
        assert_eq!(
            parent.check_readiness(handle),
            Ok(ReadinessFlags::default())
        );

        // Once taken, each child event is notified again.
        parent.signals.post_child_exit(exit(102, 3));
        parent.signals.post_child_removed();
        assert_eq!(sink.republished.lock().unwrap().len(), 5);
        assert_eq!(
            super::take(&parent, handle),
            Ok(SignalEvent::ChildExited(exit(102, 3)))
        );
        assert_eq!(super::take(&parent, handle), Ok(SignalEvent::ChildRemoved));
    }

    #[test]
    fn a_process_opens_one_signals_handle_at_a_time() {
        let broker = broker();
        let process = process(&broker);
        let sink = Arc::new(TestReadinessSink::default());
        let handle = super::open(&process, sink.clone()).unwrap();

        assert_eq!(
            super::open(&process, sink.clone()),
            Err(BrokerError::ResourceExhausted)
        );
        // The rejected registration is retired without disturbing the open one.
        let retired = sink.retired.lock().unwrap().clone();
        assert_eq!(retired.len(), 1);
        assert_ne!(retired[0], handle);
        super::send(&process, to(&process), 3).unwrap();
        assert_eq!(
            *sink.republished.lock().unwrap(),
            [(handle, ReadinessFlags::READ)]
        );

        process.close_object_reference(handle).unwrap();
        let reopened = super::open(&process, sink.clone()).unwrap();
        assert_eq!(
            super::take(&process, reopened),
            Ok(pending(3, process.id()))
        );
        assert_eq!(
            super::take(&process, ObjectHandle(u64::MAX)),
            Err(BrokerError::UnknownObject)
        );
    }

    #[test]
    fn opening_signals_requires_the_wait_right() {
        let broker = TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::WRITE,
        ))
        .build()
        .unwrap();
        let process = process(&broker);
        let sink = Arc::new(TestReadinessSink::default());

        assert_eq!(
            super::open(&process, sink.clone()),
            Err(BrokerError::PolicyDenied)
        );
        assert!(sink.retired.lock().unwrap().is_empty());
    }
}
