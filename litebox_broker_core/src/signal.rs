// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Signals sent between broker processes, and child event notifications.
//!
//! Every process has pending signals that any process may send to, either to
//! the process or to one of its threads, and learns of its children's exits
//! and removals alongside them. A process opens a handle to take
//! these events, which becomes readable while any is pending. Events that
//! occur before the process opens its handle stay pending until it takes
//! them.

use alloc::sync::Arc;
use alloc::vec;

use hashbrown::HashMap;

use litebox_broker_protocol::process::ChildExit;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::signal::{MAX_SIGNAL, PendingSignal, SignalEvent, SignalTarget};
use litebox_broker_protocol::terminal::TerminalEvents;
use litebox_broker_protocol::{ObjectHandle, ProcessId, ThreadId};
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

/// Sends `signal` to the processes or thread `target` selects, or only checks
/// that one exists if `signal` is zero.
///
/// A signal already pending for a target is not sent again. Returns
/// `UnknownObject` if no process or thread is targeted.
pub fn send(process: &BrokerProcess, target: SignalTarget, signal: u32) -> Result<()> {
    if signal > MAX_SIGNAL {
        return Err(BrokerError::UnsupportedOperation);
    }
    let targets = match target {
        SignalTarget::Process(id) => vec![process.pid_namespace().registered_process(id)?],
        SignalTarget::Thread {
            process: id,
            thread,
        } => {
            let target = process.pid_namespace().registered_process(id)?;
            return send_to_thread(process, &target, thread, signal);
        }
        SignalTarget::ProcessGroup(process_group) => {
            // Members cannot move between groups while they are selected.
            let _tree = process.core.process_tree_lock.lock();
            let caller_group = process.process_group();
            // Groups can span nested namespaces, so look in the top-level one.
            let mut targets = process.pid_namespace().top_level().registered_processes();
            targets.retain(|target| {
                target
                    .process_group()
                    .has_id(process_group, process.pid_namespace(), &caller_group)
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

/// Sends `signal` from `process` to `target`'s thread with ID `thread` in
/// `process`'s namespace, or only checks that the thread belongs to `target` if
/// `signal` is zero.
fn send_to_thread(
    process: &BrokerProcess,
    target: &BrokerProcess,
    thread: ThreadId,
    signal: u32,
) -> Result<()> {
    // The thread cannot end, which drops its signals, before its signal is
    // pending.
    target.with_live_thread(process.pid_namespace(), thread, |thread| {
        if let Some(index) = signal.checked_sub(1) {
            // A sender that the target's namespace doesn't see is 0.
            let sender = process
                .process_id_in_namespace(target.pid_namespace())
                .unwrap_or(ProcessId(0));
            target
                .signals
                .send_to_thread(thread, index as usize, sender)?;
        }
        Ok(())
    })
}

/// Takes the caller's lowest-numbered pending signal, or else, for one of its
/// threads in no particular order, that thread's lowest-numbered pending
/// signal, or else its pending child exit, or else its pending child removal.
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
    /// The signals pending for the process.
    ///
    /// A sender is its process ID in the receiver's namespace, or 0 if the
    /// receiver can't see it. Sending a signal that is already pending doesn't
    /// queue another: the pending one keeps its first sender, unless the new
    /// sender is 0.
    senders: PendingSenders,
    /// The signals pending for the process's threads, by their IDs in the
    /// process's own namespace, with senders as in `senders`.
    ///
    /// A thread has an entry only while it is alive, so the entries are
    /// bounded by the thread quota.
    thread_signals: HashMap<ThreadId, PendingSenders>,
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
            senders: PendingSenders::EMPTY,
            thread_signals: HashMap::new(),
            child_exit: None,
            child_removed: false,
            readiness: None,
        }))
    }

    /// Makes the signal numbered `index + 1` from `sender` pending for the
    /// process, unless it already is.
    pub(crate) fn send(&self, index: usize, sender: ProcessId) {
        let mut state = self.0.lock();
        if state.senders.add(index, sender) {
            state.republish();
        }
    }

    /// Makes the signal numbered `index + 1` from `sender` pending for
    /// `thread`, unless it already is.
    fn send_to_thread(&self, thread: ThreadId, index: usize, sender: ProcessId) -> Result<()> {
        let mut state = self.0.lock();
        if !state.thread_signals.contains_key(&thread) {
            state
                .thread_signals
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
        }
        let added = state
            .thread_signals
            .entry(thread)
            .or_insert(PendingSenders::EMPTY)
            .add(index, sender);
        if added {
            state.republish();
        }
        Ok(())
    }

    /// Drops the signals pending for `thread`, which ended.
    pub(crate) fn discard_signals_of_thread(&self, thread: ThreadId) {
        self.0.lock().thread_signals.remove(&thread);
    }

    /// Drops the signals pending for every thread, since all have ended.
    pub(crate) fn discard_signals_of_threads(&self) {
        // Freed once the lock is released.
        let thread_signals = core::mem::take(&mut self.0.lock().thread_signals);
        drop(thread_signals);
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
        if let Some((signal, sender)) = state.senders.take_lowest() {
            return Ok(SignalEvent::Signal(PendingSignal {
                thread: None,
                signal,
                sender,
            }));
        }
        let thread_signal = state
            .thread_signals
            .iter_mut()
            .find_map(|(&thread, senders)| {
                let (signal, sender) = senders.take_lowest()?;
                Some((thread, signal, sender, senders.is_empty()))
            });
        if let Some((thread, signal, sender, taken_all)) = thread_signal {
            if taken_all {
                state.thread_signals.remove(&thread);
            }
            return Ok(SignalEvent::Signal(PendingSignal {
                thread: Some(thread),
                signal,
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
            || !state.senders.is_empty()
            || !state.thread_signals.is_empty()
        {
            ReadinessFlags::READ
        } else {
            ReadinessFlags::default()
        }
    }
}

/// The process that first sent each pending signal, indexed by signal number
/// minus one.
#[derive(Clone, Copy)]
struct PendingSenders([Option<ProcessId>; MAX_SIGNAL as usize]);

impl PendingSenders {
    const EMPTY: Self = Self([None; MAX_SIGNAL as usize]);

    /// Makes the signal numbered `index + 1` from `sender` pending, returning
    /// whether it was not already.
    ///
    /// A pending signal keeps its first sender, unless `sender` is 0, the
    /// sender the receiver can't see.
    fn add(&mut self, index: usize, sender: ProcessId) -> bool {
        match &mut self.0[index] {
            Some(pending) => {
                if sender == ProcessId(0) {
                    *pending = sender;
                }
                false
            }
            pending @ None => {
                *pending = Some(sender);
                true
            }
        }
    }

    /// Takes the lowest-numbered pending signal and its sender.
    fn take_lowest(&mut self) -> Option<(u32, ProcessId)> {
        self.0
            .iter_mut()
            .zip(1..)
            .find_map(|(sender, signal)| Some((signal, sender.take()?)))
    }

    fn is_empty(&self) -> bool {
        self.0.iter().all(Option::is_none)
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
    use alloc::vec::Vec;

    use litebox_broker_protocol::fs::FileOpenFlags;
    use litebox_broker_protocol::process::{ChildExit, CpuTime, ProcessExitStatus};
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::signal::{PendingSignal, SignalEvent, SignalTarget};
    use litebox_broker_protocol::{ObjectHandle, ProcessGroupId, ProcessId, ThreadId};

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
        SignalEvent::Signal(PendingSignal {
            thread: None,
            signal,
            sender,
        })
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
    fn signals_reach_threads_of_their_process() {
        let broker = broker();
        let sender = process(&broker);
        let target = process(&broker);
        let other = process(&broker);
        let thread = target.create_thread().unwrap();
        let initial = target.initial_thread_id();
        let sink = Arc::new(TestReadinessSink::default());
        let handle = super::open(&target, sink.clone()).unwrap();
        let to_thread = |process: &BrokerProcess, thread| SignalTarget::Thread {
            process: process.id(),
            thread,
        };
        let thread_pending = |thread, signal, sender: &BrokerProcess| {
            SignalEvent::Signal(PendingSignal {
                thread: Some(thread),
                signal,
                sender: sender.id(),
            })
        };

        // A thread is targeted only with the process it belongs to.
        for missing in [
            to_thread(&other, thread),
            to_thread(&target, ThreadId(u32::MAX)),
        ] {
            assert_eq!(
                super::send(&sender, missing, 10),
                Err(BrokerError::UnknownObject)
            );
        }
        super::send(&sender, to_thread(&target, thread), 0).unwrap();
        super::send(&sender, to_thread(&target, initial), 0).unwrap();
        assert_eq!(super::take(&target, handle), Err(BrokerError::WouldBlock));

        // Signals coalesce per thread, keeping their first sender, and are
        // taken after the process's own, lowest-numbered first for each
        // thread.
        super::send(&sender, to_thread(&target, thread), 12).unwrap();
        super::send(&sender, to_thread(&target, thread), 10).unwrap();
        super::send(&other, to_thread(&target, thread), 10).unwrap();
        super::send(&other, to_thread(&target, initial), 10).unwrap();
        super::send(&other, to(&target), 12).unwrap();
        assert_eq!(target.check_readiness(handle), Ok(ReadinessFlags::READ));
        // Each newly pending signal republishes readiness, but the coalesced one does not.
        assert_eq!(sink.republished.lock().unwrap().len(), 4);
        assert_eq!(super::take(&target, handle), Ok(pending(12, other.id())));
        let taken: Vec<_> = (0..3)
            .map(|_| super::take(&target, handle).unwrap())
            .collect();
        assert_eq!(super::take(&target, handle), Err(BrokerError::WouldBlock));
        assert_eq!(
            target.check_readiness(handle),
            Ok(ReadinessFlags::default())
        );
        let taken_by = |thread| {
            taken
                .iter()
                .copied()
                .filter(|event| {
                    matches!(event, SignalEvent::Signal(pending) if pending.thread == Some(thread))
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            taken_by(thread),
            [
                thread_pending(thread, 10, &sender),
                thread_pending(thread, 12, &sender)
            ]
        );
        assert_eq!(taken_by(initial), [thread_pending(initial, 10, &other)]);

        // A thread that ends drops its pending signals, but not other
        // threads', and can no longer be signaled.
        super::send(&sender, to_thread(&target, thread), 10).unwrap();
        super::send(&sender, to_thread(&target, initial), 12).unwrap();
        target.exit_thread(thread).unwrap();
        // A signal pending only for a thread makes the handle readable.
        assert_eq!(target.check_readiness(handle), Ok(ReadinessFlags::READ));
        assert_eq!(
            super::take(&target, handle),
            Ok(thread_pending(initial, 12, &sender))
        );
        assert_eq!(super::take(&target, handle), Err(BrokerError::WouldBlock));
        assert_eq!(
            target.check_readiness(handle),
            Ok(ReadinessFlags::default())
        );
        assert_eq!(
            super::send(&sender, to_thread(&target, thread), 0),
            Err(BrokerError::UnknownObject)
        );
    }

    #[test]
    fn threads_of_an_ended_process_drop_their_signals() {
        let broker = broker();
        let sender = process(&broker);
        let target = sender.create_child(sender.pid_namespace(), false).unwrap();
        target.complete_start().unwrap();
        let initial = target.initial_thread_id();
        let to_initial = SignalTarget::Thread {
            process: target.id(),
            thread: initial,
        };
        super::send(&sender, to_initial, 10).unwrap();

        // Once the process ends, its threads' pending signals are dropped, and
        // its initial thread neither takes signals nor is reported.
        target.retire(true);
        target
            .complete_exit(ProcessExitStatus::Exited { code: 0 }, CpuTime::default())
            .unwrap();
        assert!(target.signals.0.lock().thread_signals.is_empty());
        assert_eq!(
            sender.process_info(target.id()).unwrap().initial_thread,
            None
        );
        assert_eq!(
            super::send(&sender, to_initial, 0),
            Err(BrokerError::UnknownObject)
        );
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
        let first = root.create_child(root.pid_namespace(), false).unwrap();
        let second = root.create_child(root.pid_namespace(), false).unwrap();
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
