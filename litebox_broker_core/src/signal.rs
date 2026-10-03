// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Signals sent between broker processes.
//!
//! Every process has pending signals that any process may send to. A process
//! opens a handle to take them, which becomes readable while any is pending.
//! Signals sent before the process opens its handle stay pending until it
//! takes them.

use alloc::sync::Arc;
use alloc::vec;

use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::signal::{MAX_SIGNAL, PendingSignal, SignalTarget};
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use spin::Mutex;

use crate::object::{ObjectEntry, ObjectRights};
use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::{BrokerError, BrokerProcess, Result};

/// Opens the caller's signals, returning a handle that becomes readable while
/// any is pending.
///
/// A process may hold only one such handle at a time; opening another fails
/// with `ResourceExhausted`. Fails with `PolicyDenied` if the caller may not
/// wait on objects, since taking signals needs that right.
pub fn open(
    process: &BrokerProcess,
    readiness_sink: Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let rights = process
        .core
        .policy
        .principal_object_rights(process.caller_credential)?;
    if !rights.contains(ObjectRights::WAIT) {
        return Err(BrokerError::PolicyDenied);
    }
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
        SignalTarget::Process(id) => vec![process.core.registered_process(id)?],
        SignalTarget::ProcessGroup(process_group) => {
            // Members cannot move between groups while they are selected.
            let _serialized = process.core.process_groups.lock();
            let mut targets = process.core.registered_processes();
            targets.retain(|target| target.membership().process_group == process_group);
            targets
        }
        SignalTarget::All => {
            let mut targets = process.core.registered_processes();
            targets.retain(|target| target.id() != process.id() && target.has_parent());
            targets
        }
    };
    if targets.is_empty() {
        return Err(BrokerError::UnknownObject);
    }
    if let Some(index) = signal.checked_sub(1) {
        for target in &targets {
            target.signals.send(index as usize, process.id);
        }
    }
    Ok(())
}

/// Takes the caller's lowest-numbered pending signal.
///
/// Returns `WouldBlock` if none is pending.
pub fn take(process: &BrokerProcess, handle: ObjectHandle) -> Result<PendingSignal> {
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

/// The pending signals of one process.
pub(crate) struct ProcessSignals(Mutex<ProcessSignalsState>);

struct ProcessSignalsState {
    /// The process that first sent each pending signal, indexed by signal
    /// number minus one.
    senders: [Option<ProcessId>; MAX_SIGNAL as usize],
    /// Publication for the process's open handle, if any.
    readiness: Option<ReadinessRegistration>,
}

impl ProcessSignals {
    pub(crate) fn new() -> Self {
        Self(Mutex::new(ProcessSignalsState {
            senders: [None; MAX_SIGNAL as usize],
            readiness: None,
        }))
    }

    fn send(&self, index: usize, sender: ProcessId) {
        let mut state = self.0.lock();
        if state.senders[index].is_some() {
            return;
        }
        state.senders[index] = Some(sender);
        // Republish, since a waiter that took the previous signals may not
        // have observed readiness change since.
        if let Some(readiness) = &state.readiness {
            let _ = readiness.republish(ReadinessFlags::READ);
        }
    }

    fn take(&self) -> Result<PendingSignal> {
        let mut state = self.0.lock();
        let (index, sender) = state
            .senders
            .iter_mut()
            .enumerate()
            .find_map(|(index, sender)| Some((index, sender.take()?)))
            .ok_or(BrokerError::WouldBlock)?;
        Ok(PendingSignal {
            signal: u32::try_from(index + 1).expect("signal numbers fit in u32"),
            sender,
        })
    }

    fn readiness(&self) -> ReadinessFlags {
        if self.0.lock().senders.iter().any(Option::is_some) {
            ReadinessFlags::READ
        } else {
            ReadinessFlags::default()
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

    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::signal::{PendingSignal, SignalTarget};
    use litebox_broker_protocol::{ObjectHandle, ProcessId};

    use crate::readiness::tests::TestReadinessSink;
    use crate::test_support::TestBrokerCoreBuilder;
    use crate::{
        BrokerCore, BrokerError, BrokerProcess, CallerCredential, ObjectRights, PolicyEngine,
    };

    fn broker() -> BrokerCore {
        TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap()
    }

    fn process(broker: &BrokerCore) -> Arc<BrokerProcess> {
        broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap()
    }

    fn pending(signal: u32, sender: ProcessId) -> PendingSignal {
        PendingSignal { signal, sender }
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
        let event = crate::event::create(&target, 0).unwrap();
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
        let first = broker
            .create_process(CallerCredential::Unauthenticated, Some(root.id()))
            .unwrap();
        // No process other than the caller has a parent yet.
        assert_eq!(
            super::send(&first, SignalTarget::All, 0),
            Err(BrokerError::UnknownObject)
        );
        let second = broker
            .create_process(CallerCredential::Unauthenticated, Some(root.id()))
            .unwrap();
        crate::process_group::set(&root, second.id(), second.id()).unwrap();
        let sink = Arc::new(TestReadinessSink::default());
        let handles = [&root, &other, &first, &second]
            .map(|process| (process, super::open(process, sink.clone()).unwrap()));
        let take_all = || {
            handles
                .iter()
                .filter_map(|(process, handle)| {
                    Some((process.id(), super::take(process, *handle).ok()?.signal))
                })
                .collect::<std::vec::Vec<_>>()
        };

        super::send(&other, SignalTarget::ProcessGroup(root.id()), 10).unwrap();
        assert_eq!(take_all(), [(root.id(), 10), (first.id(), 10)]);
        super::send(&other, SignalTarget::ProcessGroup(second.id()), 0).unwrap();
        super::send(&other, SignalTarget::ProcessGroup(second.id()), 12).unwrap();
        assert_eq!(take_all(), [(second.id(), 12)]);
        assert_eq!(
            super::send(&other, SignalTarget::ProcessGroup(ProcessId(u32::MAX)), 0),
            Err(BrokerError::UnknownObject)
        );

        // Processes without a parent and the sender are spared.
        super::send(&first, SignalTarget::All, 15).unwrap();
        assert_eq!(take_all(), [(second.id(), 15)]);
        super::send(&root, SignalTarget::All, 15).unwrap();
        assert_eq!(take_all(), [(first.id(), 15), (second.id(), 15)]);
        assert_eq!(
            super::send(&root, SignalTarget::All, 65),
            Err(BrokerError::UnsupportedOperation)
        );
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
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
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
