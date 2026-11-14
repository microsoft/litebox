// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process handles, which refer to one process rather than to its ID.
//!
//! A handle never refers to a later process that reuses its process's ID, and
//! it keeps neither the process, nor its IDs, nor its registration in its PID
//! namespace from going away. It becomes readable once the process's exit is
//! observable, and readable and closed once the process is released: its exit
//! was collected or discarded, or it never started. A handle can be a signal
//! target ([`SignalTarget::ProcessHandle`]) and can select the child whose
//! exit to collect ([`ChildSelector::ProcessHandle`]).
//!
//! [`SignalTarget::ProcessHandle`]: litebox_broker_protocol::signal::SignalTarget::ProcessHandle
//! [`ChildSelector::ProcessHandle`]: litebox_broker_protocol::process::ChildSelector::ProcessHandle

use alloc::sync::{Arc, Weak};

use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags, FileStatusFlags};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::{ObjectHandle, ProcessId};

use crate::object::{ObjectEntry, ObjectRights, StatusFlags};
use crate::process::ExitReadiness;
use crate::readiness::{ReadinessRegistration, ReadinessSink};
use crate::{BrokerError, BrokerProcess, Result};

/// Opens a handle to the process `process_id` in the caller's PID namespace,
/// which may be a child that hasn't started yet.
///
/// The handle starts with the status flags `flags`, which must be within
/// [`FileOpenFlags::STATUS`] (or this returns `UnsupportedOperation`), and
/// its reference publishes readiness through `readiness_sink`. Returns
/// `UnknownObject` if no such process exists or it was released.
pub fn open(
    process: &BrokerProcess,
    process_id: ProcessId,
    flags: FileOpenFlags,
    readiness_sink: &Arc<dyn ReadinessSink>,
) -> Result<ObjectHandle> {
    let status = StatusFlags::new(flags)?;
    let target = process.pid_namespace().registered_process(process_id)?;
    let rights = process
        .core
        .policy
        .principal_object_rights(process.caller_credential)?;
    let reference = process.reserve_object_reference(rights)?;
    let registration = ReadinessRegistration::new(reference.handle(), Arc::clone(readiness_sink));
    target.exit.watch(&registration)?;
    reference.commit_with_readiness(
        ObjectEntry::ProcessHandle(ProcessHandleObject {
            target: Arc::downgrade(&target),
            exit: Arc::clone(&target.exit),
            status,
        }),
        Some(registration),
    )
}

/// Returns the process that `handle`, a process handle of the caller, refers
/// to, held weakly: this identifies the process by its allocation and keeps
/// nothing else of it.
///
/// Returns `InvalidRights` if `handle` is of another kind.
pub(crate) fn target(process: &BrokerProcess, handle: ObjectHandle) -> Result<Weak<BrokerProcess>> {
    let object = process.authorized_object(handle, ObjectRights::WAIT)?;
    Ok(Weak::clone(&object.read().as_process_handle()?.target))
}

/// Returns the process that `handle`, a process handle of the caller, refers
/// to, for sending it a signal.
///
/// Returns `InvalidRights` if `handle` is of another kind, `PeerClosed` if the
/// process was released, and `UnknownObject` if the caller's PID namespace
/// doesn't see it.
pub(crate) fn signal_target(
    process: &BrokerProcess,
    handle: ObjectHandle,
) -> Result<Arc<BrokerProcess>> {
    let target = target(process, handle)?
        .upgrade()
        .filter(|target| !target.is_released())
        .ok_or(BrokerError::PeerClosed)?;
    if target
        .process_id_in_namespace(process.pid_namespace())
        .is_none()
    {
        return Err(BrokerError::UnknownObject);
    }
    Ok(target)
}

impl ObjectEntry {
    fn as_process_handle(&self) -> Result<&ProcessHandleObject> {
        match self {
            Self::ProcessHandle(handle) => Ok(handle),
            _ => Err(BrokerError::InvalidRights),
        }
    }
}

/// A handle to one process, whose references share its status flags.
pub(crate) struct ProcessHandleObject {
    /// The process, held weakly so that only its allocation is kept, whose
    /// address identifies it even once its ID is reused.
    target: Weak<BrokerProcess>,
    /// The process's exit, which the handle reads without upgrading `target`,
    /// so that the process's last reference never drops under an object lock.
    exit: Arc<ExitReadiness>,
    status: StatusFlags,
}

impl ProcessHandleObject {
    pub(crate) fn readiness(&self) -> ReadinessFlags {
        self.exit.readiness()
    }

    /// Publishes the process's exit through `registration` until every clone
    /// of `registration` drops.
    pub(crate) fn watch(&self, registration: &ReadinessRegistration) -> Result<()> {
        self.exit.watch(registration)
    }

    /// Returns the handle's access mode and status flags.
    pub(crate) fn get_status_flags(&self) -> FileStatusFlags {
        self.status.get(FileAccessMode::ReadWrite)
    }

    /// Changes the status flags in `mask` to their values in `flags`.
    pub(crate) fn set_status_flags(&mut self, mask: FileOpenFlags, flags: FileOpenFlags) {
        self.status.set(mask, flags);
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::fs::{
        FileAccessMode, FileOpenFlags, FileStatusFlags, SetStatusFlagsRequest,
    };
    use litebox_broker_protocol::process::{
        ChildSelector, CpuTime, PidNamespaceOptions, ProcessExitStatus,
    };
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::readiness_queue::{
        ReadinessQueueEntryFlags, ReadinessQueueInterest, ReadyEvent,
    };
    use litebox_broker_protocol::signal::{PendingSignal, SignalEvent, SignalTarget};

    use crate::id::IdAllocator;
    use crate::readiness::ReadinessSink;
    use crate::readiness::tests::TestReadinessSink;
    use crate::test_support::{TestBroker, TestBrokerBuilder};
    use crate::{
        BrokerCoreLimits, BrokerError, BrokerProcess, CallerCredential, ObjectRights, PolicyEngine,
    };

    const EXITED: ReadinessFlags = ReadinessFlags::READ;
    const RELEASED: ReadinessFlags =
        ReadinessFlags(ReadinessFlags::READ.0 | ReadinessFlags::CLOSED.0);

    fn broker(limits: BrokerCoreLimits) -> TestBroker {
        TestBrokerBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .with_limits(limits)
        .build()
        .unwrap()
    }

    /// Creates and starts a root process.
    fn started_root(broker: &TestBroker) -> Arc<BrokerProcess> {
        let root = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        root.complete_start().unwrap();
        root
    }

    /// Creates a starting child of `parent`.
    fn child_of(parent: &BrokerProcess) -> Arc<BrokerProcess> {
        parent.create_child(parent.pid_namespace(), false).unwrap()
    }

    /// Starts `process` if it is starting, then has it exit.
    fn exit(process: &BrokerProcess) {
        if process.startup_result().is_none() {
            process.complete_start().unwrap();
        }
        process.retire(true);
        process
            .complete_exit(ProcessExitStatus::Exited { code: 0 }, CpuTime::default())
            .unwrap();
    }

    fn sink() -> Arc<TestReadinessSink> {
        Arc::new(TestReadinessSink::default())
    }

    /// Opens a handle of `process` to `target`, returning it and the sink its
    /// readiness goes to.
    fn open(
        process: &BrokerProcess,
        target: &BrokerProcess,
    ) -> (ObjectHandle, Arc<TestReadinessSink>) {
        let sink = sink();
        let target = target
            .process_id_in_namespace(process.pid_namespace())
            .unwrap();
        let handle = super::open(
            process,
            target,
            FileOpenFlags::NONE,
            &(sink.clone() as Arc<dyn ReadinessSink>),
        )
        .unwrap();
        (handle, sink)
    }

    /// Returns the readiness published to `sink`, in order.
    fn published(sink: &TestReadinessSink) -> Vec<ReadinessFlags> {
        sink.published
            .lock()
            .unwrap()
            .iter()
            .map(|(_, readiness)| *readiness)
            .collect()
    }

    #[test]
    fn handles_become_readable_at_exit_and_closed_at_collection() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let root = started_root(&broker);
        let child = child_of(&root);
        let (handle, root_sink) = open(&root, &child);
        // A duplicate in another process and a readiness queue entry see the
        // same changes.
        let other = started_root(&broker);
        let other_sink = sink();
        let duplicate = root
            .duplicate_object_reference_to(handle, &other, ObjectRights::WAIT)
            .unwrap();
        other
            .register_readiness(&(other_sink.clone() as Arc<dyn ReadinessSink>))
            .unwrap();
        let queue =
            crate::readiness_queue::create(&root, &(sink() as Arc<dyn ReadinessSink>)).unwrap();
        let interest = ReadinessQueueInterest {
            readiness: ReadinessFlags::READ,
            flags: ReadinessQueueEntryFlags::empty(),
            token: 7,
        };
        crate::readiness_queue::add(&root, queue, handle, 0, interest)
            .unwrap()
            .unwrap();
        // Every reference shares the status flags.
        root.set_status_flags(SetStatusFlagsRequest {
            handle,
            mask: FileOpenFlags::NONBLOCKING,
            flags: FileOpenFlags::NONBLOCKING,
        })
        .unwrap();
        assert_eq!(
            other.get_status_flags(duplicate),
            Ok(FileStatusFlags {
                access: FileAccessMode::ReadWrite,
                flags: FileOpenFlags::NONBLOCKING,
            })
        );

        assert_eq!(root.check_readiness(handle), Ok(ReadinessFlags::default()));
        exit(&child);
        assert_eq!(other.check_readiness(duplicate), Ok(EXITED));
        assert_eq!(
            crate::readiness_queue::take_ready(&root, queue, 1),
            Ok(alloc::vec![ReadyEvent {
                token: 7,
                readiness: EXITED,
            }])
        );
        root.collect_child_exit(ChildSelector::Process(child.id()))
            .unwrap();
        assert_eq!(root.check_readiness(handle), Ok(RELEASED));
        for sink in [&root_sink, &other_sink] {
            assert_eq!(published(sink), [EXITED, RELEASED]);
        }
    }

    #[test]
    fn handles_close_when_their_process_goes_away_uncollected() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let root = started_root(&broker);
        let observer = started_root(&broker);

        // An exit the parent discards.
        root.set_child_exit_retention(false).unwrap();
        let discarded = child_of(&root);
        let (_, discarded_sink) = open(&observer, &discarded);
        exit(&discarded);
        assert_eq!(published(&discarded_sink), [EXITED, RELEASED]);
        root.set_child_exit_retention(true).unwrap();

        // A pending child that its creator cancels.
        let identity = root.allocate_child_process(None, false).unwrap();
        let cancelled = root
            .with_pending_child(identity.process_id, Arc::clone)
            .unwrap();
        let (_, cancelled_sink) = open(&observer, &cancelled);
        root.cancel_child_process(identity.process_id).unwrap();
        assert_eq!(published(&cancelled_sink), [RELEASED]);

        // A starting child whose creator dies.
        let failed = child_of(&root);
        let (_, failed_sink) = open(&observer, &failed);
        root.handle_owner_death();
        assert_eq!(published(&failed_sink), [RELEASED]);

        // A process dropped without ever exiting.
        let (_, root_sink) = open(&observer, &root);
        drop(root);
        assert_eq!(published(&root_sink), [RELEASED]);
    }

    #[test]
    fn a_withheld_exit_becomes_readable_once_its_namespace_is_gone() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let root = started_root(&broker);
        let identity = root
            .allocate_child_process(Some(PidNamespaceOptions::new(true, false)), false)
            .unwrap();
        let first = root.take_child_process(identity.process_id).unwrap();
        let other = child_of(&first);
        other.complete_start().unwrap();
        let (handle, sink) = open(&root, &first);

        exit(&first);
        assert_eq!(root.check_readiness(handle), Ok(ReadinessFlags::default()));
        exit(&other);
        assert_eq!(published(&sink), [EXITED]);
    }

    #[test]
    fn a_handle_keeps_neither_its_process_nor_its_id() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        // With four IDs, the next child gets the first child's ID.
        *broker.pid_namespace.id_allocator.lock() = IdAllocator::new(4).unwrap();
        let root = started_root(&broker);
        let child = child_of(&root);
        let child_id = child.id();
        let (handle, _) = open(&root, &child);
        exit(&child);
        root.collect_child_exit(ChildSelector::Process(child_id))
            .unwrap();
        // The process is gone for its handles, even while still held.
        assert_eq!(
            crate::signal::send(&root, SignalTarget::ProcessHandle(handle), 0),
            Err(BrokerError::PeerClosed)
        );
        drop(child);

        assert!(!broker.pid_namespace.is_registered(child_id));
        assert!(
            !broker
                .pid_namespace
                .id_allocator
                .lock()
                .is_allocated(child_id.0)
        );
        // The handle never reaches the process that reuses the ID.
        let reused = child_of(&root);
        assert_eq!(reused.id(), child_id);
        let signals = crate::signal::open(&reused, sink()).unwrap();
        assert_eq!(
            crate::signal::send(&root, SignalTarget::ProcessHandle(handle), 15),
            Err(BrokerError::PeerClosed)
        );
        assert_eq!(
            crate::signal::take(&reused, signals),
            Err(BrokerError::WouldBlock)
        );
        exit(&reused);
        assert_eq!(
            root.collect_child_exit(ChildSelector::ProcessHandle(handle)),
            Err(BrokerError::UnknownObject)
        );
        assert_eq!(
            root.collect_child_exit(ChildSelector::Process(child_id))
                .map(|exit| exit.process_id),
            Ok(child_id)
        );
    }

    #[test]
    fn a_handle_inherited_into_a_nested_namespace_cannot_signal_outside_it() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let root = started_root(&broker);
        let target = child_of(&root);
        let (handle, _) = open(&root, &target);
        let identity = root
            .allocate_child_process(Some(PidNamespaceOptions::default()), false)
            .unwrap();
        let inherited = root
            .duplicate_object_references_to_child(
                identity.process_id,
                &[handle],
                &(sink() as Arc<dyn ReadinessSink>),
            )
            .unwrap()[0];
        let nested = root.take_child_process(identity.process_id).unwrap();
        let nested_sink = sink();
        nested
            .register_readiness(&(nested_sink.clone() as Arc<dyn ReadinessSink>))
            .unwrap();

        for signal in [0, 15] {
            assert_eq!(
                crate::signal::send(&nested, SignalTarget::ProcessHandle(inherited), signal),
                Err(BrokerError::UnknownObject)
            );
        }
        exit(&target);
        assert_eq!(published(&nested_sink), [EXITED]);
    }

    #[test]
    fn a_handle_signals_its_process_and_selects_it_only_as_a_child() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let root = started_root(&broker);
        let child = child_of(&root);
        child.complete_start().unwrap();
        let sibling = child_of(&root);
        let grandchild = child_of(&child);
        let (handle, _) = open(&root, &child);
        let (to_sibling, _) = open(&child, &sibling);
        let (to_itself, _) = open(&child, &child);
        let signals = crate::signal::open(&child, sink()).unwrap();

        crate::signal::send(&root, SignalTarget::ProcessHandle(handle), 15).unwrap();
        assert_eq!(
            crate::signal::take(&child, signals),
            Ok(SignalEvent::Signal(PendingSignal {
                thread: None,
                signal: 15,
                sender: root.id(),
            }))
        );
        assert_eq!(
            root.collect_child_exit(ChildSelector::ProcessHandle(handle)),
            Err(BrokerError::WouldBlock)
        );
        // Neither a sibling nor the caller is a child, even with an exited
        // child of the caller to collect.
        exit(&sibling);
        exit(&grandchild);
        for selected in [to_sibling, to_itself] {
            assert_eq!(
                child.collect_child_exit(ChildSelector::ProcessHandle(selected)),
                Err(BrokerError::UnknownObject)
            );
        }
        exit(&child);
        assert_eq!(
            root.collect_child_exit(ChildSelector::ProcessHandle(handle))
                .map(|exit| exit.process_id),
            Ok(child.id())
        );

        // A handle of another kind is neither.
        let event = crate::event::create(&root, 0, FileOpenFlags::NONE).unwrap();
        assert_eq!(
            crate::signal::send(&root, SignalTarget::ProcessHandle(event), 0),
            Err(BrokerError::InvalidRights)
        );
        assert_eq!(
            root.collect_child_exit(ChildSelector::ProcessHandle(event)),
            Err(BrokerError::InvalidRights)
        );
    }

    #[test]
    fn the_reference_quota_bounds_handles() {
        let limits = BrokerCoreLimits::DEFAULT;
        let broker = broker(limits.with_process_quotas(2, limits.max_pipe_capacity_per_process));
        let root = started_root(&broker);
        let (first, first_sink) = open(&root, &root);
        open(&root, &root);
        let open_another = || {
            super::open(
                &root,
                root.id(),
                FileOpenFlags::NONE,
                &(sink() as Arc<dyn ReadinessSink>),
            )
        };

        assert_eq!(open_another(), Err(BrokerError::ResourceExhausted));
        // A closed handle stops watching its process.
        root.close_object_reference(first).unwrap();
        assert_eq!(*first_sink.retired.lock().unwrap(), [first]);
        open_another().unwrap();
    }
}
