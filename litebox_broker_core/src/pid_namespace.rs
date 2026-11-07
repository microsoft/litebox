// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PID namespaces.
//!
//! A PID namespace numbers its own processes, threads, process groups and
//! sessions from 1, and its processes see and reach one another only by these
//! IDs. Every container, a [`BrokerCore`] handle, works in one namespace,
//! which the root processes it creates and all their descendants belong to,
//! and several containers can share one, as containers sharing a pod's process
//! namespace do (see [`BrokerCore::with_container`]).
//!
//! [`BrokerCore`]: crate::BrokerCore
//! [`BrokerCore::with_container`]: crate::BrokerCore::with_container

use core::sync::atomic::{AtomicU64, Ordering};

use hashbrown::HashMap;
use litebox_broker_protocol::ThreadId;
use spin::{Mutex, Once, rwlock::RwLock};

use crate::id::{IdAllocator, MAX_ALLOCATED_ID};
use crate::process::BrokerThread;
use crate::process_group::ControllingTerminals;
use crate::{BrokerError, ProcessKey, ProcessRegistry, Result};

/// Broker-internal identity of a PID namespace, which is never reused and
/// never shown to the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PidNamespaceId(u64);

/// The next [`PidNamespaceId`] to allocate.
static NEXT_PID_NAMESPACE_ID: AtomicU64 = AtomicU64::new(1);

/// The processes, threads, process groups and sessions that see one another's
/// IDs, and the terminals that control these sessions.
pub struct PidNamespace {
    id: PidNamespaceId,
    /// Allocates the IDs of processes and threads, which also name process
    /// groups and sessions.
    pub(crate) ids: Mutex<IdAllocator>,
    pub(crate) processes: ProcessRegistry,
    /// Every live broker thread.
    ///
    /// Lock order: a process's thread set, then this lock, then the ID
    /// allocator.
    pub(crate) threads: RwLock<HashMap<ThreadId, BrokerThread>>,
    /// Which terminal controls which session.
    pub(crate) controlling_terminals: ControllingTerminals,
    /// The key of the first process created here, with its initial thread,
    /// which is the namespace's init and which `kill(-1)` spares. A later
    /// process given its reused ID is not init.
    init: Once<ProcessKey>,
}

impl PidNamespace {
    /// Creates an empty namespace, whose first process gets ID 1.
    ///
    /// Fails with `ResourceExhausted` rather than reuse a namespace ID.
    pub fn new() -> Result<Self> {
        let id = NEXT_PID_NAMESPACE_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| BrokerError::ResourceExhausted)?;
        Ok(Self {
            id: PidNamespaceId(id),
            ids: Mutex::new(IdAllocator::new(MAX_ALLOCATED_ID)?),
            processes: RwLock::new(HashMap::new()),
            threads: RwLock::new(HashMap::new()),
            controlling_terminals: ControllingTerminals::default(),
            init: Once::new(),
        })
    }

    /// Returns this namespace's identity.
    #[must_use]
    pub const fn id(&self) -> PidNamespaceId {
        self.id
    }

    /// Records the root process `key`, which callers have just created, as
    /// init if no process was created here before.
    pub(crate) fn record_init(&self, key: ProcessKey) {
        self.init.call_once(|| key);
    }

    /// Returns whether the process `key` is this namespace's init.
    pub(crate) fn is_init(&self, key: ProcessKey) -> bool {
        self.init.get() == Some(&key)
    }

    /// Returns whether the process `id` is registered here, even if released.
    #[cfg(test)]
    pub(crate) fn is_registered(&self, id: litebox_broker_protocol::ProcessId) -> bool {
        self.processes.read().contains_key(&id)
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use litebox_broker_protocol::process::{ChildSelector, CpuTime, ProcessExitStatus};
    use litebox_broker_protocol::signal::{SignalEvent, SignalTarget};
    use litebox_broker_protocol::{ObjectHandle, ProcessId};

    use super::PidNamespace;
    use crate::id::IdAllocator;
    use crate::readiness::tests::TestReadinessSink;
    use crate::test_support::TestBrokerCoreBuilder;
    use crate::{
        BrokerCore, BrokerCoreLimits, BrokerError, BrokerProcess, CallerCredential, ObjectRights,
        PolicyEngine,
    };

    fn broker(limits: BrokerCoreLimits) -> BrokerCore {
        TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_limits(limits)
        .build()
        .unwrap()
    }

    fn create(broker: &BrokerCore, parent: Option<&BrokerProcess>) -> Arc<BrokerProcess> {
        broker
            .create_process(
                CallerCredential::Unauthenticated,
                parent.map(BrokerProcess::id),
            )
            .unwrap()
    }

    fn open_signals(process: &BrokerProcess) -> ObjectHandle {
        crate::signal::open(process, Arc::new(TestReadinessSink::default())).unwrap()
    }

    /// Takes every target's pending signals, returning the IDs of the targets
    /// that had any.
    fn signalled(targets: &[(&BrokerProcess, ObjectHandle)]) -> Vec<ProcessId> {
        targets
            .iter()
            .filter(|(process, handle)| {
                let mut any = false;
                while let Ok(SignalEvent::Signal(_)) = crate::signal::take(process, *handle) {
                    any = true;
                }
                any
            })
            .map(|(process, _)| process.id())
            .collect()
    }

    #[test]
    fn namespaces_number_and_confine_their_processes() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let other_view = broker.with_container(Arc::new(PidNamespace::new().unwrap()), None);
        let init = create(&broker, None);
        let child = create(&broker, Some(&init));
        crate::process_group::set(&init, child.id(), child.id().into()).unwrap();
        let other = create(&other_view, None);

        // Each namespace numbers its processes from 1.
        assert_eq!([init.id(), other.id()], [ProcessId(1); 2]);
        // Another namespace's processes, threads and groups are out of reach,
        // even by IDs in use in the caller's namespace.
        assert_eq!(
            other.process_info(child.id()),
            Err(BrokerError::UnknownObject)
        );
        assert!(matches!(
            other.thread_info(child.initial_thread_id()),
            Err(BrokerError::UnknownObject)
        ));
        for target in [
            SignalTarget::Process(child.id()),
            SignalTarget::ProcessGroup(child.id().into()),
            SignalTarget::All,
        ] {
            assert_eq!(
                crate::signal::send(&other, target, 0),
                Err(BrokerError::UnknownObject)
            );
        }
    }

    #[test]
    fn views_sharing_a_namespace_spare_only_its_init_from_signals_to_all() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let pid_namespace = Arc::new(PidNamespace::new().unwrap());
        // A small ID space makes init's ID come round again quickly.
        *pid_namespace.ids.lock() = IdAllocator::new(6).unwrap();
        let [first_view, second_view] =
            [(); 2].map(|()| broker.with_container(Arc::clone(&pid_namespace), None));
        let init = create(&first_view, None);
        let root = create(&second_view, None);
        let child = create(&second_view, Some(&root));
        let [init_signals, root_signals, child_signals] =
            [&init, &root, &child].map(|process| open_signals(process));

        // Each view sees the other's processes, and a signal to all reaches
        // every process but init and the sender, including another root.
        assert_eq!(
            init.process_info(child.id()).unwrap().parent,
            Some(root.id())
        );
        crate::signal::send(&child, SignalTarget::All, 15).unwrap();
        crate::signal::send(&init, SignalTarget::All, 10).unwrap();
        assert_eq!(
            signalled(&[
                (&init, init_signals),
                (&root, root_signals),
                (&child, child_signals),
            ]),
            [root.id(), child.id()]
        );

        // A later process given init's ID is not init.
        let init_id = init.id();
        init.complete_start().unwrap();
        init.retire(true);
        init.complete_exit(ProcessExitStatus::Exited { code: 0 }, CpuTime::default())
            .unwrap();
        drop(init);
        let reused = create(&first_view, None);
        assert_eq!(reused.id(), init_id);
        let reused_signals = open_signals(&reused);
        crate::signal::send(&child, SignalTarget::All, 15).unwrap();
        assert_eq!(
            signalled(&[(&reused, reused_signals), (&root, root_signals)]),
            [reused.id(), root.id()]
        );
    }

    #[test]
    fn a_container_root_reaps_its_own_orphans_in_a_shared_namespace() {
        let broker = broker(BrokerCoreLimits::DEFAULT);
        let pid_namespace = Arc::new(PidNamespace::new().unwrap());
        let [first_view, second_view] =
            [(); 2].map(|()| broker.with_container(Arc::clone(&pid_namespace), None));
        let init = create(&first_view, None);
        let root = create(&second_view, None);
        let middle = create(&second_view, Some(&root));
        let orphan = create(&second_view, Some(&middle));
        // Like the shim, every root adopts orphans.
        for process in [&init, &root, &middle, &orphan] {
            process.complete_start().unwrap();
        }
        for process in [&init, &root] {
            process.set_orphan_adoption(true).unwrap();
        }
        let [init_signals, root_signals] = [&init, &root].map(|process| open_signals(process));
        let exit = |process: &BrokerProcess| {
            process.retire(true);
            process
                .complete_exit(ProcessExitStatus::Exited { code: 0 }, CpuTime::default())
                .unwrap();
        };

        // The orphan goes to its container's root, not the namespace's init,
        // which learns of neither its adoption nor its exit.
        exit(&middle);
        assert_eq!(
            root.process_info(orphan.id()).unwrap().parent,
            Some(root.id())
        );
        assert!(matches!(
            crate::signal::take(&root, root_signals),
            Ok(SignalEvent::ChildExited(exit)) if exit.process_id == middle.id()
        ));
        exit(&orphan);
        assert!(matches!(
            crate::signal::take(&root, root_signals),
            Ok(SignalEvent::ChildExited(exit)) if exit.process_id == orphan.id()
        ));
        assert_eq!(
            root.collect_child_exit(ChildSelector::Process(orphan.id()))
                .map(|exit| exit.process_id),
            Ok(orphan.id())
        );
        assert_eq!(
            crate::signal::take(&init, init_signals),
            Err(BrokerError::WouldBlock)
        );
        assert_eq!(
            init.collect_child_exit(ChildSelector::Any),
            Err(BrokerError::UnknownObject)
        );
    }

    #[test]
    fn init_is_the_first_process_created_with_its_thread() {
        let broker = broker(BrokerCoreLimits::DEFAULT.with_thread_quotas(1, 1));
        let pid_namespace = Arc::new(PidNamespace::new().unwrap());
        let view = broker.with_container(Arc::clone(&pid_namespace), None);
        let other = create(&broker, None);

        // A root discarded for want of a thread is not init.
        assert_eq!(
            view.create_process(CallerCredential::Unauthenticated, None)
                .map(|process| process.id()),
            Err(BrokerError::ResourceExhausted)
        );
        other.complete_start().unwrap();
        other.retire(true);
        other
            .complete_exit(ProcessExitStatus::Exited { code: 0 }, CpuTime::default())
            .unwrap();
        drop(other);
        let init = create(&view, None);
        assert!(pid_namespace.is_init(init.key()));
    }

    #[test]
    fn the_process_limit_spans_namespaces() {
        let broker = broker(BrokerCoreLimits::DEFAULT.with_process_limit(2));
        let other_view = broker.with_container(Arc::new(PidNamespace::new().unwrap()), None);
        let _first = create(&broker, None);
        let second = create(&other_view, None);
        let try_create = |broker: &BrokerCore| {
            broker
                .create_process(CallerCredential::Unauthenticated, None)
                .map(|process| process.id())
        };
        for view in [&broker, &other_view] {
            assert_eq!(try_create(view), Err(BrokerError::ResourceExhausted));
        }

        // A process counts until it is cleaned up, and a refused one never
        // does.
        drop(second);
        let _third = create(&broker, None);
        assert_eq!(try_create(&other_view), Err(BrokerError::ResourceExhausted));
    }
}
