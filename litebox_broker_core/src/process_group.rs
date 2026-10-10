// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process groups and sessions.
//!
//! Every process belongs to one process group, and every process group to one
//! session, each identified by the ID of the process that created it. A child
//! process starts in its creator's group and session, while a root process
//! leads its own. A group or session exists while any process, including a
//! zombie not yet reaped, belongs to it, and its ID is not reused until then.

use alloc::sync::Arc;

use litebox_broker_protocol::process_group::ProcessGroupMembership;
use litebox_broker_protocol::{ProcessGroupId, ProcessId};

use crate::{BrokerError, BrokerProcess, Result};

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
    let _tree = process.core.process_tree.lock();
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
    let _tree = process.core.process_tree.lock();
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

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use litebox_broker_protocol::process::ProcessExitStatus;
    use litebox_broker_protocol::process_group::ProcessGroupMembership;
    use litebox_broker_protocol::{ProcessGroupId, ProcessId};

    use crate::id::IdAllocator;
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
    fn children_inherit_their_parents_membership() {
        let broker = broker();
        let root = process(&broker, None);
        let child = process(&broker, Some(&root));
        let other = process(&broker, None);

        assert_eq!(get(&other, root.id()), Ok(membership(&root, &root)));
        assert_eq!(get(&other, child.id()), Ok(membership(&root, &root)));
        assert_eq!(get(&root, other.id()), Ok(membership(&other, &other)));
        assert_eq!(
            get(&root, ProcessId(u32::MAX)),
            Err(BrokerError::UnknownObject)
        );

        super::set(&root, child.id(), child.id().into()).unwrap();
        let grandchild = process(&broker, Some(&child));
        assert_eq!(get(&root, grandchild.id()), Ok(membership(&child, &root)));
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

        // A child in another session cannot move, nor can a session leader.
        super::create_session(&grandchild, grandchild.id()).unwrap();
        assert_eq!(
            super::set(&first, grandchild.id(), first.id().into()),
            Err(BrokerError::PolicyDenied)
        );
        assert_eq!(
            super::set(&grandchild, grandchild.id(), grandchild.id().into()),
            Err(BrokerError::PolicyDenied)
        );
        let great_grandchild = process(&broker, Some(&grandchild));
        assert_eq!(
            super::set(&great_grandchild, great_grandchild.id(), root.id().into()),
            Err(BrokerError::PolicyDenied)
        );
        super::set(
            &great_grandchild,
            great_grandchild.id(),
            grandchild.id().into(),
        )
        .unwrap();
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
}
