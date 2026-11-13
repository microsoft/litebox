// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::{any::Any, ptr};

use litebox_broker_protocol::fs::FileLockOperation;
use litebox_platform::sync::{Mutex, RawSyncPrimitivesProvider};

use crate::{BrokerError, Result};

pub(super) struct FlockTable<Platform: RawSyncPrimitivesProvider>(Mutex<Platform, Vec<Holder>>);

struct Holder {
    // XXX: lock identity is per-broker (dev, ino); no host flock cooperation, Windows identity,
    // or cross-allocator uniqueness.
    node: (u64, u64),
    // Weak: lock lives as long as the open description; dead holders are pruned lazily.
    owner: Weak<dyn Any + Send + Sync>,
    kind: FileLockOperation,
}

impl<Platform: RawSyncPrimitivesProvider> FlockTable<Platform> {
    pub(super) fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    pub(super) fn set(
        &self,
        owner: &Arc<dyn Any + Send + Sync>,
        request: Option<((u64, u64), FileLockOperation)>,
    ) -> Result<bool> {
        let mut holders = self.0.lock();
        holders.retain(|holder| holder.owner.strong_count() != 0);
        let same_owner = |holder: &Holder| ptr::addr_eq(holder.owner.as_ptr(), Arc::as_ptr(owner));
        if let Some((node, kind)) = request
            && holders
                .iter()
                .any(|holder| same_owner(holder) && holder.node == node && holder.kind == kind)
        {
            return Ok(true);
        }
        holders.retain(|holder| !same_owner(holder));
        let Some((node, kind)) = request else {
            return Ok(true);
        };
        if holders.iter().any(|holder| {
            holder.node == node
                && (holder.kind != FileLockOperation::Shared || kind != FileLockOperation::Shared)
        }) {
            return Ok(false);
        }
        holders
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        holders.push(Holder {
            node,
            owner: Arc::downgrade(owner),
            kind,
        });
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::fs::{
        FileAccessMode, FileError, FileLockOperation, FileMode, FileOpenFlags, FileUser,
        SetStatusFlagsRequest,
    };

    use crate::fs;
    use crate::readiness::{ReadinessSink, tests::TestReadinessSink};
    use crate::test_platform::TestPlatform;
    use crate::test_support::{TestBroker, TestBrokerBuilder};
    use crate::{BrokerError, BrokerProcess, CallerCredential, ObjectRights, PolicyEngine};

    use FileLockOperation::{Exclusive, Shared, Unlock};

    fn broker() -> TestBroker {
        TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_file_service(Arc::new(fs::resolver::Resolver::<TestPlatform>::new(
            fs::in_mem::InMem::<TestPlatform>::new(
                fs::inode_allocator::InodeAllocators::new().next(),
            ),
        )))
        .build()
        .unwrap()
    }

    fn open(
        process: &BrokerProcess,
        path: &str,
        access: FileAccessMode,
        flags: FileOpenFlags,
    ) -> ObjectHandle {
        let readiness: Arc<dyn ReadinessSink> = Arc::new(TestReadinessSink::default());
        fs::open(
            process,
            path,
            FileUser::ROOT,
            access,
            flags,
            FileMode::RUSR | FileMode::WUSR,
            &readiness,
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn flock_conflicts_and_conversions() {
        let broker = broker();
        let first = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let second = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let file = open(
            &first,
            "/file",
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE,
        );
        let reader = open(
            &second,
            "/file",
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONE,
        );
        let writer = open(
            &second,
            "/file",
            FileAccessMode::WriteOnly,
            FileOpenFlags::NONE,
        );

        assert_eq!(fs::lock(&first, file, Unlock), Ok(Ok(())));
        assert_eq!(fs::lock(&first, file, Shared), Ok(Ok(())));
        assert_eq!(fs::lock(&first, file, Shared), Ok(Ok(())));
        assert_eq!(fs::lock(&second, reader, Shared), Ok(Ok(())));
        assert_eq!(
            fs::lock(&second, writer, Exclusive),
            Err(BrokerError::NonBlockingWouldBlock)
        );

        assert_eq!(
            fs::lock(&first, file, Exclusive),
            Err(BrokerError::NonBlockingWouldBlock)
        );
        // The failed upgrade must have released the first description's shared lock.
        assert_eq!(fs::lock(&second, reader, Exclusive), Ok(Ok(())));
        assert_eq!(fs::lock(&second, reader, Exclusive), Ok(Ok(())));
        assert_eq!(
            fs::lock(&first, file, Shared),
            Err(BrokerError::NonBlockingWouldBlock)
        );
        assert_eq!(fs::lock(&first, file, Unlock), Ok(Ok(())));
        assert_eq!(
            fs::lock(&second, writer, Shared),
            Err(BrokerError::NonBlockingWouldBlock)
        );
        assert_eq!(fs::lock(&second, reader, Unlock), Ok(Ok(())));

        assert_eq!(fs::lock(&first, file, Exclusive), Ok(Ok(())));
        assert_eq!(fs::lock(&first, file, Exclusive), Ok(Ok(())));
        assert_eq!(
            fs::lock(&second, writer, Exclusive),
            Err(BrokerError::NonBlockingWouldBlock)
        );
        assert_eq!(
            second.set_status_flags(SetStatusFlagsRequest {
                handle: writer,
                mask: FileOpenFlags::NONBLOCKING,
                flags: FileOpenFlags::NONBLOCKING,
            }),
            Ok(())
        );
        assert_eq!(
            fs::lock(&second, writer, Exclusive),
            Err(BrokerError::NonBlockingWouldBlock)
        );
        assert_eq!(fs::lock(&first, file, Unlock), Ok(Ok(())));
        assert_eq!(fs::lock(&second, writer, Exclusive), Ok(Ok(())));
    }

    #[test]
    fn flock_follows_open_description_and_inode() {
        let broker = broker();
        let first = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let second = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        let file = open(
            &first,
            "/file",
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE,
        );
        let contender = open(
            &second,
            "/file",
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONE,
        );
        assert_eq!(fs::lock(&first, file, Exclusive), Ok(Ok(())));
        let duplicate = first
            .duplicate_object_reference_to(file, &first, ObjectRights::WAIT)
            .unwrap();
        let inherited = first
            .duplicate_object_references_to(&[duplicate], &second)
            .unwrap()[0];
        assert_eq!(first.close_object_reference(file), Ok(()));
        assert_eq!(
            fs::lock(&second, contender, Shared),
            Err(BrokerError::NonBlockingWouldBlock)
        );
        assert_eq!(first.close_object_reference(duplicate), Ok(()));
        assert_eq!(fs::lock(&second, inherited, Exclusive), Ok(Ok(())));
        assert_eq!(
            fs::lock(&second, contender, Shared),
            Err(BrokerError::NonBlockingWouldBlock)
        );

        assert_eq!(
            fs::rename(&first, "/file", "/renamed", FileUser::ROOT),
            Ok(Ok(()))
        );
        let renamed = open(
            &second,
            "/renamed",
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONE,
        );
        assert_eq!(
            fs::lock(&second, renamed, Shared),
            Err(BrokerError::NonBlockingWouldBlock)
        );
        let replacement = open(
            &first,
            "/file",
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE,
        );
        assert_eq!(fs::lock(&first, replacement, Exclusive), Ok(Ok(())));
        assert_eq!(
            fs::lock(&second, renamed, Shared),
            Err(BrokerError::NonBlockingWouldBlock)
        );

        let path_only = open(
            &first,
            "/renamed",
            FileAccessMode::ReadOnly,
            FileOpenFlags::PATH,
        );
        for operation in [Shared, Exclusive, Unlock] {
            assert_eq!(
                fs::lock(&first, path_only, operation),
                Ok(Err(FileError::PathOnly))
            );
        }
        assert_eq!(second.close_object_reference(inherited), Ok(()));
        assert_eq!(fs::lock(&second, contender, Exclusive), Ok(Ok(())));
        assert_eq!(
            fs::lock(&second, renamed, Shared),
            Err(BrokerError::NonBlockingWouldBlock)
        );
    }
}
