// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! TEMPORARY: coverage for the broker-backed file API while it coexists with the local resolver.
//!
//! These tests exist only because no production caller uses [`crate::fs::Context`] and
//! [`crate::fs::FileFd`] yet. Remove this module (and the broker test-support dev-dependencies it
//! needs) once the shims call the broker file API and cover it end to end.

use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox_broker_core::fs::in_mem::{InMem, InitialNode};
use litebox_broker_core::fs::resolver::Resolver as BrokerResolver;
use litebox_broker_core::test_support::TestBrokerCoreBuilder;
use litebox_broker_core::{BrokerCore, ObjectRights, PolicyEngine};
use litebox_broker_host::test_support::InProcessBrokerSetup;
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileMode, FileOpenFlags, FileSeekWhence, FileType, FileUser,
};
use spin::mutex::SpinMutex;

use crate::LiteBox;
use crate::fs::errors::{OpenError, ReadError, SeekError};
use crate::fs::{Context, FileFd};
use crate::platform::mock::MockPlatform;

/// The process-wide broker core. Only one may exist per process, so every association in this test
/// binary shares one filesystem; tests must use disjoint paths.
static BROKER: SpinMutex<Option<BrokerCore>> = SpinMutex::new(None);

fn test_broker() -> BrokerCore {
    let mut broker = BROKER.lock();
    broker
        .get_or_insert_with(|| {
            let fs =
                BrokerResolver::<MockPlatform, _>::new(InMem::<MockPlatform>::new_initialized([(
                    "/",
                    InitialNode::Directory {
                        mode: FileMode::from_u32_bits_truncate(0o777),
                        owner: FileUser { user: 0, group: 0 },
                    },
                )]));
            TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
                ObjectRights::all(),
            ))
            .with_file_service(Arc::new(fs))
            .build()
            .expect("the test broker core must be constructible")
        })
        .clone()
}

fn broker_litebox() -> LiteBox<MockPlatform> {
    let setup = InProcessBrokerSetup::new(test_broker());
    let (broker_local, ()) = BrokerLocal::negotiate(setup, |setup| {
        let memory = setup.shared_memory();
        Ok((setup.activate(), memory, ()))
    })
    .expect("the in-process broker association must negotiate");
    LiteBox::new_with_broker_local(MockPlatform::new(), broker_local)
}

fn create_file(litebox: &LiteBox<MockPlatform>, context: &Context, path: &str) -> FileFd {
    litebox
        .open_file(
            context,
            path,
            FileAccessMode::ReadWrite,
            FileOpenFlags::CREATE | FileOpenFlags::EXCLUSIVE,
            FileMode::from_u32_bits_truncate(0o644),
        )
        .expect("creating a new file must succeed")
}

#[test]
fn broker_file_round_trip() {
    let litebox = broker_litebox();
    let mut context = Context::new();
    litebox
        .mkdir_file(
            &context,
            "/round_trip",
            FileMode::from_u32_bits_truncate(0o755),
        )
        .unwrap();
    context.set_cwd(context.resolve("/round_trip").unwrap());

    let fd = create_file(&litebox, &context, "./data");
    assert_eq!(litebox.write_file(&fd, b"broker data", None).unwrap(), 11);
    assert_eq!(
        litebox
            .seek_file(&fd, 7, FileSeekWhence::RelativeToBeginning)
            .unwrap(),
        7
    );
    let mut buffer = [0; 4];
    assert_eq!(litebox.read_file(&fd, &mut buffer, None).unwrap(), 4);
    assert_eq!(&buffer, b"data");
    assert_eq!(litebox.read_file(&fd, &mut buffer, Some(0)).unwrap(), 4);
    assert_eq!(&buffer, b"brok");

    let status = litebox.file_status(&fd).unwrap();
    assert_eq!(status.file_type, FileType::RegularFile);
    assert_eq!(status.size, 11);
    assert_eq!(status.owner.user, context.acting_user().user);

    litebox.truncate_file(&fd, 4, true).unwrap();
    assert_eq!(litebox.path_file_status(&context, "data").unwrap().size, 4);

    litebox
        .chmod_file(&context, "data", FileMode::from_u32_bits_truncate(0o600))
        .unwrap();
    litebox.chown_file(&context, "data", Some(7), None).unwrap();
    let status = litebox
        .path_file_status(&context, "/round_trip/data")
        .unwrap();
    assert_eq!(status.mode, FileMode::from_u32_bits_truncate(0o600));
    assert_eq!(status.owner.user, 7);

    let directory = litebox
        .open_file(
            &context,
            "/round_trip",
            FileAccessMode::ReadOnly,
            FileOpenFlags::DIRECTORY,
            FileMode::empty(),
        )
        .unwrap();
    let names: Vec<_> = litebox
        .read_file_directory(&directory)
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert!(names.iter().any(|name| name == "data"));
    litebox.close_file(&directory).unwrap();

    litebox.close_file(&fd).unwrap();
    litebox.unlink_file(&context, "data").unwrap();
    litebox.rmdir_file(&Context::new(), "/round_trip").unwrap();
    assert!(matches!(
        litebox.path_file_status(&context, "/round_trip"),
        Err(crate::fs::errors::FileStatusError::PathError(_))
    ));
}

#[test]
fn closed_descriptor_operations_report_closed_fd() {
    let litebox = broker_litebox();
    let context = Context::new();
    litebox
        .mkdir_file(&context, "/closed", FileMode::from_u32_bits_truncate(0o755))
        .unwrap();

    let fd = create_file(&litebox, &context, "/closed/data");
    litebox.write_file(&fd, b"data", None).unwrap();
    litebox.close_file(&fd).unwrap();

    let mut buffer = [0; 4];
    assert!(matches!(
        litebox.read_file(&fd, &mut buffer, None),
        Err(ReadError::ClosedFd)
    ));
    assert!(matches!(
        litebox.seek_file(&fd, 0, FileSeekWhence::RelativeToCurrentOffset),
        Err(SeekError::ClosedFd)
    ));

    // The broker object is released with the descriptor, so the path can be replaced.
    litebox.unlink_file(&context, "/closed/data").unwrap();
    let fd = create_file(&litebox, &context, "/closed/data");
    litebox.close_file(&fd).unwrap();
    litebox.unlink_file(&context, "/closed/data").unwrap();
    litebox.rmdir_file(&context, "/closed").unwrap();
}

#[test]
fn broker_file_requires_a_broker() {
    let litebox = LiteBox::new(MockPlatform::new());
    assert!(matches!(
        litebox.open_file(
            &Context::new(),
            "/missing",
            FileAccessMode::ReadOnly,
            FileOpenFlags::NONE,
            FileMode::empty(),
        ),
        Err(OpenError::Io)
    ));
}
