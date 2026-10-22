// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use alloc::string::ToString as _;
use alloc::vec;
use alloc::vec::Vec;

use crate::LiteBox;
use crate::fd::FdEnabledSubsystemEntry;
use crate::fd::{ErrRawIntFd, FdEnabledSubsystem, TypedFd};
use crate::platform::mock::MockPlatform;

struct MockSubsystem;
impl FdEnabledSubsystem for MockSubsystem {
    type Entry = MockEntry;
}
struct MockEntry {
    data: String,
}
impl FdEnabledSubsystemEntry for MockEntry {}

struct MockSubsystem2;
impl FdEnabledSubsystem for MockSubsystem2 {
    type Entry = MockEntry2;
}
struct MockEntry2 {
    stuff: String,
}
impl FdEnabledSubsystemEntry for MockEntry2 {}

fn litebox() -> LiteBox<MockPlatform> {
    LiteBox::new(MockPlatform::new())
}

#[test]
fn test_insert_and_remove_entry() {
    let litebox = litebox();
    let mut descriptors = litebox.descriptor_table_mut();

    let entry = MockEntry {
        data: "test".to_string(),
    };
    let typed_fd: TypedFd<MockSubsystem> = descriptors.insert(entry);

    assert_eq!(descriptors.entries.len(), 1);

    let removed_entry = descriptors.remove(&typed_fd);
    assert!(removed_entry.is_some());
    assert_eq!(removed_entry.unwrap().data, "test");
}

#[test]
fn test_iter_entries() {
    let litebox = litebox();
    let mut descriptors = litebox.descriptor_table_mut();

    let entry1 = MockEntry {
        data: "entry1".to_string(),
    };
    let entry2 = MockEntry {
        data: "entry2".to_string(),
    };
    let entry3 = MockEntry2 {
        stuff: "x".to_string(),
    };

    let fd1: TypedFd<MockSubsystem> = descriptors.insert(entry1);
    let _fd2: TypedFd<MockSubsystem> = descriptors.insert(entry2);
    let _fd3: TypedFd<MockSubsystem2> = descriptors.insert(entry3);

    let mut entries: Vec<String> = descriptors
        .iter::<MockSubsystem>()
        .map(|(_, e)| e.data.clone())
        .collect();
    entries.sort();

    assert_eq!(entries, vec!["entry1", "entry2"]); // Notice that "x" does not show up

    // Remove one entry and check again
    descriptors.remove(&fd1);
    let entries_after_removal: Vec<String> = descriptors
        .iter::<MockSubsystem>()
        .map(|(_, e)| e.data.clone())
        .collect();
    assert_eq!(entries_after_removal, vec!["entry2"]);

    // Check that the entry from MockSubsystem2 shows up in the iteration if looking within that
    // subsystem
    let entries_subsystem2: Vec<String> = descriptors
        .iter::<MockSubsystem2>()
        .map(|(_, e)| e.stuff.clone())
        .collect();
    assert_eq!(entries_subsystem2, vec!["x"]);
}

#[test]
fn test_with_entry() {
    let litebox = litebox();
    let mut descriptors = litebox.descriptor_table_mut();

    let entry = MockEntry {
        data: "test".to_string(),
    };
    let typed_fd: TypedFd<MockSubsystem> = descriptors.insert(entry);

    descriptors.with_entry(&typed_fd, |e| {
        assert_eq!(e.data, "test");
    });

    descriptors.with_entry_mut(&typed_fd, |e| {
        e.data = "updated".to_string();
    });
    descriptors.with_entry(&typed_fd, |e| {
        assert_eq!(e.data, "updated");
    });
}

#[test]
fn test_fd_raw_integer() {
    let litebox = litebox();
    let mut descriptors = litebox.descriptor_table_mut();

    let mut rds = super::RawDescriptorStorage::new();

    let result = rds.fd_from_raw_integer::<MockSubsystem>(999);
    assert!(matches!(result, Err(ErrRawIntFd::NotFound)));

    let entry = MockEntry {
        data: "test".to_string(),
    };
    let typed_fd: TypedFd<MockSubsystem> = descriptors.insert(entry);
    let raw_fd = rds.fd_into_raw_integer(typed_fd);
    let result = rds.fd_from_raw_integer::<MockSubsystem2>(raw_fd);
    assert!(matches!(result, Err(ErrRawIntFd::InvalidSubsystem)));

    let fetched_fd = rds.fd_from_raw_integer::<MockSubsystem>(raw_fd).unwrap();
    let data = descriptors
        .with_entry(&fetched_fd, |e| e.data.clone())
        .unwrap();
    assert_eq!(data, "test");
    drop(fetched_fd);

    let consumed_fd = rds.fd_consume_raw_integer::<MockSubsystem>(raw_fd).unwrap();
    let data = descriptors
        .with_entry(&consumed_fd, |e| e.data.clone())
        .unwrap();
    assert_eq!(data, "test");
}

#[test]
fn test_reserved_slots_accept_sparse_specific_raw_integers() {
    let litebox = litebox();
    let mut descriptors = litebox.descriptor_table_mut();
    let mut rds = super::RawDescriptorStorage::new();
    let first: TypedFd<MockSubsystem> = descriptors.insert(MockEntry {
        data: "first".to_string(),
    });
    assert_eq!(rds.fd_into_raw_integer(first), 0);

    // Far beyond the implicit growth bound of `fd_into_specific_raw_integer`.
    rds.try_reserve_slots(1024).unwrap();
    let sparse: TypedFd<MockSubsystem> = descriptors.insert(MockEntry {
        data: "sparse".to_string(),
    });
    assert!(rds.fd_into_specific_raw_integer(sparse, 1023));
    let fetched = rds.fd_from_raw_integer::<MockSubsystem>(1023).unwrap();
    assert_eq!(
        descriptors
            .with_entry(&fetched, |e| e.data.clone())
            .unwrap(),
        "sparse"
    );
    assert_eq!(rds.iter_alive().collect::<Vec<_>>(), vec![0, 1023]);

    // Reserving never shrinks, and lowest-free allocation still fills holes first.
    rds.try_reserve_slots(4).unwrap();
    assert!(rds.is_alive(1023));
    let next: TypedFd<MockSubsystem> = descriptors.insert(MockEntry {
        data: "next".to_string(),
    });
    assert_eq!(rds.fd_into_raw_integer(next), 1);

    // An unsatisfiable reservation fails without changing the store.
    assert!(rds.try_reserve_slots(usize::MAX).is_err());
    assert_eq!(rds.iter_alive().collect::<Vec<_>>(), vec![0, 1, 1023]);
}
