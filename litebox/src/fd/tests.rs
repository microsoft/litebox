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
    LiteBox::new_for_test(MockPlatform::new())
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
fn test_duplicate_preserves_descriptor_object_id() {
    let litebox = litebox();
    let mut descriptors = litebox.descriptor_table_mut();

    let entry = MockEntry {
        data: "test".to_string(),
    };
    let typed_fd: TypedFd<MockSubsystem> = descriptors.insert(entry);
    let dup_fd = descriptors
        .duplicate(&typed_fd)
        .expect("duplicate should succeed");

    assert_eq!(typed_fd.object_id(), dup_fd.object_id());

    let handle = descriptors
        .entry_handle(&typed_fd)
        .expect("entry handle should exist");
    let weak = handle.downgrade();
    assert_eq!(handle.object_id(), typed_fd.object_id());
    assert_eq!(weak.object_id(), typed_fd.object_id());
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
    let object_id = typed_fd.object_id();
    let raw_fd = rds.fd_into_raw_integer(typed_fd);
    let result = rds.fd_from_raw_integer::<MockSubsystem2>(raw_fd);
    assert!(matches!(result, Err(ErrRawIntFd::InvalidSubsystem)));

    let fetched_fd = rds.fd_from_raw_integer::<MockSubsystem>(raw_fd).unwrap();
    assert_eq!(fetched_fd.object_id(), object_id);
    let data = descriptors
        .with_entry(&fetched_fd, |e| e.data.clone())
        .unwrap();
    assert_eq!(data, "test");
    drop(fetched_fd);

    let consumed_fd = rds.fd_consume_raw_integer::<MockSubsystem>(raw_fd).unwrap();
    assert_eq!(consumed_fd.object_id(), object_id);
    let data = descriptors
        .with_entry(&consumed_fd, |e| e.data.clone())
        .unwrap();
    assert_eq!(data, "test");
}

#[test]
fn test_clone_for_fork_preserves_descriptor_object_id() {
    let litebox = litebox();
    let mut descriptors = litebox.descriptor_table_mut();
    let mut parent_rds = super::RawDescriptorStorage::new();

    let entry = MockEntry {
        data: "test".to_string(),
    };
    let typed_fd: TypedFd<MockSubsystem> = descriptors.insert(entry);
    let object_id = typed_fd.object_id();
    let raw_fd = parent_rds.fd_into_raw_integer(typed_fd);

    let child_rds = parent_rds.clone_for_fork(&mut descriptors);

    let parent_fd = parent_rds
        .fd_from_raw_integer::<MockSubsystem>(raw_fd)
        .expect("parent fd should still exist");
    let child_fd = child_rds
        .fd_from_raw_integer::<MockSubsystem>(raw_fd)
        .expect("child fd should be cloned");

    assert_eq!(parent_fd.object_id(), object_id);
    assert_eq!(child_fd.object_id(), object_id);
}

/// Regression test for fork-propagation of per-fd-slot metadata.
///
/// Linux fork copies the FD_CLOEXEC bit per-fd-slot from parent to child.
/// `RawDescriptorStorage::clone_for_fork` does this via `duplicate_raw_fd`
/// which clones the per-slot `metadata` AnyMap. This test asserts that
/// metadata set on the parent's slot survives into the child's slot.
///
/// Discovered as the root cause of the exec_on_remote_host stderr-pipe
/// hang on `EV.fork_inherit.<nonpie-bt>`: `pipe2(O_CLOEXEC)` correctly
/// marks both fds CLOEXEC in the parent, but probe in the post-fork
/// child showed the fds WITHOUT FD_CLOEXEC. `close_on_exec()` in the
/// placeholder then skipped them, leaving the stderr write end open
/// across the cross-binary-type exec boundary.
///
/// We use a custom marker type rather than the linux-specific
/// `FileDescriptorFlags` to keep this test no_std-clean.
#[test]
fn test_clone_for_fork_preserves_per_fd_slot_metadata() {
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CloexecMarker;

    let litebox = litebox();
    let mut descriptors = litebox.descriptor_table_mut();
    let mut parent_rds = super::RawDescriptorStorage::new();

    let entry = MockEntry {
        data: "fd-cloexec".to_string(),
    };
    let typed_fd: TypedFd<MockSubsystem> = descriptors.insert(entry);

    // Set the per-slot marker on the parent's slot — mirrors
    // sys_pipe2 setting FileDescriptorFlags::FD_CLOEXEC on pipe ends.
    let prev = descriptors.set_fd_metadata(&typed_fd, CloexecMarker);
    assert!(prev.is_none(), "no prior CloexecMarker metadata expected");

    let raw_fd = parent_rds.fd_into_raw_integer(typed_fd);

    // Sanity: parent reads marker back.
    let parent_fd = parent_rds
        .fd_from_raw_integer::<MockSubsystem>(raw_fd)
        .expect("parent fd should still exist");
    let parent_marker = descriptors.with_metadata(&parent_fd, |_m: &CloexecMarker| ());
    assert!(parent_marker.is_ok(), "parent must have CloexecMarker set");

    // Fork → child fd table.
    let child_rds = parent_rds.clone_for_fork(&mut descriptors);

    // Child must also have the marker. If this assertion fires, the
    // fork-bridge's per-slot metadata clone in `duplicate_raw_fd` is
    // broken — exec_on_remote_host's close_on_exec will then leak CLOEXEC
    // fds (e.g. pipe ends from pipe2(O_CLOEXEC)) into the placeholder's
    // post-fork view, hanging the parent on reads that should EOF.
    let child_fd = child_rds
        .fd_from_raw_integer::<MockSubsystem>(raw_fd)
        .expect("child fd should be cloned");
    let child_marker = descriptors.with_metadata(&child_fd, |_m: &CloexecMarker| ());
    assert!(
        child_marker.is_ok(),
        "CloexecMarker must propagate through clone_for_fork's per-slot \
         metadata clone (this is the root cause of EV.fork_inherit.<nonpie-bt> \
         hang documented in checkpoint 010)"
    );
}
