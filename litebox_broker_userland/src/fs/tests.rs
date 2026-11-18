// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! [`LocalFs`] beneath broker-core path operations.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use litebox_broker_core::fs::composer::Composer;
use litebox_broker_core::fs::resolver::Resolver;
use litebox_broker_core::fs::{FileService, UserInfo};
use litebox_broker_core::test_platform::TestPlatform;
use litebox_broker_protocol::fs::FileError;

use super::LocalFs;

const ROOT: UserInfo = UserInfo::ROOT;

/// A file service whose root is a writable [`LocalFs`] on `host`.
fn host_service(host: &Path) -> Arc<dyn FileService> {
    Arc::new(Resolver::<TestPlatform, _>::new(
        Composer::<TestPlatform>::builder()
            .try_mount("/", |ids| LocalFs::new(host, ids))
            .unwrap()
            .build()
            .unwrap(),
    ))
}

#[test]
fn private_mount_pins_do_not_hide_a_read_only_host_mount() {
    use litebox_broker_core::fs::read_only::ReadOnly;
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("target")).unwrap();
    let parent: Arc<dyn FileService> = Arc::new(Resolver::<TestPlatform, _>::new(
        Composer::<TestPlatform>::builder()
            .try_mount("/", |ids| LocalFs::new(temp.path(), ids).map(ReadOnly::new))
            .unwrap()
            .build()
            .unwrap(),
    ));
    let child = parent.copy_mount_view().unwrap();
    child.mount_in_mem("/target", ROOT).unwrap().unwrap();
    assert_eq!(
        parent.rmdir("/target", ROOT).unwrap(),
        Err(FileError::ReadOnlyFs)
    );
    assert_eq!(
        parent.rename("/target", "/moved", ROOT).unwrap(),
        Err(FileError::ReadOnlyFs)
    );
    assert!(temp.path().join("target").is_dir());
}

#[test]
fn private_mount_guards_its_host_directories_under_other_spellings() {
    let temp = tempfile::tempdir().unwrap();
    for dir in ["Work", "Work/Target", "Work/Other"] {
        fs::create_dir(temp.path().join(dir)).unwrap();
    }
    // Only a case-insensitive host gives one directory a second spelling.
    if !temp.path().join("WORK").join("TARGET").is_dir() {
        return;
    }
    let parent = host_service(temp.path());
    let child = parent.copy_mount_view().unwrap();
    child.mount_in_mem("/Work/Target", ROOT).unwrap().unwrap();

    assert_eq!(
        parent.rename("/WORK", "/Moved", ROOT).unwrap(),
        Err(FileError::Busy)
    );
    assert_eq!(
        parent.rmdir("/work/target", ROOT).unwrap(),
        Err(FileError::Busy)
    );
    assert!(temp.path().join("Work").join("Target").is_dir());

    parent
        .rename("/WORK/OTHER", "/WORK/Renamed", ROOT)
        .unwrap()
        .unwrap();
    parent.rmdir("/work/renamed", ROOT).unwrap().unwrap();
    assert!(!temp.path().join("Work").join("Renamed").exists());
    drop(child);
}
