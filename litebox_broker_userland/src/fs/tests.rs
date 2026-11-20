// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use litebox_broker_core::fs::inode_allocator::InodeAllocators;
use std::os::unix::fs::symlink;

fn open_path_dir(local: &LocalFs, components: &[&str]) -> DirHandle {
    let Resolution::Found(ResolvedTarget::Dir(dir)) = local
        .resolve(local.root().unwrap(), components, &|_| unreachable!())
        .unwrap()
    else {
        panic!("expected directory")
    };
    local.open_dir(dir, OFlags::PATH).unwrap()
}

#[test]
fn directory_path_uses_fd_without_searching_or_listing_ancestors() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir_all(root.join("old/sub (deleted)")).unwrap();
    let local = LocalFs::new(root, InodeAllocators::new().next()).unwrap();
    let held = open_path_dir(&local, &["old", "sub (deleted)"]);
    fs::rename(root.join("old"), root.join("new")).unwrap();
    fs::create_dir_all(root.join("old/sub (deleted)")).unwrap();
    fs::set_permissions(root.join("new"), fs::Permissions::from_mode(0o000)).unwrap();
    let path = local.dir_path(&held);
    fs::set_permissions(root.join("new"), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(path.unwrap().unwrap(), ["new", "sub (deleted)"]);
    fs::remove_dir(root.join("new/sub (deleted)")).unwrap();
    assert!(matches!(
        local.dir_path(&held),
        Err(WalkError::PathError(PathError::NoSuchFileOrDirectory))
    ));
}

#[test]
fn dot_walk_checks_search_on_start_not_on_parent() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("parent");
    let child = parent.join("child");
    fs::create_dir_all(&child).unwrap();
    let local = LocalFs::new(temp.path(), InodeAllocators::new().next()).unwrap();
    let held = open_path_dir(&local, &["parent", "child"]);
    let walk = local.walking_dir_at(&held).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o000)).unwrap();
    // Looking up the child *name* again would require search on parent. `child/..` doesn't.
    let up = local.parent_dir(&held);
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(up.unwrap().is_some());

    fs::set_permissions(&child, fs::Permissions::from_mode(0o000)).unwrap();
    // Privileged hosts can bypass DAC; compare against the host's actual `.` lookup.
    let host_search = fs::metadata(child.join(".")).is_ok();
    let search = local.check_search_permission(&walk);
    let up = local.parent_dir(&held);
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(search.is_ok(), host_search);
    assert_eq!(up.is_ok(), host_search);
}

#[test]
fn ancestor_replacement_preserves_directory_and_live_parent() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir_all(root.join("ancestor/sub")).unwrap();
    fs::create_dir(root.join("destination")).unwrap();
    fs::write(root.join("ancestor/sub/original"), b"original").unwrap();
    let local = LocalFs::new(root, InodeAllocators::new().next()).unwrap();
    let dir = open_path_dir(&local, &["ancestor", "sub"]);
    let id = local.status(HandleRef::Dir(&dir)).unwrap().node_info;

    fs::rename(root.join("ancestor"), root.join("destination/moved")).unwrap();
    fs::create_dir_all(root.join("ancestor/sub")).unwrap();
    fs::write(root.join("ancestor/sub/replacement"), b"replacement").unwrap();
    assert_eq!(local.status(HandleRef::Dir(&dir)).unwrap().node_info, id);
    let entries = local.list_dir_at(dir.clone()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "original");

    let target = root.join("ancestor/sub/replacement");
    symlink(target, root.join("destination/moved/sub/link")).unwrap();
    let walking = local.walking_dir_at(&dir).unwrap();
    assert_eq!(
        local.read_link_at(&walking, "link").unwrap(),
        "../../../ancestor/sub/replacement"
    );
    local.unlink_at(walking, "original").unwrap();
    assert!(!root.join("destination/moved/sub/original").exists());
    assert!(root.join("ancestor/sub/replacement").is_file());

    let mut walk = dir;
    for parts in [&["destination", "moved"][..], &["destination"], &[]] {
        walk = local.parent_dir(&walk).unwrap().unwrap();
        let expected = open_path_dir(&local, parts);
        assert_eq!(
            local.status(HandleRef::Dir(&walk)).unwrap().node_info,
            local.status(HandleRef::Dir(&expected)).unwrap().node_info
        );
    }
    assert!(local.parent_dir(&walk).unwrap().is_none());
}

#[test]
fn moved_out_of_export_fails_closed_even_after_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("export");
    fs::create_dir_all(root.join("child")).unwrap();
    let local = LocalFs::new(&root, InodeAllocators::new().next()).unwrap();
    let child = open_path_dir(&local, &["child"]);
    let walking = local.walking_dir_at(&child).unwrap();
    fs::rename(root.join("child"), temp.path().join("outside")).unwrap();
    fs::create_dir(root.join("child")).unwrap();
    // Outside the export, the directory no longer exists for the guest.
    let missing = |error: WalkError| {
        matches!(
            error,
            WalkError::PathError(PathError::NoSuchFileOrDirectory)
        )
    };
    assert!(
        local
            .check_search_permission(&local.walking_dir_at(&child).unwrap())
            .is_err_and(missing)
    );
    assert!(local.parent_dir(&child).is_err_and(missing));
    assert!(local.list_dir_at(child).is_err());
    assert!(
        local
            .resolve(walking, &["name"], &|_| unreachable!())
            .is_err_and(|error| missing(error.error))
    );
}

#[test]
fn root_and_resolved_children_are_not_reopened_by_name() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("mount");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("file"), b"old").unwrap();
    let local = LocalFs::new(&root, InodeAllocators::new().next()).unwrap();
    let Resolution::Found(ResolvedTarget::File(file)) = local
        .resolve(local.root().unwrap(), &["file"], &|_| unreachable!())
        .unwrap()
    else {
        panic!("expected file")
    };
    let moved = temp.path().join("moved");
    fs::rename(&root, &moved).unwrap();
    fs::create_dir(&root).unwrap();
    fs::rename(moved.join("file"), moved.join("saved")).unwrap();
    let outside = temp.path().join("outside");
    fs::write(&outside, b"outside").unwrap();
    symlink(&outside, moved.join("file")).unwrap();
    let file = local
        .open_file(file, OFlags::TRUNC | OFlags::WRONLY)
        .unwrap();
    assert_eq!(fs::read(moved.join("saved")).unwrap(), b"");
    assert_eq!(fs::read(outside).unwrap(), b"outside");
    assert!(matches!(
        local.read(&file, &mut [0; 1], 0),
        Err(ReadError::NotForReading)
    ));
    assert!(local.read_link_at(&local.root().unwrap(), "file").is_err());
    assert!(
        local
            .list_dir_at(open_path_dir(&local, &[]))
            .unwrap()
            .iter()
            .any(|e| e.name == "saved")
    );
}

#[test]
fn rename_into_own_subtree_is_invalid_before_destination_type() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("dir")).unwrap();
    fs::write(root.join("dir/file"), b"").unwrap();
    let local = LocalFs::new(root, InodeAllocators::new().next()).unwrap();
    let parent = open_path_dir(&local, &[]);
    let dir = open_path_dir(&local, &["dir"]);
    // Linux: rename("dir", "dir/file") fails with EINVAL, not ENOTDIR (native probe).
    assert!(matches!(
        local.rename_at(parent, "dir", dir, "file"),
        Err(RenameError::InvalidArgument)
    ));
    assert!(root.join("dir/file").is_file());
}

#[test]
fn legacy_timestamps_only_update_pinned_non_links() {
    use rustix::fs::{Timespec, Timestamps};
    use std::os::unix::fs::MetadataExt;
    let temp = tempfile::tempdir().unwrap();
    let root = Location::pin_dir(temp.path()).unwrap();
    fs::create_dir(root.join("dir")).unwrap();
    fs::write(root.join("file"), b"").unwrap();
    let times = Timestamps {
        last_access: Timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
        last_modification: Timespec {
            tv_sec: 2,
            tv_nsec: 0,
        },
    };
    for name in ["file", "dir"] {
        let pinned = root.child(name).unwrap();
        let moved = root.join(format!("{name}.moved"));
        fs::rename(root.join(name), &moved).unwrap();
        symlink("untouched", root.join(name)).unwrap();
        linux::set_times_legacy(&pinned, &times).unwrap();
        assert_eq!(fs::metadata(moved).unwrap().mtime(), 2);
        // The fallback refuses a pinned symlink rather than following it.
        assert!(linux::set_times_legacy(&root.child(name).unwrap(), &times).is_err());
    }
}

#[test]
fn absolute_link_targets_cannot_climb_out_of_the_root() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("export");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("x"), b"decoy").unwrap();
    fs::write(temp.path().join("x"), b"outside").unwrap();
    let canonical = fs::canonicalize(&root).unwrap();
    symlink(canonical.join("../x"), root.join("escape")).unwrap();
    symlink(canonical.join("x"), root.join("inside")).unwrap();
    let local = LocalFs::new(&root, InodeAllocators::new().next()).unwrap();
    let dir = local.root().unwrap();
    assert!(local.read_link_at(&dir, "escape").is_err());
    assert_eq!(local.read_link_at(&dir, "inside").unwrap(), "x");
}
