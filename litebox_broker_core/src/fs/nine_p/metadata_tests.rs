// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::num::NonZeroU64;

use litebox_broker_protocol::fs::{FileMode, FileNodeInfo, FileStatus, FileType, FileUser};

use super::fcall::{GetattrMask, Qid, QidType, Rgetattr, Stat, Time};
use super::{Error, rgetattr_to_file_status};

fn attributes(valid: GetattrMask) -> Rgetattr {
    Rgetattr {
        valid,
        qid: Qid {
            typ: QidType::FILE,
            version: 0,
            path: u64::MAX - 1,
        },
        stat: Stat {
            mode: 0o100644,
            uid: 1,
            gid: 2,
            nlink: 1,
            rdev: u64::MAX,
            size: u64::MAX - 2,
            blksize: u64::MAX - 3,
            blocks: 0,
            atime: Time::default(),
            mtime: Time::default(),
            ctime: Time::default(),
            btime: Time::default(),
            generation: 0,
            data_version: 0,
        },
    }
}

#[test]
fn getattr_preserves_full_width_metadata() {
    for valid in [
        GetattrMask::BASIC,
        GetattrMask::MODE
            | GetattrMask::UID
            | GetattrMask::GID
            | GetattrMask::SIZE
            | GetattrMask::RDEV
            | GetattrMask::BLOCKS,
    ] {
        let status = rgetattr_to_file_status(&attributes(valid), u64::MAX).unwrap();

        assert_eq!(
            status,
            FileStatus {
                file_type: FileType::RegularFile,
                mode: FileMode::from_bits(0o644).unwrap(),
                size: u64::MAX - 2,
                owner: FileUser { user: 1, group: 2 },
                node_info: FileNodeInfo {
                    dev: u64::MAX,
                    ino: u64::MAX - 1,
                    rdev: NonZeroU64::new(u64::MAX),
                },
                block_size: u64::MAX - 3,
            }
        );
    }
}

#[test]
fn getattr_zero_device_number_is_absent() {
    for valid in [GetattrMask::BASIC, GetattrMask::RDEV] {
        let mut attr = attributes(valid);
        attr.stat.rdev = 0;
        let status = rgetattr_to_file_status(&attr, u64::MAX).unwrap();

        assert_eq!(status.node_info.rdev, None);
    }
}

#[test]
fn getattr_ignores_unavailable_metadata() {
    let status = rgetattr_to_file_status(&attributes(GetattrMask::empty()), u64::MAX).unwrap();

    assert_eq!(status.mode, FileMode::empty());
    assert_eq!(status.size, 0);
    assert_eq!(status.owner, FileUser::ROOT);
    assert_eq!(status.block_size, 0);
    assert_eq!(
        status.node_info,
        FileNodeInfo {
            dev: u64::MAX,
            ino: u64::MAX - 1,
            rdev: None,
        }
    );
}

#[test]
fn getattr_rejects_unrepresentable_owners() {
    for valid in [GetattrMask::BASIC, GetattrMask::UID | GetattrMask::GID] {
        let mut attr = attributes(valid);
        attr.stat.uid = u32::from(u16::MAX) + 1;
        assert!(matches!(
            rgetattr_to_file_status(&attr, 0),
            Err(Error::InvalidResponse)
        ));

        attr.stat.uid = 1;
        attr.stat.gid = u32::from(u16::MAX) + 1;
        assert!(matches!(
            rgetattr_to_file_status(&attr, 0),
            Err(Error::InvalidResponse)
        ));
    }
}
