// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::fs::{FileAccessMode, FileOpenFlags};

use super::fcall::LOpenFlags;
use super::open_flags_to_lopen;

#[test]
fn access_modes_are_not_wire_flag_bits() {
    for (access, expected) in [
        (FileAccessMode::ReadOnly, LOpenFlags::empty()),
        (FileAccessMode::WriteOnly, LOpenFlags::O_WRONLY),
        (FileAccessMode::ReadWrite, LOpenFlags::O_RDWR),
    ] {
        assert_eq!(
            open_flags_to_lopen(access, FileOpenFlags::empty()),
            expected
        );
        assert_eq!(
            open_flags_to_lopen(access, FileOpenFlags::CREATE | FileOpenFlags::APPEND),
            expected | LOpenFlags::O_CREAT | LOpenFlags::O_APPEND,
        );
    }
}

#[test]
fn canonical_flags_translate_only_at_wire_boundary() {
    for (flag, expected) in [
        (FileOpenFlags::CREATE, LOpenFlags::O_CREAT),
        (FileOpenFlags::EXCLUSIVE, LOpenFlags::O_EXCL),
        (FileOpenFlags::TRUNCATE, LOpenFlags::O_TRUNC),
        (FileOpenFlags::APPEND, LOpenFlags::O_APPEND),
        (FileOpenFlags::DIRECTORY, LOpenFlags::O_DIRECTORY),
        (FileOpenFlags::NO_FOLLOW, LOpenFlags::O_NOFOLLOW),
        (FileOpenFlags::NONBLOCKING, LOpenFlags::O_NONBLOCK),
        (FileOpenFlags::NO_CONTROLLING_TERMINAL, LOpenFlags::empty()),
        (FileOpenFlags::LARGE_FILE, LOpenFlags::empty()),
        (FileOpenFlags::PATH, LOpenFlags::empty()),
    ] {
        assert_eq!(
            open_flags_to_lopen(FileAccessMode::ReadOnly, flag),
            expected
        );
    }
}
