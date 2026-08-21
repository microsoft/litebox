// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::sync::Arc;
use std::collections::HashMap;
use std::sync::Mutex;

extern crate alloc;

use litebox::LiteBox;
use litebox::fd::TypedFd;
use litebox::fs::errors::{CloseError, OpenError, ReadError, WriteError};
use litebox::fs::{FileSystem as _, Mode, OFlags, UserInfo, in_mem, resolver::Resolver};

use crate::platform::HarnessPlatform;

pub struct HarnessKernel {
    fs: HarnessFileSystem,

    fd_table: Mutex<FdTable>,
}

struct FdTable {
    entries: HashMap<i32, TypedFd<HarnessFileSystem>>,

    next_fd: i32,
}

type HarnessFileSystem = Resolver<HarnessPlatform, in_mem::InMem<HarnessPlatform>>;

impl HarnessKernel {
    pub(crate) fn new(litebox: &LiteBox<HarnessPlatform>) -> Arc<Self> {
        let fs = Resolver::new(
            litebox,
            in_mem::InMem::new_initialized([(
                "/tmp",
                in_mem::InitialNode::Directory {
                    mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
                    owner: UserInfo::ROOT,
                },
            )]),
        );
        Arc::new(Self {
            fs,
            fd_table: Mutex::new(FdTable {
                entries: HashMap::new(),
                next_fd: 3,
            }),
        })
    }

    pub(crate) fn open(&self, path: &str, flags: OFlags, mode: Mode) -> Result<i32, OpenError> {
        let typed_fd = self.fs.open(path, flags, mode)?;
        let mut table = self.fd_table.lock().unwrap();
        let fd = table.next_fd;
        table.next_fd = table
            .next_fd
            .checked_add(1)
            .expect("HarnessKernel ran out of fds");
        let prev = table.entries.insert(fd, typed_fd);
        debug_assert!(prev.is_none(), "fd allocator handed out a duplicate fd");
        Ok(fd)
    }

    pub(crate) fn close(&self, fd: i32) -> Result<(), CloseError> {
        let typed_fd = self
            .fd_table
            .lock()
            .unwrap()
            .entries
            .remove(&fd)
            .unwrap_or_else(|| panic!("HarnessKernel::close: unknown fd {fd}"));
        self.fs.close(&typed_fd)
    }

    pub(crate) fn read(&self, fd: i32, buf: &mut [u8]) -> Result<usize, ReadError> {
        let table = self.fd_table.lock().unwrap();
        let typed_fd = table
            .entries
            .get(&fd)
            .unwrap_or_else(|| panic!("HarnessKernel::read: unknown fd {fd}"));
        self.fs.read(typed_fd, buf, None)
    }

    pub(crate) fn write(&self, fd: i32, buf: &[u8]) -> Result<usize, WriteError> {
        let table = self.fd_table.lock().unwrap();
        let typed_fd = table
            .entries
            .get(&fd)
            .unwrap_or_else(|| panic!("HarnessKernel::write: unknown fd {fd}"));
        self.fs.write(typed_fd, buf, None)
    }
}
