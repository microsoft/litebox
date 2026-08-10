// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::boxed::Box;
use alloc::sync::Arc;
use std::sync::Mutex;

extern crate alloc;

use litebox::fs::{
    Mode, OFlags,
    errors::{CloseError, OpenError, ReadError, WriteError},
};
use litebox::shim::EnterShim;

use crate::platform::HarnessPlatform;
use crate::process_memory::{ProcessMemory, ProcessPointer};

pub const AT_FDCWD: i32 = -100;

#[derive(Debug)]
pub enum ExecutionContext {
    Request(GuestRequest),

    Response(PlatformResponse),

    Action(GuestAction),
}

impl ExecutionContext {
    pub fn start<F>(guest: F) -> Self
    where
        F: for<'a> FnOnce(&GuestApi<'a>) + Send + 'static,
    {
        ExecutionContext::Action(GuestAction::Start(ThreadEntryPoint(Box::new(guest))))
    }
}

#[derive(Debug)]
pub enum GuestRequest {
    Exit,

    SpawnThread {
        new_thread_fun: Mutex<Option<ThreadEntryPoint>>,
    },

    Syscall(Syscall),
}

#[derive(Debug)]
pub enum Syscall {
    Openat {
        dirfd: i32,
        pathname: ProcessPointer<i8>,
        flags: OFlags,
        mode: Mode,
    },

    Close {
        fd: i32,
    },

    Read {
        fd: i32,
        buf: ProcessPointer<u8>,
        count: usize,
    },

    Write {
        fd: i32,
        buf: ProcessPointer<u8>,
        count: usize,
    },
}

#[derive(Debug)]
pub enum PlatformResponse {
    Syscall(SyscallResult),
}

#[derive(Debug)]
pub enum SyscallResult {
    Openat(Result<i32, OpenError>),
    Close(Result<(), CloseError>),
    Read(Result<usize, ReadError>),
    Write(Result<usize, WriteError>),
}

#[derive(Debug)]
pub enum GuestAction {
    Start(ThreadEntryPoint),
}

pub struct ThreadEntryPoint(pub Box<dyn for<'a> FnOnce(&GuestApi<'a>) + Send + 'static>);
impl std::fmt::Debug for ThreadEntryPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ThreadEntryPoint").field(&"FnOnce").finish()
    }
}

pub struct GuestApi<'shim> {
    platform: Arc<HarnessPlatform>,

    shim: &'shim (dyn EnterShim<ExecutionContext = ExecutionContext> + 'shim),

    kernel: Arc<crate::kernel::HarnessKernel>,
    process_memory: Arc<ProcessMemory>,
}

impl<'shim> GuestApi<'shim> {
    pub(crate) fn new(
        platform: Arc<HarnessPlatform>,
        shim: &'shim (dyn EnterShim<ExecutionContext = ExecutionContext> + 'shim),
        kernel: Arc<crate::kernel::HarnessKernel>,
        process_memory: Arc<ProcessMemory>,
    ) -> Self {
        Self {
            platform,
            shim,
            kernel,
            process_memory,
        }
    }

    pub fn spawn_thread<F>(&self, fun: F) -> Result<(), std::io::Error>
    where
        F: for<'a> FnOnce(&GuestApi<'a>) + Send + 'static,
    {
        use litebox::platform::ThreadProvider;

        let parent_ctx = ExecutionContext::Request(GuestRequest::SpawnThread {
            new_thread_fun: Mutex::new(Some(ThreadEntryPoint(Box::new(fun)))),
        });
        let init_thread: Box<dyn litebox::shim::InitThread<ExecutionContext = ExecutionContext>> =
            Box::new(crate::shim::HarnessInitThread {
                platform: Arc::clone(&self.platform),
                kernel: Arc::clone(&self.kernel),
                process_memory: Arc::clone(&self.process_memory),
            });

        unsafe { self.platform.spawn_thread(&parent_ctx, init_thread) }
    }

    pub fn process_pointer<T>(&self, offset: usize) -> ProcessPointer<T> {
        self.process_memory
            .pointer(offset)
            .expect("process-memory offset is out of range")
    }

    pub fn open(
        &self,
        path: ProcessPointer<i8>,
        flags: OFlags,
        mode: Mode,
    ) -> Result<i32, OpenError> {
        match self.syscall(Syscall::Openat {
            dirfd: AT_FDCWD,
            pathname: path,
            flags,
            mode,
        }) {
            SyscallResult::Openat(r) => r,
            other => panic!("expected SyscallResult::Openat, got {other:?}"),
        }
    }

    pub fn close(&self, fd: i32) -> Result<(), CloseError> {
        match self.syscall(Syscall::Close { fd }) {
            SyscallResult::Close(r) => r,
            other => panic!("expected SyscallResult::Close, got {other:?}"),
        }
    }

    pub fn read(&self, fd: i32, buf: ProcessPointer<u8>, count: usize) -> Result<usize, ReadError> {
        match self.syscall(Syscall::Read { fd, buf, count }) {
            SyscallResult::Read(r) => r,
            other => panic!("expected SyscallResult::Read, got {other:?}"),
        }
    }

    pub fn write(
        &self,
        fd: i32,
        buf: ProcessPointer<u8>,
        count: usize,
    ) -> Result<usize, WriteError> {
        match self.syscall(Syscall::Write { fd, buf, count }) {
            SyscallResult::Write(r) => r,
            other => panic!("expected SyscallResult::Write, got {other:?}"),
        }
    }

    pub fn memory_matches<T>(&self, pointer: ProcessPointer<T>, expected: &[u8]) -> bool {
        self.process_memory
            .read(&self.platform, pointer, expected.len())
            .is_ok_and(|bytes| bytes == expected)
    }

    fn syscall(&self, syscall: Syscall) -> SyscallResult {
        let mut ctx = ExecutionContext::Request(GuestRequest::Syscall(syscall));
        let _continue = self.shim.syscall(&mut ctx);
        match ctx {
            ExecutionContext::Response(PlatformResponse::Syscall(result)) => result,
            other => panic!("shim did not produce a Syscall response, got {other:?}"),
        }
    }
}
