// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::marker::PhantomData;
use std::sync::Mutex;

extern crate alloc;

use litebox::fs::{
    Mode, OFlags,
    errors::{CloseError, OpenError, ReadError, WriteError},
};
use litebox::platform::trivial_providers::{TransparentConstPtr, TransparentMutPtr};
use litebox::platform::{RawConstPointer, RawPointerProvider};
use litebox::shim::EnterShim;

use crate::platform::HarnessPlatform;

pub const AT_FDCWD: i32 = -100;

#[repr(transparent)]
pub struct UserPtr<P, T: ?Sized> {
    inner: P,
    _phantom: PhantomData<fn() -> T>,
}

impl<P: Copy, T: ?Sized> Clone for UserPtr<P, T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<P: Copy, T: ?Sized> Copy for UserPtr<P, T> {}

impl<P: core::fmt::Debug, T: ?Sized> core::fmt::Debug for UserPtr<P, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("UserPtr").field(&self.inner).finish()
    }
}

unsafe impl<P, T: Send + ?Sized> Send for UserPtr<P, T> {}
unsafe impl<P, T: Sync + ?Sized> Sync for UserPtr<P, T> {}

impl<P, T: ?Sized> UserPtr<P, T> {
    pub const fn new(inner: P) -> Self {
        Self {
            inner,
            _phantom: PhantomData,
        }
    }

    pub fn into_inner(self) -> P {
        self.inner
    }
}

impl<P: Copy, T: ?Sized> UserPtr<P, T> {
    pub fn get(self) -> P {
        self.inner
    }
}

pub type UserConstPtr<T> = UserPtr<<HarnessPlatform as RawPointerProvider>::RawConstPointer<T>, T>;

pub type UserMutPtr<T> = UserPtr<<HarnessPlatform as RawPointerProvider>::RawMutPointer<T>, T>;

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
        pathname: UserConstPtr<i8>,
        flags: OFlags,
        mode: Mode,
    },

    Close {
        fd: i32,
    },

    Read {
        fd: i32,
        buf: UserMutPtr<u8>,
        count: usize,
    },

    Write {
        fd: i32,
        buf: UserConstPtr<u8>,
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
}

impl<'shim> GuestApi<'shim> {
    pub(crate) fn new(
        platform: Arc<HarnessPlatform>,
        shim: &'shim (dyn EnterShim<ExecutionContext = ExecutionContext> + 'shim),
        kernel: Arc<crate::kernel::HarnessKernel>,
    ) -> Self {
        Self {
            platform,
            shim,
            kernel,
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
            });

        unsafe { self.platform.spawn_thread(&parent_ctx, init_thread) }
    }

    pub fn open(&self, path: *const u8, flags: OFlags, mode: Mode) -> Result<i32, OpenError> {
        let pathname = UserConstPtr::<i8>::new(TransparentConstPtr::<i8>::from_usize(
            path.expose_provenance(),
        ));
        match self.syscall(Syscall::Openat {
            dirfd: AT_FDCWD,
            pathname,
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

    pub fn read(&self, fd: i32, buf: *mut u8, count: usize) -> Result<usize, ReadError> {
        let buf =
            UserMutPtr::<u8>::new(TransparentMutPtr::<u8>::from_usize(buf.expose_provenance()));
        match self.syscall(Syscall::Read { fd, buf, count }) {
            SyscallResult::Read(r) => r,
            other => panic!("expected SyscallResult::Read, got {other:?}"),
        }
    }

    pub fn write(&self, fd: i32, buf: *const u8, count: usize) -> Result<usize, WriteError> {
        let buf = UserConstPtr::<u8>::new(TransparentConstPtr::<u8>::from_usize(
            buf.expose_provenance(),
        ));
        match self.syscall(Syscall::Write { fd, buf, count }) {
            SyscallResult::Write(r) => r,
            other => panic!("expected SyscallResult::Write, got {other:?}"),
        }
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
