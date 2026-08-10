// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;

extern crate alloc;

use litebox::fs::Mode;
use litebox::fs::OFlags;
use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo, InitThread};

use crate::context::{
    ExecutionContext, GuestAction, GuestApi, GuestRequest, PlatformResponse, Syscall,
    SyscallResult, ThreadEntryPoint,
};
use crate::kernel::HarnessKernel;
use crate::platform::HarnessPlatform;
use crate::process_memory::ProcessPointer;

pub struct HarnessShim {
    platform: Arc<HarnessPlatform>,
    kernel: Arc<HarnessKernel>,

    read_scratch: RefCell<Vec<u8>>,
    process_memory: Arc<crate::process_memory::ProcessMemory>,
}

impl EnterShim for HarnessShim {
    type ExecutionContext = ExecutionContext;

    fn init(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        let owned_ctx = core::mem::replace(ctx, ExecutionContext::Request(GuestRequest::Exit));

        let ExecutionContext::Action(GuestAction::Start(ThreadEntryPoint(body))) = owned_ctx else {
            panic!("Initial ExecutionContext must be GuestAction::Start, not {owned_ctx:?}");
        };

        let api = GuestApi::new(
            Arc::clone(&self.platform),
            self as &dyn EnterShim<ExecutionContext = ExecutionContext>,
            Arc::clone(&self.kernel),
            Arc::clone(&self.process_memory),
        );
        body(&api);

        ContinueOperation::Terminate
    }

    fn syscall(&self, ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        let result = match ctx {
            ExecutionContext::Request(GuestRequest::Syscall(s)) => self.dispatch_syscall(s),
            other => panic!("HarnessShim::syscall called with non-Syscall context: {other:?}"),
        };
        *ctx = ExecutionContext::Response(PlatformResponse::Syscall(result));
        ContinueOperation::Resume
    }

    fn exception(
        &self,
        _ctx: &mut Self::ExecutionContext,
        _info: &ExceptionInfo,
    ) -> ContinueOperation {
        ContinueOperation::Terminate
    }

    fn interrupt(&self, _ctx: &mut Self::ExecutionContext) -> ContinueOperation {
        ContinueOperation::Terminate
    }
}

impl HarnessShim {
    fn dispatch_syscall(&self, syscall: &Syscall) -> SyscallResult {
        match *syscall {
            Syscall::Openat {
                dirfd,
                pathname,
                flags,
                mode,
            } => SyscallResult::Openat(self.do_openat(dirfd, pathname, flags, mode)),
            Syscall::Close { fd } => SyscallResult::Close(self.kernel.close(fd)),
            Syscall::Read { fd, buf, count } => SyscallResult::Read(self.do_read(fd, buf, count)),
            Syscall::Write { fd, buf, count } => {
                SyscallResult::Write(self.do_write(fd, buf, count))
            }
        }
    }

    fn do_openat(
        &self,
        _dirfd: i32,
        pathname: ProcessPointer<i8>,
        flags: OFlags,
        mode: Mode,
    ) -> Result<i32, litebox::fs::errors::OpenError> {
        let c_path = self
            .process_memory
            .read_c_string(&self.platform, pathname)
            .expect("HarnessShim::do_openat: invalid pathname pointer");
        let path = c_path
            .to_str()
            .expect("HarnessShim::do_openat: path is not valid UTF-8");

        self.kernel.open(path, flags, mode)
    }

    fn do_read(
        &self,
        fd: i32,
        buf: ProcessPointer<u8>,
        count: usize,
    ) -> Result<usize, litebox::fs::errors::ReadError> {
        let mut scratch = self.read_scratch.borrow_mut();
        if scratch.len() < count {
            scratch.resize(count, 0);
        }
        let n = self.kernel.read(fd, &mut scratch[..count])?;
        if n > 0 {
            self.process_memory
                .write(&self.platform, buf, &scratch[..n])
                .expect("HarnessShim::do_read: invalid buffer pointer");
        }
        Ok(n)
    }

    fn do_write(
        &self,
        fd: i32,
        buf: ProcessPointer<u8>,
        count: usize,
    ) -> Result<usize, litebox::fs::errors::WriteError> {
        let bytes = self
            .process_memory
            .read(&self.platform, buf, count)
            .expect("HarnessShim::do_write: invalid buffer pointer");
        self.kernel.write(fd, &bytes)
    }
}

pub struct HarnessInitThread {
    pub(crate) platform: Arc<HarnessPlatform>,
    pub(crate) kernel: Arc<HarnessKernel>,
    pub(crate) process_memory: Arc<crate::process_memory::ProcessMemory>,
}

impl InitThread for HarnessInitThread {
    type ExecutionContext = ExecutionContext;

    fn init(self: Box<Self>) -> Box<dyn EnterShim<ExecutionContext = Self::ExecutionContext>> {
        Box::new(HarnessShim {
            platform: self.platform,
            kernel: self.kernel,
            read_scratch: RefCell::new(Vec::new()),
            process_memory: self.process_memory,
        })
    }
}
