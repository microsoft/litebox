// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Experimental Darwin pthread lifecycle for a runtime-provided entrypoint.

use crate::{MacosShimEntrypoints, ShimPlatform, Task, ThreadState};
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::Ordering;
use litebox::platform::ArchSpecificRegister;
use litebox_common_macos::{
    PtRegs, STACK_ALIGNMENT, errno::Errno, syscall::MachPortName, user_pointers::UserPtrMut,
};
use litebox_platform::sync::RawMutex as _;

const PTHREAD_START_CUSTOM: u32 = 0x0100_0000;
const PTHREAD_START_QOSCLASS: u32 = 0x0800_0000;
const PTHREAD_START_TSD_BASE_SET: u32 = 0x1000_0000;
/// `pthread_priority_t` carried with `PTHREAD_START_QOSCLASS`.
const PTHREAD_START_QOSCLASS_MASK: u32 = 0x00ff_ffff;

const STARTUP_PENDING: u32 = 0;
const STARTUP_OK: u32 = 1;
const STARTUP_FAILED: u32 = 2;

struct NewThread<P: ShimPlatform> {
    task: Option<Task<P>>,
    startup: Arc<P::RawMutex>,
}

impl<P: ShimPlatform> NewThread<P> {
    fn publish(&self, state: u32) {
        let _ = self.startup.underlying_atomic().compare_exchange(
            STARTUP_PENDING,
            state,
            Ordering::Release,
            Ordering::Relaxed,
        );
        self.startup.wake_all();
    }
}

impl<P: ShimPlatform> Drop for NewThread<P> {
    fn drop(&mut self) {
        // Release the parent if host TLS setup or the initializer panics.
        self.publish(STARTUP_FAILED);
    }
}

impl<P: ShimPlatform> litebox::shim::InitThread for NewThread<P> {
    type ExecutionContext = PtRegs;
    fn init(mut self: Box<Self>) -> Box<dyn litebox::shim::EnterShim<ExecutionContext = PtRegs>> {
        let task = self.task.take().expect("thread initializer consumed once");
        let result = task.publish_pthread_identity();
        if result.is_err() {
            task.thread.exited.store(true, Ordering::Release);
        }
        self.publish(if result.is_ok() {
            STARTUP_OK
        } else {
            STARTUP_FAILED
        });
        Box::new(MacosShimEntrypoints {
            task,
            _not_send: core::marker::PhantomData,
        })
    }
}

impl<P: ShimPlatform> Task<P> {
    fn publish_pthread_identity(&self) -> Result<(), Errno> {
        let runtime = self.global.pthread_runtime.ok_or(Errno::ENOSYS)?;
        let (_, port_address) = self.thread.startup.ok_or(Errno::EINVAL)?;
        let identity = (runtime.current_thread_identity)();
        if identity.0 == 0 || identity.1 == 0 || identity.1 == u32::MAX {
            return Err(Errno::EAGAIN);
        }
        UserPtrMut::<usize>::from_usize(port_address)
            .write_at_offset::<P>(0, identity.1 as usize)
            .ok_or(Errno::EFAULT)?;
        self.thread.native_identity.set(Some(identity));
        Ok(())
    }

    pub(crate) fn initialize_pthread(&self, ctx: &mut PtRegs) -> Result<(), Errno> {
        if self.process.exit_status().is_some() {
            return Err(Errno::EINTR);
        }
        if let Some((tsd, _)) = self.thread.startup {
            let (_, port) = self.thread.native_identity.get().ok_or(Errno::EAGAIN)?;
            ctx.regs[1] = port as usize;
            self.global
                .platform
                .set_arch_specific_register(&ArchSpecificRegister::TpidrEl0, tsd)
                .map_err(|_| Errno::EINVAL)?;
        }
        Ok(())
    }

    pub(crate) fn sys_bsdthread_create(
        &self,
        function: usize,
        argument: usize,
        stack: usize,
        pthread: usize,
        flags: u32,
    ) -> Result<usize, Errno> {
        let runtime = self.global.pthread_runtime.ok_or(Errno::ENOSYS)?;
        if self.process.exit_status().is_some() {
            return Err(Errno::EAGAIN);
        }
        if runtime.thread_start == 0 || !runtime.thread_start.is_multiple_of(4) {
            return Err(Errno::EINVAL);
        }
        // Scheduling and suspended starts need separate support. The QoS
        // priority is accepted but not applied.
        let supported = if flags & PTHREAD_START_QOSCLASS != 0 {
            PTHREAD_START_CUSTOM | PTHREAD_START_QOSCLASS | PTHREAD_START_QOSCLASS_MASK
        } else {
            PTHREAD_START_CUSTOM
        };
        if flags & PTHREAD_START_CUSTOM == 0
            || flags & !supported != 0
            || stack == 0
            || !stack.is_multiple_of(STACK_ALIGNMENT)
            || pthread == 0
        {
            return Err(Errno::EINVAL);
        }
        // libpthread passes `stack == pthread` unless the caller supplied the
        // stack. Joining such a running thread needs Mach semaphores, which are
        // unsupported, so reject the thread instead of failing inside the join.
        if stack != pthread {
            litebox_util_log::warn!("pthread_attr_setstack threads are unsupported");
            return Err(Errno::ENOTSUP);
        }
        let tsd = pthread
            .checked_add(runtime.tsd_offset)
            .ok_or(Errno::EINVAL)?;
        let port_address = tsd
            .checked_add(runtime.mach_thread_self_offset)
            .ok_or(Errno::EINVAL)?;
        if !tsd.is_multiple_of(16) || !port_address.is_multiple_of(size_of::<usize>()) {
            return Err(Errno::EINVAL);
        }
        UserPtrMut::<usize>::from_usize(port_address)
            .write_at_offset::<P>(0, 0)
            .ok_or(Errno::EFAULT)?;
        let mut ctx = PtRegs {
            pc: runtime.thread_start,
            sp: stack,
            ..PtRegs::default()
        };
        ctx.regs[..6].copy_from_slice(&[
            pthread,
            0,
            function,
            argument,
            stack,
            (flags | PTHREAD_START_TSD_BASE_SET) as usize,
        ]);
        let litebox_thread = self
            .global
            .litebox
            .create_thread()
            .map_err(|_| Errno::EAGAIN)?;
        let mut thread = ThreadState::new(u64::from(litebox_thread.id()), self.global.platform);
        thread.startup = Some((tsd, port_address));
        thread.litebox_thread.set(Some(litebox_thread));
        // Every Task decrements the live thread count when dropped.
        self.process.thread_started();
        let child = Task {
            global: self.global.clone(),
            files: self.files.clone(),
            params: self.params,
            process: self.process.clone(),
            thread,
        };
        let startup = Arc::new(P::RawMutex::INIT);
        // SAFETY: entry is supplied by the runtime, and guest pointers are passed
        // as register values; faults during guest execution follow the normal path.
        unsafe {
            self.global.platform.spawn_thread(
                &ctx,
                Box::new(NewThread {
                    task: Some(child),
                    startup: startup.clone(),
                }),
            )
        }
        .map_err(|_| Errno::EAGAIN)?;
        loop {
            match startup.underlying_atomic().load(Ordering::Acquire) {
                STARTUP_PENDING => {
                    let _ = startup.block(STARTUP_PENDING);
                }
                STARTUP_OK => break,
                _ => return Err(Errno::EAGAIN),
            }
        }
        Ok(pthread)
    }

    /// Terminates the calling thread. Like XNU, this never returns to the guest:
    /// libpthread aborts if it does.
    pub(crate) fn sys_bsdthread_terminate(
        &self,
        stack: usize,
        size: usize,
        port: MachPortName,
        semaphore_or_ulock: usize,
    ) {
        let own_port = self.thread.native_identity.get().map(|(_, port)| port);
        if port.0 != 0 && Some(port.0) != own_port {
            litebox_util_log::warn!(port = port.0; "bsdthread_terminate for a foreign port");
        }
        if semaphore_or_ulock != 0 {
            litebox_util_log::warn!("ignoring bsdthread_terminate semaphore");
        }
        if stack != 0
            && size != 0
            && let Err(error) = self.sys_munmap(stack, size)
        {
            litebox_util_log::warn!(error:% = error; "failed to release terminated thread stack");
        }
        self.thread.exited.store(true, Ordering::Release);
    }

    pub(crate) fn sys_pthread_sync(&self, operation: crate::PthreadSync) -> Result<usize, Errno> {
        let runtime = self.global.pthread_runtime.ok_or(Errno::ENOSYS)?;
        (runtime.synchronize)(operation)
    }
}
