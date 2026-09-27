// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Experimental Darwin pthread lifecycle for a runtime-provided entrypoint.

use crate::{MacosShimEntrypoints, ShimPlatform, Task, ThreadState};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use core::{ops::Range, sync::atomic::Ordering};
use litebox::platform::ArchSpecificRegister;
use litebox_common_macos::{
    PAGE_SIZE, PtRegs, STACK_ALIGNMENT, errno::Errno, syscall::MachPortName,
    user_pointers::UserPtrMut,
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

/// A joiner can deallocate a pthread object before its owner reaches
/// bsdthread_terminate. Keep its backing until the owner's final guest resume
/// (possibly into libc exit) has completed, without delaying the joiner.
#[derive(Default)]
pub(crate) struct PthreadMappings {
    live: BTreeMap<u64, Range<usize>>,
    // Only pages blocked by a live pin; retirement drains newly unpinned pages.
    pub(crate) pending_pages: BTreeSet<usize>,
}

impl PthreadMappings {
    pub(crate) fn overlaps(&self, range: &Range<usize>) -> bool {
        self.live
            .values()
            .any(|live| live.start < range.end && range.start < live.end)
    }

    pub(crate) fn pinned_pages(&self, range: &Range<usize>) -> BTreeSet<usize> {
        self.live
            .values()
            .flat_map(|live| {
                (live.start.max(range.start)..live.end.min(range.end)).step_by(PAGE_SIZE)
            })
            .collect()
    }
}

pub(crate) struct PthreadStartup<P: ShimPlatform> {
    tsd: usize,
    port_address: usize,
    notification: Arc<P::RawMutex>,
}

impl<P: ShimPlatform> PthreadStartup<P> {
    pub(crate) fn publish(&self, succeeded: bool) {
        let _ = self.notification.underlying_atomic().compare_exchange(
            STARTUP_PENDING,
            if succeeded {
                STARTUP_OK
            } else {
                STARTUP_FAILED
            },
            Ordering::Release,
            Ordering::Relaxed,
        );
        self.notification.wake_all();
    }
}

impl<P: ShimPlatform> Drop for PthreadStartup<P> {
    fn drop(&mut self) {
        // Keep failure notification armed through platform setup and shim init.
        // A completed notification is immutable, including on normal teardown.
        self.publish(false);
    }
}

impl<P: ShimPlatform> litebox::shim::InitThread for Task<P> {
    type ExecutionContext = PtRegs;
    fn init(self: Box<Self>) -> Box<dyn litebox::shim::EnterShim<ExecutionContext = PtRegs>> {
        Box::new(MacosShimEntrypoints {
            task: *self,
            _not_send: core::marker::PhantomData,
        })
    }
}

impl<P: ShimPlatform> Task<P> {
    pub(crate) fn retain_pthread_mapping(&self, pthread: usize) -> Result<(), Errno> {
        let size = self
            .global
            .pthread_runtime
            .ok_or(Errno::ENOSYS)?
            .pthread_size;
        if size == 0 {
            return Err(Errno::EINVAL);
        }
        let start = pthread & !(PAGE_SIZE - 1);
        let end = pthread
            .checked_add(size)
            .and_then(|end| end.checked_next_multiple_of(PAGE_SIZE))
            .ok_or(Errno::EINVAL)?;
        let mut mappings = self.global.pthread_mappings.lock();
        if !self
            .global
            .mm
            .mappings()
            .iter()
            .any(|(range, _)| range.start <= start && end <= range.end)
        {
            return Err(Errno::EFAULT);
        }
        // VM spans can merge adjacent allocations. Their bounds validate the
        // runtime-supplied footprint, but must never enlarge its pin.
        mappings.live.insert(self.thread.id, start..end);
        Ok(())
    }

    pub(crate) fn release_pthread_mapping(&self) {
        let mut mappings = self.global.pthread_mappings.lock();
        if mappings.live.remove(&self.thread.id).is_none() {
            return;
        }
        let PthreadMappings {
            live,
            pending_pages,
        } = &mut *mappings;
        pending_pages.retain(|page| {
            if live.values().any(|live| live.contains(page)) {
                return true;
            }
            // Reclaim each page as soon as its last pin retires. Never keep a
            // stale deferred range over pages that MAP_FIXED can reuse.
            // Keep the lifetime lock through deallocation to exclude new pins.
            if let Err(error) = self.unmap_pages(*page..*page + PAGE_SIZE) {
                litebox_util_log::warn!(error:% = error; "failed to release retired pthread mapping");
            }
            false
        });
    }

    pub(crate) fn initialize_pthread(&self, ctx: &mut PtRegs) -> Result<(), Errno> {
        if self.process.exit_status().is_some() {
            return Err(Errno::EINTR);
        }
        if let Some(startup) = &self.thread.startup {
            let runtime = self.global.pthread_runtime.ok_or(Errno::ENOSYS)?;
            let identity = (runtime.current_thread_identity)();
            if identity.0 == 0 || identity.1 == 0 || identity.1 == u32::MAX {
                return Err(Errno::EAGAIN);
            }
            // The platform resets guest TLS after InitThread::init. Install it
            // here, once, and report success only after all fallible setup.
            self.global
                .platform
                .set_arch_specific_register(&ArchSpecificRegister::TpidrEl0, startup.tsd)
                .map_err(|_| Errno::EINVAL)?;
            UserPtrMut::<usize>::from_usize(startup.port_address)
                .write_at_offset::<P>(0, identity.1 as usize)
                .ok_or(Errno::EFAULT)?;
            self.thread.native_identity.set(Some(identity));
            ctx.regs[1] = identity.1 as usize;
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
        if !tsd.is_multiple_of(16)
            || !port_address.is_multiple_of(size_of::<usize>())
            || runtime
                .tsd_offset
                .checked_add(runtime.mach_thread_self_offset)
                .and_then(|offset| offset.checked_add(size_of::<usize>()))
                .is_none_or(|end| end > runtime.pthread_size)
        {
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
        let startup = Arc::new(P::RawMutex::INIT);
        let mut thread = ThreadState::new(u64::from(litebox_thread.id()), self.global.platform);
        thread.startup = Some(PthreadStartup {
            tsd,
            port_address,
            notification: startup.clone(),
        });
        thread.litebox_thread.set(Some(litebox_thread));
        // Count this guest until bsdthread_terminate retires it or Task drop
        // handles startup failure/abnormal termination.
        self.process.thread_started();
        let child = Task {
            global: self.global.clone(),
            files: self.files.clone(),
            params: self.params,
            process: self.process.clone(),
            thread,
        };
        child.retain_pthread_mapping(pthread)?;
        // SAFETY: entry is supplied by the runtime, and guest pointers are passed
        // as register values; faults during guest execution follow the normal path.
        unsafe { self.global.platform.spawn_thread(&ctx, Box::new(child)) }
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

    /// Never return to libpthread's termination stub. The last guest instead
    /// enters libc exit on its still-live stack; the shared native thread count
    /// includes runner/donor threads and cannot detect guest process completion.
    pub(crate) fn sys_bsdthread_terminate(
        &self,
        ctx: &mut PtRegs,
        stack: usize,
        size: usize,
        port: MachPortName,
        semaphore_or_ulock: usize,
    ) -> Result<(), Errno> {
        let runtime = self.global.pthread_runtime.ok_or(Errno::ENOSYS)?;
        if self.process.exit_status().is_none() && runtime.process_exit != 0 {
            if self.process.retire_unless_last() {
                self.thread.counted.set(false);
            } else {
                // libpthread has released its list lock and run TSD destructors.
                // A joiner may already have requested TSD deallocation; the live
                // pthread mapping pin keeps it available through libc exit.
                // Keep this Task counted until exit's syscall records the status.
                ctx.pc = runtime.process_exit;
                ctx.regs[30] = 0;
                return Ok(());
            }
        }
        // Only workers cache a native identity. The initial thread's Mach-self
        // slot also names the executing thread, not its parked TSD donor.
        let own_port = self
            .thread
            .native_identity
            .get()
            .map_or_else(|| (runtime.current_thread_identity)().1, |(_, port)| port);
        if port.0 != 0 && port.0 != own_port {
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
        Ok(())
    }

    pub(crate) fn sys_pthread_sync(&self, operation: crate::PthreadSync) -> Result<usize, Errno> {
        let runtime = self.global.pthread_runtime.ok_or(Errno::ENOSYS)?;
        (runtime.synchronize)(operation)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::{MacosShimBuilder, Process, PthreadRuntime};
    use litebox::platform::ArchSpecificProvider as _;
    use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo, InitThread};
    use litebox_platform_macos_userland::{
        GuestAbi, MacosUserland as Platform, RawMutex, set_guest_abi,
    };

    #[test]
    fn startup_notification_follows_tls_and_identity_setup() {
        struct Probe {
            entry: Box<dyn EnterShim<ExecutionContext = PtRegs>>,
            notification: Arc<RawMutex>,
            expected: u32,
            tsd: usize,
            platform: &'static Platform,
        }
        impl EnterShim for Probe {
            type ExecutionContext = PtRegs;
            fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
                assert_eq!(
                    self.notification
                        .underlying_atomic()
                        .load(Ordering::Acquire),
                    STARTUP_PENDING
                );
                let operation = self.entry.init(ctx);
                assert_eq!(
                    self.notification
                        .underlying_atomic()
                        .load(Ordering::Acquire),
                    self.expected
                );
                if self.expected == STARTUP_OK {
                    assert_eq!(operation, ContinueOperation::Resume);
                    assert_eq!(ctx.regs[1], 123);
                    assert_eq!(
                        self.platform
                            .get_arch_specific_register(&ArchSpecificRegister::TpidrEl0)
                            .unwrap(),
                        self.tsd
                    );
                } else {
                    assert_eq!(operation, ContinueOperation::Terminate);
                }
                ContinueOperation::Terminate // Never enter synthetic guest code.
            }
            fn syscall(&self, _: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }
            fn exception(&self, _: &mut PtRegs, _: &ExceptionInfo) -> ContinueOperation {
                unreachable!()
            }
            fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }
        }

        set_guest_abi(GuestAbi::Darwin);
        let platform = Platform::new();
        // TSD rejection, identity-write failure, process exit, and successful setup.
        for (tsd, writable_port, exited) in [
            (usize::MAX & !15, true, false),
            (0x1000, false, false),
            (0x1000, true, true),
            (0x1000, true, false),
        ] {
            let shim = MacosShimBuilder::new(platform)
                .with_pthread_runtime(PthreadRuntime {
                    thread_start: 0x1000,
                    process_exit: 0x2000,
                    tsd_offset: 0,
                    mach_thread_self_offset: 0,
                    pthread_size: PAGE_SIZE,
                    current_thread_identity: || (1, 123),
                    synchronize: |_| Ok(0),
                })
                .build();
            let notification = Arc::new(RawMutex::INIT);
            let mut port = 0usize;
            let mut thread = ThreadState::new(1, platform);
            thread.startup = Some(PthreadStartup {
                tsd,
                port_address: if writable_port {
                    (&raw mut port) as usize
                } else {
                    0
                },
                notification: notification.clone(),
            });
            let process = Process::new();
            if exited {
                process.exit(9);
            }
            let task = Task {
                global: shim.global,
                files: shim.files,
                params: litebox_common_macos::TaskParams::default(),
                process: process.clone(),
                thread,
            };
            let expected = if tsd == 0x1000 && writable_port && !exited {
                STARTUP_OK
            } else {
                STARTUP_FAILED
            };
            let probe = Probe {
                entry: Box::new(task).init(),
                notification: notification.clone(),
                expected,
                tsd,
                platform,
            };
            assert_eq!(
                notification.underlying_atomic().load(Ordering::Acquire),
                STARTUP_PENDING
            );
            // SAFETY: Probe terminates in init, before any guest instructions or
            // TSD dereferences; the identity output slot stays live throughout.
            unsafe { litebox_platform_macos_userland::run_thread(probe, &mut PtRegs::default()) };
            assert_eq!(
                notification.underlying_atomic().load(Ordering::Acquire),
                expected
            );
            assert_eq!(port, if expected == STARTUP_OK { 123 } else { 0 });
            assert_eq!(process.exit_status(), Some(if exited { 9 } else { 0 }));
            assert_eq!(process.0.live_threads.load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn abandoned_startup_notifies_failure() {
        let notification = Arc::new(RawMutex::INIT);
        let startup = PthreadStartup::<Platform> {
            tsd: 0,
            port_address: 0,
            notification: notification.clone(),
        };
        drop(startup);
        assert_eq!(
            notification.underlying_atomic().load(Ordering::Acquire),
            STARTUP_FAILED
        );
    }
}
