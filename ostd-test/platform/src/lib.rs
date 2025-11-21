#![no_std]

extern crate alloc;

use core::marker::PhantomData;

#[derive(Debug)]
pub struct OstdPlatform {
    _priv: PhantomData<()>,
}

impl OstdPlatform {
    pub fn new() -> OstdPlatform {
        OstdPlatform { _priv: PhantomData }
    }
}

impl litebox::platform::Provider for OstdPlatform {}

impl litebox::platform::RawPointerProvider for OstdPlatform {
    type RawConstPointer<T: Clone> =
        litebox::platform::common_providers::userspace_pointers::UserConstPtr<T>;
    type RawMutPointer<T: Clone> =
        litebox::platform::common_providers::userspace_pointers::UserMutPtr<T>;
}

impl litebox::platform::DebugLogProvider for OstdPlatform {
    fn debug_log_print(&self, msg: &str) {
        ostd::console::early_print(format_args!("{}", msg));
    }
}

pub struct PunchthroughToken {
    punchthrough: litebox_common_linux::PunchthroughSyscall<OstdPlatform>,
}

impl litebox::platform::PunchthroughToken for PunchthroughToken {
    type Punchthrough = litebox_common_linux::PunchthroughSyscall<OstdPlatform>;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<
            <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnFailure,
        >,
    > {
        match self.punchthrough {
            #[cfg(target_arch = "x86_64")]
            litebox_common_linux::PunchthroughSyscall::SetFsBase { addr: _ } => {
                todo!()
            }
            #[cfg(target_arch = "x86_64")]
            litebox_common_linux::PunchthroughSyscall::GetFsBase { addr: _ } => {
                todo!()
            }
            _ => unimplemented!(),
        }
    }
}

impl litebox::platform::PunchthroughProvider for OstdPlatform {
    type PunchthroughToken = PunchthroughToken;
    fn get_punchthrough_token_for(
        &self,
        punchthrough: <Self::PunchthroughToken as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
        Some(PunchthroughToken { punchthrough })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    from_boot: core::time::Duration,
}
pub struct SystemTime {
    // TODO
    #[allow(dead_code)]
    x: u64,
}
impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, _earlier: &Self) -> Option<core::time::Duration> {
        todo!()
    }
    fn checked_add(&self, _duration: core::time::Duration) -> Option<Self> {
        todo!()
    }
}
impl litebox::platform::SystemTime for SystemTime {
    const UNIX_EPOCH: Self = Self { x: 0 };
    fn duration_since(
        &self,
        _earlier: &Self,
    ) -> Result<core::time::Duration, core::time::Duration> {
        todo!()
    }
}

impl litebox::platform::TimeProvider for OstdPlatform {
    type Instant = Instant;
    type SystemTime = SystemTime;
    fn now(&self) -> Self::Instant {
        Instant {
            from_boot: ostd::timer::Jiffies::elapsed().as_duration(),
        }
    }
    fn current_time(&self) -> Self::SystemTime {
        todo!()
    }
}

impl litebox::platform::IPInterfaceProvider for OstdPlatform {
    fn send_ip_packet(&self, _packet: &[u8]) -> Result<(), litebox::platform::SendError> {
        todo!()
    }
    fn receive_ip_packet(
        &self,
        _packet: &mut [u8],
    ) -> Result<usize, litebox::platform::ReceiveError> {
        todo!()
    }
}

pub struct RawMutex {
    atomic: core::sync::atomic::AtomicU32,
    wait_queue: ostd::sync::WaitQueue,
}

impl litebox::platform::RawMutex for RawMutex {
    fn underlying_atomic(&self) -> &core::sync::atomic::AtomicU32 {
        &self.atomic
    }

    fn wake_many(&self, n: usize) -> usize {
        assert!(n > 0);
        if n == 1 {
            if self.wait_queue.wake_one() { 1 } else { 0 }
        } else {
            self.wait_queue.wake_all()
        }
    }

    // XXX: Not 100% sure that these semantics match what we need, but they should be close enough
    // to work for now.
    fn block(&self, val: u32) -> Result<(), litebox::platform::ImmediatelyWokenUp> {
        let mut first_check = true;
        self.wait_queue.wait_until(|| {
            let current = self.atomic.load(core::sync::atomic::Ordering::Acquire);
            if current != val {
                if first_check {
                    Some(Err(litebox::platform::ImmediatelyWokenUp))
                } else {
                    Some(Ok(()))
                }
            } else {
                first_check = false;
                None
            }
        })
    }
    fn block_or_timeout(
        &self,
        val: u32,
        time: core::time::Duration,
    ) -> Result<litebox::platform::UnblockedOrTimedOut, litebox::platform::ImmediatelyWokenUp> {
        let start = ostd::timer::Jiffies::elapsed();
        let deadline = start.as_duration().as_nanos() + time.as_nanos();
        let mut first_check = true;
        self.wait_queue.wait_until(|| {
            let current = self.atomic.load(core::sync::atomic::Ordering::Acquire);
            if current != val {
                if first_check {
                    Some(Err(litebox::platform::ImmediatelyWokenUp))
                } else {
                    Some(Ok(litebox::platform::UnblockedOrTimedOut::Unblocked))
                }
            } else {
                first_check = false;
                if ostd::timer::Jiffies::elapsed().as_duration().as_nanos() >= deadline {
                    Some(Ok(litebox::platform::UnblockedOrTimedOut::TimedOut))
                } else {
                    None
                }
            }
        })
    }
}

impl litebox::platform::RawMutexProvider for OstdPlatform {
    type RawMutex = RawMutex;
    fn new_raw_mutex(&self) -> Self::RawMutex {
        RawMutex {
            atomic: core::sync::atomic::AtomicU32::new(0),
            wait_queue: ostd::sync::WaitQueue::new(),
        }
    }
}

impl litebox::platform::StdioProvider for OstdPlatform {
    fn read_from_stdin(&self, _buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        todo!()
    }
    fn write_to(
        &self,
        _stream: litebox::platform::StdioOutStream,
        _buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        todo!()
    }
    fn is_a_tty(&self, _stream: litebox::platform::StdioStream) -> bool {
        todo!()
    }
}

impl litebox::platform::PageManagementProvider<4096> for OstdPlatform {
    const TASK_ADDR_MIN: usize = 0x1000;
    const TASK_ADDR_MAX: usize = 0x8000_0000_0000;

    fn allocate_pages(
        &self,
        _suggested_range: core::ops::Range<usize>,
        _initial_permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
        _can_grow_down: bool,
        _populate_pages_immediately: bool,
        _fixed_address_behavior: litebox::platform::page_mgmt::FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        todo!()
    }

    unsafe fn deallocate_pages(
        &self,
        _range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        todo!()
    }

    unsafe fn update_permissions(
        &self,
        _range: core::ops::Range<usize>,
        _new_permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        todo!()
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        // TODO
        core::iter::empty()
    }
}

impl litebox::platform::SystemInfoProvider for OstdPlatform {
    fn get_syscall_entry_point(&self) -> usize {
        todo!()
    }

    fn get_vdso_address(&self) -> Option<usize> {
        None
    }
}

// XXX: Maybe should use current task instead? `Task::current`
ostd::cpu_local! {
    static TLS_POINTER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
}

unsafe impl litebox::platform::ThreadLocalStorageProvider for OstdPlatform {
    fn get_thread_local_storage() -> *mut () {
        use ostd::cpu::PinCurrentCpu as _;
        let preempt_guard = ostd::task::disable_preempt();
        let cpu_id = preempt_guard.current_cpu();
        let tls_ref = TLS_POINTER.get_on_cpu(cpu_id);
        tls_ref.load(core::sync::atomic::Ordering::Acquire) as *mut ()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        use ostd::cpu::PinCurrentCpu as _;
        let preempt_guard = ostd::task::disable_preempt();
        let cpu_id = preempt_guard.current_cpu();
        let tls_ref = TLS_POINTER.get_on_cpu(cpu_id);
        tls_ref.swap(value as usize, core::sync::atomic::Ordering::AcqRel) as *mut ()
    }
}

impl litebox::platform::CrngProvider for OstdPlatform {
    fn fill_bytes_crng(&self, _buf: &mut [u8]) {
        todo!()
    }
}

impl litebox::platform::ThreadProvider for OstdPlatform {
    type ExecutionContext = litebox_common_linux::PtRegs;

    type ThreadSpawnError = litebox_common_linux::errno::Errno;

    type ThreadHandle = ThreadHandle;

    unsafe fn spawn_thread(
        &self,
        ctx: &Self::ExecutionContext,
        init_thread: alloc::boxed::Box<dyn litebox::shim::InitThread>,
    ) -> Result<(), Self::ThreadSpawnError> {
        let mut user_ctx = ostd::arch::cpu::context::UserContext::default();

        user_ctx.set_rax(ctx.rax);
        user_ctx.set_rbx(ctx.rbx);
        user_ctx.set_rcx(ctx.rcx);
        user_ctx.set_rdx(ctx.rdx);
        user_ctx.set_rsi(ctx.rsi);
        user_ctx.set_rdi(ctx.rdi);
        user_ctx.set_rbp(ctx.rbp);
        user_ctx.set_rsp(ctx.rsp);
        user_ctx.set_r8(ctx.r8);
        user_ctx.set_r9(ctx.r9);
        user_ctx.set_r10(ctx.r10);
        user_ctx.set_r11(ctx.r11);
        user_ctx.set_r12(ctx.r12);
        user_ctx.set_r13(ctx.r13);
        user_ctx.set_r14(ctx.r14);
        user_ctx.set_r15(ctx.r15);
        user_ctx.set_rip(ctx.rip);
        user_ctx.set_rflags(ctx.eflags);

        let task_result = ostd::task::TaskOptions::new(move || {
            init_thread.init();
        })
        .spawn();

        match task_result {
            Ok(_task) => Ok(()),
            Err(_) => Err(litebox_common_linux::errno::Errno::EAGAIN),
        }
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        let current_task =
            ostd::task::Task::current().expect("current_thread called outside of a task context");
        ThreadHandle {
            task: current_task.cloned(),
        }
    }

    fn interrupt_thread(&self, _thread: &Self::ThreadHandle) {
        // TODO: Implement thread interruption
        todo!()
    }
}

pub struct ThreadHandle {
    task: alloc::sync::Arc<ostd::task::Task>,
}
