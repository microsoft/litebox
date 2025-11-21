#![no_std]

use litebox::platform::common_providers::userspace_pointers::{UserConstPtr, UserMutPtr};
use ostd::arch::cpu::context::UserContext;
use ostd::user::UserContextApi;

extern crate alloc;

macro_rules! debug {
    ($($arg:tt)*) => {
        ostd::console::early_print(format_args!($($arg)*));
    };
}

pub struct OstdPlatform {
    vm_space: alloc::sync::Arc<ostd::mm::VmSpace>,
}

static SHIM: spin::Once<
    &'static dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
> = spin::Once::new();

impl core::fmt::Debug for OstdPlatform {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OstdPlatform").finish_non_exhaustive()
    }
}

impl OstdPlatform {
    pub fn new() -> OstdPlatform {
        OstdPlatform {
            vm_space: alloc::sync::Arc::new(ostd::mm::VmSpace::new()),
        }
    }

    // XXX: We prob should not be exposing this directly like this, but this is a quick workaround.
    pub fn activate_vm_space(&self) {
        self.vm_space.activate();
    }

    pub fn register_shim(
        &self,
        shim: &'static dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ) {
        if SHIM.is_completed() {
            panic!("should not register more than one shim");
        }
        SHIM.call_once(|| shim);
    }
}

impl litebox::platform::Provider for OstdPlatform {}

impl litebox::platform::RawPointerProvider for OstdPlatform {
    type RawConstPointer<T: Clone> = UserConstPtr<T>;
    type RawMutPointer<T: Clone> = UserMutPtr<T>;
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
            litebox_common_linux::PunchthroughSyscall::SetFsBase { addr } => {
                unsafe { litebox_common_linux::wrfsbase(addr) };
                Ok(0)
            }
            #[cfg(target_arch = "x86_64")]
            litebox_common_linux::PunchthroughSyscall::GetFsBase { addr } => {
                use litebox::platform::RawMutPointer as _;
                let fs_base = unsafe { litebox_common_linux::rdfsbase() };
                unsafe { addr.write_at_offset(0, fs_base) }
                    .map(|()| 0)
                    .ok_or(litebox::platform::PunchthroughError::Failure(
                        litebox_common_linux::errno::Errno::EFAULT,
                    ))
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
        suggested_range: core::ops::Range<usize>,
        initial_permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
        _can_grow_down: bool,
        populate_pages_immediately: bool,
        _fixed_address_behavior: litebox::platform::page_mgmt::FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        use litebox::platform::page_mgmt::AllocationError;
        use ostd::mm::{CachePolicy, FrameAllocOptions, PageProperty};

        debug!(
            "[allocate_pages] range={:#x}..{:#x}, populate={}\n",
            suggested_range.start, suggested_range.end, populate_pages_immediately
        );

        let vm_space = &self.vm_space;
        debug!("[allocate_pages] Got VmSpace\n");

        let size = suggested_range.end.saturating_sub(suggested_range.start);
        if size == 0 {
            debug!("[allocate_pages] ERROR: Size is 0\n");
            return Err(AllocationError::InvalidRange);
        }
        let num_pages = (size + 4095) / 4096;
        debug!(
            "[allocate_pages] Allocating {} pages (size={:#x})\n",
            num_pages, size
        );

        let segment = if populate_pages_immediately {
            FrameAllocOptions::new()
                .zeroed(true)
                .alloc_segment(num_pages)
        } else {
            FrameAllocOptions::new().alloc_segment(num_pages)
        }
        .map_err(|_e| {
            debug!(
                "[allocate_pages] ERROR: Failed to allocate segment: {:?}\n",
                _e
            );
            AllocationError::OutOfMemory
        })?;
        debug!("[allocate_pages] Allocated segment\n");

        let flags = convert_permissions_to_flags(initial_permissions);
        let page_prop = PageProperty::new_user(flags, CachePolicy::Writeback);

        debug!("[allocate_pages] Creating cursor\n");
        let guard = ostd::task::disable_preempt();
        let mut cursor = vm_space
            .cursor_mut(&guard, &suggested_range)
            .map_err(|_e| {
                debug!(
                    "[allocate_pages] ERROR: Failed to create cursor: {:?}\n",
                    _e
                );
                AllocationError::OutOfMemory
            })?;
        debug!("[allocate_pages] Mapping frames\n");

        for frame in segment.into_iter() {
            cursor.map(frame.into(), page_prop);
        }
        debug!("[allocate_pages] All frames mapped\n");

        debug!("[allocate_pages] Flushing TLB\n");
        cursor
            .flusher()
            .issue_tlb_flush(ostd::mm::tlb::TlbFlushOp::for_range(
                suggested_range.clone(),
            ));

        debug!("[allocate_pages] Success\n");
        use litebox::platform::RawConstPointer;
        Ok(UserMutPtr::from_usize(suggested_range.start))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        use litebox::platform::page_mgmt::DeallocationError;

        debug!(
            "[deallocate_pages] range={:#x}..{:#x}\n",
            range.start, range.end
        );

        let vm_space = &self.vm_space;

        let size = range.end.saturating_sub(range.start);
        if size == 0 || size % 4096 != 0 {
            debug!("[deallocate_pages] ERROR: Invalid size {:#x}\n", size);
            return Err(DeallocationError::Unaligned);
        }
        let num_pages = size / 4096;
        debug!("[deallocate_pages] Unmapping {} pages\n", num_pages);

        let guard = ostd::task::disable_preempt();
        let mut cursor = vm_space
            .cursor_mut(&guard, &range)
            .map_err(|_| DeallocationError::Unaligned)?;

        let unmapped = cursor.unmap(num_pages);
        if unmapped != num_pages {
            debug!(
                "[deallocate_pages] ERROR: Only unmapped {} of {} pages\n",
                unmapped, num_pages
            );
            return Err(DeallocationError::AlreadyUnallocated);
        }

        cursor
            .flusher()
            .issue_tlb_flush(ostd::mm::tlb::TlbFlushOp::for_range(range));

        debug!("[deallocate_pages] Success\n");
        Ok(())
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: litebox::platform::page_mgmt::MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        use litebox::platform::page_mgmt::PermissionUpdateError;

        debug!(
            "[update_permissions] range={:#x}..{:#x}, perms={:?}\n",
            range.start, range.end, new_permissions
        );

        let vm_space = &self.vm_space;

        let size = range.end.saturating_sub(range.start);
        if size == 0 || size % 4096 != 0 {
            debug!("[update_permissions] ERROR: Invalid size {:#x}\n", size);
            return Err(PermissionUpdateError::Unaligned);
        }
        let num_pages = size / 4096;
        debug!("[update_permissions] Updating {} pages\n", num_pages);

        let new_flags = convert_permissions_to_flags(new_permissions);

        let guard = ostd::task::disable_preempt();
        let mut cursor = vm_space
            .cursor_mut(&guard, &range)
            .map_err(|_| PermissionUpdateError::Unaligned)?;

        debug!("[update_permissions] Protecting pages with new flags\n");
        let mut remaining_size = size;
        while remaining_size > 0 {
            match cursor.protect_next(remaining_size, |flags, _cache_policy| {
                *flags = new_flags;
            }) {
                Some(protected_range) => {
                    let protected_size = protected_range.end - protected_range.start;
                    remaining_size = remaining_size.saturating_sub(protected_size);
                }
                None => {
                    debug!("[update_permissions] ERROR: No more mapped pages to protect\n");
                    return Err(PermissionUpdateError::Unallocated);
                }
            }
        }

        debug!("[update_permissions] Flushing TLB\n");
        cursor
            .flusher()
            .issue_tlb_flush(ostd::mm::tlb::TlbFlushOp::for_range(range));

        debug!("[update_permissions] Success\n");
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        // TODO: Query the VmSpace or system for reserved ranges
        core::iter::empty()
    }
}

fn convert_permissions_to_flags(
    perms: litebox::platform::page_mgmt::MemoryRegionPermissions,
) -> ostd::mm::PageFlags {
    use litebox::platform::page_mgmt::MemoryRegionPermissions;
    use ostd::mm::PageFlags;

    let mut flags = PageFlags::empty();
    if perms.contains(MemoryRegionPermissions::READ) {
        flags |= PageFlags::R;
    }
    if perms.contains(MemoryRegionPermissions::WRITE) {
        flags |= PageFlags::W;
    }
    if perms.contains(MemoryRegionPermissions::EXEC) {
        flags |= PageFlags::X;
    }
    flags
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
        let mut user_ctx = UserContext::default();

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
    #[expect(dead_code)]
    task: alloc::sync::Arc<ostd::task::Task>,
}

pub fn run_thread(pt_regs: &mut litebox_common_linux::PtRegs) {
    let pt_regs = *pt_regs;
    debug!("[run_thread] setting up task\n");
    let task = alloc::sync::Arc::new(
        ostd::task::TaskOptions::new(move || {
            unsafe { run_thread_inner(pt_regs) };
        })
        .build()
        .unwrap(),
    );
    debug!("[run_thread] running task\n");
    task.run();
    // XXX: Weird that we need this
    ostd::task::Task::yield_now();
}

unsafe fn run_thread_inner(mut pt_regs: litebox_common_linux::PtRegs) {
    debug!("[run_thread] begin\n");
    let pt_regs = &mut pt_regs;
    let mut user_context = UserContext::default();

    copy_pt_to_uc(&mut user_context, pt_regs);

    let mut user_mode = ostd::user::UserMode::new(user_context);

    loop {
        debug!("[run_thread] switch to user mode\n");
        let return_reason = user_mode.execute(|| false);

        debug!("[run_thread] returned due to {return_reason:?}\n");
        match return_reason {
            ostd::user::ReturnReason::UserSyscall => {
                let user_context = user_mode.context_mut();
                copy_uc_to_pt(&user_context, pt_regs);
                debug!(
                    "[run_thread] ... start with rax={} orig_rax={}\n",
                    pt_regs.rax, pt_regs.orig_rax
                );
                match SHIM
                    .get()
                    .expect("shim must have been registered")
                    .syscall(pt_regs)
                {
                    litebox::shim::ContinueOperation::ResumeGuest => {
                        debug!(
                            "[run_thread] ...resume with rax={} orig_rax={}\n",
                            pt_regs.rax, pt_regs.orig_rax
                        );
                        copy_pt_to_uc(user_context, pt_regs);
                    }
                    litebox::shim::ContinueOperation::ExitThread => {
                        ostd::console::early_print(format_args!("Program exited\n"));
                        break;
                    }
                }
            }
            ostd::user::ReturnReason::UserException => {
                let user_context = user_mode.context();

                debug!("\n\n=== UserException Debug Dump ===\n");
                debug!("Trap Number: {:#x}\n", user_context.trap_number());
                debug!("Trap Error Code: {:#x}\n", user_context.trap_error_code());
                debug!(
                    "Instruction Pointer (RIP): {:#x}\n",
                    user_context.instruction_pointer()
                );
                debug!("Stack Pointer (RSP): {:#x}\n", user_context.stack_pointer());

                debug!("\nCPU Register State:\n");
                #[cfg(target_arch = "x86_64")]
                {
                    debug!(
                        "  RAX: {:#018x}  RBX: {:#018x}  RCX: {:#018x}  RDX: {:#018x}\n",
                        user_context.rax(),
                        user_context.rbx(),
                        user_context.rcx(),
                        user_context.rdx()
                    );
                    debug!(
                        "  RSI: {:#018x}  RDI: {:#018x}  RBP: {:#018x}  RSP: {:#018x}\n",
                        user_context.rsi(),
                        user_context.rdi(),
                        user_context.rbp(),
                        user_context.rsp()
                    );
                    debug!(
                        "  R8:  {:#018x}  R9:  {:#018x}  R10: {:#018x}  R11: {:#018x}\n",
                        user_context.r8(),
                        user_context.r9(),
                        user_context.r10(),
                        user_context.r11()
                    );
                    debug!(
                        "  R12: {:#018x}  R13: {:#018x}  R14: {:#018x}  R15: {:#018x}\n",
                        user_context.r12(),
                        user_context.r13(),
                        user_context.r14(),
                        user_context.r15()
                    );
                    debug!("  RIP: {:#018x}\n", user_context.rip());
                }

                debug!("================================\n\n\n");

                ostd::console::early_print(format_args!(
                    "TODO: Unhandled user exception: {:?}\n",
                    return_reason
                ));

                ostd::arch::qemu::exit_qemu(ostd::arch::qemu::QemuExitCode::Failed);
            }
            ostd::user::ReturnReason::KernelEvent => {
                ostd::console::early_print(format_args!(
                    "TODO: Unhandled return reason: {:?}\n",
                    return_reason
                ));
                break;
            }
        }
    }
}

fn copy_uc_to_pt(user_context: &UserContext, pt_regs: &mut litebox_common_linux::PtRegs) {
    // Convert UserContext to PtRegs for the shim
    macro_rules! cp {
        ($($r:ident),*) => { $(pt_regs.$r = user_context.$r();)* };
    }
    #[cfg(target_arch = "x86_64")]
    cp!(
        rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8, r9, r10, r11, r12, r13, r14, r15, rip
    );
    pt_regs.orig_rax = pt_regs.rax;
}

fn copy_pt_to_uc(user_context: &mut UserContext, pt_regs: &litebox_common_linux::PtRegs) {
    // Copy results back to user context
    macro_rules! cp {
        ($($r:ident),*) => { $(user_context.general_regs_mut().$r = pt_regs.$r;)* };
    }
    #[cfg(target_arch = "x86_64")]
    cp!(
        rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8, r9, r10, r11, r12, r13, r14, r15, rip
    );
}
