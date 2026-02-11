// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An implementation of [`HostInterface`] for SNP VMM
use ::alloc::{boxed::Box, ffi::CString, vec::Vec};
use core::{
    arch::asm,
    cell::{Cell, OnceCell},
    sync::atomic::{AtomicU32, Ordering},
};

use litebox::utils::ReinterpretUnsignedExt as _;
use litebox_common_linux::CloneFlags;

use super::ghcb::ghcb_prints;
use crate::{Errno, HostInterface};

/// Counter for active guest threads. Starts at 1 for the main thread.
static ACTIVE_THREAD_COUNT: AtomicU32 = AtomicU32::new(1);

/// Returns true if all guest threads have exited.
pub fn all_threads_exited() -> bool {
    ACTIVE_THREAD_COUNT.load(Ordering::Acquire) == 0
}

#[expect(dead_code, reason = "bindings are generated from C header files")]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use bindings::vmpl2_boot_params;

pub type SnpLinuxKernel = crate::LinuxKernel<HostSnpInterface>;

const MAX_ARGS_SIZE: usize = 6;
type ArgsArray = [u64; MAX_ARGS_SIZE];

#[cfg(not(test))]
mod alloc {
    use crate::HostInterface;
    use crate::mm::MemoryProvider;
    use litebox::utils::TruncateExt as _;

    const HEAP_ORDER: usize = super::bindings::SNP_VMPL_ALLOC_MAX_ORDER as usize + 12 + 1;
    const PGDIR_SHIFT: u64 = 39;
    const LINUX_PAGE_OFFSET: u64 = 0xffff888000000000;
    const LITEBOX_PAGE_OFFSET: u64 = LINUX_PAGE_OFFSET + (1 << PGDIR_SHIFT);

    #[global_allocator]
    static SNP_ALLOCATOR: litebox::mm::allocator::SafeZoneAllocator<
        'static,
        HEAP_ORDER,
        super::SnpLinuxKernel,
    > = litebox::mm::allocator::SafeZoneAllocator::new();

    impl litebox::mm::allocator::MemoryProvider for super::SnpLinuxKernel {
        fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)> {
            super::HostSnpInterface::alloc(layout).map(|(addr, size)| {
                (
                    Self::pa_to_va(crate::arch::PhysAddr::new_truncate(addr as u64))
                        .as_u64()
                        .truncate(),
                    size,
                )
            })
        }

        unsafe fn free(addr: usize) {
            unsafe { super::HostSnpInterface::free(addr) }
        }
    }

    impl crate::mm::MemoryProvider for super::SnpLinuxKernel {
        const GVA_OFFSET: crate::arch::VirtAddr = crate::arch::VirtAddr::new(LITEBOX_PAGE_OFFSET);
        const PRIVATE_PTE_MASK: u64 = 1 << 51; // SNP encryption bit

        fn mem_allocate_pages(order: u32) -> Option<*mut u8> {
            SNP_ALLOCATOR.allocate_pages(order)
        }

        unsafe fn mem_free_pages(ptr: *mut u8, order: u32) {
            unsafe { SNP_ALLOCATOR.free_pages(ptr, order) }
        }
    }
}

/// Get the current task
fn current() -> Option<&'static mut bindings::vsbox_task> {
    let task: u64;
    unsafe {
        asm!("rdgsbase {}", out(reg) task, options(nostack, preserves_flags));

        let addr = crate::arch::VirtAddr::new(task);
        if addr.is_null() {
            return None;
        }

        Some(&mut *addr.as_mut_ptr())
    }
}

impl SnpLinuxKernel {
    pub fn init_task(
        &self,
        boot_params: &bindings::vmpl2_boot_params,
    ) -> litebox_common_linux::TaskParams {
        litebox_common_linux::TaskParams {
            pid: boot_params.pid,
            ppid: boot_params.ppid,
            uid: boot_params.uid,
            gid: boot_params.gid,
            euid: boot_params.euid,
            egid: boot_params.egid,
        }
    }
}

unsafe impl litebox::platform::ThreadLocalStorageProvider for SnpLinuxKernel {
    fn get_thread_local_storage() -> *mut () {
        let tls = get_tls();
        unsafe { (*tls).shim_tls.get() }
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        let tls = get_tls();
        unsafe { (*tls).shim_tls.replace(value) }
    }
}

core::arch::global_asm!(include_str!("entry.S"));

struct ThreadStartArgs {
    ctx: litebox_common_linux::PtRegs,
    init_thread:
        Box<dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>>,
}

struct ThreadState {
    shim: OnceCell<
        Box<dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>>,
    >,
    shim_tls: Cell<*mut ()>,
}

/// Callback function for a new thread
///
/// This is called by `sandbox_process_ret_from_fork` from `entry.S`.
/// Arguments should be set up by host.
#[unsafe(no_mangle)]
extern "C" fn thread_start(
    regs: &mut litebox_common_linux::PtRegs,
    thread_start_args: Box<ThreadStartArgs>,
) -> ! {
    ACTIVE_THREAD_COUNT.fetch_add(1, Ordering::Relaxed);

    *regs = thread_start_args.ctx;

    // Set up thread-local storage for the new thread. This is done by
    // calling the actual thread callback with the unpacked arguments
    let shim = thread_start_args.init_thread.init();
    unsafe { run_thread(shim, regs) }
}

fn get_tls() -> *const ThreadState {
    let tls = current().unwrap().tls;
    if !tls.is_null() {
        return tls.cast();
    }
    let tls = Box::new(ThreadState {
        shim: OnceCell::new(),
        shim_tls: Cell::new(core::ptr::null_mut()),
    });
    let tls = Box::into_raw(tls);
    current().unwrap().tls = tls.cast();
    tls
}

/// Runs a guest thread using the provided shim and the given initial context.
///
/// # Panics
///
/// Panics if `shim` has been set in the TLS.
///
/// # Safety
///
/// The context must be valid guest context.
pub unsafe fn run_thread(
    shim: Box<dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>>,
    regs: &mut litebox_common_linux::PtRegs,
) -> ! {
    let tls = unsafe { &*get_tls() };
    tls.shim
        .set(shim)
        .ok()
        .expect("thread shim should not be initialized twice");

    let shim = tls.shim.get().unwrap().as_ref();
    match shim.init(regs) {
        litebox::shim::ContinueOperation::ResumeGuest => unsafe { crate::switch_to_guest(regs) },
        litebox::shim::ContinueOperation::ExitThread => exit_thread(),
    }
}

fn exit_thread() -> ! {
    ACTIVE_THREAD_COUNT.fetch_sub(1, Ordering::Release);

    let tls = current().unwrap().tls.cast::<ThreadState>();
    if !tls.is_null() {
        let tls = unsafe { Box::from_raw(tls) };
        drop(tls);
    }
    let r = HostSnpInterface::syscalls(SyscallN::<1, NR_SYSCALL_EXIT> { args: [0] });
    unreachable!("thread has exited: {:?}", r);
}

/// Handles a syscall from the guest.
///
/// # Panics
///
/// Panics if the thread shim has not been initialized with [`run_thread`].
pub fn handle_syscall(pt_regs: &mut litebox_common_linux::PtRegs) -> ! {
    let tls = unsafe { &*get_tls() };
    match tls.shim.get().unwrap().syscall(pt_regs) {
        litebox::shim::ContinueOperation::ResumeGuest => unsafe { crate::switch_to_guest(pt_regs) },
        litebox::shim::ContinueOperation::ExitThread => exit_thread(),
    }
}

impl litebox::platform::ThreadProvider for SnpLinuxKernel {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = litebox_common_linux::errno::Errno;
    type ThreadHandle = u32;

    unsafe fn spawn_thread(
        &self,
        ctx: &Self::ExecutionContext,
        init_thread: Box<
            dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
        >,
    ) -> Result<(), Self::ThreadSpawnError> {
        let flags = CloneFlags::THREAD
            | CloneFlags::VM
            | CloneFlags::FS
            | CloneFlags::FILES
            | CloneFlags::SIGHAND
            | CloneFlags::SYSVSEM
            | CloneFlags::CHILD_SETTID;
        let thread_start_args = Box::new(ThreadStartArgs {
            ctx: ctx.clone(),
            init_thread,
        });
        let thread_start_arg_ptr = Box::into_raw(thread_start_args);
        // Note this is different from the usual clone3 syscall as we have a driver running
        // in VMPL0's kernel and handling the syscall differently.
        // The first argument will be placed into the new thread's RSI register (i.e. the second argument).
        HostSnpInterface::syscalls(SyscallN::<2, NR_SYSCALL_CLONE3> {
            args: [thread_start_arg_ptr as u64, flags.bits()],
        })?;
        Ok(())
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        current().unwrap().pid
    }

    fn interrupt_thread(&self, tid: &Self::ThreadHandle) {
        let _ = HostSnpInterface::interrupt(*tid);
    }
}

impl bindings::SnpVmplRequestArgs {
    #[inline]
    fn new_request(code: u32, size: u32, args: ArgsArray) -> Self {
        bindings::SnpVmplRequestArgs {
            code,
            status: bindings::SNP_VMPL_REQ_INCOMPLETE,
            size,
            padding: 0,
            args,
            ret: 0,
        }
    }

    pub fn new_exit_request() -> Self {
        bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_EXIT_REQ,
            0,
            ArgsArray::default(),
        )
    }
}

pub struct HostSnpInterface;

const HVCALL_VTL_CALL: u16 = 0x0011;
const MAX_ERRNO: u64 = 4095;
#[inline]
const fn is_err_value(x: u64) -> bool {
    x >= !MAX_ERRNO
}

const PAGE_SIZE: u64 = litebox::mm::linux::PAGE_SIZE as u64;
/// Max physical address
const PHYS_ADDR_MAX: u64 = 0x10_0000_0000u64; // 64GB

const NR_SYSCALL_FUTEX: u32 = 202;
const NR_SYSCALL_READ: u32 = 0;
const NR_SYSCALL_WRITE: u32 = 1;
#[allow(dead_code)]
const NR_SYSCALL_EXIT: u32 = 60;
const NR_SYSCALL_EXIT_GROUP: u32 = 231;
const NR_SYSCALL_CLONE3: u32 = 435;

const FUTEX_WAIT: i32 = 0;
const FUTEX_WAKE: i32 = 1;

/// Punchthrough for syscalls
///
/// The generic parameter `N` is the number of arguments for the syscall
/// The generic parameter `ID` is the syscall number
pub struct SyscallN<const N: usize, const ID: u32> {
    /// Arguments for the syscall
    args: [u64; N],
}

/// Page-aligned buffer for reading file chunks from host
#[repr(C, align(4096))]
struct PageAlignedBuffer([u8; 4096]);

/// Maximum file size that can be loaded (4MB)
/// This is limited by the maximum contiguous memory allocation size.
const MAX_FILE_SIZE: u64 = PAGE_SIZE << bindings::SNP_VMPL_ALLOC_MAX_ORDER;

impl HostSnpInterface {
    #[cfg(debug_assertions)]
    pub fn dump_stack(rsp: usize, count: usize) {
        let mut req = bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_PRINT_REQ,
            3,
            [
                u64::from(bindings::SNP_VMPL_PRINT_STACK),
                rsp as u64,
                count as u64,
                0,
                0,
                0,
            ],
        );
        Self::request(&mut req);
    }

    /// Load a file from host by path
    ///
    /// Note that the maximum file size is limited to 4MB.
    pub fn load_file_from_host(path: &str) -> Result<Vec<u8>, Errno> {
        const CHUNK_SIZE: usize = 4096;
        let mut result = Vec::new();
        let mut offset = 0u64;

        // Host only accept heap or stack memory with null-terminated string
        let path = CString::new(path).map_err(|_| Errno::EINVAL)?;
        let mut chunk_buffer = Box::new(PageAlignedBuffer([0u8; CHUNK_SIZE]));
        loop {
            let bytes_read = Self::load_file(&path, &mut chunk_buffer.0, offset)?;
            debug_assert!(bytes_read <= CHUNK_SIZE);

            if bytes_read == 0 {
                // End of file reached
                break;
            }

            offset += bytes_read as u64;

            // Check if file exceeds maximum size
            if offset > MAX_FILE_SIZE {
                return Err(Errno::EFBIG); // File too large
            }

            result.extend_from_slice(&chunk_buffer.0[..bytes_read]);

            // If we read less than the chunk size, we've reached the end of the file
            if bytes_read < CHUNK_SIZE {
                break;
            }
        }

        result.shrink_to_fit();
        Ok(result)
    }

    /// [VTL CALL](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm#vtl-call) via VMMCALL
    fn request(arg: &mut bindings::SnpVmplRequestArgs) {
        unsafe {
            asm!("vmmcall",
                in("rcx") HVCALL_VTL_CALL,
                in("r14") core::ptr::from_ref(arg) as u64,
            );
        }
    }

    fn syscalls<const N: usize, const ID: u32>(arg: SyscallN<N, ID>) -> Result<usize, Errno> {
        let mut args = [0; MAX_ARGS_SIZE];
        args[..N].copy_from_slice(&arg.args);
        let mut req = bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_SYSCALL_REQ,
            ID, // repurpose size field to syscall id
            args,
        );
        Self::request(&mut req);
        Self::parse_result(req.ret)
    }

    fn interrupt(tid: u32) -> Result<(), Errno> {
        let mut req = bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_SEND_INTERRUPT_REQ,
            1, // number of arguments
            [u64::from(tid), 0, 0, 0, 0, 0],
        );
        Self::request(&mut req);
        Self::parse_result(req.ret).map(|_| ())
    }

    /// Load a file from host by path
    ///
    /// The host provides files at fixed, predetermined locations identified by path.
    ///
    /// # Parameters
    /// - `path`: Path of the file to load
    /// - `buffer`: Buffer to store the file content (must be page-aligned, max 4KB)
    /// - `offset`: Byte offset in the file to start reading from
    ///
    /// # Returns
    /// The number of bytes read on success, or an error
    fn load_file(path: &CString, buffer: &mut [u8], offset: u64) -> Result<usize, Errno> {
        let path_bytes = path.as_bytes_with_nul();
        let mut req = bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_LOAD_FILE_REQ,
            4, // number of arguments
            [
                path_bytes.as_ptr() as u64,
                buffer.as_mut_ptr() as u64,
                buffer.len() as u64,
                offset,
                0,
                0,
            ],
        );
        Self::request(&mut req);
        Self::parse_result(req.ret)
    }

    fn parse_result(res: u64) -> Result<usize, Errno> {
        const ERESTARTSYS: i64 = 512;
        const ERESTARTNOHAND: i64 = 514;
        const ERESTART_RESTARTBLOCK: i64 = 516;

        if is_err_value(res) {
            #[expect(clippy::cast_possible_wrap)]
            let v = res as i64;
            // ERESTARTSYS and other restart codes are kernel-internal and should
            // be converted to EINTR when returned back.
            let errno = match v.abs() {
                ERESTARTSYS | ERESTARTNOHAND | ERESTART_RESTARTBLOCK => Errno::EINTR,
                e => Errno::try_from(i32::try_from(e).unwrap()).unwrap(),
            };
            Err(errno)
        } else {
            Ok(usize::try_from(res).unwrap())
        }
    }

    fn parse_alloc_result(order: u32, addr: u64) -> Result<usize, Errno> {
        if addr == 0 {
            if order > bindings::SNP_VMPL_ALLOC_MAX_ORDER {
                Err(Errno::EINVAL)
            } else {
                Err(Errno::ENOMEM)
            }
        } else if !addr.is_multiple_of(PAGE_SIZE << order)
            || addr > PHYS_ADDR_MAX - (PAGE_SIZE << order)
        {
            // Address is not aligned or out of bounds
            Err(Errno::EINVAL)
        } else {
            Ok(usize::try_from(addr).unwrap())
        }
    }
}

impl HostInterface for HostSnpInterface {
    fn send_ip_packet(packet: &[u8]) -> Result<usize, Errno> {
        let mut req = bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_TUN_WRITE_REQ,
            3,
            [packet.as_ptr() as u64, packet.len() as u64, 0, 0, 0, 0],
        );
        Self::request(&mut req);
        Self::parse_result(req.ret)
    }

    fn receive_ip_packet(packet: &mut [u8]) -> Result<usize, Errno> {
        let mut req = bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_TUN_READ_REQ,
            3,
            [packet.as_ptr() as u64, packet.len() as u64, 0, 0, 0, 0],
        );
        Self::request(&mut req);
        Self::parse_result(req.ret)
    }

    fn log(msg: &str) {
        ghcb_prints(msg);
    }

    fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        // To reduce the number of hypercalls, we allocate the maximum order.
        // Assertion is added to prevent the allocation size from exceeding the maximum order.
        let size = core::cmp::max(
            layout.size().next_power_of_two(),
            usize::try_from(PAGE_SIZE).unwrap(),
        );
        assert!(size <= usize::try_from(PAGE_SIZE << bindings::SNP_VMPL_ALLOC_MAX_ORDER).unwrap());

        let mut req = bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_ALLOC_REQ,
            1,
            [u64::from(bindings::SNP_VMPL_ALLOC_MAX_ORDER), 0, 0, 0, 0, 0],
        );
        Self::request(&mut req);
        match Self::parse_alloc_result(bindings::SNP_VMPL_ALLOC_MAX_ORDER, req.ret) {
            Ok(addr) => Some((
                addr,
                usize::try_from(PAGE_SIZE << bindings::SNP_VMPL_ALLOC_MAX_ORDER).unwrap(),
            )),
            Err(Errno::ENOMEM) => None,
            Err(e) => unimplemented!("Unexpected error: {}", e),
        }
    }

    unsafe fn free(_addr: usize) {
        unimplemented!()
    }

    fn return_to_host() -> ! {
        let mut req = bindings::SnpVmplRequestArgs::new_exit_request();
        Self::request(&mut req);
        unreachable!("Should not return to the caller after returning to host");
    }

    fn terminate(reason_set: u64, reason_code: u64) -> ! {
        let mut req = bindings::SnpVmplRequestArgs::new_request(
            bindings::SNP_VMPL_TERMINATE_REQ,
            2,
            [reason_set, reason_code, 0, 0, 0, 0],
        );
        Self::request(&mut req);

        // In case hypervisor fails to terminate it or intentionally reschedules it,
        // halt the CPU to prevent further execution
        unreachable!("Should not return to the caller after terminating the vm");
    }

    fn wake_many(mutex: &core::sync::atomic::AtomicU32, n: usize) -> Result<usize, Errno> {
        Self::syscalls(SyscallN::<6, NR_SYSCALL_FUTEX> {
            args: [mutex.as_ptr() as u64, FUTEX_WAKE as u64, n as u64, 0, 0, 0],
        })
    }

    fn block_or_maybe_timeout(
        mutex: &core::sync::atomic::AtomicU32,
        val: u32,
        timeout: Option<core::time::Duration>,
    ) -> Result<(), Errno> {
        let timeout = timeout.map(|t| litebox_common_linux::Timespec {
            tv_sec: i64::try_from(t.as_secs()).unwrap(),
            tv_nsec: u64::from(t.subsec_nanos()),
        });
        Self::syscalls(SyscallN::<6, NR_SYSCALL_FUTEX> {
            args: [
                mutex.as_ptr() as u64,
                FUTEX_WAIT as u64,
                u64::from(val),
                timeout
                    .as_ref()
                    .map_or(0, |t| core::ptr::from_ref(t) as u64),
                0,
                0,
            ],
        })
        .map(|_| ())
    }

    fn read_from_stdin(buf: &mut [u8]) -> Result<usize, Errno> {
        Self::syscalls(SyscallN::<3, NR_SYSCALL_READ> {
            args: [
                litebox_common_linux::STDIN_FILENO as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
            ],
        })
    }

    fn write_to(stream: litebox::platform::StdioOutStream, buf: &[u8]) -> Result<usize, Errno> {
        Self::syscalls(SyscallN::<3, NR_SYSCALL_WRITE> {
            args: [
                u64::from(
                    match stream {
                        litebox::platform::StdioOutStream::Stdout => {
                            litebox_common_linux::STDOUT_FILENO
                        }
                        litebox::platform::StdioOutStream::Stderr => {
                            litebox_common_linux::STDERR_FILENO
                        }
                    }
                    .reinterpret_as_unsigned(),
                ),
                buf.as_ptr() as u64,
                buf.len() as u64,
            ],
        })
    }

    fn terminate_process(code: i32) -> ! {
        let _ = Self::syscalls(SyscallN::<1, NR_SYSCALL_EXIT_GROUP> {
            args: [u64::from(code.reinterpret_as_unsigned())],
        });
        unreachable!("Should not return to the caller after terminating the process");
    }
}

impl litebox::platform::CrngProvider for SnpLinuxKernel {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        // FIXME: call into the trusted host to get random bytes.
        static RANDOM: spin::mutex::SpinMutex<litebox::utils::rng::FastRng> =
            spin::mutex::SpinMutex::new(litebox::utils::rng::FastRng::new_from_seed(
                core::num::NonZeroU64::new(0x4d595df4d0f33173).unwrap(),
            ));
        let mut random = RANDOM.lock();
        for b in buf.chunks_mut(8) {
            b.copy_from_slice(&random.next_u64().to_ne_bytes()[..b.len()]);
        }
    }
}
