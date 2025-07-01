//! No-std mock platform for easily running tests on no_std targets.

#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};
use alloc::{boxed::Box, vec::Vec};
use syscalls::{syscall, Sysno};

use litebox::fs::OFlags;
use litebox::platform::*;
use litebox::platform::page_mgmt::MemoryRegionPermissions;
use litebox::utils::ReinterpretUnsignedExt as _;
use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, PunchthroughSyscall};

mod syscall_intercept;

extern crate alloc;

/// A no_std mock platform that is a [`platform::Provider`](Provider), useful for testing on no_std targets.
///
/// This is a simplified version of MockPlatform that doesn't rely on std features:
///
/// - Full determinism with simple time tracking
/// - No dynamic memory allocation for IP packets or stdio queues
/// - Minimal implementation suitable for no_std environments
/// - Uses simple counters and fixed buffers instead of dynamic collections
/// - Debug output uses syscalls directly (no eprintln! available in no_std)
pub struct MockNoStdPlatform {
    current_time: AtomicU64,
    reserved_pages: Vec<core::ops::Range<usize>>,
}

impl MockNoStdPlatform {
    pub fn new(_name: Option<&'static str>) -> &'static Self {
        // static INSTANCE: MockNoStdPlatform = MockNoStdPlatform {
        //     current_time: AtomicU64::new(0),
        // };
        // &INSTANCE
        Box::leak(Box::new(Self {
            current_time: AtomicU64::new(0),
            reserved_pages: Self::read_proc_self_maps(),
        }))
    }

    fn read_proc_self_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
        // TODO: this function is not guaranteed to return all allocated pages, as it may
        // allocate more pages after the mapping file is read. Missing allocated pages may
        // cause the program to crash when calling `mmap` or `mremap` with the `MAP_FIXED` flag later.
        // We should either fix `mmap` to handle this error, or let global allocator call this function
        // whenever it get more pages from the host.
        let path = "/proc/self/maps";
        let fd = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::open,
                path.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };
        let Ok(fd) = fd else {
            return alloc::vec::Vec::new();
        };
        let mut buf = [0u8; 8192];
        let mut total_read = 0;
        while total_read < buf.len() {
            let n = unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::read,
                    fd,
                    buf.as_mut_ptr() as usize + total_read,
                    buf.len() - total_read,
                )
            }
            .expect("read failed");
            if n == 0 {
                break;
            }
            total_read += n;
        }
        assert!(total_read < buf.len(), "buffer too small");

        let mut reserved_pages = alloc::vec::Vec::new();
        let s = core::str::from_utf8(&buf[..total_read]).expect("invalid UTF-8");
        for line in s.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }
            let range = parts[0].split('-').collect::<Vec<&str>>();
            let start = usize::from_str_radix(range[0], 16).expect("invalid start address");
            let end = usize::from_str_radix(range[1], 16).expect("invalid end address");
            reserved_pages.push(start..end);
        }
        reserved_pages
    }
}

impl Provider for MockNoStdPlatform {}

impl ExitProvider for MockNoStdPlatform {
    type ExitCode = i32;
    const EXIT_SUCCESS: Self::ExitCode = 0;
    const EXIT_FAILURE: Self::ExitCode = 1;
    
    fn exit(&self, _code: Self::ExitCode) -> ! {
        // In a no_std environment, we can't actually exit cleanly
        // This would typically be implemented by the platform-specific exit mechanism
        // For now, just loop indefinitely
        loop {
           core::hint::spin_loop();
        }
    }
}

pub struct MockNoStdRawMutex {
    atomic: core::sync::atomic::AtomicU32,
}

impl RawMutex for MockNoStdRawMutex {
    fn underlying_atomic(&self) -> &core::sync::atomic::AtomicU32 {
        &self.atomic
    }

    fn wake_many(&self, _n: usize) -> usize {
        // No-op implementation for mock
        0
    }

    fn block(&self, _val: u32) -> Result<(), ImmediatelyWokenUp> {
        // No-op implementation for mock - always immediately wake up
        Err(ImmediatelyWokenUp)
    }

    fn block_or_timeout(
        &self,
        _val: u32,
        _time: core::time::Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        // No-op implementation for mock - always immediately wake up
        Err(ImmediatelyWokenUp)
    }
}

impl RawMutexProvider for MockNoStdPlatform {
    type RawMutex = MockNoStdRawMutex;

    fn new_raw_mutex(&self) -> Self::RawMutex {
        MockNoStdRawMutex {
            atomic: core::sync::atomic::AtomicU32::new(0),
        }
    }
}

impl IPInterfaceProvider for MockNoStdPlatform {
    fn send_ip_packet(&self, _packet: &[u8]) -> Result<(), SendError> {
        // No-op implementation for mock
        Ok(())
    }

    fn receive_ip_packet(&self, _packet: &mut [u8]) -> Result<usize, ReceiveError> {
        // No-op implementation for mock - no packets available
        Err(ReceiveError::WouldBlock)
    }
}

pub struct MockNoStdInstant {
    time: u64,
}

impl Instant for MockNoStdInstant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        if earlier.time <= self.time {
            Some(core::time::Duration::from_millis(self.time - earlier.time))
        } else {
            None
        }
    }
}

impl TimeProvider for MockNoStdPlatform {
    type Instant = MockNoStdInstant;

    fn now(&self) -> Self::Instant {
        MockNoStdInstant {
            time: self.current_time.fetch_add(1, Ordering::SeqCst),
        }
    }
}


#[cfg(target_arch = "x86_64")]
const HWCAP2_FSGSBASE: u64 = 1 << 1;

/// Get the current fs base register value.
///
/// Depending on whether `fsgsbase` instructions are enabled, we choose
/// between `arch_prctl` or `rdfsbase` to get the fs base.
#[cfg(target_arch = "x86_64")]
fn get_fs_base() -> Result<usize, litebox_common_linux::errno::Errno> {
    /// Function pointer to get the current fs base.
    get_fs_base_arch_prctl()
}

/// Set the fs base register value.
///
/// Depending on whether `fsgsbase` instructions are enabled, we choose
/// between `arch_prctl` or `wrfsbase` to set the fs base.
#[cfg(target_arch = "x86_64")]
fn set_fs_base(fs_base: usize) -> Result<usize, litebox_common_linux::errno::Errno> {
    set_fs_base_arch_prctl(fs_base)
}

/// Get fs register value via syscall `arch_prctl`.
#[cfg(target_arch = "x86_64")]
fn get_fs_base_arch_prctl() -> Result<usize, litebox_common_linux::errno::Errno> {
    let mut fs_base = core::mem::MaybeUninit::<usize>::uninit();
    unsafe {
        syscalls::syscall3(
            syscalls::Sysno::arch_prctl,
            litebox_common_linux::ArchPrctlCode::GetFs as usize,
            fs_base.as_mut_ptr() as usize,
            // Unused by the syscall but would be checked by Seccomp filter if enabled.
            syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
        )
    }
    .map_err(|err| match err {
        syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
        syscalls::Errno::EPERM => litebox_common_linux::errno::Errno::EPERM,
        _ => unimplemented!("unexpected error {err}"),
    })?;
    Ok(unsafe { fs_base.assume_init() })
}

/// Set fs register value via syscall `arch_prctl`.
#[cfg(target_arch = "x86_64")]
fn set_fs_base_arch_prctl(fs_base: usize) -> Result<usize, litebox_common_linux::errno::Errno> {
    unsafe {
        syscalls::syscall3(
            syscalls::Sysno::arch_prctl,
            litebox_common_linux::ArchPrctlCode::SetFs as usize,
            fs_base,
            // Unused by the syscall but would be checked by Seccomp filter if enabled.
            syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
        )
    }
    .map_err(|err| match err {
        syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
        syscalls::Errno::EPERM => litebox_common_linux::errno::Errno::EPERM,
        _ => unimplemented!("unexpected error {err}"),
    })
}

#[cfg(target_arch = "x86")]
fn set_thread_area(
    user_desc: litebox::platform::trivial_providers::TransparentMutPtr<
        litebox_common_linux::UserDesc,
    >,
) -> Result<usize, litebox_common_linux::errno::Errno> {
    unsafe { syscalls::syscall1(syscalls::Sysno::set_thread_area, user_desc.as_usize()) }.map_err(
        |err| match err {
            syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
            syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
            syscalls::Errno::ENOSYS => litebox_common_linux::errno::Errno::ENOSYS,
            syscalls::Errno::ESRCH => litebox_common_linux::errno::Errno::ESRCH,
            _ => panic!("unexpected error {err}"),
        },
    )
}

pub struct PunchthroughToken {
    punchthrough: PunchthroughSyscall<MockNoStdPlatform>,
}

impl litebox::platform::PunchthroughToken for PunchthroughToken {
    type Punchthrough = PunchthroughSyscall<MockNoStdPlatform>;
    fn execute(
        self,
    ) -> Result<
        <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnSuccess,
        litebox::platform::PunchthroughError<
            <Self::Punchthrough as litebox::platform::Punchthrough>::ReturnFailure,
        >,
    > {
        match self.punchthrough {
            PunchthroughSyscall::RtSigprocmask { how, set, oldset } => {
                let set = match set {
                    Some(ptr) => {
                        let mut set = unsafe { ptr.read_at_offset(0) }
                            .ok_or(litebox::platform::PunchthroughError::Failure(
                                litebox_common_linux::errno::Errno::EFAULT,
                            ))?
                            .into_owned();
                        // never block SIGSYS (required by Seccomp to intercept syscalls)
                        set.remove(litebox_common_linux::Signal::SIGSYS);
                        Some(set)
                    }
                    None => None,
                };
                unsafe {
                    syscalls::syscall5(
                        syscalls::Sysno::rt_sigprocmask,
                        how as usize,
                        if let Some(set) = set.as_ref() {
                            core::ptr::from_ref(set) as usize
                        } else {
                            0
                        },
                        oldset.map_or(0, |ptr| ptr.as_usize()),
                        size_of::<litebox_common_linux::SigSet>(),
                        // Unused by the syscall but would be checked by Seccomp filter if enabled.
                        syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
                    )
                }
                .map_err(|err| match err {
                    syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
                    syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
                    _ => panic!("unexpected error {err}"),
                })
                .map_err(litebox::platform::PunchthroughError::Failure)
            }
            PunchthroughSyscall::RtSigaction {
                signum,
                act,
                oldact,
            } => {
                if signum == litebox_common_linux::Signal::SIGSYS && act.is_some() {
                    // don't allow changing the SIGSYS handler
                    return Err(litebox::platform::PunchthroughError::Failure(
                        litebox_common_linux::errno::Errno::EINVAL,
                    ));
                }

                let act = act.map_or(0, |ptr| ptr.as_usize());
                let oldact = oldact.map_or(0, |ptr| ptr.as_usize());
                unsafe {
                    syscalls::syscall4(
                        syscalls::Sysno::rt_sigaction,
                        signum as usize,
                        act,
                        oldact,
                        size_of::<litebox_common_linux::SigSet>(),
                    )
                }
                .map_err(|err| match err {
                    syscalls::Errno::EFAULT => litebox_common_linux::errno::Errno::EFAULT,
                    syscalls::Errno::EINVAL => litebox_common_linux::errno::Errno::EINVAL,
                    _ => panic!("unexpected error {err}"),
                })
                .map_err(litebox::platform::PunchthroughError::Failure)
            }
            #[cfg(target_arch = "x86_64")]
            PunchthroughSyscall::SetFsBase { addr } => {
                use litebox::platform::RawConstPointer as _;
                set_fs_base(addr.as_usize()).map_err(litebox::platform::PunchthroughError::Failure)
            }
            #[cfg(target_arch = "x86_64")]
            PunchthroughSyscall::GetFsBase { addr } => {
                use litebox::platform::RawMutPointer as _;
                let fs_base =
                    get_fs_base().map_err(litebox::platform::PunchthroughError::Failure)?;
                unsafe { addr.write_at_offset(0, fs_base) }.ok_or(
                    litebox::platform::PunchthroughError::Failure(
                        litebox_common_linux::errno::Errno::EFAULT,
                    ),
                )?;
                Ok(0)
            }
            #[cfg(target_arch = "x86")]
            PunchthroughSyscall::SetThreadArea { user_desc } => {
                set_thread_area(user_desc).map_err(litebox::platform::PunchthroughError::Failure)
            }
        }
    }
}

impl PunchthroughProvider for MockNoStdPlatform {
    type PunchthroughToken = PunchthroughToken;
    
    fn get_punchthrough_token_for(
        &self,
        punchthrough: <Self::PunchthroughToken as litebox::platform::PunchthroughToken>::Punchthrough,
    ) -> Option<Self::PunchthroughToken> {
        Some(PunchthroughToken { punchthrough })
    }
}

impl DebugLogProvider for MockNoStdPlatform {
    fn debug_log_print(&self, msg: &str) {
        let msg_ptr = msg.as_ptr() as usize;
        let msg_len = msg.len();
        
        unsafe {
            let _ = syscall!(Sysno::write, 1, msg_ptr, msg_len);
        }
    }
}

impl RawPointerProvider for MockNoStdPlatform {
    type RawConstPointer<T: Clone> = trivial_providers::TransparentConstPtr<T>;
    type RawMutPointer<T: Clone> = trivial_providers::TransparentMutPtr<T>;
}

impl StdioProvider for MockNoStdPlatform {
    fn read_from_stdin(&self, _buf: &mut [u8]) -> Result<usize, StdioReadError> {
        // No-op implementation for mock - no input available
        // Return 0 to indicate no bytes read (EOF-like behavior)
        Ok(0)
    }

    fn write_to(&self, stream: StdioOutStream, buf: &[u8]) -> Result<usize, StdioWriteError> {
        let fd = match stream {
            StdioOutStream::Stdout => 1,
            StdioOutStream::Stderr => 2,
        };
        
        let buf_ptr = buf.as_ptr() as usize;
        let buf_len = buf.len();
        
        unsafe {
            match syscall!(Sysno::write, fd, buf_ptr, buf_len) {
                Ok(bytes_written) => Ok(bytes_written as usize),
                Err(_) => Err(StdioWriteError::Closed),
            }
        }
    }

    fn is_a_tty(&self, _stream: StdioStream) -> bool {
        // In no_std environments, typically not connected to a TTY
        false
    }
}

#[global_allocator]
static SLAB_ALLOC: litebox::mm::allocator::SafeZoneAllocator<'static, 28, MockNoStdPlatform> =
    litebox::mm::allocator::SafeZoneAllocator::new();

impl litebox::mm::allocator::MemoryProvider for MockNoStdPlatform {
    fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        let size = core::cmp::max(
            layout.size().next_power_of_two(),
            // Note `mmap` provides no guarantee of alignment, so we double the size to ensure we
            // can always find a required chunk within the returned memory region.
            core::cmp::max(layout.align(), 0x1000) << 1,
        );
        unsafe {
            syscalls::syscall6(
                {
                    #[cfg(target_arch = "x86_64")]
                    {
                        syscalls::Sysno::mmap
                    }
                    #[cfg(target_arch = "x86")]
                    {
                        syscalls::Sysno::mmap2
                    }
                },
                0,
                size,
                ProtFlags::PROT_READ_WRITE.bits().reinterpret_as_unsigned() as usize,
                ((MapFlags::MAP_PRIVATE | MapFlags::MAP_ANON)
                    .bits()
                    .reinterpret_as_unsigned()
                    // This is to ensure it won't be intercepted by Seccomp if enabled.
                    | syscall_intercept::systrap::MMAP_FLAG_MAGIC) as usize,
                usize::MAX,
                0,
            )
        }
        .map(|addr| (addr, size))
        .ok()
    }

    unsafe fn free(_addr: usize) {
        todo!();
    }
}


fn prot_flags(flags: MemoryRegionPermissions) -> ProtFlags {
    let mut res = ProtFlags::PROT_NONE;
    res.set(
        ProtFlags::PROT_READ,
        flags.contains(MemoryRegionPermissions::READ),
    );
    res.set(
        ProtFlags::PROT_WRITE,
        flags.contains(MemoryRegionPermissions::WRITE),
    );
    res.set(
        ProtFlags::PROT_EXEC,
        flags.contains(MemoryRegionPermissions::EXEC),
    );
    if flags.contains(MemoryRegionPermissions::SHARED) {
        unimplemented!()
    }
    res
}

// Implementation of PageManagementProvider for the mock platform
impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for MockNoStdPlatform {
    fn allocate_pages(
        &self,
        range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages: bool,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let flags = MapFlags::MAP_PRIVATE
            | MapFlags::MAP_ANONYMOUS
            | MapFlags::MAP_FIXED
            | (if can_grow_down {
                MapFlags::MAP_GROWSDOWN
            } else {
                MapFlags::empty()
            } | if populate_pages {
                MapFlags::MAP_POPULATE
            } else {
                MapFlags::empty()
            });
        let ptr = unsafe {
            syscalls::syscall6(
                {
                    #[cfg(target_arch = "x86_64")]
                    {
                        syscalls::Sysno::mmap
                    }
                    #[cfg(target_arch = "x86")]
                    {
                        syscalls::Sysno::mmap2
                    }
                },
                range.start,
                range.len(),
                prot_flags(initial_permissions)
                    .bits()
                    .reinterpret_as_unsigned() as usize,
                (flags.bits().reinterpret_as_unsigned()
                    // This is to ensure it won't be intercepted by Seccomp if enabled.
                    | syscall_intercept::systrap::MMAP_FLAG_MAGIC) as usize,
                usize::MAX,
                0,
            )
        }
        .expect("mmap failed");
        Ok(litebox::platform::trivial_providers::TransparentMutPtr {
            inner: ptr as *mut u8,
        })
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let _ = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::munmap,
                range.start,
                range.len(),
                // This is to ensure it won't be intercepted by Seccomp if enabled.
                syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
            )
        }
        .expect("munmap failed");
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::RemapError> {
        let res = unsafe {
            syscalls::syscall6(
                syscalls::Sysno::mremap,
                old_range.start,
                old_range.len(),
                new_range.len(),
                (MRemapFlags::MREMAP_FIXED | MRemapFlags::MREMAP_MAYMOVE).bits() as usize,
                new_range.start,
                // Unused by the syscall but would be checked by Seccomp filter if enabled.
                syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
            )
            .expect("mremap failed")
        };
        assert_eq!(res, new_range.start);
        Ok(litebox::platform::trivial_providers::TransparentMutPtr {
            inner: res as *mut u8,
        })
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        unsafe {
            syscalls::syscall4(
                syscalls::Sysno::mprotect,
                range.start,
                range.len(),
                prot_flags(new_permissions).bits().reinterpret_as_unsigned() as usize,
                // This is to ensure it won't be intercepted by Seccomp if enabled.
                syscall_intercept::systrap::SYSCALL_ARG_MAGIC,
            )
        }
        .expect("mprotect failed");
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        self.reserved_pages.iter()
    }
}

// Add syscall entry point support
impl MockNoStdPlatform {
    pub fn get_syscall_entry_point(&self) -> usize {
        // Mock implementation - return a dummy address
        unimplemented!("MockNoStdPlatform does not support syscall entry points");
    }
}
