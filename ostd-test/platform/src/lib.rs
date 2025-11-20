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
    // TODO
    x: u64,
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
        todo!()
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
    // TODO
}

impl litebox::platform::RawMutex for RawMutex {
    fn underlying_atomic(&self) -> &core::sync::atomic::AtomicU32 {
        todo!()
    }
    fn wake_many(&self, _n: usize) -> usize {
        todo!()
    }
    fn block(&self, _val: u32) -> Result<(), litebox::platform::ImmediatelyWokenUp> {
        todo!()
    }
    fn block_or_timeout(
        &self,
        _val: u32,
        _time: core::time::Duration,
    ) -> Result<litebox::platform::UnblockedOrTimedOut, litebox::platform::ImmediatelyWokenUp> {
        todo!()
    }
}

impl litebox::platform::RawMutexProvider for OstdPlatform {
    type RawMutex = RawMutex;
    fn new_raw_mutex(&self) -> Self::RawMutex {
        todo!()
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
        todo!()
    }
}

unsafe impl litebox::platform::ThreadLocalStorageProvider for OstdPlatform {
    fn get_thread_local_storage() -> *mut () {
        todo!()
    }

    unsafe fn replace_thread_local_storage(_value: *mut ()) -> *mut () {
        todo!()
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
        _ctx: &Self::ExecutionContext,
        _init_thread: alloc::boxed::Box<dyn litebox::shim::InitThread>,
    ) -> Result<(), Self::ThreadSpawnError> {
        todo!()
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        todo!()
    }

    fn interrupt_thread(&self, _thread: &Self::ThreadHandle) {
        todo!()
    }
}

pub struct ThreadHandle {
    // TODO
}
