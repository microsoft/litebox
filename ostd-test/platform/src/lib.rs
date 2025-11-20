#![no_std]

use core::marker::PhantomData;

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
