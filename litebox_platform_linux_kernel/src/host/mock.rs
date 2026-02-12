// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use core::sync::atomic::AtomicU32;

use litebox::utils::ReinterpretUnsignedExt as _;
use litebox::utils::TruncateExt as _;

use crate::HostInterface;

pub struct MockHostInterface {}

pub type MockKernel = crate::LinuxKernel<MockHostInterface>;

#[macro_export]
macro_rules! mock_log_println {
    ($($tt:tt)*) => {{
        use core::fmt::Write;
        let mut t: arrayvec::ArrayString<1024> = arrayvec::ArrayString::new();
        writeln!(t, $($tt)*).unwrap();
        <$crate::host::mock::MockHostInterface as $crate::HostInterface>::log(&t);
    }};
}

impl HostInterface for MockHostInterface {
    fn alloc(layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        let size = core::cmp::max(
            layout.size().next_power_of_two(),
            // Note `mmap` provides no guarantee of alignment, so we double the size to ensure we
            // can always find a required chunk within the returned memory region.
            core::cmp::max(layout.align(), 0x1000) << 1,
        );
        let addr = unsafe {
            syscalls::syscall6(
                syscalls::Sysno::mmap,
                0,
                size << 1,
                litebox_common_linux::ProtFlags::PROT_READ_WRITE
                    .bits()
                    .reinterpret_as_unsigned() as usize,
                (litebox_common_linux::MapFlags::MAP_PRIVATE
                    | litebox_common_linux::MapFlags::MAP_ANON)
                    .bits()
                    .reinterpret_as_unsigned() as usize,
                usize::MAX,
                0,
            )
        }
        .ok()?;
        Some((addr, size << 1))
    }

    unsafe fn free(_addr: usize) {
        todo!()
    }

    fn terminate(_reason_set: u64, _reason_code: u64) -> ! {
        todo!()
    }

    fn send_ip_packet(_packet: &[u8]) -> Result<usize, crate::Errno> {
        todo!()
    }

    fn receive_ip_packet(_packet: &mut [u8]) -> Result<usize, crate::Errno> {
        todo!()
    }

    fn log(msg: &str) {
        let _ = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::write,
                litebox_common_linux::STDERR_FILENO as usize,
                msg.as_ptr() as usize,
                msg.len(),
            )
        };
    }

    fn wake_many(_mutex: &AtomicU32, _n: usize) -> Result<usize, crate::Errno> {
        todo!()
    }

    fn block_or_maybe_timeout(
        _mutex: &AtomicU32,
        _val: u32,
        _timeout: Option<core::time::Duration>,
    ) -> Result<(), crate::Errno> {
        todo!()
    }

    fn read_from_stdin(_buf: &mut [u8]) -> Result<usize, litebox_common_linux::errno::Errno> {
        todo!()
    }

    fn write_to(
        _stream: litebox::platform::StdioOutStream,
        _buf: &[u8],
    ) -> Result<usize, litebox_common_linux::errno::Errno> {
        todo!()
    }

    fn current_realtime() -> core::time::Duration {
        let mut t = core::mem::MaybeUninit::<litebox_common_linux::Timespec>::uninit();
        let ret = unsafe {
            syscalls::syscall2(
                syscalls::Sysno::clock_gettime,
                0, // CLOCK_REALTIME
                t.as_mut_ptr() as usize,
            )
        };
        assert!(ret.is_ok(), "clock_gettime failed");
        let t = unsafe { t.assume_init() };
        core::time::Duration::new(t.tv_sec.reinterpret_as_unsigned(), t.tv_nsec.truncate())
    }

    fn return_to_host() -> ! {
        todo!()
    }

    fn terminate_process(_code: i32) -> ! {
        todo!()
    }
}
