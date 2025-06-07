use core::sync::atomic::AtomicU32;

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
            libc::mmap(
                core::ptr::null_mut(),
                size << 1,
                litebox_common_linux::ProtFlags::PROT_READ_WRITE.bits(),
                (litebox_common_linux::MapFlags::MAP_PRIVATE
                    | litebox_common_linux::MapFlags::MAP_ANON)
                    .bits(),
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            None
        } else {
            Some((addr as usize, size << 1))
        }
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
        unsafe { libc::write(libc::STDOUT_FILENO, msg.as_ptr().cast(), msg.len()) };
    }

    fn exit() -> ! {
        todo!()
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

    fn rt_sigprocmask(
        _how: litebox_common_linux::SigmaskHow,
        _set: Option<crate::ptr::UserConstPtr<litebox_common_linux::SigSet>>,
        _old_set: Option<crate::ptr::UserMutPtr<litebox_common_linux::SigSet>>,
    ) -> Result<usize, crate::Errno> {
        todo!()
    }
}
