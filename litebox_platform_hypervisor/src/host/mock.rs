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
    fn alloc(_layout: &core::alloc::Layout) -> Option<(usize, usize)> {
        todo!()
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

    fn switch(_result: u64) -> ! {
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
        _how: i32,
        _set: crate::ptr::UserConstPtr<super::linux::sigset_t>,
        _old_set: crate::ptr::UserMutPtr<super::linux::sigset_t>,
        _sigsetsize: usize,
    ) -> Result<usize, crate::Errno> {
        todo!()
    }
}
