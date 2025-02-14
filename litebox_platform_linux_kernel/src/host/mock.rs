use core::sync::atomic::AtomicU32;

use crate::{HostInterface, Task};

pub struct MockHostInterface {}

#[repr(align(0x1000))]
struct Space([u8; 0x1000]);
static mut SPACES: [Space; 3] = [Space([0; 0x1000]), Space([0; 0x1000]), Space([0; 0x1000])];

impl HostInterface for MockHostInterface {
    #[allow(static_mut_refs)]
    fn alloc(layout: &core::alloc::Layout) -> Result<(usize, usize), crate::error::Errno> {
        assert!(layout.size() <= 0x1000);
        static mut IDX: usize = 0;
        unsafe {
            let space = &mut SPACES[IDX];
            IDX += 1;
            Ok((space.0.as_ptr() as usize, space.0.len() * size_of::<u8>()))
        }
    }

    fn terminate(_reason_set: u64, _reason_code: u64) -> ! {
        todo!()
    }

    fn send_ip_packet(_packet: &[u8]) -> Result<usize, crate::error::Errno> {
        todo!()
    }

    fn receive_ip_packet(_packet: &mut [u8]) -> Result<usize, crate::error::Errno> {
        todo!()
    }

    fn log(_msg: &str) {
        todo!()
    }

    fn exit() -> ! {
        todo!()
    }

    fn rt_sigprocmask(
        _how: i32,
        _set: Option<*const super::linux::sigset_t>,
        _old_set: Option<*mut super::linux::sigset_t>,
        _sigsetsize: usize,
    ) -> Result<usize, crate::error::Errno> {
        todo!()
    }

    fn wake_many<T: Task>(_mutex: &AtomicU32, _n: usize) -> Result<usize, crate::error::Errno> {
        todo!()
    }

    fn block_or_maybe_timeout<T: Task>(
        _mutex: &AtomicU32,
        _val: u32,
        _timeout: Option<core::time::Duration>,
    ) -> Result<(), crate::error::Errno> {
        todo!()
    }
}

pub struct MockTask;

static MOCK_TASK: MockTask = MockTask;

impl Task for MockTask {
    fn current<'a>() -> Option<&'a Self> {
        // let ptr = &raw mut MOCK_TASK;
        Some(&MOCK_TASK)
    }

    fn convert_ptr_to_host<T>(&self, ptr: *const T) -> *const T {
        ptr
    }

    fn convert_mut_ptr_to_host<T>(&self, ptr: *mut T) -> *mut T {
        ptr
    }
}
