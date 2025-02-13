use core::sync::atomic::AtomicU32;

use alloc::vec::Vec;
use spin::mutex::SpinMutex;

use crate::{HostInterface, Task};

pub struct MockHostInterface {}

static MUTEX_VEC_ALLOCATED: SpinMutex<Vec<AtomicU32>> = SpinMutex::new(Vec::new());
#[repr(align(0x1000))]
struct Space([u8; 0x1000]);
static mut SPACE: Space = Space([0; 0x1000]);

impl HostInterface for MockHostInterface {
    #[allow(static_mut_refs)]
    fn alloc(_layout: &core::alloc::Layout) -> Result<(usize, usize), crate::error::Errno> {
        unsafe { Ok((SPACE.0.as_ptr() as usize, SPACE.0.len() * size_of::<u8>())) }
    }

    fn exit() {
        todo!()
    }

    fn terminate(_reason_set: u64, _reason_code: u64) -> ! {
        todo!()
    }

    fn syscalls<const N: usize, const ID: u32>(
        _arg: crate::SyscallN<N, ID>,
    ) -> Result<usize, crate::error::Errno> {
        todo!()
    }

    fn alloc_raw_mutex() -> *mut AtomicU32 {
        let mutex = AtomicU32::new(0);
        let ptr = &mutex as *const AtomicU32 as *mut AtomicU32;
        MUTEX_VEC_ALLOCATED.lock().push(mutex);
        ptr
    }

    fn release_raw_mutex(mutex: *mut AtomicU32) {
        MUTEX_VEC_ALLOCATED
            .lock()
            .retain(|m| m as *const AtomicU32 != mutex);
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
}

pub struct MockTask;

static mut MOCK_TASK: MockTask = MockTask;

impl Task for MockTask {
    fn current<'a>() -> Option<&'a mut Self> {
        let ptr = &raw mut MOCK_TASK;
        Some(unsafe { &mut *ptr })
    }

    fn convert_ptr_to_host<T>(&self, ptr: *const T) -> *const T {
        ptr
    }

    fn convert_mut_ptr_to_host<T>(&self, ptr: *mut T) -> *mut T {
        ptr
    }
}
