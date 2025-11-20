#![no_std]

extern crate alloc;

use core::str;

use alloc::sync::Arc;
use alloc::vec;

use ostd::arch::cpu::context::UserContext;
use ostd::arch::qemu::{QemuExitCode, exit_qemu};
use ostd::mm::{
    CachePolicy, FallibleVmRead, FrameAllocOptions, PAGE_SIZE, PageFlags, PageProperty, Vaddr,
    VmIo, VmSpace, VmWriter,
};
use ostd::prelude::*;
use ostd::task::{Task, TaskOptions, disable_preempt};
use ostd::user::{ReturnReason, UserMode};

#[ostd::main]
pub fn main() {
    let program_binary = include_bytes!("/tmp/tempdir/temp/hello");
    let vm_space = Arc::new(create_vm_space(program_binary));
    vm_space.activate();
    let user_task = create_user_task(vm_space);
    user_task.run();
}

fn create_vm_space(program: &[u8]) -> VmSpace {
    let nbytes = program.len().next_multiple_of(PAGE_SIZE);
    let user_pages = {
        let segment = FrameAllocOptions::new()
            .alloc_segment(nbytes / PAGE_SIZE)
            .unwrap();
        segment.write_bytes(0, program).unwrap();
        segment
    };

    let vm_space = VmSpace::new();
    const MAP_ADDR: Vaddr = 0x0040_0000;
    let preempt_guard = disable_preempt();
    let mut cursor = vm_space
        .cursor_mut(&preempt_guard, &(MAP_ADDR..MAP_ADDR + nbytes))
        .unwrap();
    let map_prop = PageProperty::new_user(PageFlags::RWX, CachePolicy::Writeback);
    for frame in user_pages {
        cursor.map(frame.into(), map_prop);
    }
    drop(cursor);
    vm_space
}

fn create_user_task(vm_space: Arc<VmSpace>) -> Arc<Task> {
    fn user_task() {
        let current = Task::current().unwrap();
        let mut user_mode = {
            let user_ctx = create_user_context();
            UserMode::new(user_ctx)
        };

        loop {
            let return_reason = user_mode.execute(|| false);
            let user_context = user_mode.context_mut();
            if ReturnReason::UserSyscall == return_reason {
                let vm_space = current.data().downcast_ref::<Arc<VmSpace>>().unwrap();
                handle_syscall(user_context, &vm_space);
            }
        }
    }

    Arc::new(TaskOptions::new(user_task).data(vm_space).build().unwrap())
}

fn create_user_context() -> UserContext {
    let mut user_ctx = UserContext::default();
    const ENTRY_POINT: Vaddr = 0x0040_1000;
    user_ctx.set_rip(ENTRY_POINT);
    user_ctx
}

fn handle_syscall(user_context: &mut UserContext, vm_space: &VmSpace) {
    const SYS_WRITE: usize = 1;
    const SYS_EXIT: usize = 60;

    match user_context.rax() {
        SYS_WRITE => {
            let (_, buf_addr, buf_len) =
                (user_context.rdi(), user_context.rsi(), user_context.rdx());
            let buf = {
                let mut buf = vec![0u8; buf_len];
                let mut reader = vm_space.reader(buf_addr, buf_len).unwrap();
                reader
                    .read_fallible(&mut VmWriter::from(&mut buf as &mut [u8]))
                    .unwrap();
                buf
            };
            println!("{}", str::from_utf8(&buf).unwrap());
            user_context.set_rax(buf_len);
        }
        SYS_EXIT => exit_qemu(QemuExitCode::Success),
        _ => unimplemented!(),
    }
}
