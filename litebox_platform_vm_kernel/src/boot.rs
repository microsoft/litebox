// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::{boxed::Box, vec::Vec};
use core::ops::Range;
use x86_64::PhysAddr;

use crate::{BootConfig, VmKernel, arch, clock::ClockSource, mm, per_cpu, syscall_entry};

struct BootState {
    ram: Vec<Range<PhysAddr>>,
    text: Range<PhysAddr>,
    read_only: Range<PhysAddr>,
    ignored_vectors: Vec<u8>,
    clock: &'static dyn ClockSource,
    timer: Option<&'static dyn crate::clock::DeadlineTimer>,
    entry: fn(&'static VmKernel) -> !,
}

impl VmKernel {
    /// Initialize the single-CPU platform and call `entry` on its kernel stack.
    /// Configuration slices are copied; no boot-stack references survive the handoff.
    ///
    /// # Safety
    ///
    /// The caller must be the only running CPU, in long mode at `KERNEL_OFFSET`
    /// with relocations applied and interrupts disabled. The global allocator
    /// must be ready. `config.ram` must cover the kernel and all live allocations
    /// at `VA = PA + KERNEL_OFFSET`; the boot mappings must already make them
    /// accessible. `config.text` must cover all executable kernel code;
    /// `config.read_only` must contain no data that needs further writes.
    /// No live resource may require unwinding or returning to the boot stack.
    /// Interrupt sources must be masked or listed in `ignored_vectors`.
    ///
    /// # Panics
    ///
    /// Panics on a second boot, unsupported CPU features, invalid mappings,
    /// or allocation failure.
    pub unsafe fn boot(config: BootConfig<'_>, entry: fn(&'static Self) -> !) -> ! {
        // Claim the singleton before changing CPU state.
        mm::set_page_allocator(config.page_allocator);
        arch::enable_fsgsbase();
        arch::enable_extended_states();
        per_cpu::allocate_per_cpu_variables();

        let state = Box::into_raw(Box::new(BootState {
            ram: config.ram.to_vec(),
            text: config.text,
            read_only: config.read_only,
            ignored_vectors: config.ignored_vectors.to_vec(),
            clock: config.clock,
            timer: config.timer,
            entry,
        }));
        let stack = per_cpu::with_per_cpu_variables(per_cpu::PerCpuVariables::kernel_stack_top);
        // Safety: the stack is fresh and aligned; `state` owns all inputs and
        // remains mapped under both boot and permanent page tables.
        unsafe { enter_kernel_stack(stack, state) }
    }
}

#[unsafe(naked)]
unsafe extern "C" fn enter_kernel_stack(_stack: usize, _state: *mut BootState) -> ! {
    core::arch::naked_asm!(
        "mov rsp, rdi",
        "xor ebp, ebp",
        "mov rdi, rsi",
        "call {next}",
        "ud2",
        next = sym finish_boot,
    );
}

unsafe extern "C" fn finish_boot(state: *mut BootState) -> ! {
    // Safety: `boot` transferred its unique Box through `enter_kernel_stack`.
    let state = unsafe { Box::from_raw(state) };
    let platform = VmKernel::initialize(&state.ram, &state.text, &state.read_only, state.clock);
    per_cpu::allocate_xsave_area();
    arch::gdt::init();
    arch::interrupts::init_idt(&state.ignored_vectors, state.timer);
    syscall_entry::init();
    arch::enable_smep_smap();
    let entry = state.entry;
    drop(state);
    entry(platform)
}
