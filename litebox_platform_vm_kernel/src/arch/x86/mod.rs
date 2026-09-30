// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub mod gdt;
pub mod interrupts;
pub(crate) mod mm;

pub(crate) use x86_64::{
    addr::{PhysAddr, VirtAddr},
    structures::{
        idt::PageFaultErrorCode,
        paging::{Page, PageTableFlags, PhysFrame, Size4KiB},
    },
};

use core::arch::x86_64::__cpuid_count as cpuid_count;
use x86_64::registers::{
    control::{Cr4, Cr4Flags},
    model_specific::{Efer, EferFlags, KernelGsBase},
};

/// Enable `rd/wr{fs,gs}base`, which per-CPU data and TLS depend on.
///
/// # Panics
///
/// Panics if the CPU does not support FSGSBASE.
#[inline]
pub fn enable_fsgsbase() {
    assert!(
        cpuid_count(0x07, 0).ebx & 1 != 0,
        "CPU does not support FSGSBASE"
    );
    let mut flags = Cr4::read();
    flags.insert(Cr4Flags::FSGSBASE);
    // Safety: supported (checked above); only enables instructions.
    unsafe {
        Cr4::write(flags);
    }
}

/// Enable x87 and SSE state (the only XSAVE components saved), plus XSAVE
/// and `CR0.NE`. Must run before [`crate::per_cpu::allocate_xsave_area`].
///
/// # Panics
///
/// Panics if the CPU does not support XSAVE or XSAVEOPT, which the
/// kernel/user transitions use unconditionally.
pub fn enable_extended_states() {
    use x86_64::registers::{
        control::{Cr0, Cr0Flags},
        xcontrol::{XCr0, XCr0Flags},
    };

    assert!(
        cpuid_count(1, 0).ecx & (1 << 26) != 0,
        "CPU does not support XSAVE"
    );
    assert!(
        cpuid_count(0x0d, 1).eax & 1 != 0,
        "CPU does not support XSAVEOPT"
    );

    let mut cr0 = Cr0::read();
    cr0.remove(Cr0Flags::EMULATE_COPROCESSOR);
    cr0.insert(Cr0Flags::MONITOR_COPROCESSOR | Cr0Flags::NUMERIC_ERROR);
    // Safety: selects hardware FPU/SSE handling; no memory effects.
    unsafe { Cr0::write(cr0) };

    let mut cr4 = Cr4::read();
    cr4.insert(Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE | Cr4Flags::OSXSAVE);
    // Safety: enables FXSAVE/XSAVE and SIMD exceptions; no memory effects.
    unsafe { Cr4::write(cr4) };

    // Safety: x87 and SSE are architectural on x86-64.
    unsafe { XCr0::write(XCr0Flags::X87 | XCr0Flags::SSE) };
}

#[inline]
pub(crate) fn write_kernel_gsbase_msr(addr: VirtAddr) {
    KernelGsBase::write(addr);
}

/// Enable `EFER.NXE`. Must run before loading page tables that use
/// `NO_EXECUTE`, which is otherwise a reserved bit.
///
/// # Panics
///
/// Panics if the CPU does not support NX.
pub(crate) fn enable_dep() {
    let ext_features = cpuid_count(0x8000_0001, 0);
    assert!(
        ext_features.edx & (1 << 20) != 0,
        "CPU does not support NX/XD bit"
    );

    // Safety: supported (checked above); `NO_EXECUTE` in PTEs becomes valid.
    unsafe {
        let efer = Efer::read();
        Efer::write(efer | EferFlags::NO_EXECUTE_ENABLE);
    }
}

/// Enable supervisor write protection (`CR0.WP`), so the kernel cannot write
/// through read-only user PTEs.
pub(crate) fn enable_write_protect() {
    use x86_64::registers::control::{Cr0, Cr0Flags};
    // Safety: kernel code never writes through read-only mappings.
    unsafe { Cr0::update(|cr0| cr0.insert(Cr0Flags::WRITE_PROTECT)) };
}

/// Enable SMEP and SMAP. From then on, kernel access to user memory must be
/// wrapped in `stac`/`clac`.
///
/// # Panics
///
/// Panics if the CPU does not support SMEP or SMAP.
pub fn enable_smep_smap() {
    let structured_features = cpuid_count(0x07, 0);
    assert!(
        structured_features.ebx & (1 << 7) != 0,
        "CPU does not support SMEP"
    );
    assert!(
        structured_features.ebx & (1 << 20) != 0,
        "CPU does not support SMAP"
    );

    let mut cr4 = Cr4::read();
    cr4.insert(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION);
    cr4.insert(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION);
    // Safety: supported (checked above). Kernel accesses to user memory go
    // through `with_user_memory_access`, which sets RFLAGS.AC.
    unsafe {
        Cr4::write(cr4);
    }
}
