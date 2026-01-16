// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub mod gdt;
pub mod instrs;
pub mod interrupts;
pub mod ioport;
pub mod mm;
pub mod msr;

pub(crate) use x86_64::{
    addr::{PhysAddr, VirtAddr},
    structures::{
        idt::PageFaultErrorCode,
        paging::{Page, PageSize, PageTableFlags, PhysFrame, Size4KiB},
    },
};

#[cfg(test)]
pub(crate) use x86_64::structures::paging::mapper::{MappedFrame, TranslateResult};

/// Get the APIC ID of the current core.
#[inline]
pub fn get_core_id() -> usize {
    use core::arch::x86_64::__cpuid_count as cpuid_count;
    const CPU_VERSION_INFO: u32 = 1;

    let result = unsafe { cpuid_count(CPU_VERSION_INFO, 0x0) };
    let apic_id = (result.ebx >> 24) & 0xff;

    apic_id as usize
}

/// Enable FSGSBASE instructions
#[inline]
pub fn enable_fsgsbase() {
    let mut flags = x86_64::registers::control::Cr4::read();
    flags.insert(x86_64::registers::control::Cr4Flags::FSGSBASE);
    unsafe {
        x86_64::registers::control::Cr4::write(flags);
    }
}

/// The maximum number of supported CPU cores. It depends on the number of VCPUs that
/// Hyper-V supports. We set it to 128 for now.
pub const MAX_CORES: usize = 128;

/// Enable CPU extended states such as XMM and instructions to use and manage them
/// such as SSE and XSAVE
#[cfg(target_arch = "x86_64")]
pub fn enable_extended_states() {
    let mut flags = x86_64::registers::control::Cr0::read();
    flags.remove(x86_64::registers::control::Cr0Flags::EMULATE_COPROCESSOR);
    flags.insert(x86_64::registers::control::Cr0Flags::MONITOR_COPROCESSOR);
    unsafe {
        x86_64::registers::control::Cr0::write(flags);
    }

    let mut flags = x86_64::registers::control::Cr4::read();
    flags.insert(x86_64::registers::control::Cr4Flags::OSFXSR);
    flags.insert(x86_64::registers::control::Cr4Flags::OSXMMEXCPT_ENABLE);
    flags.insert(x86_64::registers::control::Cr4Flags::OSXSAVE);
    unsafe {
        x86_64::registers::control::Cr4::write(flags);
    }

    let mut flags = x86_64::registers::xcontrol::XCr0::read();
    // if necessary, we can enable AVX and other extended states here
    flags.insert(x86_64::registers::xcontrol::XCr0Flags::SSE);
    flags.insert(x86_64::registers::xcontrol::XCr0Flags::X87);
    unsafe {
        x86_64::registers::xcontrol::XCr0::write(flags);
    }
}

#[inline]
pub fn write_kernel_gsbase_msr(addr: VirtAddr) {
    x86_64::registers::model_specific::KernelGsBase::write(addr);
}
