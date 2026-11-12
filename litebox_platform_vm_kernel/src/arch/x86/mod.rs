// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub mod gdt;
pub mod interrupts;
pub(crate) mod mm;
pub(crate) mod trampoline;

pub(crate) use x86_64::{
    addr::{PhysAddr, VirtAddr},
    structures::{
        idt::PageFaultErrorCode,
        paging::{Page, PageTableFlags, PhysFrame, Size4KiB},
    },
};

use core::arch::x86_64::__cpuid_count as cpuid_count;
use litebox::arch::x86_64::xstate::XsaveLayout;
use x86_64::registers::{
    control::{Cr4, Cr4Flags},
    model_specific::{Efer, EferFlags, KernelGsBase},
};

/// The control registers and MSRs each CPU sets before it has its per-CPU
/// variables: FSGSBASE, extended states (with `xcr0`, see
/// [`enable_extended_states`]), NX, and WP.
pub(crate) fn init_cpu_registers(xcr0: u64) {
    enable_fsgsbase();
    enable_extended_states(xcr0);
    enable_dep();
    enable_write_protect();
}

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

/// XCR0 user state components user mode never gets, though the CPU may
/// support them. Each is a whole group, so what remains satisfies XSETBV's
/// dependencies (e.g., AMX's two bits together). User mode gets no CET
/// (shadow stacks, IBT) either, as the Linux shim implements no
/// `ARCH_SHSTK_*` calls: `CR4.CET` stays clear, and CET user state, which is
/// supervisor state (`IA32_XSS`) that XSAVE does not save, is never in XCR0.
const GUEST_XCR0_EXCLUDED: u64 =
    // PKRU: the Linux shim implements no protection-key calls, so
    // `CR4.PKE` stays clear too.
    (1 << 9)
    // AMX tile configuration and data: about 8 KiB per thread, and without
    // Linux's `ARCH_REQ_XCOMP_PERM` permission ABI; AMX instructions raise
    // #UD, as on Linux without the permission.
    | (1 << 17) | (1 << 18);

/// The XCR0 user mode runs with, given the components the CPU `supported`
/// (`CPUID.(EAX=0Dh,ECX=0):EDX:EAX`): all but [`GUEST_XCR0_EXCLUDED`]. The
/// kernel itself is soft-float and uses none of them.
const fn guest_xcr0_for(supported: u64) -> u64 {
    supported & !GUEST_XCR0_EXCLUDED
}

/// [`guest_xcr0_for`] the calling CPU. The boot CPU's is every CPU's.
pub(crate) fn guest_xcr0() -> u64 {
    guest_xcr0_for(supported_xcr0())
}

/// The XCR0 components the calling CPU supports.
fn supported_xcr0() -> u64 {
    let leaf = cpuid_count(0x0d, 0);
    (u64::from(leaf.edx) << 32) | u64::from(leaf.eax)
}

/// Enable the extended state components in `xcr0` (the boot CPU's
/// [`guest_xcr0`] on every CPU), XSAVE, SIMD exceptions, and `CR0.NE`. The
/// first call must be on the boot CPU, with the heap: [`XsaveLayout::get`]
/// lays out user XSAVE areas for the XCR0 of its first call, and caches it.
///
/// # Panics
///
/// Panics if the CPU does not support XSAVE or XSAVEOPT (which the
/// kernel/user transitions use unconditionally) or every component in
/// `xcr0`, or if user XSAVE areas are laid out for another XCR0.
pub fn enable_extended_states(xcr0: u64) {
    use x86_64::registers::{
        control::{Cr0, Cr0Flags},
        xcontrol::XCr0,
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
    cr4.remove(Cr4Flags::PROTECTION_KEY_USER | Cr4Flags::CONTROL_FLOW_ENFORCEMENT);
    // Safety: enables FXSAVE/XSAVE and SIMD exceptions, and disables
    // protection keys and CET, which user mode does not get (see
    // `GUEST_XCR0_EXCLUDED`); no memory effects.
    unsafe { Cr4::write(cr4) };

    let supported = supported_xcr0();
    assert!(
        xcr0 & !supported == 0,
        "CPU does not support the XCR0 components {:#x}",
        xcr0 & !supported
    );
    // Safety: supported (checked above), with x87 and the other
    // components' dependencies (see `GUEST_XCR0_EXCLUDED`); user state only.
    unsafe { XCr0::write_raw(xcr0) };
    assert_eq!(
        XsaveLayout::get().mask,
        xcr0,
        "the XSAVE layout does not match XCR0"
    );
}

#[inline]
pub(crate) fn write_kernel_gsbase_msr(addr: VirtAddr) {
    KernelGsBase::write(addr);
}

/// Outside `swapgs` pairs, the user's GS base.
#[inline]
pub(crate) fn read_kernel_gsbase_msr() -> VirtAddr {
    KernelGsBase::read()
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

#[cfg(test)]
mod tests {
    use super::guest_xcr0_for;

    #[test]
    fn guest_xcr0_for_drops_only_pkru_and_amx() {
        // x87, SSE, AVX, MPX, AVX-512 (opmask, ZMM_Hi256, Hi16_ZMM), PKRU,
        // AMX (XTILECFG, XTILEDATA), and APX.
        let supported = 0b1111_1111 | (1 << 9) | (1 << 17) | (1 << 18) | (1 << 19);
        assert_eq!(guest_xcr0_for(supported), 0b1111_1111 | (1 << 19));
        // x87, SSE, AVX alone, as on CPUs without AVX-512.
        assert_eq!(guest_xcr0_for(0b111), 0b111);
        assert_eq!(guest_xcr0_for(0b11 | (1 << 9)), 0b11);
    }
}
