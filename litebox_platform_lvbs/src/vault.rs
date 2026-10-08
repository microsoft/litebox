// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Vault address space for Platform Root Key (PRK) based key derivation.
//!
//! Threat model: VTL1 userspace using speculative side channels. VTL0
//! is out of scope as it provides the PRK.
//!
//! - The PRK page and the KDF stack are mapped only in the vault page table.
//!   Their `PA + KERNEL_OFFSET` aliases are unmapped (zeroed PTEs) from the
//!   shared kernel tables.
//! - The KDF runs on the vault stack, which is wiped on exit. Caller-saved
//!   GPRs and VTL1 extended state (x87/SSE) are overwritten too.
//! - Entry: IBPB, STIBP, SSBD, RSB stuffing; vault dispatch uses retpolines.
//!   Exit: `VERW`, L1D flush (best-effort eviction if unavailable), IBPB.
//!   Retpolines do not replace SRSO microcode; eviction is not a guaranteed flush.
//! - Vault entries are serialized with each other, with interrupts disabled.
//!   Other cores keep running.
//!
//! Retpolines protect explicit vault dispatches, not indirect branches inside
//! the KDF. Those rely on available IBPB and eIBRS/AutoIBRS controls.
//!
//! SMT: the sibling hyperthread may run userspace of this VM. eIBRS/AutoIBRS
//! plus STIBP block branch injection from it; concurrent data sampling is
//! an accepted risk limited to older CPUs.
//!
//! The vault shares only the VTL1 kernel region (`>= KERNEL_OFFSET`: image,
//! heap, stacks); see [`is_accessible`].
//!
//! A fault or panic inside the vault is fatal (VTL0 crash dump and reboot),
//! so the skipped exit path cannot leak to userspace.

use crate::arch::spec_ctrl::VaultControls;
use crate::host::per_cpu_variables::PerCpuVariablesAsm;
use crate::mm::{MemoryProvider, pgtable::PageTableAllocator};
use crate::{PageTableManager, mm};
use alloc::boxed::Box;
use arrayvec::ArrayVec;
use litebox::utils::TruncateExt;
use litebox_common_linux::vmem::{PAGE_SIZE, PageRange};
use litebox_common_lvbs::PRK_LEN;
use x86_64::{
    VirtAddr,
    structures::paging::{FrameDeallocator, PageTableFlags, PhysFrame, Size4KiB},
};

/// Vault pages, in the guard gap below `KERNEL_OFFSET`. Its top-level entry
/// is not shared, so only the vault page table maps them.
const VAULT_BASE: u64 = 0xFFFF_E100_0000_0000;
const _: () = assert!(VAULT_BASE > crate::VMAP_END as u64);
const _: () = assert!(VAULT_BASE + (1 << 39) <= crate::KERNEL_OFFSET);
const _: () = assert!(
    ((VAULT_BASE >> 39) & 0x1ff) < crate::arch::mm::paging::KERNEL_PML4_START as u64,
    "vault slot must not be shared"
);

const VAULT_PRK_VA: u64 = VAULT_BASE;

const VAULT_STACK_PAGES: usize = 8; // 32 KiB
const VAULT_STACK_SIZE: usize = VAULT_STACK_PAGES * PAGE_SIZE;
/// Unmapped guard pages surround the stack.
const VAULT_STACK_BOTTOM: u64 = VAULT_BASE + 2 * PAGE_SIZE as u64;
const VAULT_STACK_TOP: u64 = VAULT_STACK_BOTTOM + VAULT_STACK_SIZE as u64;
// Separate writable dispatch page above the upper stack guard, serialized by the lock.
const VAULT_DISPATCH_VA: u64 = if cfg!(test) {
    0x7000_0000_0000 // Host ABI tests use a scratch mapping, not the production page.
} else {
    VAULT_STACK_TOP + PAGE_SIZE as u64
};

pub(crate) enum InstallError<E> {
    AlreadyInstalled,
    OutOfMemory,
    Fill(E),
}

pub(crate) struct NotInstalled;

pub(crate) fn is_installed() -> bool {
    VAULT.is_completed()
}

/// Returns whether `buf` is mapped inside the vault, i.e., lies in the VTL1
/// kernel region (`>= KERNEL_OFFSET`) rather than user, vmap, or the
/// `GVA_OFFSET` direct map.
pub(crate) fn is_accessible(buf: &[u8]) -> bool {
    buf.is_empty() || buf.as_ptr() as u64 >= crate::KERNEL_OFFSET
}

struct Vault {
    /// Never dropped; maps the leaked PRK/stack frames.
    _page_table: mm::PageTable<PAGE_SIZE>,
    /// Physical address of `_page_table`'s top-level table.
    p4: u64,
    spec: VaultControls,
    eviction: Option<Box<[u8]>>,
    /// Serializes vault entries.
    lock: spin::Mutex<()>,
}

static VAULT: spin::Once<Vault> = spin::Once::new();

type FrameAlloc = PageTableAllocator<crate::host::LvbsLinuxKernel>;

fn kernel_va(frame: PhysFrame<Size4KiB>) -> VirtAddr {
    <crate::host::LvbsLinuxKernel as MemoryProvider>::pa_to_va(frame.start_address())
}

/// Zero and free `frames` (installation failure only).
fn free_frames(frames: &[PhysFrame<Size4KiB>]) {
    for &frame in frames {
        // Safety: frames come from `FrameAlloc` and are still mapped.
        unsafe {
            core::ptr::write_bytes(kernel_va(frame).as_mut_ptr::<u8>(), 0, PAGE_SIZE);
            FrameAlloc::new().deallocate_frame(frame);
        }
    }
}

/// Create the vault. `fill` writes the PRK directly into its page, leaving no
/// copy elsewhere, before the page's kernel alias is unmapped.
///
/// `VAULT` admits a single installer, and `with_prk` ignores the vault until
/// it is published.
pub(crate) fn install<E>(
    manager: &PageTableManager,
    fill: impl FnOnce(&mut [u8; PRK_LEN]) -> Result<(), E>,
) -> Result<(), InstallError<E>> {
    let mut installed = false;
    VAULT.try_call_once(|| {
        installed = true;
        build_vault(manager, fill)
    })?;
    if installed {
        Ok(())
    } else {
        Err(InstallError::AlreadyInstalled)
    }
}

fn build_vault<E>(
    manager: &PageTableManager,
    fill: impl FnOnce(&mut [u8; PRK_LEN]) -> Result<(), E>,
) -> Result<Vault, InstallError<E>> {
    let spec = VaultControls::detect();
    let eviction = if spec.has_l1d_flush() {
        None
    } else {
        let mut buffer = alloc::vec::Vec::new();
        buffer
            .try_reserve_exact(128 * 1024)
            .map_err(|_| InstallError::OutOfMemory)?;
        buffer.resize(128 * 1024, 0u8);
        for (index, page) in buffer.chunks_mut(PAGE_SIZE).enumerate() {
            page.fill(u8::try_from(index % 255 + 1).unwrap());
        }
        Some(buffer.into_boxed_slice())
    };

    // PRK page, dispatch page, then stack pages.
    let mut frames = ArrayVec::<PhysFrame<Size4KiB>, { 2 + VAULT_STACK_PAGES }>::new();
    while !frames.is_full() {
        let Some(frame) = FrameAlloc::allocate_frame(true) else {
            free_frames(&frames);
            return Err(InstallError::OutOfMemory);
        };
        frames.push(frame);
    }
    let [prk_frame, dispatch_frame, stack_frames @ ..] = frames.into_inner().unwrap();

    // Safety: exclusively owned, zeroed page.
    let prk = unsafe { &mut *kernel_va(prk_frame).as_mut_ptr::<[u8; PRK_LEN]>() };
    let page_table = match fill(prk) {
        Err(e) => Err(InstallError::Fill(e)),
        Ok(()) => build_page_table(manager, prk_frame, dispatch_frame, &stack_frames)
            .ok_or(InstallError::OutOfMemory),
    };
    let page_table = page_table.inspect_err(|_| {
        free_frames(&[prk_frame, dispatch_frame]);
        free_frames(&stack_frames);
    })?;

    // Hide the kernel aliases. They are in the shared kernel region, so this
    // removes them from every page table and flushes all CPUs. The frames are
    // intentionally leaked.
    for frame in [prk_frame, dispatch_frame].into_iter().chain(stack_frames) {
        let start: usize = kernel_va(frame).as_u64().trunc();
        // Safety: nothing accesses vault memory through its kernel alias.
        unsafe {
            manager.base_page_table.unmap_pages(
                PageRange::new(start, start + PAGE_SIZE).unwrap(),
                false,
                true,
                false,
            )
        }
        .expect("failed to unmap vault kernel alias");
    }
    evict_l1d(eviction.as_deref());
    spec.flush_l1d();

    Ok(Vault {
        p4: page_table.get_physical_frame().start_address().as_u64(),
        _page_table: page_table,
        spec,
        eviction,
        lock: spin::Mutex::new(()),
    })
}

/// Shared kernel slots plus private PRK and stack mappings.
fn build_page_table(
    manager: &PageTableManager,
    prk_frame: PhysFrame<Size4KiB>,
    dispatch_frame: PhysFrame<Size4KiB>,
    stack_frames: &[PhysFrame<Size4KiB>],
) -> Option<mm::PageTable<PAGE_SIZE>> {
    // Safety: allocates a fresh, empty top-level table.
    let pt = unsafe { mm::PageTable::<PAGE_SIZE>::new_top_level() }?;
    pt.copy_pml4_entries_from(&manager.base_page_table);

    let ro = PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE;
    let rw = ro | PageTableFlags::WRITABLE;
    pt.map_non_contiguous_phys_frames(&[prk_frame], VirtAddr::new(VAULT_PRK_VA), ro)
        .ok()?;
    pt.map_non_contiguous_phys_frames(&[dispatch_frame], VirtAddr::new(VAULT_DISPATCH_VA), rw)
        .ok()?;
    pt.map_non_contiguous_phys_frames(stack_frames, VirtAddr::new(VAULT_STACK_BOTTOM), rw)
        .ok()?;
    // On failure, dropping `pt` frees its private tables but not the frames.
    Some(pt)
}

/// Run `f` with the PRK inside the vault.
///
/// `f` must not take locks or touch memory outside the kernel image, heap,
/// and stacks; `ctx` must live there too.
pub(crate) fn with_prk<C>(ctx: &mut C, f: fn(&[u8; PRK_LEN], &mut C)) -> Result<(), NotInstalled> {
    struct Call<'a, C> {
        ctx: &'a mut C,
        f: fn(&[u8; PRK_LEN], &mut C),
    }

    unsafe extern "C" fn thunk<C>(call: *mut u8, prk: *const u8) {
        union Dispatch<C> {
            entry: *const (),
            call: unsafe fn(&[u8; PRK_LEN], &mut C),
        }
        // Safety: `call` points to the live `Call<C>` passed by `with_prk`.
        #[allow(clippy::cast_ptr_alignment, reason = "`call` points to a `Call<C>`")]
        let call = unsafe { &mut *call.cast::<Call<'_, C>>() };
        // Safety: `prk` is `VAULT_PRK_VA`, mapped read-only in the vault.
        let prk = unsafe { &*prk.cast::<[u8; PRK_LEN]>() };
        // Safety: inside the serialized vault window; signature matches `call.f`.
        unsafe {
            set_dispatch(call.f as *const () as usize);
            (Dispatch {
                entry: dispatch_retpoline as *const (),
            }
            .call)(prk, call.ctx);
        }
    }

    let vault = VAULT.get().ok_or(NotInstalled)?;
    let vault_p4 = vault.p4;
    let mut call = Call { ctx, f };

    x86_64::instructions::interrupts::without_interrupts(|| {
        // Lock with interrupts off so an IRQ cannot re-enter and deadlock.
        let _guard = vault.lock.lock();
        let spec = vault.spec.enter();
        // Safety: interrupts are disabled and the lock is held.
        unsafe {
            trampoline(
                vault_p4,
                thunk::<C> as unsafe extern "C" fn(*mut u8, *const u8),
                (&raw mut call).cast(),
            );
        }
        evict_l1d(vault.eviction.as_deref());
        vault.spec.exit(spec);
    });
    Ok(())
}

/// Best-effort L1D displacement, not a substitute for microcode or a hardware flush.
fn evict_l1d(buffer: Option<&[u8]>) {
    if let Some(buffer) = buffer {
        // Warm the TLB first so page walks do not interfere with cache displacement.
        for offset in (0..buffer.len()).step_by(PAGE_SIZE) {
            // Safety: offset is in bounds.
            unsafe {
                core::ptr::read_volatile(buffer.as_ptr().add(offset));
            }
        }
        for offset in (0..buffer.len()).step_by(64) {
            // Safety: offset is in bounds; volatile loads retain every cache-line touch.
            unsafe {
                core::ptr::read_volatile(buffer.as_ptr().add(offset));
            }
        }
        // Safety: LFENCE orders eviction loads and changes no registers or flags.
        unsafe {
            core::arch::asm!("lfence", options(nostack, preserves_flags));
        }
    }
}

/// Invoke the shim KDF through a retpoline.
///
/// # Safety
///
/// Must run inside the serialized vault window; `kdf` must obey its restrictions.
pub(crate) unsafe fn invoke_kdf<E>(
    kdf: fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>,
    prk: &[u8],
    params: litebox::platform::KDFParams,
) -> Result<(), E> {
    union Dispatch<E> {
        entry: *const (),
        call: unsafe fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>,
    }
    // Safety: caller holds the vault lock and has loaded its page table.
    unsafe {
        set_dispatch(kdf as *const () as usize);
        (Dispatch {
            entry: dispatch_retpoline as *const (),
        }
        .call)(prk, params)
    }
}

unsafe fn set_dispatch(target: usize) {
    // Safety: writable dispatch page, accessible only under the vault lock.
    unsafe {
        (VAULT_DISPATCH_VA as *mut usize).write_volatile(target);
    }
}

// Assembly-only Rust-ABI tail entry, used through each target's exact signature.
// Arguments, stack and return layout are unchanged; r11 is scratch on x86_64.
// Host ABI tests exercise register arguments and hidden generic return pointers.
//
// TODO: Consider to use rustc's retpoline when it becomes stable.
unsafe extern "Rust" {
    #[link_name = "litebox_vault_dispatch_retpoline"]
    fn dispatch_retpoline();
}
core::arch::global_asm!(
        ".pushsection .text.litebox_vault_dispatch_retpoline,\"ax\",@progbits",
        ".global litebox_vault_dispatch_retpoline",
        ".type litebox_vault_dispatch_retpoline,@function",
        "litebox_vault_dispatch_retpoline:",
        "movabs r11, {slot}",
        "mov r11, [r11]",
        "call 3f",
        "2:",
        "pause",
        "lfence",
        "jmp 2b",
        "3:",
        "mov [rsp], r11",
        "ret",
        ".size litebox_vault_dispatch_retpoline, .-litebox_vault_dispatch_retpoline",
        ".popsection",
        slot = const VAULT_DISPATCH_VA.cast_signed(),
);

/// Call `thunk(arg, VAULT_PRK_VA)` on the vault stack and address space, then
/// scrub.
///
/// # Safety
///
/// Interrupts disabled, the vault lock held, and `vault_p4` is the vault.
#[inline(never)]
#[rustfmt::skip] // rustfmt would break `stringify!` in the asm macro arguments.
unsafe fn trampoline(vault_p4: u64, thunk: unsafe extern "C" fn(*mut u8, *const u8), arg: *mut u8) {
    // Safety: see above. r12-r15 are callee-saved, so they survive the call.
    unsafe {
        core::arch::asm!(
            // Enter, keeping CR3 flag bits.
            "mov r12, rsp",
            "mov r13, cr3",
            "mov rax, r13",
            "and rax, 0xfff",
            "or rax, rdx",
            "mov cr3, rax",
            "mov rsp, r14",
            // Stuff the RSB (32 entries).
            "mov ecx, 16",
            "2:",
            "call 4f",
            "3:",
            "pause",
            "lfence",
            "jmp 3b",
            "4:",
            "call 6f",
            "5:",
            "pause",
            "lfence",
            "jmp 5b",
            "6:",
            "dec ecx",
            "jnz 2b",
            "add rsp, 256",
            "lfence",
            // Call the thunk (RSP is 16-byte aligned).
            "movabs rsi, {prk_va}",
            // Retpoline: architectural target in r8; speculation stays in the loop.
            "call 20f",
            "jmp 23f",
            "20:",
            "call 22f",
            "21:",
            "pause",
            "lfence",
            "jmp 21b",
            "22:",
            "mov [rsp], r8",
            "ret",
            "23:",
            // Wipe the stack.
            "mov rdi, r15",
            "mov ecx, {stack_qwords}",
            "xor eax, eax",
            "rep stosq",
            // Leave; flushes the vault's non-global TLB entries.
            "mov rsp, r12",
            "mov cr3, r13",
            // Overwrite VTL1 extended state (x87/SSE, `VTL1_XSAVE_MASK`) with
            // the saved user state or init state, as `switch_to_user` does.
            // This also loads MXCSR and the x87 control word, which
            // `clobber_abi` does not model; harmless, as the kernel does no
            // floating-point math.
            XRSTOR_VTL1_ASM!({user_xsave_area_off}, {xsave_mask_lo_off}, {xsave_mask_hi_off}, {user_xsaved_off}),
            // Scrub caller-saved GPRs.
            "xor eax, eax",
            "xor ecx, ecx",
            "xor edx, edx",
            "xor esi, esi",
            "xor edi, edi",
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            CLEAR_CPU_BUFFERS_ASM!({verw_sel_off}),
            prk_va = const VAULT_PRK_VA.cast_signed(),
            user_xsave_area_off = const PerCpuVariablesAsm::vtl1_user_xsave_area_addr_offset(),
            xsave_mask_lo_off = const PerCpuVariablesAsm::vtl1_xsave_mask_lo_offset(),
            xsave_mask_hi_off = const PerCpuVariablesAsm::vtl1_xsave_mask_hi_offset(),
            user_xsaved_off = const PerCpuVariablesAsm::vtl1_user_xsaved_offset(),
            verw_sel_off = const PerCpuVariablesAsm::verw_sel_offset(),
            stack_qwords = const VAULT_STACK_SIZE / 8,
            inout("rdx") vault_p4 => _,
            inout("r8") thunk => _,
            inout("rdi") arg => _,
            inout("r14") VAULT_STACK_TOP => _,
            inout("r15") VAULT_STACK_BOTTOM => _,
            out("r12") _,
            out("r13") _,
            clobber_abi("C"),
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use litebox::platform::KDFParams;

    #[test]
    fn retpoline_preserves_kdf_arguments_and_error_returns() {
        struct Scratch(*mut libc::c_void);
        impl Drop for Scratch {
            fn drop(&mut self) {
                // Safety: this test owns the mapping.
                assert_eq!(unsafe { libc::munmap(self.0, PAGE_SIZE) }, 0);
            }
        }
        fn check(prk: &[u8], params: KDFParams) {
            assert_eq!(prk, &[0x42u8; PRK_LEN]);
            assert_eq!(params.context, b"context");
            params.output.copy_from_slice(prk);
        }
        fn small(prk: &[u8], params: KDFParams) -> Result<(), u32> {
            check(prk, params);
            Err(0x1234_5678)
        }
        #[allow(
            clippy::result_large_err,
            reason = "exercise hidden return-pointer ABI"
        )]
        fn large(prk: &[u8], params: KDFParams) -> Result<(), [u8; 128]> {
            check(prk, params);
            Err([0x5a; 128])
        }
        // Safety: MAP_FIXED_NOREPLACE does not replace existing mappings.
        let page = unsafe {
            libc::mmap(
                VAULT_DISPATCH_VA as *mut libc::c_void,
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        let _scratch = Scratch(page);
        assert_eq!(page, VAULT_DISPATCH_VA as *mut libc::c_void);
        let prk = [0x42u8; PRK_LEN];
        let mut output = [0u8; 32];
        // Safety: single test owns the scratch dispatch slot; these callbacks
        // access only their arguments and need no vault CR3.
        unsafe {
            assert_eq!(
                invoke_kdf(
                    small,
                    &prk,
                    KDFParams {
                        context: b"context",
                        output: &mut output,
                    }
                ),
                Err(0x1234_5678)
            );
            assert_eq!(
                invoke_kdf(
                    large,
                    &prk,
                    KDFParams {
                        context: b"context",
                        output: &mut output,
                    }
                ),
                Err([0x5a; 128])
            );
        }
        assert_eq!(output, prk);
    }
}
