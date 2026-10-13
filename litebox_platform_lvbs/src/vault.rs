// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Vault address space for Platform Root Key (PRK) computations
//! (`DerivedKeyProvider`): deriving keys from the PRK, and running computations
//! with such keys without exposing the PRK to them.
//!
//! Threat model: speculative side channels from VTL1 userspace and post-boot
//! VTL0. VTL0 is trusted only in early boot, when it supplies the PRK and then
//! wipes its copy; afterwards it is an untrusted ring-0 attacker without the
//! PRK. The controls below do not depend on the attacker. Isolating VTL1 memory
//! from VTL0 is Hyper-V's job.
//!
//! - Boot reserves the PRK and stack pages outside the normal kernel mapping
//!   and allocator. Only the vault page tables map them.
//! - Shim callbacks (KDFs and computations) run on the vault stack, which is
//!   wiped on exit, derived keys included. Caller-saved GPRs and VTL1 extended
//!   state (x87/SSE) are overwritten too.
//! - Entry: IBPB, STIBP, SSBD, RSB stuffing; vault dispatch uses retpolines.
//!   Exit: `VERW`, L1D flush (best-effort eviction if unavailable), IBPB.
//!   Retpolines do not replace SRSO microcode; eviction is not a guaranteed flush.
//! - Up to `VAULT_SLOTS` entries run concurrently, with interrupts disabled.
//!   Each slot's page table maps the shared PRK page and only its own stack.
//!
//! Retpolines protect explicit vault dispatches, not indirect branches inside
//! the shim callbacks. Those rely on available IBPB and eIBRS/AutoIBRS controls.
//!
//! SMT: the sibling hyperthread may run userspace or VTL0 of this VM. STIBP
//! blocks branch injection from it (eIBRS/AutoIBRS does not separate VTL0 and
//! VTL1 kernel mode); concurrent data sampling is an accepted risk limited to
//! older CPUs. Concurrent vault entries on siblings can expose data only to
//! each other.
//!
//! Other cores share the last-level cache, which the vault does not flush; shim
//! callbacks should avoid secret-dependent branches and memory accesses.
//!
//! The vault shares only the VTL1 kernel region (`>= KERNEL_OFFSET`: image,
//! heap, stacks); see [`is_accessible`].
//!
//! A fault or panic inside the vault is fatal (VTL0 crash dump and reboot),
//! so the skipped exit path cannot leak to userspace.
//!
//! TODO: The panic path returns to VTL0 for the crash dump without scrubbing
//! (no stack wipe, `VERW`, L1D flush or IBPB).

use crate::arch::spec_ctrl::VaultControls;
use crate::host::per_cpu_variables::PerCpuVariablesAsm;
use crate::mm::MemoryProvider;
use crate::mshv::vtl1_mem_layout::{
    VTL1_VAULT_SLOTS, VTL1_VAULT_STACK_PAGES, get_memory_base_address, vault_frame_range,
};
use crate::{PageTableManager, mm};
use alloc::boxed::Box;
use core::sync::atomic::{AtomicU32, Ordering};
use litebox::platform::{ComputeParams, KDFParams};
use litebox::utils::TruncateExt;
use litebox_common_linux::vmem::{PAGE_SIZE, PageRange, VmFlags};
use litebox_common_lvbs::PRK_LEN;
use x86_64::{
    VirtAddr,
    structures::paging::{PageTableFlags, PhysFrame, Size4KiB},
};
use zeroize::Zeroizing;

/// Vault pages, in the guard gap below `KERNEL_OFFSET`. Its top-level entry
/// is not shared, so only the vault page tables map them.
const VAULT_BASE: u64 = 0xFFFF_E100_0000_0000;
const _: () = assert!(VAULT_BASE > crate::VMAP_END as u64);
const _: () = assert!(VAULT_BASE + (1 << 39) <= crate::KERNEL_OFFSET);
const _: () = assert!(
    ((VAULT_BASE >> 39) & 0x1ff) < crate::arch::mm::paging::KERNEL_PML4_START as u64,
    "vault slot must not be shared"
);

const VAULT_PRK_VA: u64 = VAULT_BASE;

const VAULT_SLOTS: usize = VTL1_VAULT_SLOTS;
const _: () = assert!(VAULT_SLOTS >= 1 && VAULT_SLOTS <= u32::BITS as usize);

const VAULT_STACK_PAGES: usize = VTL1_VAULT_STACK_PAGES; // 64 KiB debug, 16 KiB release
const VAULT_STACK_SIZE: usize = VAULT_STACK_PAGES * PAGE_SIZE;
/// Each slot maps its own stack here. Unmapped guard pages surround it.
const VAULT_STACK_BOTTOM: u64 = VAULT_BASE + 2 * PAGE_SIZE as u64;
const VAULT_STACK_TOP: u64 = VAULT_STACK_BOTTOM + VAULT_STACK_SIZE as u64;
/// Initial stack pointer: 16-byte aligned, below the dispatch word.
const VAULT_STACK_ENTRY: u64 = VAULT_STACK_TOP - 16;
// Dispatch word at the top of the slot's stack: private to the entry and wiped
// with the stack.
const VAULT_DISPATCH_VA: u64 = if cfg!(test) {
    0x7000_0000_0000 // Host ABI tests use a scratch mapping, not the production page.
} else {
    VAULT_STACK_TOP - 8
};

pub(crate) enum InstallError<E> {
    AlreadyInstalled,
    OutOfMemory,
    Fill(E),
}

pub(crate) struct NotInstalled;

/// Returns whether `buf` is mapped inside the vault, i.e., lies in the VTL1
/// kernel region (`>= KERNEL_OFFSET`) rather than user, vmap, or the
/// `GVA_OFFSET` direct map.
pub(crate) fn is_accessible(buf: &[u8]) -> bool {
    buf.is_empty() || buf.as_ptr() as u64 >= crate::KERNEL_OFFSET
}

/// One concurrent vault entry: maps the shared PRK page and this slot's stack.
struct Slot {
    /// Never dropped; maps boot-reserved vault frames.
    page_table: mm::PageTable<PAGE_SIZE>,
    /// Physical address of `page_table`'s top-level table.
    p4: u64,
}

/// Which of the `VAULT_SLOTS` slots are in use.
struct SlotSet(AtomicU32);

impl SlotSet {
    /// Claim a free slot. `Acquire` pairs with `release`, so the previous
    /// holder's writes (e.g., its stack wipe) are visible.
    fn claim(&self) -> Option<usize> {
        let mut busy = self.0.load(Ordering::Relaxed);
        loop {
            let slot = busy.trailing_ones() as usize;
            if slot >= VAULT_SLOTS {
                return None;
            }
            match self.0.compare_exchange_weak(
                busy,
                busy | (1 << slot),
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(slot),
                Err(current) => busy = current,
            }
        }
    }

    fn release(&self, slot: usize) {
        self.0.fetch_and(!(1 << slot), Ordering::Release);
    }
}

struct Vault {
    slots: Box<[Slot]>,
    busy: SlotSet,
    spec: VaultControls,
    eviction: Option<Box<[u8]>>,
}

static VAULT: spin::Once<Vault> = spin::Once::new();

/// Create the vault. `fill` reads the PRK into a zeroized boot buffer, which is
/// copied into its reserved page through the vault mapping.
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
    unsafe extern "C" fn copy_key(key: *mut u8, prk: *const u8) {
        // Safety: unpublished writable PRK page; `key` is the live boot buffer.
        unsafe { core::ptr::copy_nonoverlapping(key, prk.cast_mut(), PRK_LEN) };
    }
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

    let mut key = Zeroizing::new([0u8; PRK_LEN]);
    fill(&mut key).map_err(InstallError::Fill)?;
    let memory_start = <crate::host::LvbsLinuxKernel as MemoryProvider>::va_to_pa(VirtAddr::new(
        get_memory_base_address(),
    ));
    let frames = vault_frame_range(memory_start);
    let prk_frame = frames.start;
    let mut slots = alloc::vec::Vec::new();
    slots
        .try_reserve_exact(VAULT_SLOTS)
        .map_err(|_| InstallError::OutOfMemory)?;
    for slot in 0..VAULT_SLOTS {
        let first = prk_frame + 1 + u64::try_from(slot * VAULT_STACK_PAGES).unwrap();
        let stack_frames =
            core::array::from_fn::<_, VAULT_STACK_PAGES, _>(|i| first + u64::try_from(i).unwrap());
        let page_table =
            build_page_table(manager, prk_frame, &stack_frames).ok_or(InstallError::OutOfMemory)?;
        slots.push(Slot {
            p4: page_table.get_physical_frame().start_address().as_u64(),
            page_table,
        });
    }
    let vault = Vault {
        slots: slots.into_boxed_slice(),
        busy: SlotSet(AtomicU32::new(0)),
        spec,
        eviction,
    };
    // Every slot maps the same PRK frame, so writing it through one suffices.
    // Safety: only this installer can access the unpublished vault.
    unsafe { vault.run(copy_key, key.as_mut_ptr()) };
    for slot in &vault.slots {
        // Empty VmFlags leave this present page supervisor-only, read-only and NX.
        // Safety: no vault window is active; the table has not been published.
        unsafe {
            slot.page_table.mprotect_pages(
                PageRange::new(
                    VAULT_PRK_VA.trunc(),
                    (VAULT_PRK_VA + PAGE_SIZE as u64).trunc(),
                )
                .unwrap(),
                VmFlags::empty(),
            )
        }
        .expect("failed to make vault PRK read-only");
    }
    Ok(vault)
}

/// Shared kernel PML4 entries plus private PRK and stack mappings.
fn build_page_table(
    manager: &PageTableManager,
    prk_frame: PhysFrame<Size4KiB>,
    stack_frames: &[PhysFrame<Size4KiB>],
) -> Option<mm::PageTable<PAGE_SIZE>> {
    // Safety: allocates a fresh, empty top-level table.
    let pt = unsafe { mm::PageTable::<PAGE_SIZE>::new_top_level() }?;
    pt.copy_pml4_entries_from(&manager.base_page_table);

    let ro = PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE;
    let rw = ro | PageTableFlags::WRITABLE;
    // Writable only for installation; changed to read-only before publication.
    pt.map_non_contiguous_phys_frames(&[prk_frame], VirtAddr::new(VAULT_PRK_VA), rw)
        .ok()?;
    pt.map_non_contiguous_phys_frames(stack_frames, VirtAddr::new(VAULT_STACK_BOTTOM), rw)
        .ok()?;
    // On failure, dropping `pt` frees private tables, not the reserved frames.
    Some(pt)
}

/// Run `f` with the PRK inside the vault.
///
/// User/vmap memory is unmapped in the vault. `ctx` must be kernel-resident.
/// `f` must not take locks or re-enter the vault, to avoid deadlock.
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
        // Safety: inside a vault window; signature matches `call.f`.
        unsafe {
            set_dispatch(call.f as *const () as usize);
            (Dispatch {
                entry: dispatch_retpoline as *const (),
            }
            .call)(prk, call.ctx);
        }
    }

    let vault = VAULT.get().ok_or(NotInstalled)?;
    let mut call = Call { ctx, f };
    // Safety: the thunk matches `Call<C>`, which outlives the window.
    unsafe { vault.run(thunk::<C>, (&raw mut call).cast()) };
    Ok(())
}

/// Input to a pipeline stage, copied to the kernel heap if the vault cannot
/// reach it.
pub(crate) enum Input<'a> {
    Borrowed(&'a [u8]),
    Copied(Zeroizing<alloc::vec::Vec<u8>>),
}

impl<'a> Input<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        if is_accessible(buf) {
            Self::Borrowed(buf)
        } else {
            Self::Copied(Zeroizing::new(buf.to_vec()))
        }
    }

    fn get(&self) -> &[u8] {
        match self {
            Self::Borrowed(buf) => buf,
            Self::Copied(buf) => buf,
        }
    }
}

/// A stage of a vault pipeline: maps `key` to `output`.
pub(crate) trait Stage<E> {
    /// # Safety
    ///
    /// Must run inside a vault window.
    unsafe fn run(&self, key: &[u8], output: &mut [u8]) -> Result<(), E>;
}

/// Shim KDF stage: `f(key, KDFParams { context, output })`.
pub(crate) struct Kdf<'a, E> {
    pub f: fn(&[u8], KDFParams) -> Result<(), E>,
    pub context: Input<'a>,
}

impl<E> Stage<E> for Kdf<'_, E> {
    unsafe fn run(&self, key: &[u8], output: &mut [u8]) -> Result<(), E> {
        let params = KDFParams {
            context: self.context.get(),
            output,
        };
        // Safety: the caller is inside the vault window, and `DerivedKeyProvider`
        // requires `f` to obey the vault restrictions.
        unsafe { invoke(self.f, key, params) }
    }
}

/// Shim computation stage: `f(key, ComputeParams { input, output })`.
pub(crate) struct Compute<'a, E> {
    pub f: fn(&[u8], ComputeParams) -> Result<(), E>,
    pub input: Input<'a>,
}

impl<E> Stage<E> for Compute<'_, E> {
    unsafe fn run(&self, key: &[u8], output: &mut [u8]) -> Result<(), E> {
        let params = ComputeParams {
            input: self.input.get(),
            output,
        };
        // Safety: the caller is inside the vault window, and `DerivedKeyProvider`
        // requires `f` to obey the vault restrictions.
        unsafe { invoke(self.f, key, params) }
    }
}

/// `A` then `B`: `A`'s `N`-byte output, kept on the (wiped) vault stack, is
/// `B`'s key.
pub(crate) struct Then<A, B, const N: usize>(pub A, pub B);

impl<E, A: Stage<E>, B: Stage<E>, const N: usize> Stage<E> for Then<A, B, N> {
    unsafe fn run(&self, key: &[u8], output: &mut [u8]) -> Result<(), E> {
        let mut mid = Zeroizing::new([0u8; N]);
        // Safety: the caller is inside the vault window.
        unsafe {
            self.0.run(key, &mut *mid)?;
            self.1.run(&*mid, output)
        }
    }
}

/// Run `stage` inside the vault with the PRK as its key, writing `output`
/// (copied out on success if the vault cannot reach it).
pub(crate) fn run<E, S: Stage<E>>(
    stage: &S,
    output: &mut [u8],
) -> Result<Result<(), E>, NotInstalled> {
    struct Ctx<'a, S, E> {
        stage: &'a S,
        output: &'a mut [u8],
        result: Option<Result<(), E>>,
    }

    let mut output_copy =
        (!is_accessible(output)).then(|| Zeroizing::new(alloc::vec![0u8; output.len()]));
    let result = {
        let mut ctx = Ctx {
            stage,
            output: match output_copy.as_mut() {
                Some(copy) => copy.as_mut_slice(),
                None => &mut *output,
            },
            result: None,
        };
        with_prk(&mut ctx, |prk, ctx| {
            // Safety: inside a vault window.
            ctx.result = Some(unsafe { ctx.stage.run(prk, ctx.output) });
        })?;
        ctx.result.expect("vault did not run the stage")
    };
    if let (Ok(()), Some(copy)) = (&result, &output_copy) {
        output.copy_from_slice(copy);
    }
    Ok(result)
}

impl Vault {
    /// `thunk` must obey the vault restrictions and accept `arg` plus the PRK address.
    unsafe fn run(&self, thunk: unsafe extern "C" fn(*mut u8, *const u8), arg: *mut u8) {
        loop {
            let done = x86_64::instructions::interrupts::without_interrupts(|| {
                // Hold a slot with interrupts off so an IRQ cannot re-enter the vault.
                let Some(slot) = self.busy.claim() else {
                    return false;
                };
                let spec = self.spec.enter();
                // Safety: interrupts are disabled, the slot is held, and the
                // caller supplies a valid thunk.
                unsafe { trampoline(self.slots[slot].p4, thunk, arg) };
                evict_l1d(self.eviction.as_deref());
                self.spec.exit(spec);
                self.busy.release(slot);
                true
            });
            if done {
                return;
            }
            // All slots are busy, which is rare: wait with interrupts restored.
            core::hint::spin_loop();
        }
    }
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

/// Invoke a shim callback (KDF or computation) through a retpoline.
///
/// # Safety
///
/// Must run inside a vault window; `f` must obey its restrictions.
unsafe fn invoke<E, P>(f: fn(&[u8], P) -> Result<(), E>, key: &[u8], params: P) -> Result<(), E> {
    union Dispatch<E, P> {
        entry: *const (),
        call: unsafe fn(&[u8], P) -> Result<(), E>,
    }
    // Safety: caller holds a vault slot and has loaded its page table.
    unsafe {
        set_dispatch(f as *const () as usize);
        (Dispatch {
            entry: dispatch_retpoline as *const (),
        }
        .call)(key, params)
    }
}

unsafe fn set_dispatch(target: usize) {
    // Safety: the held slot's private dispatch word.
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
/// Interrupts disabled, and `vault_p4` is a vault slot held by the caller.
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
            inout("r14") VAULT_STACK_ENTRY => _,
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
                invoke(
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
                invoke(
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

    #[test]
    fn slot_set_hands_out_each_slot_once() {
        let slots = SlotSet(AtomicU32::new(0));
        for slot in 0..VAULT_SLOTS {
            assert_eq!(slots.claim(), Some(slot));
        }
        assert_eq!(slots.claim(), None);
        slots.release(VAULT_SLOTS - 1);
        assert_eq!(slots.claim(), Some(VAULT_SLOTS - 1));
    }
}
