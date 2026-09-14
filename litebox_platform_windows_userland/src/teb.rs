//! Native TEB state exchange and per-thread runtime-slot access.

use core::ffi::c_void;

use litebox_common_windows::nt_types::ThreadEnvironmentBlock;

use super::TlsState;

/// Like DynamoRIO's x64 fallback, use the last pointer-sized slot in the TEB's
/// second page, beyond the shared `ThreadEnvironmentBlock`. The size of
/// `ThreadEnvironmentBlock` is 0x1878 but its allocation is rounded up to 0x2000.
pub(super) const TEB_RUNTIME_TLS_OFFSET: usize = 0x2000 - size_of::<*const c_void>();
pub(super) const GUEST_TEB_SIZE: usize = size_of::<ThreadEnvironmentBlock>();
/// Set to true and rebuild to enable whole TEB swapping for debugging purposes.
/// Selective TEB swapping is faster but may miss certain internal state changes
/// that whole TEB swapping would catch.
const USE_WHOLE_TEB_SWAP: bool = false;
/// State exchanged for non-graphical guests. GDI batching and Win32/OpenGL
/// client arrays remain native; supporting guest graphics requires revisiting
/// this selection. Keep the remaining state until narrower ownership is proven.
static TEB_SWAP_RANGES: [[usize; 2]; 4] = [
    [
        0,
        core::mem::offset_of!(ThreadEnvironmentBlock, gdi_teb_batch),
    ],
    [
        core::mem::offset_of!(ThreadEnvironmentBlock, real_client_id),
        core::mem::offset_of!(ThreadEnvironmentBlock, win_32_client_info),
    ],
    [
        core::mem::offset_of!(ThreadEnvironmentBlock, last_status_value),
        GUEST_TEB_SIZE,
    ],
    [0, 0],
];
const _: () = {
    let mut index = 0;
    while index < TEB_SWAP_RANGES.len() - 1 {
        let [start, end] = TEB_SWAP_RANGES[index];
        assert!(start < end && end <= GUEST_TEB_SIZE);
        assert!(end - start >= 16);
        assert!(start.is_multiple_of(8) && end.is_multiple_of(8));
        if index > 0 {
            assert!(TEB_SWAP_RANGES[index - 1][1] <= start);
        }
        index += 1;
    }
};
/// Some pointers are relocated between the guest shadow and native TEB when
/// they point inside the source TEB.
static TEB_INTERNAL_POINTER_OFFSETS: [usize; 7] = [
    core::mem::offset_of!(ThreadEnvironmentBlock, nt_tib.self_pointer),
    core::mem::offset_of!(ThreadEnvironmentBlock, thread_local_storage_pointer),
    core::mem::offset_of!(ThreadEnvironmentBlock, activation_stack.active_frame),
    core::mem::offset_of!(
        ThreadEnvironmentBlock,
        activation_stack.frame_list_cache.flink
    ),
    core::mem::offset_of!(
        ThreadEnvironmentBlock,
        activation_stack.frame_list_cache.blink
    ),
    core::mem::offset_of!(ThreadEnvironmentBlock, activation_context_stack_pointer),
    core::mem::offset_of!(ThreadEnvironmentBlock, static_unicode_string.buffer),
];

fn current_teb() -> *mut u8 {
    let teb: *mut u8;
    // SAFETY: On Windows x64, GS:[0x30] contains the current native TEB pointer.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb,
            options(nostack, preserves_flags, readonly),
        );
    }
    teb
}

fn teb_runtime_tls_slot(teb: usize) -> *mut *const TlsState {
    let address = teb + TEB_RUNTIME_TLS_OFFSET;
    debug_assert!(address.is_multiple_of(align_of::<*const TlsState>()));
    core::ptr::with_exposed_provenance_mut(address)
}

fn runtime_tls_slot() -> *mut *const TlsState {
    teb_runtime_tls_slot(current_teb().addr())
}

/// Saves selected host TEB fields and installs guest fields without changing GS.
/// `USE_WHOLE_TEB_SWAP` overrides the selection for both install and restore.
///
/// # Safety
///
/// `tls` must belong to this thread and have a configured, nonzero guest TEB.
/// Its TEB allocations must be live, disjoint, and writable for `GUEST_TEB_SIZE`
/// bytes. Host TEB state must be installed.
#[unsafe(naked)]
pub(super) unsafe extern "C" fn install_guest_teb(tls: &TlsState) {
    core::arch::naked_asm!(
        ".if {USE_WHOLE_TEB_SWAP}",
        "jmp {install_guest_whole_teb}",
        ".endif",
        "mov r10, [rcx + {GUEST_TEB}]",
        "mov r8, [rcx + {HOST_TEB}]",
        "mov r9, [rcx + {HOST_TEB_SHADOW}]",
        "mov rcx, r10",
        "mov rdx, r8",
        "jmp .Lcopy_teb",
        ".globl restore_host_teb",
    "restore_host_teb:",
        ".if {USE_WHOLE_TEB_SWAP}",
        "jmp {restore_host_whole_teb}",
        ".endif",
        "mov r9, [rcx + {GUEST_TEB}]",
        "mov r8, [rcx + {HOST_TEB}]",
        "mov r10, [rcx + {HOST_TEB_SHADOW}]",
        "mov rcx, r8",
        "mov rdx, r9",
        ".Lcopy_teb:",
        "movq xmm3, rcx",
        "lea rax, [rip + {SWAP_RANGES}]",
    ".Lcopy_teb_range:",
        "mov r11, [rax]",
        "mov rcx, [rax + 8]",
        "cmp r11, rcx",
        "je .Lcopy_teb_done",
        "sub rcx, 16",
        "cmp r11, rcx",
        "ja .Lcopy_teb_tail",
    ".Lcopy_teb_blocks:",
        "movdqu xmm0, [r8 + r11]",
        "movdqu xmm1, [r10 + r11]",
        "movdqu [r9 + r11], xmm0",
        "movdqu [r8 + r11], xmm1",
        "add r11, 16",
        "cmp r11, rcx",
        "jbe .Lcopy_teb_blocks",
    ".Lcopy_teb_tail:",
        "add rcx, 16",
        "cmp r11, rcx",
        "je .Lcopy_teb_next",
        "movq xmm0, [r8 + r11]",
        "movq xmm1, [r10 + r11]",
        "movq [r9 + r11], xmm0",
        "movq [r8 + r11], xmm1",
    ".Lcopy_teb_next:",
        "add rax, 16",
        "jmp .Lcopy_teb_range",
        ".Lcopy_teb_done:",
        "movq r9, xmm3",
        "mov r10, rdx",
        "lea r8, [rip + {POINTER_OFFSETS}]",
        "xor r11d, r11d",
        "8:",
        "mov rdx, [r8 + r11 * 8]",
        "mov rax, [r10 + rdx]",
        "sub rax, r9",
        "cmp rax, {TEB_SIZE}",
        "jae 10f",
        "add rax, r10",
        "mov [r10 + rdx], rax",
        "10:",
        "inc r11",
        "cmp r11, {POINTER_COUNT}",
        "jb 8b",
        "ret",
        GUEST_TEB = const core::mem::offset_of!(TlsState, guest_teb),
        HOST_TEB = const core::mem::offset_of!(TlsState, host_teb),
        HOST_TEB_SHADOW = const core::mem::offset_of!(TlsState, host_teb_shadow),
        TEB_SIZE = const GUEST_TEB_SIZE,
        SWAP_RANGES = sym TEB_SWAP_RANGES,
        POINTER_OFFSETS = sym TEB_INTERNAL_POINTER_OFFSETS,
        POINTER_COUNT = const TEB_INTERNAL_POINTER_OFFSETS.len(),
        USE_WHOLE_TEB_SWAP = const USE_WHOLE_TEB_SWAP as usize,
        install_guest_whole_teb = sym install_guest_whole_teb,
        restore_host_whole_teb = sym restore_host_whole_teb,
    );
}

/// Whole-modeled-TEB fallback for diagnosing selective exchange bugs.
///
/// # Safety
///
/// The same requirements as `install_guest_teb` apply.
#[unsafe(naked)]
unsafe extern "C" fn install_guest_whole_teb(tls: &TlsState) {
    core::arch::naked_asm!(
        "mov r10, [rcx + {GUEST_TEB}]",
        "mov r8, [rcx + {HOST_TEB}]",
        "mov r9, [rcx + {HOST_TEB_SHADOW}]",
        "mov rcx, r10",
        "mov rdx, r8",
        "jmp .Lwhole_copy_teb",
        ".globl restore_host_whole_teb",
    "restore_host_whole_teb:",
        "mov r9, [rcx + {GUEST_TEB}]",
        "mov r8, [rcx + {HOST_TEB}]",
        "mov r10, [rcx + {HOST_TEB_SHADOW}]",
        "mov rcx, r8",
        "mov rdx, r9",
        ".Lwhole_copy_teb:",
        "xor r11d, r11d",
    ".Lwhole_copy_teb_blocks:",
        "movdqu xmm0, [r8 + r11]",
        "movdqu xmm1, [r8 + r11 + 16]",
        "movdqu xmm2, [r8 + r11 + 32]",
        "movdqu xmm3, [r8 + r11 + 48]",
        "movdqu [r9 + r11], xmm0",
        "movdqu [r9 + r11 + 16], xmm1",
        "movdqu [r9 + r11 + 32], xmm2",
        "movdqu [r9 + r11 + 48], xmm3",
        "movdqu xmm0, [r10 + r11]",
        "movdqu xmm1, [r10 + r11 + 16]",
        "movdqu xmm2, [r10 + r11 + 32]",
        "movdqu xmm3, [r10 + r11 + 48]",
        "movdqu [r8 + r11], xmm0",
        "movdqu [r8 + r11 + 16], xmm1",
        "movdqu [r8 + r11 + 32], xmm2",
        "movdqu [r8 + r11 + 48], xmm3",
        "add r11, 64",
        "cmp r11, {BLOCK_END}",
        "jb .Lwhole_copy_teb_blocks",
        "3:",
        "mov rax, [r8 + r11]",
        "mov [r9 + r11], rax",
        "mov rax, [r10 + r11]",
        "mov [r8 + r11], rax",
        "add r11, 8",
        "cmp r11, {TEB_SIZE}",
        "jb 3b",
        "mov r9, rcx",
        "mov r10, rdx",
        "lea r8, [rip + {POINTER_OFFSETS}]",
        "xor r11d, r11d",
        "8:",
        "mov rdx, [r8 + r11 * 8]",
        "mov rax, [r10 + rdx]",
        "sub rax, r9",
        "cmp rax, {TEB_SIZE}",
        "jae 10f",
        "add rax, r10",
        "mov [r10 + rdx], rax",
        "10:",
        "inc r11",
        "cmp r11, {POINTER_COUNT}",
        "jb 8b",
        "ret",
        GUEST_TEB = const core::mem::offset_of!(TlsState, guest_teb),
        HOST_TEB = const core::mem::offset_of!(TlsState, host_teb),
        HOST_TEB_SHADOW = const core::mem::offset_of!(TlsState, host_teb_shadow),
        TEB_SIZE = const GUEST_TEB_SIZE,
        BLOCK_END = const GUEST_TEB_SIZE / 64 * 64,
        POINTER_OFFSETS = sym TEB_INTERNAL_POINTER_OFFSETS,
        POINTER_COUNT = const TEB_INTERNAL_POINTER_OFFSETS.len(),
    );
}

unsafe extern "C" {
    /// Writes selected guest TEB fields to its shadow and restores saved host fields.
    /// Excluded graphics fields are neither saved nor restored; see `TEB_SWAP_RANGES`.
    /// GS is unchanged. Internal guest pointers are relocated back into the shadow.
    ///
    /// # Safety
    ///
    /// `tls` must belong to this thread and have a configured, nonzero guest TEB.
    /// Its TEB allocations must be live, disjoint, and writable for `GUEST_TEB_SIZE`
    /// bytes. Guest TEB state must be installed and the host save area must contain
    /// valid state.
    #[expect(
        improper_ctypes,
        reason = "assembly entry in install_guest_teb uses Rust-computed TlsState offsets"
    )]
    pub(super) fn restore_host_teb(tls: &TlsState);

    /// Restores the entire modeled host TEB and writes guest state back to its shadow.
    ///
    /// # Safety
    ///
    /// The same requirements as `restore_host_teb` apply, and the preceding
    /// install must have used `install_guest_whole_teb`.
    #[expect(
        improper_ctypes,
        reason = "assembly entry in install_guest_whole_teb uses Rust-computed TlsState offsets"
    )]
    fn restore_host_whole_teb(tls: &TlsState);
}

/// Captures the native TEB and stores `tls` in its runtime slot.
///
/// # Safety
///
/// The caller must ensure `tls` remains valid for the duration of its use.
pub(super) unsafe fn install_tls(tls: &TlsState) {
    let host_teb = current_teb();
    assert!(!host_teb.is_null(), "host TEB is not configured");
    tls.host_teb.set(host_teb);
    // SAFETY: The native TEB allocation covers the aligned runtime slot, and
    // the caller keeps tls alive until it is uninstalled.
    unsafe {
        teb_runtime_tls_slot(host_teb.addr()).write(core::ptr::from_ref(tls));
    }
}

/// Clears the current thread's post-TEB runtime slot.
pub(super) fn uninstall_tls() {
    // SAFETY: Teardown runs on the owning thread after host state was restored.
    unsafe {
        runtime_tls_slot().write(core::ptr::null());
    }
}

pub(super) fn get_tls_ptr() -> Option<*const TlsState> {
    // SAFETY: The aligned slot is within the native TEB allocation and is
    // accessed only by its owning thread. The pointer is not dereferenced here.
    let ptr = unsafe { runtime_tls_slot().read() };
    if ptr.is_null() {
        return None;
    }
    Some(ptr)
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "microbenchmark; run in release mode with --ignored --nocapture"]
    fn benchmark_teb_exchange_selective_vs_whole() {
        #[unsafe(naked)]
        unsafe extern "C" fn round_trips<const SELECTIVE: bool>(
            _tls: &super::TlsState,
            _iterations: usize,
        ) {
            core::arch::naked_asm!(
                "push rsi",
                "push rdi",
                "sub rsp, 40",
                "mov rsi, rcx",
                "mov rdi, rdx",
                "2:",
                "mov rcx, rsi",
                ".if {SELECTIVE}",
                "call {install_selective}",
                "mov rcx, rsi",
                "call {restore_selective}",
                ".else",
                "call {install_whole}",
                "mov rcx, rsi",
                "call {restore_whole}",
                ".endif",
                "dec rdi",
                "jnz 2b",
                "add rsp, 40",
                "pop rdi",
                "pop rsi",
                "ret",
                SELECTIVE = const SELECTIVE as usize,
                install_selective = sym super::install_guest_teb,
                restore_selective = sym super::restore_host_teb,
                install_whole = sym super::install_guest_whole_teb,
                restore_whole = sym super::restore_host_whole_teb,
            );
        }

        const ITERATIONS: usize = 500_000;
        const SAMPLES: usize = 21;
        assert!(
            !std::hint::black_box(super::USE_WHOLE_TEB_SWAP),
            "disable the whole-TEB fallback before benchmarking"
        );
        let tls = super::TlsState::new();
        let mut native = Box::new([0x1111_1111_1111_1111usize; super::GUEST_TEB_SIZE / 8]);
        let mut guest = Box::new([0x2222_2222_2222_2222usize; super::GUEST_TEB_SIZE / 8]);
        let guest_base = guest.as_mut_ptr().addr();
        for offset in super::TEB_INTERNAL_POINTER_OFFSETS {
            guest[offset / 8] = guest_base + offset;
        }
        let original_native = native.clone();
        let original_guest = guest.clone();
        tls.host_teb.set(native.as_mut_ptr().cast());
        tls.guest_teb.set(guest_base);
        // SAFETY: Both implementations use the same live, disjoint synthetic TEB
        // buffers and balanced transitions; GS and the real host TEB are untouched.
        unsafe {
            round_trips::<false>(&tls, 10_000);
            round_trips::<true>(&tls, 10_000);
        }
        let mut before = [0.0f64; SAMPLES];
        let mut after = [0.0f64; SAMPLES];
        for sample in 0..SAMPLES {
            for selective in [sample % 2 != 0, sample % 2 == 0] {
                let start = std::time::Instant::now();
                // SAFETY: Same validated buffers and balanced transitions as warmup.
                unsafe {
                    if selective {
                        round_trips::<true>(&tls, ITERATIONS);
                    } else {
                        round_trips::<false>(&tls, ITERATIONS);
                    }
                }
                let elapsed = start.elapsed().as_secs_f64() * 1e9
                    / f64::from(u32::try_from(ITERATIONS).unwrap());
                if selective {
                    after[sample] = elapsed;
                } else {
                    before[sample] = elapsed;
                }
                assert_eq!(native, original_native);
                assert_eq!(guest, original_guest);
            }
        }
        before.sort_by(f64::total_cmp);
        after.sort_by(f64::total_cmp);
        let selected_bytes: usize = super::TEB_SWAP_RANGES
            .iter()
            .map(|[start, end]| end - start)
            .sum();
        println!(
            "Warm-cache synthetic TEB round trip (install + restore), {SAMPLES} samples, {ITERATIONS} iterations/sample; alternating order"
        );
        println!(
            "Whole: {} bytes; median {:.2} ns, min {:.2}, max {:.2}",
            super::GUEST_TEB_SIZE,
            before[SAMPLES / 2],
            before[0],
            before[SAMPLES - 1],
        );
        println!(
            "Selective: {selected_bytes} bytes; median {:.2} ns, min {:.2}, max {:.2}",
            after[SAMPLES / 2],
            after[0],
            after[SAMPLES - 1],
        );
        println!(
            "Reduction: {:.2} ns ({:.1}%); speedup {:.2}x",
            before[SAMPLES / 2] - after[SAMPLES / 2],
            (1.0 - after[SAMPLES / 2] / before[SAMPLES / 2]) * 100.0,
            before[SAMPLES / 2] / after[SAMPLES / 2],
        );
    }

    #[test]
    fn configured_teb_exchange_preserves_selected_state() {
        check_teb_exchange(
            super::install_guest_teb,
            super::restore_host_teb,
            super::USE_WHOLE_TEB_SWAP,
        );
    }

    #[test]
    fn whole_teb_exchange_preserves_all_state() {
        check_teb_exchange(
            super::install_guest_whole_teb,
            super::restore_host_whole_teb,
            true,
        );
    }

    fn check_teb_exchange(
        install: unsafe extern "C" fn(&super::TlsState),
        restore: unsafe extern "C" fn(&super::TlsState),
        whole: bool,
    ) {
        let tls = super::TlsState::new();
        let mut native = Box::new([0x1111_1111_1111_1111usize; super::GUEST_TEB_SIZE / 8]);
        let mut guest = Box::new([0x2222_2222_2222_2222usize; super::GUEST_TEB_SIZE / 8]);
        let native_base = native.as_mut_ptr().addr();
        let guest_base = guest.as_mut_ptr().addr();
        for offset in super::TEB_INTERNAL_POINTER_OFFSETS {
            guest[offset / 8] = guest_base + offset;
        }
        let original_native = native.clone();
        let original_guest = guest.clone();
        tls.host_teb.set(native.as_mut_ptr().cast());
        tls.guest_teb.set(guest_base);

        // SAFETY: These disjoint, initialized buffers cover the modeled TEB.
        // The helper does not access GS, so the actual native TEB stays installed.
        unsafe { install(&tls) };
        for index in 0..native.len() {
            let offset = index * 8;
            let selected = whole
                || super::TEB_SWAP_RANGES
                    .iter()
                    .any(|&[start, end]| (start..end).contains(&offset));
            let expected = if super::TEB_INTERNAL_POINTER_OFFSETS.contains(&offset) {
                assert!(selected);
                native_base + offset
            } else if selected {
                original_guest[index]
            } else {
                original_native[index]
            };
            assert_eq!(native[index], expected, "offset {offset:#x}");
            if selected && !super::TEB_INTERNAL_POINTER_OFFSETS.contains(&offset) {
                native[index] = 0x3333_3333_3333_3333;
            }
        }
        // SAFETY: The same live buffers contain balanced host/guest states.
        unsafe { restore(&tls) };
        assert_eq!(native, original_native);
        for index in 0..guest.len() {
            let offset = index * 8;
            let selected = whole
                || super::TEB_SWAP_RANGES
                    .iter()
                    .any(|&[start, end]| (start..end).contains(&offset));
            let expected = if selected && !super::TEB_INTERNAL_POINTER_OFFSETS.contains(&offset) {
                0x3333_3333_3333_3333
            } else {
                original_guest[index]
            };
            assert_eq!(guest[index], expected, "offset {offset:#x}");
        }
    }
}
