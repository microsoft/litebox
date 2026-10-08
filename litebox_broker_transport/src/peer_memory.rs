// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Raw access to memory that a peer can modify concurrently.
//!
//! A peer process may write shared memory at any time, through an alias Rust
//! does not know about and with accesses of any width. Ordinary loads and
//! stores, and even Rust atomics, would race with those writes under Rust's
//! memory model, so these primitives perform each access in inline assembly,
//! which the compiler treats as an opaque hardware operation. No Rust reference
//! into peer-writable memory is ever formed: values are copied out as untrusted
//! snapshots for the caller to validate, and copied in from private buffers.
//!
//! Word operations are indivisible and ordered with respect to a peer that
//! uses matching atomic operations. A peer that does not can only corrupt the
//! values it shares, never the caller's memory safety.

use core::arch::asm;

/// Reads a `u32` with acquire semantics.
///
/// # Safety
///
/// `address` must be naturally aligned and readable for the whole call.
pub unsafe fn load_u32_acquire(address: *const u32) -> u32 {
    let value: u32;
    // SAFETY: Guaranteed by the caller. An aligned load is indivisible; on
    // x86-64, total store order makes every load an acquire load.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!(
            "mov {value:e}, dword ptr [{address}]",
            value = out(reg) value,
            address = in(reg) address,
            options(nostack, preserves_flags),
        );
    }
    // SAFETY: Guaranteed by the caller.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!(
            "ldar {value:w}, [{address}]",
            value = out(reg) value,
            address = in(reg) address,
            options(nostack, preserves_flags),
        );
    }
    value
}

/// Indivisibly increments a `u32` with release semantics, wrapping on
/// overflow.
///
/// # Safety
///
/// `address` must be naturally aligned and writable for the whole call.
pub unsafe fn increment_u32_release(address: *mut u32) {
    // SAFETY: Guaranteed by the caller. A locked read-modify-write is
    // indivisible and fully ordered on x86-64.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!(
            "lock inc dword ptr [{address}]",
            address = in(reg) address,
            options(nostack),
        );
    }
    // SAFETY: Guaranteed by the caller. The exclusive pair retries until the
    // increment is indivisible, and the store-release orders earlier accesses
    // before it. This avoids requiring the ARMv8.1 atomic instructions.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!(
            "2:",
            "ldxr {value:w}, [{address}]",
            "add {value:w}, {value:w}, #1",
            "stlxr {failed:w}, {value:w}, [{address}]",
            "cbnz {failed:w}, 2b",
            address = in(reg) address,
            value = out(reg) _,
            failed = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}

/// Reads a `u64` with acquire semantics.
///
/// # Safety
///
/// `address` must be naturally aligned and readable for the whole call.
pub unsafe fn load_u64_acquire(address: *const u64) -> u64 {
    let value: u64;
    // SAFETY: Guaranteed by the caller. An aligned load is indivisible; on
    // x86-64, total store order makes every load an acquire load.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!(
            "mov {value}, qword ptr [{address}]",
            value = out(reg) value,
            address = in(reg) address,
            options(nostack, preserves_flags),
        );
    }
    // SAFETY: Guaranteed by the caller.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!(
            "ldar {value}, [{address}]",
            value = out(reg) value,
            address = in(reg) address,
            options(nostack, preserves_flags),
        );
    }
    value
}

/// Writes a `u64` with release semantics.
///
/// # Safety
///
/// `address` must be naturally aligned and writable for the whole call.
pub unsafe fn store_u64_release(address: *mut u64, value: u64) {
    // SAFETY: Guaranteed by the caller. `xchg` with memory is indivisible and
    // fully ordered on x86-64.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!(
            "xchg qword ptr [{address}], {value}",
            address = in(reg) address,
            value = inout(reg) value => _,
            options(nostack, preserves_flags),
        );
    }
    // SAFETY: Guaranteed by the caller.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!(
            "stlr {value}, [{address}]",
            address = in(reg) address,
            value = in(reg) value,
            options(nostack, preserves_flags),
        );
    }
}

/// Copies `destination.len()` bytes from `source` into a private buffer.
///
/// The bytes are an untrusted snapshot that a concurrent peer write may tear.
/// The copy is unordered: callers order it against word operations with
/// [`core::sync::atomic::fence`].
///
/// # Safety
///
/// `source..source + destination.len()` must be readable for the whole call
/// and must not overlap `destination`.
pub unsafe fn copy_from_peer(source: *const u8, destination: &mut [u8]) {
    // SAFETY: Guaranteed by the caller.
    unsafe { copy(source, destination.as_mut_ptr(), destination.len()) };
}

/// Copies `source` into peer-visible memory at `destination`.
///
/// The copy is unordered: callers publish it with a later release operation.
///
/// # Safety
///
/// `destination..destination + source.len()` must be writable for the whole
/// call and must not overlap `source`.
pub unsafe fn copy_to_peer(source: &[u8], destination: *mut u8) {
    // SAFETY: Guaranteed by the caller.
    unsafe { copy(source.as_ptr(), destination, source.len()) };
}

/// Copies `length` bytes between non-overlapping ranges.
///
/// Each chunk is loaded completely before any of it is stored. A copy that
/// interleaves loads and stores, such as `rep movsb`, can stall on every access
/// when the destination's page offset sits just past the source's, because
/// the CPU mistakes the pair for a store-to-load dependency. Callers copy
/// between page-aligned shared buffers and arbitrarily aligned private ones, so
/// that case is common.
///
/// # Safety
///
/// `source` must be readable and `destination` writable for `length` bytes,
/// and the ranges must not overlap.
unsafe fn copy(source: *const u8, destination: *mut u8, length: usize) {
    let mut offset = 0;
    while length - offset >= CHUNK_SIZE {
        let (from, to) = (
            source.wrapping_add(offset),
            destination.wrapping_add(offset),
        );
        // SAFETY: Guaranteed by the caller for the remaining range.
        unsafe { copy_chunk(from, to) };
        offset += CHUNK_SIZE;
    }
    while length - offset >= size_of::<u64>() {
        let (from, to) = (
            source.wrapping_add(offset),
            destination.wrapping_add(offset),
        );
        // SAFETY: Guaranteed by the caller for the remaining range.
        unsafe { copy_word(from, to) };
        offset += size_of::<u64>();
    }
    while offset < length {
        let (from, to) = (
            source.wrapping_add(offset),
            destination.wrapping_add(offset),
        );
        // SAFETY: Guaranteed by the caller for the remaining range.
        unsafe { copy_byte(from, to) };
        offset += 1;
    }
}

const CHUNK_SIZE: usize = 64;

/// Copies [`CHUNK_SIZE`] bytes.
///
/// # Safety
///
/// As for [`copy`] with `length` equal to [`CHUNK_SIZE`].
unsafe fn copy_chunk(source: *const u8, destination: *mut u8) {
    // SAFETY: Guaranteed by the caller. SSE2 is part of the x86-64 baseline,
    // but kernel targets such as `x86_64-unknown-none` disable it.
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    unsafe {
        asm!(
            "movdqu {a}, xmmword ptr [{source}]",
            "movdqu {b}, xmmword ptr [{source} + 16]",
            "movdqu {c}, xmmword ptr [{source} + 32]",
            "movdqu {d}, xmmword ptr [{source} + 48]",
            "movdqu xmmword ptr [{destination}], {a}",
            "movdqu xmmword ptr [{destination} + 16], {b}",
            "movdqu xmmword ptr [{destination} + 32], {c}",
            "movdqu xmmword ptr [{destination} + 48], {d}",
            source = in(reg) source,
            destination = in(reg) destination,
            a = out(xmm_reg) _,
            b = out(xmm_reg) _,
            c = out(xmm_reg) _,
            d = out(xmm_reg) _,
            options(nostack, preserves_flags),
        );
    }
    // SAFETY: Guaranteed by the caller. Without SSE, general-purpose
    // registers copy each 32-byte half, still loading it before storing it.
    #[cfg(all(target_arch = "x86_64", not(target_feature = "sse2")))]
    unsafe {
        asm!(
            "mov {a}, qword ptr [{source}]",
            "mov {b}, qword ptr [{source} + 8]",
            "mov {c}, qword ptr [{source} + 16]",
            "mov {d}, qword ptr [{source} + 24]",
            "mov qword ptr [{destination}], {a}",
            "mov qword ptr [{destination} + 8], {b}",
            "mov qword ptr [{destination} + 16], {c}",
            "mov qword ptr [{destination} + 24], {d}",
            "mov {a}, qword ptr [{source} + 32]",
            "mov {b}, qword ptr [{source} + 40]",
            "mov {c}, qword ptr [{source} + 48]",
            "mov {d}, qword ptr [{source} + 56]",
            "mov qword ptr [{destination} + 32], {a}",
            "mov qword ptr [{destination} + 40], {b}",
            "mov qword ptr [{destination} + 48], {c}",
            "mov qword ptr [{destination} + 56], {d}",
            source = in(reg) source,
            destination = in(reg) destination,
            a = out(reg) _,
            b = out(reg) _,
            c = out(reg) _,
            d = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
    // SAFETY: Guaranteed by the caller. General-purpose registers keep this
    // usable on targets without floating-point registers.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!(
            "ldp {a}, {b}, [{source}]",
            "ldp {c}, {d}, [{source}, #16]",
            "ldp {e}, {f}, [{source}, #32]",
            "ldp {g}, {h}, [{source}, #48]",
            "stp {a}, {b}, [{destination}]",
            "stp {c}, {d}, [{destination}, #16]",
            "stp {e}, {f}, [{destination}, #32]",
            "stp {g}, {h}, [{destination}, #48]",
            source = in(reg) source,
            destination = in(reg) destination,
            a = out(reg) _,
            b = out(reg) _,
            c = out(reg) _,
            d = out(reg) _,
            e = out(reg) _,
            f = out(reg) _,
            g = out(reg) _,
            h = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}

/// Copies eight bytes.
///
/// # Safety
///
/// As for [`copy`] with `length` equal to eight.
unsafe fn copy_word(source: *const u8, destination: *mut u8) {
    // SAFETY: Guaranteed by the caller.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!(
            "mov {word}, qword ptr [{source}]",
            "mov qword ptr [{destination}], {word}",
            source = in(reg) source,
            destination = in(reg) destination,
            word = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
    // SAFETY: Guaranteed by the caller.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!(
            "ldr {word}, [{source}]",
            "str {word}, [{destination}]",
            source = in(reg) source,
            destination = in(reg) destination,
            word = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}

/// Copies one byte.
///
/// # Safety
///
/// As for [`copy`] with `length` equal to one.
unsafe fn copy_byte(source: *const u8, destination: *mut u8) {
    // SAFETY: Guaranteed by the caller.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!(
            "mov {byte}, byte ptr [{source}]",
            "mov byte ptr [{destination}], {byte}",
            source = in(reg) source,
            destination = in(reg) destination,
            byte = out(reg_byte) _,
            options(nostack, preserves_flags),
        );
    }
    // SAFETY: Guaranteed by the caller.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!(
            "ldrb {byte:w}, [{source}]",
            "strb {byte:w}, [{destination}]",
            source = in(reg) source,
            destination = in(reg) destination,
            byte = out(reg) _,
            options(nostack, preserves_flags),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_increments_are_indivisible() {
        const THREADS: u32 = 4;
        const INCREMENTS: u32 = 10_000;
        let mut counter = 0u32;
        let address = std::ptr::from_mut(&mut counter).expose_provenance();
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(move || {
                    for _ in 0..INCREMENTS {
                        let shared = std::ptr::with_exposed_provenance_mut(address);
                        // SAFETY: `counter` outlives the scope, is aligned, and
                        // is only accessed through these increments meanwhile.
                        unsafe { increment_u32_release(shared) };
                    }
                });
            }
        });
        assert_eq!(counter, INCREMENTS * THREADS);
    }

    #[test]
    fn copies_cover_every_length_and_alignment() {
        let source: alloc::vec::Vec<u8> = (0..=255u8).collect();
        for start in 0..8 {
            for length in 0..(source.len() - start) {
                let mut shared = [0xffu8; 256];
                // SAFETY: Both ranges are live, in bounds, and disjoint.
                unsafe {
                    copy_to_peer(
                        &source[start..start + length],
                        shared.as_mut_ptr().add(start),
                    );
                };
                assert_eq!(
                    &shared[start..start + length],
                    &source[start..start + length]
                );
                assert!(shared[..start].iter().all(|&byte| byte == 0xff));
                assert!(shared[start + length..].iter().all(|&byte| byte == 0xff));
                let mut private = alloc::vec![0u8; length];
                // SAFETY: Both ranges are live, in bounds, and disjoint.
                unsafe { copy_from_peer(shared.as_ptr().add(start), &mut private) };
                assert_eq!(private, &source[start..start + length]);
            }
        }
    }
}
