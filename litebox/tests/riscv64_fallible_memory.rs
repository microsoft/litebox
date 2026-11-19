// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(all(target_os = "linux", target_arch = "riscv64"))]

use litebox::mm::exception_table::*;
use litebox::utils::TruncateExt as _;
use std::ptr;
use zerocopy::IntoBytes as _;

#[test]
fn scalar_accesses_preserve_width_at_any_alignment() {
    let mut storage = [0u64; 2];
    let bytes = storage.as_mut_bytes();
    macro_rules! check {
        ($read:ident, $write:ident, $value:expr) => {{
            let value = $value;
            for offset in 0..size_of_val(&value) {
                bytes.fill(0x55);
                let dst = bytes.as_mut_ptr().wrapping_add(offset).cast();
                // SAFETY: dst covers one value inside storage; no reference to it is in use.
                unsafe { $write(dst, value).unwrap() };
                let end = offset + size_of_val(&value);
                assert_eq!(&bytes[offset..end], value.to_ne_bytes());
                assert!(
                    bytes[..offset]
                        .iter()
                        .chain(&bytes[end..])
                        .all(|&b| b == 0x55)
                );
                // SAFETY: Same initialized range, reborrowed after checking the bytes.
                assert_eq!(
                    unsafe { $read(bytes.as_ptr().wrapping_add(offset).cast()) }.unwrap(),
                    value
                );
            }
        }};
    }
    check!(read_u8_fallible, write_u8_fallible, 0xadu8);
    check!(read_u16_fallible, write_u16_fallible, 0xab07u16);
    check!(read_u32_fallible, write_u32_fallible, 0x890a_bcdeu32);
    check!(
        read_u64_fallible,
        write_u64_fallible,
        0x8123_4567_89ab_cdefu64
    );
}

#[test]
fn aligned_copy_includes_byte_tail() {
    let src = [0x1122_3344_5566_7788u64; 3];
    let mut dst = [0u64; 3];
    // SAFETY: These disjoint, aligned buffers each hold 24 bytes.
    unsafe { memcpy_fallible(dst.as_mut_ptr().cast(), src.as_ptr().cast(), 17) }.unwrap();
    assert_eq!(&dst.as_bytes()[..17], &src.as_bytes()[..17]);
    assert_eq!(&dst.as_bytes()[17..], &[0; 7]);
}

extern "C" fn recover(signal: libc::c_int, _: *mut libc::siginfo_t, context: *mut libc::c_void) {
    // SAFETY: SA_SIGINFO supplies the interrupted thread's writable ucontext.
    let pc =
        unsafe { &mut (*context.cast::<libc::ucontext_t>()).uc_mcontext.__gregs[libc::REG_PC] };
    if let Some(resume) = search_exception_tables((*pc).trunc()) {
        *pc = resume as libc::c_ulong;
    } else {
        // SAFETY: An unexpected fault must fail the test, not loop; _exit is async-signal-safe.
        unsafe { libc::_exit(128 + signal) };
    }
}

// libc may leave fields or unused signal-mask bytes uninitialized. Only libc
// interprets its saved action; do not turn it back into a Rust sigaction.
type SavedAction = std::mem::MaybeUninit<libc::sigaction>;
struct Restore(*mut libc::c_void, usize, SavedAction);
impl Drop for Restore {
    fn drop(&mut self) {
        // SAFETY: Restore the previously installed action and release the entire private mapping.
        unsafe {
            libc::sigaction(libc::SIGSEGV, self.2.as_ptr(), ptr::null_mut());
            libc::munmap(self.0, self.1);
        }
    }
}

#[test]
fn recovers_from_scalar_and_copy_faults() {
    // SAFETY: sysconf takes no pointer arguments for this query.
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
    // SAFETY: Request two private pages; the second remains inaccessible for the test.
    let base = unsafe {
        libc::mmap(
            ptr::null_mut(),
            2 * page,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(base, libc::MAP_FAILED);
    // SAFETY: The first page belongs to this mapping.
    assert_eq!(
        unsafe { libc::mprotect(base, page, libc::PROT_READ | libc::PROT_WRITE) },
        0
    );
    let guard = base.cast::<u8>().wrapping_add(page);

    // SAFETY: A zeroed sigaction with an empty mask and SA_SIGINFO selects the three-argument ABI.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_flags = libc::SA_SIGINFO;
    action.sa_sigaction = recover as *const () as usize;
    let mut old = SavedAction::new(action);
    // SAFETY: Both action buffers have the sigaction layout and recover lives for the whole test.
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGSEGV, &raw const action, old.as_mut_ptr()) },
        0
    );
    let _restore = Restore(base, 2 * page, old);

    // SAFETY: All guest pointers refer to our non-Rust mapping. Only the fallible
    // primitives access the protected page, under the recovery handler above.
    unsafe {
        assert!(read_u8_fallible(guard).is_err());
        assert!(write_u8_fallible(guard, 1).is_err());
        assert!(read_u16_fallible(guard.cast()).is_err());
        assert!(write_u16_fallible(guard.cast(), 1).is_err());
        assert!(read_u32_fallible(guard.cast()).is_err());
        assert!(write_u32_fallible(guard.cast(), 1).is_err());
        assert!(read_u64_fallible(guard.cast()).is_err());
        assert!(write_u64_fallible(guard.cast(), 1).is_err());
        assert!(read_u64_fallible(guard.sub(1).cast()).is_err());
        assert!(write_u64_fallible(guard.sub(1).cast(), 1).is_err());

        memcpy_fallible(guard, guard, 0).unwrap();
        let mut words = [0u64; 2];
        let bytes = words.as_mut_bytes();
        // Aligned doubleword loop and unaligned byte loop, faulting on both sides.
        for prefix in [8, 7] {
            let guest = guard.sub(prefix);
            bytes.fill(0xab);
            memcpy_fallible(guest, bytes.as_ptr(), prefix).unwrap();
            assert!(memcpy_fallible(guest, bytes.as_ptr(), bytes.len()).is_err());
            bytes.fill(0);
            assert!(memcpy_fallible(bytes.as_mut_ptr(), guest, bytes.len()).is_err());
            assert_eq!(&bytes[..prefix], &([0xab; 8])[..prefix]);
            assert!(bytes[prefix..].iter().all(|&b| b == 0));
        }
    }
}
