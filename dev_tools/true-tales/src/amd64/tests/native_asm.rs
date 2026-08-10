// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(target_arch = "x86_64")]
unsafe fn byte_copy_asm(dst: &mut [u8], src: *mut u8) {
    let len: usize = dst.len();

    unsafe {
        core::arch::asm!(
            "2:", "mov al, byte ptr [rsi]",
            "3:", "mov byte ptr [rdi], al",
            "4:", "inc rdi",
            "5:", "inc rsi",
            "6:", "dec rcx",
            "7:", "jnz 2b",
            inout("rdi") dst.as_mut_ptr() => _,
            inout("rsi") src => _,
            inout("rcx") len => _,
            out("rax") _,
            options(nostack),
        );
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn byte_copy_native() {
    let mut src: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    let mut dst: [u8; 4] = [0; 4];

    let src_ptr: *mut u8 = src.as_mut_ptr();

    unsafe {
        byte_copy_asm(&mut dst, src_ptr);
    }

    assert_eq!(dst, src);
}

#[cfg(target_arch = "x86_64")]
unsafe fn byte_copy_fallible_asm(dst: &mut [u8], src: *mut u8) -> usize {
    let len: usize = dst.len();
    let err: usize;

    unsafe {
        core::arch::asm!(
            "xor edx, edx",
            "2:",
            "mov al, byte ptr [rsi]",
            "3:",
            "mov byte ptr [rdi], al",
            "4:",
            "inc rdi",
            "5:",
            "inc rsi",
            "6:",
            "dec rcx",
            "7:",
            "jnz 2b",
            "8:",
            "jmp 20f",
            "9:",
            "mov rdx, 1",
            "20:",
            inout("rdi") dst.as_mut_ptr() => _,
            inout("rsi") src => _,
            inout("rcx") len => _,
            out("rax") _,
            lateout("rdx") err,
            options(nostack),
        );
    }

    err
}

#[test]
#[cfg(target_arch = "x86_64")]
fn byte_copy_fallible_native_success() {
    let mut src: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    let mut dst: [u8; 4] = [0; 4];

    let src_ptr: *mut u8 = src.as_mut_ptr();

    let err = unsafe { byte_copy_fallible_asm(&mut dst, src_ptr) };

    assert_eq!(err, 0);
    assert_eq!(dst, src);
}
