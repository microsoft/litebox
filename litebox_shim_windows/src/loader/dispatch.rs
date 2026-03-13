// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Function dispatch system for Windows API implementations
//!
//! This module provides a trampoline-based dispatch system that:
//! 1. Allocates executable memory for function stubs
//! 2. Creates trampolines that redirect Windows API calls to Linux implementations
//! 3. Handles calling convention translation between Windows x64 and System V AMD64
//!
//! ## Calling Convention Differences
//!
//! Windows x64:
//! - Parameters: RCX, RDX, R8, R9, then stack (right-to-left)
//! - Return value: RAX (integers), XMM0 (floats)
//! - Caller must allocate 32 bytes of "shadow space" on stack
//! - Volatile registers: RAX, RCX, RDX, R8-R11, XMM0-XMM5
//! - Non-volatile: RBX, RBP, RDI, RSI, RSP, R12-R15, XMM6-XMM15
//!
//! System V AMD64 (Linux):
//! - Parameters: RDI, RSI, RDX, RCX, R8, R9, then stack (right-to-left)
//! - Return value: RAX (integers), XMM0 (floats)
//! - No shadow space requirement
//! - Volatile registers: RAX, RCX, RDX, RSI, RDI, R8-R11, XMM0-XMM15
//! - Non-volatile: RBX, RBP, RSP, R12-R15
//!
//! ## Trampoline Approach
//!
//! For each Windows API function, we generate a small assembly stub that:
//! 1. Translates registers from Windows calling convention to Linux
//! 2. Calls the actual implementation function
//! 3. Returns the result in the expected register (RAX)
//!
//! Example trampoline for a function with 2 parameters:
//! ```asm
//! ; On entry: RCX = param1, RDX = param2 (Windows)
//! ; Need to call with: RDI = param1, RSI = param2 (Linux)
//! mov rdi, rcx    ; param1: Windows RCX -> Linux RDI
//! mov rsi, rdx    ; param2: Windows RDX -> Linux RSI
//! mov rax, <impl_address>
//! jmp rax         ; Tail call to implementation
//! ```

use crate::{Result, WindowsShimError};
extern crate alloc;
use alloc::vec::Vec;

/// Function pointer type for actual implementations
pub type ImplFunction = usize;

/// Generate x86-64 machine code for a trampoline that adapts calling conventions
///
/// This generates a stub that:
/// 1. Saves Windows callee-saved registers `RDI` and `RSI` (volatile in System V ABI)
/// 2. Ensures 16-byte stack alignment (System V ABI requirement)
/// 3. Moves parameters from Windows x64 registers/stack to System V AMD64 registers/stack:
///    - Windows RCX/RDX/R8/R9 (params 1-4) → Linux RDI/RSI/RDX/RCX
///    - Windows stack params 5-6 → Linux R8/R9 (register params in System V)
///    - Windows stack params 7+ → Linux stack at [RSP+0], [RSP+8], ...
/// 4. Calls the actual implementation
/// 5. Restores `RDI` and `RSI` before returning
///
/// ## Callee-saved register differences (why this matters)
///
/// Windows x64 callee-saved: `RBX`, `RBP`, `RDI`, `RSI`, `RSP`, `R12`-`R15`, `XMM6`-`XMM15`\
/// System V AMD64 callee-saved: `RBX`, `RBP`, `RSP`, `R12`-`R15`
///
/// `RDI` and `RSI` are callee-saved in Windows but caller-saved (volatile) in Linux.
/// Without explicit save/restore, Linux implementations can freely clobber `RSI`/`RDI`,
/// corrupting Windows code that relies on those registers being preserved across API calls.
///
/// ## Example stub (2 parameters):
/// ```asm
/// push rdi              ; save Windows callee-saved RDI (RSP%16: 8→0)
/// push rsi              ; save Windows callee-saved RSI (RSP%16: 0→8)
/// sub  rsp, 8           ; 16-byte align for System V call (RSP%16: 8→0)
/// mov  rdi, rcx         ; param1: Windows RCX → Linux RDI
/// mov  rsi, rdx         ; param2: Windows RDX → Linux RSI
/// movabs rax, <impl>
/// call rax
/// add  rsp, 8           ; undo alignment
/// pop  rsi              ; restore RSI
/// pop  rdi              ; restore RDI
/// ret
/// ```
///
/// # Parameters
/// * `num_params` - Number of integer/pointer parameters (0-8 supported)
/// * `impl_address` - Address of the actual implementation function
///
/// # Returns
/// Machine code bytes for the trampoline
///
/// # Safety
/// The returned bytes must be placed in executable memory and executed
/// from Windows x64 calling convention code.
pub fn generate_trampoline(num_params: usize, impl_address: u64) -> Vec<u8> {
    let mut code = Vec::new();

    // Register mapping:
    //   Windows x64: RCX, RDX, R8, R9, then stack at [RSP+40], [RSP+48], ...
    //     (shadow space 32 bytes + return address 8 bytes = first stack param at RSP+40)
    //   Linux x64:   RDI, RSI, RDX, RCX, R8, R9, then stack at [RSP+0], [RSP+8], ...

    // === PROLOGUE ===
    // Save Windows callee-saved registers that Linux treats as volatile (RDI and RSI).
    //
    // Stack alignment accounting:
    //   - At trampoline entry: RSP % 16 == 8  (return address on stack)
    //   - After push rdi:      RSP % 16 == 0
    //   - After push rsi:      RSP % 16 == 8  (misaligned)
    //   - After sub rsp, 8:    RSP % 16 == 0  (aligned for System V call)

    code.push(0x57); // push rdi
    code.push(0x56); // push rsi
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x08]); // sub rsp, 8

    // Stack layout after prologue (RSP = RSP_entry - 24):
    //   RSP + 0:  alignment padding (8 bytes)
    //   RSP + 8:  saved rsi
    //   RSP + 16: saved rdi
    //   RSP + 24: return address     (= RSP_entry + 0)
    //   RSP + 32: Windows shadow[0]  (= RSP_entry + 8)
    //   RSP + 40: Windows shadow[1]
    //   RSP + 48: Windows shadow[2]
    //   RSP + 56: Windows shadow[3]
    //   RSP + 64: Windows param 5    (= RSP_entry + 40)
    //   RSP + 72: Windows param 6    (= RSP_entry + 48)
    //   RSP + 80: Windows param 7    (= RSP_entry + 56)
    //   RSP + 88: Windows param 8    (= RSP_entry + 64)

    // === LINUX STACK PARAMETERS (params 7+) ===
    // System V uses RDI,RSI,RDX,RCX,R8,R9 for the first 6 params (not 4 like Windows).
    // Only params 7+ need to go on the Linux stack.
    let linux_stack_params = num_params.saturating_sub(6);

    let stack_extra: usize; // additional RSP adjustment for Linux stack params
    if linux_stack_params > 0 {
        // Allocate aligned stack space for Linux stack params.
        // RSP is currently 16-byte aligned; linux_stack_params * 8 bytes rounded up to 16.
        let align_pad = if linux_stack_params % 2 == 1 {
            8usize
        } else {
            0
        };
        stack_extra = linux_stack_params * 8 + align_pad;

        // sub rsp, stack_extra
        #[allow(clippy::cast_possible_truncation)]
        if stack_extra <= 127 {
            code.extend_from_slice(&[0x48, 0x83, 0xEC, stack_extra as u8]);
        } else {
            code.extend_from_slice(&[0x48, 0x81, 0xEC]);
            code.extend_from_slice(&(stack_extra as u32).to_le_bytes());
        }

        // Copy each Linux stack param (params 7+) from the Windows stack.
        // After sub rsp, stack_extra:
        //   Windows param (7+i) is at [RSP + stack_extra + 80 + i*8]
        //   Linux stack param i goes at [RSP + i*8]
        #[allow(clippy::cast_possible_truncation)]
        for i in 0..linux_stack_params {
            let win_offset = stack_extra + 80 + i * 8;
            let linux_offset = i * 8;

            // mov rax, [rsp + win_offset]
            if win_offset <= 127 {
                code.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, win_offset as u8]);
            } else {
                code.extend_from_slice(&[0x48, 0x8B, 0x84, 0x24]);
                code.extend_from_slice(&(win_offset as u32).to_le_bytes());
            }

            // mov [rsp + linux_offset], rax
            if linux_offset <= 127 {
                code.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, linux_offset as u8]);
            } else {
                code.extend_from_slice(&[0x48, 0x89, 0x84, 0x24]);
                code.extend_from_slice(&(linux_offset as u32).to_le_bytes());
            }
        }
    } else {
        stack_extra = 0;
    }

    // === REGISTER PARAMETERS 1-4 ===
    // Windows RCX/RDX/R8/R9 → Linux RDI/RSI/RDX/RCX
    // Order: params 1 and 2 FIRST (RDI ← RCX, RSI ← RDX) before RCX/RDX are
    // overwritten by the param 3/4 moves.
    if num_params >= 1 {
        code.extend_from_slice(&[0x48, 0x89, 0xCF]); // mov rdi, rcx
    }
    if num_params >= 2 {
        code.extend_from_slice(&[0x48, 0x89, 0xD6]); // mov rsi, rdx
    }
    if num_params >= 3 {
        code.extend_from_slice(&[0x4C, 0x89, 0xC2]); // mov rdx, r8
    }
    if num_params >= 4 {
        code.extend_from_slice(&[0x4C, 0x89, 0xC9]); // mov rcx, r9
    }

    // === REGISTER PARAMETERS 5-6 ===
    // R8 and R9 are now free (their original values were moved to RDX/RCX above).
    // Load Windows params 5 and 6 from the stack into Linux R8 and R9.
    // After the prologue and any stack_extra: Windows param 5 is at [RSP + stack_extra + 64].
    if num_params >= 5 {
        let p5_offset = stack_extra + 64;
        // mov r8, [rsp + p5_offset]
        #[allow(clippy::cast_possible_truncation)]
        if p5_offset <= 127 {
            code.extend_from_slice(&[0x4C, 0x8B, 0x44, 0x24, p5_offset as u8]);
        } else {
            code.extend_from_slice(&[0x4C, 0x8B, 0x84, 0x24]);
            code.extend_from_slice(&(p5_offset as u32).to_le_bytes());
        }
    }
    if num_params >= 6 {
        let p6_offset = stack_extra + 72;
        // mov r9, [rsp + p6_offset]
        #[allow(clippy::cast_possible_truncation)]
        if p6_offset <= 127 {
            code.extend_from_slice(&[0x4C, 0x8B, 0x4C, 0x24, p6_offset as u8]);
        } else {
            code.extend_from_slice(&[0x4C, 0x8B, 0x8C, 0x24]);
            code.extend_from_slice(&(p6_offset as u32).to_le_bytes());
        }
    }

    // === CALL ===
    code.extend_from_slice(&[0x48, 0xB8]); // movabs rax, impl_address
    code.extend_from_slice(&impl_address.to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xD0]); // call rax

    // === EPILOGUE ===
    // Undo the Linux stack allocation plus the prologue's alignment sub.
    let epilogue_add = stack_extra + 8; // stack_extra + prologue's "sub rsp, 8"
    #[allow(clippy::cast_possible_truncation)]
    if epilogue_add <= 127 {
        code.extend_from_slice(&[0x48, 0x83, 0xC4, epilogue_add as u8]); // add rsp, N
    } else {
        code.extend_from_slice(&[0x48, 0x81, 0xC4]);
        code.extend_from_slice(&(epilogue_add as u32).to_le_bytes());
    }
    code.push(0x5E); // pop rsi
    code.push(0x5F); // pop rdi
    code.push(0xC3); // ret

    code
}

/// Allocate executable memory for trampolines
///
/// NOTE: This function is a placeholder. Actual allocation must be done
/// by the platform layer (e.g., LinuxPlatformForWindows) which has access
/// to system calls like mmap.
///
/// The platform should allocate memory with PROT_READ | PROT_WRITE | PROT_EXEC
/// permissions.
///
/// # Safety
/// This function allocates memory with execute permissions, which is inherently
/// dangerous. The caller must ensure that only valid machine code is written
/// to this memory.
///
/// # Arguments
/// * `_size` - Size of memory to allocate in bytes (unused in this stub)
///
/// # Returns
/// An error indicating that allocation must be done by the platform layer
pub unsafe fn allocate_executable_memory(_size: usize) -> Result<u64> {
    Err(WindowsShimError::UnsupportedFeature(
        "Executable memory allocation must be done by the platform layer".to_string(),
    ))
}

/// Generate x86-64 trampoline with floating-point parameter support
///
/// This generates a stub that:
/// 1. Ensures 16-byte stack alignment
/// 2. Moves integer parameters from Windows to Linux registers
/// 3. Moves floating-point parameters from Windows to Linux XMM registers
/// 4. Handles stack parameters for 5+ parameter functions
///
/// # Parameters
/// * `num_int_params` - Number of integer/pointer parameters
/// * `_num_fp_params` - Reserved for future use (currently ignored)
/// * `impl_address` - Address of the actual implementation function
///
/// # Returns
/// Machine code bytes for the trampoline
///
/// # Floating-Point Register Mapping
/// Windows x64 and System V AMD64 both use XMM0-XMM7 for FP parameters,
/// BUT the parameter ordering differs:
/// - Windows: First 4 params use RCX/XMM0, RDX/XMM1, R8/XMM2, R9/XMM3 (mixed)
/// - Linux: First 6 int params use RDI, RSI, RDX, RCX, R8, R9; first 8 FP use XMM0-XMM7
///
/// For simplicity, this implementation assumes XMM registers don't need translation
/// (already in XMM0-XMM3), which is correct for most common cases.
///
/// # Safety
/// The returned bytes must be placed in executable memory.
pub fn generate_trampoline_with_fp(
    num_int_params: usize,
    _num_fp_params: usize,
    impl_address: u64,
) -> Vec<u8> {
    // For now, floating-point parameters in XMM registers don't need translation
    // because both Windows and Linux use XMM0-XMM7 for FP parameters.
    // The main difference is in how they're mixed with integer parameters,
    // but for simple cases where FP params are the first few parameters,
    // they're already in the right XMM registers.
    //
    // Future enhancement: Handle complex mixed parameter scenarios

    // Just use the regular trampoline for integer parameters
    generate_trampoline(num_int_params, impl_address)
}

/// Write machine code to executable memory
///
/// # Safety
/// This function writes arbitrary bytes to executable memory. The caller must
/// ensure that:
/// - The memory was allocated with execute permissions
/// - The bytes represent valid machine code
/// - The destination has enough space for the code
///
/// # Arguments
/// * `dest` - Destination address in executable memory
/// * `code` - Machine code bytes to write
pub unsafe fn write_to_executable_memory(dest: u64, code: &[u8]) {
    let dest_ptr = dest as *mut u8;
    // SAFETY: The caller guarantees dest is valid executable memory
    // with sufficient space for code.len() bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(code.as_ptr(), dest_ptr, code.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Prologue bytes: push rdi (57), push rsi (56), sub rsp,8 (48 83 EC 08) = 6 bytes
    const PROLOGUE: &[u8] = &[0x57, 0x56, 0x48, 0x83, 0xEC, 0x08];
    /// Epilogue tail (without add rsp): pop rsi (5E), pop rdi (5F), ret (C3) = 3 bytes
    const EPILOGUE_TAIL: &[u8] = &[0x5E, 0x5F, 0xC3];
    /// call rax = FF D0
    const CALL_RAX: &[u8] = &[0xFF, 0xD0];
    /// movabs rax prefix = 48 B8
    const MOVABS_RAX: &[u8] = &[0x48, 0xB8];
    /// add rsp, 8 = 48 83 C4 08
    const ADD_RSP_8: &[u8] = &[0x48, 0x83, 0xC4, 0x08];

    /// All trampolines must start with the RSI/RDI save prologue.
    fn assert_has_prologue(code: &[u8]) {
        assert!(
            code.len() >= PROLOGUE.len(),
            "Code too short to contain prologue"
        );
        assert_eq!(
            &code[..PROLOGUE.len()],
            PROLOGUE,
            "Code must start with push rdi; push rsi; sub rsp,8"
        );
    }

    /// All trampolines must end with pop rsi; pop rdi; ret.
    fn assert_has_epilogue_tail(code: &[u8]) {
        let n = code.len();
        assert!(
            n >= EPILOGUE_TAIL.len(),
            "Code too short to contain epilogue"
        );
        assert_eq!(
            &code[n - EPILOGUE_TAIL.len()..],
            EPILOGUE_TAIL,
            "Code must end with pop rsi; pop rdi; ret"
        );
    }

    #[test]
    fn test_generate_trampoline_0_params() {
        let code = generate_trampoline(0, 0x1234_5678_9ABC_DEF0);
        // prologue(6) + movabs(10) + call(2) + add rsp,8(4) + epilogue_tail(3) = 25 bytes
        assert_eq!(code.len(), 25);
        assert_has_prologue(&code);
        assert_has_epilogue_tail(&code);
        // movabs rax starts right after the 6-byte prologue
        assert_eq!(&code[6..8], MOVABS_RAX);
        // all trampolines use 'call rax', never 'jmp rax'
        assert!(
            code.windows(2).any(|w| w == CALL_RAX),
            "Must use 'call rax', not 'jmp rax'"
        );
        assert!(
            !code.windows(2).any(|w| w == [0xFF, 0xE0]),
            "Must NOT use 'jmp rax'"
        );
        // epilogue must contain 'add rsp, 8' to undo the prologue's 'sub rsp, 8'
        assert!(
            code.windows(ADD_RSP_8.len()).any(|w| w == ADD_RSP_8),
            "Epilogue must contain 'add rsp, 8'"
        );
    }

    #[test]
    fn test_generate_trampoline_1_param() {
        let code = generate_trampoline(1, 0x1234_5678_9ABC_DEF0);
        // prologue(6) + mov rdi,rcx(3) + movabs(10) + call(2) + add rsp,8(4) + tail(3) = 28
        assert_eq!(code.len(), 28);
        assert_has_prologue(&code);
        assert_has_epilogue_tail(&code);
        // mov rdi, rcx (48 89 CF) right after prologue
        assert_eq!(&code[6..9], &[0x48, 0x89, 0xCF]);
    }

    #[test]
    fn test_generate_trampoline_2_params() {
        let code = generate_trampoline(2, 0x1234_5678_9ABC_DEF0);
        // prologue(6) + mov rdi(3) + mov rsi(3) + movabs(10) + call(2) + add(4) + tail(3) = 31
        assert_eq!(code.len(), 31);
        assert_has_prologue(&code);
        assert_has_epilogue_tail(&code);
        // mov rdi, rcx
        assert_eq!(&code[6..9], &[0x48, 0x89, 0xCF]);
        // mov rsi, rdx
        assert_eq!(&code[9..12], &[0x48, 0x89, 0xD6]);
    }

    #[test]
    fn test_generate_trampoline_3_params() {
        let code = generate_trampoline(3, 0x1234_5678_9ABC_DEF0);
        // prologue(6) + mov rdi(3) + mov rsi(3) + mov rdx,r8(3) + movabs(10) + call(2) + add(4) + tail(3) = 34
        assert_eq!(code.len(), 34);
        assert_has_prologue(&code);
        assert_has_epilogue_tail(&code);
        assert_eq!(&code[6..9], &[0x48, 0x89, 0xCF]); // mov rdi, rcx
        assert_eq!(&code[9..12], &[0x48, 0x89, 0xD6]); // mov rsi, rdx
        assert_eq!(&code[12..15], &[0x4C, 0x89, 0xC2]); // mov rdx, r8
    }

    #[test]
    fn test_generate_trampoline_4_params() {
        let code = generate_trampoline(4, 0x1234_5678_9ABC_DEF0);
        // prologue(6) + 4×mov(12) + movabs(10) + call(2) + add(4) + tail(3) = 37
        assert_eq!(code.len(), 37);
        assert_has_prologue(&code);
        assert_has_epilogue_tail(&code);
        // All trampolines now use 'call rax', not 'jmp rax'
        assert!(
            code.windows(2).any(|w| w == CALL_RAX),
            "4-param trampoline must use 'call rax'"
        );
        assert!(
            !code.windows(2).any(|w| w == [0xFF, 0xE0]),
            "4-param trampoline must NOT use 'jmp rax'"
        );
    }

    #[test]
    fn test_generate_trampoline_5_params() {
        let code = generate_trampoline(5, 0x1234_5678_9ABC_DEF0);
        // 5 params: all fit in Linux registers (RDI,RSI,RDX,RCX,R8) – no Linux stack params.
        // prologue(6) + 4×reg_mov(12) + mov r8,[rsp+64](5) + movabs(10) + call(2) + add(4) + tail(3) = 42
        assert_eq!(code.len(), 42);
        assert_has_prologue(&code);
        assert_has_epilogue_tail(&code);
        assert!(
            code.windows(2).any(|w| w == CALL_RAX),
            "Should use 'call rax'"
        );
        // 'mov r8, [rsp+64]' = 4C 8B 44 24 40
        let has_load_r8 = code.windows(5).any(|w| w == [0x4C, 0x8B, 0x44, 0x24, 0x40]);
        assert!(has_load_r8, "Should load param5 into R8 from [rsp+64]");
    }

    #[test]
    fn test_generate_trampoline_6_params() {
        let code = generate_trampoline(6, 0x1234_5678_9ABC_DEF0);
        // 6 params: all in Linux registers – no Linux stack params.
        // prologue(6) + 4×reg_mov(12) + mov r8(5) + mov r9(5) + movabs(10) + call(2) + add(4) + tail(3) = 47
        assert_eq!(code.len(), 47);
        assert_has_prologue(&code);
        assert_has_epilogue_tail(&code);
        assert!(
            code.windows(2).any(|w| w == CALL_RAX),
            "Should use 'call rax'"
        );
        // 'mov r9, [rsp+72]' = 4C 8B 4C 24 48
        let has_load_r9 = code.windows(5).any(|w| w == [0x4C, 0x8B, 0x4C, 0x24, 0x48]);
        assert!(has_load_r9, "Should load param6 into R9 from [rsp+72]");
    }

    #[test]
    fn test_generate_trampoline_8_params() {
        let code = generate_trampoline(8, 0x1234_5678_9ABC_DEF0);
        // 8 params: linux_stack_params=2, align_pad=0, stack_extra=16
        // prologue(6) + sub rsp,16(4) + 2×(mov rax+mov store)(10) + 4×reg_mov(12) +
        //   mov r8(5) + mov r9(5) + movabs(10) + call(2) + add rsp,24(4) + tail(3) = 71
        assert_eq!(code.len(), 71);
        assert_has_prologue(&code);
        assert_has_epilogue_tail(&code);
        assert!(
            code.windows(2).any(|w| w == CALL_RAX),
            "Should use 'call rax'"
        );
        // epilogue add rsp, 24 (stack_extra=16, +8 prologue = 24 = 0x18)
        let has_add_24 = code.windows(4).any(|w| w == [0x48, 0x83, 0xC4, 0x18]);
        assert!(
            has_add_24,
            "Epilogue should add rsp, 24 for 8-param function"
        );
    }

    #[test]
    fn test_stack_params_go_to_registers_not_stack() {
        // Params 5 and 6 should go to Linux R8 and R9 (register params in System V),
        // NOT onto the Linux stack as the old implementation incorrectly did.
        let code5 = generate_trampoline(5, 0x1234_5678_9ABC_DEF0);
        let code6 = generate_trampoline(6, 0x1234_5678_9ABC_DEF0);

        // For 5 params there should be no 'sub rsp' beyond the prologue's 'sub rsp, 8'
        // (prologue sub rsp,8 is at bytes 2-5; no second sub rsp should appear)
        let sub_rsp_count = code5
            .windows(3)
            .filter(|w| w == &[0x48, 0x83, 0xEC])
            .count();
        assert_eq!(
            sub_rsp_count, 1,
            "5-param trampoline should only have the prologue sub rsp,8"
        );
        let sub_rsp_count6 = code6
            .windows(3)
            .filter(|w| w == &[0x48, 0x83, 0xEC])
            .count();
        assert_eq!(
            sub_rsp_count6, 1,
            "6-param trampoline should only have the prologue sub rsp,8"
        );
    }

    #[test]
    fn test_linux_stack_params_for_7_plus_params() {
        // 7 params: linux_stack_params=1, stack_extra=16 (8 param + 8 align pad)
        let code7 = generate_trampoline(7, 0x1234_5678_9ABC_DEF0);
        assert_has_prologue(&code7);
        assert_has_epilogue_tail(&code7);
        // sub rsp, 16 for linux stack allocation: 48 83 EC 10
        let has_sub_16 = code7.windows(4).any(|w| w == [0x48, 0x83, 0xEC, 0x10]);
        assert!(
            has_sub_16,
            "7-param trampoline should sub rsp,16 for stack_extra"
        );

        // 8 params: linux_stack_params=2, stack_extra=16 (2 params, no extra pad)
        let code8 = generate_trampoline(8, 0x1234_5678_9ABC_DEF0);
        let has_sub_16_8 = code8.windows(4).any(|w| w == [0x48, 0x83, 0xEC, 0x10]);
        assert!(
            has_sub_16_8,
            "8-param trampoline should sub rsp,16 for stack_extra"
        );
    }

    #[test]
    fn test_rdi_rsi_save_restore_present() {
        // Every trampoline must save RSI/RDI in prologue and restore in epilogue.
        for n in 0..=8 {
            let code = generate_trampoline(n, 0xDEAD_BEEF_1234_5678);
            // Prologue starts with: push rdi (57), push rsi (56)
            assert_eq!(
                code[0], 0x57,
                "param count {n}: first byte must be 'push rdi' (0x57)"
            );
            assert_eq!(
                code[1], 0x56,
                "param count {n}: second byte must be 'push rsi' (0x56)"
            );
            // Epilogue ends with: pop rsi (5E), pop rdi (5F), ret (C3)
            let n_bytes = code.len();
            assert_eq!(
                code[n_bytes - 3],
                0x5E,
                "param count {n}: third-from-last byte must be 'pop rsi' (0x5E)"
            );
            assert_eq!(
                code[n_bytes - 2],
                0x5F,
                "param count {n}: second-from-last byte must be 'pop rdi' (0x5F)"
            );
            assert_eq!(
                code[n_bytes - 1],
                0xC3,
                "param count {n}: last byte must be 'ret' (0xC3)"
            );
            // No trampoline should use 'jmp rax' anymore
            assert!(
                !code.windows(2).any(|w| w == [0xFF, 0xE0]),
                "param count {n}: must NOT use 'jmp rax'"
            );
        }
    }

    #[test]
    fn test_generate_trampoline_with_fp() {
        // Test FP parameter handling
        let code = generate_trampoline_with_fp(2, 2, 0x1234_5678_9ABC_DEF0);
        // Should generate code for 2 integer parameters
        // FP parameters are already in correct XMM registers
        assert!(!code.is_empty());
        assert_has_prologue(&code);
    }
}
