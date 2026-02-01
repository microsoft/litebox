# LiteBox Syscall Rewriter: ELF Patching for Syscall Interception

## Overview

The `litebox_syscall_rewriter` crate performs ahead-of-time (AOT) ELF binary rewriting to intercept syscalls without runtime overhead. It replaces all `syscall` (x86-64) and `int 0x80` (x86-32) instructions with jumps to a trampoline section, enabling syscall hooking without ptrace, seccomp, or signal-based interception.

## Entry Point

The main API is `hook_syscalls_in_elf()`, which takes an ELF binary and returns a patched version with all syscalls redirected through trampolines.

## How It Works

### 1. ELF Parsing

The rewriter uses the `object` crate to parse both ELF32 and ELF64 binaries. It identifies executable sections (`.text` and others) by looking for sections with:
- Type: `SHT_PROGBITS`
- Flags: `SHF_ALLOC | SHF_EXECINSTR`

### 2. Syscall Detection

The rewriter scans executable sections using `iced_x86` for disassembly and detects:

| Architecture | Instruction | Opcode |
|--------------|-------------|--------|
| x86-64 | `syscall` | `0F 05` |
| x86-32 | `int 0x80` | `CD 80` |
| x86-32 | `call DWORD PTR gs:0x10` | vDSO entry |

### 3. Patching Strategy

The rewriter uses three strategies in order of preference:

#### Strategy 1: Hook Surrounding Instructions (Primary)

When there are 5+ bytes of instructions before or after the syscall:

1. Scan backwards from the syscall to find preceding instructions
2. Stop at control transfer instructions (jumps, calls, returns) or jump targets
3. Replace the syscall and surrounding instructions with a `JMP rel32` (5 bytes)
4. Fill remaining space with `NOP` instructions
5. Copy displaced instructions to the trampoline section

**Example transformation (x86-64):**
```asm
# Original
401227:  b8 0e 00 00 00    mov    $0xe,%eax
40122c:  0f 05             syscall

# Patched
401227:  e9 e4 0d 0b 00    jmp    4b2010    ; jump to trampoline
40122c:  90                nop
40122d:  90                nop
```

#### Strategy 2: Hook After Syscall

When insufficient space exists before the syscall but 5+ bytes exist after:
- Replace syscall + following instructions with `JMP` to trampoline
- Copy following instructions to trampoline
- Jump back after those instructions

#### Strategy 3: Hook Before and After (x86-32 only)

For tightly packed x86-32 code where neither strategy above works:
- Combine previous instruction + syscall + next instruction (must total 5+ bytes)
- Requires careful control flow analysis to ensure safety

### 4. Trampoline Generation

Each hooked syscall gets a trampoline entry that:
1. Saves the return address
2. Jumps to the syscall handler
3. Executes any displaced instructions
4. Returns to the original code flow

**x86-64 Trampoline Pattern:**
```asm
lea    rcx, [rip + disp32]        ; save return address to RCX (7 bytes)
jmp    [rip + offset_to_handler]  ; jump to handler (6 bytes)
; displaced instructions from original code
jmp    <continuation_address>     ; return to original flow
```

**x86-32 Trampoline Pattern:**
```asm
push   eax                        ; save EAX
call   <next_instruction>         ; get current address
pop    eax                        ; address now in EAX
call   [eax + offset_to_handler]  ; call handler
; displaced instructions
jmp    <continuation_address>
```

### 5. Output Format

The patched binary consists of:

```
[Modified ELF binary (page-aligned to 4KB)]
[Trampoline section]:
  - "LITEBOX0"         (8 bytes magic header)
  - Handler address    (4 or 8 bytes depending on arch)
  - Trampoline code    (one entry per hooked syscall)
```

The trampoline section is marked with name `.trampolineLB0` and uses special section header fields:
- `sh_addr`: Magic marker `LTBX`
- `sh_offset`: Trampoline base address
- `sh_entsize`: Trampoline data size

## Control Flow Safety

The rewriter performs control flow analysis to ensure safe patching:

1. **Jump Target Detection**: Pre-computes all branch targets to avoid overwriting them
2. **Control Transfer Boundaries**: Stops instruction scanning at jumps, calls, and returns
3. **Symbol Awareness**: Skips internal symbols like `_dl_sysinfo_int80`

## Limitations

- **Static analysis only**: Cannot detect or hook dynamically generated syscalls (JIT, self-modifying code)
- **x86 only**: Currently supports x86-32 and x86-64 architectures
- **Minimum space requirement**: Needs at least 5 bytes for the `JMP rel32` instruction

## Error Conditions

| Error | Description |
|-------|-------------|
| `NoTextSectionFound` | No executable sections in ELF |
| `NoSyscallInstructionsFound` | No syscalls detected |
| `AlreadyHooked` | Binary already contains trampoline section |
| `InsufficientBytesBeforeOrAfter` | Cannot find 5+ bytes for patching |
| `TrampolineAddressTooLarge` | Address overflow in 32-bit mode |

## Dependencies

- `object`: ELF parsing and building
- `iced-x86`: x86 instruction disassembly
- `thiserror`: Error type definitions
- `clap`: CLI argument parsing
