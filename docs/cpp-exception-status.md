# C++ Exception Handling: Current Implementation Status

**Last Updated:** 2026-02-24  
**Branch:** `copilot/continue-implementing-exception-handling`

---

## Quick Summary

### SEH / Windows Exception Infrastructure

| Component | Status |
|-----------|--------|
| `RtlCaptureContext` | ✅ Working |
| `RtlLookupFunctionEntry` | ✅ Working (searches registered .pdata table) |
| `RtlVirtualUnwind` | ✅ Working (applies UNWIND_INFO, returns language handler) |
| `RtlUnwindEx` | ✅ Implemented — context fixup (Rip/Rsp/Rax/Rdx) + `seh_restore_context_and_jump` |
| `RaiseException` | ✅ Implemented — Phase 1 SEH walk via `seh_walk_stack_dispatch` |
| `seh_restore_context_and_jump` | ✅ Assembly helper — switches stack, restores all GPRs, jumps to landing pad |
| `AddVectoredExceptionHandler` | ✅ Returns non-NULL handle (handler not invoked) |
| `RemoveVectoredExceptionHandler` | ✅ Returns 1 |
| `SetUnhandledExceptionFilter` | ✅ Accepts filter (not invoked) |
| `__C_specific_handler` | ✅ Implemented — scope table walking with __try/__except/__finally support |
| `RtlPcToFileHeader` | ✅ Implemented — maps PC to module image base |
| `GetThreadId` | ✅ Added (returns current TID) |

### MSVC C++ Exception Handling (from Wine/ReactOS DLL analysis)

| Component | Status |
|-----------|--------|
| `__CxxFrameHandler3` | ✅ Implemented — FuncInfo parsing, IP-to-state map, try block matching, catch type matching, local destructor unwinding |
| `__CxxFrameHandler4` | ✅ Delegates to v3 handler |
| `_CxxThrowException` | ✅ Implemented — proper image base resolution from registered exception table |
| `__CxxRegisterExceptionObject` | ✅ Stub (returns success) |
| `__CxxUnregisterExceptionObject` | ✅ Stub (returns success) |
| `__DestructExceptionObject` | ✅ Stub |
| `__uncaught_exception` | ✅ Returns 0 |
| `__uncaught_exceptions` | ✅ Returns 0 |
| `_local_unwind` | ✅ Delegates to RtlUnwindEx |
| `_set_se_translator` | ✅ Stub (returns NULL) |
| `_is_exception_typeof` | ✅ Stub (returns 0) |
| `_CxxExceptionFilter` | ✅ Stub (returns EXCEPTION_CONTINUE_SEARCH) |
| `__current_exception` | ✅ Thread-local storage |
| `__current_exception_context` | ✅ Thread-local storage |
| `terminate` | ✅ Calls abort() |
| `__std_terminate` | ✅ Calls abort() |

### MSVC C++ Exception Data Structures (x64 RVA-based)

All structures modeled after native Microsoft `msvcrt.dll` (via Wine's `cxx.h`):

| Structure | Status | Description |
|-----------|--------|-------------|
| `CxxFuncInfo` | ✅ | Function descriptor — unwind map, try blocks, IP-to-state map |
| `CxxTryBlockInfo` | ✅ | Try block descriptor — start/end levels, catch blocks |
| `CxxCatchBlockInfo` | ✅ | Catch block — flags, type_info, offset, handler, frame |
| `CxxUnwindMapEntry` | ✅ | Unwind chain entry — prev state, destructor handler |
| `CxxIpMapEntry` | ✅ | IP-to-state mapping — instruction pointer → trylevel |
| `CxxExceptionType` | ✅ | ThrowInfo — flags, destructor, type info table |
| `CxxTypeInfoTable` | ✅ | Array of catchable types for an exception |
| `CxxTypeInfo` | ✅ | Type descriptor — flags, type_info, offsets, size, copy ctor |
| `CxxThisPtrOffsets` | ✅ | Virtual base class pointer adjustments |

---

## Test Results

### `seh_c_test.exe` — **21/21 tests PASS** ✅

The C-language SEH runtime API test passes completely. This validates:
- `RtlCaptureContext` captures valid RSP/RIP
- `SetUnhandledExceptionFilter` is callable
- `AddVectoredExceptionHandler` / `RemoveVectoredExceptionHandler` work
- `RtlLookupFunctionEntry` finds entries in the registered .pdata
- `RtlVirtualUnwind` returns NULL for NULL function_entry
- `RtlUnwindEx` does not crash on NULL arguments
- Exception code constants are correctly defined
- `GetCurrentThreadId` / `GetCurrentProcessId` return non-zero values

```
=== Results: 21 passed, 0 failed ===
```

### `seh_cpp_test.exe` — **FAILS** ❌

The Phase 1 SEH walk now runs and correctly locates the `__gxx_personality_seh0` handler, which in turn calls `RtlUnwindEx` to jump to the landing pad. However `seh_cpp_test.exe` still crashes (SIGSEGV) upon arrival at the catch landing pad — the stack/frame state at the landing pad is not yet correct.

```
Test 1: throw int / catch(int)
[SIGSEGV at landing pad — stack alignment or establisher frame mismatch]
```

---

## GDB Analysis

### Call Stack when `RaiseException` is invoked

```
[PE guest]  __cxa_throw                (libstdc++ in PE, ~0x14001f640)
→ [PE guest]  _Unwind_RaiseException   (libgcc in PE,   ~0x14000c760)
  → [PE IAT]  RaiseException thunk     (import stub,    ~0x140012448)
    → [trampl] trampoline              (LiteBox executor)
      → [Rust]  kernel32_RaiseException ← current abort() is here
```

### `_Unwind_Exception` at `0x5555559454e0`

| Field | Offset | Value | Meaning |
|-------|--------|-------|---------|
| `exception_class` | +0 | `0x474e5543432b2b00` | `"GNUCC++\0"` — GCC C++ ABI |
| `exception_cleanup` | +8 | `0x7ffff7e39820` | `__gxx_exception_cleanup` |
| `private_[0]` | +16 | 0 | (stop function — unused on throw) |
| `private_[1]` | +24 | 0 | target_frame — set in Phase 1 |
| `private_[2]` | +32 | 0 | target_ip — set in Phase 1 |
| `private_[3]` | +40 | 0 | target_rdx — set in Phase 1 |

The `private_` fields are all zero because Phase 1 (search phase) has never run — `RaiseException` aborts before calling any personality handler.

### What `RaiseException(0x20474343)` needs to do

According to `libgcc/unwind-seh.c` (`_GCC_specific_handler`):

**Phase 1 (search):**
1. Walk the guest call stack: `RtlCaptureContext` → loop `[RtlLookupFunctionEntry, RtlVirtualUnwind]`.
2. For each frame with a language handler, call handler with `ExceptionFlags = 0` (search mode).
3. If handler returns `ExceptionContinueSearch` (1), continue to next frame.
4. If handler returns something that triggers unwind, handler internally calls `RtlUnwindEx`.

**Phase 2 (unwind — via `RtlUnwindEx`):**
1. Re-walk the stack from current to `target_frame` with `EXCEPTION_UNWINDING` flag set.
2. For each frame, call language handler (cleanup mode).
3. At `target_frame`, set `EXCEPTION_TARGET_UNWIND` and call handler once more.
4. Restore CPU context: `rax = _Unwind_Exception*`, `rdx = type_selector`, `rsp = target_frame_rsp`, `rip = landing_pad_ip`.

---

## What's Inside the PE

The `seh_cpp_test.exe` binary statically links libgcc and libstdc++ — the entire GCC C++ exception runtime is inside the PE. Key symbols:

| Symbol | PE Address | Role |
|--------|-----------|------|
| `_GCC_specific_handler` | `0x14000c540` | SEH personality wrapper |
| `__gxx_personality_seh0` | `0x14001f690` | C++ personality (calls _GCC_specific_handler) |
| `_Unwind_RaiseException` | `0x14000c760` | Calls `RaiseException(0x20474343)` |
| `_Unwind_Resume` | `0x14000c7a0` | Resumes after cleanup frame |
| `__cxa_throw` | `0x14001f640` | C++ throw entry point |
| `__cxa_begin_catch` | `0x14001f280` | Marks exception as caught |
| `__cxa_end_catch` | `0x14001f460` | Ends catch block |

The `.pdata` section is at RVA `0x28000`, size `0x2550` (314 entries × 12 bytes each). The `.xdata` section (UNWIND_INFO) is at RVA `0x2b000`, size `0x237c`. Both are already parsed and registered by the LiteBox PE loader.

---

## What Needs to Be Implemented

### 1. `RaiseException` — Two-Phase SEH Dispatcher

Replace the current `std::process::abort()` stub with:

```rust
pub unsafe extern "C" fn kernel32_RaiseException(
    exception_code: u32,
    exception_flags: u32,
    number_parameters: u32,
    arguments: *const usize,
) -> ! {
    match exception_code {
        STATUS_GCC_THROW => {
            // Phase 1: walk PE stack calling language handlers in search mode
            seh_phase1_dispatch(exception_code, exception_flags, number_parameters, arguments)
        }
        STATUS_GCC_UNWIND => {
            // Phase 2: called by _GCC_specific_handler after finding the catch frame
            let target_frame = (*arguments.add(1)) as *mut c_void;
            let target_ip    = (*arguments.add(2)) as *mut c_void;
            let exc_ptr      = *arguments.add(0) as *mut c_void;
            let orig_context = /* capture current context */;
            kernel32_RtlUnwindEx(target_frame, target_ip, /*exc_rec*/ arguments.cast_mut().cast(), exc_ptr, orig_context, core::ptr::null_mut());
            core::hint::unreachable_unchecked()
        }
        _ => {
            eprintln!("Unhandled exception: code=0x{exception_code:08x}");
            std::process::abort()
        }
    }
}
```

### 2. `RtlUnwindEx` — Phase 2 Walker + Context Restore

```rust
pub unsafe extern "C" fn kernel32_RtlUnwindEx(
    target_frame: *mut c_void,
    target_ip: *mut c_void,
    exception_record: *mut c_void,  // EXCEPTION_RECORD*
    return_value: *mut c_void,      // rax at landing pad
    context_record: *mut c_void,    // CONTEXT* (current)
    history_table: *mut c_void,
) {
    // Walk stack in cleanup mode (EXCEPTION_UNWINDING flag set)
    // For each frame < target_frame:
    //   - RtlVirtualUnwind → get language handler
    //   - if handler != NULL: call handler (cleanup mode)
    // At target_frame:
    //   - Set EXCEPTION_TARGET_UNWIND flag
    //   - Restore CONTEXT with rax=return_value, rip=target_ip
    //   - restore_context_and_jump(&context)   ← assembly, noreturn
}
```

### 3. `restore_context_and_jump` — Assembly Helper

```asm
// Restore full CPU context from a Windows CONTEXT struct and jump to RIP.
// rdi = *CONTEXT
restore_context_and_jump:
    mov r15, [rdi + 0xF0]   // R15
    mov r14, [rdi + 0xE8]   // R14
    mov r13, [rdi + 0xE0]   // R13
    mov r12, [rdi + 0xD8]   // R12
    mov rbp, [rdi + 0xA0]   // RBP
    mov rbx, [rdi + 0x90]   // RBX
    mov rdx, [rdi + 0x88]   // RDX (type selector)
    mov rax, [rdi + 0x78]   // RAX (_Unwind_Exception*)
    mov rsp, [rdi + 0x98]   // RSP
    jmp qword ptr [rdi + 0xF8]  // RIP = landing pad
```

### 4. `DISPATCHER_CONTEXT` Structure

```rust
#[repr(C)]
struct DispatcherContext {
    control_pc:        u64,
    image_base:        u64,
    function_entry:    *mut c_void,  // PRUNTIME_FUNCTION
    establisher_frame: u64,
    target_ip:         u64,
    context_record:    *mut u8,      // PCONTEXT
    language_handler:  *mut c_void,  // PEXCEPTION_ROUTINE
    handler_data:      *mut c_void,
    history_table:     *mut c_void,  // PUNWIND_HISTORY_TABLE
    scope_index:       u32,
    _fill0:            u32,
}
```

---

## Dependencies on Already-Working Code

The implementation can reuse:
- `kernel32_RtlCaptureContext` — already works, captures RSP/RIP
- `kernel32_RtlLookupFunctionEntry` — already searches registered .pdata
- `kernel32_RtlVirtualUnwind` — already applies UNWIND_INFO and returns handler pointer
- `apply_unwind_info` — internal function, already handles all UWOP opcodes
- CONTEXT offsets (`CTX_RSP`, `CTX_RIP`, `CTX_RAX`, etc.) — already defined

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Stack walk exits PE image (Rust frames) | High | High | Stop walk when `RtlLookupFunctionEntry` returns NULL |
| Off-by-one in establisher frame calculation | Medium | High | GDB validation after each step |
| `restore_context_and_jump` corrupts non-volatile registers | Medium | High | Careful register ordering; validate with test 6 (destructor) |
| Nested exceptions / rethrow (test 4, 7) | Medium | Medium | Preserve `ExceptionInformation[1..3]` across rethrow |
| `STATUS_GCC_UNWIND` second raise not handled | High | High | Step 8 in R&D plan |

---

## Files to Modify

| File | Change |
|------|--------|
| `litebox_platform_linux_for_windows/src/kernel32.rs` | Replace `RaiseException` stub, implement `RtlUnwindEx`, add assembly helper, add `DispatcherContext` struct |
| `litebox_runner_windows_on_linux_userland/tests/integration.rs` | Add `test_seh_cpp_program` and `test_seh_c_program` integration tests |

---

## References

- `libgcc/unwind-seh.c` — https://github.com/gcc-mirror/gcc/blob/master/libgcc/unwind-seh.c  
  **The authoritative source** for the GCC SEH exception protocol on Windows.
- Wine `dlls/ntdll/signal_x86_64.c` — https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/signal_x86_64.c  
  Reference implementation of `RtlUnwindEx` for x86_64.
- ReactOS `sdk/lib/rtl/unwind.c` — https://github.com/reactos/reactos/blob/master/sdk/lib/rtl/unwind.c  
  Clean C implementation of the unwind stack walk.
- Microsoft x64 Exception Handling — https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
