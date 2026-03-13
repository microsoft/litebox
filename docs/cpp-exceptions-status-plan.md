# C++ Exception Handling for Windows-on-Linux: R&D Plan

**Status:** In Progress  
**Target:** Pass all 12 tests in `windows_test_programs/seh_test/seh_cpp_test.exe`  
**Current:** `seh_c_test.exe` passes 21/21 tests; `seh_cpp_test.exe` fails at first `throw` because `RaiseException` stubs out instead of dispatching through the SEH chain.

---

## Background

C++ exceptions on Windows x64 are implemented on top of the Structured Exception Handling (SEH) machinery. When a `throw` statement executes, the compiler-emitted code:

1. Allocates a `_Unwind_Exception` struct on the heap with `__cxa_allocate_exception`.
2. Calls `_Unwind_RaiseException` (inside the statically-linked libgcc).
3. `_Unwind_RaiseException` calls Windows `RaiseException(0x20474343, 0, 1, &exc_ptr)` — code `STATUS_GCC_THROW = 0x20474343`.
4. The OS walks the `.pdata` exception table, calling `__gxx_personality_seh0` (which wraps `_GCC_specific_handler`) for each frame.
5. **Phase 1 (search):** `_GCC_specific_handler` calls the GCC personality `__gxx_personality_v0` with `_UA_SEARCH_PHASE`. When it finds the handler frame it calls `RtlUnwindEx` to begin Phase 2.
6. **Phase 2 (unwind):** `RtlUnwindEx` walks the stack backward calling cleanup handlers, then jumps to the catch landing pad with `rax=_Unwind_Exception*` and `rdx=selector`.

The entire C++ exception machinery is **self-contained inside the PE binary** (statically linked libgcc / libstdc++). LiteBox only needs to:
- Expose a working `RaiseException` that drives the two-phase SEH walk.
- Expose a working `RtlUnwindEx` that walks the PE's `.pdata` in cleanup mode and then **jumps into the target frame**.
- Expose working `RtlLookupFunctionEntry` / `RtlVirtualUnwind` (already present and tested).

---

## Key References

### MinGW / GCC Source Code
| File | URL | Relevance |
|------|-----|-----------|
| `libgcc/unwind-seh.c` | https://github.com/gcc-mirror/gcc/blob/master/libgcc/unwind-seh.c | **Primary reference.** The C implementation of `_GCC_specific_handler`, `_Unwind_RaiseException`, `_Unwind_Resume`. |
| `libgcc/unwind.h` | https://github.com/gcc-mirror/gcc/blob/master/libgcc/unwind.h | `_Unwind_Exception` struct layout, reason codes, action flags. |
| `libgcc/unwind-pe.h` | https://github.com/gcc-mirror/gcc/blob/master/libgcc/unwind-pe.h | LSDA (Language-Specific Data Area) encoding helpers. |
| `libstdc++-v3/libsupc++/eh_personality.cc` | https://github.com/gcc-mirror/gcc/blob/master/libstdc%2B%2B-v3/libsupc%2B%2B/eh_personality.cc | `__gxx_personality_v0` — the C++ personality function. |
| `libstdc++-v3/libsupc++/eh_throw.cc` | https://github.com/gcc-mirror/gcc/blob/master/libstdc%2B%2B-v3/libsupc%2B%2B/eh_throw.cc | `__cxa_throw`, `__cxa_rethrow`. |

### Wine Source Code
| File | URL | Relevance |
|------|-----|-----------|
| `dlls/ntdll/signal_x86_64.c` | https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/signal_x86_64.c | Wine's `RtlUnwindEx` implementation for x86_64. |
| `dlls/ntdll/exception.c` | https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/exception.c | `RtlRaiseException`, `NtRaiseException`, VEH/SEH dispatcher. |
| `dlls/ntdll/unwind.c` | https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/unwind.c | `.pdata` table lookup and UNWIND_INFO processing. |

### ReactOS Source Code
| File | URL | Relevance |
|------|-----|-----------|
| `sdk/lib/rtl/unwind.c` | https://github.com/reactos/reactos/blob/master/sdk/lib/rtl/unwind.c | Native `RtlUnwindEx` and `RtlVirtualUnwind` implementation. |
| `sdk/lib/rtl/amd64/unwindasm.asm` | https://github.com/reactos/reactos/blob/master/sdk/lib/rtl/amd64/unwindasm.asm | Assembly stubs for context restoration. |

### Windows Documentation
- [x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
- [RUNTIME_FUNCTION / UNWIND_INFO / UNWIND_CODE](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-runtime_function)
- [RtlUnwindEx](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlunwindex)

---

## GDB-Derived Observations

From GDB analysis of `seh_cpp_test.exe` running under the LiteBox runner:

### `RaiseException` call site (code=0x20474343, nparams=1)
```
[RAISE] code=0x20474343 nparams=1
  args[0] = 0x5555559454e0  <- _Unwind_Exception*
  exception_class = 0x474e5543432b2b00  ("GNUCC++\0")
  cleanup_fn      = 0x7ffff7e39820      (__gxx_exception_cleanup in PE)
  private_[0..3]  = all zeros           (Phase 1 not yet run)
```

### Stack layout on entry to `kernel32_RaiseException` (SysV ABI)
```
rdi = exception_code = 0x20474343
rsi = exception_flags = 0x0
rdx = nparams = 1
rcx = args_ptr  (Windows param 4 → Linux RCX via trampoline)
rsp = our stack frame in Rust
```

The call chain is:
```
[PE guest] __cxa_throw
  → [PE guest] _Unwind_RaiseException     (libgcc inside PE)
    → [PE guest IAT thunk] RaiseException
      → [trampoline] → kernel32_RaiseException (Rust)
```

### What currently happens
`kernel32_RaiseException` immediately calls `std::process::abort()` — no SEH dispatch.

### What needs to happen
`kernel32_RaiseException` must drive the two-phase SEH walk:
1. Walk the guest call stack via `RtlLookupFunctionEntry` + `RtlVirtualUnwind`.
2. Call the language handler (`__gxx_personality_seh0`) for each frame with `_UA_SEARCH_PHASE`.
3. When a handler frame is found, the personality calls `RtlUnwindEx(target_frame, target_ip, exc_rec, exc_ptr, ctx, history)`.
4. `RtlUnwindEx` re-walks the stack in cleanup mode, calling personality with `_UA_CLEANUP_PHASE` for each frame.
5. At the target frame, restore the CONTEXT (rax=exc_ptr, rdx=selector) and **jump** to `target_ip`.

---

## R&D Plan (10 Steps)

### Step 1: Research & Understand the GCC/MinGW SEH Exception Protocol
**Goal:** Deeply understand the data structures and call sequences.

**Actions:**
1. Read `libgcc/unwind-seh.c` (already fetched) — study `_GCC_specific_handler`, `_Unwind_RaiseException`, `_Unwind_Resume`.
2. Study `_Unwind_Exception` struct layout from `libgcc/unwind.h`.
3. Study `DISPATCHER_CONTEXT` layout (Windows SDK / ReactOS headers).
4. Understand the two-phase (search + unwind) protocol end-to-end.

**GDB validation:**
```bash
# After implementing Phase 1 dispatch, verify personality is called:
break __gxx_personality_seh0  # symbol inside PE (if debug info available)
# Or set breakpoint at address from nm:
# nm seh_cpp_test.exe | grep gxx_personality_seh0
```

**References:** `libgcc/unwind-seh.c`, `libgcc/unwind.h`, ReactOS `sdk/lib/rtl/unwind.c`.

---

### Step 2: Research Wine's `RtlUnwindEx` Implementation
**Goal:** Understand how Wine implements the two-phase walk.

**Actions:**
1. Study `dlls/ntdll/signal_x86_64.c` — `RtlUnwindEx`, `dispatch_exception`.
2. Note how Wine calls `RtlVirtualUnwind` for each frame and invokes the language handler.
3. Note how Wine restores the CONTEXT at the target frame to "land" in the catch block.
4. Study `DISPATCHER_CONTEXT` fields that are passed to language handlers.

**Key structures from Wine/ReactOS:**
```c
typedef struct _DISPATCHER_CONTEXT {
    ULONG64              ControlPc;
    ULONG64              ImageBase;
    PRUNTIME_FUNCTION    FunctionEntry;
    ULONG64              EstablisherFrame;
    ULONG64              TargetIp;
    PCONTEXT             ContextRecord;
    PEXCEPTION_ROUTINE   LanguageHandler;
    PVOID                HandlerData;
    PUNWIND_HISTORY_TABLE HistoryTable;
    ULONG                ScopeIndex;
    ULONG                Fill0;
} DISPATCHER_CONTEXT, *PDISPATCHER_CONTEXT;
```

---

### Step 3: Implement `DISPATCHER_CONTEXT` Structure in Rust
**Goal:** Represent `DISPATCHER_CONTEXT` accurately in Rust for passing to language handlers.

**Actions:**
1. Add `DispatcherContext` struct with the 11 fields listed above (total 96 bytes on x64).
2. Add `ExceptionRecord` struct (Windows EXCEPTION_RECORD).
3. Verify field offsets against Wine/ReactOS source.

**GDB validation:**
```bash
# After implementing, print the DISPATCHER_CONTEXT passed to handler:
break kernel32_RaiseException  # after dispatch is live
# inspect the disp pointer passed to language handler
```

---

### Step 4: Implement Phase 1 SEH Walk in `RaiseException`
**Goal:** Walk the guest stack calling the language handler for each frame in search mode.

**Actions:**
1. Capture the current CONTEXT using `RtlCaptureContext` (already working).
2. Build a guest call stack by repeatedly calling `RtlLookupFunctionEntry` + `RtlVirtualUnwind`.
3. For each frame that has a language handler, populate a `DISPATCHER_CONTEXT` and call the handler.
4. Detect `ExceptionContinueSearch` (1) vs. `ExceptionContinueExecution` (0) / other results.
5. If no handler is found, fall back to `std::process::abort()`.

**Key implementation detail — the guest RSP:**  
The trampoline saves the guest's return-to-guest RSP at a known offset from our Rust RSP. We must reconstruct the guest stack frame to start the walk from the guest's `_Unwind_RaiseException` call site.

**GDB validation:**
```bash
# After implementing, place breakpoints at RtlLookupFunctionEntry and RtlVirtualUnwind
# and verify they are called with reasonable PCs (within the PE image range)
```

---

### Step 5: Build the `EXCEPTION_RECORD` for `RaiseException`
**Goal:** Correctly populate `EXCEPTION_RECORD` to pass to language handlers.

**From MinGW `unwind-seh.c`:**
```c
// _Unwind_RaiseException fills args:
ms_exc.ExceptionCode           = STATUS_GCC_THROW;   // 0x20474343
ms_exc.ExceptionFlags          = 0;
ms_exc.NumberParameters        = 1;
ms_exc.ExceptionInformation[0] = (ULONG_PTR) gcc_exc;
```

**After Phase 1 finds the handler (`_GCC_specific_handler` fills these):**
```c
ms_exc.NumberParameters        = 4;
ms_exc.ExceptionInformation[1] = (_Unwind_Ptr) this_frame;  // target frame
ms_exc.ExceptionInformation[2] = gcc_context.ra;             // target IP
ms_exc.ExceptionInformation[3] = gcc_context.reg[1];         // target RDX
```

---

### Step 6: Implement `RtlUnwindEx` — Phase 2 Stack Walk
**Goal:** Walk the stack backward from the current frame to `target_frame`, calling cleanup handlers.

**Actions:**
1. Capture context at the call site.
2. Walk the stack (same loop as Phase 1, but with `EXCEPTION_UNWINDING` flag set in `ExceptionRecord.ExceptionFlags`).
3. For each frame between current and `target_frame`, call the language handler (cleanup phase).
4. At `target_frame`, restore the CONTEXT with `rax = return_value`, `rip = target_ip`, and jump.

**Key implementation detail — jumping to the landing pad:**  
At the end of `RtlUnwindEx`, the function must **never return**. Instead, it must restore the full CPU context and jump to `target_ip`. This requires an assembly stub:

```asm
restore_context_and_jump:
  ; rdi = pointer to CONTEXT
  mov rsp, [rdi + CTX_RSP_OFFSET]
  mov rax, [rdi + CTX_RAX_OFFSET]   ; return value / _Unwind_Exception*
  mov rdx, [rdi + CTX_RDX_OFFSET]   ; selector
  jmp [rdi + CTX_RIP_OFFSET]        ; jump to landing pad
```

---

### Step 7: Implement `restore_context_and_jump` Assembly Helper
**Goal:** Atomic context switch from Rust into the PE guest landing pad.

**Actions:**
1. Add `global_asm!` in `kernel32.rs` (or a new `seh_dispatch.rs`) with a `restore_context_and_jump` symbol.
2. Restore all non-volatile registers (rbx, rbp, rsi, rdi, r12-r15) from the CONTEXT.
3. Set rsp, rax, rdx, then `jmp [rip_ptr]`.

**GDB validation:**
```bash
# After implementing, run seh_cpp_test.exe and verify:
# 1. RaiseException walks frames (multiple RtlLookupFunctionEntry calls)
# 2. RtlUnwindEx is called
# 3. Program jumps into the catch block
# 4. "catch(int) handler entered" is printed
```

---

### Step 8: Handle `STATUS_GCC_UNWIND` (0x21474343) — Colliding Exception
**Goal:** Support the rethrow/forced-unwind path used by `_GCC_specific_handler`.

From `unwind-seh.c`, when Phase 2 starts, `_GCC_specific_handler` raises a *second* exception with code `0x21474343` (`STATUS_GCC_UNWIND`) to coordinate the actual stack unwind:
```c
RaiseException(STATUS_GCC_UNWIND, EXCEPTION_NONCONTINUABLE, 4, ms_exc->ExceptionInformation);
```

**Actions:**
1. In `RaiseException`, detect `code == 0x21474343`.
2. Extract `ExceptionInformation[1]` (target frame) and `ExceptionInformation[2]` (target IP).
3. Call `RtlUnwindEx` with these as `target_frame` / `target_ip`.

---

### Step 9: Test and Debug with GDB
**Goal:** Iteratively verify each phase works correctly.

**GDB Test Scripts:**

*Phase 1 verification:*
```python
import gdb, struct

class RaiseBreak(gdb.Breakpoint):
    def stop(self):
        code = int(gdb.parse_and_eval("$rdi"))
        inf = gdb.inferiors()[0]
        print(f"RAISE code=0x{code:08x}")
        gdb.execute("bt 5")
        return code == 0x20474343  # stop only on first raise

RaiseBreak("kernel32_RaiseException")
gdb.execute("run windows_test_programs/seh_test/seh_cpp_test.exe")
```

*Phase 2 / landing pad verification:*
```python
# After implementing, break at the expected landing pad address
# (from PE disassembly: the instruction after __cxa_throw that catches the exception)
landing_pad_addr = 0x...  # from: objdump -d seh_cpp_test.exe | grep -A5 "cmp.*0x2a"
gdb.execute(f"break *0x...")
```

*Full sequence:*
```bash
# Run with verbose to see all API calls
./target/debug/litebox_runner_windows_on_linux_userland \
  --trace-apis --trace-format text \
  windows_test_programs/seh_test/seh_cpp_test.exe 2>&1 | head -100
```

---

### Step 10: Integration Test and Regression Guard
**Goal:** Add automated integration test for `seh_cpp_test.exe`.

**Actions:**
1. Add `test_seh_cpp_test_program` to `litebox_runner_windows_on_linux_userland/tests/integration.rs`.
2. The test should:
   - Skip if `seh_cpp_test.exe` doesn't exist (requires `make` in `seh_test/`).
   - Run the program and assert exit code 0.
   - Assert stdout contains `=== Results: 12 passed, 0 failed ===`.
3. Add `seh_c_test.exe` test similarly.
4. Add to CI: `cd windows_test_programs/seh_test && make`.

**Test template:**
```rust
#[test]
#[ignore = "Requires MinGW-built C++ test (cd windows_test_programs/seh_test && make)"]
fn test_seh_cpp_program() {
    use std::path::PathBuf;
    use std::process::Command;

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let exe_path = PathBuf::from(manifest_dir)
        .parent().unwrap()
        .join("windows_test_programs/seh_test/seh_cpp_test.exe");
    assert!(exe_path.exists(), "seh_cpp_test.exe not found");

    let runner = env!("CARGO_BIN_EXE_litebox_runner_windows_on_linux_userland");
    let output = Command::new(runner).arg(&exe_path).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "Exit failed\n{stdout}");
    assert!(stdout.contains("12 passed, 0 failed"), "Tests failed\n{stdout}");
}
```

---

## Implementation Roadmap

| Step | Description | Status | Estimated Effort |
|------|-------------|--------|-----------------|
| 1 | Research GCC/MinGW SEH protocol | ✅ Done | — |
| 2 | Research Wine `RtlUnwindEx` | ✅ Done (reviewed) | — |
| 3 | Implement `DISPATCHER_CONTEXT` struct | ✅ Done | — |
| 4 | `RaiseException` Phase 1 walk | ✅ Done | — |
| 5 | `EXCEPTION_RECORD` construction | ✅ Done | — |
| 6 | `RtlUnwindEx` Phase 2 walk | ✅ Done | — |
| 7 | `restore_context_and_jump` assembly | ✅ Done | — |
| 8 | `STATUS_GCC_UNWIND` handling | ✅ Done | — |
| 9 | GDB debugging + iteration | ⬜ In Progress | ongoing |
| 10 | Integration test | ⬜ TODO | 1h |
| 11 | MSVC C++ exception structures (CxxFuncInfo, etc.) | ✅ Done | — |
| 12 | Proper `__CxxFrameHandler3` implementation | ✅ Done | — |
| 13 | `_CxxThrowException` image base resolution | ✅ Done | — |
| 14 | `RtlPcToFileHeader` | ✅ Done | — |
| 15 | MSVC helper stubs (__CxxRegister/Unregister, etc.) | ✅ Done | — |

---

## Known Challenges

### Challenge 1: Guest Stack Pointer Reconstruction
The Rust `kernel32_RaiseException` is called through a trampoline which adjusts the stack. We need to reconstruct the **guest** RSP (the Windows stack pointer at the `call RaiseException` instruction) to correctly start the SEH walk.

The trampoline layout (from `dispatch.rs`):
```
[entry] RSP % 16 == 8
  push rdi           # RSP -= 8  → RSP % 16 == 0
  push rsi           # RSP -= 8  → RSP % 16 == 8
  sub  rsp, 8        # RSP -= 8  → RSP % 16 == 0
  ...
  call impl          # RSP -= 8  → RSP % 16 == 8  (inside Rust impl)
```
So at entry to our Rust function: `guest_ret_addr = *(rsp + 32)` and `guest_rsp = rsp + 40`.

### Challenge 2: The `noreturn` Nature of `RtlUnwindEx`
`RtlUnwindEx` must never return on success — it jumps into the catch block. In Rust, this means the function must be declared `-> !` or use `core::hint::unreachable_unchecked()`.

### Challenge 3: Thread Safety of the Exception State
The `_Unwind_Exception` struct is heap-allocated by the PE and pointed to from the `EXCEPTION_RECORD`. Our dispatcher must not free or corrupt it.

### Challenge 4: `EXCEPTION_TARGET_UNWIND` Flag
When `RtlUnwindEx` reaches the target frame, it sets `EXCEPTION_TARGET_UNWIND` in the `ExceptionFlags` before calling the language handler one final time (so it can install the context). Our `RtlUnwindEx` must implement this correctly.

---

## Open Questions

1. **History Table:** Windows passes an `UNWIND_HISTORY_TABLE*` to cache `RtlLookupFunctionEntry` results. Should LiteBox implement a real history table, or is NULL safe?  
   *Answer from GCC source:* NULL is safe — the history table is a performance optimization only.

2. **`EXCEPTION_NONCONTINUABLE` flag:** The initial GCC throw uses flags=0; the colliding `STATUS_GCC_UNWIND` uses `EXCEPTION_NONCONTINUABLE`. Does our stub need to check this?  
   *Answer:* We should check it and not attempt to continue non-continuable exceptions.

3. **Nested exceptions:** The test suite includes rethrow (test 4), nested try/catch (test 7), and cross-function propagation (test 8). The two-phase approach handles these naturally if EXCEPTION_RECORD.ExceptionInformation[0..3] are preserved through both phases.
