# MinGW-w64 Bug Submission: __do_global_ctors_aux Crashes on -1 Sentinel

## Summary

The `__do_global_ctors_aux` function in MinGW-w64 CRT (crtbegin.o) crashes when processing the `__CTOR_LIST__` array because it attempts to call the `-1` (0xffffffffffffffff) sentinel value as a function pointer.

## Environment

- **Platform:** x86_64 Windows
- **MinGW Version:** Multiple versions affected (tested with various x86_64-w64-mingw32-gcc)
- **Architecture:** 64-bit (x64/AMD64)
- **Component:** C Runtime Library, global constructor initialization

## Bug Description

The global constructor initialization code in `__do_global_ctors_aux` has a logic error when handling the `__CTOR_LIST__` array format:

**Expected Format:**
```
[-1 sentinel] [func_ptr_1] [func_ptr_2] ... [0 terminator]
```

**Bug:** The implementation doesn't properly skip the `-1` sentinel and attempts to call it as a function, resulting in:
```
SIGSEGV at address 0xffffffffffffffff
```

## Reproduction

### Minimal C++ Test Case

```cpp
// test.cpp
#include <stdio.h>

struct Init {
    Init() { printf("ctor\n"); }
} g_init;

int main() {
    printf("main\n");
    return 0;
}
```

**Compile & Run:**
```bash
$ x86_64-w64-mingw32-g++ -o test.exe test.cpp
$ ./test.exe
Segmentation fault (core dumped)
```

## Root Cause

The disassembly shows a 32-bit comparison on what should be a 64-bit sentinel:

```asm
mov    (%rdx),%rax           # Read 64-bit sentinel
mov    %eax,%ecx
cmp    $0xffffffff,%eax      # Compare only lower 32 bits!
je     handle_sentinel       # Branch may not be taken
```

The code compares only the lower 32 bits of the sentinel, which may cause the `-1` value to be treated as a valid function pointer instead of being skipped.

## Expected Behavior

The CRT should:
1. Read the first entry of `__CTOR_LIST__`
2. If it's `-1` (0xffffffffffffffff), skip it and count remaining constructors
3. Call each valid constructor function
4. Stop at `0` terminator

## Actual Behavior

The CRT attempts to call `0xffffffffffffffff` as a function address, causing immediate crash before `main()` is reached.

## Impact

- **Severity:** High - immediate crash
- **Scope:** All programs with global constructors
- **Affected Languages:** C++, Rust (x86_64-pc-windows-gnu target)

## Suggested Fix

In `__do_global_ctors_aux` (gccmain.c or equivalent), ensure proper 64-bit comparison:

```c
void __do_global_ctors_aux(void) {
    func_ptr *p = &__CTOR_LIST__;
    
    // Read as 64-bit value
    int64_t count = (int64_t)*p;
    
    // Proper 64-bit comparison
    if (count == -1LL) {
        // Count-based iteration
        p++;
        while (*p) {
            if (*p != (func_ptr)-1) {  // Extra safety check
                (*p)();
            }
            p++;
        }
    } else {
        // Direct iteration with count
        while (count > 0) {
            p++;
            if (*p && *p != (func_ptr)-1) {  // Extra safety check
                (*p)();
            }
            count--;
        }
    }
}
```

## Workaround

Until MinGW-w64 is fixed, applications can:
1. Avoid global constructors
2. Patch the binary to replace `-1` sentinels with `0`
3. Use alternative toolchains (MSVC, Clang-MSVC)

Reference implementation of binary patching workaround:
https://github.com/Vadiml1024/litebox/blob/main/litebox_shim_windows/src/loader/pe.rs

## Additional Information

- **Related:** Similar issues in LLD linker support for MinGW COFF format
- **Upstream References:**
  - https://sourceforge.net/p/mingw-w64/mailman/message/35982084/
  - https://reviews.llvm.org/D52053

---

**Submitted by:** LiteBox Project Team  
**Date:** 2026-02-16  
**Contact:** See https://github.com/Vadiml1024/litebox
