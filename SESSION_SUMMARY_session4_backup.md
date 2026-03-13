# Windows-on-Linux Support - Session Summary (2026-02-16 Session 4)

## Work Completed ✅

### 1. Implemented WriteFile for stdout/stderr
- Modified `kernel32_WriteFile` to handle stdout/stderr writes (was just a stub before)
- Added proper handle checking for stdout (-11) and stderr (-12)
- Writes data to Rust stdout/stderr with proper flushing

### 2. Added Missing Windows API Functions
- Implemented `GetCommandLineW` - returns empty command line
- Implemented `GetEnvironmentStringsW` - returns empty environment block
- Implemented `FreeEnvironmentStringsW` - no-op since we return static buffer

### 3. Extensive GDB Debugging
- Used GDB to trace execution and identify crash point
- Found crash occurs at address 0xffffffffffffffff (invalid function pointer)
- Crash happens in `__do_global_ctors` function (C++ global constructor initialization)
- Only ONE call to `_initterm` executes (for __xi array), not the expected TWO calls

## Current Issue Analysis 🔍

### The Crash
**Symptom**: Program crashes attempting to jump to 0xffffffffffffffff

**Root Cause**: The crash occurs in `__do_global_ctors` at address 0x140098d68:
```assembly
140098d68:ff 13                call   *(%rbx)   # Calls 0xffffffffffffffff
140098d6a:48 83 eb 08          sub    $0x8,%rbx
```

**Call Stack** (from GDB):
```
#0  0xffffffffffffffff in ?? ()
#1  0x00007ffff7b29d6a in ?? ()  # __do_global_ctors + 0x3a
```

### Why __do_global_ctors is Called
- pre_c_init (0x140001010) is called as part of CRT initialization
- pre_c_init may directly or indirectly invoke __do_global_ctors
- __do_global_ctors reads __CTOR_LIST__ and calls each constructor function
- One of the entries in __CTOR_LIST__ is 0xffffffffffffffff (sentinel/invalid)

### The __CTOR_LIST__ Problem
The __CTOR_LIST__ is expected to have:
- First entry: COUNT of constructors (or -1 to indicate count in last entry)
- Middle entries: Function pointers to constructors
- Last entry: NULL terminator (or count if first is -1)

The code checks if first entry is -1 or 0 and skips if so, but doesn't filter -1 from middle entries.

### Missing Second _initterm Call
Analysis shows that after the first `_initterm` (for __xi array) returns and jumps to 0x140001206, the code should check if `__native_startup_state` is 1 and call the second `_initterm` (for __xc array). But this isn't happening, suggesting either:
1. The state was changed by pre_c_init
2. The crash happens before reaching the state check
3. Control flow takes a different path

## Debug Logging Side Effects ⚠️
Added extensive `eprintln!` debug logging (34 statements total) which may be causing issues:
- eprintln! from within Windows code during CRT initialization could corrupt state
- Rust's eprintln! macro has its own initialization requirements
- May be interfering with TLS or stack setup

## Next Steps 📋

### Immediate Actions
1. **Remove Debug Logging**
   - Remove all `eprintln!` statements from msvcrt.rs and kernel32.rs
   - Test if program runs without crashing
   - Only add back minimal, targeted logging if needed

2. **Implement Missing CRT Functions**
   These are called by pre_c_init and may be critical:
   - `__p__fmode` - returns pointer to _fmode global
   - `__p__commode` - returns pointer to _commode global  
   - `_setargv` - parse command line into argv
   - `_set_invalid_parameter_handler` - set handler for invalid parameters
   - `_pei386_runtime_relocator` - perform runtime relocations

3. **Fix __CTOR_LIST__ Handling**
   Options:
   a) Patch the __CTOR_LIST__ data during PE loading to remove -1 sentinels
   b) Provide a wrapper for __do_global_ctors that filters -1 values
   c) Ensure __CTOR_LIST__ is properly zero-initialized in .CRT section

### Investigation Tasks
1. Verify the actual contents of __CTOR_LIST__ in memory after relocations
2. Trace execution path from pre_c_init to understand what it's calling
3. Understand why second _initterm isn't being called
4. Test with a simpler C program (not Rust) to isolate CRT issues

## Files Changed This Session

- `litebox_platform_linux_for_windows/src/msvcrt.rs`:
  - Added debug logging to _initterm, __getmainargs, printf, fwrite
  - Fixed function pointer handling (using raw usize instead of typed pointers)

- `litebox_platform_linux_for_windows/src/kernel32.rs`:
  - Implemented WriteFile for stdout/stderr (was stub before)
  - Added GetCommandLineW, GetEnvironmentStringsW, FreeEnvironmentStringsW

## Testing Status

- ✅ All 162 tests still passing (no regressions)
- ⚠️ hello_cli.exe crashes at 0xffffffffffffffff in __do_global_ctors
- ⚠️ No console output produced yet

## Technical Details

### .CRT Section Layout (0x1400d2000-0x1400d2068)
```
0x1400d2000: __xc_a (start of C++ static constructors for DLL)
0x1400d2010: __xc_z (end of __xc array)
0x1400d2018: __xi_a (start of C init functions)  
0x1400d2028: __xi_z (end of __xi array)
0x1400d2030+: Likely __CTOR_LIST__ or TLS callbacks
```

### Function Call Trace
```
mainCRTStartup (0x140001410)
  → __tmainCRTStartup (0x140001190)
    → _initterm(__xi_a, __xi_z)  # Called at 0x1400013c4
      → pre_c_init (0x140001010)
        → [calls missing CRT functions]
        → __do_global_ctors? (0x140098d30)
          → CRASH: call 0xffffffffffffffff
```

## Key Insights

1. **CRT Initialization is Complex**: Windows CRT has multiple initialization phases with specific ordering requirements
2. **Sentinel Values**: Both _initterm and __do_global_ctors use -1 as sentinel, must filter
3. **State Management**: __native_startup_state controls which init functions run
4. **Rust Complications**: Rust programs have additional runtime requirements beyond basic CRT
5. **Debug Interference**: Heavy logging during CRT init may cause problems

## Summary

Made significant progress understanding the Windows CRT initialization flow and identifying the crash point. The main blocker is handling -1 sentinel values in constructor lists. Removing debug logging and implementing missing CRT functions should allow progress toward successful execution.

Next session should focus on:
- Clean build without debug logging
- Implement missing CRT functions (__p__fmode, _setargv, etc.)
- Handle __CTOR_LIST__ sentinel values properly
- Test with simpler non-Rust Windows programs
