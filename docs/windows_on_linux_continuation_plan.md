# Windows-on-Linux: Detailed Continuation Plan

**Created:** 2026-02-18 (Session 9)  
**Status at this writing:** Phase 8 complete; Phase 9 partially complete.  
**Tests passing:** 151 platform + 47 shim = 198 total

---

## Current Baseline (End of Session 9)

### Test-program scorecard

| Program | Status | Notes |
|---|---|---|
| `hello_cli.exe` | ✅ Full pass | Prints output correctly |
| `math_test.exe` | ✅ 7/7 | All arithmetic, float, bitwise |
| `string_test.exe` | ✅ 8/9 | 1 Unicode byte-count edge case |
| `env_test.exe` | ✅ Gets/sets env vars | `GetEnvironmentVariableW`, `SetEnvironmentVariableW`, `GetEnvironmentStringsW` all functional |
| `file_io_test.exe` | 🔶 Partial | `CreateDirectoryW`, `CreateFileW` work; `WriteFile` to files fails with `ERROR_INVALID_HANDLE` |
| `args_test.exe` | 🔶 Not tested | Command-line infra in place; `set_process_command_line` wired into runner |

### New APIs implemented in Session 9

| API | Module | Status |
|---|---|---|
| `GetEnvironmentVariableW` | kernel32.rs | ✅ Real `getenv` via libc |
| `SetEnvironmentVariableW` | kernel32.rs | ✅ Real `setenv`/`unsetenv` via libc |
| `GetEnvironmentStringsW` | kernel32.rs | ✅ Returns full process environment block |
| `FreeEnvironmentStringsW` | kernel32.rs | ✅ Properly frees the allocated block via registry |
| `GetCommandLineW` | kernel32.rs | ✅ Reads from `PROCESS_COMMAND_LINE` global |
| `set_process_command_line` | kernel32.rs (pub) | ✅ Called by runner before entry point |
| `CreateDirectoryW` | kernel32.rs | ✅ `std::fs::create_dir` + path translation |
| `DeleteFileW` | kernel32.rs | ✅ `std::fs::remove_file` + path translation |
| `GetFileAttributesW` | kernel32.rs | ✅ `std::fs::metadata` + attribute mapping |
| `CreateFileW` | kernel32.rs | ✅ `std::fs::OpenOptions` + handle registry |
| `ReadFile` | kernel32.rs | ✅ Reads from handle registry |
| `WriteFile` (stdout/stderr) | kernel32.rs | ✅ |
| `WriteFile` (regular file) | kernel32.rs | 🔶 Handle lookup fails (see Phase 10) |
| `CloseHandle` (file) | kernel32.rs | ✅ Removes from handle registry |

### Key infrastructure added

- **`wide_str_to_string`** – converts null-terminated UTF-16 wide pointer to `String`.
- **`wide_path_to_linux`** – converts Windows/MinGW-encoded wide path to an absolute Linux path, handling the MinGW root-relative path encoding (leading `\0` u16).
- **`copy_utf8_to_wide`** – writes a UTF-8 value into a caller-provided UTF-16 buffer (respects `ERROR_MORE_DATA` semantics).
- **`FILE_HANDLES` global** – `Mutex<HashMap<usize, FileEntry>>` for file I/O handle tracking.
- **`FILE_HANDLE_COUNTER` global** – `AtomicUsize` for unique handle allocation.
- **`PROCESS_COMMAND_LINE` global** – `OnceLock<Vec<u16>>` set by the runner.

---

## Known Issues (Carry-forward)

### Issue 1 — `WriteFile` to regular files returns `ERROR_INVALID_HANDLE` (6)

**Symptom:** `file_io_test.exe` succeeds at `CreateFileW` but fails on the first `WriteFile` call.

**Root cause (suspected):** The Rust Windows stdlib for the `x86_64-pc-windows-gnu` target may
route `std::fs::File::write_all` through the C runtime's `_write` call (which calls NtWriteFile)
rather than calling Win32 `WriteFile` directly.  If true, the handle returned by our
`CreateFileW` (a synthetic `usize` value like `0x10000`) is not a valid NT handle, so NtWriteFile
rejects it.

**Fix options (in priority order):**
1. Intercept `NtWriteFile` / `NtReadFile` calls that come from a `CreateFileW`-opened handle and
   redirect them to the handle-registry entry.  The NT file handle passed will be whatever the
   Windows program stored; we can check whether it matches one of our synthetic handles.
2. Make `CreateFileW` open the file using a real Linux fd and cast the `fd` as the handle value,
   so that NtWriteFile's implementation can use it directly.
3. Add a `GetFileSizeEx` + `SetFilePointerEx` path that covers the cases needed by the test.

### Issue 2 — `__getmainargs` still populates `argc=0, argv=[]`

**Symptom:** `args_test.exe` may receive empty args even though the runner calls
`set_process_command_line`.

**Root cause:** `msvcrt___getmainargs` in `msvcrt.rs` uses a static empty array and always
reports `argc=0`. The command line is stored in `PROCESS_COMMAND_LINE` (UTF-16) but is never
parsed into a `char**` array.

**Fix:** Implement a proper command-line parser in `msvcrt___getmainargs` that:
1. Reads `PROCESS_COMMAND_LINE` via `kernel32_GetCommandLineW`.
2. Converts UTF-16 to UTF-8.
3. Parses the command line into a `Vec<CString>` (respecting Windows quoting rules).
4. Stores them in a `Mutex<Option<…>>` so the `*mut *mut i8` pointers are stable.

### Issue 3 — `MoveFileExW`, `CopyFileExW` are stubs

**Symptom:** `file_io_test.exe` will fail on rename/copy tests once write is fixed.

**Fix:** Implement using `std::fs::rename` and `std::fs::copy` with `wide_path_to_linux`.

### Issue 4 — Unicode byte-count edge case in `string_test.exe` (1/9 fail)

**Symptom:** A multibyte UTF-8 string has one fewer byte than expected.

**Root cause:** MinGW `strlen` counts bytes excluding null, but our implementation may differ.
Investigate `MultiByteToWideChar` / `WideCharToMultiByte` path.

---

## Phase 10 — Fix File I/O Round-Trip (Priority: HIGH)

**Goal:** `file_io_test.exe` fully passes (all subtests).

### 10.1 Unify file handles between CreateFileW and NtWriteFile / NtReadFile

The `LinuxPlatformForWindows` struct (in `lib.rs`) already maintains open file handles for
`NtCreateFile` / `NtWriteFile` / `NtReadFile`.  `kernel32_CreateFileW` maintains a *separate*
map in `kernel32.rs`.  These two maps are invisible to each other.

**Plan:**

a. Add a `pub fn register_file_handle(handle: usize, file: File)` and
   `pub fn take_file_handle(handle: usize) -> Option<File>` to the platform lib API so both
   kernel32 and NTDLL impls share one backing store.

b. Replace the `FILE_HANDLES` static in `kernel32.rs` with calls to the shared store.

c. In `NtWriteFile` / `NtReadFile` (in `lib.rs`), check the shared store for the handle *before*
   treating it as an fd.

### 10.2 Implement `GetFileSizeEx`

```rust
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileSizeEx(
    file: *mut c_void,
    file_size: *mut i64,
) -> i32 {
    // look up handle in FILE_HANDLES, call file.metadata().len()
}
```

Register in `function_table.rs` with `num_params: 2`.

### 10.3 Implement `SetFilePointerEx`

```rust
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetFilePointerEx(
    file: *mut c_void,
    distance_to_move: i64,
    new_file_pointer: *mut i64,
    move_method: u32, // FILE_BEGIN=0, FILE_CURRENT=1, FILE_END=2
) -> i32 {
    // look up handle, call std::io::Seek::seek
}
```

### 10.4 Implement `MoveFileExW`

```rust
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_MoveFileExW(
    existing: *const u16,
    new_name: *const u16,
    flags: u32,
) -> i32 {
    // wide_path_to_linux both args, std::fs::rename
}
```

### 10.5 Integration test

Add a dedicated Rust unit test in `litebox_platform_linux_for_windows/src/lib.rs`:

```rust
#[test]
fn test_create_write_read_file_roundtrip() {
    let path = "/tmp/litebox_roundtrip_test.txt";
    // CreateFileW CREATE_ALWAYS + GENERIC_WRITE
    // WriteFile with known data
    // CloseHandle
    // CreateFileW OPEN_EXISTING + GENERIC_READ
    // ReadFile
    // assert content matches
    // CloseHandle
    // DeleteFileW
}
```

---

## Phase 11 — Command-Line Argument Passing (Priority: HIGH)

**Goal:** `args_test.exe` correctly receives CLI arguments.

### 11.1 Fix `msvcrt___getmainargs`

Parse `PROCESS_COMMAND_LINE` into a `Vec<CString>`:

```rust
pub unsafe extern "C" fn msvcrt___getmainargs(
    p_argc: *mut i32,
    p_argv: *mut *mut *mut i8,
    p_env: *mut *mut *mut i8,
    _do_wildcard: i32,
    _start_info: *mut u8,
) -> i32 {
    // 1. Read the command line from PROCESS_COMMAND_LINE.
    // 2. Decode UTF-16 → UTF-8.
    // 3. Parse Windows quoting rules into Vec<String>.
    // 4. Store in OnceLock<(Vec<CString>, Vec<*mut i8>)>.
    // 5. Set *p_argc, *p_argv.
    0
}
```

Use a `OnceLock` so the `CString` buffers are stable for the lifetime of the process.

### 11.2 Fix `msvcrt__wgetmainargs` (wide version)

Same as above but fill in `*mut *mut u16` pointers from UTF-16 strings.

### 11.3 Fix `_acmdln` data export

The `ACMDLN` static in `msvcrt.rs` is a stub `b"\0"`.  After `set_process_command_line` is
called, derive the ANSI command line and update a global that `_acmdln` points to.

### 11.4 Test

```rust
// in tests/integration.rs
fn test_args_test_program() {
    // run args_test.exe with "hello world" arguments
    // assert output matches
}
```

---

## Phase 12 — Extended File System APIs (Priority: MEDIUM)

**Goal:** Cover the file-system surface area used by typical Windows programs.

| API | Implementation hint |
|---|---|
| `MoveFileExW` | `std::fs::rename` + `wide_path_to_linux` |
| `CopyFileExW` | `std::fs::copy` + progress callback (stub) |
| `RemoveDirectoryW` | `std::fs::remove_dir` |
| `CreateDirectoryExW` | Same as `CreateDirectoryW` + template attributes ignored |
| `GetCurrentDirectoryW` | `std::env::current_dir` + `copy_utf8_to_wide` |
| `SetCurrentDirectoryW` | `std::env::set_current_dir` + `wide_path_to_linux` |
| `FindFirstFileW` | `std::fs::read_dir` with pattern matching |
| `FindNextFileW` | Advance the `ReadDir` iterator |
| `FindClose` | Remove from a search-handle registry |
| `GetFullPathNameW` | Resolve relative → absolute using `std::fs::canonicalize` |
| `PathFileExistsW` (Shlwapi) | `std::path::Path::exists` |

All path-taking APIs must call `wide_path_to_linux` on their input.

---

## Phase 13 — Process / Thread Robustness (Priority: MEDIUM)

**Goal:** Support multithreaded Windows programs.

### 13.1 Fix `ExitProcess`

Currently a no-op.  Should call `std::process::exit(exit_code)`.

### 13.2 Fix `CreateThread` → real Linux thread

The current trampoline creates a thread but the Windows thread-function calling convention
differs.  Verify that the trampoline generated for the thread function entry is correct.

### 13.3 Implement `WaitForSingleObject` (thread join)

Map to `thread::JoinHandle::join` from the thread-handle registry.

### 13.4 Implement `WaitForMultipleObjects`

Map to iterating thread join handles.

### 13.5 `Sleep` accuracy

Currently uses `thread::sleep(Duration::from_millis(ms))`.  This is fine; no change needed.

---

## Phase 14 — Networking (Priority: LOW)

**Goal:** Enable simple WinSock2 programs.

### APIs required for a minimal HTTP GET

- `WSAStartup`, `WSACleanup`
- `socket`, `closesocket`
- `connect`, `send`, `recv`
- `gethostbyname` / `getaddrinfo`
- `htons`, `htonl`, `ntohs`, `ntohl`

### Mapping to Linux

All WinSock2 APIs map 1:1 to POSIX sockets.  Key differences:

- Socket handles on Windows are `SOCKET` (usize), not fd (i32).  Store in a socket-handle
  registry similar to `FILE_HANDLES`.
- `WSAGetLastError()` maps to `errno`.
- `WSAEWOULDBLOCK` (10035) maps to `EAGAIN` (11).

### New DLL required

Add `WS2_32.dll` to the DLL manager exports in `litebox_shim_windows/src/loader/dll.rs`.

---

## Phase 15 — GUI Stubs (Priority: LOW)

**Goal:** Prevent crashes in programs that link GUI APIs.

### Minimal stubs needed

| API | Stub return value |
|---|---|
| `MessageBoxW` | 1 (IDOK) — print to stderr |
| `RegisterClassExW` | Non-zero (fake ATOM) |
| `CreateWindowExW` | Non-null fake HWND |
| `ShowWindow` | 1 |
| `UpdateWindow` | 1 |
| `GetMessageW` | 0 (no messages) |
| `TranslateMessage` | 0 |
| `DispatchMessageW` | 0 |
| `DestroyWindow` | 1 |

These stubs allow headless execution of programs that have optional GUI code paths.

---

## Phase 16 — Registry (Priority: LOW)

**Goal:** Persist registry reads/writes in a JSON or sqlite file.

### Approach

Implement a lightweight in-process registry backed by a `HashMap`:
- Keys: `HKEY` pseudo-handle → path string
- Values: `HashMap<String, RegistryValue>`

File-backed persistence can be added in a later iteration.

### APIs

`RegOpenKeyExW`, `RegCreateKeyExW`, `RegQueryValueExW`, `RegSetValueExW`, `RegDeleteValueW`,
`RegCloseKey`, `RegEnumKeyExW`, `RegEnumValueW`.

---

## Phase 17 — Robustness and Security (Priority: ONGOING)

### 17.1 Path traversal prevention

`wide_path_to_linux` currently resolves paths as-is.  Consider:
- Optionally sandboxing all paths to a configurable root (e.g. `--root /tmp/wol-sandbox`).
- Rejecting paths that escape the sandbox root after `canonicalize`.

### 17.2 Handle validation

The `FILE_HANDLES` map currently has no bound on size.  Add a maximum of e.g. 1024 open handles
and return `ERROR_TOO_MANY_OPEN_FILES` (4) when exceeded.

### 17.3 Overflow / truncation auditing

All `as u32` / `as usize` casts should be reviewed with `clippy::cast_possible_truncation`
enabled for the `litebox_platform_linux_for_windows` crate.

### 17.4 Fuzzing entry points

Use `cargo-fuzz` targets for:
- PE binary parsing (`PeLoader::load`)
- Wide-string helpers (`wide_path_to_linux`, `wide_str_to_string`)
- Trampoline generation (`generate_trampoline`)

---

## Phase 18 — Test Coverage and CI (Priority: ONGOING)

### 18.1 Integrate Windows test-program results into CI

Add a CI step that runs all `windows_test_programs/*.exe` under the runner and checks exit
codes / stdout matches.  Currently this is manual.

### 18.2 Ratchet for API stubs

Create a `dev_tests` ratchet for the number of `// stub` or `not implemented` comments in
`kernel32.rs` and `lib.rs`, to track progress on replacing stubs with real implementations.

### 18.3 Code coverage

Enable `cargo-llvm-cov` for the Windows-on-Linux crates to measure which kernel32/msvcrt stubs
are exercised by the test programs.

---

## Implementation Roadmap

```
Priority  Phase  Description                         Complexity
HIGH      10     Fix WriteFile round-trip            Medium
HIGH      11     Command-line argument passing       Medium
MEDIUM    12     Extended file system APIs           Low-Medium per API
MEDIUM    13     Process/thread robustness           Medium
LOW       14     WinSock2 networking                 High
LOW       15     GUI stubs                           Low
LOW       16     Registry persistence                Medium
ONGOING   17     Security & robustness               Ongoing
ONGOING   18     CI & test coverage                  Ongoing
```

---

## Quick Reference: Adding a New API

1. **Implement** the function in `kernel32.rs` (or `msvcrt.rs` for CRT functions):
   - Use `wide_str_to_string` or `wide_path_to_linux` for wide-string parameters.
   - Use `copy_utf8_to_wide` for wide-string output buffers.
   - Call `kernel32_SetLastError(code)` on failure.
   - Mark as `#[unsafe(no_mangle)] pub unsafe extern "C" fn kernel32_<Name>`.

2. **Register** in `function_table.rs`:
   ```rust
   FunctionImpl {
       name: "CreateDirectoryW",
       dll_name: "KERNEL32.dll",
       num_params: 2,
       impl_address: crate::kernel32::kernel32_CreateDirectoryW as *const () as usize,
   },
   ```

3. **Add to DLL exports** in `litebox_shim_windows/src/loader/dll.rs` if not already present.

4. **Write a unit test** in the `#[cfg(test)]` block at the bottom of the implementing file.

5. **Run** `cargo fmt && cargo clippy --all-targets && cargo test -p litebox_platform_linux_for_windows`.

---

## Session Notes (Session 9)

### Accomplished

- Implemented real `GetEnvironmentVariableW` / `SetEnvironmentVariableW` backed by `libc::getenv`
  / `setenv` / `unsetenv`.
- Implemented real `GetEnvironmentStringsW` returning the full process environment block.
- Implemented `GetCommandLineW` reading from a new `PROCESS_COMMAND_LINE` global.
- Exposed `set_process_command_line` from the platform crate and wired it into the runner so that
  Windows programs receive the correct command line before their entry point executes.
- Added `wide_str_to_string` and `wide_path_to_linux` helpers (the latter handles the MinGW
  root-relative path encoding where leading `/` is stored as a null u16).
- Implemented real `CreateDirectoryW`, `DeleteFileW`, `GetFileAttributesW`.
- Implemented `CreateFileW` with a file-handle registry (`FILE_HANDLES` + `FILE_HANDLE_COUNTER`).
- Implemented `ReadFile` backed by the handle registry.
- Extended `WriteFile` to handle both stdout/stderr and regular file handles.
- Fixed `CloseHandle` to remove entries from the file-handle registry.
- Updated unit tests that were written for the old stubs.
- Updated `ratchet_globals` limit from 20 → 21 (net +1 global due to three new globals minus two
  removed stub statics).

### Remaining issue from this session

`WriteFile` to a regular file still returns `ERROR_INVALID_HANDLE` because the Rust MinGW stdlib
likely routes `std::fs::File::write_all` through the C runtime (`_write` → `NtWriteFile`) rather
than calling `WriteFile` directly.  The fix requires unifying the kernel32 file-handle registry
with the NTDLL NtWriteFile implementation (Phase 10.1).
