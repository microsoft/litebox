# Windows-on-Linux Support — Session Summary (Phase 44)

## ⚡ CURRENT STATUS ⚡

**Branch:** `copilot/implement-windows-on-linux-support`
**Goal:** Phase 44 — `std::deque<void*>`, `std::stack<void*>`, `std::queue<void*>`, MSVCRT temp-file helpers, WinSock service/protocol lookup, KERNEL32 volume path enumeration.

### Status at checkpoint

| Component | State |
|-----------|-------|
| All tests (728 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcp140.rs`
  - Added `DEQUE_REGISTRY` global for `std::deque<void*>` state
  - Added `msvcp140__deque_ctor` — default constructor
  - Added `msvcp140__deque_dtor` — destructor
  - Added `msvcp140__deque_push_back` — append to back
  - Added `msvcp140__deque_push_front` — prepend to front
  - Added `msvcp140__deque_pop_front` — remove and return front element
  - Added `msvcp140__deque_pop_back` — remove and return back element
  - Added `msvcp140__deque_front` — return reference (`void*&`) to front element (returns `*mut *mut u8`)
  - Added `msvcp140__deque_back` — return reference (`void*&`) to back element (returns `*mut *mut u8`)
  - Added `msvcp140__deque_size` — element count
  - Added `msvcp140__deque_clear` — remove all elements
  - 4 unit tests in `tests_deque` module
  - Added `STACK_REGISTRY` global for `std::stack<void*>` state
  - Added `msvcp140__stack_ctor` — default constructor
  - Added `msvcp140__stack_dtor` — destructor
  - Added `msvcp140__stack_push` — push element (LIFO)
  - Added `msvcp140__stack_pop` — pop element (LIFO)
  - Added `msvcp140__stack_top` — return reference (`void*&`) to top element (returns `*mut *mut u8`)
  - Added `msvcp140__stack_size` — element count
  - Added `msvcp140__stack_empty` — empty predicate
  - 3 unit tests in `tests_stack` module
  - Added `QUEUE_REGISTRY` global for `std::queue<void*>` state
  - Added `msvcp140__queue_ctor` — default constructor
  - Added `msvcp140__queue_dtor` — destructor
  - Added `msvcp140__queue_push` — enqueue element
  - Added `msvcp140__queue_pop` — dequeue element (FIFO)
  - Added `msvcp140__queue_front` — return reference (`void*&`) to front element (returns `*mut *mut u8`)
  - Added `msvcp140__queue_back` — return reference (`void*&`) to back element (returns `*mut *mut u8`)
  - Added `msvcp140__queue_size` — element count
  - Added `msvcp140__queue_empty` — empty predicate
  - 3 unit tests in `tests_queue` module
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `tmpnam` — generate unique temp file name (delegates to libc `tmpnam`)
  - Added `_mktemp` — modify template in-place with unique suffix (delegates to libc `mktemp`)
  - Added `_tempnam` — allocate temp file name in given directory (delegates to libc `tempnam`)
  - 3 unit tests
- `litebox_platform_linux_for_windows/src/ws2_32.rs`
  - Added `WSANO_DATA` (11004) constant
  - Added `getservbyname` — look up service entry by name (delegates to libc)
  - Added `getservbyport` — look up service entry by port (delegates to libc)
  - Added `getprotobyname` — look up protocol entry by name (delegates to libc)
  - 3 unit tests
- `litebox_platform_linux_for_windows/src/kernel32.rs`
  - Added `kernel32_GetVolumePathNamesForVolumeNameW` — returns single `\` mount path
  - 1 unit test
- `litebox_platform_linux_for_windows/src/function_table.rs` — 37 new `FunctionImpl` entries
- `litebox_shim_windows/src/loader/dll.rs`
  - 25 new msvcp140.dll stubs (88–112): deque (10) + stack (7) + queue (8)
  - 3 new MSVCRT.dll stubs (0x10B–0x10D): tmpnam, _mktemp, _tempnam
  - 3 new WS2_32.dll stubs (0x2F–0x31): getservbyname, getservbyport, getprotobyname
  - 1 new KERNEL32.dll stub (0xFD): GetVolumePathNamesForVolumeNameW
- `litebox_runner_windows_on_linux_userland/tests/integration.rs` — Phase 44 resolution test block
- `dev_tests/src/ratchet.rs` — updated globals count 67→70 for DEQUE_REGISTRY + STACK_REGISTRY + QUEUE_REGISTRY

### Next phase suggestions
- **Phase 45**: `std::priority_queue<T>` basic stubs (ctor, dtor, push, pop, top, size, empty)
- **Phase 45**: More MSVCRT: `_access`, `_access_s`, `_chmod`, `_umask`
- **Phase 45**: More KERNEL32: `GetDriveTypeW`, `GetDiskFreeSpaceExW`, `GetLogicalDrives`
- **Phase 45**: More WinSock: `gethostbyaddr`, `getservbyport` edge cases
- **Phase 45**: `std::set<void*>` basic stubs (ctor, dtor, insert, find, size, clear)

---

# Windows-on-Linux Support — Session Summary (Phase 43)

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `_getcwd` — get current working directory (delegates to `libc::getcwd`, allocates on null buf)
  - Added `_chdir` — change current directory (delegates to `libc::chdir`)
  - Added `_mkdir` — create directory (delegates to `libc::mkdir` with mode 0o777)
  - Added `_rmdir` — remove directory (delegates to `libc::rmdir`)
  - 6 unit tests for all new functions
- `litebox_platform_linux_for_windows/src/msvcp140.rs`
  - Added `SS_REGISTRY` global for `std::stringstream` state
  - Added `msvcp140__stringstream_ctor` — default constructor
  - Added `msvcp140__stringstream_ctor_str` — constructor from C string
  - Added `msvcp140__stringstream_dtor` — destructor
  - Added `msvcp140__stringstream_str` — get buffer as malloc'd C string
  - Added `msvcp140__stringstream_str_set` — set buffer from C string, reset pos
  - Added `msvcp140__stringstream_read` — read bytes from current read position
  - Added `msvcp140__stringstream_write` — append bytes to buffer
  - Added `msvcp140__stringstream_seekg` — seek read position
  - Added `msvcp140__stringstream_tellg` — get read position
  - Added `msvcp140__stringstream_seekp` — set write position (resize buffer)
  - Added `msvcp140__stringstream_tellp` — get write position (buffer length)
  - 5 unit tests in `tests_stringstream` module
  - Added `UMAP_REGISTRY` global for `std::unordered_map` state
  - Added `msvcp140__unordered_map_ctor` — constructor
  - Added `msvcp140__unordered_map_dtor` — destructor
  - Added `msvcp140__unordered_map_insert` — insert (key, value) pair
  - Added `msvcp140__unordered_map_find` — look up key
  - Added `msvcp140__unordered_map_size` — element count
  - Added `msvcp140__unordered_map_clear` — remove all elements
  - 3 unit tests in `tests_unordered_map` module
  - Pre-existing clippy fix: `val as *mut u8` → `val.cast_mut()` in `tests_map`
- `litebox_platform_linux_for_windows/src/kernel32.rs`
  - Added `kernel32_FindFirstVolumeW` — returns sentinel handle + synthetic GUID path
  - Added `kernel32_FindNextVolumeW` — always returns 0 with ERROR_NO_MORE_FILES
  - Added `kernel32_FindVolumeClose` — always returns 1 (success)
  - 3 unit tests for volume enumeration
- `litebox_platform_linux_for_windows/src/ws2_32.rs`
  - Pre-existing clippy fix: `libc::AF_INET as i32` → `libc::AF_INET` in 2 tests
  - Pre-existing clippy fix: `libc::POLLIN as i16` → `libc::POLLIN` in 1 test
- `litebox_platform_linux_for_windows/src/function_table.rs` — 22 new `FunctionImpl` entries
- `litebox_shim_windows/src/loader/dll.rs`
  - 3 new KERNEL32.dll stubs (0xFA–0xFC): FindFirstVolumeW, FindNextVolumeW, FindVolumeClose
  - 4 new MSVCRT.dll stubs (0x107–0x10A): _getcwd, _chdir, _mkdir, _rmdir
  - 15 new msvcp140.dll stubs (71–85): stringstream (11) + unordered_map (4)
- `litebox_runner_windows_on_linux_userland/tests/integration.rs` — Phase 43 resolution test block
- `dev_tests/src/ratchet.rs` — updated globals count 65→67 for SS_REGISTRY + UMAP_REGISTRY

### Next phase suggestions
- **Phase 44**: `std::deque<T>` basic stubs (ctor, dtor, push_back, pop_front, front, back, size, clear)
- **Phase 44**: More MSVCRT: `_tempnam`, `_mktemp`, `tmpnam`, `tmpfile`
- **Phase 44**: More KERNEL32: `GetVolumePathNamesForVolumeNameW`, `GetVolumeInformationW`
- **Phase 44**: `std::stack<T>` / `std::queue<T>` basic stubs
- **Phase 44**: More WinSock: `getservbyname`, `getservbyport`, `getprotobyname`

---


**Goal:** Phase 42 — MSVCRT path manipulation, WS2_32 networking, msvcp140 istringstream.

### Status at checkpoint

| Component | State |
|-----------|-------|
| All tests (672 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `_fullpath` — resolves absolute path via `realpath()`
  - Added `_splitpath` — splits path into drive/dir/fname/ext components
  - Added `_splitpath_s` — safe version of `_splitpath` with length parameters
  - Added `build_makepath` private helper
  - Added `_makepath` — builds path from components
  - Added `_makepath_s` — safe version of `_makepath`
  - Unit tests for all new functions
- `litebox_platform_linux_for_windows/src/ws2_32.rs`
  - Added `WSAIoctl` — stub returning SOCKET_ERROR + WSAEOPNOTSUPP
  - Added `inet_addr` — converts dotted-decimal IPv4 to binary via `libc::inet_addr`
  - Added `inet_pton` — converts text address to binary via `libc::inet_pton`
  - Added `inet_ntop` — converts binary address to text via `libc::inet_ntop`
  - Added `WSAPoll` — wraps `libc::poll`
- `litebox_platform_linux_for_windows/src/msvcp140.rs`
  - Added `ISS_REGISTRY` global for `std::istringstream` state
  - Added `msvcp140__istringstream_ctor` — default constructor
  - Added `msvcp140__istringstream_ctor_str` — constructor from C string
  - Added `msvcp140__istringstream_dtor` — destructor
  - Added `msvcp140__istringstream_str` — get buffer as malloc'd C string
  - Added `msvcp140__istringstream_str_set` — set buffer from C string, reset pos
  - Added `msvcp140__istringstream_read` — read bytes from current position
  - Added `msvcp140__istringstream_seekg` — seek read position
  - Added `msvcp140__istringstream_tellg` — get read position
  - 6 unit tests in `tests_istringstream` module
- `litebox_platform_linux_for_windows/src/function_table.rs` — 18 new `FunctionImpl` entries
- `litebox_shim_windows/src/loader/dll.rs` — 5 MSVCRT stubs (0x102–0x106), 5 WS2_32 stubs (0x2A–0x2E), 8 msvcp140 stubs (63–70)
- `litebox_runner_windows_on_linux_userland/tests/integration.rs` — Phase 42 resolution test block
- `dev_tests/src/ratchet.rs` — updated globals count 64→65 for ISS_REGISTRY

### Next phase suggestions
- **Phase 43**: `std::stringstream` (bidirectional: combines istringstream + ostringstream)
- **Phase 43**: More MSVCRT path: `_getcwd`, `_chdir`, `_mkdir`, `_rmdir`
- **Phase 43**: More WinSock: `WSAStartup` improvements, `getaddrinfo`/`freeaddrinfo` edge cases
- **Phase 43**: `std::unordered_map<K,V>` basic stubs (ctor, dtor, insert, find, size, clear)
- **Phase 43**: More KERNEL32: `FindFirstVolumeW`, `FindNextVolumeW`, `FindVolumeClose`

---

# Windows-on-Linux Support — Session Summary (Phase 40)

## ⚡ CURRENT STATUS ⚡

**Branch:** `copilot/continue-windows-linux-support`
**Goal:** Phase 40 — MSVCRT stat functions, wide-path file opens, and WinSock2 event APIs.

### Status at checkpoint

| Component | State |
|-----------|-------|
| All tests (646 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `WinStat32` and `WinStat64` structs (MSVC x64 ABI-compatible layout with explicit padding)
  - Added `WIN_S_IFREG`, `WIN_S_IFDIR`, `WIN_S_IFCHR`, `WIN_S_IREAD`, `WIN_S_IWRITE`, `WIN_S_IEXEC` named constants
  - Added `fill_win_stat32` / `fill_win_stat64` helpers mapping Linux `libc::stat` → Windows structs
  - Added `_stat`, `_stat64`, `_fstat`, `_fstat64` — file metadata for path and open fd
  - Added `_wopen`, `_wsopen` — wide-char (UTF-16) path file open
  - Added `_wstat`, `_wstat64` — wide-char file metadata
  - 7 unit tests
- `litebox_platform_linux_for_windows/src/ws2_32.rs`
  - Extended `SocketEntry` with `network_events_mask` field
  - Added `WSA_EVENT_COUNTER` and `WSA_EVENT_HANDLES` globals for event registry
  - Added `WsaNetworkEvents` struct (matches Windows `WSANETWORKEVENTS`)
  - Added `WSACreateEvent`, `WSACloseEvent`, `WSAResetEvent`, `WSASetEvent`
  - Added `WSAEventSelect` — stores FD_* mask on socket entry
  - Added `WSAEnumNetworkEvents` — uses `poll(2)` with 0 timeout to query readiness
  - Added `WSAWaitForMultipleEvents` — spin-sleep loop with 10 ms granularity
  - Added `gethostbyname` — delegates to `libc::gethostbyname`
  - 6 unit tests
- `litebox_platform_linux_for_windows/src/function_table.rs` — 16 new `FunctionImpl` entries
- `litebox_shim_windows/src/loader/dll.rs` — 8 new WS2_32.dll stubs (0x21–0x28), 8 new MSVCRT.dll stubs (0xF8–0xFF)
- `dev_tests/src/ratchet.rs` — updated globals count 60→62
- `litebox_runner_windows_on_linux_userland/tests/integration.rs` — Phase 40 resolution test blocks

### Next phase suggestions
- **Phase 41**: `std::map<K,V>` basic stubs (ctor, dtor, insert, find, size, clear)
- **Phase 41**: `std::ostringstream` / `std::stringstream` basic stubs
- **Phase 41**: More WinSock: `WSAAsyncSelect`, `select` with overlapped I/O
- **Phase 41**: `_sopen_s`, `_wsopen_s` — safe versions of `_sopen`/`_wsopen`
- **Phase 41**: Registry stubs: `RegOpenKeyExW`, `RegQueryValueExW`, `RegCloseKey`

---


| Component | State |
|-----------|-------|
| All tests (635 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `translate_open_flags()` helper: maps Windows `_O_*` flags → Linux `O_*` flags
  - Added 15 new low-level file I/O functions: `_open`, `_close`, `_lseek`, `_lseeki64`, `_tell`, `_telli64`, `_eof`, `_creat`, `_commit`, `_dup`, `_dup2`, `_chsize`, `_chsize_s`, `_filelength`, `_filelengthi64`
  - 6 unit tests
- `litebox_platform_linux_for_windows/src/msvcp140.rs`
  - Added `std::vector<char>` with MSVC x64 ABI layout (24-byte, 3-pointer: `_Myfirst`/`_Mylast`/`_Myend`)
  - Functions: default ctor, dtor, `push_back` (2× growth), `size`, `capacity`, `clear`, `data` (mut + const), `reserve`
  - Exported with correct MSVC mangled names
  - 5 unit tests
- `litebox_platform_linux_for_windows/src/function_table.rs` — 24 new `FunctionImpl` entries
- `litebox_shim_windows/src/loader/dll.rs` — 15 new MSVCRT stubs (0xE9–0xF7), 9 new msvcp140 stubs (42–50)
- `litebox_runner_windows_on_linux_userland/tests/integration.rs` — Phase 39 resolution test blocks

### Next phase suggestions
- **Phase 40**: `std::map<K,V>` basic stubs (ctor, dtor, insert, find, size, clear)
- **Phase 40**: `std::ostringstream` / `std::stringstream` basic stubs
- **Phase 40**: `_wopen`, `_wsopen`, `_wstat`, `_wfstat` (wide-char file path variants)
- **Phase 40**: `_stat64`, `_fstat64`, `_stat` (file metadata)
- **Phase 40**: More WinSock: `WSAEventSelect`, `WSAEnumNetworkEvents`, `gethostbyname`

---

# Windows-on-Linux Support — Session Summary (Phase 38)

## ⚡ CURRENT STATUS ⚡

**Branch:** `copilot/continue-windows-on-linux-support-another-one`
**Goal:** Phase 38 — `basic_wstring<wchar_t>`, `_wfindfirst`/`_wfindnext`/`_findclose`, locale-aware printf variants.

### Status at checkpoint

| Component | State |
|-----------|-------|
| All tests (600 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcp140.rs`
  - Added `std::basic_string<wchar_t>` full MSVC x64 ABI implementation (SSO threshold=7, 32-byte layout)
  - Functions: default ctor, construct-from-wide-cstr, copy ctor, dtor, `c_str()`, `size()`, `empty()`, copy assignment, assign-from-cstr, `append()`
  - 6 unit tests in `tests_wstring` module
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `_wfindfirst64i32` / `_wfindnext64i32` / `_findclose` — wide-character file enumeration using `libc::opendir`/`readdir`/`closedir` with a mutex-protected handle table and DP wildcard matching
  - Added `_printf_l`, `_fprintf_l`, `_sprintf_l`, `_snprintf_l`, `_wprintf_l` — locale-aware printf variants (locale ignored)
  - 8 new unit tests
- `litebox_platform_linux_for_windows/src/function_table.rs` — 18 new FunctionImpl entries
- `litebox_shim_windows/src/loader/dll.rs` — 10 new msvcp140.dll stubs, 8 new MSVCRT.dll stubs
- `litebox_runner_windows_on_linux_userland/tests/integration.rs` — Phase 38 resolution test block
- `dev_tests/src/ratchet.rs` — updated globals count 55→58

### Next phase suggestions
- **Phase 39**: C++ STL containers (e.g., `std::vector<T>`, `std::map<K,V>`)
- **Phase 39**: More file I/O: `_open`/`_close`/`_lseek`/`_read`/`_write` with Windows semantics
- **Phase 39**: Exception handling: `_CxxThrowException`, `__CxxFrameHandler3`
- **Phase 39**: Wide string utilities: `wcslen`, `wcscpy`, `wcscmp`, `wcscat`, `wcsstr`
- **Phase 39**: Registry stubs: `RegOpenKeyExW`, `RegQueryValueExW`, `RegCloseKey`

---

# Windows-on-Linux Support — Session Summary (Phase 37)

## ⚡ CURRENT STATUS ⚡

**Branch:** `copilot/continue-windows-on-linux-support-another-one`
**Goal:** Phase 37 — UCRT sprintf/snprintf entry points, fscanf/scanf, numeric conversions, std::basic_string<char>.

### Status at checkpoint

| Component | State |
|-----------|-------|
| All tests (585 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `ucrt__stdio_common_vsprintf` — UCRT vsprintf entry point (writes to buffer)
  - Added `ucrt__stdio_common_vsnprintf_s` — UCRT vsnprintf_s with `_TRUNCATE` semantics
  - Added `ucrt__stdio_common_vsprintf_s` — UCRT vsprintf_s (overflow-checking)
  - Added `ucrt__stdio_common_vswprintf` — UCRT wide vsprintf (UTF-16 output buffer)
  - Added `msvcrt_scanf` — scanf from stdin (up to 16 specifiers)
  - Added `msvcrt_fscanf` — fscanf from FILE* (up to 16 specifiers)
  - Added `ucrt__stdio_common_vfscanf` — UCRT fscanf entry point
  - Added `msvcrt__ultoa` — unsigned long to string
  - Added `msvcrt__i64toa` — i64 to string (delegates to `_ltoa`)
  - Added `msvcrt__ui64toa` — u64 to string (delegates to `_ultoa`)
  - Added `msvcrt__strtoi64` — string to i64 (via `libc::strtoll`)
  - Added `msvcrt__strtoui64` — string to u64 (via `libc::strtoull`)
  - Added `msvcrt__itow`, `msvcrt__ltow`, `msvcrt__ultow`, `msvcrt__i64tow`, `msvcrt__ui64tow` — integer to wide string
  - Added 17 new unit tests
- `litebox_platform_linux_for_windows/src/msvcp140.rs`
  - Implemented `std::basic_string<char>` with MSVC x64 ABI layout (SSO threshold 15):
    - `msvcp140__basic_string_ctor` — default constructor (empty SSO)
    - `msvcp140__basic_string_ctor_cstr` — construct from C string
    - `msvcp140__basic_string_copy_ctor` — copy constructor
    - `msvcp140__basic_string_dtor` — destructor (frees heap if not SSO)
    - `msvcp140__basic_string_c_str` — returns data pointer
    - `msvcp140__basic_string_size` — returns length
    - `msvcp140__basic_string_empty` — returns true if empty
    - `msvcp140__basic_string_assign_op` — copy assignment operator
    - `msvcp140__basic_string_assign_cstr` — assign from C string
    - `msvcp140__basic_string_append_cstr` — append C string
  - Added 5 new unit tests
- `litebox_platform_linux_for_windows/src/function_table.rs`
  - Added `FunctionImpl` entries for all new MSVCRT and msvcp140 functions
- `litebox_shim_windows/src/loader/dll.rs`
  - Added MSVCRT.dll stub exports (0xD0–0xE0) for Phase 37 functions
  - Added msvcp140.dll stub exports (22–31) for `basic_string<char>` members
- `litebox_runner_windows_on_linux_userland/tests/integration.rs`
  - Added Phase 37 assertion block for MSVCRT.dll and msvcp140.dll new exports

### Key design decisions
- **`std::basic_string<char>` ABI**: Matches MSVC x64 layout: 16-byte SSO buffer union + 8-byte size + 8-byte capacity. SSO threshold is 15 chars. Uses `ptr::read_unaligned`/`ptr::write_unaligned` defensively.
- **Malloc failure handling**: If heap allocation fails in `basic_string`, the object is left in a valid empty SSO state instead of storing a null heap pointer with non-zero size.
- **`ucrt__stdio_common_vfscanf`**: For stdin (stream == null), uses `libc::fdopen(0, "r")` to obtain a FILE*. All actual FILE* values are valid Linux FILE* handles.
- **Wide integer conversion**: `_itow`/`_ltow`/etc. produce ASCII-only wide strings (each char fits in u16); this covers all practical cases for decimal/hex output.

### What the next session should consider

**Possible Phase 38 directions:**
1. **WriteFile round-trip fix (Phase 10)** — unify kernel32 file handle registry with NtWriteFile/NtReadFile
2. **`std::basic_string<wchar_t>`** — wide string stubs analogous to `basic_string<char>`
3. **More msvcp140.dll** — `std::vector<T>` operations, `std::ostringstream`, `std::cout`/`std::cerr` objects
4. **More UCRT** — `_printf_l`, `_fprintf_l`, `_sprintf_l` (locale-aware variants)
5. **`_wfindfirst`/`_wfindnext`/`_findclose`** — directory enumeration via CRT
6. **WinSock completions** — `WSAEventSelect`, `WSAEnumNetworkEvents`, `gethostbyname`

### Build & test commands

```bash
cd /home/runner/work/litebox/litebox

# Quick build
cargo build -p litebox_platform_linux_for_windows

# Full build + runner
cargo build -p litebox_runner_windows_on_linux_userland

# Run all Windows-specific tests
cargo nextest run -p litebox_shim_windows \
                 -p litebox_platform_linux_for_windows \
                 -p litebox_runner_windows_on_linux_userland

# Lint (with CI-equivalent flags)
RUSTFLAGS="-Dwarnings" cargo clippy -p litebox_shim_windows \
             -p litebox_platform_linux_for_windows \
             -p litebox_runner_windows_on_linux_userland

# Ratchet tests
cargo test -p dev_tests
```

### Key source locations

| What | File | ~Line |
|------|------|-------|
| `ucrt__stdio_common_vsprintf` | `litebox_platform_linux_for_windows/src/msvcrt.rs` | ~4786 |
| `ucrt__stdio_common_vfscanf` | same | ~5242 |
| `msvcrt_scanf` | same | ~5148 |
| `msvcrt_fscanf` | same | ~5190 |
| `msvcrt__ultoa` | same | ~2608 |
| `msvcrt__strtoi64` / `_strtoui64` | same | ~2660 |
| `msvcrt__itow` and wide variants | same | ~2720 |
| `std::basic_string<char>` | `litebox_platform_linux_for_windows/src/msvcp140.rs` | ~370 |
| Function table | `litebox_platform_linux_for_windows/src/function_table.rs` | — |
| DLL manager stubs | `litebox_shim_windows/src/loader/dll.rs` | — |



## ⚡ CURRENT STATUS ⚡

**Branch:** `copilot/continue-windows-on-linux-support-again`
**Goal:** Phase 36 — `sscanf` real implementation, `_wcsdup`, and `__stdio_common_vsscanf`.

### Status at checkpoint

| Component | State |
|-----------|-------|
| `seh_c_test.exe` | ✅ **21/21 PASS** |
| `seh_cpp_test.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_clang.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_msvc.exe` | ✅ **21/21 PASS** |
| All tests (563 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `count_scanf_specifiers(fmt: &[u8]) -> usize` — counts non-suppressed format conversion specifiers in a scanf format string (handles `%%`, `%*d`, `%[...]`, length modifiers, etc.)
  - Added `format_scanf_va(buf, fmt, args: &mut VaList) -> i32` — extracts up to 16 output pointers from a Linux VaList, calls `libc::sscanf` with those 16 explicit args
  - Added `format_scanf_raw(buf, fmt, ap: *mut u8) -> i32` — bridges a Windows x64 va_list pointer (via the same `VaListTag` trick as `format_printf_raw`) to `format_scanf_va`
  - Replaced `msvcrt_sscanf` stub (always returned 0) with real implementation calling `format_scanf_va`
  - Added `msvcrt__wcsdup` — heap duplicate of a null-terminated wide string (analogous to `_strdup`)
  - Added `ucrt__stdio_common_vsscanf` — UCRT `__stdio_common_vsscanf(options, buf, buf_count, fmt, locale, arglist)` entry point; delegates to `format_scanf_raw`
  - Added 7 new unit tests (`test_wcsdup`, `test_wcsdup_null`, `test_count_scanf_specifiers`, `test_sscanf_int`, `test_sscanf_two_ints`, `test_sscanf_string`, `test_sscanf_null_input`)
- `litebox_platform_linux_for_windows/src/function_table.rs`
  - Fixed `sscanf` `num_params` from 2 → 18 (buf + fmt + up to 16 pointer args, so the trampoline actually passes all pointer arguments)
  - Added `FunctionImpl` entries for `_wcsdup` and `__stdio_common_vsscanf`
- `litebox_shim_windows/src/loader/dll.rs`
  - Added `_wcsdup` (MSVCRT_BASE + 0xCD) and `__stdio_common_vsscanf` (MSVCRT_BASE + 0xCE) stub exports
- `litebox_runner_windows_on_linux_userland/tests/integration.rs`
  - Added Phase 36 assertion block checking both new exports are resolvable

### Key design decisions
- **sscanf strategy**: Parse the format string to count non-suppressed specifiers, extract exactly that many `*mut c_void` pointers from the Linux VaList, fill the remaining 16 slots with null, then call `libc::sscanf` with all 16 explicit args. libc::sscanf only dereferences as many pointers as the format specifies, so the trailing nulls are never accessed.
- **`num_params: 18`**: The trampoline translates N positional Windows arguments to Linux System V. Setting this to 18 allows up to 16 scanf output pointers (plus buf + fmt) to pass through the trampoline correctly.
- **`MAX_SCANF_ARGS: 16`**: Constant limiting the maximum number of format specifiers handled. Sufficient for all practical use cases.

### What the next session should consider

**Possible Phase 37 directions:**
1. **`fscanf` / `scanf`** — similar to sscanf but reading from a FILE* or stdin
2. **More `msvcp140.dll`** — `std::basic_string` member functions, `std::vector` operations, `std::cout`/`std::cerr` stream stubs
3. **WriteFile round-trip fix** — unify kernel32 file handle registry with NtWriteFile/NtReadFile
4. **`__stdio_common_vsprintf`** — UCRT's `sprintf`/`snprintf` entry point (similar to `__stdio_common_vfprintf`)
5. **WinSock completions** — `WSAEventSelect`, `WSAEnumNetworkEvents`, `GetHostByName`
6. **More numeric conversion** — `_itoa`, `_itow`, `_ultoa`, `_ui64toa`

### Build & test commands

```bash
cd /home/runner/work/litebox/litebox

# Quick build
cargo build -p litebox_platform_linux_for_windows

# Full build + runner
cargo build -p litebox_runner_windows_on_linux_userland

# Run all Windows-specific tests
cargo nextest run -p litebox_shim_windows \
                 -p litebox_platform_linux_for_windows \
                 -p litebox_runner_windows_on_linux_userland

# Lint (with CI-equivalent flags)
RUSTFLAGS="-Dwarnings" cargo clippy -p litebox_shim_windows \
             -p litebox_platform_linux_for_windows \
             -p litebox_runner_windows_on_linux_userland

# Ratchet tests
cargo test -p dev_tests
```

### Key source locations

| What | File | ~Line |
|------|------|-------|
| `count_scanf_specifiers` | `litebox_platform_linux_for_windows/src/msvcrt.rs` | ~683 |
| `format_scanf_va` | same | ~745 |
| `format_scanf_raw` | same | ~785 |
| `msvcrt_sscanf` | same | ~4865 |
| `ucrt__stdio_common_vsscanf` | same | ~4780 |
| `msvcrt__wcsdup` | same | ~3060 |
| `format_printf_raw` | same | ~646 |
| `msvcrt_vprintf` | same | ~1003 |
| Function table | `litebox_platform_linux_for_windows/src/function_table.rs` | — |
| DLL manager stubs | `litebox_shim_windows/src/loader/dll.rs` | — |


## ⚡ CURRENT STATUS ⚡

**Branch:** `copilot/continue-windows-on-linux-support-again`
**Goal:** Phase 35 — `_vsnwprintf`, printf-length helpers (`_scprintf`, `_vscprintf`, `_scwprintf`, `_vscwprintf`), fd/Win32 handle interop (`_get_osfhandle`, `_open_osfhandle`), and extended `msvcp140.dll` stubs (`std::exception`, locale, `ios_base::Init`).

### Status at checkpoint

| Component | State |
|-----------|-------|
| `seh_c_test.exe` | ✅ **21/21 PASS** |
| `seh_cpp_test.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_clang.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_msvc.exe` | ✅ **21/21 PASS** |
| All tests (551 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `msvcrt__vsnwprintf` — size-limited wide-char vsnprintf (returns -1 on truncation per MSVCRT semantics)
  - Added `msvcrt__scprintf` — count characters `printf` would write (no output, variadic)
  - Added `msvcrt__vscprintf` — va_list version of `_scprintf`
  - Added `msvcrt__scwprintf` — count wide characters `wprintf` would write (variadic)
  - Added `msvcrt__vscwprintf` — va_list version of `_scwprintf`
  - Added `msvcrt__get_osfhandle` — CRT fd → Win32 HANDLE (stdin/stdout/stderr return -10/-11/-12)
  - Added `msvcrt__open_osfhandle` — Win32 HANDLE → CRT fd (reverse mapping)
  - Added 12 new unit tests
- `litebox_platform_linux_for_windows/src/msvcp140.rs`
  - Added `msvcp140__exception_what` / `_ctor` / `_ctor_msg` / `_dtor` — `std::exception` stubs
  - Added `msvcp140__Getgloballocale` — global locale stub (returns null)
  - Added `msvcp140__Lockit_ctor` / `_dtor` — locale lock stubs (no-op)
  - Added `msvcp140__ios_base_Init_ctor` / `_dtor` — `ios_base::Init` stubs (no-op)
  - Added 5 new unit tests
- `litebox_platform_linux_for_windows/src/function_table.rs`
  - Added 16 new `FunctionImpl` entries for all new functions
- `litebox_shim_windows/src/loader/dll.rs`
  - Added 7 new MSVCRT.dll stub exports (0xC6–0xCC)
  - Added 9 new msvcp140.dll stub exports (offsets 13–21)
- `litebox_runner_windows_on_linux_userland/tests/integration.rs`
  - Added Phase 35 assertion blocks for MSVCRT.dll and msvcp140.dll new exports

### What the next session should consider

**Possible Phase 36 directions:**
1. **`sscanf`/`fscanf`/`scanf` real implementation** — currently `sscanf` is a stub returning 0. Implement using libc's sscanf with fixed-max-args trick or build a proper scanf parser.
2. **More `msvcp140.dll`** — `std::basic_string` member functions, `std::vector` operations, `std::cout`/`std::cerr` stream stubs
3. **WriteFile round-trip fix (Phase 10)** — unify kernel32 file handle registry with NtWriteFile/NtReadFile so that files opened with CreateFileW can be written via both WriteFile and NtWriteFile
4. **`__stdio_common_vsscanf`** — UCRT's sscanf entry point
5. **`_wcsdup`/`_strdup`** — string duplication functions
6. **WinSock completions** — `WSAEventSelect`, `WSAEnumNetworkEvents`, `GetHostByName`

### Build & test commands

```bash
cd /home/runner/work/litebox/litebox

# Quick build
cargo build -p litebox_platform_linux_for_windows

# Full build + runner
cargo build -p litebox_runner_windows_on_linux_userland

# Run all Windows-specific tests
cargo nextest run -p litebox_shim_windows \
                 -p litebox_platform_linux_for_windows \
                 -p litebox_runner_windows_on_linux_userland

# Lint (with CI-equivalent flags)
RUSTFLAGS="-Dwarnings" cargo clippy -p litebox_shim_windows \
             -p litebox_platform_linux_for_windows \
             -p litebox_runner_windows_on_linux_userland

# Ratchet tests
cargo test -p dev_tests
```

### Key source locations

| What | File | ~Line |
|------|------|-------|
| `format_printf_raw` | `litebox_platform_linux_for_windows/src/msvcrt.rs` | 582 |
| `msvcrt_vprintf` | same | ~1003 |
| `msvcrt_vsprintf` | same | ~1020 |
| `msvcrt_vsnprintf` | same | ~1045 |
| `msvcrt_vswprintf` | same | ~1070 |
| `msvcrt_vfprintf` (fixed) | same | ~968 |
| `ucrt__stdio_common_vfprintf` (fixed) | same | ~4450 |
| `msvcrt_fwprintf` | same | ~4720 |
| `msvcrt__write` | same | ~2060 |
| `msvcrt_getchar`/`msvcrt_putchar` | same | ~2080 |
| Function table | `litebox_platform_linux_for_windows/src/function_table.rs` | — |
| DLL manager stubs | `litebox_shim_windows/src/loader/dll.rs` | — |

