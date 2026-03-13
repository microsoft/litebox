# Windows on Linux: Implementation Status

**Last Updated:** 2026-03-04  
**Total Tests:** 769 passing in Windows-on-Linux crates (697 platform + 51 shim + 12 runner + 9 runner integration) + 5 dev_tests ratchet checks — Phase 45 adds extended USER32 GUI APIs (dialog boxes, menus, clipboard, drawing, capture, monitor info), extended GDI32 graphics primitives (bitmaps, pens, BitBlt, DIBSection, drawing primitives, DC management), and full vulkan-1.dll stub layer (62 Vulkan API functions covering instance, device, surface, swapchain, memory, pipelines, command buffers, synchronisation)  
**Overall Status:** Core infrastructure complete. Seven Rust-based test programs (hello_cli, math_test, env_test, args_test, file_io_test, string_test, getprocaddress_test) run successfully end-to-end through the runner on Linux. **All API stub functions have been fully replaced — stub count is now 0.** Full C++ exception handling implemented and validated: `seh_c_test` (21/21), `seh_cpp_test` MinGW (26/26), `seh_cpp_test_clang` clang/MinGW (26/26), and `seh_cpp_test_msvc` MSVC ABI (21/21) all pass. Phases 33–44 add msvcp140.dll C++ runtime stubs, extended MSVCRT printf/scanf/va variants, `std::basic_string<char/wchar_t>`, file enumeration, locale-aware printf wrappers, low-level POSIX file I/O, stat functions, wide-path file opens, WinSock2 event APIs, path manipulation utilities, `std::vector<char>`, `std::map`, `std::ostringstream`, `std::istringstream`, `std::stringstream`, `std::unordered_map`, extended KERNEL32 process/job management, volume enumeration APIs, `std::deque`/`std::stack`/`std::queue`, and service/protocol lookup APIs. Phase 45 adds full Windows GUI API support and a Vulkan API stub layer.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Windows PE Binary (unmodified .exe)                    │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  litebox_shim_windows (North Layer)                     │
│  - PE/DLL loader                                        │
│  - Windows syscall interface (NTDLL)                    │
│  - API tracing framework                                │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  litebox_platform_linux_for_windows (South Layer)       │
│  - Linux syscall implementations                        │
│  - Windows API → Linux translation                      │
│  - Process/thread management                            │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  litebox_runner_windows_on_linux_userland               │
│  - CLI tool for running Windows programs                │
│  - Configurable tracing options                         │
└─────────────────────────────────────────────────────────┘
```

---

## What Is Implemented ✅

### PE Loading
- Parse PE headers (DOS, NT, Optional headers) and validate signatures
- Load all sections into memory with correct alignment
- Apply base relocations (ASLR rebasing)
- Parse and resolve the Import Address Table (IAT)
- Patch IAT with resolved function addresses

### DLL Emulation
- `DllManager` with stub/trampoline support for KERNEL32, NTDLL, MSVCRT, WS2_32, advapi32, user32
- Case-insensitive DLL name matching
- `LoadLibrary` / `GetProcAddress` / `FreeLibrary` APIs
- 57 trampolined functions with proper Windows x64 → System V AMD64 ABI translation (18 MSVCRT + 39 KERNEL32)
- All KERNEL32 exports have real implementations or permanently-correct no-op behavior (stub count = 0)
- SHELL32.dll and VERSION.dll registered at startup with Phase 25 implementations

### Execution Context
- TEB (Thread Environment Block) and PEB (Process Environment Block) structures
- GS segment register configured to point at TEB (`%gs:0x30` returns TEB pointer)
- Real `mmap`-based stack allocation (1 MB default, grows downward)
- Assembly trampoline calling Windows x64 entry points with correct ABI:
  - 16-byte stack alignment before `call`
  - 32-byte shadow space
  - Return value in RAX

### NTDLL / Core APIs
| Category | Implemented Functions |
|---|---|
| File I/O | `NtCreateFile`, `NtReadFile`, `NtWriteFile`, `NtClose` |
| Console I/O | `GetStdOutput`, `WriteConsole`, `GetStdHandle`, `WriteConsoleW` |
| Memory | `NtAllocateVirtualMemory`, `NtFreeVirtualMemory`, `NtProtectVirtualMemory` |
| Threads | `NtCreateThread`, `NtTerminateThread`, `NtWaitForSingleObject`, `NtCloseHandle` |
| Events (NTDLL) | `NtCreateEvent`, `NtSetEvent`, `NtResetEvent`, `NtWaitForEvent` |
| Environment | `GetEnvironmentVariable`, `SetEnvironmentVariable` |
| Process info | `GetCurrentProcessId` (real PID), `GetCurrentThreadId` (real TID) |
| Registry (emulated) | `RegOpenKeyEx`, `RegQueryValueEx`, `RegCloseKey` |
| Error handling | `GetLastError` / `SetLastError` (thread-local) |

### KERNEL32 Real Implementations
| Function | Implementation |
|---|---|
| `Sleep` | `std::thread::sleep` |
| `GetCurrentThreadId` | `SYS_gettid` syscall |
| `GetCurrentProcessId` | `getpid()` syscall |
| `GetProcessId` | `std::process::id()` |
| `TlsAlloc` / `TlsFree` / `TlsGetValue` / `TlsSetValue` | Thread-local storage manager |
| `CreateEventW` | Manual/auto-reset Condvar-backed events |
| `SetEvent` | `notify_one()` (auto-reset) or `notify_all()` (manual-reset) |
| `ResetEvent` | Clear event state |
| `WaitForSingleObject` | Timed wait on threads or events |
| `CloseHandle` | Removes event/thread entries |
| `GetTempPathW` | `std::env::temp_dir()` |
| `InitializeCriticalSection` / `EnterCriticalSection` / `LeaveCriticalSection` / `DeleteCriticalSection` | Mutex-backed |
| `GetExitCodeProcess` | Returns `STILL_ACTIVE` (259) for the current process |
| `SetFileAttributesW` | Maps `FILE_ATTRIBUTE_READONLY` to Linux `chmod`; other bits silently accepted |
| `GetModuleFileNameW` | Returns current executable path via `/proc/self/exe` |
| `LoadLibraryA` / `LoadLibraryW` | Looks up registered DLL in global registry; returns synthetic HMODULE |
| `GetModuleHandleA` / `GetModuleHandleW` | Null → main module base; named → registry lookup |
| `GetProcAddress` | Looks up trampoline address in global registry by HMODULE + function name |
| `CreateHardLinkW` | `std::fs::hard_link` |
| `CreateSymbolicLinkW` | `std::os::unix::fs::symlink` |
| `LockFileEx` | `flock(2)` with `LOCK_SH`/`LOCK_EX`/`LOCK_NB` flags |
| `UnlockFile` | `flock(LOCK_UN)` |
| `VirtualQuery` | Parses `/proc/self/maps` and fills `MEMORY_BASIC_INFORMATION` (48 bytes) |
| `CancelIo` | Returns TRUE (all I/O is synchronous; no pending async I/O to cancel) |
| `UpdateProcThreadAttribute` | Returns TRUE (attribute accepted; `CreateProcessW` is not implemented) |
| `NtClose` | Delegates to `CloseHandle` to update handle tables |
| `GetSystemTime` | `clock_gettime(CLOCK_REALTIME)` + `gmtime_r` → SYSTEMTIME |
| `GetLocalTime` | `clock_gettime(CLOCK_REALTIME)` + `localtime_r` → SYSTEMTIME |
| `SystemTimeToFileTime` | SYSTEMTIME → Windows FILETIME via `timegm` |
| `FileTimeToSystemTime` | Windows FILETIME → SYSTEMTIME via `gmtime_r` |
| `GetTickCount` | 32-bit truncation of `GetTickCount64` |
| `LocalAlloc` | Delegates to `HeapAlloc` (`LMEM_ZEROINIT` maps to `HEAP_ZERO_MEMORY`) |
| `LocalFree` | Delegates to `HeapFree`; returns NULL |
| `InterlockedIncrement` / `InterlockedDecrement` | `AtomicI32::fetch_add/fetch_sub` with SeqCst |
| `InterlockedExchange` / `InterlockedExchangeAdd` | `AtomicI32::swap` / `fetch_add` with SeqCst |
| `InterlockedCompareExchange` | `AtomicI32::compare_exchange` with SeqCst |
| `InterlockedCompareExchange64` | `AtomicI64::compare_exchange` with SeqCst |
| `IsWow64Process` | Returns TRUE (call succeeded); sets `*is_wow64 = 0` (not WOW64) |
| `GetNativeSystemInfo` | Delegates to `GetSystemInfo` (already returns AMD64 info) |
| `CreateMutexW` / `CreateMutexA` | Recursive mutex backed by `Arc<(Mutex<Option<(u32,u32)>>, Condvar)>` |
| `OpenMutexW` | Look up named mutex in global registry |
| `ReleaseMutex` | Release ownership; decrement recursive count; notify waiters |
| `CreateSemaphoreW` / `CreateSemaphoreA` | Counting semaphore backed by `Arc<(Mutex<i32>, Condvar)>` |
| `OpenSemaphoreW` | Look up named semaphore in global registry |
| `ReleaseSemaphore` | Increment semaphore count; notify one waiter |
| `WaitForSingleObject` | Extended to handle mutex and semaphore handles |
| `SetConsoleMode` | Accepts mode (no-op); returns TRUE |
| `SetConsoleTitleW` / `SetConsoleTitleA` | Stores title in global `CONSOLE_TITLE` |
| `GetConsoleTitleW` | Returns stored title; falls back to empty string |
| `AllocConsole` / `FreeConsole` | Returns TRUE (always have a console) |
| `GetConsoleWindow` | Returns NULL (headless) |
| `lstrlenA` | ANSI `strlen` |
| `lstrcpyW` / `lstrcpyA` | Wide/ANSI string copy; returns dst |
| `lstrcmpW` / `lstrcmpA` | Wide/ANSI string comparison |
| `lstrcmpiW` / `lstrcmpiA` | Case-insensitive wide/ANSI comparison |
| `OutputDebugStringW` / `OutputDebugStringA` | Writes debug message to stderr |
| `GetDriveTypeW` | Returns `DRIVE_FIXED` (3) for all paths |
| `GetLogicalDrives` | Returns 0x4 (only C: drive) |
| `GetLogicalDriveStringsW` | Returns `"C:\\\0\0"` (single-drive list) |
| `GetDiskFreeSpaceExW` | Returns 10 GB free / 20 GB total (fake values) |
| `GetVolumeInformationW` | Returns volume name `"LITEBOX"`, filesystem `"NTFS"` |
| `GetComputerNameW` / `GetComputerNameExW` | Reads Linux hostname via `/proc/sys/kernel/hostname` |
| `SetThreadPriority` | Accepts priority value; returns TRUE (all threads run at normal priority) |
| `GetThreadPriority` | Returns `THREAD_PRIORITY_NORMAL` (0) for all threads |
| `SuspendThread` | Returns 0 (suspension not implemented; thread continues) |
| `ResumeThread` | Returns 0 (previous suspend count; no-op) |
| `OpenThread` | Returns handle from THREAD_HANDLES if thread ID matches; NULL otherwise |
| `GetExitCodeThread` | Returns `STILL_ACTIVE` (259) or actual exit code from thread registry |
| `OpenProcess` | Returns pseudo-handle for current process; NULL for unknown PIDs |
| `GetProcessTimes` | Returns current wall-clock time as creation time; zeros for CPU times |
| `GetFileTime` | Reads file timestamps via `fstat(2)` on the underlying fd |
| `CompareFileTime` | Compares two FILETIME values; returns -1, 0, or 1 |
| `FileTimeToLocalFileTime` | Adjusts UTC FILETIME by local timezone offset via `localtime_r` |
| `GetTempFileNameW` | Generates a temp file name from path + prefix + unique hex suffix |
| `GetPriorityClass` | Returns `NORMAL_PRIORITY_CLASS` (0x20) for all non-null handles |
| `SetPriorityClass` | Accepts priority class (no-op); returns TRUE for non-null handles |
| `GetProcessAffinityMask` | Queries `sched_getaffinity`; sets both mask outputs to the CPU set |
| `SetProcessAffinityMask` | Accepts mask (no-op); returns TRUE for non-null handles |
| `FlushInstructionCache` | Returns TRUE (no-op; x86-64 has coherent I/D cache) |
| `ReadProcessMemory` | Returns FALSE + `ERROR_ACCESS_DENIED` (5) |
| `WriteProcessMemory` | Returns FALSE + `ERROR_ACCESS_DENIED` (5) |
| `VirtualAllocEx` | Returns NULL + `ERROR_ACCESS_DENIED` (5) for external processes; delegates to `VirtualAlloc` for self |
| `VirtualFreeEx` | Returns FALSE + `ERROR_ACCESS_DENIED` (5) for external processes; delegates to `VirtualFree` for self |
| `CreateJobObjectW` | Returns a synthetic job handle; name stored in registry |
| `AssignProcessToJobObject` | Returns TRUE (no-op) |
| `IsProcessInJob` | Returns TRUE; sets `*result = 1` |
| `QueryInformationJobObject` | Returns FALSE + `ERROR_NOT_SUPPORTED` (50) |
| `SetInformationJobObject` | Returns TRUE (no-op) |
| `FindFirstVolumeW` | Returns sentinel handle + synthetic GUID path `\\?\Volume{00000000-...}\` |
| `FindNextVolumeW` | Always returns 0 + `ERROR_NO_MORE_FILES` (18) |
| `FindVolumeClose` | Always returns 1 (success) |

### Permanently-correct no-op APIs (return appropriate Windows codes)
| Function | Return / Error |
|---|---|
| `SetConsoleCtrlHandler` | TRUE — handler registered; Linux SIGINT termination preserved |
| `SetWaitableTimer` | TRUE — waitable timers not created; no valid timer handle exists |
| `WaitOnAddress` | TRUE — returns immediately (no blocking wait; can be extended) |
| `CreateProcessW` | FALSE + `ERROR_NOT_SUPPORTED` (50) |
| `CreateToolhelp32Snapshot` | `INVALID_HANDLE_VALUE` + `ERROR_NOT_SUPPORTED` (50) |
| `CreateWaitableTimerExW` | NULL + `ERROR_NOT_SUPPORTED` (50) |
| `DeviceIoControl` | FALSE + `ERROR_NOT_SUPPORTED` (50) |
| `GetOverlappedResult` | FALSE + `ERROR_NOT_SUPPORTED` (50) |
| `ReadFileEx` | FALSE + `ERROR_NOT_SUPPORTED` (50) |
| `WriteFileEx` | FALSE + `ERROR_NOT_SUPPORTED` (50) |
| `SetFileInformationByHandle` | FALSE + `ERROR_NOT_SUPPORTED` (50) |
| `Module32FirstW` / `Module32NextW` | FALSE + `ERROR_NO_MORE_FILES` (18) |

### MSVCRT Implementations (18 functions)
`printf`, `fprintf`, `sprintf`, `snprintf`, `malloc`, `calloc`, `realloc`, `free`, `memcpy`, `memmove`, `memset`, `memcmp`, `strlen`, `strcpy`, `strncpy`, `strcmp`, `strncmp`, `exit`

### Exception Handling — Full C++ Exception Dispatch (13 functions)
`__C_specific_handler`, `SetUnhandledExceptionFilter`, `RaiseException`, `RtlCaptureContext`, `RtlLookupFunctionEntry`, `RtlUnwindEx`, `RtlVirtualUnwind`, `AddVectoredExceptionHandler`, `RemoveVectoredExceptionHandler`, `_GCC_specific_handler` (GCC/MinGW C++ personality), `msvcrt__CxxThrowException`, `__CxxFrameHandler3` (MSVC C++ personality), `cxx_frame_handler`

- **C SEH API tests**: `seh_c_test.exe` — **21/21 PASS** (MinGW)
- **C++ GCC/MinGW exceptions**: `seh_cpp_test.exe` — **26/26 PASS** (MinGW g++)
- **C++ Clang/MinGW exceptions**: `seh_cpp_test_clang.exe` — **26/26 PASS** (clang++ `--target=x86_64-w64-mingw32`)
- **C++ MSVC ABI exceptions**: `seh_cpp_test_msvc.exe` — **21/21 PASS** (clang-cl/MSVC ABI; all 10 tests including destructor unwinding and cross-frame propagation)

### String / Wide-Char Operations
`MultiByteToWideChar`, `WideCharToMultiByte`, `lstrlenW`, `lstrlenA`, `CompareStringOrdinal`  
`lstrcpyW`, `lstrcpyA`, `lstrcmpW`, `lstrcmpA`, `lstrcmpiW`, `lstrcmpiA`, `OutputDebugStringW`, `OutputDebugStringA`

### Performance Counters
`QueryPerformanceCounter`, `QueryPerformanceFrequency`, `GetSystemTimePreciseAsFileTime`

### Heap Management
`GetProcessHeap`, `HeapAlloc`, `HeapFree`, `HeapReAlloc`

### Networking (WS2_32) — 47 functions backed by Linux POSIX sockets
| Category | Implemented Functions |
|---|---|
| Lifecycle | `WSAStartup`, `WSACleanup`, `WSAGetLastError`, `WSASetLastError` |
| Socket creation | `socket`, `WSASocketW`, `closesocket` |
| Connection | `bind`, `listen`, `accept`, `connect`, `shutdown` |
| Data transfer | `send`, `recv`, `sendto`, `recvfrom`, `WSASend`, `WSARecv` |
| Socket info | `getsockname`, `getpeername`, `getsockopt`, `setsockopt`, `ioctlsocket` |
| Multiplexing | `select`, `__WSAFDIsSet`, `WSAPoll` |
| Name resolution | `getaddrinfo`, `freeaddrinfo`, `GetHostNameW`, `gethostbyname` |
| Byte order | `htons`, `htonl`, `ntohs`, `ntohl` |
| Address conversion | `inet_addr`, `inet_pton`, `inet_ntop` |
| Event-based I/O (Phase 40) | `WSACreateEvent`, `WSACloseEvent`, `WSAResetEvent`, `WSASetEvent`, `WSAEventSelect`, `WSAEnumNetworkEvents`, `WSAWaitForMultipleEvents` |
| Misc | `WSADuplicateSocketW`, `WSAIoctl` |

### USER32 — Extended GUI Support (Phases 24 + 27 + 28, 42 core functions)
| Category | Implemented Functions |
|---|---|
| Basic | `MessageBoxW`, `RegisterClassExW`, `CreateWindowExW`, `ShowWindow`, `UpdateWindow`, `DestroyWindow` |
| Message loop | `GetMessageW`, `TranslateMessage`, `DispatchMessageW`, `PeekMessageW`, `PostQuitMessage` |
| Window proc | `DefWindowProcW` |
| Resources | `LoadCursorW`, `LoadIconW` |
| Window info | `GetSystemMetrics`, `SetWindowLongPtrW`, `GetWindowLongPtrW` |
| Messaging | `SendMessageW`, `PostMessageW` |
| Painting | `BeginPaint`, `EndPaint`, `GetClientRect`, `InvalidateRect` |
| Timer | `SetTimer`, `KillTimer` |
| Device context | `GetDC`, `ReleaseDC` |
| Character conversion | `CharUpperW`, `CharLowerW`, `CharUpperA`, `CharLowerA` |
| Character classification | `IsCharAlphaW`, `IsCharAlphaNumericW`, `IsCharUpperW`, `IsCharLowerW` |
| Window utilities | `IsWindow`, `IsWindowEnabled`, `IsWindowVisible`, `EnableWindow`, `GetWindowTextW`, `SetWindowTextW`, `GetParent` |

**Phase 45 — Extended GUI APIs (49 additional functions):**
| Category | Implemented Functions |
|---|---|
| Non-Ex variants | `RegisterClassW`, `CreateWindowW` |
| Dialog boxes | `DialogBoxParamW`, `CreateDialogParamW`, `EndDialog`, `GetDlgItem`, `GetDlgItemTextW`, `SetDlgItemTextW`, `SendDlgItemMessageW`, `GetDlgItemInt`, `SetDlgItemInt`, `CheckDlgButton`, `IsDlgButtonChecked` |
| Drawing | `DrawTextW`, `DrawTextA`, `DrawTextExW` |
| Window rect | `AdjustWindowRect`, `AdjustWindowRectEx` |
| System params | `SystemParametersInfoW`, `SystemParametersInfoA` |
| Menus | `CreateMenu`, `CreatePopupMenu`, `DestroyMenu`, `AppendMenuW`, `InsertMenuItemW`, `GetMenu`, `SetMenu`, `DrawMenuBar`, `TrackPopupMenu` |
| Mouse capture | `SetCapture`, `ReleaseCapture`, `GetCapture`, `TrackMouseEvent` |
| Window updates | `RedrawWindow` |
| Clipboard | `OpenClipboard`, `CloseClipboard`, `EmptyClipboard`, `GetClipboardData`, `SetClipboardData` |
| Resources | `LoadStringW`, `LoadBitmapW`, `LoadImageW` |
| Window proc | `CallWindowProcW` |
| Window info | `GetWindowInfo`, `MapWindowPoints` |
| Monitor | `MonitorFromWindow`, `MonitorFromPoint`, `GetMonitorInfoW` |

All USER32 functions operate in headless mode: no real windows are created, no messages
are dispatched, and drawing operations are silently discarded.

### GDI32 — Graphics Device Interface (Phases 24 + 45)
| Category | Implemented Functions (Phase 24) |
|---|---|
| Objects | `GetStockObject`, `CreateSolidBrush`, `DeleteObject`, `SelectObject` |
| Device context | `CreateCompatibleDC`, `DeleteDC` |
| Color | `SetBkColor`, `SetTextColor` |
| Drawing | `TextOutW`, `Rectangle`, `FillRect` |
| Font | `CreateFontW`, `GetTextExtentPoint32W` |

**Phase 45 — Extended Graphics Primitives (37 additional functions):**
| Category | Implemented Functions |
|---|---|
| Device context | `GetDeviceCaps`, `SetBkMode`, `SetMapMode`, `SetViewportOrgEx`, `SaveDC`, `RestoreDC` |
| Pen creation | `CreatePen`, `CreatePenIndirect` |
| Brush creation | `CreateBrushIndirect`, `CreatePatternBrush`, `CreateHatchBrush` |
| Bitmaps | `CreateBitmap`, `CreateCompatibleBitmap`, `CreateDIBSection`, `GetDIBits`, `SetDIBits` |
| Blit | `BitBlt`, `StretchBlt`, `PatBlt`, `SetStretchBltMode` |
| Pixels | `GetPixel`, `SetPixel` |
| Line drawing | `MoveToEx`, `LineTo`, `Polyline` |
| Shape drawing | `Polygon`, `Ellipse`, `Arc`, `RoundRect` |
| Text metrics | `GetTextMetricsW` |
| Regions | `CreateRectRgn`, `SelectClipRgn`, `GetClipBox`, `ExcludeClipRect`, `IntersectClipRect` |
| Objects | `GetObjectW`, `GetCurrentObject` |

All GDI32 functions operate in headless mode: drawing is silently discarded.

### vulkan-1.dll — Vulkan API Stubs (Phase 45, 62 functions)

All Vulkan functions are headless stubs.  Query functions (`vkEnumerate*`) return
`VK_SUCCESS` with a count of 0.  Creation functions return
`VK_ERROR_INITIALIZATION_FAILED` (-3) to clearly signal that no real GPU / ICD
is available.  Wait/idle functions return `VK_SUCCESS` immediately.

| Category | Implemented Functions |
|---|---|
| Instance | `vkCreateInstance`, `vkDestroyInstance`, `vkEnumerateInstanceExtensionProperties`, `vkEnumerateInstanceLayerProperties` |
| Physical device | `vkEnumeratePhysicalDevices`, `vkGetPhysicalDeviceProperties`, `vkGetPhysicalDeviceFeatures`, `vkGetPhysicalDeviceQueueFamilyProperties`, `vkGetPhysicalDeviceMemoryProperties` |
| Logical device | `vkCreateDevice`, `vkDestroyDevice`, `vkGetDeviceQueue`, `vkQueueWaitIdle`, `vkDeviceWaitIdle` |
| Surface | `vkCreateWin32SurfaceKHR`, `vkDestroySurfaceKHR`, `vkGetPhysicalDeviceSurfaceSupportKHR`, `vkGetPhysicalDeviceSurfaceCapabilitiesKHR`, `vkGetPhysicalDeviceSurfaceFormatsKHR`, `vkGetPhysicalDeviceSurfacePresentModesKHR` |
| Swapchain | `vkCreateSwapchainKHR`, `vkDestroySwapchainKHR`, `vkGetSwapchainImagesKHR`, `vkAcquireNextImageKHR`, `vkQueuePresentKHR` |
| Memory & resources | `vkAllocateMemory`, `vkFreeMemory`, `vkCreateBuffer`, `vkDestroyBuffer`, `vkCreateImage`, `vkDestroyImage` |
| Render passes | `vkCreateRenderPass`, `vkDestroyRenderPass`, `vkCreateFramebuffer`, `vkDestroyFramebuffer` |
| Pipelines | `vkCreateGraphicsPipelines`, `vkDestroyPipeline`, `vkCreateShaderModule`, `vkDestroyShaderModule`, `vkCreatePipelineLayout`, `vkDestroyPipelineLayout` |
| Descriptors | `vkCreateDescriptorSetLayout`, `vkDestroyDescriptorSetLayout` |
| Commands | `vkCreateCommandPool`, `vkDestroyCommandPool`, `vkAllocateCommandBuffers`, `vkFreeCommandBuffers`, `vkBeginCommandBuffer`, `vkEndCommandBuffer`, `vkCmdBeginRenderPass`, `vkCmdEndRenderPass`, `vkCmdDraw`, `vkCmdDrawIndexed`, `vkQueueSubmit` |
| Synchronization | `vkCreateFence`, `vkDestroyFence`, `vkWaitForFences`, `vkResetFences`, `vkCreateSemaphore`, `vkDestroySemaphore` |
| Proc address | `vkGetInstanceProcAddr`, `vkGetDeviceProcAddr` |

### C Test Program — GUI + Vulkan (Phase 45)

`windows_test_programs/gui_test/gui_test.c` exercises 25 tests covering:
- USER32: window creation, painting, menus, clipboard, monitor info, `DrawTextW`, `AdjustWindowRectEx`, `LoadStringW`
- GDI32: `GetDeviceCaps`, pen/line drawing, compatible bitmap / BitBlt, ellipse/rectangle/roundrect, `GetTextMetricsW`, `SaveDC`/`RestoreDC`, `CreateDIBSection`
- Vulkan-1: `vkEnumerateInstanceExtensionProperties` (VK_SUCCESS + count=0), `vkEnumerateInstanceLayerProperties`, `vkCreateInstance` (VK_ERROR_INITIALIZATION_FAILED), `vkEnumeratePhysicalDevices`, `vkGetInstanceProcAddr`

### SHELL32.dll — Shell API (Phase 25, 4 functions)
| Category | Implemented Functions |
|---|---|
| Command line | `CommandLineToArgvW` (real Windows parsing with backslash/quote rules) |
| Folder paths | `SHGetFolderPathW` (maps CSIDL constants to Linux paths) |
| Process | `ShellExecuteW` (headless stub; returns success value > 32) |
| File system | `SHCreateDirectoryExW` (delegates to `CreateDirectoryW`) |

### VERSION.dll — File Version Info (Phase 25, 3 functions)
| Function | Behaviour |
|---|---|
| `GetFileVersionInfoSizeW` | Returns 0 (no version resources in emulated environment) |
| `GetFileVersionInfoW` | Returns FALSE |
| `VerQueryValueW` | Returns FALSE; clears output pointers |

### ADVAPI32 — Extended System APIs (Phase 26)
| Function | Implementation |
|---|---|
| `GetUserNameW` | Reads Linux username via `$USER` env / `getlogin_r(3)` |
| `GetUserNameA` | ANSI variant; delegates to wide version |

### Drive/Volume APIs (Phase 26, 5 functions)
| Function | Behaviour |
|---|---|
| `GetDriveTypeW` | Returns `DRIVE_FIXED` (3) for all paths |
| `GetLogicalDrives` | Returns 0x4 (only C: drive) |
| `GetLogicalDriveStringsW` | Returns `"C:\\\0\0"` drive list |
| `GetDiskFreeSpaceExW` | Returns 10 GB free / 20 GB total (fake) |
| `GetVolumeInformationW` | Returns volume `"LITEBOX"`, filesystem `"NTFS"` |

### API Tracing Framework
- Text and JSON output formats with timestamps and thread IDs
- Filtering by function name pattern (wildcards), category, or exact name
- Output to stdout or file
- Zero overhead when disabled
- Categories: `file_io`, `console_io`, `memory`, `threading`, `synchronization`, `environment`, `process`, `registry`

### ole32.dll — COM Initialization and Memory (Phase 32, 12 functions)
| Function | Behaviour |
|---|---|
| `CoInitialize` / `CoInitializeEx` | Returns S_OK (COM initialized in STA/MTA mode; headless) |
| `CoUninitialize` | No-op |
| `CoCreateInstance` | Returns E_NOTIMPL (0x80004001); COM object creation not supported in sandboxed env |
| `CoGetClassObject` | Returns REGDB_E_CLASSNOTREG (0x80040154) |
| `CoCreateGuid` | Fills 16 bytes with random data via `/dev/urandom` |
| `StringFromGUID2` | Formats GUID as `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`; returns char count |
| `CLSIDFromString` | Parses GUID string; returns CO_E_CLASSSTRING if invalid, S_OK if valid |
| `CoTaskMemAlloc` / `CoTaskMemFree` / `CoTaskMemRealloc` | Delegate to `malloc`/`free`/`realloc` |
| `CoSetProxyBlanket` | Returns E_NOTIMPL (security blanket not supported) |

### MSVCRT New Functions (Phases 32–43)
| Category | Functions |
|---|---|
| Formatted I/O (Phase 32) | `sprintf`, `snprintf`, `sscanf`, `swprintf`, `wprintf` |
| Character classification | `isalpha`, `isdigit`, `isspace`, `isupper`, `islower`, `isprint`, `isxdigit`, `isalnum`, `iscntrl`, `ispunct`, `toupper`, `tolower` |
| Sorting | `qsort`, `bsearch` |
| Wide numeric | `wcstol`, `wcstoul`, `wcstod` |
| File I/O (Phase 32) | `fopen`, `fclose`, `fread`, `fseek`, `ftell`, `fflush`, `fgets`, `rewind`, `feof`, `ferror`, `clearerr`, `fgetc`, `ungetc`, `fileno` (`_fileno`), `fdopen` (`_fdopen`), `tmpfile`, `remove`, `rename` |
| va_list formatted I/O (Phase 34) | `vprintf`, `vsprintf`, `vsnprintf`, `vswprintf`, `fwprintf`, `vfwprintf` |
| Low-level I/O (Phase 34) | `_write`, `getchar`, `putchar` |
| Wide printf (Phase 35) | `_vsnwprintf` |
| Printf-count helpers (Phase 35) | `_scprintf`, `_vscprintf`, `_scwprintf`, `_vscwprintf` |
| Handle interop (Phase 35) | `_get_osfhandle`, `_open_osfhandle` |
| scanf real impl (Phase 36) | complete `sscanf` implementation (replaces Phase 32 stub), `_wcsdup`, `__stdio_common_vsscanf` |
| UCRT printf/scanf (Phase 37) | `__stdio_common_vsprintf`, `__stdio_common_vsnprintf_s`, `__stdio_common_vsprintf_s`, `__stdio_common_vswprintf`, `scanf`, `fscanf`, `__stdio_common_vfscanf` |
| Integer/wide string conversions (Phase 37) | `_ultoa`, `_i64toa`, `_ui64toa`, `_strtoi64`, `_strtoui64`, `_itow`, `_ltow`, `_ultow`, `_i64tow`, `_ui64tow` |
| Locale-aware printf (Phase 38) | `_printf_l`, `_fprintf_l`, `_sprintf_l`, `_snprintf_l`, `_wprintf_l` |
| File enumeration (Phase 38) | `_wfindfirst64i32`, `_wfindnext64i32`, `_findclose` |
| Low-level POSIX file I/O (Phase 39) | `_open`, `_close`, `_lseek`, `_lseeki64`, `_tell`, `_telli64`, `_eof`, `_creat`, `_commit`, `_dup`, `_dup2`, `_chsize`, `_chsize_s`, `_filelength`, `_filelengthi64` |
| File metadata / wide-path opens (Phase 40) | `_stat`, `_stat64`, `_fstat`, `_fstat64`, `_wopen`, `_wsopen`, `_wstat`, `_wstat64` |
| Path manipulation (Phase 42) | `_fullpath`, `_splitpath`, `_splitpath_s`, `_makepath`, `_makepath_s` |
| Directory navigation (Phase 43) | `_getcwd`, `_chdir`, `_mkdir`, `_rmdir` |

### msvcp140.dll — C++ Runtime (Phases 33–43)
| Category | Functions |
|---|---|
| Memory (Phase 33) | `operator new` (`??2@YAPEAX_K@Z`), `operator delete` (`??3@YAXPEAX@Z`), array variants (`??_U@YAPEAX_K@Z`, `??_V@YAXPEAX@Z`) |
| Exception helpers (Phase 33) | `_Xbad_alloc`, `_Xlength_error`, `_Xout_of_range`, `_Xinvalid_argument`, `_Xruntime_error`, `_Xoverflow_error` |
| Locale (Phase 33) | `_Locinfo::_Getctype`, `_Locinfo::_Getdays`, `_Locinfo::_Getmonths` |
| `std::exception` (Phase 35) | `what()`, default ctor, message ctor, dtor |
| Locale/lock (Phase 35) | `_Getgloballocale`, `_Lockit` ctor/dtor |
| `ios_base::Init` (Phase 35) | ctor/dtor (no-op; deferred stream init) |
| `std::basic_string<char>` (Phase 37) | default ctor, construct-from-cstr, copy ctor, dtor, `c_str()`, `size()`, `empty()`, copy assignment, assign-from-cstr, `append()` |
| `std::basic_string<wchar_t>` (Phase 38) | default ctor, construct-from-wide-cstr, copy ctor, dtor, `c_str()`, `size()`, `empty()`, copy assignment, assign-from-cstr, `append()` |
| `std::vector<char>` (Phase 39) | default ctor, dtor, `push_back` (2× growth), `size`, `capacity`, `clear`, `data` (mut + const), `reserve` |
| `std::map<void*,void*>` (Phase 41) | default ctor, dtor, `insert`, `find`, `size`, `clear` |
| `std::ostringstream` (Phase 41) | default ctor, dtor, `str()`, `write()`, `tellp()`, `seekp()` |
| `std::istringstream` (Phase 42) | default ctor, construct-from-cstr, dtor, `str()`, `str_set()`, `read()`, `seekg()`, `tellg()` |
| `std::stringstream` (Phase 43) | default ctor, construct-from-cstr, dtor, `str()`, `str_set()`, `read()`, `write()`, `seekg()`, `tellg()`, `seekp()`, `tellp()` |
| `std::unordered_map<void*,void*>` (Phase 43) | default ctor, dtor, `insert`, `find`, `size`, `clear` |

### TLS Callbacks (Phase 32)
- `TlsInfo` now includes `address_of_callbacks` field parsed from the PE TLS directory
- Runner executes all TLS callbacks (terminated by NULL pointer) before the entry point with `(base, DLL_PROCESS_ATTACH=1, NULL)` arguments

---

## What Is NOT Implemented ❌

| Feature | Status |
|---|---|
| Full GUI rendering | USER32/GDI32 are headless stubs; no real window/drawing output |
| Vulkan rendering | `vulkan-1.dll` stubs return `VK_ERROR_INITIALIZATION_FAILED`; no real GPU/ICD |
| Overlapped (async) I/O | `ReadFileEx`, `WriteFileEx`, `GetOverlappedResult` return `ERROR_NOT_SUPPORTED` |
| Process creation (`CreateProcessW`) | Returns `ERROR_NOT_SUPPORTED`; sandboxed environment |
| Toolhelp32 enumeration | `CreateToolhelp32Snapshot`, `Module32FirstW/NextW` return `ERROR_NOT_SUPPORTED` |
| Waitable timers | `CreateWaitableTimerExW` returns `ERROR_NOT_SUPPORTED`; `SetWaitableTimer` is a no-op |
| `WaitOnAddress` blocking | Returns TRUE immediately; no blocking wait |
| Advanced networking | Completion ports not implemented; `WSAAsyncSelect` not implemented |

### What IS Implemented ✅ (Exception Handling)

| Feature | Status |
|---|---|
| Full SEH / C++ exception handling (GCC/MinGW) | ✅ Fully implemented; `seh_c_test` 21/21, `seh_cpp_test` 26/26, `seh_cpp_test_clang` 26/26 |
| MSVC ABI C++ exception throw/catch/rethrow | ✅ Fully working; all 10 tests pass (throw/catch for int/double/string, rethrow, catch-all, destructor unwinding, cross-frame propagation, indirect calls) |

---

## Test Coverage

**769 Windows-on-Linux crate tests + 5 dev_tests ratchet checks (all passing):**

| Package | Tests | Notes |
|---|---|---|
| `litebox_platform_linux_for_windows` | 697 | KERNEL32, MSVCRT, WS2_32, advapi32, user32, gdi32, shell32, version, ole32, msvcp140, vulkan1, platform APIs |
| `litebox_shim_windows` | 51 | ABI translation, PE loader, tracing, DLL manager |
| `litebox_runner_windows_on_linux_userland` | 12 | integration: 9 non-ignored + 3 new Phase 45 checks |
| `dev_tests` | 5 | Ratchet constraints (globals, transmutes, MaybeUninit, stubs, copyright) — run separately with `cargo test -p dev_tests` |

**Integration tests (12, plus 13 MinGW-gated):**
1. PE loader with minimal binary
2. DLL loading infrastructure
3. Command-line APIs (`GetCommandLineW`, `CommandLineToArgvW`)
4. File search APIs (`FindFirstFileW`, `FindNextFileW`, `FindClose`)
5. Memory protection APIs (`NtProtectVirtualMemory`)
6. Error handling APIs (`GetLastError` / `SetLastError`)
7. DLL exports validation (all critical KERNEL32, WS2_32, USER32, GDI32, ole32, and msvcp140 exports — including Phases 33–44 additions)
8. Phase 41 DLL exports (msvcp140 `std::map`, `std::ostringstream`)
9. Phase 42 DLL exports (MSVCRT path, WS2_32 inet, msvcp140 `std::istringstream`)
10. Phase 43 DLL exports (MSVCRT dir nav, msvcp140 `std::stringstream`/`std::unordered_map`, KERNEL32 volume enumeration)
11. Phase 44 DLL exports (`getservbyname`, `getservbyport`, `getprotobyname`, `tmpnam`, `_mktemp`, `_tempnam`, `GetVolumePathNamesForVolumeNameW`, msvcp140 `std::deque`/`std::stack`/`std::queue`)
12. Phase 45 DLL exports (USER32 dialog/menu/clipboard/monitor APIs, GDI32 extended graphics, vulkan-1.dll 62 Vulkan functions)

**MinGW-gated integration tests (13, run with `cargo test -p litebox_runner_windows_on_linux_userland -- --ignored`):**
- `test_hello_cli_program_exists` — checks hello_cli.exe is present
- `test_math_test_program_exists` — checks math_test.exe is present
- `test_env_test_program_exists` — checks env_test.exe is present
- `test_args_test_program_exists` — checks args_test.exe is present
- `test_file_io_test_program_exists` — **runs** file_io_test.exe end-to-end; verifies exit 0 and test header/completion output
- `test_string_test_program_exists` — **runs** string_test.exe end-to-end; verifies exit 0, test header, and 0 failures
- `test_getprocaddress_c_program` — **runs** getprocaddress_test.exe end-to-end; verifies exit 0 and 0 failures
- `test_hello_gui_program` — **runs** hello_gui.exe end-to-end; verifies exit 0 (MessageBoxW prints headless message to stderr)
- `test_seh_c_program` — **runs** seh_c_test.exe; verifies 21 passed, 0 failed (MinGW C SEH API tests)
- `test_seh_cpp_program` — **runs** seh_cpp_test.exe; verifies 26 passed, 0 failed (MinGW C++ exceptions)
- `test_seh_cpp_clang_program` — **runs** seh_cpp_test_clang.exe; verifies 26 passed, 0 failed (clang/MinGW C++ exceptions)
- `test_seh_cpp_msvc_program` — **runs** seh_cpp_test_msvc.exe; verifies 21 passed, 0 failed (MSVC ABI C++ exceptions, all 10 tests)
- `test_phase27_program` — **runs** phase27_test.exe (Phase 27 extended APIs smoke test)

**CI-validated test programs (7 + 4 SEH):**

| Program | What it tests | CI status |
|---|---|---|
| `hello_cli.exe` | Basic stdout via `println!` | ✅ Passing |
| `math_test.exe` | Arithmetic and math operations | ✅ Passing |
| `env_test.exe` | `GetEnvironmentVariableW` / `SetEnvironmentVariableW` | ✅ Passing |
| `args_test.exe` | `GetCommandLineW` / `CommandLineToArgvW` | ✅ Passing |
| `file_io_test.exe` | `CreateFileW`, `ReadFile`, `WriteFile`, directory operations | ✅ Passing |
| `string_test.exe` | Rust `String` operations (allocations, comparisons, Unicode) | ✅ Passing |
| `getprocaddress_test.exe` (C) | `GetModuleHandleA/W`, `GetProcAddress`, `LoadLibraryA`, `FreeLibrary` | ✅ Passing |
| `seh_c_test.exe` (MinGW C) | SEH runtime APIs (`RtlCaptureContext`, `RtlUnwindEx`, vectored handlers) | ✅ **21/21 Passing** |
| `seh_cpp_test.exe` (MinGW C++) | C++ exceptions with GCC/MinGW ABI (`throw`/`catch`, rethrow, destructors) | ✅ **26/26 Passing** |
| `seh_cpp_test_clang.exe` (clang/MinGW) | C++ exceptions with Clang targeting MinGW ABI (`_Unwind_Resume` path) | ✅ **26/26 Passing** |
| `seh_cpp_test_msvc.exe` (clang-cl/MSVC ABI) | C++ exceptions with MSVC ABI (`_CxxThrowException` / `__CxxFrameHandler3`) | ✅ **21/21 Passing** |

---

## Usage

### Basic Usage

```bash
# Run a Windows PE binary
litebox_runner_windows_on_linux_userland program.exe
```

### API Tracing

```bash
# Enable tracing with text format
litebox_runner_windows_on_linux_userland --trace-apis program.exe

# Enable tracing with JSON format to file
litebox_runner_windows_on_linux_userland \
  --trace-apis \
  --trace-format json \
  --trace-output trace.json \
  program.exe

# Filter by category (only memory operations)
litebox_runner_windows_on_linux_userland \
  --trace-apis \
  --trace-category memory \
  program.exe

# Filter by pattern (only file operations)
litebox_runner_windows_on_linux_userland \
  --trace-apis \
  --trace-filter "Nt*File" \
  program.exe
```

---

## Code Quality

- **All 705 Windows-on-Linux crate tests passing + 5 dev_tests ratchet checks passing**
- `RUSTFLAGS=-Dwarnings cargo clippy --all-targets --all-features` — clean
- `cargo fmt --check` — clean
- All `unsafe` blocks have detailed safety comments
- Ratchet limits: globals ≤ 67, transmutes ≤ 3, MaybeUninit ≤ current
- **Stub count = 0** (ratchet entry removed; all stub doc-phrases eliminated)

---

## Development History Summary

| Phase | Description | Status |
|---|---|---|
| 1 | PE loader foundation | ✅ Complete |
| 2 | Core NTDLL APIs (file, console, memory) | ✅ Complete |
| 3 | API tracing framework | ✅ Complete |
| 4 | Threading & synchronization (NTDLL) | ✅ Complete |
| 5 | Environment variables, process info, registry emulation | ✅ Complete |
| 6 | Import resolution, IAT patching, relocations, DLL manager, TEB/PEB | ✅ Complete |
| 7 | MSVCRT, GS register, ABI trampolines, TLS, memory protection, error handling | ✅ Complete |
| 8 | Real stack allocation, Windows x64 ABI entry-point calling, exception/heap/critical-section stubs | ✅ Complete |
| 9 | BSS zero-initialization, `__CTOR_LIST__` patching for MinGW CRT compatibility | ✅ Complete |
| 10 | Path security: sandbox root enforcement; all file paths validated/translated through a configurable sandbox root | ✅ Complete |
| 11 | Handle limits: per-process handle table with enforced maximum handle count | ✅ Complete |
| 12 | ADVAPI32 registry APIs: `RegOpenKeyEx`, `RegQueryValueEx`, `RegCloseKey` (emulated in-memory registry) | ✅ Complete |
| 13 | WS2_32 networking: full 34-function POSIX socket layer (`WSAStartup`/`WSACleanup`, `socket`/`bind`/`listen`/`accept`/`connect`, `send`/`recv`, `select`, `getaddrinfo`, byte-order helpers) | ✅ Complete |
| 14 | Win32 events: `CreateEventW`, `SetEvent`, `ResetEvent`, `WaitForSingleObject` backed by `Condvar` | ✅ Complete |
| 15 | CI integration: GitHub Actions workflow; automated build and test pipeline for Windows-on-Linux crates | ✅ Complete |
| 16 | CI test harness: `--include-ignored` MinGW-gated integration tests; runner smoke tests | ✅ Complete |
| 17 | CI stabilisation and cross-crate test coverage consolidation; all crates green on CI | ✅ Complete |
| 18 | CI test programs (hello_cli, math_test, env_test, args_test, file_io_test, string_test all pass) | ✅ Complete |
| 19 | Real `GetExitCodeProcess`, `SetFileAttributesW`, `GetModuleFileNameW`; upgraded string_test and file_io_test integration tests | ✅ Complete |
| 20 | Dynamic loading: `LoadLibraryA/W`, `GetModuleHandleA/W`, `GetProcAddress` backed by global DLL registry; `CreateHardLinkW`, `CreateSymbolicLinkW` | ✅ Complete |
| 21 | `CreateFileMappingA`, `MapViewOfFile`, `UnmapViewOfFile` (real mmap/munmap); `CreatePipe` (Linux pipe()); `DuplicateHandle`; `GetFinalPathNameByHandleW`; `GetFileInformationByHandleEx`; `InitializeProcThreadAttributeList`; stub count 29→22 | ✅ Complete |
| 22 | `VirtualQuery` (parses `/proc/self/maps`), `CancelIo`, `UpdateProcThreadAttribute`, `NtClose`; stub count 22→14 | ✅ Complete |
| 23 | `LockFileEx` / `UnlockFile` (real `flock(2)`); appropriate error codes for all permanently-unsupported APIs; **stub count 14→0** | ✅ Complete |
| 24 | Extended USER32 (18 new functions: `PostQuitMessage`, `DefWindowProcW`, `LoadCursorW`, `LoadIconW`, `GetSystemMetrics`, `SetWindowLongPtrW`, `GetWindowLongPtrW`, `SendMessageW`, `PostMessageW`, `PeekMessageW`, `BeginPaint`, `EndPaint`, `GetClientRect`, `InvalidateRect`, `SetTimer`, `KillTimer`, `GetDC`, `ReleaseDC`); new GDI32.dll (13 functions: `GetStockObject`, `CreateSolidBrush`, `DeleteObject`, `SelectObject`, `CreateCompatibleDC`, `DeleteDC`, `SetBkColor`, `SetTextColor`, `TextOutW`, `Rectangle`, `FillRect`, `CreateFontW`, `GetTextExtentPoint32W`); `hello_gui` integration test; +35 new tests | ✅ Complete |
| 25 | Time APIs (`GetSystemTime`, `GetLocalTime`, `SystemTimeToFileTime`, `FileTimeToSystemTime`, `GetTickCount`); local memory (`LocalAlloc`, `LocalFree`); interlocked ops (`InterlockedIncrement/Decrement/Exchange/ExchangeAdd/CompareExchange/CompareExchange64`); system info (`IsWow64Process`, `GetNativeSystemInfo`); new SHELL32.dll (`CommandLineToArgvW`, `SHGetFolderPathW`, `ShellExecuteW`, `SHCreateDirectoryExW`); new VERSION.dll (`GetFileVersionInfoSizeW`, `GetFileVersionInfoW`, `VerQueryValueW`); +17 new tests | ✅ Complete |
| 26 | Mutex/Semaphore sync objects (`CreateMutexW/A`, `OpenMutexW`, `ReleaseMutex`, `CreateSemaphoreW/A`, `OpenSemaphoreW`, `ReleaseSemaphore`); console extensions (`SetConsoleMode`, `SetConsoleTitleW/A`, `GetConsoleTitleW`, `AllocConsole`, `FreeConsole`, `GetConsoleWindow`); string utilities (`lstrlenA`, `lstrcpyW/A`, `lstrcmpW/A`, `lstrcmpiW/A`, `OutputDebugStringW/A`); drive/volume APIs (`GetDriveTypeW`, `GetLogicalDrives`, `GetLogicalDriveStringsW`, `GetDiskFreeSpaceExW`, `GetVolumeInformationW`); computer/user name (`GetComputerNameW/ExW`, `GetUserNameW/A`); +16 new tests; globals ratchet 39→42 | ✅ Complete |
| 27 | Thread management (`SetThreadPriority`, `GetThreadPriority`, `SuspendThread`, `ResumeThread`, `OpenThread`, `GetExitCodeThread`); process management (`OpenProcess`, `GetProcessTimes`); file-time utilities (`GetFileTime`, `CompareFileTime`, `FileTimeToLocalFileTime`); temp file name (`GetTempFileNameW`); USER32 character conversion (`CharUpperW/A`, `CharLowerW/A`); character classification (`IsCharAlphaW`, `IsCharAlphaNumericW`, `IsCharUpperW`, `IsCharLowerW`); window utilities (`IsWindow`, `IsWindowEnabled`, `IsWindowVisible`, `EnableWindow`, `GetWindowTextW`, `SetWindowTextW`, `GetParent`); +23 new tests | ✅ Complete |
| 28 | MSVCRT numeric conversions (`atoi`, `atol`, `atof`, `strtol`, `strtoul`, `strtod`, `_itoa`, `_ltoa`); string extras (`strncpy`, `strncat`, `_stricmp`, `_strnicmp`, `_strdup`, `strnlen`); random/time (`rand`, `srand`, `time`, `clock`); math (`abs`, `labs`, `_abs64`, `fabs`, `sqrt`, `pow`, `log`, `log10`, `exp`, `sin`, `cos`, `tan`, `atan`, `atan2`, `ceil`, `floor`, `fmod`); wide-char extras (`wcscpy`, `wcscat`, `wcsncpy`, `wcschr`, `wcsncmp`, `_wcsicmp`, `_wcsnicmp`, `wcstombs`, `mbstowcs`); KERNEL32 (`GetFileSize`, `SetFilePointer`, `SetEndOfFile`, `FlushViewOfFile`, `GetSystemDefaultLangID/LCID`, `GetUserDefaultLangID/LCID`); new SHLWAPI.dll (`PathFileExistsW`, `PathCombineW`, `PathGetFileNameW`, `PathRemoveFileSpecW`, `PathIsRelativeW`, `PathFindExtensionW`, `PathStripPathW`, `PathAddBackslashW`, `StrToIntW`, `StrCmpIW`); USER32 window stubs (`FindWindowW`, `FindWindowExW`, `GetForegroundWindow`, `SetForegroundWindow`, `BringWindowToTop`, `GetWindowRect`, `SetWindowPos`, `MoveWindow`, `GetCursorPos`, `SetCursorPos`, `ScreenToClient`, `ClientToScreen`, `ShowCursor`, `GetFocus`, `SetFocus`); +27 new tests | ✅ Complete |
| 29–31 | SEH/C++ exception handling (`__C_specific_handler`, `RtlCaptureContext`, `RtlLookupFunctionEntry`, `RtlVirtualUnwind`, `RtlUnwindEx`, `_GCC_specific_handler`, `__CxxFrameHandler3/4`, `msvcrt__CxxThrowException`); seh_c_test 21/21, seh_cpp_test 26/26, seh_cpp_test_clang 26/26, seh_cpp_test_msvc 21/21 all pass | ✅ Complete |
| 32 | New `ole32.dll` (12 COM functions: `CoInitialize/Ex`, `CoUninitialize`, `CoCreateInstance`, `CoGetClassObject`, `CoCreateGuid`, `StringFromGUID2`, `CLSIDFromString`, `CoTaskMemAlloc/Free/Realloc`, `CoSetProxyBlanket`); 39 new MSVCRT functions (formatted I/O: `sprintf/snprintf/sscanf/swprintf/wprintf`; char classification: `isalpha/isdigit/isspace/isupper/islower/isprint/isxdigit/isalnum/iscntrl/ispunct/toupper/tolower`; sorting: `qsort/bsearch`; wide numeric: `wcstol/wcstoul/wcstod`; file I/O: `fopen/fclose/fread/fseek/ftell/fflush/fgets/rewind/feof/ferror/clearerr/fgetc/ungetc/fileno/fdopen/tmpfile/remove/rename`); TLS callbacks execution before entry point; +47 new tests (500 total) | ✅ Complete |
| 33 | New `msvcp140.dll` with 13 initial exports: `operator new/delete` (scalar + array), exception helpers (`_Xbad_alloc`, `_Xlength_error`, `_Xout_of_range`, `_Xinvalid_argument`, `_Xruntime_error`, `_Xoverflow_error`), locale helpers (`_Locinfo::_Getctype/Getdays/Getmonths`) | ✅ Complete |
| 34 | MSVCRT va_list formatted I/O: `vprintf`, `vsprintf`, `vsnprintf`, `vswprintf`; wide printf: `fwprintf`, `vfwprintf`; low-level I/O: `_write`, `getchar`, `putchar` | ✅ Complete |
| 35 | MSVCRT printf-count helpers: `_scprintf`, `_vscprintf`, `_scwprintf`, `_vscwprintf`; wide vsnprintf: `_vsnwprintf`; fd/handle interop: `_get_osfhandle`, `_open_osfhandle`; msvcp140 `std::exception` stubs, `_Getgloballocale`, `_Lockit` ctor/dtor, `ios_base::Init` ctor/dtor; (551 total) | ✅ Complete |
| 36 | Real `sscanf` implementation (up to 16 specifiers via libc, replaces Phase 32 stub); `_wcsdup` (wide string heap-duplicate); UCRT `__stdio_common_vsscanf` entry point; `sscanf` `num_params` fix (2→18); +12 new tests (563 total) | ✅ Complete |
| 37 | UCRT `__stdio_common_vsprintf`, `__stdio_common_vsnprintf_s`, `__stdio_common_vsprintf_s`, `__stdio_common_vswprintf`; real `scanf`/`fscanf`/`__stdio_common_vfscanf`; integer-to-wide conversions (`_itow`, `_ltow`, `_ultow`, `_i64tow`, `_ui64tow`); numeric conversions (`_ultoa`, `_i64toa`, `_ui64toa`, `_strtoi64`, `_strtoui64`); msvcp140 `std::basic_string<char>` with MSVC x64 SSO ABI (ctor, copy, dtor, `c_str`, `size`, `empty`, assign, append); +22 new tests (585 total) | ✅ Complete |
| 38 | msvcp140 `std::basic_string<wchar_t>` with MSVC x64 SSO ABI (SSO threshold=7, 32-byte layout; ctor, copy, dtor, `c_str`, `size`, `empty`, assign, append); MSVCRT directory enumeration: `_wfindfirst64i32`/`_wfindnext64i32`/`_findclose` (mutex-protected handle table, DOS-style wildcard matching via `libc::opendir/readdir`); locale-aware printf wrappers: `_printf_l`, `_fprintf_l`, `_sprintf_l`, `_snprintf_l`, `_wprintf_l` (locale ignored); +15 new tests (600 total) | ✅ Complete |
| 39 | MSVCRT low-level POSIX-style file I/O: `_open`, `_close`, `_lseek`, `_lseeki64`, `_tell`, `_telli64`, `_eof`, `_creat`, `_commit`, `_dup`, `_dup2`, `_chsize`, `_chsize_s`, `_filelength`, `_filelengthi64`; msvcp140 `std::vector<char>` with MSVC x64 ABI (24-byte 3-pointer layout; ctor, dtor, `push_back`, `size`, `capacity`, `clear`, `data`, `reserve`); KERNEL32 extended process/job management: `GetPriorityClass`, `SetPriorityClass`, `GetProcessAffinityMask`, `SetProcessAffinityMask`, `FlushInstructionCache`, `ReadProcessMemory`, `WriteProcessMemory`, `VirtualAllocEx`, `VirtualFreeEx`, `CreateJobObjectW`, `AssignProcessToJobObject`, `IsProcessInJob`, `QueryInformationJobObject`, `SetInformationJobObject`; +35 new tests (635 total) | ✅ Complete |
| 40 | MSVCRT stat functions: `_stat`/`_stat64`/`_fstat`/`_fstat64` (MSVC x64 ABI-compatible layout); wide-path file opens: `_wopen`, `_wsopen`, `_wstat`, `_wstat64`; WS2_32 event APIs: `WSACreateEvent`, `WSACloseEvent`, `WSAResetEvent`, `WSASetEvent`, `WSAEventSelect` (FD_* mask per socket), `WSAEnumNetworkEvents` (poll-based), `WSAWaitForMultipleEvents` (spin-sleep); `gethostbyname` (delegates to `libc::gethostbyname`); +11 new tests (646 total) | ✅ Complete |
| 41 | msvcp140 `std::map<void*,void*>` (ctor, dtor, insert, find, size, clear); msvcp140 `std::ostringstream` (ctor, dtor, str, write, tellp, seekp); +7 new tests (653 total) | ✅ Complete |
| 42 | MSVCRT path manipulation: `_fullpath` (via `realpath`), `_splitpath`/`_splitpath_s` (drive/dir/fname/ext), `_makepath`/`_makepath_s`; WS2_32 inet helpers: `inet_addr`, `inet_pton`, `inet_ntop`; `WSAPoll` (wraps `libc::poll`); `WSAIoctl` (stub, WSAEOPNOTSUPP); msvcp140 `std::istringstream` (ctor, ctor-from-cstr, dtor, str, str_set, read, seekg, tellg); +19 new tests (672 total) | ✅ Complete |
| 43 | msvcp140 `std::stringstream` (bidirectional: ctor, ctor-from-cstr, dtor, str, str_set, read, write, seekg, tellg, seekp, tellp); msvcp140 `std::unordered_map<void*,void*>` (ctor, dtor, insert, find, size, clear); MSVCRT directory navigation: `_getcwd`, `_chdir`, `_mkdir`, `_rmdir`; KERNEL32 volume enumeration: `FindFirstVolumeW`, `FindNextVolumeW`, `FindVolumeClose`; +33 new tests (705 total) | ✅ Complete |
