# Plan: NT Shim for Litebox

## Problem Statement

To run native Windows PE binaries (specifically Copilot CLI / Node.js) inside the LiteBox sandbox on Windows, we need an NT syscall shim — analogous to the existing Linux shim (`litebox_shim_linux`) but implementing Windows NT semantics instead of Linux syscall semantics.

**Architecture decisions (confirmed with user):**
- x86_64 only (matches current Windows runner)
- Initial target: Copilot CLI (Node.js on Windows)
- Own ntdll.dll replacement (Option A — cleaner, more control than syscall rewriting)
- Own PE loader (mirrors ELF loader architecture)
- New crate: `litebox_shim_windows` (separate from `litebox_shim_linux`)

## Architecture Overview

```
┌─────────────────────────────────────────┐
│              Guest PE Binary            │
│  (node.exe, copilot CLI)                │
│                                         │
│  imports: ntdll.dll, kernel32.dll, ...  │
└────────────┬────────────────────────────┘
             │ function calls
┌────────────▼────────────────────────────┐
│         Our Stub DLLs (in guest VA)     │
│  ntdll.dll    - NT syscall stubs        │
│  kernel32.dll - Win32 API stubs         │
│  ws2_32.dll   - Winsock stubs           │
│  advapi32.dll - Security API stubs      │
│                                         │
│  Each stub → syscall instruction        │
│              (trapped by platform)      │
└────────────┬────────────────────────────┘
             │ syscall trap
┌────────────▼────────────────────────────┐
│      litebox_shim_windows               │
│  (implements EnterShim trait)            │
│                                         │
│  NT syscall dispatch table              │
│  ├── NtCreateFile → litebox VFS         │
│  ├── NtReadFile → litebox fd/pipes/net  │
│  ├── NtWriteFile → litebox fd/pipes/net │
│  ├── NtAllocateVirtualMemory → PageMgr  │
│  ├── NtCreateThread → ThreadProvider    │
│  └── ...                                │
│                                         │
│  Reuses litebox core:                   │
│  - fd table, VFS, pipes, net (smoltcp)  │
│  - PageManager, process model           │
│  - event/poll, sync primitives          │
└────────────┬────────────────────────────┘
             │ platform trait calls
┌────────────▼────────────────────────────┐
│   litebox_platform_windows_userland     │
│   (existing — VEH, VirtualAlloc, etc.)  │
└─────────────────────────────────────────┘
```

## Key Design Decisions

### 1. Stub DLL Strategy

Instead of loading real Windows system DLLs and rewriting their `syscall` instructions, we provide our own minimal DLLs:

- **ntdll.dll**: Exports ~30-50 Nt* functions. Each is a tiny stub: move rcx→r10 (preserve arg0 across syscall), load syscall number → `syscall` → ret. The platform traps the `syscall` and dispatches to our shim.
- **kernel32.dll**: Many Win32 APIs are thin wrappers around ntdll. We implement them as user-mode code calling our ntdll stubs (no syscall needed). Examples: `CreateFileW` → builds OBJECT_ATTRIBUTES → calls `NtCreateFile`.
- **ws2_32.dll**: Winsock functions → translate to AFD IOCTL calls through `NtDeviceIoControlFile`, or implement directly in user mode on top of our ntdll stubs.
- **advapi32.dll**: Registry, security token stubs — mostly return SUCCESS with hardcoded values for sandboxed execution.

**Syscall calling convention**: The x64 `syscall` instruction clobbers RCX (saved return RIP) and R11 (saved RFLAGS). Since the Windows x64 ABI puts the first argument in RCX, each ntdll stub must execute `mov r10, rcx` before `syscall` to preserve arg0. The NT shim dispatcher reads arguments from `r10, rdx, r8, r9, [rsp+0x28], ...` (matching the Windows kernel convention). Guest code calling ntdll already has args in RCX/RDX/R8/R9 per the Windows x64 calling convention, so the stub's only job is the RCX→R10 move.

**Build approach**: Generate stub DLLs programmatically at build time. The stubs are so simple (a few dozen tiny functions) that a minimal PE builder in Rust can emit them as byte arrays, avoiding cdylib toolchain issues (notably, a Rust cdylib targeting MSVC would itself import ntdll.dll, creating a circular dependency). The PE builder lives in `litebox_common_windows` and is used by `build.rs` or at runtime to synthesize stub DLLs in guest memory directly.

**API-set and forwarder resolution**: Modern PE imports use API-set contract names (`api-ms-win-*`, `ext-ms-*`) and forwarded exports. The import resolver must include an API-set remapping table that maps these contract names to our stub DLLs (e.g., `api-ms-win-crt-runtime-l1-1-0.dll` → `ucrt.dll`). Forwarded exports (where an export in DLL A points to DLL B's export) must be followed during IAT resolution.

### 2. PE Loader

Mirrors the ELF loader's architecture:
- Parse PE headers (DOS header → PE signature → COFF header → optional header → section table)
- Map sections into guest address space via `PageManager`
- Resolve import table: for each imported DLL, load our stub DLL and resolve function addresses
- Handle relocations (base relocation table) for non-preferred load addresses
- Process `.tls` section for implicit TLS (`__declspec(thread)`) — allocate TLS storage and populate TEB TLS directory
- Set up initial thread stack and TEB/PEB structures
- Jump to PE entry point (AddressOfEntryPoint)

**Crate placement**: The PE parser lives in `litebox_common_windows` (not in the shim), mirroring how the ELF parser lives in `litebox_common_linux`. This allows reuse by tests, tooling, and other consumers without depending on the full shim crate.

### 3. NT Syscall Numbers

Unlike Linux, NT syscall numbers change between Windows versions. Since we provide our own ntdll.dll, we define our own syscall numbers — they just need to be consistent between our stubs and our dispatch table. This is a major advantage of Option A.

### 4. Process Environment

Windows PE binaries expect:
- **PEB** (Process Environment Block): Process-wide info (image base, loader data, process parameters, process heap, number of processors)
- **TEB** (Thread Environment Block): Per-thread info (stack limits, TLS, exception chain). On x86_64, GS segment base points to TEB.
- **Process Parameters**: Command line, environment variables, current directory, standard handles
- **Loader Data**: Linked list of loaded modules (LDR_DATA_TABLE_ENTRY per DLL). This is an ongoing data structure — updated whenever a DLL is loaded or unloaded.

We synthesize minimal PEB/TEB structures in guest memory. Node.js primarily cares about: command line, environment, standard handles, TLS, stack limits, process heap, and number of processors.

**Key PEB fields:**
- `ProcessHeap` — Must point to a valid heap handle for `RtlAllocateHeap`. A single default heap suffices.
- `NumberOfProcessors` — V8 uses this for thread pool sizing. Return 1 initially.
- `Ldr` (LDR_DATA) — Maintained by the loader as a linked list of loaded modules. Required for `GetModuleHandle`, `GetProcAddress`, and the CRT's DLL initialization loop.

**Key TEB fields:**
- `StackBase` / `StackLimit` — V8 reads these for stack overflow detection. Must match the guest stack allocation.
- `TlsSlots[64]` — Static TLS (64 slots). `TlsAlloc()` returns indices into this array.
- `TlsExpansionSlots` — Dynamic TLS (up to 1088 additional slots). Allocated on demand.

### 5. GS Segment: Host/Guest Conflict and Resolution

**The conflict:** On Windows x86_64, the GS segment serves dual purposes:
- The **host OS** uses GS to access the Thread Environment Block (TEB). The platform's own `syscall_callback` asm reads `gs:[tls_slot]` as its first action to find per-thread state.
- The **NT guest** expects GS to point to its synthesized TEB (standard Windows x64 convention).

If GS points to the guest TEB during a syscall trap, the platform reads garbage from `gs:[tls_slot]` and crashes.

**Note:** The FS segment is used for Linux guest TLS (glibc `__thread`). The platform manages FS via `wrfsbase`. For the NT shim, FS is free since Windows PE binaries do not use FS for TLS.

**Resolution: Save/restore GS at guest/host transitions (Option A).**

At guest→host transitions (syscall entry, exception entry):
```asm
rdgsbase rax          ; save guest GS (synthetic TEB address)
mov [tls.guest_gs], rax
wrgsbase <host_gs>    ; restore host GS (real Windows TEB)
```

At host→guest transitions (switch_to_guest):
```asm
rdgsbase rax          ; save host GS
mov [tls.host_gs], rax
wrgsbase <guest_gs>   ; restore guest GS (synthetic TEB)
```

**Cost:** ~40 cycles per transition (`rdgsbase` + `wrgsbase` are ~10-20 cycles each). Acceptable given the overall syscall handler cost (~hundreds of cycles).

**Implementation:** Add `guest_gs` field to `TlsState`. The `syscall_callback` prologue saves guest GS and restores host GS before accessing `gs:[tls_slot]`. `switch_to_guest` does the reverse. This is a per-platform change in `litebox_platform_windows_userland` — the shim and core are unaffected.

**Alternative considered:** Using FS for host TLS lookup instead of GS (Option D from review). Rejected because it requires a separate platform backend and breaks the existing Linux-guest FS management.

### 6. SEH Exception Delivery

Windows PE binaries expect Structured Exception Handling (SEH) when faults occur. The current `ExceptionInfo` struct carries x86 exception type + error code + CR2, which is sufficient for the Linux shim's POSIX signal delivery but not for Windows SEH.

**Design:** The NT shim reconstructs Windows exception records from the x86 exception info (the mapping is well-defined):
- Page fault (exception 14) + write bit → `EXCEPTION_ACCESS_VIOLATION` with `ExceptionInformation[0]=1`
- Page fault + read → `EXCEPTION_ACCESS_VIOLATION` with `ExceptionInformation[0]=0`
- Integer divide by zero (exception 0) → `EXCEPTION_INT_DIVIDE_BY_ZERO`
- Breakpoint (exception 3) → `EXCEPTION_BREAKPOINT`
- Illegal instruction (exception 6) → `EXCEPTION_ILLEGAL_INSTRUCTION`

The shim's `exception()` handler:
1. Builds an `EXCEPTION_RECORD` (exception code, flags, address, parameters) in guest stack memory
2. Builds a `CONTEXT` (full register state snapshot) in guest stack memory
3. Walks the `.pdata`/`.xdata` unwind tables to find the registered exception handler
4. Redirects guest RIP to the handler, with RSP pointing to the exception frame

This approach requires no changes to the `ExceptionInfo` trait — the NT shim derives all needed Windows exception data from the existing x86 exception fields.

### 7. What We Reuse from litebox Core

The NT shim hooks into the same litebox core abstractions as the Linux shim:
- **fd table** (`litebox::fd`): Used as the backing store for simple file-like handles. NT HANDLEs map to internal fd numbers via a translation layer.
- **VFS** (`litebox::fs`): Same layered filesystem (in_mem + tar_ro + devices). NT paths (e.g., `\??\C:\foo`) are translated to POSIX paths internally.
- **PageManager** (`litebox::mm`): Same virtual memory management. `NtAllocateVirtualMemory` → `PageManager` operations.
- **Pipes** (`litebox::pipes`): Same pipe implementation. `NtCreateNamedPipeFile` / anonymous pipes → litebox pipes.
- **Network** (`litebox::net`): Same smoltcp stack. Winsock → AFD IOCTLs → smoltcp sockets.
- **Process model** (`litebox::process`): Same process tree. `NtCreateUserProcess` → fork-like semantics.
- **Event/poll** (`litebox::event`): Same polling infrastructure. `NtWaitForSingleObject`/`NtWaitForMultipleObjects` → litebox events.

### 8. What's New (NT-Specific)

- **litebox_common_windows** crate: NT status codes (NTSTATUS), NT structures (UNICODE_STRING, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, FILE_INFORMATION classes), NT constants, NT syscall request enum, PE format structures, PE parser, and programmatic PE builder for stub DLL generation.
- **PE loader**: Map PE sections, resolve imports (including API-set remapping and forwarder chains), handle relocations, process `.tls` sections.
- **PEB/TEB synthesis**: Construct minimal Windows process/thread environment with accurate stack limits, TLS, heap, and loader data.
- **NT path translation**: `\??\C:\` → `/`, `\DosDevices\` → alias for `\??\`, `\Device\` → device namespace, `\\.\pipe\` → litebox pipes, `\KnownDlls\` → STATUS_OBJECT_NAME_NOT_FOUND (force filesystem load). Support `RootDirectory` handle + relative path in `OBJECT_ATTRIBUTES`.
- **NT object/handle table**: A first-class NT object table (not a thin veneer over `litebox::fd`). NT HANDLEs can reference files, processes, threads, events, semaphores, sections, and registry keys — each with object-type-specific wait/query semantics. HANDLEs are opaque values (multiples of 4). Pseudo-handles (`GetCurrentProcess()` = -1, `GetCurrentThread()` = -2) are special-cased. The object table dispatches `NtWaitForSingleObject`, `NtDuplicateObject`, and `NtQueryObject` polymorphically based on object type. File-like objects delegate to the litebox fd table internally.
- **Console subsystem**: `NtReadFile`/`NtWriteFile` on console handles → existing StdioProvider.
- **Registry stubs**: `NtOpenKey`/`NtQueryValueKey` → return minimal hardcoded values or STATUS_OBJECT_NAME_NOT_FOUND.
- **Heap manager**: `RtlAllocateHeap`/`RtlFreeHeap` in our ntdll stub (user-mode, no syscall needed).
- **SRW locks**: `RtlAcquireSRWLockExclusive`/`Shared` etc. implemented in user-mode ntdll stub using litebox's futex mechanism, avoiding keyed event syscall complexity.
- **IOCP / completion ports**: libuv's Windows event loop is built around I/O Completion Ports. `NtCreateIoCompletionPort`, `NtSetIoCompletionPort`, `NtRemoveIoCompletion` must be implemented. Overlapped `NtReadFile`/`NtWriteFile` with completion delivery are required for libuv's async file and network I/O.

## NT Syscalls Required (Prioritized for Node.js)

### Phase 1: Minimal Boot (process starts, prints to console)
| NT Syscall | Linux Equivalent | Purpose |
|---|---|---|
| NtAllocateVirtualMemory | mmap | Memory allocation |
| NtFreeVirtualMemory | munmap | Memory deallocation |
| NtProtectVirtualMemory | mprotect | Change page protection |
| NtQueryVirtualMemory | /proc/self/maps | Query page permissions (CRT/V8 guard page checks) |
| NtReadFile | read | Read from file/pipe/console |
| NtWriteFile | write | Write to file/pipe/console |
| NtClose | close | Close handle |
| NtCreateFile | openat | Open/create file |
| NtQueryInformationFile | fstat | File metadata |
| NtSetInformationFile | lseek, ftruncate | File position, truncate |
| NtQueryVolumeInformationFile | statfs | Volume info |
| NtCreateSection / NtMapViewOfSection | mmap(MAP_PRIVATE, fd) | Memory-mapped files |
| NtQuerySystemInformation | sysinfo, uname | System info |
| NtQueryPerformanceCounter | clock_gettime | High-res time |
| NtQuerySystemTime | gettimeofday | Wall clock |
| NtDelayExecution | clock_nanosleep | Sleep |

### Phase 2: Threading & Sync (Node.js worker threads, libuv)
| NT Syscall | Linux Equivalent | Purpose |
|---|---|---|
| NtCreateThreadEx | clone | Create thread |
| NtTerminateThread | exit | Thread exit |
| NtTerminateProcess | exit_group | Process exit |
| NtWaitForSingleObject | futex(WAIT) | Wait on handle |
| NtWaitForMultipleObjects | epoll_wait | Wait on multiple handles |
| NtSetEvent / NtResetEvent / NtCreateEvent | eventfd | Event signaling |
| NtReleaseSemaphore / NtCreateSemaphore | futex(WAKE) | Semaphore ops |
| NtQueryInformationThread | get_robust_list | Thread info (TEB address) |
| NtSetInformationThread | arch_prctl | Set thread name, affinity |
| NtCreateKeyedEvent / NtWaitForKeyedEvent | futex | Keyed events (SRW locks) |

### Phase 3: Networking (Copilot HTTP/TLS)
| NT Syscall | Linux Equivalent | Purpose |
|---|---|---|
| NtDeviceIoControlFile (AFD) | socket/connect/bind/... | All Winsock operations go through AFD IOCTLs |
| NtCreateFile (\Device\Afd) | socket | Create socket (AFD device) |

Note: All Winsock operations (connect, send, recv, etc.) are implemented as `NtDeviceIoControlFile` IOCTLs on AFD (Ancillary Function Driver) handles. We intercept these and route to litebox's smoltcp stack.

### Phase 4: Process Management (Copilot spawns git, etc.)
| NT Syscall | Linux Equivalent | Purpose |
|---|---|---|
| NtCreateUserProcess | fork+exec | Create child process |
| NtQueryInformationProcess | getpid, getppid | Process info |
| NtWaitForSingleObject (process) | waitpid | Wait for child |
| NtDuplicateObject | dup/dup2 | Handle duplication |
| NtQueryObject | fcntl(F_GETFL) | Object type/info |

### Phase 5: Miscellaneous
| NT Syscall | Linux Equivalent | Purpose |
|---|---|---|
| NtOpenKey / NtQueryValueKey | N/A | Registry access (stub) |
| NtQueryDirectoryFile | getdents64 | Directory enumeration |
| NtDeleteFile | unlink | File deletion |
| NtSetInformationFile (rename) | renameat2 | File rename |
| NtCreateNamedPipeFile | pipe2 | Named/anonymous pipes |
| NtFsControlFile | ioctl | File system control |
| NtQueryAttributesFile | access/stat | Quick file existence check |

## Crate Structure

All new crates should be `#![no_std]` per project convention, with `extern crate alloc` where heap allocation is needed.

```
litebox_shim_windows/                 # NT syscall shim (no_std)
├── Cargo.toml
├── src/
│   ├── lib.rs              # WindowsShimBuilder, WindowsShim, entrypoints (EnterShim impl)
│   ├── loader/
│   │   ├── mod.rs          # PE loader module root
│   │   ├── pe.rs           # PE mapper (sections, relocations) — uses parser from litebox_common_windows
│   │   ├── imports.rs      # Import table resolution + API-set remapping + forwarder chains
│   │   └── environment.rs  # PEB/TEB/ProcessParameters synthesis
│   ├── syscalls/
│   │   ├── mod.rs          # NT syscall dispatch table
│   │   ├── file.rs         # NtCreateFile, NtReadFile, NtWriteFile, NtQueryInformationFile, ...
│   │   ├── memory.rs       # NtAllocateVirtualMemory, NtFreeVirtualMemory, NtProtectVirtualMemory, NtQueryVirtualMemory, ...
│   │   ├── process.rs      # NtCreateUserProcess, NtTerminateProcess, NtQueryInformationProcess, ...
│   │   ├── thread.rs       # NtCreateThreadEx, NtTerminateThread, NtSetInformationThread, ...
│   │   ├── sync.rs         # NtWaitForSingleObject, NtCreateEvent, NtReleaseSemaphore, ...
│   │   ├── iocp.rs         # NtCreateIoCompletionPort, NtSetIoCompletionPort, NtRemoveIoCompletion
│   │   ├── net.rs          # NtDeviceIoControlFile (AFD IOCTLs) → smoltcp
│   │   ├── registry.rs     # NtOpenKey, NtQueryValueKey (stubs)
│   │   ├── misc.rs         # NtQuerySystemInformation, NtQueryPerformanceCounter, ...
│   │   └── console.rs      # Console-specific NtReadFile/NtWriteFile handling
│   ├── object.rs           # NT object table: HANDLE ↔ typed object (file/process/thread/event/section/...)
│   ├── path.rs             # NT path (\??\, \DosDevices\, \Device\, \KnownDlls\, \\.\) → litebox path translation
│   └── seh.rs              # SEH exception delivery: EXCEPTION_RECORD + CONTEXT synthesis, .pdata/.xdata unwinding

litebox_common_windows/               # NT types, PE format, PE parser, PE builder (no_std)
├── Cargo.toml
├── src/
│   ├── lib.rs              # NT types, constants, syscall request enum
│   ├── ntstatus.rs         # NTSTATUS codes (STATUS_SUCCESS, STATUS_ACCESS_DENIED, ...)
│   ├── ntstructs.rs        # NT structures (UNICODE_STRING, OBJECT_ATTRIBUTES, FILE_*_INFORMATION, ...)
│   ├── pe.rs               # PE format structures (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, ...)
│   ├── pe_parser.rs        # PE parser (reusable by tests/tooling without depending on shim)
│   ├── pe_builder.rs       # Programmatic PE builder for generating stub DLLs as byte arrays
│   └── apisets.rs          # API-set contract name → DLL remapping table

litebox_runner_windows_userland/        # Runner for Windows PE execution on userland platform
├── Cargo.toml
├── src/
│   └── lib.rs              # CLI, PE loading, stub DLL setup, enter guest
```

## Implementation Phases

### Phase 0: Foundation
- Create `litebox_common_windows` (`#![no_std]`) with NTSTATUS codes, NT structures, PE format structures, PE parser, PE builder, API-set remapping table
- Create `litebox_shim_windows` skeleton: crate setup, EnterShim impl, empty syscall dispatch
- Implement GS save/restore in platform asm (section 5)

### Phase 1: Static Hello World
- PE loader: map sections, apply relocations, process `.tls` sections
- PEB/TEB synthesis (minimal — stack limits, TLS slots, PEB pointer, process heap, command line)
- NT object/handle table (polymorphic HANDLE → typed object mapping)
- NT path translation (including `\DosDevices\`, `\KnownDlls\`)
- Implement: NtWriteFile (console stdout), NtAllocateVirtualMemory, NtFreeVirtualMemory, NtProtectVirtualMemory, NtQueryVirtualMemory, NtClose, NtTerminateProcess
- Generate ntdll.dll stub via PE builder (with `mov r10, rcx; mov eax, NR; syscall; ret` stubs)
- Generate minimal kernel32.dll stub (WriteConsoleW, ExitProcess, GetCommandLineW, GetStdHandle)
- Import resolver with API-set remapping and forwarder chain support
- Target: a static PE "hello world" binary runs in the sandbox

### Phase 2: File I/O & CRT Initialization
- Implement: NtCreateFile, NtReadFile, NtQueryInformationFile, NtSetInformationFile, NtQueryVolumeInformationFile, NtQueryDirectoryFile, NtDeleteFile, NtQueryAttributesFile
- Implement: NtCreateSection, NtMapViewOfSection (for DLL loading)
- Expand kernel32.dll: CreateFileW, ReadFile, WriteFile, CloseHandle, GetFileSize, FindFirstFileW, FindNextFileW
- Implement: NtQuerySystemInformation, NtQueryPerformanceCounter, NtQuerySystemTime
- Implement: NtSetInformationThread(ThreadNameInformation) as no-op (Node.js sets thread names)
- **Milestone 1.5**: UCRT (Universal C Runtime) initializes successfully. This is a critical checkpoint — UCRT calls many ntdll functions internally and will surface most missing syscalls early.
- Target: UCRT initializes, dynamic PE with CRT dependency runs

### Phase 3: Threading & Synchronization
- Implement: NtCreateThreadEx, NtTerminateThread, NtWaitForSingleObject, NtWaitForMultipleObjects
- Implement: NtCreateEvent, NtSetEvent, NtResetEvent, NtCreateSemaphore, NtReleaseSemaphore
- Implement SRW locks (`RtlAcquireSRWLockExclusive`/`Shared` etc.) in user-mode ntdll stub using litebox futex — avoids keyed event syscall complexity entirely
- GS segment management (save/restore per section 5; TEB per thread)
- Implement: NtDuplicateObject, NtQueryObject
- Target: multi-threaded programs work (Node.js libuv thread pool)

### Phase 4: Networking & IOCP
- Implement I/O Completion Ports: NtCreateIoCompletionPort, NtSetIoCompletionPort, NtRemoveIoCompletion — required because libuv's Windows event loop is IOCP-based
- Implement overlapped (async) NtReadFile/NtWriteFile with completion delivery
- Implement AFD IOCTL dispatch in NtDeviceIoControlFile
- AFD_BIND, AFD_CONNECT, AFD_SEND, AFD_RECV, AFD_SELECT, AFD_POLL
- Map AFD operations to litebox smoltcp sockets
- Expand ws2_32.dll stubs
- Target: HTTP client works (Node.js can fetch URLs)

### Phase 5: Process Spawning & Copilot
- Implement: NtCreateUserProcess (PE loading of child process)
- Pipe-based stdin/stdout/stderr redirection for child processes
- Implement: NtCreateNamedPipeFile
- Registry stubs for Node.js runtime queries
- Target: Copilot CLI runs end-to-end

## Stub DLL Build Strategy

**Option A (recommended): Programmatic PE generation**

Generate stub DLLs at build time using a minimal PE builder written in Rust. The stubs are simple enough (a few dozen tiny functions each) that writing them as byte arrays avoids all DLL toolchain issues:
- No circular dependency (a Rust cdylib targeting MSVC would itself import ntdll.dll)
- No dependency on MSVC linker or .def files
- Full control over exact binary layout, exports, and section structure
- The PE builder lives in `litebox_common_windows` and can also be used at runtime to synthesize stubs directly in guest memory

Each ntdll stub function is:
```asm
mov r10, rcx          ; preserve first argument (syscall clobbers RCX)
mov eax, <syscall_nr> ; load our custom syscall number
syscall               ; trapped by platform VEH
ret
```

**For kernel32/ws2_32/advapi32**: These implement higher-level APIs in user mode on top of ntdll. They're Rust code compiled by the PE builder (or, if complex enough, built as `cdylib` that imports only our custom ntdll).

## Risks & Open Questions

1. **UCRT / VC runtime**: Node.js links against `ucrt.dll` and `vcruntime140.dll`. These call ntdll internally. Option: include real UCRT DLLs (redistributable) and let our ntdll handle their syscalls. Expect significant discovery iteration — add Phase 1.5 milestone for "UCRT initializes successfully."
2. **GS segment conflict**: **Resolved** — see section 5. Save/restore GS via `rdgsbase`/`wrgsbase` at guest/host transitions (~40 cycles overhead).
3. **SEH exception delivery**: **Resolved** — see section 6. Reconstruct `EXCEPTION_RECORD` + `CONTEXT` from x86 exception info; walk `.pdata`/`.xdata` to find handlers.
4. **DLL initialization**: DllMain must be called with DLL_PROCESS_ATTACH for each loaded DLL (including UCRT). Our loader must handle this and maintain the LDR_DATA linked list.
5. **Thread-local storage**: Windows TLS needs both static TLS (TEB.TlsSlots, 64 slots) and dynamic TLS (TEB.TlsExpansionSlots, up to 1088 additional slots). For implicit TLS (`__declspec(thread)`), the loader must process the `.tls` section of each PE and allocate TLS storage per thread. Node.js uses both forms.
6. **API coverage**: Node.js (V8 + libuv) touches a wide Win32 surface. We'll discover missing stubs iteratively — the shim should log unsupported syscalls/APIs clearly to guide development.
7. **Stub DLL compatibility**: Real Windows DLLs have version resources, manifests, etc. Node.js may check DLL versions. Our stubs should include plausible version resources.
8. **AFD IOCTL complexity**: AFD is undocumented. References: (a) ReactOS source, (b) Windows driver samples, (c) libuv source (`src/win/winsock.c`). Key IOCTLs: `AFD_POLL`, `AFD_SEND`, `AFD_RECV`, `AFD_CONNECT`, `AFD_BIND`, `AFD_GET_INFO`. This is the most complex NT subsystem to implement.
9. **IOCP / completion model**: libuv's Windows event loop is built around I/O Completion Ports, not just AFD. Phase 4 must include IOCP implementation, overlapped I/O semantics, and async completion delivery. This significantly increases the scope beyond "just AFD IOCTLs."
10. **Console vs ConPTY**: Node.js may use ConPTY (pseudo-console) for terminal support. For initial bring-up, emulating a legacy console is simpler. ConPTY can be added later if needed.
11. **API-set and forwarder resolution**: Modern PE imports use API-set contract names (`api-ms-win-*`) and forwarded exports. The import resolver needs a remapping table and must follow forwarder chains.
12. **Size estimate**: The Linux shim is ~16,800 lines total. The NT shim will likely be **larger** (20,000-25,000 lines) because NT data structures (OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, FILE_*_INFORMATION classes) are more verbose and the NT object model is richer.
13. **`no_std` compatibility**: Both `litebox_common_linux` and `litebox_shim_linux` are `#![no_std]`. New crates (`litebox_common_windows`, `litebox_shim_windows`) should follow suit per project convention, affecting PE parsing (no `std::io`) and stub DLL handling.

## Todos

1. **nt-common-types** — Create `litebox_common_windows` crate (`#![no_std]`) with NTSTATUS codes, NT structures (UNICODE_STRING, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK), PE format structures (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER), NtSyscallRequest enum, and API-set remapping table.

2. **pe-parser** — Implement PE file parser in `litebox_common_windows`: read DOS header, PE signature, COFF header, optional header, section table, import directory, relocation table, `.tls` directory. Output a `PeParsedFile` struct analogous to `ElfParsedFile`.

3. **pe-builder** — Implement programmatic PE builder in `litebox_common_windows` for generating stub DLLs as byte arrays at build time. Produces valid PE/COFF with exports, sections, and relocations.

4. **pe-loader** — Implement PE loader: map sections into guest VA via PageManager, apply base relocations, process `.tls` sections, set section permissions (R/W/X). Analogous to ELF loader's `load_segments`.

5. **import-resolver** — Implement import table resolution: API-set contract name remapping, forwarder chain resolution, recursive DLL loading, IAT patching. Depends on pe-parser and ntdll-stub-dll.

6. **peb-teb-synthesis** — Synthesize PEB and TEB structures in guest memory. PEB: image base, process parameters, process heap, NumberOfProcessors, Ldr (loader data linked list). TEB: stack limits, TLS slots (64 static + expansion), PEB pointer. GS segment management per section 5.

7. **nt-shim-skeleton** — Create `litebox_shim_windows` crate skeleton (`#![no_std]`): implement `EnterShim` trait, NT syscall dispatch table (reading args from r10/rdx/r8/r9), NT object/handle table (polymorphic typed objects), NT path translation (including `\DosDevices\`, `\KnownDlls\`).

8. **nt-syscalls-memory** — Implement NtAllocateVirtualMemory, NtFreeVirtualMemory, NtProtectVirtualMemory, NtQueryVirtualMemory using existing PageManager.

9. **nt-syscalls-file-basic** — Implement NtCreateFile, NtReadFile, NtWriteFile, NtClose, NtQueryInformationFile, NtSetInformationFile using existing VFS + fd table.

10. **nt-syscalls-console** — Implement console I/O: NtReadFile/NtWriteFile on console handles → StdioProvider. Handle GetConsoleMode/SetConsoleMode via NtDeviceIoControlFile on console handles.

11. **nt-syscalls-process-exit** — Implement NtTerminateProcess, NtTerminateThread (basic process/thread lifecycle).

12. **ntdll-stub-dll** — Generate ntdll.dll stub via pe-builder: export Nt* functions as `mov r10, rcx; mov eax, NR; syscall; ret` stubs. Also export Rtl* user-mode functions: RtlAllocateHeap, RtlFreeHeap (user-mode heap), RtlInitUnicodeString, RtlNtStatusToDosError, RtlAcquireSRWLockExclusive/Shared (futex-based, no keyed events).

13. **kernel32-stub-dll** — Generate kernel32.dll stub: implement Win32 wrappers (CreateFileW, ReadFile, WriteFile, CloseHandle, GetStdHandle, GetCommandLineW, ExitProcess, etc.) as user-mode code calling our ntdll.

14. **runner-windows-userland** — Create `litebox_runner_windows_userland` crate: CLI args, PE loading, stub DLL generation, GS save/restore setup, enter guest execution loop.

15. **hello-world-e2e** — End-to-end test: compile a Windows PE "hello world" binary, generate stub DLLs, package into tar, run in litebox.

16. **nt-syscalls-threading** — Implement NtCreateThreadEx, NtTerminateThread, NtWaitForSingleObject, NtWaitForMultipleObjects, NtCreateEvent/NtSetEvent/NtResetEvent, NtCreateSemaphore/NtReleaseSemaphore. Per-thread TEB with GS management.

17. **nt-syscalls-iocp** — Implement I/O Completion Ports: NtCreateIoCompletionPort, NtSetIoCompletionPort, NtRemoveIoCompletion. Overlapped NtReadFile/NtWriteFile with completion delivery. Required for libuv's Windows event loop.

18. **nt-syscalls-file-advanced** — Implement NtQueryDirectoryFile, NtDeleteFile, NtSetInformationFile (rename), NtCreateSection/NtMapViewOfSection, NtQueryVolumeInformationFile, NtQueryAttributesFile, NtDuplicateObject.

19. **nt-syscalls-system** — Implement NtQuerySystemInformation, NtQueryPerformanceCounter, NtQuerySystemTime, NtDelayExecution, NtQueryInformationProcess/Thread, NtSetInformationThread(ThreadNameInformation) as no-op.

20. **nt-syscalls-afd** — Implement AFD IOCTL dispatch: NtDeviceIoControlFile with AFD device. Map AFD_BIND, AFD_CONNECT, AFD_SEND, AFD_RECV, AFD_POLL to smoltcp sockets.

21. **ws2-stub-dll** — Generate ws2_32.dll stub: WSAStartup, socket, connect, send, recv, closesocket, select, etc. → NtDeviceIoControlFile(AFD).

22. **nt-syscalls-process-create** — Implement NtCreateUserProcess: PE loading of child, stdin/stdout/stderr pipe redirection, NtCreateNamedPipeFile.

23. **registry-stubs** — Implement NtOpenKey, NtQueryValueKey with minimal hardcoded responses for common Node.js registry queries (timezone, locale, etc.).

24. **seh-exception-delivery** — Implement SEH exception delivery per section 6: EXCEPTION_RECORD + CONTEXT synthesis, `.pdata`/`.xdata` unwind table walking, handler dispatch.

25. **copilot-e2e** — End-to-end: run Copilot CLI (Windows native) in litebox.

## Dependency Graph

```
nt-common-types ──→ pe-parser ──→ pe-loader ──→ import-resolver ──→ peb-teb-synthesis ──→ hello-world-e2e
nt-common-types ──→ nt-shim-skeleton ──→ nt-syscalls-memory ──→ hello-world-e2e
                    nt-shim-skeleton ──→ nt-syscalls-file-basic ──→ hello-world-e2e
                    nt-shim-skeleton ──→ nt-syscalls-console ──→ hello-world-e2e
                    nt-shim-skeleton ──→ nt-syscalls-process-exit ──→ hello-world-e2e
nt-common-types ──→ ntdll-stub-dll ──→ import-resolver  (import resolver needs stubs to resolve against)
                    ntdll-stub-dll ──→ kernel32-stub-dll ──→ hello-world-e2e
                                       runner-windows-native ──→ hello-world-e2e

hello-world-e2e ──→ nt-syscalls-threading ──→ nt-syscalls-iocp ──→ nt-syscalls-afd ──→ copilot-e2e
hello-world-e2e ──→ nt-syscalls-file-advanced ──→ copilot-e2e
hello-world-e2e ──→ nt-syscalls-system ──→ copilot-e2e
                    nt-syscalls-afd ──→ ws2-stub-dll ──→ copilot-e2e
                    nt-syscalls-process-create ──→ copilot-e2e
                    registry-stubs ──→ copilot-e2e
```

Milestone 1 (hello-world-e2e): 15 todos, can parallelize across 3 tracks:
  - Track A: PE loading (pe-parser → pe-builder → pe-loader → import-resolver → peb-teb-synthesis)
  - Track B: Syscall handlers (nt-shim-skeleton → memory/file/console/exit in parallel)
  - Track C: Stub DLLs + runner (ntdll-stub → kernel32-stub, runner-windows-native)
  - Critical path: nt-common-types → pe-parser → pe-loader → ntdll-stub-dll → import-resolver → peb-teb-synthesis → hello-world-e2e

Milestone 2 (copilot-e2e): 10 additional todos after hello-world (threading, IOCP, AFD, process creation, SEH, registry).
