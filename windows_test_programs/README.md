# Windows Test Programs

This directory contains Windows programs used to test the Windows-on-Linux platform in LiteBox.

## Test Programs

### hello_cli

A simple command-line "Hello World" program that:
- Prints "Hello World from LiteBox!" to the console
- Demonstrates basic Windows console I/O
- Tests standard output in the Windows-on-Linux environment

### hello_gui

A simple GUI program that:
- Shows a message box with "Hello LiteBox!"
- Demonstrates basic Windows GUI functionality
- Tests Windows API calls (MessageBoxW) in the Windows-on-Linux environment

### file_io_test

Comprehensive file I/O operations test that validates:
- Creating and writing files
- Reading file contents
- File metadata queries
- Deleting files
- Directory creation and listing
- Nested file operations

This test creates files and directories in a unique temporary directory, performs operations on them, validates results, and cleans up afterward. Exits with non-zero status on any test failure.

### args_test

Command-line argument parsing test that validates:
- Accessing the program name (argv[0])
- Parsing command-line arguments
- Handling arguments with spaces
- Getting the current executable path

Run with various arguments to test: `args_test.exe arg1 "arg with spaces" arg3`

### env_test

Environment variable operations test that validates:
- Reading common environment variables (PATH, HOME, USER, etc.)
- Setting custom environment variables
- Removing environment variables
- Listing all environment variables

### string_test

String operations test that validates:
- String concatenation and manipulation
- String comparison (case-sensitive and case-insensitive)
- String searching (finding substrings)
- String splitting and trimming
- Unicode string handling
- Case conversion (uppercase/lowercase)

### math_test

Mathematical operations test that validates:
- Integer arithmetic (addition, subtraction, multiplication, division, modulo)
- Floating-point arithmetic
- Math library functions (sqrt, pow, sin, cos, tan, exp, ln)
- Special floating-point values (infinity, NaN)
- Rounding operations (floor, ceil, round, trunc)
- Bitwise operations (AND, OR, XOR, NOT, shifts)

### winsock_test (C++)

C++ programs that test the Windows Sockets 2 (WinSock2) API implementation
provided by the Windows-on-Linux platform.  Located in the `winsock_test/`
subdirectory and built with the MinGW cross-compiler (not Cargo).

### dynload_test (C)

A plain-C program that exercises the dynamic-loading Windows APIs:
`GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`, and
`FreeLibrary`.  Located in `dynload_test/` and built with the MinGW C
cross-compiler (not Cargo).

#### getprocaddress_test

Validates the `GetProcAddress` API and friends:
- `GetModuleHandleA(NULL)` → non-NULL pseudo-handle for the main module
- `GetModuleHandleA("kernel32.dll")` → non-NULL HMODULE
- `GetProcAddress` with a known export (`GetLastError`) → non-NULL
- Call the resolved function pointer and verify it executes correctly
- `GetProcAddress` with an unknown name → NULL + `ERROR_PROC_NOT_FOUND` (127)
- `GetProcAddress` with an ordinal value → NULL + `ERROR_PROC_NOT_FOUND` (127)
- `GetModuleHandleW(NULL)` → non-NULL (wide-string variant)
- `LoadLibraryA` + `GetProcAddress` + `FreeLibrary` round-trip

### seh_test (C and C++)

Test programs that exercise Windows Structured Exception Handling (SEH).
Located in `seh_test/` and built with the MinGW cross-compiler (not Cargo).

> **Note:** GCC/MinGW does not support the MSVC-specific `__try/__except/__finally`
> syntax in C mode.  The C test therefore exercises the SEH runtime API layer
> directly, while the C++ test uses standard `try/catch/throw` (which on
> Windows x64 uses the SEH `.pdata`/`.xdata` unwind machinery under the hood).

#### seh_c_test

Plain-C program that validates the Windows SEH runtime APIs:

- `RtlCaptureContext` – captures non-zero RSP and RIP for the current thread
- `SetUnhandledExceptionFilter` – accepts a filter and returns the previous one
- `AddVectoredExceptionHandler` – returns a non-NULL registration handle
- `RemoveVectoredExceptionHandler` – removes the registration
- `RtlLookupFunctionEntry` – returns NULL for out-of-range PC; finds own entry when exception table is registered
- `RtlVirtualUnwind` – returns NULL for NULL function_entry argument
- `RtlUnwindEx` – does not crash with NULL arguments
- `setjmp`/`longjmp` – C-standard non-local jumps (the C alternative to `__try/__except`)
- Standard exception-code constants (EXCEPTION_ACCESS_VIOLATION, etc.)

#### seh_cpp_test

C++ program that validates C++ exception handling (exercises the SEH unwind machinery):

- `throw int` / `catch(int)` – basic typed exception
- `throw std::string` / `catch(const std::string &)` – class exception
- Polymorphic catch via base-class reference
- Rethrowing with `throw;`
- `catch(...)` catch-all handler
- Stack unwinding: destructors called when exception propagates
- Nested `try/catch` blocks
- Exception propagates across multiple stack frames
- `std::exception` hierarchy (`std::runtime_error`, `std::logic_error`)
- Member destructor called when constructor throws
- Multiple catch clauses with correct clause selection
- Exception propagation through an indirect function call

#### winsock_basic_test

Validates the fundamental WinSock2 building blocks:
- `WSAStartup` / `WSACleanup`
- Byte-order helpers: `htons`, `htonl`, `ntohs`, `ntohl`
- `WSAGetLastError` / `WSASetLastError`
- TCP and UDP `socket()` creation and `closesocket()`
- `setsockopt` / `getsockopt` (SO_REUSEADDR, SO_SNDBUF, SO_RCVBUF, SO_KEEPALIVE)
- `ioctlsocket` – FIONBIO non-blocking mode toggle
- `bind` to `127.0.0.1:0` + `getsockname` to retrieve the assigned port
- `getaddrinfo` / `freeaddrinfo`

#### winsock_tcp_test

Exercises a full TCP client-server exchange over loopback in a single thread
using non-blocking sockets and `select`:
- Server: `socket`, `setsockopt`, `bind`, `listen`, `getsockname`, `accept`
- Client: `socket`, non-blocking `connect` (expects WSAEWOULDBLOCK)
- `select` to wait for server readability (incoming connection)
- `select` to wait for client writability (connect completed)
- Bidirectional `send` / `recv` data exchange
- `getpeername` on accepted socket
- `shutdown` (SD_BOTH) and `closesocket`

#### winsock_udp_test

Exercises UDP datagram exchange over loopback in a single thread:
- Server: `socket`, `bind`, `getsockname`
- Client: `socket`, `bind` (to obtain a reply address), `sendto`
- `select` to wait for server readability
- Server `recvfrom` – verifies payload and sender address
- Server `sendto` reply back to client address
- `select` to wait for client readability
- Client `recvfrom` – verifies reply payload
- `closesocket` both sockets

## Building

### Rust programs (hello_cli, hello_gui, file_io_test, args_test, env_test, string_test, math_test)

These programs are automatically built for Windows (x86_64-pc-windows-gnu) by the GitHub Actions workflow.

To build locally with cross-compilation:

```bash
# Install the Windows target
rustup target add x86_64-pc-windows-gnu

# Install MinGW cross-compiler
sudo apt install -y mingw-w64

# Build the programs
cd windows_test_programs
cargo build --release --target x86_64-pc-windows-gnu
```

The resulting executables will be in:
- `target/x86_64-pc-windows-gnu/release/hello_cli.exe`
- `target/x86_64-pc-windows-gnu/release/hello_gui.exe`
- `target/x86_64-pc-windows-gnu/release/file_io_test.exe`
- `target/x86_64-pc-windows-gnu/release/args_test.exe`
- `target/x86_64-pc-windows-gnu/release/env_test.exe`
- `target/x86_64-pc-windows-gnu/release/string_test.exe`
- `target/x86_64-pc-windows-gnu/release/math_test.exe`

### C++ WinSock programs (winsock_test/)

```bash
# Install MinGW cross-compiler (if not already installed)
sudo apt install -y mingw-w64

# Build all three WinSock test programs
cd windows_test_programs/winsock_test
make
```

The resulting executables will be in `windows_test_programs/winsock_test/`:
- `winsock_basic_test.exe`
- `winsock_tcp_test.exe`
- `winsock_udp_test.exe`

### C dynload program (dynload_test/)

```bash
# Install MinGW C cross-compiler (if not already installed)
sudo apt install -y gcc-mingw-w64-x86-64

# Build
cd windows_test_programs/dynload_test
make
```

The resulting executable will be in `windows_test_programs/dynload_test/`:
- `getprocaddress_test.exe`

### C and C++ SEH programs (seh_test/)

```bash
# Install MinGW cross-compiler (if not already installed)
sudo apt install -y mingw-w64

# Build both SEH test programs
cd windows_test_programs/seh_test
make
```

The resulting executables will be in `windows_test_programs/seh_test/`:
- `seh_c_test.exe`   – C program testing SEH runtime APIs
- `seh_cpp_test.exe` – C++ program testing C++ exceptions (which use SEH)

## Testing

These programs can be used to test the Windows-on-Linux runner:

```bash
# Build the runner
cargo build -p litebox_runner_windows_on_linux_userland

# Run the Rust test programs
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/target/x86_64-pc-windows-gnu/release/hello_cli.exe
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/target/x86_64-pc-windows-gnu/release/file_io_test.exe
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/target/x86_64-pc-windows-gnu/release/args_test.exe arg1 arg2
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/target/x86_64-pc-windows-gnu/release/env_test.exe
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/target/x86_64-pc-windows-gnu/release/string_test.exe
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/target/x86_64-pc-windows-gnu/release/math_test.exe

# Run the C++ WinSock test programs
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/winsock_test/winsock_basic_test.exe
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/winsock_test/winsock_tcp_test.exe
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/winsock_test/winsock_udp_test.exe

# Run the C dynload test program
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/dynload_test/getprocaddress_test.exe

# Run the C and C++ SEH test programs
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/seh_test/seh_c_test.exe
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/seh_test/seh_cpp_test.exe
```

### Current Status

As of the last update, the Windows-on-Linux platform can:
- ✅ Load and parse PE executables
- ✅ Apply relocations
- ⚠️ Import resolution requires Windows DLLs to be available

When running the test programs, you'll see output like:
```
Loaded PE binary: ./windows_test_programs/target/x86_64-pc-windows-gnu/release/hello_cli.exe
  Entry point: 0x1410
  Image base: 0x140000000
  Sections: 10
```

This confirms the PE loader is working correctly. Full execution will be possible once DLL loading is implemented.

## Purpose

These test programs serve as a comprehensive test suite to verify that:
1. Windows executables can be loaded and executed correctly
2. File I/O operations work properly (create, read, write, delete, directory ops)
3. Command-line argument parsing is functional
4. Environment variable operations work correctly
5. String manipulation and CRT functions are implemented
6. Mathematical operations and floating-point handling work correctly
7. Console I/O works correctly
8. Memory allocation and management are functional
9. The Windows-on-Linux platform is working as expected
10. WinSock2 APIs function correctly (socket creation, TCP/UDP data exchange)
11. SEH runtime APIs are callable and return correct values (C test)
12. C++ exceptions using the x64 SEH unwind machinery work end-to-end (C++ test)

Most test programs validate their operations and report success (✓) or failure (✗) for each check, exiting with non-zero status on any failure. Programs like `file_io_test`, `string_test`, and `math_test` perform actual validation. Programs like `args_test` and `hello_cli` primarily demonstrate functionality by displaying output. The C++ WinSock programs (`winsock_basic_test`, `winsock_tcp_test`, `winsock_udp_test`) all perform end-to-end validation and exit with non-zero status on any failure. The SEH programs (`seh_c_test`, `seh_cpp_test`) validate the exception-handling infrastructure.
