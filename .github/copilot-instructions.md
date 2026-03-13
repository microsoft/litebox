---
model: capi-prod-claude-sonnet-4.6
---
This repository contains a Rust-based, security-focused sandboxing library OS. To maintain high code quality and consistency, please adhere to the following guidelines when contributing.

## Code Standards

### Required Before Each Commit
- Run `cargo fmt` to format all Rust files using `rustfmt`.
  - This ensures consistent code style across the codebase.

### Development Workflow
The recommended sequence during development is:
1. **Format**: `cargo fmt`
2. **Build**: `cargo build`
3. **Lint**: `RUSTFLAGS="-Dwarnings" cargo clippy --all-targets --all-features`
   - **Important**: Always run with `RUSTFLAGS="-Dwarnings"` to match the CI environment.
     The CI uses `-Dwarnings` which promotes all warnings to errors, including:
     - `clippy::items_after_statements` — `const` / `static` items must appear *before* any
       non-`const`/`let` statements in the same block. Move them to the top of the function.
     - `clippy::doc_overindented_list_items` — continuation lines of a doc-comment list item
       must be indented with exactly 2 spaces (e.g. `///   text`), not aligned to the item text.
     - `clippy::manual_let_else` — `match`/`if let` blocks that unconditionally early-return in
       one arm should be written as `let x = … else { return … };`.
     - `clippy::ptr_as_ptr` — use `.cast::<T>()` instead of `as *const T` / `as *mut T` when
       only the type changes, not the constness.
4. **Test**: `cargo nextest run`
5. **Ratchet Tests**: `cargo test -p dev_tests` - Verify ratchet constraints are met

- Full CI checks are defined in `.github/workflows/ci.yml`.

### Ratchet Tests
The repository uses "ratchet tests" in `dev_tests/src/ratchet.rs` to track and reduce usage of certain features:
- **Globals** (`static` declarations) - We aim to minimize global state
- **Transmutes** - We aim to minimize unsafe transmutes  
- **MaybeUninit** - We aim to minimize uninitialized memory usage

**Important**: If your changes add new instances of these features:
1. First, try to avoid using the feature if possible
2. If unavoidable, update the count in `dev_tests/src/ratchet.rs` for the affected module
3. Justify why the feature is necessary in your PR description

**Note**: The ratchet heuristic for globals detects lines that start with `static ` or `pub static ` (after trimming whitespace). Struct field type annotations like `pub name: &'static str` do NOT count as globals.

## Key Guidelines

1. Follow Rust best practices and idiomatic patterns.
2. Preserve the existing code structure and organization.
3. Minimize use of `unsafe` code. Every `unsafe` block **must** include a clear safety comment explaining why it's sound. Always prefer safe abstractions and code where possible.
4. Write unit tests for new functionality, especially if it affects public interfaces.
   - Extremely simple changes do not require explicit unit tests.
5. Document all public APIs and non-trivial implementation details.
6. Avoid introducing new dependencies unless strictly necessary. If a dependency is added:
   - It must be justified.
   - Prefer `default-features = false` in `Cargo.toml`.
7. Favor `no_std` compatibility wherever feasible.
   - Some crates in the workspace may use `std`, but this should be deliberate and justified.
8. **Prefer modern `let...else` syntax** over manual if-let-else patterns:
   - Prefer: `let Some(x) = opt else { return Err(...); };`
   - Avoid: `let x = if let Some(v) = opt { v } else { return Err(...); };`
   - The modern syntax is more concise and idiomatic in Rust.

## Windows on Linux Support - Development Continuation Guide

### Quick Start for New Sessions

When resuming Windows on Linux development, follow this checklist:

1. **Review Current Status**
   - Read `SESSION_SUMMARY.md` in the repository root (updated after each session)
   - Review `docs/windows_on_linux_status.md` for complete implementation status
   - Check recent commits to understand latest changes

2. **Verify Test Status**
   ```bash
   # Test Windows-specific packages (should take ~10 seconds)
   cargo test -p litebox_shim_windows -p litebox_platform_linux_for_windows -p litebox_runner_windows_on_linux_userland
   
   # Expected: 160 tests passing (105 platform + 39 shim + 16 runner)
   ```

3. **Understand Current Issues**
   - Known crash point: MinGW CRT initialization at low memory address (e.g., 0x3018)
   - Root cause: Uninitialized global variables / BSS section handling
   - See "Known Issues" section below for details

### Architecture Overview

```
Windows PE Binary (.exe)
        ↓
litebox_shim_windows (North Layer)
  - PE/DLL loader (loader/pe.rs)
  - Entry point execution (loader/execution.rs)
  - Windows syscall interface (syscalls/ntdll.rs)
  - API tracing (tracing/)
        ↓
litebox_platform_linux_for_windows (South Layer)
  - Linux syscall implementations
  - Windows API → Linux translation
  - DLL manager with stubs (kernel32.rs, msvcrt.rs)
        ↓
litebox_runner_windows_on_linux_userland
  - CLI interface (main.rs, lib.rs)
  - Integration tests (tests/)
```

### Key Files and Their Purposes

**PE Loader & Execution:**
- `litebox_shim_windows/src/loader/pe.rs` - PE parsing, section loading, relocations, imports
- `litebox_shim_windows/src/loader/execution.rs` - TEB/PEB structures, entry point calling
- `litebox_shim_windows/src/loader/dll.rs` - DLL manager and function resolution

**Platform Implementation:**
- `litebox_platform_linux_for_windows/src/lib.rs` - Main platform implementation
- `litebox_platform_linux_for_windows/src/kernel32.rs` - KERNEL32.DLL stubs
- `litebox_platform_linux_for_windows/src/msvcrt.rs` - MSVCRT.DLL implementations

**Runner:**
- `litebox_runner_windows_on_linux_userland/src/lib.rs` - Main execution flow
- `litebox_runner_windows_on_linux_userland/tests/integration.rs` - Integration tests

### Known Issues and Next Steps

**Current Blocker: CRT Initialization Crash**
- **Symptom**: Program crashes in MinGW CRT at low memory addresses (e.g., 0x3018)
- **Cause**: Uninitialized global variables, BSS section not zero-initialized
- **Location**: `litebox_shim_windows/src/loader/pe.rs::load_sections()`

**Immediate Fixes Needed:**
1. **Zero-initialize BSS sections** in `load_sections()`:
   - BSS sections have `SizeOfRawData == 0` but `VirtualSize > 0`
   - Must allocate and zero-fill virtual memory for these sections
   
2. **Validate data section initialization**:
   - Ensure all `.data` sections are properly copied from file
   - Verify relocations are applied to data sections

3. **Add debug diagnostics**:
   - Log each section being loaded with characteristics
   - Print BSS sections separately to verify they're being handled

**Testing Strategy:**
```bash
# Build test program
cd windows_test_programs
cargo build --release --target x86_64-pc-windows-gnu

# Run with runner (will crash at CRT init currently)
cd ..
cargo run -p litebox_runner_windows_on_linux_userland -- \
  windows_test_programs/target/x86_64-pc-windows-gnu/release/hello_cli.exe

# Debug with GDB (if needed)
gdb --args target/debug/litebox_runner_windows_on_linux_userland \
  windows_test_programs/target/x86_64-pc-windows-gnu/release/hello_cli.exe
```

### Implementation Phases (Historical Context)

- ✅ **Phase 1**: PE Loader foundation
- ✅ **Phase 2**: Core NTDLL APIs (file I/O, memory, console)
- ✅ **Phase 3**: API Tracing framework
- ✅ **Phase 4**: Threading & Synchronization
- ✅ **Phase 5**: Extended APIs (environment, registry, process info)
- ✅ **Phase 6**: Import resolution, DLL loading, relocations
- ✅ **Phase 7**: MSVCRT implementation, GS register setup, trampolines
- ✅ **Phase 8**: Entry point execution, TEB/PEB fixes, stack allocation
- 🚧 **Phase 9** (CURRENT): Fix BSS initialization and CRT global variable support

### Quick Reference Commands

```bash
# Format code
cargo fmt

# Build all Windows components
cargo build -p litebox_shim_windows \
            -p litebox_platform_linux_for_windows \
            -p litebox_runner_windows_on_linux_userland

# Run clippy on Windows components (with -Dwarnings to match CI)
RUSTFLAGS="-Dwarnings" cargo clippy -p litebox_shim_windows \
             -p litebox_platform_linux_for_windows \
             -p litebox_runner_windows_on_linux_userland

# Run all Windows tests
cargo test -p litebox_shim_windows \
           -p litebox_platform_linux_for_windows \
           -p litebox_runner_windows_on_linux_userland

# Build Windows test programs (requires MinGW)
cd windows_test_programs
cargo build --release --target x86_64-pc-windows-gnu

# Run a test program
cargo run -p litebox_runner_windows_on_linux_userland -- \
  windows_test_programs/target/x86_64-pc-windows-gnu/release/hello_cli.exe
```

### Common Development Patterns

**Adding a new Windows API:**
1. Define signature in `litebox_shim_windows/src/syscalls/ntdll.rs`
2. Implement in `litebox_platform_linux_for_windows/src/lib.rs` or specific module
3. Add tracing support in `litebox_shim_windows/src/tracing/wrapper.rs`
4. Update DLL manager exports if needed
5. Add unit tests in platform crate
6. Add integration test in runner's `tests/integration.rs`

**Debugging a crash:**
1. Build with debug symbols: `cargo build` (not `--release`)
2. Run under GDB: `gdb --args target/debug/litebox_runner_windows_on_linux_userland <exe>`
3. Useful GDB commands:
   - `break call_entry_point` - Break before entry point
   - `si` - Step one instruction
   - `x/16x $rsp` - Examine stack
   - `info registers` - Show all registers
   - `x/i $rip` - Show current instruction

### Session Documentation

After each development session:
1. Update `SESSION_SUMMARY.md` in repository root with:
   - What was accomplished
   - What issues were fixed
   - What remains to be done
   - Test results
2. Commit with descriptive message using `report_progress` tool
3. Update `docs/windows_on_linux_status.md` if major milestones achieved
