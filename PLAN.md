# Plan: macOS-on-Linux Userland Runner

## Context

LiteBox currently runs Linux ELF binaries on Linux by intercepting syscalls and emulating them. The goal is to add parallel support for running **static x86_64 Mach-O binaries** (macOS format) on Linux, following the same crate structure. A Hello World binary is the initial test target.

No changes to existing crates. The new crates use LiteBox's existing `PageManager`, `LiteBox` (for the filesystem/fd subsystem), and the existing seccomp interception mechanism ΓÇö exactly how the Linux shim works.

---

## Scope

- Three new crates: `litebox_common_bsd`, `litebox_shim_bsd`, `litebox_runner_macos_on_linux_userland`
- Workspace `Cargo.toml` updated to include them
- No changes to any existing crate

---

## New Crates

### 1. `litebox_common_bsd` (analogous to `litebox_common_linux`)

Mach-O parsing/loading and macOS-specific type definitions.

**`Cargo.toml`**
```toml
[package]
name = "litebox_common_bsd"
version = "0.1.0"
edition = "2024"

[dependencies]
litebox = { path = "../litebox", version = "0.1.0" }
object = { version = "0.36", default-features = false, features = ["macho", "read_core"] }
thiserror = { version = "2.0", default-features = false }
zerocopy = { version = "0.8", default-features = false, features = ["derive"] }

[lints]
workspace = true
```

**`src/lib.rs`** ΓÇö pub re-exports `loader` and `syscall_nr` modules.

**`src/syscall_nr.rs`** ΓÇö macOS syscall numbers:
```rust
pub const SYSCALL_CLASS_UNIX: u64 = 0x2000000;
pub const SYS_EXIT:  u64 = SYSCALL_CLASS_UNIX | 1;
pub const SYS_WRITE: u64 = SYSCALL_CLASS_UNIX | 4;
```

**`src/loader.rs`** ΓÇö Mach-O parser and loader:

Key types:
```rust
/// Result of parsing a Mach-O file header + load commands
pub struct MachoParsedFile {
    entry_point: u64,         // from LC_MAIN or LC_UNIXTHREAD
    segments: Vec<SegmentInfo>,
}

struct SegmentInfo {
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    initprot: u32,  // VM_PROT_* bits
}

/// Result after all segments are mapped
pub struct MappingInfo {
    pub entry_point: usize,
    pub brk: usize,   // top of highest mapped segment
}

/// Trait: read bytes at a file offset (implemented by caller)
pub trait ReadAt {
    type Error;
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Self::Error>;
}

/// Trait: map memory (implemented by the shim using PageManager)
pub trait MapMemory {
    type Error;
    /// Map zero'd R/W pages at fixed addr, size page-aligned
    fn map_anon(&mut self, addr: usize, len: usize) -> Result<*mut u8, Self::Error>;
    /// Map R+X pages at fixed addr, initialized with data
    fn map_exec(&mut self, addr: usize, len: usize, data: &[u8]) -> Result<(), Self::Error>;
    /// Map R/W pages at fixed addr, initialized with data
    fn map_data(&mut self, addr: usize, len: usize, data: &[u8]) -> Result<(), Self::Error>;
}
```

`MachoParsedFile::parse(data: &[u8])` ΓÇö uses `object::macho::MachHeader64` to iterate load commands, collecting `LC_SEGMENT_64` entries and entry point from `LC_MAIN` (sets `entryoff` relative to `__TEXT` vmaddr) or `LC_UNIXTHREAD` (x86_64 thread state `rip`).

`MachoParsedFile::load(reader, mapper)` ΓÇö iterates segments, uses initprot to determine page type, maps each segment using `mapper`.

---

### 2. `litebox_shim_bsd` (analogous to `litebox_shim_linux`)

**`Cargo.toml`**
```toml
[package]
name = "litebox_shim_bsd"
version = "0.1.0"
edition = "2024"

[dependencies]
litebox = { path = "../litebox", version = "0.1.0" }
litebox_common_linux = { path = "../litebox_common_linux", version = "0.1.0" }
litebox_common_bsd = { path = "../litebox_common_bsd", version = "0.1.0" }
litebox_platform_multiplex = { path = "../litebox_platform_multiplex", version = "0.1.0", default-features = false }
thiserror = { version = "2.0", default-features = false }

[features]
default = ["platform_linux_userland"]
platform_linux_userland = [
    "litebox_platform_multiplex/platform_linux_userland_with_linux_syscall",
    "litebox_platform_multiplex/systrap_backend",
]

[lints]
workspace = true
```

**`src/lib.rs`** ΓÇö Core shim structure:

```rust
#![no_std]
extern crate alloc;

use litebox::{LiteBox, mm::PageManager, shim::ContinueOperation};
use litebox_common_linux::PtRegs;
use litebox_platform_multiplex::Platform;

/// Shim entry points ΓÇö one per guest task
pub struct BsdShimEntrypoints {
    task: Task,
    _not_send: core::marker::PhantomData<*const ()>,
}

impl litebox::shim::EnterShim for BsdShimEntrypoints {
    type ExecutionContext = PtRegs;

    fn init(&self, ctx: &mut PtRegs) -> ContinueOperation {
        // Set instruction pointer and stack pointer from loaded values
        ctx.rip = self.task.entry_point as u64;
        ctx.rsp = self.task.stack_top as u64;
        ContinueOperation::Resume
    }

    fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        self.task.handle_syscall(ctx)
    }

    fn exception(&self, _ctx: &mut PtRegs, _: &litebox::shim::ExceptionInfo) -> ContinueOperation {
        ContinueOperation::Terminate
    }

    fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
        ContinueOperation::Resume
    }
}

struct GlobalState {
    pm: PageManager<Platform, { litebox::mm::linux::PAGE_SIZE }>,
    fs: litebox::fs::devices::FileSystem<Platform>,  // provides /dev/stdin, stdout, stderr
    litebox: LiteBox<Platform>,
}

struct Task {
    global: alloc::sync::Arc<GlobalState>,
    entry_point: usize,
    stack_top: usize,
}

impl Task {
    fn handle_syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
        let nr = ctx.rax;  // macOS: syscall nr in rax
        match nr {
            litebox_common_bsd::syscall_nr::SYS_WRITE => {
                let fd = ctx.rdi as i32;
                let ptr = ctx.rsi as usize;
                let count = ctx.rdx as usize;
                let result = self.do_write(fd, ptr, count);
                ctx.rax = result as u64;
                ContinueOperation::Resume
            }
            litebox_common_bsd::syscall_nr::SYS_EXIT => {
                ContinueOperation::Terminate
            }
            _ => {
                ctx.rax = (-38i64) as u64;  // -ENOSYS
                ContinueOperation::Resume
            }
        }
    }

    fn do_write(&self, fd: i32, ptr: usize, count: usize) -> isize {
        // Read bytes from guest memory, write to LiteBox fs device
        // Uses RawConstPointer to safely read guest memory, then fs.write()
        ...
    }
}

pub struct BsdShim(alloc::sync::Arc<GlobalState>);

pub struct LoadedProgram {
    pub entrypoints: BsdShimEntrypoints,
}

impl BsdShim {
    pub fn load_program(
        &self,
        binary_data: &[u8],
        argv: alloc::vec::Vec<alloc::ffi::CString>,
        envp: alloc::vec::Vec<alloc::ffi::CString>,
    ) -> Result<LoadedProgram, LoadError> { ... }
}

pub struct BsdShimBuilder;
impl BsdShimBuilder {
    pub fn new() -> Self { ... }
    pub fn build(self) -> BsdShim { ... }
}
```

**`src/loader/mod.rs`** ΓÇö Mach-O loader using `PageManager`:

Implements `litebox_common_bsd::loader::MapMemory` using `PageManager`:
- `map_anon` ΓåÆ `pm.create_writable_pages(fixed_addr, len, CreatePagesFlags::FIXED_ADDR, |_| Ok(0))`
- `map_exec` ΓåÆ `pm.create_executable_pages(fixed_addr, len, CreatePagesFlags::FIXED_ADDR, |ptr| { copy data; Ok(0) })`
- `map_data` ΓåÆ `pm.create_writable_pages(fixed_addr, len, CreatePagesFlags::FIXED_ADDR, |ptr| { copy data; Ok(0) })`

Stack setup:
- `pm.create_stack_pages(None, 8MB, CreatePagesFlags::empty())` ΓåÆ `stack_top`
- Push strings and pointers using the same `UserStack`-style approach from `litebox_shim_linux/src/loader/stack.rs`, but without auxv

**`src/loader/stack.rs`** ΓÇö `MacOSStack` ΓÇö identical structure to `litebox_shim_linux/src/loader/stack.rs` but without the auxv section (macOS stack: argc, argv ptrs, NULL, envp ptrs, NULL, strings).

---

### 3. `litebox_runner_macos_on_linux_userland`

**`Cargo.toml`**
```toml
[package]
name = "litebox_runner_macos_on_linux_userland"
version = "0.1.0"
edition = "2024"

[dependencies]
anyhow = "1.0"
clap = { version = "4.5", features = ["derive"] }
litebox_common_linux = { path = "../litebox_common_linux", version = "0.1.0" }
litebox_platform_linux_userland = { path = "../litebox_platform_linux_userland", version = "0.1.0" }
litebox_platform_multiplex = { path = "../litebox_platform_multiplex", version = "0.1.0", default-features = false, features = ["platform_linux_userland", "systrap_backend"] }
litebox_shim_bsd = { path = "../litebox_shim_bsd", version = "0.1.0" }
memmap2 = "0.9"

[lints]
workspace = true
```

**`src/main.rs`** ΓÇö `fn main() -> anyhow::Result<()> { run(CliArgs::parse()) }`

**`src/lib.rs`** ΓÇö `run()`:
1. mmap the binary file ΓåÆ `&[u8]`
2. `let platform = LinuxUserland::new(None)` ΓåÆ `&'static LinuxUserland`
3. `litebox_platform_multiplex::set_platform(platform)`
4. `BsdShimBuilder::new().build()` ΓåÆ `BsdShim`
5. Build argv/envp as `Vec<CString>`
6. `shim.load_program(&binary_data, argv, envp)` ΓåÆ `LoadedProgram`
7. `platform.enable_seccomp_based_syscall_interception()` ΓåÉ must be after all host setup
8. `unsafe { litebox_platform_linux_userland::run_thread(program.entrypoints, &mut PtRegs::default()) }`
9. `std::process::exit(0)` (Hello World exit code)

---

## Workspace `Cargo.toml` Changes

Add to `members` and `default-members`:
```toml
"litebox_common_bsd",
"litebox_shim_bsd",
"litebox_runner_macos_on_linux_userland",
```

---

## Key Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Memory management | `litebox::mm::PageManager` directly | Same as Linux shim; no new platform APIs needed |
| I/O for write syscall | `litebox::fs::devices::FileSystem` + `LiteBox` fd table | Same mechanism as Linux shim's stdio; routes through `/dev/stdout` |
| Mach-O parsing | `object` crate (v0.36.7, already in workspace) | `object::macho` provides `MachHeader64`, load command iterator |
| Syscall interception | seccomp SIGSYS ΓÇö existing `systrap_backend` mechanism | Mach-O is not ELF; binary rewriter doesn't apply; seccomp intercepts all `syscall` insts |
| `ExecutionContext` | `litebox_common_linux::PtRegs` | Required by `run_thread` signature; cannot define a separate type |
| Stack layout | macOS ABI: argc, argv[], NULL, envp[], NULL, strings ΓÇö no auxv | macOS has no auxv; mirrors `UserStack` from Linux shim minus auxv section |
| Entry point detection | LC_MAIN preferred, LC_UNIXTHREAD fallback | Static Hello World typically uses LC_UNIXTHREAD; modern binaries use LC_MAIN |
| No changes to existing crates | All new code is in new crates | Platform remains unchanged; uses LiteBox APIs as-is |

---

## Critical Files to Reference During Implementation

| File | Purpose |
|---|---|
| `litebox/src/mm/mod.rs:124,164,270` | `create_executable_pages`, `create_writable_pages`, `create_stack_pages` |
| `litebox/src/mm/linux.rs` | `CreatePagesFlags`, `NonZeroPageSize`, `NonZeroAddress` |
| `litebox_common_linux/src/loader.rs` | `ReadAt`/`MapMemory`/`ElfParsedFile` patterns to mirror |
| `litebox_shim_linux/src/lib.rs:78-298` | `EnterShim` impl, builder, `load_program`, `LoadedProgram` |
| `litebox_shim_linux/src/loader/elf.rs` | How the ELF loader wraps the file and implements mapper traits |
| `litebox_shim_linux/src/loader/stack.rs` | `UserStack` push-in-reverse approach (adapt without auxv) |
| `litebox_shim_linux/src/loader/mod.rs` | `DEFAULT_STACK_SIZE`, `DEFAULT_LOW_ADDR` constants |
| `litebox_runner_linux_userland/src/lib.rs` | Platform init order, seccomp enable placement, `run_thread` call |
| `litebox_shim_linux/src/lib.rs:344-369` | `initialize_stdio_in_shared_descriptors_table` ΓÇö LiteBox fd setup for I/O |

---

## Verification

1. Build: `cargo build -p litebox_runner_macos_on_linux_userland`
2. Obtain a static x86_64 Mach-O Hello World (can cross-compile or use pre-built)
3. Run: `./target/debug/litebox_runner_macos_on_linux_userland ./hello_world`
4. Expected: `Hello, World!` on stdout, exit code 0
