# Plan: macOS Dynamic Hello World on Linux Userland Runner

## Objective

Enable LiteBox to run a **dynamically linked x86_64 Mach-O Hello World** on Linux userland, building on the already-working static Mach-O path.

Success means:
1. The macOS dynamic executable starts via `dyld`.
2. Required dependent dylibs load successfully.
3. Program prints `Hello, World!` and exits with status 0 under `litebox_runner_macos_on_linux_userland`.

---

## Current State

What already works:
- Workspace contains:
  - `litebox_common_bsd`
  - `litebox_shim_bsd`
  - `litebox_runner_macos_on_linux_userland`
- Static Mach-O loading and execution path exists.
- `SYS_WRITE` and `SYS_EXIT` are implemented in the BSD shim.
- Seccomp-based syscall interception is wired through the multiplex platform.
- A static test binary exists in `litebox_runner_macos_on_linux_userland/test_binaries`.

Key gap to close:
- Dynamic Mach-O execution requires `dyld` + dylib loading and a larger syscall/loader surface than static binaries.

---

## Scope

### In scope
- Evolve the existing BSD crates to support dynamically linked x86_64 Mach-O binaries.
- Add loader metadata and runtime behavior needed for `dyld`-first startup.
- Add enough BSD syscall handling for dynamic Hello World to complete.
- Add reproducible validation artifacts/commands for dynamic Hello World.

### Out of scope (for this phase)
- Full macOS syscall coverage.
- Full Objective-C/Cocoa runtime support.
- Universal binary / arm64 Mach-O support.
- Kernel-mode or non-userland platform changes.

---

## Design Direction

Adopt the same high-level model LiteBox already uses for Linux ELF dynamic binaries:
- Parse executable metadata to discover the runtime linker.
- Load main image first, then load runtime linker image.
- Transfer control to linker entry point.
- Keep seccomp interception as the syscall capture mechanism.

For Mach-O, this means:
- Main executable and `dyld` are both guest images.
- `dyld` performs relocation/binding for dependent dylibs.
- LiteBox provides enough memory mapping + syscall + filesystem behavior for `dyld` and the test program to run.

---

## Workstreams

## 1) Mach-O Parse/Load Extensions (`litebox_common_bsd`)

### Goals
- Extend loader metadata beyond static-only fields so dynamic launch decisions can be made.

### Deliverables
- Parse and expose dynamic-link-relevant load commands:
  - `LC_LOAD_DYLINKER` path
  - Required dylib commands (`LC_LOAD_DYLIB`, etc.) for diagnostics/validation
  - Entry point details (`LC_MAIN` and fallback behavior)
- Add parsed output type(s) capturing:
  - Main image segments
  - Preferred load behavior (fixed vs slide-aware where needed)
  - Runtime linker path
- Tighten parser error taxonomy for malformed/unsupported dynamic binaries.

### Notes
- Keep parser `no_std` and avoid new dependencies unless strictly necessary.
- Maintain compatibility with existing static path.

---

## 2) Dynamic Program Loader Flow (`litebox_shim_bsd`)

### Goals
- Introduce a two-image startup model: main Mach-O + runtime linker Mach-O.

### Deliverables
- New load path in shim loader module that:
  1. Loads main image.
  2. Resolves and loads linker image (`dyld`) from guest-visible filesystem path.
  3. Sets process entrypoint to linker entrypoint (not main image entrypoint).
- Stack/setup updates required for dynamic launch compatibility.
- Keep existing static flow as fallback when no dynamic linker is specified.

### Notes
- Reuse Linux shim architecture patterns where applicable (`litebox_shim_linux/src/loader/elf.rs`).
- Keep page mapping through existing `PageManager` APIs.

---

## 3) Guest Filesystem Inputs for dyld + dylibs

### Goals
- Ensure runtime linker and dependent libraries are visible to the guest process.

### Deliverables
- Runner-side mechanism to provide dynamic runtime files (expected minimal option for this phase):
  - deterministic rootfs/tar input containing executable + `dyld` + required dylibs
- Path resolution behavior documented (e.g., where `LC_LOAD_DYLINKER` and dylib paths resolve from).
- Clear startup errors when required runtime files are missing.

### Notes
- Favor reusing existing LiteBox FS layers and patterns from Linux runner.
- Keep this minimal: just enough to run dynamic Hello World.

---

## 4) BSD Syscall Surface Expansion (minimum viable for dynamic Hello)

### Goals
- Implement the syscall subset required by `dyld` and Hello World runtime.

### Deliverables
- Add syscall numbers/constants needed for dynamic path in `litebox_common_bsd::syscall_nr`.
- Implement corresponding handlers in `litebox_shim_bsd`.
- Improve unknown-syscall diagnostics (debug logging/tracing) to support iterative bring-up.

### Expected workflow
1. Run dynamic binary.
2. Capture first failing syscall.
3. Implement syscall with minimal correct semantics.
4. Repeat until Hello World succeeds.

### Notes
- Prioritize correctness over breadth.
- Return accurate errno-style failures for unimplemented edge cases.

---

## 5) Validation Assets and Developer Workflow

### Goals
- Make dynamic Hello World bring-up reproducible.

### Deliverables
- Add/adjust test binaries tooling in `litebox_runner_macos_on_linux_userland/test_binaries` for dynamic sample generation.
- Add a documented run path for dynamic sample (build + run commands).
- Add at least one automated smoke test where feasible (or scripted manual check if test harness limitations apply).

### Build/quality gates
- `cargo fmt`
- `cargo build -p litebox_runner_macos_on_linux_userland`
- `cargo clippy --all-targets --all-features`
- Targeted runner invocation for dynamic sample

---

## Milestones

### M1: Dynamic metadata plumbing
- Mach-O parser exposes linker path and dynamic metadata.
- Shim can distinguish static vs dynamic executable.

### M2: dyld launch handoff
- Shim loads `dyld` and transfers control to linker entry.
- Process reaches early `dyld` execution before first unsupported syscall failure.

### M3: Runtime syscall completeness for Hello World
- Required syscall subset implemented.
- Dynamic Hello World prints expected output.

### M4: Stabilization
- Error messages and docs are clear.
- Formatting/lint/build checks pass for touched crates.

---

## Primary Code Areas

- `litebox_common_bsd/src/loader.rs`
- `litebox_common_bsd/src/syscall_nr.rs`
- `litebox_shim_bsd/src/lib.rs`
- `litebox_shim_bsd/src/loader/mod.rs`
- `litebox_runner_macos_on_linux_userland/src/lib.rs`
- `litebox_runner_macos_on_linux_userland/test_binaries/Makefile`

Reference patterns to mirror:
- `litebox_common_linux/src/loader.rs` (dynamic interpreter model)
- `litebox_shim_linux/src/loader/elf.rs` (main + interpreter loading flow)
- `litebox_runner_linux_userland/src/lib.rs` (filesystem/runtime bootstrapping patterns)

---

## Risks and Mitigations

1. **dyld behavior needs more ABI details than current stack/setup provides**
   - Mitigation: stage bring-up with explicit diagnostics at handoff boundary.

2. **Dynamic runtime needs files not present in minimal environment**
   - Mitigation: define deterministic runtime bundle input and fail fast on missing paths.

3. **Syscall surface growth may sprawl**
   - Mitigation: strict “dynamic Hello World first” syscall prioritization and trace-driven implementation.

4. **Address mapping collisions for additional images**
   - Mitigation: reuse proven page-mapping patterns and add explicit mapping failure diagnostics.

---

## Definition of Done

The plan is complete when all are true:
1. `cargo build -p litebox_runner_macos_on_linux_userland` succeeds.
2. Runner can launch a **dynamically linked** x86_64 Mach-O Hello World under Linux userland.
3. Program prints `Hello, World!` and exits with status 0.
4. The dynamic startup path (runtime linker + dylib inputs) is documented and reproducible.
5. Static path remains functional.
