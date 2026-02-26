# Plan: BSD/macOS Syscall Expansion for Running Real Programs

## Objective

Move from assembly-only smoke tests to **real macOS user programs** (initially simple Zig-built binaries), by substantially expanding BSD/macOS syscall support in the BSD path.

Success means:
1. A dynamically linked x86_64 Mach-O program built with Zig can start under `litebox_runner_macos_on_linux_userland`.
2. Program executes meaningful libc/runtime behavior (not just direct `write`/`exit`) and exits cleanly.

---

## Current Baseline (Already Achieved)

- Dynamic two-image startup path exists (main image + runtime linker handoff).
- Runtime linker file injection is supported by the macOS-on-linux runner (`--runtime-file`).
- Static and dynamic assembly samples run via:
  - `make test-static`
  - `make test-dynamic`
- Early syscall diagnostics are present for unknown macOS syscall numbers.

Primary remaining gap:
- Syscall surface is still too small for real user programs and libc/runtime startup paths.

---

## Scope

### In scope
- Expand syscall constants + handlers on the BSD/macOS path.
- Improve argument decoding, errno behavior, and syscall diagnostics.
- Add Zig-based real-program test assets and reproducible invocation flow.
- Add gdb-based debugging workflow for syscall/entry faults.

### Explicitly out of scope
- Any edits to Linux/common Linux/shim Linux/platform crates beyond referencing them.
- Any edits to `litebox` crate itself.
- Full macOS parity (kernel APIs, Objective-C runtime, GUI stacks, arm64 Mach-O).
- Platform changes.

---

## Design Principles for This Phase

1. **BSD-first implementation**
   - Implement in:
     - `litebox_common_bsd`
     - `litebox_shim_bsd`
     - `litebox_runner_macos_on_linux_userland`
   - Linux path is reference-only; do not modify it.

2. **Trace-driven syscall bring-up**
   - Run target binary.
   - Record first failing syscall and call-site context.
   - Implement minimal correct semantics.
   - Repeat until program works.

3. **Correctness over breadth**
   - Prefer a smaller set of accurate syscalls over broad stubs.
   - Return macOS-appropriate negative errno values for unsupported edges.

4. **Debuggability first**
   - Add actionable logs for unimplemented and malformed syscall invocations.
   - Use gdb routinely to inspect RIP/RSP/register state at crashes.

---

## Workstreams

## 1) Syscall Inventory and Prioritization (`litebox_common_bsd` + `litebox_shim_bsd`)

### Goals
- Identify the real syscall set required by Zig-built test programs and startup runtime.

### Deliverables
- Prioritized syscall matrix with status: `missing` / `partial` / `implemented` / `validated`.
- Initial target set likely to include (exact list validated by traces):
  - file I/O (`open`, `open_nocancel`, `read`, `pread`, `close`, `fcntl`, `ioctl`)
  - memory (`mmap`, `munmap`, `mprotect`)
  - process/thread basics (`getpid`, `issetugid`, `csops`-style probes if encountered)
  - metadata/time (`fstat`, `stat64`-like variants, `gettimeofday`, `clock_gettime` variants)
  - signal/tls/runtime glue as required by observed startup path.
- Expanded constant coverage in `litebox_common_bsd/src/syscall_nr.rs`.

### Notes
- Linux shim syscall organization is a reference for structure and error mapping style only.

---

## 2) BSD Shim Syscall Handler Expansion (`litebox_shim_bsd/src/lib.rs` + modules)

### Goals
- Add practical syscall implementations needed for libc/runtime and simple CLI programs.

### Deliverables
- Structured syscall dispatch (group related syscalls into helper modules where needed).
- Implemented handlers with:
  - guest pointer validation,
  - correct return conventions,
  - consistent errno mapping,
  - deterministic behavior for unsupported flags/options.
- Improved diagnostics:
  - syscall number + key args in debug logs,
  - one-line failure reason for unsupported semantics.

### Notes
- Keep behavior minimal but real (avoid fake success when state changes are required).

---

## 3) Runtime Filesystem and Path Behavior (`litebox_runner_macos_on_linux_userland`)

### Goals
- Make real-program runtime inputs manageable and repeatable.

### Deliverables
- Runner-side conventions for runtime artifacts:
  - executable,
  - runtime linker (`dyld`),
  - required dylibs.
- Clear docs/examples for `--runtime-file` mapping strategy.
- Helpful startup failures for missing runtime paths.

### Notes
- Keep this lightweight for now (no large packaging framework unless needed).

---

## 4) Zig-Based Validation Assets (`test_binaries`)

### Goals
- Validate with realistic binaries compiled from C/Zig source instead of hand-written assembly.

### Deliverables
- Add Zig-oriented test assets in `litebox_runner_macos_on_linux_userland/test_binaries`:
  - at least one simple dynamically linked program,
  - at least one program exercising file + memory + metadata syscalls.
- Extend Makefile targets, e.g.:
  - `build-zig-samples`
  - `test-zig-basic`
  - `test-zig-io`
- Document expected toolchain invocation (host Zig cross-compiling to x86_64 macOS target).

### Notes
- Keep assembly tests as quick smoke checks; Zig tests become the primary integration signal.

---

## 5) gdb-Centric Debug Workflow and Documentation

### Goals
- Standardize failure triage for crashes and syscall bring-up.

### Deliverables
- Debug playbook section in plan/docs with command patterns:
  - run runner under gdb,
  - capture `bt`, `info registers`, disassembly around RIP,
  - correlate traps with shim syscall logs.
- Suggested workflow:
  1. Reproduce with smallest Zig binary.
  2. Gather syscall trace / unknown syscall logs.
  3. If crash: use gdb to identify faulting address/register contract mismatch.
  4. Implement/fix syscall or ABI setup.
  5. Re-run targeted test and then broader sample set.

---

## Milestones

### M1: Syscall baseline map complete
- First-pass syscall inventory from Zig samples exists.
- Prioritized implementation order is documented.

### M2: Runtime startup syscall minimum
- libc/runtime initialization path reaches `main` for Zig basic sample.
- No crash before first meaningful user code.

### M3: Real program functionality
- Zig basic + I/O sample both complete successfully under runner.
- Failures produce actionable logs rather than silent faults.

### M4: Stabilization and polish
- Static + dynamic assembly tests still pass.
- Zig tests are reproducible.
- Build/lint checks for touched crates pass.

---

## Primary Code Areas (Next Stage)

- `litebox_common_bsd/src/syscall_nr.rs`
- `litebox_shim_bsd/src/lib.rs`
- `litebox_shim_bsd/src/loader/mod.rs` (if ABI setup updates are needed)
- `litebox_runner_macos_on_linux_userland/src/lib.rs`
- `litebox_runner_macos_on_linux_userland/test_binaries/Makefile`
- `litebox_runner_macos_on_linux_userland/test_binaries/*` (new Zig test assets)

Reference-only (do not modify):
- `litebox_common_linux/src/loader.rs`
- `litebox_shim_linux/src/loader/elf.rs`
- `litebox_runner_linux_userland/src/lib.rs`

---

## Risks and Mitigations

1. **Syscall growth becomes unbounded**
   - Mitigation: strict Zig-test-driven prioritization; defer rare/sysadmin APIs.

2. **ABI mismatches cause hard crashes**
   - Mitigation: mandatory gdb triage for segfaults and explicit register-state checks.

3. **Errno/flag semantics drift from macOS expectations**
   - Mitigation: centralize errno mapping and add targeted negative tests.

4. **Runtime file layout complexity**
   - Mitigation: keep deterministic `--runtime-file` conventions and fail-fast diagnostics.

---

## Build / Validation Gates

- `cargo fmt`
- `cargo build -p litebox_runner_macos_on_linux_userland`
- `cargo clippy --all-targets --all-features` (workspace-level as needed)
- `make test-static`
- `make test-dynamic`
- Zig-based tests (`make test-zig-*` targets once added)

---

## Definition of Done (This Next Stage)

This stage is complete when all are true:
1. At least two real Zig-built macOS binaries (non-assembly) run successfully under `litebox_runner_macos_on_linux_userland`.
2. Required syscall subset is implemented on BSD path with clear diagnostics for remaining gaps.
3. Crash triage workflow using gdb is documented and proven on at least one failure case.
4. Static and dynamic assembly smoke tests remain green.
5. No Linux/common Linux/platform/litebox crates were modified for this stage.
