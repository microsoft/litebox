# Test Suite Principles & Enforcement

## Principles

Future tests in litebox_test_harness must follow these rules:

### 1. Minimal test cases use protocol commands, not bash
Tests should use the agent's protocol commands (FsRead, FsWrite, NetListen,
NetConnect, UnixSocketTest, UnixSocketRelay, Exec with self_exe subcommands)
rather than `bash -c "..."`. Bash is only justified when testing bash-specific
fork behavior (X6-X25 shell patterns).

### 2. Self-contained rootfs
`cargo test --test integration` must pass without any manually-prepared rootfs.
The integration test builds its own rootfs programmatically. Any new test
dependency (binary, library, config file) must be added to `build_rootfs()`
in `tests/integration.rs`.

### 3. No python3 or other interpreters
All test logic is in Rust. If a test needs a server/client pattern, add a
subcommand to the test binary (main.rs) rather than invoking an interpreter.

### 4. Complete axis coverage
When adding a new capability test (e.g., Unix sockets), test all relevant
axes of the process tree:
- In-process (same agent)
- Parent → child (agent forks child)
- Child → parent (reverse direction)
- Sibling → sibling (if applicable, xfail if known limitation)
- At depth 2+ (nested workers)

### 5. xfail must have a reason and track a real issue
Every `record_xfail()` call must include a reason string explaining the
limitation. When the limitation is fixed, the test becomes XPASS and forces
the expectation to be updated.

### 6. VS Code concerns → minimal tests first
Before adding a VS Code-specific test (V-series, bash, needs code-server),
check whether the underlying platform capability can be tested minimally
(F/N/X/U-series). Add the minimal test first, then the VS Code-specific
one if needed.

## Enforcement

### Compile-time: `#[cfg(test)]` lint in integration test
The integration test verifies:
- All tests produce results (no silent skips)
- 0 FAIL, 0 XPASS
- Known xfail count matches expected (catches accidental xfail additions)

### CI: `cargo test -p litebox_test_harness --test integration`
This runs the full suite with a programmatic rootfs. Any new test that
breaks self-containment (e.g., requires python3 in rootfs) will fail CI.

### Code review checklist (for humans/AI)
When adding tests, verify:
- [ ] Uses protocol commands, not bash (unless testing bash behavior)
- [ ] No new interpreter dependencies (python3, ruby, etc.)
- [ ] Tests both directions if applicable (parent↔child)
- [ ] Added to `build_rootfs()` if new binary/file needed
- [ ] xfail has a reason string
- [ ] VS Code concern has a corresponding minimal test
