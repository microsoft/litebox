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

### 7. No timer delays or polling to mask product bugs
Product code issues must be fixed in the product code. Tests must never
use `sleep`, `tokio::time::sleep`, retry loops, or polling intervals to
work around race conditions or coordination bugs. If a test needs
synchronization, use explicit protocol-level signals (e.g., a response
that confirms readiness).

### 8. Fix failing minimal tests before investigating further
When a minimal test fails, fix it before moving on to additional issues.
A failing minimal test is the highest-priority signal — it identifies
a concrete product bug with a clear reproduction. Do not defer it to
investigate broader or more complex failures.

### 9. Never remove failing tests for convenience
Failing minimal tests must not be deleted, commented out, or converted
to xfail simply because they are inconvenient. If a test is failing, the
product code must be fixed. The only valid reason to mark a test as xfail
is a known platform limitation that cannot currently be resolved, with a
documented reason.

### 10. Cover all configurations before changing product code
Before fixing a product code bug, write minimal tests that cover all
relevant configurations of the affected code path. For example, a pipe
relay fix must have tests for init→child, child→grandchild, and any
other topology that exercises the code. This ensures the fix is correct
for all cases, not just the one that was initially observed.

## Workflow

The correct sequence for fixing a bug is:

1. **Write the test** that demonstrates the desired behavior
2. **Watch it fail** (confirming the bug exists and the test catches it)
3. **Fix the product code**
4. **Watch the test pass** (confirming the fix is correct)
5. **Verify no regressions** (all other tests still pass)

Never fix product code without a failing test first. Never skip step 2 —
if the test doesn't fail before the fix, it doesn't prove the fix works.

## Debugging strategy

When a test fails and the root cause is unclear, follow this order:

### 11. Isolate layers with bypass tests
Write a test that bypasses intermediate layers (e.g., the agent protocol)
to determine WHICH layer has the bug. For example, `stress-exec` runs
fork+exec directly from a single process, proving litebox's fork/exec
works and the bug is in the mux relay. This avoids spending time
analyzing the wrong layer.

### 12. Vary one axis at a time
Write focused tests that change only one variable:
- Fresh agent vs used agent (isolates accumulated state)
- Same agent vs sibling agent (isolates parent-level corruption)
- PIE-only vs non-PIE-only vs mixed (isolates exec path)
- 1 exec vs 30 execs (isolates resource leaks)

Each test should have a clear hypothesis: "if this passes but that
fails, the bug is in X."

### 13. Check accumulating data structures for cleanup
When investigating state corruption, grep for data structures that
grow without bound. Look for `.push()` without corresponding
`.remove()`, `.retain()`, or `.clear()`. Accumulating lists of IDs,
handles, or references are a common source of stale-entry bugs,
especially when IDs can be reused (pointer addresses, fd numbers,
recycling pools).

### 14. Check handle identity mechanisms
When investigating misrouted data, verify how handles/IDs are
generated. Compare against codebase conventions:
- Monotonic counters (like `DescriptorObjectId`) — safe
- Pointer addresses (`Arc::as_ptr()`) — vulnerable to reuse after free
- Recycling pools (`IdPool`) — require caller validation

If a handle uses pointer identity, verify that all tracking structures
(like `mux_pipe_pair_ids`) are cleaned up when the handle is freed.

### 15. Check cleanup ordering for concurrent resources
When investigating data loss, verify that resources used by background
threads are not cleaned up before those threads finish. For example,
if a bridge thread writes to a pipe and the parent calls `exit_group`,
the pipe must stay open until the bridge finishes. Look for
`detach`/`move to background` patterns that skip `join()`.

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
