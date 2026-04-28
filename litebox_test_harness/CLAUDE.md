# Testing Rules for litebox_test_harness

These rules are mandatory when adding, modifying, or reviewing tests.

## Test Categories

**Self-contained tests** depend only on bash and the test harness binaries.
These are preferred. They run everywhere: WSL2 chroot, litebox, CI.

**Integration tests** require external binaries like Node.js or VS Code.
These are acceptable but always secondary — add a self-contained test
for the underlying platform capability first.

## WSL2 Gold Standard

The native baseline (chroot into rootfs on real Linux) is the gold standard.
Every test must pass there — **0 FAIL, 0 xfail** on native.

- `tests/integration.rs` runs native baseline via `unshare --root`
- Any native failure is a **test bug**, not a litebox bug
- The rootfs is built programmatically by `build_rootfs()` — no manual setup

Litebox xfails are only for **dynamically detected** platform limitations
(e.g., symlink probe returns ENOTSUP). Never use static/hardcoded xfails.

## Principles

### Writing Tests

1. **Self-contained over integration** — prefer tests that need only
   bash + test harness. Before adding a node/VS Code-dependent test,
   add an equivalent self-contained test for the underlying capability.

2. **Minimal test cases use protocol commands, not bash** — use FsRead,
   FsWrite, NetListen, Exec with self_exe subcommands. Bash is only
   justified when testing bash-specific fork behavior.

3. **No silent failures** — missing dependencies must cause loud FAIL
   with a clear error message, never a silent skip.

4. **Matrix coverage** — test all configurations via cross-product loops.
   When adding a capability test, cover all relevant axes:
   - In-process (same agent)
   - Parent → child (agent forks child)
   - Child → parent (reverse direction)
   - Sibling → sibling (if applicable)
   - At depth 2+ (nested workers)

5. **No timer delays** — never use sleep/retry loops to mask product bugs.
   Use protocol-level signals for synchronization.

6. **Self-contained rootfs** — `cargo test --test integration` must pass
   without manual rootfs setup. Add new deps to `build_rootfs()`.

7. **No python3 or other interpreters** — all test logic is in Rust.
   If a test needs a server/client pattern, add a subcommand to the
   test binary (main.rs) rather than invoking an interpreter.

8. **xfail must have a reason and track a real issue** — every
   `record_xfail()` call must include a reason string. When the
   limitation is fixed, the test becomes XPASS and forces the
   expectation to be updated.

### Fixing Bugs

9. **Fix failing minimal tests before investigating further** — a failing
   minimal test is the highest-priority signal. It identifies a concrete
   product bug with a clear reproduction. Do not defer it.

10. **Never remove failing tests for convenience** — failing tests must
    not be deleted, commented out, or converted to xfail simply because
    they are inconvenient. The product code must be fixed. The only valid
    xfail reason is a known platform limitation with a documented reason.

11. **Cover all configurations before changing product code** — before
    fixing a bug, write minimal tests covering all relevant configurations
    (e.g., init→child, child→grandchild). This ensures the fix works for
    all cases, not just the one initially observed.

12. **Fix-first workflow:**
    1. Write the test that demonstrates the desired behavior
    2. Watch it fail (confirming the bug exists)
    3. Fix the product code
    4. Watch the test pass (confirming the fix is correct)
    5. Verify no regressions (all other tests still pass)

    Never fix product code without a failing test first.

## Debugging Strategy

When a test fails and the root cause is unclear:

13. **Isolate layers with bypass tests** — write a test that bypasses
    intermediate layers (e.g., the agent protocol) to determine WHICH
    layer has the bug. For example, `stress-exec` runs fork+exec
    directly, proving litebox's fork/exec works and the bug is elsewhere.

14. **Vary one axis at a time** — write focused tests that change only
    one variable:
    - Fresh agent vs used agent (isolates accumulated state)
    - Same agent vs sibling agent (isolates parent-level corruption)
    - PIE-only vs non-PIE-only vs mixed (isolates exec path)
    - 1 exec vs 30 execs (isolates resource leaks)

    Each test should have a clear hypothesis: "if this passes but that
    fails, the bug is in X."

15. **Check accumulating data structures** — grep for `.push()` without
    corresponding `.remove()`, `.retain()`, or `.clear()`. Accumulating
    lists of IDs/handles are a common source of stale-entry bugs,
    especially when IDs can be reused.

16. **Check handle identity mechanisms** — verify how handles/IDs are
    generated. Monotonic counters are safe. Pointer addresses
    (`Arc::as_ptr()`) are vulnerable to reuse after free. Recycling
    pools require caller validation.

17. **Check cleanup ordering** — verify that resources used by background
    threads are not cleaned up before those threads finish. Look for
    `detach`/`move to background` patterns that skip `join()`.

## What NOT to Do

- Do NOT add static xfail sets or hardcoded expected-failure lists
- Do NOT skip tests by recording `pass` with "skipped" detail — that hides failures
- Do NOT use `child.kill().await` in litebox (hangs; use `start_kill()`)
- Do NOT let Exec timeouts desync the agent — use subprocess isolation
- Do NOT add python3, ruby, or other interpreter dependencies
- Do NOT remove failing tests for convenience

## Enforcement

### Integration test: `cargo test -p litebox_test_harness --test integration`
Verifies:
- Native baseline: 0 FAIL, 0 XPASS, 0 xfail
- Litebox: expected FAIL/XPASS/xfail counts match constants
- Cross-check: any test passing native but failing litebox is a regression
- Any new test that breaks self-containment fails CI

Update `EXPECTED_XFAIL_COUNT`, `EXPECTED_FAIL_COUNT`, `EXPECTED_XPASS_COUNT`
in `tests/integration.rs` when intentionally changing expectations.

### Code review checklist
When adding tests, verify:
- [ ] Uses protocol commands, not bash (unless testing bash behavior)
- [ ] No new interpreter dependencies
- [ ] Tests all relevant axes (parent↔child, sibling, depth 2+)
- [ ] Added to `build_rootfs()` if new binary/file needed
- [ ] xfail has a reason string
- [ ] VS Code concern has a corresponding minimal self-contained test
- [ ] Passes on native baseline (WSL2 gold standard)

## fd Inheritance Pattern

The VS Code CLI hands a listen socket to a child process via fork+exec:

```
parent: bind()+listen() → clear CLOEXEC → fork()+exec(child) → close(fd)
child:  accept() on inherited fd → echo data
```

This pattern is tested by the `tcp-fork-listen-accept` subcommand in
main.rs (used by the FKLC.cross_connect test). It cannot currently be
expressed via the agent protocol because the child needs to accept on a
raw fd number rather than re-binding.

The `Fork` protocol command has an `inherit_listen_ports` field designed
for this but not yet implemented. See the design notes in protocol.rs
for implementation guidance.
