# Testing Rules for litebox_test_harness

These rules are mandatory when adding, modifying, or reviewing tests.

## Test Categories

**Self-contained tests** depend only on bash and the test harness binaries.
These are preferred. They run everywhere: WSL2 chroot, litebox, CI.

**Integration tests** require external binaries like Node.js or VS Code.
These are acceptable but always secondary — add a self-contained test
for the underlying platform capability first (principle 6 from TESTING.md).

## WSL2 Gold Standard

The native baseline (chroot into rootfs on real Linux) is the gold standard.
Every test must pass there — **0 FAIL, 0 xfail** on native.

- `tests/integration.rs` runs native baseline via `unshare --root`
- Any native failure is a **test bug**, not a litebox bug
- The rootfs is built programmatically by `build_rootfs()` — no manual setup

Litebox xfails are only for **dynamically detected** platform limitations
(e.g., symlink probe returns ENOTSUP). Never use static/hardcoded xfails.

## Core Principles

1. **Self-contained over integration** — prefer tests that need only
   bash + test harness. Before adding a node-dependent test, add an
   equivalent self-contained test for the underlying capability.

2. **No silent failures** — missing dependencies must cause loud FAIL
   with a clear error message ("exec spawn: No such file or directory"),
   never a silent skip. The integration test asserts 0 FAIL on native.

3. **Minimal reproduction** — use protocol commands (FsRead, FsWrite,
   NetListen, Exec with self_exe subcommands), not `bash -c "..."`.
   Bash is only for testing bash-specific fork behavior.

4. **Matrix coverage** — test all configurations via cross-product loops.
   When adding a capability test, cover: in-process, parent→child,
   child→parent, sibling, depth 2+. Vary one axis at a time.

5. **No timer delays** — never use sleep/retry loops to mask bugs.
   Use protocol-level signals for synchronization.

6. **Self-contained rootfs** — `cargo test --test integration` must pass
   without manual rootfs setup. Add new deps to `build_rootfs()`.

7. **Fix-first workflow** — write test → watch fail → fix code → watch
   pass → verify no regressions. Never fix code without a failing test.

## What NOT to Do

- Do NOT add static xfail sets or hardcoded expected-failure lists
- Do NOT skip tests by recording `pass` with "skipped" detail — that hides failures
- Do NOT use `child.kill().await` in litebox (hangs; use `start_kill()`)
- Do NOT let Exec timeouts desync the agent — use subprocess isolation
- Do NOT add python3, ruby, or other interpreter dependencies
- Do NOT remove failing tests for convenience (TESTING.md principle 9)

## Integration Test Enforcement

`tests/integration.rs` verifies:
- Native baseline: 0 FAIL, 0 XPASS, expected xfail count
- Litebox: 0 FAIL, 0 XPASS, expected xfail count
- Cross-check: any test passing native but failing litebox is a regression

Update `EXPECTED_XFAIL_COUNT` when intentionally adding/removing xfails.
