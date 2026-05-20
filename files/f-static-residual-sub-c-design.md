# f-static-residual Sub-C: static-pie-glibc socketpair exec

## Focused repro

Added focused harness leaves in `litebox_test_harness/src/coordinator/special_cases/unix_socket.rs`:

- `FET.socketpair_exec.static-pie-glibc.dpg1`
- `FET.socketpair_exec.static-pie-musl.dpg1`

They run the existing minimal socketpair + fork + exec child path under a single `dpg1` agent, with only the target binary type varied.

Observed baseline after adding the leaves:

- native static-pie-glibc: pass
- native static-pie-musl: pass
- litebox static-pie-musl: pass
- litebox static-pie-glibc: fail with `US6E_READ_FAIL:n=0,errno=2,exit=139`

## Findings

The failure is not a missing broker socketpair handoff. The parent creates the broker-backed socketpair and writes 16 bytes successfully. The passing static-pie-musl comparison receives the same inherited fd and replies.

An audit run saved under `target/audit-logs/` showed the failing static-pie-glibc child reached the fork/exec boundary and then died by SIGSEGV before it could issue the child-side socket read. In one run, the restored child worker replayed `close(3)`, `readlink(/proc/self/exe)`, and entered `execve(/opt/static-pie-glibc/litebox_test_harness)` without a matching execve exit event. In a later run with rebuilt bits, the trace ended at the fork/clone boundary and the parent observed the same `exit=139`. The static-pie-musl trace completed the child exec and then performed the expected socket read/write.

The host-built static-pie-glibc harness is ET_DYN static PIE with no PT_INTERP in this build, but it has glibc static-PIE runtime/TLS/relocation behavior that differs from the static-pie-musl leg. That means the original `ld.so visibility` suspect is not supported by this worktree's binary: there is no interpreter path to find. The remaining suspect is the static-pie-glibc fork child execution/exec transition, most likely in the fork snapshot restore or guest TLS/reset path, not socketpair fd preservation.

## Non-fix attempted and reverted

I tested changing exec teardown to clear the robust-list registration without walking it, because Linux exec clears robust-list state and the shim currently calls the thread-exit robust futex wake path. That did not fix the focused leaf and was reverted.

## Recommended next step

Keep the FET leaves as the regression/repro. The next narrow chokepoint is the fork-restored static-pie-glibc child immediately before/after the exec syscall, specifically guest TLS handoff/reset and memory teardown. A surgical fix should be validated first by making `FET.socketpair_exec.static-pie-glibc.dpg1` pass without regressing the static-pie-musl comparison.
