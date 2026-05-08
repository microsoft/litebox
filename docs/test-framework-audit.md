# Test-framework + tests + shim coverage audit

> **TL;DR for VS-Code-in-litebox:** Start with the loopback/process regressions, not generic test cleanup: `TC.in_process.x10.d0` and the deterministic `LB.*` failures show Litebox can still drop or wedge VS-Code-like local TCP helper traffic. The test harness also cannot yet express the top VS Code shapes directly: inherited listen sockets via `Fork.inherit_listen_ports`, real PTY handover, and `SCM_RIGHTS` fd-passing. Before debugging the live VS Code stack, reduce each symptom to a self-contained harness capability test with signal-driven readiness (`ExecReady`/`WaitFor`) so failures localize to a product capability rather than bash, `nc`, or sleeps.

> **Update — see also**:
> - `docs/audit/vscode-syscall-trace-combined.md` — successor to the
>   connection-only trace, captured under a real workflow (connect →
>   workspace open → terminal → file edit → Copilot-Chat). Confirms
>   `SCM_RIGHTS` is real, surfaces `inotify_add_watch` as a hot
>   capability (1 343 calls), and adds `clone3 CLONE_VFORK`.
> - `docs/audit/test-scenario-priorities.md` — per-family priority
>   table (P0–P4) plus a coverage-by-capability **gaps view**
>   (G0–G3) — the direct answer to "what are the testing gaps?".

## Executive summary

### Numeric snapshot

| Metric | Count | Source |
|---|---:|---|
| Registered test IDs | 1002 | [axis-coverage](audit/axis-coverage.md) |
| Test families | 63 | [axis-coverage](audit/axis-coverage.md) |
| VS Code capability rows | 37 | [vscode-capabilities](audit/vscode-capabilities.md) |
| MISSING VS Code capabilities | 23 | [vscode-capabilities](audit/vscode-capabilities.md) |
| PARTIAL capabilities with exact VS-Code gaps | 8 | [vscode-capabilities](audit/vscode-capabilities.md) |
| Weak/non-structured assertions | 701 (`551` substring + `119` existence-only + `31` multi-substring) | [assertion-strength](audit/assertion-strength.md) |
| Unjustified coordinator sleeps | 22 | [synchronization-primitives](audit/synchronization-primitives.md) |
| Real product regressions in existing litebox failures | 10 | [litebox-failures-triage](audit/litebox-failures-triage.md) |
| Bash/sh wrappers | 55 | [bash-census](audit/bash-census.md) |
| Self-exe bash wrappers | 26 | [bash-census](audit/bash-census.md) |
| Silent-pass protocol handler stubs | 3 | [stub-protocol](audit/stub-protocol.md) |

### Top 5 findings by VS-Code-in-litebox impact

| Rank | Finding | Impact | Evidence | First action |
|---:|---|---|---|---|
| 1 | **Loopback TCP + helper process regressions are already real.** | VS-Code blocker | 10 real product regressions; deterministic `LB.*` failures and `TC.in_process.x10.d0` partial success under Litebox, clean native baseline. | Build protocol/self-exe minimal repros for `LB.*` and `TC.*`; then fix product behavior on dedicated branches. |
| 2 | **The harness cannot express inherited listen-fd handoff.** | VS-Code blocker | `Fork.inherit_listen_ports` exists but is not implemented; `NetAccept`/`NetCloseListener` are dead by callsite count. | Complete `Fork.inherit_listen_ports` + true inherited `NetAccept`, then replace `FKLC` helper coverage. |
| 3 | **PTY and controlling-tty handover are MISSING.** | VS-Code blocker | `TERM.*` only probes inherited stdio; no PTY protocol exists. | Add `PtyOpen`/`PtyExec`/`PtyRead`/`PtyWrite` plus `setsid`/`TIOCSCTTY`/foreground-pgrp tests. |
| 4 | **`SCM_RIGHTS` fd-passing is MISSING.** | VS-Code blocker | Unix echo/socketpair tests exist, but no ancillary fd transfer helper or protocol surface. | Add handle-based Unix socketpair + fd create/send/recv/read/write primitives. |
| 5 | **Timer-driven helper readiness weakens the tests most likely to catch VS Code failures.** | Regression risk | 22 unjustified sleeps; `LB.*`, `TF.*`, `U.*`, `FKLC.cross_connect`, file/pid tests wait on timers. | Add `ExecReady`/`WaitReady`, then bounded `WaitFor` predicates. |

## Test-quality findings

### Summary table

| Area | Finding | VS Code relevance | Source |
|---|---|---|---|
| Bash overuse | 55 shell wrappers; 26 wrap live `litebox_test_harness` subcommands. Top migration family is `LB.*`. | Bash/`nc`/sleep wrappers obscure loopback, process, and fd-inheritance failures. | [bash-census](audit/bash-census.md) |
| Assertion weakness | 701 tests are non-structured or weakly structured; 119 are existence-only. | Weak payload checks can miss wrong ports, paths, stderr, or partial success counts. | [assertion-strength](audit/assertion-strength.md) |
| Tautologies | `SS.* DONE`, `BASH.fork_bg_fg`, `BASH.fork_subst`, `XM`/`X.echo`/`XB.echo`, permissive `TERM`/`X48`. | Install-script and Node smoke tests may only prove “the script reached `echo`.” | [assertion-strength](audit/assertion-strength.md) |
| Axis holes | 146 actionable missing-axis cells across 63 families; top extensions: `PB`, `PR`, `EP`, `FT`, `TRR`, `TF`, `TW`, `LB`, `NPIPE`, `XM`. | VS Code failures often appear only in child, sibling, depth-2, or cross-worker contexts. | [axis-coverage](audit/axis-coverage.md) |
| Pseudo-pass skips | No `record_xfail` calls, but `F.host.*` and `NA.*.self_ip` can record pass-with-skip detail. | Hidden fixture/network absence can mask filesystem and network regressions. | [xfail-census](audit/xfail-census.md) |
| Protocol silent-pass stubs | 15 variants sampled; 12 caught, 3 silent-pass: `UnixUnlisten`, `Kill`, `Exit`. | Cleanup and shutdown regressions can silently pass when responses are ignored. | [stub-protocol](audit/stub-protocol.md) |
| Dynamic mutation strength | 10/10 spot mutations were caught on native and litebox. | Good news: sampled high-value tests are mutation-sensitive. | [mutation-spotchecks](audit/mutation-spotchecks.md) |

### Bash overuse

The shell census found **55** bash/sh wrapper rows: **13** legitimate shell-behavior tests, **26** self-exe wrappers, **6** simple syscall/proc utility wrappers, and **10** setup-glue wrappers. The top migration candidates are VS-Code-relevant: `LB.*` loopback TCP, `XDF.*` delayed fork, `KP/KPX` process metadata, `CF.vscode.*` install-style `/proc` pipelines, and `CWF/TR/FR` background file/redirection cases.

Keep explicit shell-behavior families (`XB`, selected `BASH`, shell-on-stdin `SS`/`XSI`) but migrate capability tests toward protocol/self-exe operations with structured responses and readiness barriers.

### Assertion weakness and tautologies

| Bucket | Count | Risk |
|---|---:|---|
| Structured | 301 | Best current pattern: exact response fields, payloads, byte counts, exit codes. |
| Substring | 551 | Often useful, but can be tautological when the script unconditionally prints the marker. |
| Existence-only | 119 | High risk for protocol payloads (`Listening.port`, `UnixListening.path`, `Ok.data`). |
| Multi-substring | 31 | Better than one marker, but still not a substitute for structured expected/observed values. |

High-priority tautologies or permissive checks:

- `SS.file_pipe_subst.*` and `SS.vscode_osrelease.*`: final `DONE` is asserted, not the substituted content.
- `BASH.fork_bg_fg.*`: final `BG_FG_OK` is printed regardless of `cat` success.
- `BASH.fork_subst.*`: `HOST=` accepts empty substitution.
- `XM.*` generated-script cases and simple `X.echo`/`XB.echo`: marker is the payload.
- `TERM.*` and `X48.node_networkInterfaces`: detect crashes/hangs more than capability correctness.

### Axis-coverage holes

The axis audit found **63** families, **1002** test IDs, and **146** actionable missing-axis cells. Strong all-axis families include `NA`, `UA`, `S`, `U`, `TLB`, `KPX`, and `XW`; use their matrix style as templates.

Top families to extend, in VS Code priority order: `PB`, `PR`, `EP`, `FT`, `TRR`, `TF`, `TW`, `LB`, `NPIPE`, `XM`.

### Pseudo-pass skips and xfails

There are **0** `record_xfail()` callsites. Keep that invariant: no expected-fail allowlists.

Two non-`record_xfail` pseudo-pass patterns should be removed:

| Pattern | Current behavior | Fix |
|---|---|---|
| `F.host.*` | Records pass with `skipped: host_wrote.txt not in rootfs` if fixture is absent. | Make fixture mandatory or fail loudly with fixture error. |
| `NA.*.self_ip` | Records pass with `self_ip not discoverable, skipping` if no non-loopback IPv4 exists. | Use deterministic fixture/address or fail loudly when environment cannot support the test. |

`SKIP` sentinels in `fork_matrix.rs` are not xfails: the harness converts missing non-PIE binaries into loud failures. Renaming the sentinel would reduce confusion, but it is not a correctness hole.

### Silent-pass protocol handlers

The dynamic protocol-stub sample covered 15 variants. Twelve stubs were caught; three silently passed:

| Variant | Why it matters | Fix direction |
|---|---|---|
| `UnixUnlisten` | Cleanup response is ignored in broad Unix socket tests. | Add post-unlisten negative connect/path assertion. |
| `Kill` | Used as cleanup; response often ignored. | Separate cleanup `Kill` from explicit signal/termination assertions. |
| `Exit` | Cooperative child shutdown in `PR.listen_inherit_self` is ignored. | Strengthen `Exit`/`WaitExited` semantics and assert child is gone. |

### What to fix first

1. **Rewrite/reduce `LB.*` loopback tests**: remove bash/`nc`/sleep and assert exact protocol/self-exe behavior; these currently expose real product regressions.
2. **Strengthen `TC.*`, `FT.*`, and stateful TCP tests**: assert counts, EOF, and per-step observed responses.
3. **Harden `SS/XSI` script-substitution checks**: replace `DONE` markers with exact expected output and stderr/exit-code assertions.
4. **Harden `KP/KPX/PROC` process metadata checks**: structured pid/ppid/cmdline fields over boolean markers.
5. **Harden pipe/stdio bridge families (`PB`, `P1/P2`, `CP`)**: structured direction/count/EOF state, plus missing sibling/cousin axes.
6. **Clean up pseudo-pass skips and silent cleanup handlers**: make fixture absence and cleanup failures loud.

## VS Code capability matrix

Coverage key: **COVERED** = focused harness test exists; **PARTIAL** = adjacent tests exist but exact VS-Code-relevant behavior is missing; **MISSING** = no focused harness test found; **EXCLUDED** = not recommended as a blocker without more evidence.

| # | Capability | Coverage | Short reason / gap |
|---:|---|---|---|
| 1 | `epoll` + `pidfd` process-exit notification | PARTIAL | Epoll socket/pipe coverage exists; no `pidfd` harness coverage. |
| 2 | `epoll` socket/pipe/socketpair readiness wakeups | COVERED | `EP.*`, `PB.epoll*`, and socketpair/pipe bridge tests cover readiness; add deeper/cross axes. |
| 3 | PTY allocation + `setsid`/`TIOCSCTTY`/`TIOCSPGRP` controlling-tty handover | MISSING | `TERM.*` probes inherited stdio only; no PTY protocol. |
| 4 | fork + `CLOEXEC` listen-fd inheritance (`Fork.inherit_listen_ports`) | PARTIAL | Standalone `FKLC` helper exists; protocol field is unimplemented and bypassed. |
| 5 | Generic fd inheritance across fork/exec for pipes/socketpairs/stdout bridges | COVERED | `P.*`, `PB.*`, `US6.*`, `BS.*` cover the base bridge behavior. |
| 6 | `io_uring` probe-only fallback | MISSING | No probe that asserts graceful unsupported fallback. |
| 7 | `/proc/self/*` reads: cmdline/stat/status/fd/exe/maps | PARTIAL | cmdline/stat adjacent coverage exists; `status`, `fd`, `exe`, `maps` are missing. |
| 8 | `/proc/<pid>/*` cross-pid reads and liveness | COVERED | `KPX.*` and `KP.*` cover cmdline/liveness strongly. |
| 9 | `clone3` / thread creation with `CLONE_THREAD` + `CLONE_VM` pressure | PARTIAL | `XDF.thread.*` covers behavior, not exact clone3 flag/errno matrix. |
| 10 | `clone3` with `CLONE_PIDFD` / pidfd-return semantics | MISSING | No pidfd or explicit clone3 flag probe. |
| 11 | Direct `eventfd` semantics and epoll integration | MISSING | Eventfd-like paths are only indirect through Tokio/event-loop tests. |
| 12 | `signalfd` delivery | MISSING | No signalfd coverage. |
| 13 | `timerfd` / POSIX timer / `rt_sigsuspend` | MISSING | Deleted syscall-test coverage left timer/sigsuspend gaps; no timerfd probe. |
| 14 | `inotify` file watcher semantics | MISSING | No inotify harness coverage. |
| 15 | `fanotify` semantics | MISSING | No fanotify coverage; lower priority without evidence. |
| 16 | `SCM_RIGHTS` fd-passing over Unix domain sockets | MISSING | Unix echo/socketpair tests exist, but no ancillary fd transfer. |
| 17 | `setsid` / orphan reparenting / `prctl(PR_SET_PDEATHSIG)` | MISSING | Process metadata/subtree tests exist, but not exact session/orphan/PDEATHSIG semantics. |
| 18 | `mmap(MAP_SHARED | MAP_FIXED)` and fork/COW behavior | PARTIAL | Delayed-fork-after-mmap exists; exact aliasing/COW assertions are missing. |
| 19 | `getrandom` and `/dev/urandom` semantics | MISSING | No randomness/urandom startup probe. |
| 20 | DNS + netlink combined glibc flow | PARTIAL | Ingredients exist; exact combined glibc flow and DNS resolver path are missing. |
| 21 | `posix_spawn` behavior for `child_process.spawn` | MISSING | Tests use Rust `Command`/fork+exec, not explicit `posix_spawn_file_actions`. |
| 22 | Abstract Unix domain sockets | COVERED | `US5.abstract_unix` covers the basic case. |
| 23 | Filesystem `O_TMPFILE` + `linkat` | MISSING | General fs coverage exists; no `O_TMPFILE`/`linkat` probe. |
| 24 | Filesystem `renameat2` semantics | MISSING | No `renameat2` probe. |
| 25 | Filesystem `statx` semantics | MISSING | `FsStat` exists, but no `statx` probe/fallback assertion. |
| 26 | `dup3` fd duplication/`O_CLOEXEC` | MISSING | Bridge tests cover effects indirectly; no exact `dup3` assertion. |
| 27 | `fcntl(F_SETPIPE_SZ)` | MISSING | No pipe-size coverage. |
| 28 | `fcntl(F_GETFL/F_SETFL)` and `O_NONBLOCK` | COVERED | `PN.*` and pipe-nonblock helpers cover this. |
| 29 | `SO_REUSEADDR` | PARTIAL | Used by helpers; no focused rebind semantics assertion. |
| 30 | `SO_REUSEPORT` | MISSING | No reuseport coverage. |
| 31 | `SO_KEEPALIVE` | MISSING | No keepalive set/get coverage. |
| 32 | Signal masks across fork+exec (`sigprocmask`) | MISSING | Signals beyond cleanup `Kill` are not expressible. |
| 33 | `ptrace` | EXCLUDED | No current VS Code/Node/sshd evidence; do not prioritize. |
| 34 | `Exec` environment overrides | MISSING | `Command::Exec` cannot set/remove/clear child env. |
| 35 | Background helper readiness / observed-state waits | MISSING | `Exec background` discards stdout; many tests sleep instead of waiting for readiness. |
| 36 | Stateful TCP connection registry / multi-step half-close | PARTIAL | `NetHalfCloseEcho` is one-shot; no multi-step socket handles. |
| 37 | Arbitrary signal delivery / process-group signals | MISSING | `Kill` is cleanup-only; no handler/send/wait/process-group assertions. |

### Top-10 list from the capability audit

Ranked by combined missingness/partial-exact-gap and VS Code pressure:

1. **`Fork.inherit_listen_ports` + true inherited `NetAccept` (`#4`, PARTIAL, 🔥).** Documented VS Code CLI listen-socket handoff; protocol field exists but is unimplemented.
2. **PTY allocation + controlling-tty handover (`#3`, MISSING, 🔥).** VS Code terminal/ptyHost cannot be validated without real PTY + session/pgrp tests.
3. **SCM_RIGHTS fd passing (`#16`, MISSING, 🔥).** Common Unix/Node/ptyHost IPC pattern; no harness surface.
4. **`epoll` + `pidfd` exit notification (`#1`, PARTIAL, 🔥).** Epoll is covered, but pidfd process-exit notification is not.
5. **Background readiness / `WaitFor` (`#35`, MISSING, 🔥).** Multiple current VS-Code-relevant tests are timer-driven; missing primitive causes flakes and weak localization.
6. **Direct `eventfd` semantics (`#11`, MISSING, 🔥).** Tokio/libuv wake paths rely on eventfd-like readiness; current coverage is only indirect.
7. **Stateful TCP connection handles (`#36`, PARTIAL, 🔥).** One-shot half-close cannot express VS Code/Node multi-step socket state machines.
8. **`/proc/self` and `/proc/<pid>` expansion to `fd`/`exe`/`maps`/`status` (`#7`, PARTIAL, 🔥).** `/proc/cmdline` was recently fixed; remaining proc metadata is likely to be hit by Node/VS Code diagnostics.
9. **`clone3` flag matrix including pidfd (`#9/#10`, PARTIAL/MISSING, 🔥/⚠️).** Node/V8 thread startup is covered behaviorally, but exact clone3 flags and pidfd combinations are not.
10. **`inotify` file watcher semantics (`#14`, MISSING, ⚠️).** VS Code file watching is likely to touch this; no focused harness test exists.

Near misses: `posix_spawn` (`#21`), exact glibc DNS/netlink flow (`#20`), `io_uring` graceful probe (`#6`), and `Exec.env` (`#34`).

## Framework gaps

### Protocol-surface top additions

| Rank | Addition | Effort | Sketch | Why first |
|---:|---|---:|---|---|
| 1 | Complete `Fork.inherit_listen_ports` + inherited `NetAccept` | M | Store/duplicate listener fds, clear `FD_CLOEXEC` only for requested ports, import inherited listeners in child agents, make `NetAccept` accept on a registered listener, and use `NetCloseListener` for parent-close semantics. | Directly models VS Code CLI listen-socket handoff. |
| 2 | PTY open/exec/read/write + controlling-tty handover | L | Add `PtyOpen`, `PtyExec`, `PtyWrite`, `PtyRead`, `PtyResize`, `PtyClose`; exercise `openpty`, `setsid`, `TIOCSCTTY`, foreground pgrp, resize, and echo/read. | Required to validate terminal/ptyHost behavior. |
| 3 | `SCM_RIGHTS` fd-passing | M/L | Add handle-based `FdCreate`, `UnixSocketPair`, `ScmSendFd`, `ScmRecvFd`, `FdRead`, `FdWrite`, `FdClose`; start same-agent, then child/cross-agent. | Covers dynamic fd transfer over Unix sockets, distinct from fork inheritance. |

Secondary protocol gaps from [protocol-surface](audit/protocol-surface.md): add `Exec.env` (S), explicit signal testing (M), stateful TCP handles (M), and reconcile dead/half-finished variants (`Go`, `TestResult`, `HalfCloseFailed`, `NetAccept`, `NetCloseListener`) while strengthening weak payload assertions.

### Synchronization gap

The synchronization audit found **5 justified** sleeps and **22 unjustified** sleeps. The top recommendation is:

1. **`ExecReady` / `WaitReady`** for background helpers that already print readiness (`LISTENING`, server-ready beacons). This directly targets `TF.full_duplex`, `U.*.connect`, `LB.*`, and `FKLC.cross_connect`.
2. **`WaitFor` predicates** for observed state: `FileExists`, `FileContains`, `PidExists`, `CmdlineContains`, `TcpConnectable`, `UnixSocketConnectable`. This removes CWF/CC/TR/KP timer gates.
3. **`WaitExited` / stronger `Exit` semantics** for post-`Exit`, EOF, and cleanup assertions.

Together, `ExecReady` and `WaitFor` would remove roughly **18 of the 22** unjustified sleep occurrences.

### Error-localization top improvements

| Rank | Improvement | Effort | Why |
|---:|---|---:|---|
| 1 | Include stderr path and last ~30 stderr lines in libtest failures. | S | No-JSON/startup failures can point only at empty stdout while stderr has the root cause. |
| 2 | Standardize `TestOutcome::detail` as expected-vs-observed with failing step/cycle. | S/M | Some failures report labels instead of observed response, count, or cycle. |
| 3 | Surface poisoned-agent state and `LITEBOX_KEEP_CONTAINER=1` hint. | M | Distinguishes primary timeout from secondary fallout and improves container/debug artifact discovery. |

### Lazy-matrix doc-cleanup note

The lazy matrix implementation now uses the declared dependency graph, not a test-name heuristic. The audit found **no real misses today**, but stale comments/docs still describe the old dot-component heuristic. Update those docs/comments and add a registration invariant against raw `Forward` to static agents bypassing typed handles.

## Pre-existing litebox failures triage

Native passed all requested prefixes (`LB`, `TC`, `TD`, `TRR`, `TF`, `TW`, `FT`, `PR`/`PROC`). Litebox failures were limited to `LB`, `TC`, and `FT`.

Classification counts by failing test ID:

| Classification | Count |
|---|---:|
| R — real product regression | 10 |
| F — flaky / intermittent | 3 |
| E — environmental artifact | 0 |

### Failure table

| test ID | symptom | class | log path | repro sketch / next step |
|---|---|---:|---|---|
| `LB.same_worker.A` | No JSON result; stdout empty. Exact rerun still failed after `A spawn ["AA"]`; coordinator never recorded the test result. | R | `target/test-logs/litebox-LB-same-worker-A.{stdout,stderr}.log`; aggregate lines in `target/audit-logs/audit-litebox-fails.log`; exact rerun in `target/audit-logs/audit-litebox-fail-reruns.log` | Replace bash+`nc` with self-contained coordinator/protocol test: agent `A` starts `tcp-echo`, connects to `127.0.0.1`, sends one line, asserts echo and child exit. |
| `LB.any_to_local.A` | No JSON result; exact rerun reproduced hang/no-result. | R | `target/test-logs/litebox-LB-any-to-local-A.{stdout,stderr}.log`; aggregates above | Same minimal repro, keeping child PID cleanup; suspect loopback TCP plus kill/wait cleanup of an Exec-spawned child. |
| `LB.localhost.A` | No JSON result; exact rerun reproduced. | R | `target/test-logs/litebox-LB-localhost-A.{stdout,stderr}.log`; aggregates above | Minimal single-agent loopback test using self-exe server, client connect, kill/wait. |
| `LB.same_worker.AA` | No JSON result after spawning `AA`; exact rerun reproduced. | R | `target/test-logs/litebox-LB-same-worker-AA.{stdout,stderr}.log`; aggregates above | Same as `LB.same_worker.A`, but inside child agent `AA` to isolate delayed-fork worker behavior. |
| `LB.localhost.AA` | Exact rerun returned `ExecTimeout { stderr: "process timed out after 15s (likely deadlocked)" }`; initial run had no JSON result. | R | `target/test-logs/litebox-LB-localhost-AA.{stdout,stderr}.log`; aggregates above | Minimal `AA` Exec test: spawn `tcp-echo`, connect with Rust client, kill/wait. |
| `LB.any_to_local.AA` | No JSON result after spawning `AA`; exact rerun reproduced. | R | `target/test-logs/litebox-LB-any-to-local-AA.{stdout,stderr}.log`; aggregates above | Same as `LB.localhost.AA`, preserving `0.0.0.0` bind / `127.0.0.1` connect distinction. |
| `LB.same_worker.B` | No JSON result; exact rerun reproduced. | R | `target/test-logs/litebox-LB-same-worker-B.{stdout,stderr}.log`; aggregates above | Same as `LB.same_worker.A`, but on sibling root agent `B`. |
| `LB.any_to_local.B` | No JSON result; exact rerun reproduced. | R | `target/test-logs/litebox-LB-any-to-local-B.{stdout,stderr}.log`; aggregates above | Same as `LB.any_to_local.A`, but on `B`. |
| `LB.localhost.B` | No JSON result; exact rerun reproduced. | R | `target/test-logs/litebox-LB-localhost-B.{stdout,stderr}.log`; aggregates above | Same as `LB.localhost.A`, but on `B`. |
| `TC.in_process.x10.d0` | Initial run returned `Ok { data: Some("success=8/10") }`; exact rerun returned `success=9/10`. Native passed. | R | `target/test-logs/litebox-TC-in-process-x10-d0.{stdout,stderr}.log`; aggregates above | Protocol-only test: one `NetListen` on `A`, then `NetConnectMany` to `127.0.0.1` with counts 2/5/10/20; assert exact success count. |
| `TC.depth2.x5.d0` | Initial run produced no JSON; stderr contained `Error: IPC handshake response timeout`. Exact rerun passed. | F | `target/test-logs/litebox-TC-depth2-x5-d0.{stdout,stderr}.log`; initial aggregate above | Treat as startup/handshake flake until repeated; if it recurs, create focused child-agent spawn + `NetListen`/`NetConnectMany` test. |
| `FT.interleave_self_4k` | Initial run returned `Error { error: "read timeout" }`; exact rerun passed. | F | `target/test-logs/litebox-FT-interleave-self-4k.{stdout,stderr}.log`; initial aggregate above | If repeated, make minimal `NetSendFileRecv` matrix over `/etc/hostname` and project paths, same-agent first. |
| `FT.interleave_cross_4k` | Initial run returned `Error { error: "read timeout" }`; exact rerun passed; teardown also exceeded 10s. | F | `target/test-logs/litebox-FT-interleave-cross-4k.{stdout,stderr}.log`; initial aggregate above | Same as self case, but split listener/client across `B` and `A`; include same-agent and cross-agent variants. |

The **10 R entries are concrete product fixes**. Each should follow the fix-first workflow on a dedicated branch: isolate or add a minimal harness test, prove native passes and Litebox fails, then use audit logs/debugger only to inform the product fix.

Top 5 VS-Code-relevant failure entries:

1. `TC.in_process.x10.d0` — concurrent loopback TCP drops 1–2 of 10 connections under Litebox.
2. `LB.localhost.AA` — child-agent Exec of a loopback TCP helper times out/deadlocks.
3. `LB.same_worker.A` / `LB.any_to_local.A` / `LB.localhost.A` — root-agent Exec + self-exe TCP echo never records JSON.
4. `FT.interleave_cross_4k` — cross-agent TCP transfer plus filesystem read timed out once.
5. `TC.depth2.x5.d0` — initial depth-2 IPC handshake timeout, clean on rerun but relevant to nested helper trees.

## Recommended fix order

This numbered list is intended to translate 1:1 into the next `audit-backlog` SQL rows.

1. **VS-Code-blocker / M:** Reduce and fix `TC.in_process.x10.d0` concurrent loopback TCP partial-success regression with exact `NetConnectMany` count assertions.
2. **VS-Code-blocker / M:** Reduce and fix deterministic `LB.*` loopback helper hangs using protocol/self-exe Rust helpers instead of bash/`nc`/sleep.
3. **VS-Code-blocker / M:** Complete `Fork.inherit_listen_ports`, true inherited `NetAccept`, and `NetCloseListener`; replace standalone `FKLC` inherited-listener coverage.
4. **VS-Code-blocker / L:** Add PTY protocol coverage for `openpty`, `setsid`, `TIOCSCTTY`, `TIOCSPGRP`/foreground pgrp, read/write, resize, and close.
5. **VS-Code-blocker / M/L:** Add handle-based `SCM_RIGHTS` fd-passing tests over Unix sockets.
6. **VS-Code-blocker / M:** Add `ExecReady`/`WaitReady` for background helpers and migrate `LB.*`, `TF.*`, `U.*`, and `FKLC.cross_connect` server-ready sleeps.
7. **Regression-risk / M:** Add `WaitFor` observed-state predicates and migrate CWF/CC/TR/KP timer-gated file and process checks.
8. **Regression-risk / M:** Add stateful TCP connection handles (`NetOpen`, `NetSend`, `NetRecv`, `NetShutdown`, `NetClose`) and strengthen half-close/EOF failure assertions.
9. **Regression-risk / M:** Expand `/proc` coverage to `fd`, `exe`, `maps`, and `status`; convert KP/KPX boolean markers into structured pid/ppid/cmdline assertions.
10. **Regression-risk / S/M:** Improve error localization: stderr path/tail, expected-vs-observed details, poisoned-agent state, and `LITEBOX_KEEP_CONTAINER=1` hints.
11. **Regression-risk / S:** Add `Exec.env` fields (`env`, `env_remove`, clear/inherit mode) and exact child-environment assertions.
12. **Regression-risk / M:** Add direct `eventfd` + epoll tests and pidfd/clone3 exit-notification coverage.
13. **Regression-risk / M:** Add `inotify`, `posix_spawn`, `getrandom`/`urandom`, `statx`, `renameat2`, `O_TMPFILE`/`linkat`, `dup3`, `SO_REUSEPORT`, and signal-mask probes, prioritized by observed VS Code pressure.
14. **Regression-risk / M:** Fill top axis gaps for `PB`, `PR`, `EP`, `FT`, `TRR`, `TF`, `TW`, `LB`, `NPIPE`, and `XM` after the supporting protocol surfaces exist.
15. **Cleanup / S:** Remove pseudo-pass skips in `F.host.*` and `NA.*.self_ip`; rename confusing `SKIP` sentinels if desired.
16. **Cleanup / S/M:** Reconcile dead/stale protocol variants (`Go`, `TestResult`, `HalfCloseFailed`) and assert weak payloads (`Listening.port`, `UnixListening.path`, `ConnectFailed.error`, `ExecTimeout.stderr`, `Ok.data`, `ExecResult.stderr`).
17. **Cleanup / S:** Update lazy-matrix docs/comments to describe dependency-graph spawning, and add an invariant against raw static-agent `Forward` bypasses.
18. **Cleanup / S/M:** Harden tautological script and canary tests (`SS`, `BASH`, `XM`, `X.echo`, `XB.echo`, permissive `TERM`/`X48`) with semantic stdout/stderr/exit assertions.

## Audit methodology

This audit used **static analysis plus lightweight dynamic checks**. It did not use coverage instrumentation.

| Phase | Static / dynamic | Scope |
|---|---|---|
| Bash census | Static | Exhaustive coordinator shell wrapper census by callsite row. |
| Xfail census | Static | Exhaustive `record_xfail` and xfail-like skip-pattern search under `litebox_test_harness`. |
| Protocol coverage | Static | Exhaustive `Command`/`Response` callsite scan in coordinator tests. |
| Assertion strength | Static + sampling | Expanded all 1002 registered test IDs into assertion buckets; sampled substring cases for tautologies. |
| Axis coverage | Static | All registered test IDs and declared agent dependencies; missing-axis cells are actionable judgments, not full cross-product requirements. |
| VS Code capability matrix | Static synthesis | 37 capabilities from harness docs, audit findings, and recent VS-Code-focused branch pressure. |
| Mutation spotchecks | Dynamic sample | 10 representative one-line mutations; all 10 caught on native and litebox. |
| Stub protocol audit | Dynamic sample | 15 protocol variants; 12 caught, 3 silent-pass. Dead variants and cap-skipped variants were not fully stubbed. |
| Litebox failure triage | Dynamic targeted runs | Requested prefixes run native and litebox; exact reruns of observed failures classified as R/F/E. |
| Framework gap analysis | Static | Protocol surface, synchronization primitives, lazy-matrix behavior, and failure UX reviewed from source and observed failures. |

Explicit limits:

- Mutation sample size was **10**; it is a spotcheck, not proof every test is high-signal.
- Stub sample size was **15** non-dead or weak/fragile variants; several healthy variants were skipped after the cap.
- Axis coverage identifies missing topology cells per family, not every possible argument/value cross-product.
- The VS Code capability matrix prioritizes likely and observed VS Code/Node/sshd pressure; it is not a complete Linux syscall conformance plan.
- Existing Litebox failures were triaged, not fixed; product fixes must happen on follow-up branches with minimal harness repros.

## Cross-references

Per-phase findings under `docs/audit/`:

| File | Role in this synthesis |
|---|---|
| [bash-census.md](audit/bash-census.md) | Bash/sh wrapper counts, categories, and migration priorities. |
| [xfail-census.md](audit/xfail-census.md) | `record_xfail` absence and pseudo-pass skip findings. |
| [protocol-coverage.md](audit/protocol-coverage.md) | Dead/fragile/healthy protocol variants and weak payload assertions. |
| [assertion-strength.md](audit/assertion-strength.md) | Assertion bucket counts, tautologies, and hardening priorities. |
| [axis-coverage.md](audit/axis-coverage.md) | 63-family topology coverage table and top missing-axis cells. |
| [vscode-capabilities.md](audit/vscode-capabilities.md) | 37-row VS Code/Node/sshd capability matrix and top-10 ranking. |
| [mutation-spotchecks.md](audit/mutation-spotchecks.md) | 10 dynamic mutation spotchecks and catch rates. |
| [stub-protocol.md](audit/stub-protocol.md) | 15 dynamic protocol stubs and silent-pass variants. |
| [litebox-failures-triage.md](audit/litebox-failures-triage.md) | Existing Litebox failure classifications and repro sketches. |
| [protocol-surface.md](audit/protocol-surface.md) | Protocol additions and dead/half-finished surface recommendations. |
| [synchronization-primitives.md](audit/synchronization-primitives.md) | Sleep census and `ExecReady`/`WaitFor` recommendations. |
| [lazy-matrix.md](audit/lazy-matrix.md) | Dependency-graph lazy-matrix analysis and stale-doc cleanup. |
| [error-localization.md](audit/error-localization.md) | Failure UX findings and minimal improvements. |
