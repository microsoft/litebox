# Existing litebox failure triage

## Run summary

Audit branch: `wportnoy/test-framework-audit` in `/home/wportnoy/src/litebox-audit`.

The requested multi-filter command is not accepted by this `libtest_mimic` harness (`unexpected argument 'litebox::TC'`), so I ran the same prefixes sequentially and kept logs under the worktree instead of `/tmp`:

- Litebox aggregate: `target/audit-logs/audit-litebox-fails.log`
- Native aggregate: `target/audit-logs/audit-native-baseline.log`
- Exact litebox reruns of observed failures: `target/audit-logs/audit-litebox-fail-reruns.log`

Native was clean for all requested prefixes: `LB`, `TC`, `TD`, `TRR`, `TF`, `TW`, `FT`, and `PR` all passed. Litebox failures were limited to `LB`, `TC`, and `FT`.

Classification counts by failing test ID:

- **R — real product regression:** 10
- **F — flaky / intermittent:** 3
- **E — environmental artifact:** 0

## Failure table

| test ID | symptom | classification | log path | repro sketch / next step |
|---|---|---:|---|---|
| `LB.same_worker.A` | No JSON result; stdout empty. Exact rerun still failed after `A spawn ["AA"]`; coordinator never recorded the test result. | R | `target/test-logs/litebox-LB-same-worker-A.{stdout,stderr}.log`; aggregate lines in `target/audit-logs/audit-litebox-fails.log`; exact rerun in `target/audit-logs/audit-litebox-fail-reruns.log` | Replace the bash+`nc` script with a self-contained coordinator/protocol test: on agent `A`, start a `tcp-echo` child, connect to `127.0.0.1`, send one line, assert echo and child exit. Suspect capability: loopback TCP plus child process stdout/stderr/exit handling under Exec. Deeper debugging should use that minimal harness test, not audit-log spelunking. |
| `LB.any_to_local.A` | No JSON result; stdout empty. Exact rerun reproduced the hang/no-result pattern. | R | `target/test-logs/litebox-LB-any-to-local-A.{stdout,stderr}.log`; aggregates above | Same minimal repro as `LB.same_worker.A`, but keep explicit child PID cleanup: Exec starts `tcp-echo`, client connects over `127.0.0.1`, then parent kills/waits child. Suspect capability: loopback TCP plus kill/wait cleanup of an Exec-spawned child. |
| `LB.localhost.A` | No JSON result; stdout empty. Exact rerun reproduced the hang/no-result pattern. | R | `target/test-logs/litebox-LB-localhost-A.{stdout,stderr}.log`; aggregates above | Minimal single-agent loopback test using self-exe server with stdout/stderr redirected, client connect, kill/wait. Suspect capability: localhost TCP connect/accept/EOF and process cleanup. |
| `LB.same_worker.AA` | No JSON result after spawning `AA`; exact rerun reproduced. | R | `target/test-logs/litebox-LB-same-worker-AA.{stdout,stderr}.log`; aggregates above | Same as `LB.same_worker.A`, but run inside child agent `AA` to isolate delayed-fork worker behavior. |
| `LB.localhost.AA` | `ExecTimeout { stderr: "process timed out after 15s (likely deadlocked)" }` on exact rerun; initial run had no JSON result. | R | `target/test-logs/litebox-LB-localhost-AA.{stdout,stderr}.log`; aggregates above | Minimal `AA` Exec test: spawn self-exe `tcp-echo`, connect with a self-contained Rust client rather than bash/`nc`, then kill/wait. Suspect capability: child-agent Exec plus loopback TCP plus signal/wait cleanup. |
| `LB.any_to_local.AA` | No JSON result after spawning `AA`; exact rerun reproduced. | R | `target/test-logs/litebox-LB-any-to-local-AA.{stdout,stderr}.log`; aggregates above | Same as `LB.localhost.AA`, preserving the 0.0.0.0 bind / 127.0.0.1 connect distinction. |
| `LB.same_worker.B` | No JSON result; exact rerun reproduced. | R | `target/test-logs/litebox-LB-same-worker-B.{stdout,stderr}.log`; aggregates above | Same as `LB.same_worker.A`, but on sibling root agent `B`. This checks whether the failure is agent-local or common across root workers. |
| `LB.any_to_local.B` | No JSON result; exact rerun reproduced. | R | `target/test-logs/litebox-LB-any-to-local-B.{stdout,stderr}.log`; aggregates above | Same as `LB.any_to_local.A`, but on `B`. |
| `LB.localhost.B` | No JSON result; exact rerun reproduced. | R | `target/test-logs/litebox-LB-localhost-B.{stdout,stderr}.log`; aggregates above | Same as `LB.localhost.A`, but on `B`. |
| `TC.in_process.x10.d0` | Initial full-prefix run returned `Ok { data: Some("success=8/10") }`; exact rerun returned `success=9/10`. Native passed. | R | `target/test-logs/litebox-TC-in-process-x10-d0.{stdout,stderr}.log`; aggregates above | Minimal protocol-only test: one `NetListen` on `A`, then `NetConnectMany` to `127.0.0.1` with counts 2/5/10/20, asserting exact success count. Suspect capability: concurrent loopback TCP accept/read/write/shutdown in one agent. This is highly VS-Code-relevant because Node/VS Code commonly multiplex local TCP connections. |
| `TC.depth2.x5.d0` | Initial full-prefix run produced no JSON; failed trial stderr contained `Error: IPC handshake response timeout`. Exact rerun passed with `success=5/5`. | F | Current rerun log: `target/test-logs/litebox-TC-depth2-x5-d0.{stdout,stderr}.log`; initial aggregate: `target/audit-logs/audit-litebox-fails.log` | Treat as intermittent startup/handshake flake until reproduced. If it recurs, create a focused child-agent spawn + `NetListen`/`NetConnectMany` test for `AA`→`AB`; do not diagnose from the audit log alone. |
| `FT.interleave_self_4k` | Initial full-prefix run returned `Error { error: "read timeout" }`; exact rerun passed with `tcp_ok=4096,file_len=13`. | F | Current rerun log: `target/test-logs/litebox-FT-interleave-self-4k.{stdout,stderr}.log`; initial aggregate: `target/audit-logs/audit-litebox-fails.log` | Intermittent file+TCP interleaving failure. If it repeats, make a minimal `NetSendFileRecv` test matrix over `/etc/hostname` and `/tmp` paths, single-agent first; only then inspect audit logs. Suspect capability: TCP stream progress while 9P/read-only-file I/O is in flight. |
| `FT.interleave_cross_4k` | Initial full-prefix run returned `Error { error: "read timeout" }`; exact rerun passed with `tcp_ok=4096,file_len=13`. Rerun stderr also noted `teardown_tree exceeded 10s`, but the test result itself passed. | F | Current rerun log: `target/test-logs/litebox-FT-interleave-cross-4k.{stdout,stderr}.log`; initial aggregate: `target/audit-logs/audit-litebox-fails.log` | Same as `FT.interleave_self_4k`, but split listener/client across `B` and `A`. If made minimal, include same-agent and cross-agent variants to avoid chasing cross-worker noise from a single failing audit log. |

## Per-prefix summary

- **LB:** 6 passed, 9 failed on litebox; 15/15 passed native. All failing LB cases are deterministic on exact rerun and affect self-exe TCP echo launched under `Exec`. This is a real loopback/process-interaction product regression, though the current tests are bash-heavy and should be reduced before fixing.
- **TC:** 8 passed, 2 failed on the initial litebox prefix run; 10/10 passed native. `TC.in_process.x10.d0` reproduced as partial success and is classified real. `TC.depth2.x5.d0` passed on exact rerun after an initial IPC handshake timeout, so it is classified flaky.
- **TD:** 8/8 passed on both litebox and native.
- **TRR:** 4/4 passed on both litebox and native.
- **TF:** 3/3 passed on both litebox and native.
- **TW:** 6/6 passed on both litebox and native.
- **FT:** 17 passed, 2 failed on the initial litebox prefix run; 19/19 passed native. Both failing 4K interleave cases passed on exact rerun, so they are classified flaky pending a minimal repeated repro.
- **PR / PROC:** The `PR` filter also matched `PROC.*`; all 20 matched tests passed on both litebox and native.

## Top 5 most VS-Code-relevant entries

1. **`TC.in_process.x10.d0`** — concurrent loopback TCP drops 1–2 of 10 connections under litebox. VS Code/Node multiplex local sockets and are sensitive to exactly this reliability class.
2. **`LB.localhost.AA`** — child-agent Exec of a loopback TCP helper times out/deadlocks. VS Code remote server runs nested helper processes that communicate over loopback and need reliable cleanup.
3. **`LB.same_worker.A` / `LB.any_to_local.A` / `LB.localhost.A` family** — root-agent Exec + self-exe TCP echo never records JSON, indicating process/TCP interaction can wedge before the harness reports.
4. **`FT.interleave_cross_4k`** — cross-agent TCP transfer plus `/etc/hostname` read timed out once. This resembles VS Code/Node doing filesystem probes while network streams are active.
5. **`TC.depth2.x5.d0`** — initial IPC handshake timeout in a depth-2 TCP concurrency test. It reran cleanly, but depth-2 worker startup/handshake instability is relevant to nested helper trees.

## Notes on investigation discipline

This was diagnostic triage, not bug fixing. For every **R** item above, the next branch should first add or isolate a self-contained failing harness test for the named capability, run native first, and only then inspect audit logs or debugger output. The existing LB tests already fail on litebox but are bash/`nc` scripts with sleeps, so they should be reduced to protocol/self-exe Rust repros before product fixes are attempted.
