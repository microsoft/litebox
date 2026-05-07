# Synchronization primitives audit

## existing primitives

Coordinator tests currently synchronize mostly through request/response edges in the agent protocol:

- `TestRunner::send` / `send_cmd` is the core barrier: the coordinator writes one JSON command, flushes it, and waits for exactly one JSON response before continuing (`litebox_test_harness/src/coordinator/mod.rs:240`, `:1037`). Nested `Forward` preserves that synchronous edge across agent hops (`protocol.rs:142`).
- `Spawn`, `SpawnRemote`, and `Fork` only synchronize on the parent agent spawning/registering the child and returning `Ok` (`agent.rs:97`, `:117`, `:150`). They do **not** prove the child agent has completed a protocol-level ready handshake; the next command to that child is the first real readiness probe.
- `RunContext::spawn_ephemeral` wraps the same `Spawn` / `SpawnRemote` / `Fork` edge for typed tests (`coordinator/run_context.rs:61`). It is a spawn-complete barrier, not a workload-ready barrier.
- `NetListen` is a useful state barrier: `Response::Listening { port }` is returned only after `TcpListener::bind` succeeds, the actual port is known, and the echo task is registered (`agent.rs:331`, `protocol.rs:262`). `UnixListen` / `UnixListening` provides the same protocol-level barrier for in-agent Unix sockets (`agent.rs:590`, `protocol.rs:266`).
- `Exec` foreground mode synchronizes on child process exit and captured stdout/stderr (`agent.rs:455`). `Exec { background: true }` only returns a PID after spawn; stdout/stderr are discarded, so readiness beacons printed by background helpers are currently unusable (`agent.rs:478`).
- `NetConnect`, `NetHalfCloseEcho`, `NetConnectMany`, `NetSendRecv`, etc. are observed-behavior barriers: success means connect/write/read completed, but failure usually cannot distinguish "server not ready yet" from a product/network bug.
- `Go` exists but is only an immediate echo/ack (`protocol.rs:238`, `agent.rs:586`); it is not a multi-party barrier.
- Timeouts (`send_cmd`, per-test timeout, `Exec` timeout, teardown timeout) are failure bounds, not synchronization primitives (`coordinator/mod.rs:1037`, `:875`, `agent.rs:530`, `coordinator/mod.rs:899`).
- `record_baseline` is not a test synchronization primitive. It selects allow-all broker policy so operations succeed while being audit-logged (`litebox_tool_executor/src/main.rs:63`, `:485`) and is used by the litebox integration pass (`litebox_test_harness/tests/integration.rs:181`). The surrounding executor waits for broker socket-path existence before launching the runner (`litebox_tool_executor/src/main.rs:452`), but `record_baseline` itself does not wait for guest state.
- The host port-forward integration test has an observed-state readiness loop: it repeatedly connects and sends `cwd_get` until a well-formed protocol response arrives (`tests/integration.rs:594`). This is better than a blind sleep, but it lives outside coordinator tests and still polls on a timer. After `NetListen` on the forwarded data port it also uses a short sleep before host connect (`tests/integration.rs:653`).
- Standalone helper subcommands sometimes print readiness to stdout (for example `unix-echo-server` prints `LISTENING`, `main.rs:1495`), but `Exec background` discards stdout, so coordinator tests cannot consume those signals today.

## unjustified-sleep callsites table

Count by static sleep occurrence in `litebox_test_harness/src/coordinator`: **5 justified**, **22 unjustified**. "Justified" means the delay is the behavior under test or the workload being held alive; "unjustified" means it gates a later assertion because there is no protocol-level state signal.

| File:line | Test(s) / pattern | Classification | Why it sleeps | Better primitive |
|---|---|---:|---|---|
| `fork_matrix.rs:61` | `background_wait` shell pattern | Justified | Exercises bash background job + `wait` semantics; `sleep 0` is the subject workload. | None needed. |
| `port_router.rs:270` | `PR.fork_bg` | Justified | Holds a background process alive while the listener is probed after other execs. It is not waiting for server readiness. | A dedicated long-lived helper would be clearer but not required. |
| `platform_fixes.rs:626` | `TLB.listen_busy.*` | Justified | Deliberately spans a delay after `NetListen`; the test is about a listener remaining usable while accept is delayed. | None; this is intentional delay coverage. |
| `platform_fixes.rs:806` | `BASH.fork_bg_fg.*` | Justified | Exercises bash background + foreground interaction. | None needed. |
| `platform_fixes.rs:1810` | `KP.kill0_many.*` | Justified | Checks the child remains visible after time has passed; the delayed observation is part of the assertion. | Could be shortened by a helper, but not a missing sync edge. |
| `port_router.rs:355` | `PR.listen_inherit_self` | **Unjustified** | Sleeps after `Exit` on the forked child before reconnecting to the parent listener. This masks missing child-exit/cleanup acknowledgement. | `WaitExited { agent }` or stronger `Exit` ack that waits for child process termination. |
| `port_router.rs:419` | `PR.listen_inherit_cross` | **Unjustified** | Same as above, but cross-agent connect. | `WaitExited { agent }`. |
| `tcp_stress.rs:411` | `TF.full_duplex.*` | **Unjustified** | Sleeps after spawning `tcp-fullduplex` server in background before client connect. | `ExecReady`/`WaitReady` for helper stdout beacon, or protocol `NetListen`-based server helper. |
| `matrix.rs:1761` | `U.*.connect` | **Unjustified** | Sleeps after background `unix-echo-server`; the helper already prints `LISTENING`, but `Exec background` drops stdout. | `ExecReady` capturing readiness line; or convert to `UnixListen`. |
| `platform_fixes.rs:1232` | `CWF.concurrent.*` | **Unjustified** | Sleeps after background `cross-worker-file write-and-sleep` before `FsRead`. | `WaitFor { fs_exists/content_prefix }` or helper ready beacon after flush. |
| `platform_fixes.rs:1287` | `CWF.hold_open.*` | **Unjustified** | Sleeps until `write-and-hold` has written/flushed and is holding the fd open. | `WaitFor` file predicate or ready beacon. |
| `platform_fixes.rs:1324` | `CWF.self_open.*` script | **Unjustified** | Bash backgrounds writer, then sleeps before `cat`. | `WaitFor` file predicate; avoid bash timer. |
| `platform_fixes.rs:1373` | `CWF.redirect_stdout.*` script | **Unjustified** | Bash backgrounds redirected writer, then sleeps before `cat`. | `WaitFor` file predicate or background ready beacon after stdout flush. |
| `platform_fixes.rs:1657` | `CC.{echo,fork_exec,pipe_capture,file_write}.*` | **Unjustified** | Starts a background shell command, sleeps, then reads the output file. | `WaitFor` file predicate or foreground exec where possible. |
| `platform_fixes.rs:1692` | `TR.no_touch.*` script | **Unjustified** | Backgrounds `echo-test`, sleeps before reading redirected file. | Foreground exec or `WaitFor` file predicate. |
| `platform_fixes.rs:1702` | `TR.touch.*` script | **Unjustified** | Same timer-gated file read. | `WaitFor` file predicate. |
| `platform_fixes.rs:1712` | `TR.touch_chmod.*` script | **Unjustified** | Same timer-gated file read. | `WaitFor` file predicate. |
| `platform_fixes.rs:1722` | `TR.echo_touch.*` script | **Unjustified** | Same timer-gated file read. | `WaitFor` file predicate. |
| `platform_fixes.rs:1821` | `KP.proc_child.*` script | **Unjustified** | Sleeps before probing `/proc/$PID`; compensates for child exec/start visibility instead of observing it. | `WaitFor { pid_exists/cmdline_contains }`. |
| `platform_fixes.rs:2369` | `LB.same_worker.*` script | **Unjustified** | Sleeps before connecting to a standalone `tcp-echo` server. | `ExecReady` on `LISTENING`, or protocol `NetListen`. |
| `platform_fixes.rs:2380` | `LB.localhost.*` script | **Unjustified** | Sleeps before host-side `nc` connect to helper server. | `ExecReady` / `WaitReady`. |
| `platform_fixes.rs:2391` | `LB.any_to_local.*` script | **Unjustified** | Same server-ready timer. | `ExecReady` / `WaitReady`. |
| `platform_fixes.rs:2402` | `LB.fast_close.*` script | **Unjustified** | Sleeps before connecting to `tcp-recv-all`. | `ExecReady` / `WaitReady`. |
| `platform_fixes.rs:2404` | `LB.fast_close.*` script | **Unjustified** | Sleeps after client close before `wait`, masking missing completion/EOF signal. | Server exits should be the signal; use bounded foreground helper or `WaitExited`. |
| `platform_fixes.rs:2413` | `LB.halfclose_eof.*` script | **Unjustified** | Sleeps before connecting to `tcp-recv-all`. | `ExecReady` / `WaitReady`. |
| `platform_fixes.rs:2415` | `LB.halfclose_eof.*` script | **Unjustified** | Sleeps after `nc -w2`, then waits for server; timer stands in for EOF/completion. | Use protocol `NetHalfCloseEcho` or `WaitExited`. |
| `platform_fixes.rs:2625` | `FKLC.cross_connect` | **Unjustified** | Sleeps after spawning `tcp-fork-listen-accept` before connecting from another agent. | `ExecReady` for inherited-listen helper, or implement `Fork.inherit_listen_ports` and use `NetAccept`. |

## recommended new primitives

1. **`ExecReady` / `WaitReady` for background helpers (top recommendation).** Extend `Command::Exec` background mode with an optional readiness contract, e.g. `ready_stdout: Option<String>` or a new `ExecReady { args, ready_line, timeout_secs } -> Background { pid }` that keeps stdout readable until the marker appears, then detaches/discards the rest. This directly removes the server-ready sleeps in `TF.full_duplex`, `U.*.connect`, `LB.*`, and `FKLC.cross_connect`, and can also cover file-writer helpers that print after `flush()`. It leverages existing helper behavior (`unix-echo-server` already prints `LISTENING`) and keeps tests self-contained.

2. **`WaitFor` observed-state predicates.** Add a bounded protocol command evaluated on an agent, with a small explicit predicate set rather than arbitrary scripts: `FileExists`, `FileContains`, `PidExists`, `CmdlineContains`, `TcpConnectable`, maybe `UnixSocketConnectable`. This removes the CWF/CC/TR file sleeps and the `/proc/$PID` sleep, and gives failure details that distinguish "state never appeared" from the next assertion failing. It should poll internally with a deadline, but tests would express the required state instead of hard-coding sleeps.

Lower priority: **`WaitExited { pid | agent }` / stronger `Exit` semantics** would remove the two `PR.listen_inherit_*` post-`Exit` sleeps and the post-client sleeps in `LB.fast_close` / `LB.halfclose_eof`. It is useful but eliminates fewer current callsites than the two options above.

A generic `Barrier { name, n }` is not the best first addition: current sleeps are mostly coordinator-vs-background-helper readiness problems, not N-party rendezvous among multiple live agents. It may be valuable later for concurrent stress tests, but it would eliminate fewer audited sleeps today.

## VS-Code-impact ranking

1. **`ExecReady` / `WaitReady` — highest impact.** VS Code/Node/sshd regressions often involve background servers becoming ready (`listen()` complete), fork+exec helpers inheriting fds, and Unix/TCP sockets. Replacing blind server-start sleeps would make tests fail deterministically when readiness never happens and would reduce false confidence from overlong timers. It directly improves coverage around `tcp-fullduplex`, Unix sockets, loopback TCP, and the VS-Code-relevant fd-inheritance helper.

2. **`WaitFor` observed-state predicates — high impact.** VS Code writes logs, pid files, sockets, and `/proc`-visible child state while processes remain alive. File and process predicates would eliminate the largest cluster of timer-gated tests (`CWF`, `CC`, `TR`, `KP.proc_child`) and make failures point at the missing state instead of an arbitrary delay budget.

3. **`WaitExited` / exit acknowledgement — medium impact.** Useful for cleanup-sensitive fork/listen and EOF tests, but lower priority because fewer current sleeps depend on process-exit synchronization.

4. **`Barrier { name, n }` — medium/low current impact.** Valuable for future multi-agent race tests, but today the largest problem is one-party readiness/state observation rather than rendezvous among N already-running agents.

Summary: implement **`ExecReady` first**, then **`WaitFor` predicates**. Together they would remove roughly 18 of the 22 unjustified coordinator sleep occurrences identified above.
