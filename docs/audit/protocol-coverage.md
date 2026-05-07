# Protocol coverage audit

Method: static scan of `litebox_test_harness/src/protocol.rs` variants against direct `Command::...` and `Response::...` references under `litebox_test_harness/src/coordinator/`, excluding comment-only hits. Counts include coordinator helper/wiring callsites where those helpers are the protocol surface used by tests.

Summary: `Command` variants are 3 dead, 9 fragile, 22 healthy. `Response` variants are 2 dead, 2 fragile, 9 healthy.

## Command variants

| variant | callsite count | example | classification | notes |
|---|---:|---|---|---|
| `Spawn` | 12 | `litebox_test_harness/src/coordinator/mod.rs:334` | healthy | Heavily used by matrix setup and nested forwarding. Stub should break many topology-dependent tests. |
| `SpawnRemote` | 5 | `litebox_test_harness/src/coordinator/mod.rs:410` | healthy | Non-PIE subtree setup plus helper-routed remote children. Stub should break non-PIE coverage. |
| `Fork` | 1 | `litebox_test_harness/src/coordinator/run_context.rs:78` | fragile | Constructed only through `RunContext::spawn_ephemeral`; actual `SpawnKind::Fork` declarations exist, but the wire variant has a single construction point. |
| `NetAccept` | 0 | — | dead | Declared protocol surface with no coordinator caller. Candidate for deletion or for the future explicit listen/accept fd-inheritance tests. |
| `NetCloseListener` | 0 | — | dead | Declared protocol surface with no coordinator caller; notable because protocol docs mention VS Code parent-close-after-fork flow. |
| `GetPid` | 1 | `litebox_test_harness/src/coordinator/platform_fixes.rs:2049` | fragile | Used only by cross-PID visibility setup. |
| `FsRead` | 29 | `litebox_test_harness/src/coordinator/file_tcp.rs:113` | healthy | Usually paired with `Response::Ok { data: ... }` assertions, so stubs should fail. |
| `FsWrite` | 28 | `litebox_test_harness/src/coordinator/file_tcp.rs:60` | healthy | Some write responses are asserted only as `Ok { .. }`; many writes are setup whose response is ignored. |
| `FsDelete` | 22 | `litebox_test_harness/src/coordinator/matrix.rs:496` | healthy | Often cleanup/setup with ignored response; a stub may still fail indirectly when stale files affect later assertions. |
| `FsSymlink` | 11 | `litebox_test_harness/src/coordinator/matrix.rs:1125` | healthy | Creation success sometimes asserted only as `Ok { .. }`; readlink/read-through tests exercise effects. |
| `FsReadlink` | 3 | `litebox_test_harness/src/coordinator/matrix.rs:1179` | healthy | Payload asserted against expected target. |
| `FsStat` | 2 | `litebox_test_harness/src/coordinator/matrix.rs:1276` | healthy | Payload asserted for file type. |
| `NetListen` | 52 | `litebox_test_harness/src/coordinator/file_tcp.rs:47` | healthy | Very high coverage, but `Response::Listening { port }` payload is generally ignored. |
| `NetUnlisten` | 52 | `litebox_test_harness/src/coordinator/file_tcp.rs:69` | healthy | Mostly cleanup; responses are commonly ignored, so a stub may silently pass in some tests. |
| `NetConnect` | 36 | `litebox_test_harness/src/coordinator/file_tcp.rs:192` | healthy | Echo payload usually asserted via `Response::Connected { echo }`. |
| `NetHalfCloseEcho` | 1 | `litebox_test_harness/src/coordinator/platform_fixes.rs:2528` | fragile | Single TCP half-close EOF test; one regression away from being uncovered. |
| `Forward` | 23 | `litebox_test_harness/src/coordinator/mod.rs:421` | healthy | Core nested-agent routing surface. Stub should break many nested/remote tests. |
| `Exec` | 30 | `litebox_test_harness/src/coordinator/matrix.rs:1700` | healthy | Direct `Command::Exec` count; additional tests call `super::exec(...)`. `ExecResult` assertions mostly check stdout/exit code, rarely stderr. |
| `EnvGet` | 3 | `litebox_test_harness/src/coordinator/matrix.rs:1057` | healthy | Payload asserted non-empty/not `NOT_SET`. |
| `CwdGet` | 1 | `litebox_test_harness/src/coordinator/matrix.rs:1071` | fragile | Payload is only checked as `Some(_)`, not the expected cwd. |
| `UnixListen` | 20 | `litebox_test_harness/src/coordinator/matrix.rs:965` | healthy | Response path payload ignored (`UnixListening { .. }`). |
| `UnixUnlisten` | 12 | `litebox_test_harness/src/coordinator/matrix.rs:992` | healthy | Mostly cleanup; response commonly ignored. |
| `UnixConnect` | 11 | `litebox_test_harness/src/coordinator/matrix.rs:981` | healthy | Uses `Response::Connected` echo assertions. |
| `Kill` | 8 | `litebox_test_harness/src/coordinator/matrix.rs:1718` | healthy | Often cleanup of background processes; response ignored. |
| `NetConnectMany` | 3 | `litebox_test_harness/src/coordinator/tcp_stress.rs:259` | healthy | Structured success count is in `Ok` data and is asserted in stress tests. |
| `NetSendRecv` | 1 | `litebox_test_harness/src/coordinator/tcp_stress.rs:318` | fragile | Single large-transfer/backpressure test. |
| `NetReconnectStress` | 1 | `litebox_test_harness/src/coordinator/tcp_stress.rs:357` | fragile | Single TIME_WAIT/reconnect stress test. |
| `NetSendFileRecv` | 3 | `litebox_test_harness/src/coordinator/file_tcp.rs:382` | healthy | `Ok` data is substring-checked for `tcp_ok=...`; file payload details are weaker. |
| `PollReady` | 1 | `litebox_test_harness/src/coordinator/platform_fixes.rs:46` | fragile | Single poll/epoll readiness regression test. |
| `BindGetsockname` | 1 | `litebox_test_harness/src/coordinator/platform_fixes.rs:78` | fragile | Single construction site inside a family loop; validates returned port. |
| `PipePairIdUnique` | 1 | `litebox_test_harness/src/coordinator/platform_fixes.rs:110` | fragile | Single construction site inside a family loop; validates `unique`. |
| `Go` | 0 | — | dead | Declared coordination primitive with no coordinator caller. |
| `Exit` | 4 | `litebox_test_harness/src/coordinator/platform_fixes.rs:2883` | healthy | Used for graceful remote-agent shutdown; response ignored. |

## Response variants

| variant | callsite count | example | classification | notes |
|---|---:|---|---|---|
| `Ok` | 66 | `litebox_test_harness/src/coordinator/file_tcp.rs:67` | healthy | Mixed strength: many assert `data`, but at least 23 direct callsites use `Ok { .. }` and ignore payload. |
| `NotFound` | 9 | `litebox_test_harness/src/coordinator/matrix.rs:502` | healthy | Mostly direct variant checks for absent files/negative path tests. |
| `Listening` | 49 | `litebox_test_harness/src/coordinator/file_tcp.rs:49` | healthy | Port payload is almost always ignored via `Listening { .. }`; this is a clear assertion-strength gap. |
| `UnixListening` | 20 | `litebox_test_harness/src/coordinator/matrix.rs:970` | healthy | Path payload is ignored in all direct callsites (`UnixListening { .. }`). |
| `Connected` | 40 | `litebox_test_harness/src/coordinator/file_tcp.rs:198` | healthy | Echo payload is generally asserted; strongest network response variant. |
| `HalfClosed` | 1 | `litebox_test_harness/src/coordinator/platform_fixes.rs:2538` | fragile | Single callsite, but it asserts echoed payload. |
| `HalfCloseFailed` | 0 | — | dead | No coordinator assertion/handling; failures will surface as generic unexpected response. |
| `ConnectFailed` | 4 | `litebox_test_harness/src/coordinator/platform_fixes.rs:2584` | healthy | Three callsites are local synthetic construction in `mod.rs`; the one test assertion ignores the error payload. |
| `ExecResult` | 106 | `litebox_test_harness/src/coordinator/concurrent_fork.rs:108` | healthy | High coverage. Most callsites assert stdout and/or exit code; `stderr` is almost never asserted (2 snippets observed), and `..` commonly ignores remaining fields. |
| `ExecTimeout` | 1 | `litebox_test_harness/src/coordinator/fork_matrix.rs:386` | fragile | Single timeout-detection callsite; stderr payload ignored. |
| `Background` | 9 | `litebox_test_harness/src/coordinator/matrix.rs:1713` | healthy | PID is usually consumed for cleanup; one direct `Background { .. }` existence-only check. |
| `Error` | 21 | `litebox_test_harness/src/coordinator/fork_matrix.rs:624` | healthy | Several callsites are local synthetic errors in `mod.rs`; test assertions often ignore payload with `Error { .. }`. |
| `TestResult` | 0 | — | dead | Structured-reporting response is declared but unused by coordinator tests. |

## next-step inputs

### Stub tests that should obviously fail (high-coverage variants)

`Spawn`, `SpawnRemote`, `FsRead`, `FsWrite`, `FsSymlink`, `FsReadlink`, `FsStat`, `NetListen`, `NetConnect`, `Forward`, `Exec`, `EnvGet`, `UnixListen`, `UnixConnect`, `NetConnectMany`, `NetSendFileRecv`.

Also include `FsDelete`, `NetUnlisten`, `UnixUnlisten`, `Kill`, and `Exit`, but treat them specially: they are healthy by callsite count yet many callers ignore responses because the commands are cleanup/setup. A stub may pass in isolated tests unless downstream state is asserted.

### Stub tests likely to silently pass or provide weak signal

Dead command variants: `NetAccept`, `NetCloseListener`, `Go`.

Fragile command variants: `Fork`, `GetPid`, `NetHalfCloseEcho`, `CwdGet`, `NetSendRecv`, `NetReconnectStress`, `PollReady`, `BindGetsockname`, `PipePairIdUnique`.

Weak response-payload assertion inputs for `audit-assertion-strength` / `audit-protocol-surface`: `Listening.port`, `UnixListening.path`, `ConnectFailed.error`, `ExecTimeout.stderr`, much of `Ok.data` for success-only commands, and most `ExecResult.stderr` fields.

### Protocol-surface deletion/addition seeds

Deletion candidates if no planned test covers them: `Command::Go`, `Response::TestResult`, `Response::HalfCloseFailed`.

Surface-gap candidates to keep but test: `Command::NetAccept` and `Command::NetCloseListener`, because they map directly to the future VS Code inherited-listener / parent-close-after-fork scenario described in `protocol.rs`.
