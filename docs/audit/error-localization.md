# Error-localization audit

## current failure UX

Scope: `audit-error-localization`. I traced `cargo test -p litebox_test_harness --test integration` through `litebox_test_harness/tests/integration.rs`, the coordinator result path in `litebox_test_harness/src/coordinator/mod.rs`, and a local failing litebox stress run.

Command sampled:

```sh
cd /home/wportnoy/src/litebox-audit
cargo test -p litebox_test_harness --test integration -- 'litebox::FT' --nocapture
```

Observed libtest-mimic failure output from that run:

```text
test litebox::FT.conn_readback        ... FAILED
test litebox::FT.interleave_self_4k   ... FAILED
test litebox::FT.interleave_cross_4k  ... FAILED
test litebox::FT.multi_interleave_x5  ... FAILED

---- litebox::FT.conn_readback ----
litebox[FT.conn_readback]: no JSON result for FT.conn_readback on stdout (full log: /home/wportnoy/src/litebox-audit/target/test-logs/litebox-FT-conn-readback.stdout.log)

---- litebox::FT.interleave_cross_4k ----
litebox::FT.interleave_cross_4k: Error { error: "read timeout" } (logs: /home/wportnoy/src/litebox-audit/target/test-logs/litebox-FT-interleave-cross-4k.stdout.log /home/wportnoy/src/litebox-audit/target/test-logs/litebox-FT-interleave-cross-4k.stderr.log)

---- litebox::FT.multi_interleave_x5 ----
litebox::FT.multi_interleave_x5: 5 interleaved file+TCP cycles (logs: /home/wportnoy/src/litebox-audit/target/test-logs/litebox-FT-multi-interleave-x5.stdout.log /home/wportnoy/src/litebox-audit/target/test-logs/litebox-FT-multi-interleave-x5.stderr.log)
```

The nominal failing-result path is good enough to discover per-trial logs: `run_pass_group()` includes both stdout and stderr log paths when the JSON result line is parsed and reports `result == "FAIL"` (`tests/integration.rs:373-385`). The startup/no-result path is weaker: `run_one_test()` reports only the stdout log path when no matching JSON line appears (`tests/integration.rs:298-304`), even though stderr often contains the actual root-cause hint.

Per-trial logs observed:

- `target/test-logs/litebox-FT-interleave-cross-4k.stdout.log` contained one machine-readable result line:

  ```json
  {"agent":"A","detail":"Error { error: \"read timeout\" }","result":"FAIL","test":"FT.interleave_cross_4k"}
  ```

- `target/test-logs/litebox-FT-interleave-cross-4k.stderr.log` contained the human progress stream and teardown state:

  ```text
  [coord] running 1 registered tests
  [harness] self_exe=/opt/litebox/litebox_test_harness resolved=/opt/litebox/litebox_test_harness
    FAIL: FT.interleave_cross_4k [A] Error { error: "read timeout" }
  [coord] B killed
  [coord] teardown_tree exceeded 10s — abandoning agent cleanup, hard-exit will reap

  === SUMMARY: 1 total, 0 passed, 1 failed ===
  ```

- `target/test-logs/litebox-FT-conn-readback.stdout.log` was empty. Its stderr log contained the root-cause class, but the libtest error pointed only to stdout:

  ```text
  Audit log: /tmp/litebox-vscode-server-logs/2026-05-06T21-58-55.jsonl
    Query with: litebox_audit_query sql --file /tmp/litebox-vscode-server-logs/2026-05-06T21-58-55.jsonl '<SQL>'
  Tool executor: /opt/litebox/litebox_tool_executor (built 761s ago)
  Runner: /opt/litebox/litebox_runner_linux_userland (built 699s ago)
  Broker: /opt/litebox/litebox_broker (built 727s ago)
  Error: IPC handshake response timeout
  ```

- `target/test-logs/litebox-FT-multi-interleave-x5.stdout.log` contained a `FAIL` JSON record with detail `5 interleaved file+TCP cycles`; stderr repeated the same detail and cleanup. That message is an assertion label, not first-failure evidence; it does not say which cycle failed or what response was observed.

The coordinator does satisfy the CLAUDE.md rule against end-of-main-only flushing. `TestRunner::record()` emits a human line to stderr plus one JSON line to stdout and immediately flushes stdout per result (`coordinator/mod.rs:207-235`). This is why `read timeout` failures survive even when teardown later times out. However, the integration wrapper's stdout tee contradicts its comment: after it finds the matching JSON result, it `break`s out of the read loop (`tests/integration.rs:274-288`) and the drain thread only waits for the child (`tests/integration.rs:325-330`), so any post-result stdout is not captured. Stderr continues going directly to the file via `Stdio::from(File::create(...))` (`tests/integration.rs:254-259`).

## observed-vs-ideal

| Area | Observed | Ideal |
|---|---|---|
| Log discoverability | Parsed `FAIL` results include both log paths. No-JSON/startup failures include only stdout. | Every failure path prints stdout and stderr paths, plus a one-line hint when stderr has the likely cause. |
| First failure detail | Depends on each test's `TestOutcome::detail`. Some are useful (`Error { error: "read timeout" }`); others are labels (`5 interleaved file+TCP cycles`). | Detail includes expected vs observed: expected response/data/count, observed response, and failing step/cycle. |
| Guest stderr | Captured inside `ExecResult { stderr: ... }` when a foreground `Exec` returns, but not summarized by libtest. Startup/no-JSON stderr is only in the log file. | Libtest failure includes the last ~30 lines of the trial stderr log, or at least the last non-empty error block. |
| Agent poisoning | Poisoning is logged to stderr when a timeout desynchronizes a direct child (`coordinator/mod.rs:266-289`) and later sends return `Error { error: "agent X is poisoned (previous timeout)" }` (`coordinator/mod.rs:251-255`). | Failure message names poisoned agents and says whether this failure is primary timeout vs secondary poisoned-agent fallout. |
| JSON parsing | The wrapper parses stdout line-by-line and accepts the first JSON object whose `test` matches (`tests/integration.rs:274-281`). Non-JSON stdout is ignored but tee'd until the break. | Continue draining/teeing stdout after the result, or make the comment and behavior match. On no-result, report stderr too. |
| stdout/stderr separation | stdout is the machine channel; stderr is human progress, component startup errors, tool-executor audit-log pointers, and inherited agent stderr (`coordinator/mod.rs:1018-1024`). This separation is conceptually sound. | Preserve the separation, but add curated stderr snippets to the libtest error. Do not move human logs onto stdout. |
| Agent/broker cross-references | Tool-executor startup failures print an audit-log path and `litebox_audit_query` command to stderr, but parsed test failures usually do not include broker/audit-log pointers. Runner/shim diagnostic logs are not linked from the per-trial failure unless the executor printed them. | Include audit-log path if present in trial stderr; optionally include container name and `/tmp/rst-diag.log`/runner diagnostic location when available. |
| Container cleanup hint | Container names are generated and `LITEBOX_KEEP_CONTAINER` is documented in CLAUDE.md, but failed libtest output does not mention the container name or that rerunning with `LITEBOX_KEEP_CONTAINER=1` would preserve it. | For no-JSON, teardown timeout, or IPC handshake failures, append: rerun with `LITEBOX_KEEP_CONTAINER=1` and the deterministic trial filter to inspect `docker logs`/filesystem. |

## recommended minimal improvements (ranked by effort/payoff)

1. **Always include stderr path and a short stderr tail in the libtest failure.**  
   Effort: **S**. Payoff: **high**. Update both error exits in `tests/integration.rs`: the `found.ok_or_else` no-JSON path should print both stdout and stderr paths, and `run_pass_group()` should append the last ~30 lines of the stderr log for `FAIL`. This would have made `FT.conn_readback` immediately show `Error: IPC handshake response timeout` instead of sending the operator to an empty stdout log. Keep stdout as the JSON channel; only summarize stderr in the libtest error.

2. **Standardize `TestOutcome::detail` around expected/observed/step.**  
   Effort: **S/M** for the worst offenders, **M** across the suite. Payoff: **high**. Add small helpers such as `fail_observed(agent, step, expected, observed)` or `expect_response(...)` so tests like `FT.multi_interleave_x5` report `cycle=N expected=... observed=...` instead of `5 interleaved file+TCP cycles`. The current free-form detail field is already wired through JSON and libtest, so this is mostly test-author discipline plus helper APIs.

3. **Surface poisoning and cleanup/debug hints as structured failure context.**  
   Effort: **M**. Payoff: **medium/high**. Track poisoned agents in the final result context (or append a coordinator summary line before exit) so secondary failures are labeled as fallout from an earlier timeout. If stderr contains `teardown_tree exceeded`, `IPC handshake response timeout`, or no JSON was parsed, append a hint to rerun the exact trial with `LITEBOX_KEEP_CONTAINER=1`; include the generated container name from `run_one_test()` because it is already known there (`tests/integration.rs:240-249`). This is especially useful when the broker/runner died before the coordinator could emit JSON.

4. **Fix the stdout tee/drain mismatch.**  
   Effort: **S/M**. Payoff: **medium**. Either continue teeing stdout after the matching JSON line as the comment promises, or change the comment and explicitly close stdout after result. Continuing to tee is safer for forensic completeness, but it requires the drain thread to own and drain stdout as well as wait for the child.

5. **Promote audit-log cross-reference extraction.**  
   Effort: **M**. Payoff: **medium**. When stderr contains `Audit log: ...`, copy that line into the libtest failure. This avoids making the operator open the full stderr log just to find the next diagnostic artifact. Do not require audit-log-driven debugging; per CLAUDE.md, this is only a pointer after a minimal harness failure exists.

## VS-Code-impact note

VS Code remote-server failures often present as indirect symptoms: Node child startup stalls, IPC handshakes time out, a socket server never becomes ready, or one agent times out and poisons later operations. The current harness does preserve per-trial evidence, but the first screen sometimes hides the decisive line (`IPC handshake response timeout`) or replaces expected/observed facts with a generic label. The top three improvements above would shorten the loop from "VS Code is broken under Litebox" to a self-contained failing harness capability by making the first failed Trial identify: the exact log files, the last stderr evidence, whether this is primary vs poisoned fallout, and what the test expected compared with what the agent observed.
