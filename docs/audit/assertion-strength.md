# Assertion-strength audit

Scope: all registered coordinator tests in `litebox_test_harness/src/coordinator/`, expanded through `collect_all_tests()` as reported by `cargo test -p litebox_test_harness --test integration -- --list` (1002 unique test IDs; native/litebox pass wrappers excluded).

## Bucket counts

| Primary assertion bucket | Count | Notes |
|---|---:|---|
| `substring` | 551 | Single-token/stdout substring, prefix, or equivalent stdout-marker checks. Dominated by fork/shell/pipe subcommands that print `*_OK` markers. |
| `structured` | 301 | Destructures a `Response` variant and checks named fields, exact stdout, exit code, echo payload, byte count, or parsed data. |
| `existence-only` | 119 | Only checks success-like variant presence (`Ok`, `Listening`, `UnixListening`, `Background`, `NotFound`) without validating returned payload or side effect. |
| `multi-substring` | 31 | Several stdout markers must be present (`&&`/`all(contains)`), intermediate strength. |

High-volume substring families: `XB` 51, `PB` 46, `CF` 46, `SS` 32, `CP` 28, `XDF` 25, `SC` 24, `US6` 21, `FS` 18, `SP` 18, `LB` 15, `FR` 15, `TR` 15, `KP` 15 single-substring plus 12 multi-substring.

## Ten substring samples

| Test/sample | Matched marker | Script/template source | Verdict |
|---|---|---|---|
| `XB.echo.A` | `hello_from_bash` | `bash -c "echo hello_from_bash"` in `fork_matrix.rs` | **Tautological**: marker is the script body. It only proves bash/exec/stdout did not fail. |
| `XM.script_echo` | `script_echo_ok` | creates `/tmp/xm.sh` containing `echo script_echo_ok` | **Tautological**: marker is unconditionally printed by generated script. |
| `SS.file_pipe_subst.sh.A` | `DONE` | `A=$(cat /etc/hostname | cat); echo A=$A; echo DONE` | **Tautological**: `DONE` is printed even if substitution returns empty/non-semantic output. |
| `SS.vscode_osrelease.bash.AA` | `DONE` | `ID=$(cat /etc/os-release ...); echo ID=$ID; echo DONE` | **Tautological**: does not assert the parsed `ID`; only script reaches the final echo. |
| `BASH.fork_bg_fg.A` | `BG_FG_OK` | `sleep 0.1 & cat /etc/hostname > /dev/null; echo BG_FG_OK` | **Tautological**: final echo is not guarded by `&&` or output validation. |
| `X.echo.NP` | `ECHO_TEST_OK` | harness `echo-test` subcommand prints `ECHO_TEST_OK` | **Tautological-ish canary**: useful as exec/stdout smoke, but marker itself is unconditional. |
| `CP.simple.sh.A` | `CP_OK` | `capture-pipe` subcommand | **Conditional**: `CP_OK` prints only after parent captures `CAPTURE_OK` from child pipe output. |
| `FS.write-read.tmp` | `FS_OK` | `fs-test io write-read` | **Conditional**: `FS_OK` prints only after readback equals expected bytes. |
| `PB.c2p.pie.A` | `PB_C2P_OK` | `pipe-test extra-pipe-c2p` | **Conditional**: marker requires child data over extra pipe and zero child exit. |
| `KP.ppid_proc.A` | `ppid_proc=true` | `{exe} proc-probe ...; cat output` | **Conditional**: marker is a boolean emitted from `/proc/<ppid>` visibility logic. |

## Benchmark/control families

- `KP.*`: 27 tests. The newer `proc_child`, `proc_self`, `kill0_many`, and `parent_monitor` cases use multi-marker checks; single-marker `ppid_*` cases still rely on booleans from `proc-probe`. These are mostly conditional and VS-Code-relevant, but would be stronger if they parsed pid/cmdline fields instead of grepping `true`.
- `KPX.*`: 9 tests, all **multi-substring** (`PROC_DIR_OK`, `litebox_test_harness`, `KILL0_OK`). Good control sample for cross-agent `/proc` visibility; still marker-based but non-tautological.
- `TLB.*`: 5 tests, all **structured**: bind ephemeral port, delay, connect, assert `Response::Connected { echo } == payload`. This is the bar for TCP regressions.
- `THC.*`: 4 tests, all **structured**: assert `Response::HalfClosed { echo } == payload`. Good benchmark for half-close behavior.
- `XSI.*`: 4 tests: 3 exact/exit-code structured assertions, 1 multi-substring (`fork_exec`) over three axes. Stronger than the older `SS.*` stdin-script checks.

## Tautological / low-signal assertion list

Prioritize these for hardening because they print the matched token unconditionally or accept too-broad outcomes:

1. `SS.file_pipe_subst.*` and `SS.vscode_osrelease.*` (8 tests): match final `DONE`, not command-substitution result.
2. `BASH.fork_bg_fg.*` (2 tests): final `BG_FG_OK` is printed after `cat` regardless of `cat` success.
3. `BASH.fork_subst.*` (2 tests, prefix-style): `HOST=` passes even when substitution is empty.
4. `XM.script_echo` and similar generated-script echo cases (`XM.script_node`, `XM.nested_bash_node`, `XM.script_exec_node`): marker is the payload.
5. Simple exec canaries (`X.echo.*`, several `XB.echo`/literal-echo patterns): useful smoke coverage, but low mutation resistance.
6. Permissive probes (`TERM.*`, `X48.node_networkInterfaces`): pass on either success or error marker; they detect hangs/crashes but not capability correctness.
7. Existence-only setup tests (`N.*.listen`, `U.*.listen`, several `XW*.listen/spawn/write`, `F.unlink.*.delete`, `F.tmp.*.isolation`): success variant only; no payload/side-effect verification.

## Recommended hardening order (VS-Code impact first)

1. **Stdin/script substitution: `SS.*`, `XSI.fork_exec` parity** — VS Code install/bootstrap scripts depend on shell substitution and pipelines. Replace `DONE` checks with exact stdout including substituted value and exit/stderr checks.
2. **Process/proc visibility: `KP.*`, `KPX.*`, permissive `PROC` neighbors** — Node/VS Code probe `/proc/self`, parent pid, and `kill -0`. Convert boolean-marker greps into structured pid/cmdline/ppid assertions where possible.
3. **Pipe/stdio bridge: `PB.*`, `P1/P2`, `CP.*`** — code-server/ptyHost IPC is pipe-heavy. Prefer subcommands that return counts/direction/EOF state as structured data, not only `*_OK` markers.
4. **Bash/fork pipeline matrix: `XB.*`, `XM.*`, `XDF.*`, `CF.*`, `BASH.*`** — important for npm/VS Code shell scripts. Keep smoke tests, but add semantic assertions for transformed output, stderr, exact line counts, and failure modes.
5. **Cross-worker socket/TCP controls** — `TLB`, `THC`, `TC`, `TD`, `TRR`, `TW` are already comparatively strong; use their echo-payload style as templates for older `LB`, `EP`, and `XW` substring/existence tests.

No source files were modified for this audit.
