# Bash/sh wrapper census

Scope: `script_template:` definitions in `litebox_test_harness/src/coordinator/`, plus coordinator `Exec`/`super::exec` callsites that invoke `bash -c`, `sh -c`, `/bin/sh -c`, or shell-on-stdin helpers. Counts below are table rows/callsites (or individual `script_template` definitions), not expanded agent-matrix test instances.

Category key:

- **(a)** testing bash/sh-specific behavior; legitimate under `litebox_test_harness/CLAUDE.md` rule 2.
- **(b)** wrapping a live `litebox_test_harness` subcommand; migrate toward protocol-only where possible.
- **(c)** wrapping `cat /proc/...`, `kill -0`, `dd`, `uname`, or similar simple syscall-probing utilities; borderline.
- **(d)** other shell use/setup glue.

## Census table

| test ID prefix | callsite (`file:line`) | category | subcommand (if b) | recommendation |
|---|---|---:|---|---|
| `CF.pipe{2,3,4}*`, `CF.sequential_control.{A,AA,B}` | `litebox_test_harness/src/coordinator/concurrent_fork.rs:102` | (a) | — | Keep as an explicit bash-pipeline/concurrent-fork stressor; it models VS Code install-script fork pressure. |
| `CF.pipe4_vscode.{NP,D4}` | `litebox_test_harness/src/coordinator/concurrent_fork.rs:140` | (a) | — | Keep as non-PIE/depth coverage for the same pipeline pressure. |
| `CF.sequential_control.{NP,D4}` | `litebox_test_harness/src/coordinator/concurrent_fork.rs:178` | (d) | — | Consider replacing with direct `Exec` commands or a protocol setup command; this is control glue, not bash behavior. |
| `CF.concurrent_exec_{2,3,4}.*` | `litebox_test_harness/src/coordinator/concurrent_fork.rs:226` | (b) | `echo-test` | Add protocol support for parallel/background exec joins so concurrent child-spawn behavior is tested without `bash & wait`. |
| `CF.vscode.proc_*`, `CF.vscode.uname_pipeline.*` | `litebox_test_harness/src/coordinator/concurrent_fork.rs:293` | (c) | — | High VS Code relevance, but add protocol probes for `/proc/*` and `uname`; keep one install-pipeline smoke test if desired. |
| `XB.*` | `litebox_test_harness/src/coordinator/fork_matrix.rs:370` | (a) | — | Keep: this family explicitly exercises bash constructs, pipes, substitutions, background jobs, heredocs, herestrings, and subshells. |
| `XM.script_echo`, `XM.script_node`, `XM.script_env_shebang`, `XM.script_cat_pipe`, `XM.nested_bash_node`, `XM.script_exec_node` | `litebox_test_harness/src/coordinator/fork_matrix.rs:473` | (a) | — | Keep as shell/script/shebang/nested-bash execution-method coverage. |
| `XM.script_self_exe` | `litebox_test_harness/src/coordinator/fork_matrix.rs:473` | (b) | `echo-test` | Split from `XM` or migrate to direct protocol exec plus a separate script/shebang-only test. |
| `XDF.*.script.*` | `litebox_test_harness/src/coordinator/fork_matrix.rs:610` | (b) | `trigger-delayed-fork`, `trigger-delayed-fork-thread`; inner `echo-test` | Top migration target: script-file invocation is useful, but delayed-fork capability should be expressible through protocol without a generated bash wrapper. |
| `XNP.script`, `XNP.bash_inline` | `litebox_test_harness/src/coordinator/fork_matrix.rs:739` | (b) | `echo-test` | Keep only if validating shell invocation of non-PIE; otherwise use direct exec/protocol for non-PIE child coverage. |
| `XC.child_clean`, `XC.child_sequential`, `XC.grandchild_nonpie`, `XC.depth2_clean` | `litebox_test_harness/src/coordinator/fork_matrix.rs:829` | (b) | `echo-test` | Replace contamination sequencing with protocol-level ordered execs where possible; keep one nested-bash case only if it specifically targets bash process ancestry. |
| `S.dir.read_through` | `litebox_test_harness/src/coordinator/matrix.rs:1311` | (d) | — | Use protocol filesystem setup if/when mkdir/write helpers exist; otherwise prefer direct `mkdir`/`tee` without bash. |
| `BASH.fork_ls.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:746` | (a) | — | Keep: named bash fork+exec coverage. |
| `BASH.fork_subst.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:775` | (a) | — | Keep: named bash command-substitution coverage. |
| `BASH.fork_bg_fg.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:804` | (a) | — | Keep: named bash background/foreground coverage. |
| `SP.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1116` | (a) | — | Shell-on-stdin helper; keep if the intent is stdin script semantics, but this is outside the requested `-c` shape. |
| `CWF.seq.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1161` | (b) | `cross-worker-file write-and-exit` | Replace with a protocol cross-worker write/exit primitive or direct exec of the subcommand without bash. |
| `CWF.self_open.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1334` | (b) | `cross-worker-file write-and-hold` | Replace bash background/sleep/cat/signal cleanup with protocol background exec plus `FsRead` and signal-driven synchronization. |
| `CWF.redirect_stdout.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1383` | (b) | `cross-worker-file write-stdout` | Same as above; useful file-visibility signal, but bash timing and redirection hide the capability boundary. |
| `CWF.redirect_exit.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1431` | (b) | `echo-test` | Use direct exec with protocol stdout capture or protocol file write. |
| `CWF.builtin_redirect.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1476` | (d) | — | Convert to `FsWrite`/`FsRead` if testing file coherence rather than shell redirection. |
| `SC.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1570` | (a) | — | Keep if this family is intentionally shell command-substitution/path-discovery coverage. |
| `CC.echo.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1603` | (a) | — | Keep only as shell substitution coverage; otherwise protocol `FsWrite` is cleaner. |
| `CC.fork_exec.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1608` | (b) | `echo-test` | Migrate to direct/background protocol exec; the useful signal is child exec and file visibility, not bash. |
| `CC.pipe_capture.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1613` | (a) | — | Keep if pipeline capture is the target. |
| `CC.file_write.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1618` | (d) | — | Replace with `FsWrite`; this is simple setup via shell. |
| `TR.no_touch.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1689` | (b) | `echo-test` | Migrate to protocol file creation/exec/stdout capture; current fixed delay is timer-driven. |
| `TR.touch.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1699` | (b) | `echo-test` | Same as `TR.no_touch`; use protocol sync instead of bash job control. |
| `TR.touch_chmod.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1709` | (b) | `echo-test` | Same; direct chmod/exec protocol would make the assertion sharper. |
| `TR.echo_touch.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1719` | (b) | `echo-test` | Same; use `FsWrite` for initial contents. |
| `TR.builtin_touch.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1729` | (d) | — | Replace shell builtin redirect with protocol file operations if the target is coherence. |
| `KP.kill0_bg.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1792` | (c) | — | Add protocol liveness probe (`Kill { signal: 0 }`/`GetPid`-style) instead of shell signal-0. |
| `KP.kill0_many.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1802` | (c) | — | Same; this is process-liveness plus utility churn, not bash semantics. |
| `KP.proc_child.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1818` | (c) | — | Add protocol `/proc/<pid>/cmdline` read/metadata assertion. |
| `KP.proc_self.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1831` | (b) | `proc-probe` | Migrate `proc-probe` to a protocol command or structured response; `/proc/self/*` is VS Code/Node relevant. |
| `KP.ppid_proc.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1845` | (b) | `proc-probe` | Same; expose ppid `/proc` observations structurally. |
| `KP.ppid_kill0.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1854` | (b) | `proc-probe` | Same; separate liveness probe from shell wrapper. |
| `KP.ppid_cmdline.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1863` | (b) | `proc-probe` | Same. |
| `KP.getppid_correct.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1872` | (b) | `check-ppid` | Return parent/child pid data through protocol instead of comparing shell output. |
| `KP.parent_monitor.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:1891` | (b) | `proc-probe` | Same; high value because process metadata affects VS Code server supervision. |
| `KPX.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:2016` | (c) | — | Replace `/bin/sh -c` observer with protocol operations for `/proc/<pid>/cmdline` and signal-0. |
| `FR.fg_redirect.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:2088` | (d) | — | Use `FsWrite`/`FsRead` unless shell redirection itself is the target. |
| `FR.bg_echo.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:2093` | (d) | — | If background shell behavior is not the target, use protocol background exec and file operations. |
| `FR.bg_exe.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:2098` | (b) | `echo-test` | Migrate to protocol background exec with stdout redirection modeled explicitly. |
| `FR.bg_cat_pipe.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:2103` | (d) | — | Keep only if pipe+redirect behavior is intentional; otherwise use protocol file write/read. |
| `FR.bg_append.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:2108` | (d) | — | Replace with protocol append/write if available. |
| `LB.same_worker.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:2367` | (b) | `tcp-echo` | Top migration target: express loopback server/client, readiness, and shutdown through protocol rather than bash+`nc`+fixed delay. |
| `LB.localhost.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:2378` | (b) | `tcp-echo` | Same; relevant to Node/VS Code server listen/connect. |
| `LB.any_to_local.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:2389` | (b) | `tcp-echo` | Same. |
| `LB.fast_close.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:2400` | (b) | `tcp-recv-all` | Same; half-close/EOF propagation should be protocol-driven. |
| `LB.halfclose_eof.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:2411` | (b) | `tcp-recv-all` | Same; direct VS Code/Node impact. |
| `PROC.stat_seekable.*` | `litebox_test_harness/src/coordinator/platform_fixes.rs:2704` | (c) | — | Replace `sh -c 'dd ... | wc -c'` with a structured proc/lseek probe. |
| `XSI.*` | `litebox_test_harness/src/coordinator/special_cases.rs:628` | (a) | — | Shell-on-stdin helper; keep as POSIX shell script semantics coverage. |
| `SS.*` | `litebox_test_harness/src/coordinator/special_cases.rs:521` | (a) | — | Shell-on-stdin helper; keep if stdin script parsing is the target. |
| `X57.pipe_churn_then_nonpie` | `litebox_test_harness/src/coordinator/special_cases.rs:1814` | (d) | — | Replace the repeated bash churn with a protocol/direct-exec churn primitive if the useful signal is later non-PIE cleanliness. |

## Live subcommand cross-reference for category (b)

All category (b) rows reference subcommands still present in `litebox_test_harness/src/main.rs` after the recent orphan deletions:

| subcommand | main.rs line | category (b) test families using it |
|---|---:|---|
| `echo-test` | `litebox_test_harness/src/main.rs:129` | `CF.concurrent_exec`, `XM.script_self_exe`, `XNP`, `XC`, `CC.fork_exec`, `TR.*`, `CWF.redirect_exit`, `FR.bg_exe` |
| `trigger-delayed-fork` | `litebox_test_harness/src/main.rs:1560` | `XDF.*.script.*` |
| `trigger-delayed-fork-thread` | `litebox_test_harness/src/main.rs:1586` | `XDF.*.script.*` |
| `cross-worker-file` | `litebox_test_harness/src/main.rs:1640` | `CWF.seq`, `CWF.self_open`, `CWF.redirect_stdout` |
| `slow-echo` | `litebox_test_harness/src/main.rs:1160` | Used by category (c) `KP.kill0_*`/`KP.proc_child` shell probes |
| `proc-probe` | `litebox_test_harness/src/main.rs:1299` | `KP.proc_self`, `KP.ppid_proc`, `KP.ppid_kill0`, `KP.ppid_cmdline`, `KP.parent_monitor` |
| `check-ppid` | `litebox_test_harness/src/main.rs:1285` | `KP.getppid_correct` |
| `tcp-echo` | `litebox_test_harness/src/main.rs:792` | `LB.same_worker`, `LB.localhost`, `LB.any_to_local` |
| `tcp-recv-all` | `litebox_test_harness/src/main.rs:875` | `LB.fast_close`, `LB.halfclose_eof` |

Other live self-exe subcommands relevant to VS Code but not wrapped by coordinator `bash -c` in this census include `tcp-fork-listen-accept` (`main.rs:720`) for fd inheritance, `epoll-socket` (`main.rs:1011`), `capture-pipe` (`main.rs:1368`), `stdin-script` (`main.rs:1378`), and `stress-exec` (`main.rs:1389`).

## Summary counts

| category | row count | notes |
|---|---:|---|
| (a) bash/sh-specific behavior | 13 | Mostly explicit shell matrices (`XB`, `BASH`, `SC`, shell-on-stdin helpers) and intentional pipeline stressors. |
| (b) self-exe subcommand wrapper | 26 | Largest bucket; many can become protocol-only or direct protocol exec with structured synchronization. |
| (c) simple syscall/proc utility wrapper | 6 | `/proc`, signal-0, `dd`, `uname`/install-pipeline probes; high VS Code relevance but currently shell-shaped. |
| (d) other shell/setup glue | 10 | File setup, control churn, and redirect helpers that are not inherently bash-specific. |
| **total** | **55** | Counts are grouped rows/callsites, not expanded test IDs per agent. |

## Top migration candidates by VS Code impact

1. **`LB.*` loopback TCP (`tcp-echo`, `tcp-recv-all`)** — Node and the VS Code remote server depend on listen/connect, EOF, and half-close behavior. Replace `bash`+`nc`+fixed delays with protocol server/client commands and readiness barriers.
2. **`XDF.*.script.*` delayed-fork wrappers** — delayed fork after mmap/thread setup mirrors VS Code/Node child-process pressure. Preserve script-file coverage separately, but make the delayed-fork capability protocol-expressible.
3. **`KP.*`/`KPX.*` `/proc` and signal-0 probes** — VS Code, sshd, and Node all inspect process metadata/liveness. Move `proc-probe`, ppid checks, cmdline reads, and signal-0 checks to structured protocol responses.
4. **`CF.vscode.*` install pipelines** — directly modeled after VS Code install-script `/proc` pipelines. Add protocol probes for the underlying `/proc` reads and keep at most one end-to-end shell pipeline smoke test.
5. **`CWF.*`/`TR.*`/`FR.bg_exe` file/redirect background wrappers** — file visibility, stdout redirection, and background-process synchronization matter to installers and server startup, but current wrappers use fixed delays, `cat`, and shell job control. Migrate to protocol background exec, `FsRead/FsWrite`, and signal-driven readiness.
