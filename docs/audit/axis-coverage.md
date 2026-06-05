# Test harness axis coverage audit

Scope: every test ID registered by `litebox_test_harness::coordinator::collect_all_tests()` on branch `wportnoy/test-framework-audit`. Discovery used `cargo test -q -p litebox_test_harness --test integration -- --list`, which reported 1002 native IDs (2004 native+litebox trials). Static axis inference used `cx.require(...)`, matrix topology constants, and `RunContext::forward(...)`/`Forward` targets in `litebox_test_harness/src/coordinator/`.

Axes are from `litebox_test_harness/CLAUDE.md` rule 4: in-process, parent→child, child→parent, sibling/cousin, and depth ≥2. A check means the family has at least one registered test that exercises that topology for the family capability; it does not imply every case is fully cross-producted.

## Summary

- Families: **63**
- Test IDs: **1002**
- Actionable missing-axis cells: **146**
- Strong all-axis families: **NA, UA, S, U, TLB, KPX, XW**

## Family axis table

| family | tests | in-process | parent→child | child→parent | sibling/cousin | depth ≥2 | reason if single-axis is OK / notes | recommended axis to add |
|---|---:|:---:|:---:|:---:|:---:|:---:|---|---|
| `X_` | 1 (`X_canary.pre_sequence` … `X_canary.pre_sequence`) | ✓ | ✗ | ✗ | ✗ | ✗ | Canary intentionally only proves sequencing/contamination at test start. | None; single-axis is OK. |
| `NL` | 9 (`NL1.netlink_socket` … `NL6.mac_address`) | ✓ | ✗ | ✗ | ✗ | ✗ | Netlink interface queries are local kernel API probes. | Add AA/B/D4 variants because Node os.networkInterfaces can run in child workers. |
| `X` | 29 (`X48.node_networkInterfaces` … `X59.sequential_nonpie`) | ✓ | ✓ | ✗ | ✗ | ✓ | Exec/Node smoke spans A/AA/AAA/NP/NPC/D5 but remains per-agent. | Add sibling/cross-worker Node exec under load. |
| `CF` | 61 (`CF.pipe2_cat.A` … `CF.rwlock_multi_6.B`) | ✓ | ✓ | ✗ | ✗ | ✓ | Local process-pipeline stress per worker; no inter-agent data path. | Add one sibling/cross-worker pipeline with producer on one agent and consumer on another, if protocol can express it. |
| `NET` | 5 (`NET1.ipv6_socket` … `NET6.ipv6_v6only`) | ✓ | ✗ | ✗ | ✗ | ✗ | IPv4/IPv6 socket option tests are local. | Add AA/B/D4 matrix for getaddrinfo and listen. |
| `TERM` | 15 (`TERM.tcgets_fd0` … `TERM.tiocgwinsz_fd2`) | ✓ | ✗ | ✗ | ✗ | ✗ | Termios fd probes are init stdio-only; agent topology is not meaningful until PTY support exists. | After PTY protocol exists, add pty handover across parent/child. |
| `EX` | 4 (`EX6.node_version_exit` … `EX9.node_console_exit`) | ✓ | ✗ | ✗ | ✗ | ✗ | Node process exit smoke is single-agent only. | Add A/AA/B/D4 matrix. |
| `FS` | 18 (`FS.write-read.tmp` … `FS.open_nonpie_fs-exec.txt`) | ✓ | ✗ | ✗ | ✗ | ✗ | Legacy fs script tests are one-agent smoke tests and overlap with matrix F. | Prefer extending F; otherwise add parent↔child. |
| `CP` | 28 (`CP.simple.sh.A` … `CP.subshell_continue.bash.AA`) | ✓ | ✓ | ✗ | ✗ | ✗ | Shell capture is local, but only A/AA coverage leaves B and deep workers untested. | Add B and D4/D5 shell-capture variants. |
| `SS` | 32 (`SS.cmd_subst.sh.A` … `SS.backtick_pipe.bash.AA`) | ✓ | ✓ | ✗ | ✗ | ✗ | Shell substitution is local; A/AA only. | Add B and D4. |
| `XSI` | 4 (`XSI.stdin_script.simple` … `XSI.stdin_script.fork_exec`) | ✓ | ✓ | ✗ | ✗ | ✓ | XSI stdin script registers A, AA, and an ephemeral fork target, but not sibling/cross. | Add sibling/cousin stdin-script execution. |
| `F` | 73 (`F.shared.parent_to_child.absent` … `F.host.AA`) | ✗ | ✓ | ✓ | ✓ | ✓ | Shared filesystem CRUD intentionally stresses cross-agent visibility rather than same-agent CRUD. | Add one in-process baseline for each operation to localize failures. |
| `N` | 36 (`N.init_to_A.listen` … `N.D5_to_B.unlisten`) | ✗ | ✓ | ✓ | ✓ | ✓ | Network listener/connector matrix is intentionally cross-agent; no same-agent baseline in this family. | Add same-agent A and D4 rows or rely on LB/NA. |
| `NA` | 30 (`NA.A_to_A.127.0.0.1` … `NA.A_to_NP.self_ip`) | ✓ | ✓ | ✓ | ✓ | ✓ | Address matrix covers same-agent, parent/child, sibling/cross, non-PIE, and deep D* pairs. | None. |
| `UA` | 10 (`UA.A_to_A` … `UA.A_to_NP`) | ✓ | ✓ | ✓ | ✓ | ✓ | Unix address matrix includes same, A↔AA, A↔B, D* depth, and NP directions. | None. |
| `E` | 18 (`E.HOME.A` … `E.CWD.D5`) | ✓ | ✓ | ✗ | ✗ | ✓ | Environment/CWD/HOME are per-process observations; cross-agent direction is mostly not meaningful. | Optional: add B to AAA comparison only if env inheritance differs by subtree. |
| `S` | 25 (`S.basic.in_process.create` … `S.relative.read_through`) | ✓ | ✓ | ✓ | ✓ | ✓ | Symlink matrix covers same, parent↔child, sibling, and grandchild-up. | None. |
| `U` | 35 (`U.in_process.A.listen` … `U.repro.cross_worker`) | ✓ | ✓ | ✓ | ✓ | ✓ | Unix socket matrix covers same-agent, fork child, parent↔grandchild, sibling, cross-subtree and D* cross-worker cases. | None. |
| `POLL` | 3 (`POLL.pipe.A` … `POLL.pipe.B`) | ✓ | ✓ | ✗ | ✗ | ✗ | Poll-ready is local pipe readiness. | Add D4 and socketpair/cross-worker readiness. |
| `GSN` | 4 (`GSN.ipv4.A` … `GSN.ipv6.AA`) | ✓ | ✓ | ✗ | ✗ | ✗ | getsockname is local socket state. | Add B and D4 only if bind behavior differs by worker. |
| `PID` | 3 (`PID.A` … `PID.B`) | ✓ | ✓ | ✗ | ✗ | ✗ | Pipe pair-id uniqueness is local allocator state. | Add D4/NP allocator cases if collisions are worker-local. |
| `EXITD` | 12 (`EXITD.256.pie.A` … `EXITD.65536.nonpie.AA`) | ✓ | ✓ | ✗ | ✗ | ✗ | Exit data integrity is local to a launcher agent. | Add B and D4/NP variants. |
| `NPIPE` | 12 (`NPIPE.seq.x1.A` … `NPIPE.interleaved.x10.AA`) | ✓ | ✓ | ✗ | ✗ | ✗ | Non-PIE pipe chain is local to launcher. | Add B, NP, and D4 launcher variants. |
| `XCONN` | 7 (`XCONN.cross_first` … `XCONN.sibling_AB`) | ✓ | ✓ | ✓ | ✓ | ✗ | Cross-worker first-connect covers same, parent_child, child_parent, sibling, and deep_cross AA↔B but lacks true depth ≥2 like D4/D5. | Add D4↔D5 or B↔AAA first-connect. |
| `TLB` | 5 (`TLB.listen_busy.same_agent` … `TLB.listen_busy.depth2`) | ✓ | ✓ | ✓ | ✓ | ✓ | Listen-busy covers all named axes including parent_child, child_parent, sibling, depth2. | None. |
| `BASH` | 6 (`BASH.fork_ls.A` … `BASH.fork_bg_fg.B`) | ✓ | ✗ | ✗ | ✗ | ✗ | Bash-specific fork smoke currently only targets root workers A/B; not OK for VS Code shell trees. | Add AA and D4 variants; then one A↔B cross-connect if relevant. |
| `FWE` | 4 (`FWE.nonpie_from_init` … `FWE.nonpie_from_worker_exec`) | ✓ | ✗ | ✗ | ✗ | ✗ | Fork/worker exec launch source is init or a single worker; cross-agent is not the core behavior. | Add D4 worker-exec launcher. |
| `M` | 20 (`M1.A` … `M4.D5`) | ✓ | ✓ | ✗ | ✗ | ✓ | Non-PIE spawn survival is local to a launcher agent and already spans deep D* launchers. | Add sibling background load while D4 spawns non-PIE. |
| `BS` | 15 (`BS1.A` … `BS3.D5`) | ✓ | ✓ | ✗ | ✗ | ✓ | Single-agent non-PIE stdio bridge shape; direction is inside spawned child, but topology still misses sibling pressure. | Add B/NP cross-worker or sibling launcher after non-PIE spawn. |
| `SP` | 18 (`SP.simple.A` … `SP.os_detect.B`) | ✓ | ✓ | ✗ | ✗ | ✗ | stdin pipe substitution is local shell behavior. | Add D4 and B variants. |
| `CWF` | 21 (`CWF.seq.A` … `CWF.builtin_redirect.B`) | ✓ | ✓ | ✗ | ✗ | ✗ | Despite the name, these are per-agent cross-worker-file cases over A/AA/B. | Add true A→B and D4→B file handoff cases. |
| `SC` | 24 (`SC.echo.A` … `SC.uname.B`) | ✓ | ✓ | ✗ | ✗ | ✗ | Command substitution is shell-local. | Add D4 and B or rely on XB for broader depth. |
| `CC` | 12 (`CC.echo.A` … `CC.file_write.B`) | ✓ | ✓ | ✗ | ✗ | ✗ | Concurrent fork is local to one agent, but VS Code can trigger it below deeper workers. | Add D4/D5 concurrent fork variants. |
| `TR` | 15 (`TR.no_touch.A` … `TR.builtin_touch.B`) | ✓ | ✓ | ✗ | ✗ | ✗ | Touch/redirection is local shell/fs behavior. | Add D4 and cross-agent readback. |
| `KP` | 27 (`KP.kill0_bg.A` … `KP.parent_monitor.B`) | ✓ | ✓ | ✗ | ✗ | ✗ | Local pid/proc semantics include child processes but not cross-agent observation. | Covered better by KPX; add D4 local proc if needed. |
| `KPX` | 9 (`KPX.cross.same_agent.A.to.A` … `KPX.cross.cross_subtree.B.to.AAA`) | ✓ | ✓ | ✓ | ✓ | ✓ | Full cross-agent pid/proc matrix includes same, both directions, siblings, depth, and cross-subtree. | None. |
| `FR` | 15 (`FR.fg_redirect.A` … `FR.bg_append.B`) | ✓ | ✓ | ✗ | ✗ | ✗ | Redirection is local shell/file-descriptor behavior. | Add D4 and one sibling-visible file check. |
| `PN` | 18 (`PN.A.setfl` … `PN.child.AA.eof`) | ✓ | ✓ | ✗ | ✗ | ✗ | Nonblocking pipe tests include local child pipe cases but no inter-agent pipe path. | Add D4 and explicit parent↔child variants. |
| `EP` | 12 (`EP.direct.accept.A` … `EP.tokio.read.B`) | ✓ | ✓ | ✗ | ✗ | ✗ | Epoll socket readiness is local to a worker; VS Code event loops also run in child/deep workers. | Add D4/D5 and cross-agent listener/connector readiness variants. |
| `LB` | 15 (`LB.same_worker.A` … `LB.halfclose_eof.B`) | ✓ | ✓ | ✗ | ✗ | ✗ | Loopback smoke is per-agent only. | Add A↔B, A↔AA, D4↔D5 loopback variants or fold into N/NA. |
| `THC` | 4 (`THC.halfclose.eof.same_agent` … `THC.halfclose.eof.depth2`) | ✓ | ✓ | ✗ | ✓ | ✓ | Half-close EOF covers same, cross_agent, sibling, and depth2 but not reverse parent/child. | Add child→parent direction. |
| `FKLC` | 2 (`FKLC.listen_unlisten` … `FKLC.cross_connect`) | ✓ | ✗ | ✗ | ✓ | ✗ | Raw fd-inheritance pattern currently bypasses the agent protocol, so full topology matrix is not expressible yet. | Implement Fork.inherit_listen_ports, then add parent↔child and depth-2. |
| `PROC` | 9 (`PROC.self_stat.A` … `PROC.uptime.B`) | ✓ | ✓ | ✗ | ✗ | ✗ | /proc/self and uptime are local reads; cross-pid is KPX. | Add D4 and route cross-pid expectations to KPX. |
| `SK` | 3 (`SK.subtree.direct_nonpie` … `SK.subtree.exit_then_kill`) | ✗ | ✓ | ✗ | ✗ | ✓ | Subtree termination is intentionally rooted at E/EE; sibling/cousin is less meaningful. | Add surviving sibling assertion if E has an adjacent sibling in the termination tree. |
| `XB` | 54 (`XB.echo.A` … `XB.xargs.AAA`) | ✓ | ✓ | ✗ | ✗ | ✓ | Bash pattern matrix spans A/AA/AAA but no cross-agent flow. | Add B/D4 and one cross-worker pipeline if possible. |
| `XM` | 8 (`XM.script_echo` … `XM.node_networkInterfaces`) | ✓ | ✗ | ✗ | ✗ | ✗ | Exec-method cases are A-only local smoke. | Add A/AA/B/D4 matrix for Node/networkInterfaces methods. |
| `XDF` | 25 (`XDF.mmap.pie.direct.A` … `XDF.triple_nesting`) | ✓ | ✓ | ✗ | ✗ | ✗ | Delayed fork matrix is local to A/AA plus nested process-internal fork. | Add D4 and sibling background pressure. |
| `XS` | 6 (`XS.pie.sync` … `XS.mixed.tokio`) | ✓ | ✗ | ✗ | ✗ | ✗ | Stress exec is A-only and process-local. | Add AA/B/D4 launchers. |
| `XNP` | 3 (`XNP.direct` … `XNP.bash_inline`) | ✓ | ✗ | ✗ | ✗ | ✗ | Non-PIE invocation is A-only. | Add AA/B/D4 launchers. |
| `XC` | 5 (`XC.init_level` … `XC.depth2_clean`) | ✓ | ✓ | ✗ | ✗ | ✓ | Contamination cases are local/depth-focused by design. | Add sibling survivor/contamination check. |
| `US` | 26 (`US1.cross_process_unix` … `US6.socketpair_nonpie.B`) | ✓ | ✓ | ✗ | ✗ | ✓ | Unix special cases mostly execute within one agent but span A/AA/B/D*/NP launchers. | Add explicit A↔B and parent↔child Unix special cases. |
| `VS` | 1 (`VS1.socket_race` … `VS1.socket_race`) | ✓ | ✗ | ✗ | ✗ | ✗ | VS socket-race is a focused single-process repro. | Add child/deep launcher once the race is stable. |
| `UF` | 3 (`UF.fork_unix.A` … `UF.fork_unix.B`) | ✓ | ✓ | ✗ | ✗ | ✗ | Unix fork tests are local to A/AA/B. | Add D4 and cross-agent Unix socket handoff. |
| `XW` | 24 (`XW.spawn_remote` … `XW11.r2_tcp_connect`) | ✓ | ✓ | ✓ | ✓ | ✓ | Cross-worker suite covers local/remote reads, listens/connects, D3/D4, B, and late-spawn depth. | None. |
| `P` | 12 (`P1.pipe_eof_fork.A` … `P2.pipe_eof_exec_nonpie.B`) | ✓ | ✓ | ✗ | ✗ | ✓ | Pipe EOF is local fork/exec behavior but already covers deep launchers. | Add cross-agent reader/writer if protocol can expose pipe endpoints. |
| `PB` | 46 (`PB.c2p.pie.A` … `PB.epoll_sp.nonpie.B`) | ✓ | ✓ | ✓ | ✗ | ✓ | Pipe/socketpair bridge coverage is child↔parent inside one process tree; no sibling/cousin IPC topology. | Add sibling/cousin parent process with extra-pipe child to mimic VS Code ptyHost across workers. |
| `TC` | 10 (`TC.in_process.x2.d0` … `TC.depth2_delayed.x5.d10`) | ✓ | ✗ | ✗ | ✓ | ✓ | TCP concurrency covers same-agent, sibling, and AA/AB depth-2 but not parent↔child direction. | Add A↔AA parent/child both directions. |
| `TD` | 8 (`TD.1K.in_process` … `TD.256K.sibling`) | ✓ | ✗ | ✗ | ✓ | ✓ | TCP data-size covers same, sibling, and cross-subtree, not direct parent↔child. | Add A↔AA and AA↔A data-size variants. |
| `TRR` | 4 (`TRR.x5.in_process` … `TRR.x20.sibling`) | ✓ | ✗ | ✗ | ✓ | ✗ | Reconnect stress covers same and root sibling only. | Add parent↔child and depth-2 reconnect cases. |
| `TF` | 3 (`TF.A` … `TF.B`) | ✓ | ✓ | ✗ | ✗ | ✗ | Full-duplex currently starts client and server within the same agent. | Add A↔B and D4↔D5 full-duplex. |
| `TW` | 6 (`TW.remote_listen.x1` … `TW.local_listen.x5`) | ✗ | ✓ | ✓ | ✗ | ✗ | Remote/local listen uses A plus ephemeral non-PIE child; good for parent↔child only. | Add sibling and D4/D5 remote-listen variants. |
| `FT` | 19 (`FT.listen_write.A` … `FT.echo_after_exec`) | ✓ | ✗ | ✗ | ✓ | ✗ | File+TCP deadlock repro has same-agent and A/B cross only. | Add parent↔child and D4/D5 file+TCP cases. |
| `PR` | 11 (`PR.fork_exec.A` … `PR.child_listen_cross`) | ✓ | ✓ | ✗ | ✓ | ✗ | Port-router tests cover A/B and ephemeral child, but not deeper fork-tree owners. | Add D4/D5 inherited-listener and child→parent/cousin connect cases. |

## Top axis-coverage gaps ranked by VS Code impact

1. **`PB`** — Extra-pipe/socketpair bridge is closest to VS Code `child_process.fork()`/ptyHost IPC. It covers child↔parent inside one launched process, but not sibling/cousin worker topology. Recommended: Add sibling/cousin parent process with extra-pipe child to mimic VS Code ptyHost across workers.
2. **`PR`** — Port-router/fd-inheritance is the documented VS Code listen-socket handoff pattern. It lacks depth ≥2 and child→parent/cousin inheritance cases. Recommended: Add D4/D5 inherited-listener and child→parent/cousin connect cases.
3. **`EP`** — Node and VS Code event loops depend on epoll readiness. Current tests are local A/AA/B only, not cross-worker or D4/D5. Recommended: Add D4/D5 and cross-agent listener/connector readiness variants.
4. **`FT`** — File+TCP deadlock pressure is VS Code-relevant; current coverage has same-agent and A/B cross but no parent↔child/deep matrix. Recommended: Add parent↔child and D4/D5 file+TCP cases.
5. **`TRR`** — Reconnect stress catches port-router/address-table churn, but only same-agent and root sibling are covered. Recommended: Add parent↔child and depth-2 reconnect cases.
6. **`TF`** — Full-duplex transfer is local-only; VS Code socket traffic should include A↔B and D4↔D5. Recommended: Add A↔B and D4↔D5 full-duplex.
7. **`TW`** — Remote/local listen tests cover A↔ephemeral non-PIE parent/child, but not sibling or stable depth-2 worker paths. Recommended: Add sibling and D4/D5 remote-listen variants.
8. **`LB`** — Loopback smoke is per-agent. Cross-agent loopback variants would catch address-routing regressions earlier. Recommended: Add A↔B, A↔AA, D4↔D5 loopback variants or fold into N/NA.
9. **`NPIPE`** — Non-PIE pipe-chain integrity is local to A/AA; VS Code remote workers also run in B/NP/D4-like contexts. Recommended: Add B, NP, and D4 launcher variants.
10. **`XM`** — Node exec-method and `networkInterfaces()` smoke is A-only despite VS Code/Node relying on these APIs from child workers. Recommended: Add A/AA/B/D4 matrix for Node/networkInterfaces methods.

## Appendix: complete test ID enumeration

### `X_` (1)
- `X_canary.pre_sequence`

### `NL` (9)
- `NL1.netlink_socket`, `NL2.netlink_bind`, `NL3.netlink_getlink`, `NL4.netlink_getaddr`, `NL3b.sendmsg_recvmsg`, `NL3c.double_request`, `NL3d.peek_trunc`, `NL5.getifaddrs_full`
- `NL6.mac_address`

### `X` (29)
- `X48.node_networkInterfaces`, `X.echo.A`, `X.echo.AA`, `X.echo.AAA`, `X.echo.NP`, `X.echo.NPC`, `X.echo.D5`, `X.exit_code.A.42`
- `X.exit_code.AAA.7`, `X.node.A`, `X.node.AA`, `X.node.AAA`, `X.node_stdout_write.A`, `X49a.pie_sequential_1`, `X49b.pie_sequential_2`, `X50a.nonpie_then_pie_1`
- `X50b.nonpie_then_pie_2`, `X51.nonpie_fresh_agent`, `X52a.B_nonpie_then_pie`, `X52b.B_pie_after_nonpie`, `X52c.B_third_exec`, `X53.stress_pie`, `X54.nonpie_after_stress`, `X55a.one_pie_first`
- `X55b.nonpie_second`, `X56.second_nonpie_on_B`, `X57.pipe_churn_then_nonpie`, `X58.alternating_pie_nonpie`, `X59.sequential_nonpie`

### `CF` (61)
- `CF.pipe2_cat.A`, `CF.pipe3_cat.A`, `CF.pipe3_grep.A`, `CF.pipe4_vscode.A`, `CF.pipe4_mixed.A`, `CF.sequential_control.A`, `CF.pipe2_cat.AA`, `CF.pipe3_cat.AA`
- `CF.pipe3_grep.AA`, `CF.pipe4_vscode.AA`, `CF.pipe4_mixed.AA`, `CF.sequential_control.AA`, `CF.pipe2_cat.B`, `CF.pipe3_cat.B`, `CF.pipe3_grep.B`, `CF.pipe4_vscode.B`
- `CF.pipe4_mixed.B`, `CF.sequential_control.B`, `CF.pipe4_vscode.NP`, `CF.sequential_control.NP`, `CF.pipe4_vscode.D4`, `CF.sequential_control.D4`, `CF.concurrent_exec_2.A`, `CF.concurrent_exec_2.AA`
- `CF.concurrent_exec_2.B`, `CF.concurrent_exec_3.A`, `CF.concurrent_exec_3.AA`, `CF.concurrent_exec_3.B`, `CF.concurrent_exec_4.A`, `CF.concurrent_exec_4.AA`, `CF.concurrent_exec_4.B`, `CF.vscode.proc_cat_grep.A`
- `CF.vscode.proc_pipeline_3.A`, `CF.vscode.proc_pipeline_4.A`, `CF.vscode.uname_pipeline.A`, `CF.vscode.proc_cat_grep.AA`, `CF.vscode.proc_pipeline_3.AA`, `CF.vscode.proc_pipeline_4.AA`, `CF.vscode.uname_pipeline.AA`, `CF.vscode.proc_cat_grep.B`
- `CF.vscode.proc_pipeline_3.B`, `CF.vscode.proc_pipeline_4.B`, `CF.vscode.uname_pipeline.B`, `CF.rwlock_2.A`, `CF.rwlock_2.AA`, `CF.rwlock_2.B`, `CF.rwlock_3.A`, `CF.rwlock_3.AA`
- `CF.rwlock_3.B`, `CF.rwlock_4.A`, `CF.rwlock_4.AA`, `CF.rwlock_4.B`, `CF.rwlock_multi_3.A`, `CF.rwlock_multi_3.AA`, `CF.rwlock_multi_3.B`, `CF.rwlock_multi_4.A`
- `CF.rwlock_multi_4.AA`, `CF.rwlock_multi_4.B`, `CF.rwlock_multi_6.A`, `CF.rwlock_multi_6.AA`, `CF.rwlock_multi_6.B`

### `NET` (5)
- `NET1.ipv6_socket`, `NET2.ipv6_listen`, `NET4.ipv4_listen`, `NET5.ipv6_getaddrinfo`, `NET6.ipv6_v6only`

### `TERM` (15)
- `TERM.tcgets_fd0`, `TERM.tcgets_fd1`, `TERM.tcgets_fd2`, `TERM.tcsets_fd0`, `TERM.tcsets_fd1`, `TERM.tcsets_fd2`, `TERM.tcsetsw_fd0`, `TERM.tcsetsw_fd1`
- `TERM.tcsetsw_fd2`, `TERM.tcsetsf_fd0`, `TERM.tcsetsf_fd1`, `TERM.tcsetsf_fd2`, `TERM.tiocgwinsz_fd0`, `TERM.tiocgwinsz_fd1`, `TERM.tiocgwinsz_fd2`

### `EX` (4)
- `EX6.node_version_exit`, `EX7.node_process_exit`, `EX8.node_exit_code`, `EX9.node_console_exit`

### `FS` (18)
- `FS.write-read.tmp`, `FS.write-read.root`, `FS.append-read.tmp`, `FS.append-read.root`, `FS.write-bg-read.tmp`, `FS.write-bg-read.root`, `FS.redirect-bg-read.tmp`, `FS.redirect-bg-read.root`
- `FS.fork-write-read.tmp`, `FS.fork-write-read.root`, `FS.bg-open-read.tmp`, `FS.bg-open-read.root`, `FS.parent-open-fork-read.tmp`, `FS.parent-open-fork-read.root`, `FS.exec_pie_fs-exec.txt`, `FS.exec_nonpie_fs-exec.txt`
- `FS.open_pie_fs-exec.txt`, `FS.open_nonpie_fs-exec.txt`

### `CP` (28)
- `CP.simple.sh.A`, `CP.pipe.sh.A`, `CP.multi.sh.A`, `CP.noexec.sh.A`, `CP.nested_fork.sh.A`, `CP.subshell_pipe.sh.A`, `CP.subshell_continue.sh.A`, `CP.simple.bash.A`
- `CP.pipe.bash.A`, `CP.multi.bash.A`, `CP.noexec.bash.A`, `CP.nested_fork.bash.A`, `CP.subshell_pipe.bash.A`, `CP.subshell_continue.bash.A`, `CP.simple.sh.AA`, `CP.pipe.sh.AA`
- `CP.multi.sh.AA`, `CP.noexec.sh.AA`, `CP.nested_fork.sh.AA`, `CP.subshell_pipe.sh.AA`, `CP.subshell_continue.sh.AA`, `CP.simple.bash.AA`, `CP.pipe.bash.AA`, `CP.multi.bash.AA`
- `CP.noexec.bash.AA`, `CP.nested_fork.bash.AA`, `CP.subshell_pipe.bash.AA`, `CP.subshell_continue.bash.AA`

### `SS` (32)
- `SS.cmd_subst.sh.A`, `SS.pipe_in_subst.sh.A`, `SS.multi_pipe_subst.sh.A`, `SS.file_pipe_subst.sh.A`, `SS.sequential_subst.sh.A`, `SS.subst_then_cmds.sh.A`, `SS.vscode_osrelease.sh.A`, `SS.backtick_pipe.sh.A`
- `SS.cmd_subst.bash.A`, `SS.pipe_in_subst.bash.A`, `SS.multi_pipe_subst.bash.A`, `SS.file_pipe_subst.bash.A`, `SS.sequential_subst.bash.A`, `SS.subst_then_cmds.bash.A`, `SS.vscode_osrelease.bash.A`, `SS.backtick_pipe.bash.A`
- `SS.cmd_subst.sh.AA`, `SS.pipe_in_subst.sh.AA`, `SS.multi_pipe_subst.sh.AA`, `SS.file_pipe_subst.sh.AA`, `SS.sequential_subst.sh.AA`, `SS.subst_then_cmds.sh.AA`, `SS.vscode_osrelease.sh.AA`, `SS.backtick_pipe.sh.AA`
- `SS.cmd_subst.bash.AA`, `SS.pipe_in_subst.bash.AA`, `SS.multi_pipe_subst.bash.AA`, `SS.file_pipe_subst.bash.AA`, `SS.sequential_subst.bash.AA`, `SS.subst_then_cmds.bash.AA`, `SS.vscode_osrelease.bash.AA`, `SS.backtick_pipe.bash.AA`

### `XSI` (4)
- `XSI.stdin_script.simple`, `XSI.stdin_script.multiline_set_e`, `XSI.stdin_script.heredoc_style`, `XSI.stdin_script.fork_exec`

### `F` (73)
- `F.shared.parent_to_child.absent`, `F.shared.parent_to_child.created`, `F.shared.parent_to_child.updated`, `F.shared.parent_to_child.deleted`, `F.shared.child_to_parent.absent`, `F.shared.child_to_parent.created`, `F.shared.child_to_parent.updated`, `F.shared.child_to_parent.deleted`
- `F.shared.sibling.absent`, `F.shared.sibling.created`, `F.shared.sibling.updated`, `F.shared.sibling.deleted`, `F.shared.sibling_rev.absent`, `F.shared.sibling_rev.created`, `F.shared.sibling_rev.updated`, `F.shared.sibling_rev.deleted`
- `F.shared.grandchild_up.absent`, `F.shared.grandchild_up.created`, `F.shared.grandchild_up.updated`, `F.shared.grandchild_up.deleted`, `F.shared.great_grandchild_up.absent`, `F.shared.great_grandchild_up.created`, `F.shared.great_grandchild_up.updated`, `F.shared.great_grandchild_up.deleted`
- `F.shared.pie_to_nonpie.absent`, `F.shared.pie_to_nonpie.created`, `F.shared.pie_to_nonpie.updated`, `F.shared.pie_to_nonpie.deleted`, `F.shared.nonpie_to_parent.absent`, `F.shared.nonpie_to_parent.created`, `F.shared.nonpie_to_parent.updated`, `F.shared.nonpie_to_parent.deleted`
- `F.shared.nonpie_child_up.absent`, `F.shared.nonpie_child_up.created`, `F.shared.nonpie_child_up.updated`, `F.shared.nonpie_child_up.deleted`, `F.shared.deep_nonpie.absent`, `F.shared.deep_nonpie.created`, `F.shared.deep_nonpie.updated`, `F.shared.deep_nonpie.deleted`
- `F.unlink.parent_to_child.delete`, `F.unlink.parent_to_child.gone`, `F.unlink.child_to_parent.delete`, `F.unlink.child_to_parent.gone`, `F.unlink.sibling.delete`, `F.unlink.sibling.gone`, `F.unlink.sibling_rev.delete`, `F.unlink.sibling_rev.gone`
- `F.unlink.grandchild_up.delete`, `F.unlink.grandchild_up.gone`, `F.unlink.great_grandchild_up.delete`, `F.unlink.great_grandchild_up.gone`, `F.unlink.pie_to_nonpie.delete`, `F.unlink.pie_to_nonpie.gone`, `F.unlink.nonpie_to_parent.delete`, `F.unlink.nonpie_to_parent.gone`
- `F.unlink.nonpie_child_up.delete`, `F.unlink.nonpie_child_up.gone`, `F.unlink.deep_nonpie.delete`, `F.unlink.deep_nonpie.gone`, `F.tmp.parent_to_child.isolation`, `F.tmp.child_to_parent.isolation`, `F.tmp.sibling.isolation`, `F.tmp.sibling_rev.isolation`
- `F.tmp.grandchild_up.isolation`, `F.tmp.great_grandchild_up.isolation`, `F.tmp.pie_to_nonpie.isolation`, `F.tmp.nonpie_to_parent.isolation`, `F.tmp.nonpie_child_up.isolation`, `F.tmp.deep_nonpie.isolation`, `F.host.init`, `F.host.A`
- `F.host.AA`

### `N` (36)
- `N.init_to_A.listen`, `N.init_to_A.connect`, `N.init_to_A.unlisten`, `N.A_to_B.listen`, `N.A_to_B.connect`, `N.A_to_B.unlisten`, `N.B_to_A.listen`, `N.B_to_A.connect`
- `N.B_to_A.unlisten`, `N.AAA_to_A.listen`, `N.AAA_to_A.connect`, `N.AAA_to_A.unlisten`, `N.B_to_AAA.listen`, `N.B_to_AAA.connect`, `N.B_to_AAA.unlisten`, `N.AA_to_AB.listen`
- `N.AA_to_AB.connect`, `N.AA_to_AB.unlisten`, `N.AAA_to_AAB.listen`, `N.AAA_to_AAB.connect`, `N.AAA_to_AAB.unlisten`, `N.AB_to_B.listen`, `N.AB_to_B.connect`, `N.AB_to_B.unlisten`
- `N.NP_to_A.listen`, `N.NP_to_A.connect`, `N.NP_to_A.unlisten`, `N.A_to_NPC.listen`, `N.A_to_NPC.connect`, `N.A_to_NPC.unlisten`, `N.NPC_to_B.listen`, `N.NPC_to_B.connect`
- `N.NPC_to_B.unlisten`, `N.D5_to_B.listen`, `N.D5_to_B.connect`, `N.D5_to_B.unlisten`

### `NA` (30)
- `NA.A_to_A.127.0.0.1`, `NA.A_to_A.0.0.0.0`, `NA.A_to_A.self_ip`, `NA.AA_to_AA.127.0.0.1`, `NA.AA_to_AA.0.0.0.0`, `NA.AA_to_AA.self_ip`, `NA.A_to_AA.127.0.0.1`, `NA.A_to_AA.0.0.0.0`
- `NA.A_to_AA.self_ip`, `NA.A_to_B.127.0.0.1`, `NA.A_to_B.0.0.0.0`, `NA.A_to_B.self_ip`, `NA.D3_to_D4.127.0.0.1`, `NA.D3_to_D4.0.0.0.0`, `NA.D3_to_D4.self_ip`, `NA.D4_to_D5.127.0.0.1`
- `NA.D4_to_D5.0.0.0.0`, `NA.D4_to_D5.self_ip`, `NA.D4_to_B.127.0.0.1`, `NA.D4_to_B.0.0.0.0`, `NA.D4_to_B.self_ip`, `NA.D4_to_A.127.0.0.1`, `NA.D4_to_A.0.0.0.0`, `NA.D4_to_A.self_ip`
- `NA.NP_to_A.127.0.0.1`, `NA.NP_to_A.0.0.0.0`, `NA.NP_to_A.self_ip`, `NA.A_to_NP.127.0.0.1`, `NA.A_to_NP.0.0.0.0`, `NA.A_to_NP.self_ip`

### `UA` (10)
- `UA.A_to_A`, `UA.AA_to_AA`, `UA.A_to_AA`, `UA.A_to_B`, `UA.D3_to_D4`, `UA.D4_to_D5`, `UA.D4_to_B`, `UA.D4_to_A`
- `UA.NP_to_A`, `UA.A_to_NP`

### `E` (18)
- `E.HOME.A`, `E.PATH.A`, `E.CWD.A`, `E.HOME.AA`, `E.PATH.AA`, `E.CWD.AA`, `E.HOME.AAA`, `E.PATH.AAA`
- `E.CWD.AAA`, `E.HOME.NP`, `E.PATH.NP`, `E.CWD.NP`, `E.HOME.NPC`, `E.PATH.NPC`, `E.CWD.NPC`, `E.HOME.D5`
- `E.PATH.D5`, `E.CWD.D5`

### `S` (25)
- `S.basic.in_process.create`, `S.basic.in_process.readlink`, `S.basic.in_process.read_through`, `S.basic.in_process.stat_type`, `S.basic.parent_to_child.create`, `S.basic.parent_to_child.readlink`, `S.basic.parent_to_child.read_through`, `S.basic.parent_to_child.stat_type`
- `S.basic.child_to_parent.create`, `S.basic.child_to_parent.readlink`, `S.basic.child_to_parent.read_through`, `S.basic.child_to_parent.stat_type`, `S.basic.sibling.create`, `S.basic.sibling.readlink`, `S.basic.sibling.read_through`, `S.basic.sibling.stat_type`
- `S.basic.grandchild_up.create`, `S.basic.grandchild_up.readlink`, `S.basic.grandchild_up.read_through`, `S.basic.grandchild_up.stat_type`, `S.dir.read_through`, `S.dangling.readlink`, `S.dangling.read_fails`, `S.nested.read_through`
- `S.relative.read_through`

### `U` (35)
- `U.in_process.A.listen`, `U.in_process.A.connect`, `U.in_process.AA.listen`, `U.in_process.AA.connect`, `U.server_fork.A.listen`, `U.server_fork.A.child_connect`, `U.server_fork.AA.listen`, `U.server_fork.AA.child_connect`
- `U.bg_server.A.server_start`, `U.bg_server.A.connect`, `U.bg_server.AA.server_start`, `U.bg_server.AA.connect`, `U.sibling.listen`, `U.sibling.connect`, `U.parent_to_grandchild.listen`, `U.parent_to_grandchild.connect`
- `U.grandchild_to_parent.listen`, `U.grandchild_to_parent.connect`, `U.cross_subtree.listen`, `U.cross_subtree.connect`, `U.vscode_d3_d4.listen`, `U.vscode_d3_d4.connect`, `U.vscode_d4_d3.listen`, `U.vscode_d4_d3.connect`
- `U.d4_to_sibling_b.listen`, `U.d4_to_sibling_b.connect`, `U.d5_to_a.listen`, `U.d5_to_a.connect`, `U.a_to_np.listen`, `U.a_to_np.connect`, `U.np_to_a.listen`, `U.np_to_a.connect`
- `U.repro.listen`, `U.repro.same_agent`, `U.repro.cross_worker`

### `POLL` (3)
- `POLL.pipe.A`, `POLL.pipe.AA`, `POLL.pipe.B`

### `GSN` (4)
- `GSN.ipv4.A`, `GSN.ipv4.AA`, `GSN.ipv6.A`, `GSN.ipv6.AA`

### `PID` (3)
- `PID.A`, `PID.AA`, `PID.B`

### `EXITD` (12)
- `EXITD.256.pie.A`, `EXITD.256.pie.AA`, `EXITD.256.nonpie.A`, `EXITD.256.nonpie.AA`, `EXITD.4096.pie.A`, `EXITD.4096.pie.AA`, `EXITD.4096.nonpie.A`, `EXITD.4096.nonpie.AA`
- `EXITD.65536.pie.A`, `EXITD.65536.pie.AA`, `EXITD.65536.nonpie.A`, `EXITD.65536.nonpie.AA`

### `NPIPE` (12)
- `NPIPE.seq.x1.A`, `NPIPE.interleaved.x1.A`, `NPIPE.seq.x1.AA`, `NPIPE.interleaved.x1.AA`, `NPIPE.seq.x5.A`, `NPIPE.interleaved.x5.A`, `NPIPE.seq.x5.AA`, `NPIPE.interleaved.x5.AA`
- `NPIPE.seq.x10.A`, `NPIPE.interleaved.x10.A`, `NPIPE.seq.x10.AA`, `NPIPE.interleaved.x10.AA`

### `XCONN` (7)
- `XCONN.cross_first`, `XCONN.deep_cross`, `XCONN.cross_seq_x3`, `XCONN.self_A`, `XCONN.parent_child`, `XCONN.child_parent`, `XCONN.sibling_AB`

### `TLB` (5)
- `TLB.listen_busy.same_agent`, `TLB.listen_busy.parent_child`, `TLB.listen_busy.child_parent`, `TLB.listen_busy.sibling`, `TLB.listen_busy.depth2`

### `BASH` (6)
- `BASH.fork_ls.A`, `BASH.fork_subst.A`, `BASH.fork_bg_fg.A`, `BASH.fork_ls.B`, `BASH.fork_subst.B`, `BASH.fork_bg_fg.B`

### `FWE` (4)
- `FWE.nonpie_from_init`, `FWE.pie_from_init`, `FWE.pie_from_worker_exec`, `FWE.nonpie_from_worker_exec`

### `M` (20)
- `M1.A`, `M2.A`, `M3.A`, `M4.A`, `M1.AA`, `M2.AA`, `M3.AA`, `M4.AA`
- `M1.D3`, `M2.D3`, `M3.D3`, `M4.D3`, `M1.D4`, `M2.D4`, `M3.D4`, `M4.D4`
- `M1.D5`, `M2.D5`, `M3.D5`, `M4.D5`

### `BS` (15)
- `BS1.A`, `BS2.A`, `BS3.A`, `BS1.AA`, `BS2.AA`, `BS3.AA`, `BS1.D3`, `BS2.D3`
- `BS3.D3`, `BS1.D4`, `BS2.D4`, `BS3.D4`, `BS1.D5`, `BS2.D5`, `BS3.D5`

### `SP` (18)
- `SP.simple.A`, `SP.pipeline.A`, `SP.file_read.A`, `SP.file_pipe.A`, `SP.multi_subst.A`, `SP.os_detect.A`, `SP.simple.AA`, `SP.pipeline.AA`
- `SP.file_read.AA`, `SP.file_pipe.AA`, `SP.multi_subst.AA`, `SP.os_detect.AA`, `SP.simple.B`, `SP.pipeline.B`, `SP.file_read.B`, `SP.file_pipe.B`
- `SP.multi_subst.B`, `SP.os_detect.B`

### `CWF` (21)
- `CWF.seq.A`, `CWF.concurrent.A`, `CWF.hold.A`, `CWF.self_open.A`, `CWF.redirect_stdout.A`, `CWF.redirect_exit.A`, `CWF.builtin_redirect.A`, `CWF.seq.AA`
- `CWF.concurrent.AA`, `CWF.hold.AA`, `CWF.self_open.AA`, `CWF.redirect_stdout.AA`, `CWF.redirect_exit.AA`, `CWF.builtin_redirect.AA`, `CWF.seq.B`, `CWF.concurrent.B`
- `CWF.hold.B`, `CWF.self_open.B`, `CWF.redirect_stdout.B`, `CWF.redirect_exit.B`, `CWF.builtin_redirect.B`

### `SC` (24)
- `SC.echo.A`, `SC.cat.A`, `SC.readlink.A`, `SC.dirname.A`, `SC.nested.A`, `SC.vscode_root.A`, `SC.which.A`, `SC.uname.A`
- `SC.echo.AA`, `SC.cat.AA`, `SC.readlink.AA`, `SC.dirname.AA`, `SC.nested.AA`, `SC.vscode_root.AA`, `SC.which.AA`, `SC.uname.AA`
- `SC.echo.B`, `SC.cat.B`, `SC.readlink.B`, `SC.dirname.B`, `SC.nested.B`, `SC.vscode_root.B`, `SC.which.B`, `SC.uname.B`

### `CC` (12)
- `CC.echo.A`, `CC.echo.AA`, `CC.echo.B`, `CC.fork_exec.A`, `CC.fork_exec.AA`, `CC.fork_exec.B`, `CC.pipe_capture.A`, `CC.pipe_capture.AA`
- `CC.pipe_capture.B`, `CC.file_write.A`, `CC.file_write.AA`, `CC.file_write.B`

### `TR` (15)
- `TR.no_touch.A`, `TR.touch.A`, `TR.touch_chmod.A`, `TR.echo_touch.A`, `TR.builtin_touch.A`, `TR.no_touch.AA`, `TR.touch.AA`, `TR.touch_chmod.AA`
- `TR.echo_touch.AA`, `TR.builtin_touch.AA`, `TR.no_touch.B`, `TR.touch.B`, `TR.touch_chmod.B`, `TR.echo_touch.B`, `TR.builtin_touch.B`

### `KP` (27)
- `KP.kill0_bg.A`, `KP.kill0_many.A`, `KP.proc_child.A`, `KP.proc_self.A`, `KP.ppid_proc.A`, `KP.ppid_kill0.A`, `KP.ppid_cmdline.A`, `KP.getppid_correct.A`
- `KP.parent_monitor.A`, `KP.kill0_bg.AA`, `KP.kill0_many.AA`, `KP.proc_child.AA`, `KP.proc_self.AA`, `KP.ppid_proc.AA`, `KP.ppid_kill0.AA`, `KP.ppid_cmdline.AA`
- `KP.getppid_correct.AA`, `KP.parent_monitor.AA`, `KP.kill0_bg.B`, `KP.kill0_many.B`, `KP.proc_child.B`, `KP.proc_self.B`, `KP.ppid_proc.B`, `KP.ppid_kill0.B`
- `KP.ppid_cmdline.B`, `KP.getppid_correct.B`, `KP.parent_monitor.B`

### `KPX` (9)
- `KPX.cross.same_agent.A.to.A`, `KPX.cross.parent_to_child.A.to.AA`, `KPX.cross.child_to_parent.AA.to.A`, `KPX.cross.root_sibling.A.to.B`, `KPX.cross.nested_sibling.AA.to.AB`, `KPX.cross.depth1_to_depth2.AB.to.AAA`, `KPX.cross.depth2_to_depth1.AAA.to.AB`, `KPX.cross.depth2_sibling.AAA.to.AAB`
- `KPX.cross.cross_subtree.B.to.AAA`

### `FR` (15)
- `FR.fg_redirect.A`, `FR.bg_echo.A`, `FR.bg_exe.A`, `FR.bg_cat_pipe.A`, `FR.bg_append.A`, `FR.fg_redirect.AA`, `FR.bg_echo.AA`, `FR.bg_exe.AA`
- `FR.bg_cat_pipe.AA`, `FR.bg_append.AA`, `FR.fg_redirect.B`, `FR.bg_echo.B`, `FR.bg_exe.B`, `FR.bg_cat_pipe.B`, `FR.bg_append.B`

### `PN` (18)
- `PN.A.setfl`, `PN.A.empty_eagain`, `PN.A.data`, `PN.A.eof`, `PN.AA.setfl`, `PN.AA.empty_eagain`, `PN.AA.data`, `PN.AA.eof`
- `PN.B.setfl`, `PN.B.empty_eagain`, `PN.B.data`, `PN.B.eof`, `PN.child.A.eagain`, `PN.child.A.data`, `PN.child.A.eof`, `PN.child.AA.eagain`
- `PN.child.AA.data`, `PN.child.AA.eof`

### `EP` (12)
- `EP.direct.accept.A`, `EP.direct.read.A`, `EP.direct.accept.AA`, `EP.direct.read.AA`, `EP.direct.accept.B`, `EP.direct.read.B`, `EP.tokio.accept.A`, `EP.tokio.read.A`
- `EP.tokio.accept.AA`, `EP.tokio.read.AA`, `EP.tokio.accept.B`, `EP.tokio.read.B`

### `LB` (15)
- `LB.same_worker.A`, `LB.localhost.A`, `LB.any_to_local.A`, `LB.fast_close.A`, `LB.halfclose_eof.A`, `LB.same_worker.AA`, `LB.localhost.AA`, `LB.any_to_local.AA`
- `LB.fast_close.AA`, `LB.halfclose_eof.AA`, `LB.same_worker.B`, `LB.localhost.B`, `LB.any_to_local.B`, `LB.fast_close.B`, `LB.halfclose_eof.B`

### `THC` (4)
- `THC.halfclose.eof.same_agent`, `THC.halfclose.eof.cross_agent`, `THC.halfclose.eof.sibling`, `THC.halfclose.eof.depth2`

### `FKLC` (2)
- `FKLC.listen_unlisten`, `FKLC.cross_connect`

### `PROC` (9)
- `PROC.self_stat.A`, `PROC.stat_seekable.A`, `PROC.uptime.A`, `PROC.self_stat.AA`, `PROC.stat_seekable.AA`, `PROC.uptime.AA`, `PROC.self_stat.B`, `PROC.stat_seekable.B`
- `PROC.uptime.B`

### `SK` (3)
- `SK.subtree.direct_nonpie`, `SK.subtree.deep_nonpie`, `SK.subtree.exit_then_kill`

### `XB` (54)
- `XB.echo.A`, `XB.cmd_substitution.A`, `XB.pipe_in_subshell.A`, `XB.process_substitution.A`, `XB.simple_pipe.A`, `XB.three_stage_pipe.A`, `XB.background_wait.A`, `XB.multi_background.A`
- `XB.subshell_exit_code.A`, `XB.sequential_cmds.A`, `XB.nested_subshell.A`, `XB.heredoc.A`, `XB.herestring.A`, `XB.pipe_grep.A`, `XB.subshell_pipe_wc.A`, `XB.backtick_subst.A`
- `XB.pipe_while_read.A`, `XB.xargs.A`, `XB.echo.AA`, `XB.cmd_substitution.AA`, `XB.pipe_in_subshell.AA`, `XB.process_substitution.AA`, `XB.simple_pipe.AA`, `XB.three_stage_pipe.AA`
- `XB.background_wait.AA`, `XB.multi_background.AA`, `XB.subshell_exit_code.AA`, `XB.sequential_cmds.AA`, `XB.nested_subshell.AA`, `XB.heredoc.AA`, `XB.herestring.AA`, `XB.pipe_grep.AA`
- `XB.subshell_pipe_wc.AA`, `XB.backtick_subst.AA`, `XB.pipe_while_read.AA`, `XB.xargs.AA`, `XB.echo.AAA`, `XB.cmd_substitution.AAA`, `XB.pipe_in_subshell.AAA`, `XB.process_substitution.AAA`
- `XB.simple_pipe.AAA`, `XB.three_stage_pipe.AAA`, `XB.background_wait.AAA`, `XB.multi_background.AAA`, `XB.subshell_exit_code.AAA`, `XB.sequential_cmds.AAA`, `XB.nested_subshell.AAA`, `XB.heredoc.AAA`
- `XB.herestring.AAA`, `XB.pipe_grep.AAA`, `XB.subshell_pipe_wc.AAA`, `XB.backtick_subst.AAA`, `XB.pipe_while_read.AAA`, `XB.xargs.AAA`

### `XM` (8)
- `XM.script_echo`, `XM.script_node`, `XM.script_env_shebang`, `XM.script_cat_pipe`, `XM.nested_bash_node`, `XM.script_self_exe`, `XM.script_exec_node`, `XM.node_networkInterfaces`

### `XDF` (25)
- `XDF.mmap.pie.direct.A`, `XDF.mmap.pie.direct.AA`, `XDF.mmap.pie.script.A`, `XDF.mmap.pie.script.AA`, `XDF.mmap.nonpie.direct.A`, `XDF.mmap.nonpie.direct.AA`, `XDF.mmap.nonpie.script.A`, `XDF.mmap.nonpie.script.AA`
- `XDF.mmap.node.direct.A`, `XDF.mmap.node.direct.AA`, `XDF.mmap.node.script.A`, `XDF.mmap.node.script.AA`, `XDF.thread.pie.direct.A`, `XDF.thread.pie.direct.AA`, `XDF.thread.pie.script.A`, `XDF.thread.pie.script.AA`
- `XDF.thread.nonpie.direct.A`, `XDF.thread.nonpie.direct.AA`, `XDF.thread.nonpie.script.A`, `XDF.thread.nonpie.script.AA`, `XDF.thread.node.direct.A`, `XDF.thread.node.direct.AA`, `XDF.thread.node.script.A`, `XDF.thread.node.script.AA`
- `XDF.triple_nesting`

### `XS` (6)
- `XS.pie.sync`, `XS.pie.tokio`, `XS.nonpie.sync`, `XS.nonpie.tokio`, `XS.mixed.sync`, `XS.mixed.tokio`

### `XNP` (3)
- `XNP.direct`, `XNP.script`, `XNP.bash_inline`

### `XC` (5)
- `XC.init_level`, `XC.child_clean`, `XC.child_sequential`, `XC.grandchild_nonpie`, `XC.depth2_clean`

### `US` (26)
- `US1.cross_process_unix`, `US2.cross_exec_unix`, `US3.bidirectional_unix`, `US4.multi_conn_unix`, `US5.abstract_unix`, `US6.socketpair_write.A`, `US6.socketpair_read.A`, `US6.socketpair_write.AA`
- `US6.socketpair_read.AA`, `US6.socketpair_write.B`, `US6.socketpair_read.B`, `US6.socketpair_write.D3`, `US6.socketpair_read.D3`, `US6.socketpair_write.D4`, `US6.socketpair_read.D4`, `US6.socketpair_write.NP`
- `US6.socketpair_read.NP`, `US6.socketpair_exec.A`, `US6.socketpair_exec.AA`, `US6.socketpair_exec.B`, `US6.socketpair_exec.D3`, `US6.socketpair_exec.D4`, `US6.socketpair_exec.NP`, `US6.socketpair_nonpie.A`
- `US6.socketpair_nonpie.AA`, `US6.socketpair_nonpie.B`

### `VS` (1)
- `VS1.socket_race`

### `UF` (3)
- `UF.fork_unix.A`, `UF.fork_unix.AA`, `UF.fork_unix.B`

### `XW` (24)
- `XW.spawn_remote`, `XW1.remote_write`, `XW1.local_read`, `XW2.local_write`, `XW2.remote_read`, `XW3.remote_listen`, `XW3.local_connect`, `XW4.local_listen`
- `XW4.remote_connect`, `XW5.remote_tcp_listen`, `XW5.local_tcp_connect`, `XW6.local_tcp_listen`, `XW6.remote_tcp_connect`, `XW7.d4_listen`, `XW7.d3_connect`, `XW8.d3_listen`
- `XW8.d4_connect`, `XW9.d4_listen`, `XW9.aa_connect`, `XW10.d3_tcp_listen`, `XW10.b_tcp_connect`, `XW11.d3_tcp_listen`, `XW11.spawn_r2`, `XW11.r2_tcp_connect`

### `P` (12)
- `P1.pipe_eof_fork.A`, `P1.pipe_eof_fork.AA`, `P1.pipe_eof_fork.B`, `P1.pipe_eof_fork.D3`, `P1.pipe_eof_fork.D4`, `P1.pipe_eof_fork.NP`, `P2.pipe_eof_exec_pie.A`, `P2.pipe_eof_exec_pie.AA`
- `P2.pipe_eof_exec_pie.B`, `P2.pipe_eof_exec_nonpie.A`, `P2.pipe_eof_exec_nonpie.AA`, `P2.pipe_eof_exec_nonpie.B`

### `PB` (46)
- `PB.c2p.pie.A`, `PB.c2p.pie.AA`, `PB.c2p.pie.B`, `PB.c2p.nonpie.A`, `PB.c2p.nonpie.AA`, `PB.c2p.nonpie.B`, `PB.p2c.pie.A`, `PB.p2c.pie.AA`
- `PB.p2c.pie.B`, `PB.p2c.nonpie.A`, `PB.p2c.nonpie.AA`, `PB.p2c.nonpie.B`, `PB.multi.pie.A`, `PB.multi.pie.AA`, `PB.multi.pie.B`, `PB.multi.nonpie.A`
- `PB.multi.nonpie.AA`, `PB.multi.nonpie.B`, `PB.sp.pie.A`, `PB.sp.pie.AA`, `PB.sp.pie.B`, `PB.sp.nonpie.A`, `PB.sp.nonpie.AA`, `PB.sp.nonpie.B`
- `PB.c2p.xworker_pie.NP`, `PB.c2p.xworker_pie.D4`, `PB.c2p.xworker_nonpie.NP`, `PB.c2p.xworker_nonpie.D4`, `PB.many.pie.A`, `PB.many.pie.AA`, `PB.many.pie.B`, `PB.many.nonpie.A`
- `PB.many.nonpie.AA`, `PB.many.nonpie.B`, `PB.epoll.pie.A`, `PB.epoll.pie.AA`, `PB.epoll.pie.B`, `PB.epoll.nonpie.A`, `PB.epoll.nonpie.AA`, `PB.epoll.nonpie.B`
- `PB.epoll_sp.pie.A`, `PB.epoll_sp.pie.AA`, `PB.epoll_sp.pie.B`, `PB.epoll_sp.nonpie.A`, `PB.epoll_sp.nonpie.AA`, `PB.epoll_sp.nonpie.B`

### `TC` (10)
- `TC.in_process.x2.d0`, `TC.in_process.x5.d0`, `TC.in_process.x10.d0`, `TC.sibling.x2.d0`, `TC.sibling.x5.d0`, `TC.sibling.x10.d0`, `TC.depth2.x2.d0`, `TC.depth2.x5.d0`
- `TC.sibling_delayed.x5.d10`, `TC.depth2_delayed.x5.d10`

### `TD` (8)
- `TD.1K.in_process`, `TD.1K.sibling`, `TD.1K.cross_subtree`, `TD.64K.in_process`, `TD.64K.sibling`, `TD.64K.cross_subtree`, `TD.256K.in_process`, `TD.256K.sibling`

### `TRR` (4)
- `TRR.x5.in_process`, `TRR.x20.in_process`, `TRR.x5.sibling`, `TRR.x20.sibling`

### `TF` (3)
- `TF.A`, `TF.AA`, `TF.B`

### `TW` (6)
- `TW.remote_listen.x1`, `TW.local_listen.x1`, `TW.remote_listen.x3`, `TW.local_listen.x3`, `TW.remote_listen.x5`, `TW.local_listen.x5`

### `FT` (19)
- `FT.listen_write.A`, `FT.listen_read.A`, `FT.listen_read_etc.A`, `FT.listen_write.B`, `FT.listen_read.B`, `FT.listen_read_etc.B`, `FT.conn_echo`, `FT.conn_read_after`
- `FT.conn_write`, `FT.conn_readback`, `FT.interleave_self_small`, `FT.interleave_self_4k`, `FT.interleave_self_32k`, `FT.interleave_cross_small`, `FT.interleave_cross_4k`, `FT.multi_x5`
- `FT.multi_interleave_x5`, `FT.exec_cat_during_tcp`, `FT.echo_after_exec`

### `PR` (11)
- `PR.fork_exec.A`, `PR.fork_single.A`, `PR.fork_exec.B`, `PR.fork_single.B`, `PR.fork_multi_x5`, `PR.fork_cross`, `PR.fork_interleave`, `PR.fork_bg`
- `PR.listen_inherit_self`, `PR.listen_inherit_cross`, `PR.child_listen_cross`
