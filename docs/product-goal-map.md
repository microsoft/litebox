# Product goal map

> **Purpose:** anchor the per-phase / per-session todo lists to the
> two top-level product goals so we can answer "are we close?" at a
> glance, without scanning the per-session plan.md files. Maintained
> at the **amalgamation merge point** — see "Maintenance" below.
>
> **Bootstrap commit:** drafted by session
> `cbc74e79-ac7a-4cdf-a64b-05ed3f70913f` on `wportnoy/product-goal-map-bootstrap`
> against amalgamation tip `73317a1c`. Numbers and edges below
> reflect a best-effort survey of plan.md + harness CLAUDE.md +
> amalgamation log; refine on first real merge update.
>
> **Status legend:** ✅ landed · 🟡 in-flight (branch named) · 🔴 blocked (blocker named) · ⚪ not started · 🟦 deferred (out of current scope)

## Top-level goals

- **Goal A — Interactive Copilot CLI TUI inside Litebox.** End-user
  runs `copilot` from a sandboxed shell session (sshd → bash →
  copilot) and gets a working TUI: line discipline, window resize,
  job control, pipelines, `child_process.spawn` (Node's shell-tool
  drain path).
- **Goal B — VS Code Remote Server inside Litebox.** End-user
  connects from VS Code desktop to a sandboxed server. Process tree
  per the canonical VS Code shape:
  `sshd_pty → login_bash → piped_sh → launcher_bash → cli → node`
  (PieGlibc → NonPie → NonPie → NonPie → StaticPieMusl → NonPieGlibc).
  Requires everything Goal A needs, plus: TCP listener for RPC, file
  watching (inotify), pidfd lifecycle, UDS streams, the
  StaticPieMusl→NonPieGlibc cli→node transition, and acceptable
  fork-restore latency.

## Capability map

```mermaid
flowchart TD
    classDef landed fill:#d4edda,stroke:#28a745,color:#000
    classDef inflight fill:#fff3cd,stroke:#ffc107,color:#000
    classDef blocked fill:#f8d7da,stroke:#dc3545,color:#000
    classDef notstarted fill:#e2e3e5,stroke:#6c757d,color:#000
    classDef deferred fill:#cce5ff,stroke:#0056b3,color:#000
    classDef goal fill:#f5e8ff,stroke:#5a2d82,color:#000,stroke-width:2px

    GA[Goal A — Copilot CLI TUI]:::goal
    GB[Goal B — VS Code Remote Server]:::goal

    %% PTY layer
    PTY_TERMIOS[PTY: termios / winsize / SIGWINCH / ICANON / ECHO / line discipline]:::landed
    PTY_SIGTTIN[PTY: TIOCSCTTY + background-pgrp SIGTTIN]:::landed
    PTY_SIGTTOU[PTY: SIGTTOU + TOSTOP]:::landed
    PTY_TERMIOS --> GA
    PTY_TERMIOS --> GB
    PTY_SIGTTIN --> GA
    PTY_SIGTTIN --> GB
    PTY_SIGTTOU --> GA
    PTY_SIGTTOU --> GB

    %% fork + pipe + cloexec layer
    FORK_PIPE[fork + pipe inheritance + CLOEXEC preservation]:::landed
    FORK_LATENCY[fork-restore latency under bound ~9x native, regression-guarded]:::inflight
    FIND_HEAD[Pipeline shapes: cat-pipe-head, node-spawn-bash-drain, dropbear-bash]:::landed
    W8_W10[TUI 'find_head' family — w8/w10 todos]:::inflight
    TUI_STARTUP[TUI mode startup + interactive rendering — regression window 708fd18..33a2453e]:::landed
    FORK_PIPE --> GA
    FORK_PIPE --> GB
    FORK_LATENCY --> GA
    FORK_LATENCY --> GB
    FIND_HEAD --> GA
    FIND_HEAD --> GB
    W8_W10 --> GA
    TUI_STARTUP --> GA
    TUI_STARTUP --> W8_W10

    %% pidfd + signals
    PIDFD_OPEN[pidfd_open + waitid P_PIDFD]:::landed
    PIDFD_SEND[pidfd_send_signal + WIFSIGNALED encoding]:::landed
    PIDFD_OPEN --> GB
    PIDFD_SEND --> GB

    %% UDS family
    UDS_STREAM[UDS_STREAM broker-held, default-on]:::landed
    UDS_SEQPACKET[UDS_SEQPACKET broker-held, default-on]:::landed
    UDS_DGRAM[UDS_DGRAM with SCM_RIGHTS for file/pipe/dgram]:::landed
    UDS_CRED[SCM_CREDENTIALS on dgram]:::deferred
    UDS_STREAM --> GB
    UDS_SEQPACKET --> GB
    UDS_DGRAM --> GB

    %% broker-held substrate
    MUX_RETIRED[Mux relay topology retired -- multiplexer.rs + litebox::pipes deleted]:::landed
    BROKER_HANDLES[Broker-held pipe / socketpair / PTY / host-fd attach]:::landed
    OFD_REGISTRY[9P + cross-conn OFD registry for fs fid inherit]:::landed
    BROKER_INET[Broker-held inet TCP/UDP/listener/raw -- Phases A-F]:::landed
    BROKER_INOTIFY[Broker-held inotify for file watching]:::landed
    HOSTFD_RENAME[HostPassthroughFd rename + 9-site install audit]:::landed
    MUX_RETIRED --> FORK_PIPE
    BROKER_HANDLES --> FORK_PIPE
    OFD_REGISTRY --> FORK_PIPE
    BROKER_INET --> GB
    BROKER_INOTIFY --> GB
    HOSTFD_RENAME --> FORK_PIPE

    %% binary-type spawn coverage
    CLI_NODE[StaticPieMusl -> NonPieGlibc -- cli to node transition -- Dpg1SpmDng covered]:::landed
    CLI_NODE --> GB

    %% open todos at edge
    HYPB[HypB notification-coalescing 30/60 remaining]:::inflight
    HYPB --> FORK_LATENCY
```

## Capability detail

| Capability | Status | Validating test family | Notes / open work |
|---|---|---|---|
| PTY: termios, winsize, SIGWINCH, line discipline | ✅ | `PTY.termios.*`, `PTY.winsize.*`, `PTY.sigwinch.*`, `PTY.line_discipline.*` | Phase 3 followups (Session 13). Replaces `MuxPtySlaveFd` fake-PTY with real `BrokerPtyFd`. |
| PTY: TIOCSCTTY + background-pgrp SIGTTIN | ✅ | `PTY.controlling_tty.tiocsctty_sigttin` 11/11 | Session 15 round 3 (`goal2-pty-bgpgrp`, commit `a5a5bac4`). |
| PTY: SIGTTOU + TOSTOP | ✅ | `PTY.controlling_tty.tostop_sigttou.*` 50 tests | Session 16 round 4 (`goal3-pty-sigttou`, commit `8b06c60e`). |
| fork + pipe inheritance + CLOEXEC | ✅ | `FORK.pipe_fd_inheritance`, `PFLG.nonblock_fork.*`, `INHERIT.{pidfd,epoll,inotify,eventfd,signalfd,pipe,socketpair,tcp_*,brokerfile,pty,timerfd,tcp_listen}.*` (12 fd kinds × ops × 5×5 binary cross-product), `NESTED_INHERIT.{pipe,eventfd,brokerfile}.*` (315 tests covering 3-deep grandparent→parent→child shape), `DF_PARENT_TRIGGER.*` (99 tests sweeping parent-side fd-state through commit_delayed_fork), `MULTI_INHERIT.*` (250 tests with multiple fd kinds open at fork), `PROMOTION_RACE.*` (12 tests stressing concurrent lazy-promotion triggers), `WORKER_READY_RACE.*` (60 tests, sized at N=10 iters to fit under the harness's 15s send_cmd timeout — see commit `e4fd4007`) | Phase 2 (legacy local pipes → BrokerPipe). w11 CLOEXEC regression subsumed by Phase 3. **Session `fbe2af35` (wportnoy/wave-cleanup) substrate fix**: nested-delayed-fork CoW skip at `process.rs:2589` (commit `5241b07c`) was unsafe — grandchild's glibc `__nptl_fork_child` user-space writes (TLS, pthread_t, malloc arenas) could clobber the parent's live stack canary, deterministically tripping `__stack_chk_fail` on static-PIE-glibc parents. Fix installs a CoW layer per nested fork. Validated end-to-end on docker: +31 tests across `RL.parent_exits_first.pipe.static-pie-glibc.*` (15 hard-fail → 0), `RL.subscriber_exits_first.pidfd.*` (+11), `INHERIT.*` (+5). Also landed: eager broker-backed eventfd (commit `8adc0659`, −147 LOC; `sys_eventfd2` now creates BrokerBacked at creation rather than promoting at fork); FdClass cleanup removing dead `PidFd`/`TimerFd`/`AnonSpecialFd` reject arms and the `Other` catch-all (commits `c0897002`, `2f245f9e`). **WORKER_READY_RACE misdiagnosis correction (commit `e4fd4007`):** the prior "race is real, 6/60 baseline" claim was wrong. The handler simply took ~20s for the original N=50 iters and tripped the framework's 15s `send_cmd` response timeout. In the broker-held model there is no race for parent-side ops: the parent's `dup_handle` returns a valid broker reference immediately; the worker's `install_broker_fd_bridge_spec` is purely local with no broker RPC. The held speculative branch `wportnoy/wave-cleanup-inherit` (commit `65a9ae87`) added a `--worker-ready-fd` pipe barrier that made each iter LONGER (parent blocked until full runner init), tripping the timeout even more reliably — that's why "with held fix = 0/60" was observed. The held branch is solving a non-problem and is **permanently abandoned**; `--worker-ready-fd` is not needed. Test sized at N=10 → 60/60 pass under docker. **`--worker-result-fd` pipe-vestige retired (commit `dd06463c`):** the runner→parent guest wait_status was previously delivered via a host pipe; now the runner stamps `try_mark_broker_process_exited` (already doing this) and the parent subscribes via `try_subscribe_broker_process_exit`'s `already_exited` snapshot. No new broker RPC needed — existing process-exit subscription mechanism carried the wait_status. Removes `create_worker_result_pipe`, `read_worker_result_fd`, `write_worker_result`, `CliArgs::worker_result_fd`, and the `--worker-result-fd` argv. **`--fork-restore-ack-fd` pipe-vestige retired (commit `5357a574`):** runner→parent fork-restore install-complete ack was previously delivered via a host pipe (success = 0 byte, failure = errno bytes); now the parent allocates an auxiliary broker process pid as the ack channel, runner stamps it via the existing `MarkProcessExited` mechanism with success/errno encoded, parent blocks on a new `GuestPidProvider::wait_process_exit_blocking` trait method (condvar-based, 30s timeout). No new broker opcodes or wire-format changes. Both pipe-based runner→parent coordination primitives are now consolidated onto the broker; the only remaining runner↔parent pipes are the bootstrap-config / state-transfer ones that are necessarily argv (chicken-and-egg with the broker connection). **Session `fbe2af35` (wave-cleanup-2) — second pass of wave work on structural gates and fork-path consolidation, ~80 hard FAILs collapsed**: (1) **Migration_policy compile-time gate** (commits `4d72c300` + `b2e12d9f`): new `litebox_shim_linux/src/syscalls/migration_policy.rs` exposes `migration_policies_for(&RawFdRef) -> {worker_exec, delayed_fork, independent_fork}` with exhaustive `RawFdRef` match (rustc E0004 + workspace `clippy::wildcard_enum_match_arm = "deny"`); every fork-path entry point references `reference_gate::<FS>()` to keep the gate in the build dependency graph. Test-discovery `InheritSubsystem::coverage_gate` cfg(test) module asserts every variant has matrix coverage. **Typed loop-name constants** (commit `357bed5d`) — `pub(crate) const <NAME>_BRIDGE_LOOP_NAME: &str` declarations referenced by typed paths from `migration_policy` policy arms; renaming/removing an emit loop produces `error[E0425]: cannot find value` at the policy table, closing the dishonest-attestation gap. (2) **Epoll/inotify migration across both fork paths**: worker-exec path (commit `5387acc3`, 68/68 FAILs → pass) added `EpollFile::snapshot_interests` + `install_epoll_bridge_fd` + `install_inotify_bridge_fd` + `fd:epoll`/`fd:inotify` runner spec prefixes. Delayed-fork snapshot path (commit `cf7348e5`) reuses the same bridge-spec mechanism via new `collect_epoll_inotify_bridge_specs` helper. **Critical follow-up**: `cf7348e5`'s unconditional accept tripped a perf regression on WRR.pidfd (tokio's `epoll_create1(EPOLL_CLOEXEC)` in the test harness made every non-PIE `Command::spawn` take the slow snapshot/restore path); gated on `!FD_CLOEXEC` in commit `8d674619` — CLOEXEC fds fall through to vfork shared-AS as before; non-CLOEXEC fds still take the migration path. (3) **Signalfd bridge-mask propagation** (commit `e619e8ff`, 5/5 FAILs → pass): `install_signalfd_bridge_fd` now folds the bridge's mask into the worker shim's `signals.blocked` set so a child that self-raises a signalfd signal doesn't terminate via default-disposition. Only `child=dng` (NonPieGlibc, the worker-exec-shape) was affected — true-fork preserves the mask via `ThreadSnapshot`. (4) **WORKER_READY_RACE.pidfd budget correction** (commit `081be663`): per-fd-kind iteration sizing via `default_iterations(fd_kind)` — eventfd=10, pidfd=5 — accounts for pidfd's extra fork+pidfd_open+SIGKILL+waitpid per iter. (5) **`BrokerSocketDgram` + `BrokerSocketSeqPacket` `RawFdRef` variants** (commit `729c9c9f`) — closes the structural-gate gap where these subsystems were in `descriptor_table` but invisible to `migration_policy`. Adds 47-site exhaustive-match cascade across `file.rs`, `mm.rs`, `net.rs`, `epoll.rs`, `process.rs`, `lib.rs`. (6) **Unified per-fork-path walk** (commits `8bb8545a` + `81a3fd9b` + `a8c1b6ae` → `d21a2aa9`): 14 per-subsystem `iter_alive()` walks across 3 fork paths replaced by 3 calls to one shared `collect_migratable_fds(files, global, survives_exec_filter) -> CollectedMigratableFds<FS>` with exhaustive `RawFdRef` match; preserves epoll-last invariant by source ordering; `collect_worker_exec_subsystem_fds` + `collect_epoll_inotify_bridge_specs` deleted. (7) **Phase-2 emit-block extraction** (commits `b5afc9bc` + `a1f43822` + `8d425e6e` → `b173e242`): 14 inline 30-40-LOC Phase-2 emit blocks extracted as named `emit_<kind>_bridge_specs<FS>(task, bucket, accumulators...)` free functions; `exec_on_remote_host` body shrunk 838→400 LOC (-52%); `emit_fork_inotify_epoll_bridge_specs` wrapper deleted (commit/true-fork paths call per-kind helpers directly). (8) **UDS_SEQPACKET/Dgram restore arms + if-chain elimination** (commit `12e52a1d`): added missing `BrokerHandleSnapshot::SocketDgram` + `SocketSeqPacket` arms in the `FdClass::UnixSocket` restore loop (without which SOCK_SEQPACKET snapshot entries silently fell through to a fresh disconnected stream socket — `UDS_SEQPACKET.fork_restore_inherit` was failing because the child's recv had no peer; `UDS_DGRAM_SCM` had the same gap silently); converted the `if broker_handle.kind == X` chain to an exhaustive `match` so future variants fail to compile here. (9) **`BrokerHandleKind` + `BrokerHandleSnapshot` taxonomy collapse** (commit `18e5ba53`, wire format bumped 1→2): replaced the dual taxonomy (enum + struct with `Option<…>`-soup fields invalid in 5/11 arms) with a single typed `BrokerHandleSnapshot` enum where each variant carries exactly its valid fields (`Pty { handle_id, role, pty_id }`, `Pipe { handle_id, direction }`, `UnixSocket { handle_id, endpoint }`, etc.). All per-class restore loops in `lib.rs` now match exhaustively on the typed enum; impossible variant×class combinations use `unreachable!()` per AGENTS.md "loud failure for logic errors." `FdClass` preserved (it's the policy + reopen-strategy axis, not 1:1 with `BrokerHandleKind`; survey at `docs/fd-taxonomy-survey.md`). Validation: 150v150 head-to-head Fisher's exact test on `RL.subscriber_exits_first.pidfd` showed semantic equivalence (p ≈ 0.69; pre 11/150 vs post 14/150). (10) **Dead `worker_exec_bridge_decision` scaffold deleted** (commit `4c811998`, -119 LOC) — never-wired prototype superseded by `migration_policy`. **Validation methodology lesson**: dashboard cumulative pass/fail counts can mislead when pre/post sample sizes differ. For collapse-style refactors, matched-N stress + Fisher exact / Wilson CI is the right comparison; CIs from small samples often overlap even when point estimates look different. **Pre-existing residuals not addressed by wave-cleanup-2** (left for future work): 5-10% load-correlated tail on `RL.subscriber_exits_first.pidfd` + other broker-fd-restore families at high parallelism (predates the collapse; verified via Fisher test); `PROMOTION_RACE.concurrent_fork.{eventfd,signalfd}.*` deterministic EAGAIN-on-fork; latent single-variant-filter risk in per-class restore loops (PTY, Signalfd, Pipe, InetListener). |
| fork-restore latency | 🟡 | `PERF.fork_only_exit`, `PERF.fork_with_inherited_pipe` | ~9x native fork-only, ~8x fork+pipe post-Phase-3. PERF probes are regression guards. Further improvement = future work (not blocking either goal). |
| Pipeline shapes (cat-pipe-head, node-spawn-bash-drain) | ✅ | `dropbear_bash.*` 24/24, `CL3.mux_pipe.*` | Phase H red gate closed; e1aa42d0 D5 work generalized. |
| **TUI mode startup + interactive rendering (Copilot CLI)** | ✅ | `copilot::tui.startup_then_exit` PASS native + litebox; `copilot::tui.llm.simple_math` + `copilot::tui.llm.simple_bash` PASS native + litebox; deterministic noLLM gates: `copilot::tui.bang.{simple_bash,read_file,pipeline_wc,find_head}` PASS native + litebox (serially); `copilot::tui.bang.build` PASS native, reproduces TUI startup-hang under litebox; 6 minimal PTY+signal probes (5 shim divergences fixed; 2 confirming) | **Five shim divergences identified and fixed by session 7c1fc95d**: (1) TIOCGPTN-on-slave returned pty_id instead of ENOTTY (commit `7858a614`); (2) openat("/dev/pts/", O_DIRECTORY) returned ENOENT instead of falling through to rootfs FS (`8c373d50`); (3) readlink on /proc/self/fd/{0,1,2} returned generic /dev/std{in,out,err} instead of /dev/pts/<pty_id> for BrokerPty slaves (`b65b6047`); (4) SIG_DFL for Stop-disposition signals (SIGTSTP/SIGTTIN/SIGTTOU) terminated the process instead of being a no-op (`27393b02`); (5) is_signal_blocked_or_ignored returned false for SIG_DFL Stop signals, causing broker_pty_background_read_sigttin to deliver SIGTTIN in a loop that became an EINTR storm after fix #4 made the handler a no-op (commit `e72ea86d` — sibling fix that completes #4). All probes PASS native + litebox. **End-to-end TUI startup now works**: copilot's launcher and node child stay alive, copilot's TUI capability negotiation completes, trust modal renders, harness sees the markers. This row flips to ✅. **Bang (noLLM) deterministic gates added** (branch `wportnoy/copilot-noLLM-bang-variants`, refactor commit `d2711cc5`): Copilot CLI's `!<shell-cmd>` TUI passthrough runs commands locally without an LLM round-trip and without a GitHub token, exercising the same TUI startup/input/render/teardown surface as LLM-driven scenarios. The full copilot trial set is now organized as a (Mode × Driver × Scenario) matrix with IDs `copilot::<mode>.<driver>.<scenario>` (4 segments uniform); `Driver::Bang` is TUI-only by design. This enables the TUI regression-window bisect to run on deterministic, token-free tests — under parallel load the bang variants reproduce the same 188-byte startup-hang signature seen in LLM-driven trials, providing a stable diagnostic surface. |
| TUI `find_head` (Copilot shell-tool) | 🟡 | `copilot::tui.llm.find_head*`, `copilot::pminus.llm.find_head*`, plus deterministic bang gate `copilot::tui.bang.find_head` (PASS native + litebox serially — confirms shell-tool execution path itself is fine, the regression is upstream in the LLM-driven prompt → shell-tool dispatch) | Validation session 7c1fc95d (run_id 30281) confirmed regression: 1/8 `pminus.find_head_*` variants pass (only `find_head_ls`), 0/4 `tui.find_head*` variants pass. Originally hypothesised as transitively fixed by Phase 3 (802afcd2); falsified by data. **Downstream of the broader TUI mode startup capability above** — find_head behavior cannot be evaluated until TUI mode starts. Bisect the broader row first; this row likely flips when that root cause is fixed. The new `copilot::tui.bang.find_head` deterministic gate (same `find /workspace -name '*.txt' \| head -5` pipeline, but run via Copilot's `!` passthrough rather than via LLM-driven shell-tool dispatch) PASSes under litebox — narrowing the regression surface: the pipeline + shell-tool execution work; the LLM → shell-tool dispatch path is what's regressing. |
| pidfd_open + waitid(P_PIDFD) | ✅ | `PIDFD.open_and_waitid` | Session 15 round 3 (`goal2-pidfd`, commit `3552f8ad`). |
| pidfd_send_signal + WIFSIGNALED encoding | ✅ | `PIDFD.send_signal`, `KILL_WAIT.signal_kill_propagation.*` 3+3 | Session 16 round 5. WIFSIGNALED substrate landed `goal3-pidfd-wait` commit `e9373c76` (worker raw `wait_status` plumbed end-to-end via `worker_raw_wait_status_to_registry_status`; WCOREDUMP preserved). pidfd delivery landed `goal3-pidfd-signal` commit `c8ea23ca` (pidfd → guest pid → `sys_kill`; `is_running` extended to consult `fork_child_host_pids`). |
| broker wait-status WIFSIGNALED preservation | ✅ | `KILL_WAIT.signal_kill_propagation.*` 3+3 | Substrate for pidfd_send_signal. Session 16 round 5 commit `e9373c76`. Replaces previous `(exit_code - 256) + 128` lossy encoding at 4 sites in `process.rs`. |
| UDS_STREAM broker-held (Phase U.1) | ✅ | `UDS_STREAM.*` 48/48 | Session 15 round 3 (`goal2-stream-flip`, `LITEBOX_EAGER_BROKER_SOCKETPAIR=1` default). |
| UDS_SEQPACKET broker-held (Phase U.3) | ✅ | `UDS_SEQPACKET.*` 10/10 | Session 15 round 3 (`goal2-seqpacket`, default-on). |
| UDS_DGRAM with SCM_RIGHTS | ✅ | `UDS_DGRAM_SCM.*` 8/8 | Session 16 round 4 (`goal3-scm-rights`, commit `b1c5b479`). file/pipe/dgram supported; MSG_CTRUNC handled. |
| SCM_CREDENTIALS on dgram | 🟦 | — | Documented as deferred by `goal3-scm-rights`. Likely not needed by either Goal A or B. |
| Broker-held inet (TCP/UDP/listener/raw) | ✅ | `BL.*`, `INHERIT.tcp_*`, `BL.udp_recvfrom_remote_addr`, etc. | Phases A-F.1 landed pre-Phase-3. Phase F.2/F.3 (delete worker-local smoltcp, reclaim broker net_proxy) explicitly deferred — see 802afcd2 plan.md "Pending follow-ups." |
| Broker-held inotify (file watching) | ✅ | INO families | Landed pre-Phase-3. Required for VS Code file-change subscriptions. |
| OFD registry (cross-connection 9P fid inherit) | ✅ | `inherit_matrix.fs_fid.*` 3 tests | Phase 3 D3 + D5-fs (e1aa42d0 Sessions 11-13). |
| Mux relay topology retired | ✅ | All CL3 / mux test families | Phase 3 D6/D7 — `multiplexer.rs` and `litebox::pipes` module deleted. |
| HostPassthroughFd rename + install-site invariant audit | ✅ | INV families | Session 16 round 4 (`goal3-externalfd-rename`, commit `25dadda4`). Outbound TCP raw-host fallback deleted (broker TCP mandatory). |
| cli → node transition (StaticPieMusl → NonPieGlibc) | ✅ | `Dpg1SpmDng.*` agent + `VS.shape.smoke` | Covered by canonical agent tree per `litebox_test_harness/CLAUDE.md`. |
| **Goal-B end-to-end validation: VS Code Remote Server inside Litebox** | ✅ | `vscode::bootstrap`, `vscode::server_listen`, `vscode::connect_loopback`, `vscode::connect_cross_ssh` (4 scenarios × 2 passes = 8 trials, in `litebox_test_harness/tests/integration.rs` `mod vscode`) | Work stream `wportnoy/vscode-integration-tests` (merge `0d000938`, component commits `9f304b6c..ec79648b`). Mirrors `mod copilot`'s shape: per-pass `docker run` of the `litebox-vscode` Dockerfile stage, host-side driven via SSH-over-PTY. Native: 4/4 pass in ~22 s. Litebox: 4/4 pass post-`e4bc258f` (was 0/4 pre-fix — the CLI's `Listening on N.N.N.N:PORT` line sat in the 9P write-behind buffer indefinitely after the CLI entered its `epoll_pwait` accept loop; cross-process bash subshells never saw it). Image flexibility: `LITEBOX_VSCODE_IMAGE_STAGE=prewrite` flips to the `litebox-vscode-prewrite` Dockerfile stage (pre-rewritten `node`/`dropbear`/`bash`); `ensure_vscode_image` copies the workspace-built `litebox_syscall_rewriter` into the build context automatically. Concurrency cap: `LITEBOX_VSCODE_JOBS` (default 1). `litebox::vscode::connect_cross_ssh` is a parallelism-flake candidate at high `LITEBOX_TEST_JOBS` (passes in isolation; CLI bind latency × 8-container CPU contention pushes past the 60 s polling window — same shape as the documented "~16-test parallelism flake cluster"). See `litebox_test_harness/CLAUDE.md` § "VS Code Server integration scenarios". |
| **9P cross-process read-after-write visibility** | ✅ | `CWF.full_visibility.{pie-glibc,nonpie-glibc,static-pie-glibc,static-pie-musl,non-pie-static-musl}.{dpg1,dpg1_dpg1,dpg2}` (5 binary types × 3 agents × 2 passes = 30 trials, in `litebox_test_harness/src/coordinator/special_cases/fs.rs`). Pre-fix: 6/30 FAIL with `"writer wrote 30 bytes, reader sees 29 bytes"` (non-PIE writer variants). Post-fix: 30/30 pass. | Surfaced and fixed by merge `0d000938` (component commit `e4bc258f`). The 9P client's per-process write-behind buffer in `litebox/src/fs/nine_p/mod.rs:331` (`WRITE_BUFFER_CAPACITY = 256 KiB`, `write_buffers: BTreeMap<Fid, WriteBuffer>`) had flush triggers (`flush_write_buffers_for_file` on read/open/seek/truncate, `flush_sibling_write_buffers` on sibling-fid writes, `flush_write_buffer` on close) that only fired on intra-process events. When the writer process went idle after its last write, the tail bytes stayed in the buffer indefinitely — cross-process readers walked straight to the 9P server, read from the host file, and saw only previously-flushed bytes. **Why this only surfaced now**: PIE-writer scenarios pass because PIE binaries can be loaded into the parent's address space and share the runner (and thus the `write_buffers` map), so the parent reader's flush trigger fires on the shared buffer. Non-PIE-writer scenarios go to separate workers with separate runners. Even PIE writers can hit the bug via fork+exec chains where bash (NonPieGlibc) opens the fd and the runner state is inherited through to the final PIE writer process whose runner the reader doesn't share. The fix sets `WRITE_BUFFER_CAPACITY = 0`, short-circuiting every write to the direct-RPC path. **Perf trade-off**: small-write-heavy workloads (cargo build emitting `.d`/`.rmeta` files) lose the coalescing benefit and pay one 9P RPC per write. **Proper perf-preserving follow-up** documented in the constant's doc-comment: small (4 KB) buffer + debounced eager-flush timer that fires Nms after the last write, bounding cross-process visibility delay while preserving tight-loop coalescing — strictly larger change that can land incrementally without re-breaking correctness. |

## What's still in flight or unmapped

Cross-checked against current open todos in active session
`e1aa42d0` plan.md tail:

- **TUI mode startup + interactive rendering (🔴 blocked)** —
  newly-discovered broader regression in the `708fd18..33a2453e`
  window. Every `copilot::tui.*` litebox trial fails, including the
  no-pipe baselines `tui.simple_math` / `tui.simple_bash`. Bisect
  required; see capability detail row.
- TUI `find_head` w8/w10 (🟡) — re-verified against `898af46a` in
  dashboard `run_id=30281`; Phase 3 did **not** transitively resolve.
  **Downstream of the TUI mode startup row above** and likely flips
  with it.
- `ha-probe` (parked HypB probe — not actively pursued).
- HypB notification-coalescing (🟡 30/60 remaining failures, deferred until a specific consumer needs it).

The map's leaf-status flips for Goal A would be: TUI mode startup → ✅
(unblocks Goal A and W8/W10 simultaneously). Goal B's capability nodes
are all ✅ as of round 5 (Session 16); its end-to-end validation layer
landed in merge `0d000938` (work stream
`wportnoy/vscode-integration-tests`) with 4 `vscode::*` Trials all
passing under both native and litebox after the same merge's 9P
write-behind buffer correctness fix.

After Goal A's TUI mode startup flips, the remaining gap to declaring
each goal "done" is *end-to-end validation*. **Goal B is now covered**
by the `vscode::*` Trials added in merge `0d000938` (running the
actual VS Code CLI inside the litebox sandbox over SSH, validating
bootstrap, listener bind, loopback connect, and cross-SSH connect).
**Goal A** is similarly covered for non-LLM scenarios by the
`copilot::tui.startup_then_exit` + `copilot::tui.bang.*` Trials
(Session 7c1fc95d); LLM-driven Trials still depend on a GitHub token
and the upstream model's response shape, so they remain flaky-by-
design rather than a hard gate on Goal A.

## Maintenance

This file is the **canonical** product-goal view across all
concurrent sessions. It serves two roles: a status snapshot
(the diagram + emoji legend) AND a curated knowledge base
(the Capability detail table accumulates evidence about each
capability over time). To avoid lost updates, edits are made
only at amalgamation merge points:

1. **Sessions don't update this file mid-flight on their
   work-stream branches.** Each session declares which capability
   its current work targets in its own private `plan.md`
   ("Capability: <node name>") and proceeds normally. Discoveries
   made during the work (new test families, measured numbers,
   edge cases, refined understanding) are also captured in the
   session's plan.md until merge time.
2. **At `--no-ff` merge of a work stream into the amalgamation
   branch (`wportnoy/vscode-server-in-litebox`), the same merge
   commit updates this file.** Two kinds of update are expected:
   - **Status flips on the diagram** (most commonly 🟡 → ✅;
     occasionally 🔴 unblocked by a dependency landing). Status
     is monotonic — capabilities don't un-deliver, so a
     regression+fix in one merge keeps ✅ and the test history
     records the round-trip.
   - **Detail-row updates in the Capability detail table.**
     The table accumulates evidence. As a session learns more
     about a capability while working on it, the merging commit
     should:
     - Add newly-discovered validating test families (when a new
       harness probe or regression guard is added that exercises
       the capability).
     - Refine "Notes / open work" with new measured numbers
       (e.g., a perf ratio that improved), known edge cases
       found during validation, or links to follow-up commits.
     - Rename or split a capability if the original framing
       turned out to be wrong (also update the diagram node + any
       edges).
     - Add new rows for capabilities the work uncovered that the
       map didn't show before (also add the corresponding diagram
       node + goal edges).
3. **Doc-only refinement merges are also permitted.** If a
   session discovers something worth recording but isn't bundled
   with a capability landing (e.g., a wrong link in a notes
   cell, a missing test family, a measurement that needs an
   update), prepare a small `--no-ff` merge with just the doc
   change — same branch+merge discipline as a regular work
   stream, just narrower scope. Don't accumulate doc refinements
   indefinitely in a private plan.md; small doc-only merges keep
   the canonical view fresh.
4. **Conflicting concurrent updates** (rare; both sessions
   flipped the same node, or both refined the same detail row)
   resolve at the amalgamation merge via standard `git merge`
   semantics. ✅ wins over 🟡; identical ✅ flips trivially
   merge; detail-row conflicts use the same conflict-resolution
   judgment as any other prose conflict — merge what's true now,
   keep the richer evidence.
5. **Sessions starting new work should fetch and read this file**
   from `origin/wportnoy/vscode-server-in-litebox` to see which
   capabilities are 🟡 or ⚪ before claiming a new one — avoids
   silent duplication of effort. Session-private plan.md
   continues to record which capability ID the session has
   claimed.
6. **Periodic curation is healthy.** Status emojis are
   monotonic, but detail-row prose can drift (stale notes, dated
   measurements, outgrown limitations). When a session notices a
   row is no longer accurate, a doc-only merge per (3) is the
   right fix. There's no automated audit — this is a "leave it
   better than you found it" norm.

For per-session todo detail (granular sub-tasks, harness shapes,
debugging notes), continue reading the relevant
`~/.copilot/session-state/<id>/plan.md`. This file describes the
**what** of the product (and accumulates what we've learned about
each capability); per-session plans describe the **how** of the
work.

The Mermaid diagram renders in VS Code preview, GitHub PRs, and
most modern markdown viewers. If you need an alternate format,
add it alongside the diagram block rather than replacing it.
