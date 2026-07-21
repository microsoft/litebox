# Upstream decomposition map

> **Purpose:** the `wportnoy/vscode-server-in-litebox` amalgamation has reached
> its milestone (VS Code Remote Server + sandbox policy enforcement + audit
> frontier viz run under Litebox). This file maps its ~2496-commit / ~450K-line
> divergence into **small, correctly-targeted, hand-reviewable PRs** for the two
> upstreams — `main` (bug fixes only) and `ulitebox` (user-space Litebox with a
> broker). Both upstreams are artisanal / hand-reviewed, so **large PRs are a
> hard sell**; every landed change is a minimal single-purpose PR.
>
> **Companion:** `docs/product-goal-map.md` (what capabilities exist);
> this file (how to get them upstream). Maintained as the decomposition
> proceeds — see "Maintenance" at the bottom.

## TL;DR

- Merge-base with **both** `origin/main` and `origin/ulitebox`: `56174aa2`
  (~4 months old). Divergence since: **280 `--no-ff` work-stream merges /
  2496 commits**.
- **Front-loaded work: Bucket A** — substrate bug fixes that port to *both*
  targets, the proven **#891 → main / #908 → ulitebox** recipe.
- Path-level triage of the 280 merges: **A=66, B=69, D=131, N=14, W=0**
  (definitions below). Path-level A is an **over-count** — several A-by-path
  merges are internally broker- or fork-migration-coupled and fail content
  review. **Content review is authoritative.**
- **Verified-ready dual-target `main` candidates:** 2 — the advisory-sockopt
  accepts (`IP_TOS`, `SO_RCVBUF`, `SO_SNDBUF`), submitted as PR #1054. The
  `SIG_DFL` stop-signal no-op was **dropped on quality review** (a silent no-op
  that hides an unimplemented STOP; maintainer chose to leave `main` as-is).
  Plus 1 to re-check, 2 sliceable, 1 feature. See the Bucket-A ranking.
- **Approval gate:** no PR is opened for any bucket without explicit sign-off
  on that specific candidate.

## Branch topology (verified via GitHub API + local git)

| Crate group | amalgamation | `main` | `ulitebox` |
|---|:--:|:--:|:--:|
| **7 shared Linux substrate crates** — `litebox`, `litebox_common_linux`, `litebox_platform_linux_userland`, `litebox_platform_linux_kernel`, `litebox_runner_linux_userland`, `litebox_shim_linux`, `litebox_syscall_rewriter` | ✓ | ✓ (same names) | ✓ (same names) |
| optee / lvbs / snp / windows platform+runner, `litebox_util_log*`, `litebox_packager`, `dev_tests`/`dev_bench` | ✓ | ✓ | ✓ |
| `litebox_broker` (monolithic) | ✓ | ✗ | ✗ |
| 6-crate modular broker `litebox_broker_{core,host,local,protocol,transport,userland}` | ✗ | ✗ | ✓ |
| `litebox_tool_executor`, `litebox_audit_query`, `litebox_test_harness` | ✓ | ✗ | ✗ |

- **`main`** = classic single-process Litebox — **no broker at all** (resources
  are in-process in the shim), no tool_executor, no audit_query, no harness.
- **`ulitebox`** = **6-crate modular broker** (broker-held resources) + the same
  7 Linux substrate crates; no tool_executor/audit_query/harness.
- **Validation reality:** `dev_tests` is a **hygiene/ratchet crate**
  (license-header boilerplate + lint ratchets over all source files) on *every*
  branch — **not** behavioral tests. Behavioral tests live inline as
  `#[cfg(test)]` in each crate's `src`. The amalgamation-only
  `litebox_test_harness` (Docker integration) does **not** exist on either
  target, so harness tests do **not** port — a ported fix should carry a
  main-native inline test, **unless** it is extremely simple and the crate has
  no existing test scaffold for it (e.g. the sockopt accept in PR #1054).

## The proven PR recipe (#891 / #908)

`fix(loader): page-align head/tail munmap in MapMemory::reserve`:
- **PR #891 → `main`** — branch `wportnoy/optee-reserve-page-align`, 3 files
  (+248/-20), all shared substrate (`common_linux/loader.rs`,
  `shim_linux/loader/elf.rs`, `shim_optee/loader/elf.rs`), conventional-commit
  title, review rounds landed as `review:`-prefixed follow-up commits (renames
  + doc tightening the reviewer requested).
- **PR #908 → `ulitebox`** — branch `wportnoy/ulitebox-reserve-page-align`,
  cherry-pick of #891, title suffixed `(cherry-pick of #891)`.

**Cadence: both-PRs-per-fix, main-first.** Each fix ships as its own `main` PR
**and** a separate `ulitebox` cherry-pick PR — but **sequentially**: open the
`main` PR first, and only **after it merges** open the cherry-pick PR against
`ulitebox` (as #908 followed #891). Never batch multiple fixes into one PR (the
team is particular about PR structure + commit messages).

**PR-description convention (litebox team):** 2–4 sentences describing the
change, **no extra line breaks** (a single flowing paragraph), and **no
nonessentials** — do not mention that tests pass / clippy is clean / how it was
validated. Commit messages use conventional-commit titles (`fix(scope): …`);
the standard `Co-authored-by: Copilot` + `Copilot-Session:` trailers are fine in
**commit messages** but must **not** appear in the PR description body.

### PRs in flight

| candidate | main PR | ulitebox PR |
|:--|:--|:--|
| advisory-sockopt accept (IP_TOS, SO_RCVBUF, SO_SNDBUF) | **#1054** (open) | queued — after #1054 merges |

## Methodology (reproducible)

1. `git merge-base HEAD origin/main` → `56174aa2` (same for `origin/ulitebox`).
2. Enumerate work streams: `git log --first-parent --merges 56174aa2..HEAD`.
3. Per merge `M`, the work stream's own changes = `git diff M^1...M^2`; bucket
   by the set of top-level crates it touches (path sieve):
   - touches `litebox_broker` → **B** (broker-coupled → ulitebox).
   - else touches a shared substrate crate → **A** (candidate dual-target).
   - else only windows crates → **W**; else only tooling → **D**; else **N**.
4. **Content review (authoritative)** for each A candidate: (a) is the change
   broker-/fork-migration-independent? (b) does the *current* target still have
   the un-fixed code (`git show origin/main:<file>`), or is it a no-op / a
   feature the target's diverged model doesn't have? Reject no-ops and
   model-coupled changes.
5. Re-express the harness test as an inline `#[cfg(test)]` unit test (or main's
   guest-ELF path) on the target.

## Bucket distribution (path sieve, 280 merges)

| Bucket | merges | +lines | meaning | target |
|:--:|--:|--:|:--|:--|
| **A** | 66 | ~54K | shared-substrate-only (no broker crate) | main **+** ulitebox (content-review gated) |
| **B** | 69 | ~110K | touches `litebox_broker` | ulitebox (adapt to 6-crate broker) |
| **D** | 131 | ~76K | tooling: harness / tool_executor / audit_query / dashboard | optional / greenfield |
| **N** | 14 | ~0.8K | docs / policy / CI / junk only | n/a |
| **W** | 0 | 0 | windows-only | (none since fork) |

A cross-cutting **fork-migration** sub-theme (delayed-fork, vfork-quiesce,
CoW snapshot-restore, worker-host migration, descriptor-table sealing) runs
through both the A-path and B-path pools. It is **Bucket C** conceptually —
**not upstreamable to either target** (ulitebox's one-guest-per-host model
obviates it; main has no broker/worker-host model). Content review routes these
out of the dual-target set.

## Bucket A — dual-target substrate candidates (content-reviewed)

**Only ~2–4 of the 66 A-by-path merges are genuinely clean, upstream-quality
dual-target `main` fixes** — and as content review proceeds the pool keeps
shrinking (candidates turn out broker-/fork-migration-coupled, already
independently implemented on `main`, or scenario-driven papering-over). So far
the sockopt accept (**PR #1054**) is the only confirmed one. The
ranking below is authoritative (coupling-symbol scan of each merge's shared-crate
diff + subject semantics + `origin/main` presence check). The raw size-ordered
table is kept as a `<details>` reference at the end of this section.

Verdict tally: **A-READY**=2, **A-DROP**=1, **A-CHECK**=0, **A-SLICE**=0, **A-FEAT**=1,
**->review**=1, **->B**=24, **->C**=27, **->D**=3, **REJECT**=7.

Legend: **A-READY** = verified clean + broker-independent + still-buggy on
`main` + **upstream-quality** (a real fix, not a silent papering-over of an
unimplemented path) — extract now · **A-DROP** = portable but rejected on
*quality* review (e.g. hides an unimplemented gap by going silent); left as-is
on `main` · **A-CHECK** = clean-looking, one `main`-diff check pending
· **A-SLICE** = a portable fix bundled inside a broker merge (extract the hunk) ·
**A-FEAT** = portable but a feature `main` deliberately rejects (product call) ·
**->B**/**->C**/**->D** = content review re-routes an A-by-path merge to
ulitebox-broker / fork-migration-neither / tooling · **REJECT** = no-op on main,
model mismatch, or noise. **A-SLICE extraction:** cherry-pick the merge,
`git reset` the broker hunks, keep only the substrate hunk + inline its test.

**Quality bar (learned from SIG_DFL):** portability is necessary but not
sufficient. A fix that only lets *our* scenario progress by silencing a
previously-loud unimplemented path (e.g. turning `terminate`-on-unimplemented
into a silent no-op) violates this repo's "loud failure for unimplemented"
principle and is **not** A-READY even though it compiles and is
broker-independent. Scrutinize each candidate for whether it is a real fix or a
papering-over before promoting it.

**Conclusion (Bucket A fully content-reviewed):** every A candidate that could be
a genuine fix has been read at diff level. The **only** clean, upstream-quality,
main-portable Bucket-A *bug fix* is the advisory-sockopt accept (**PR #1054**).
SIG_DFL (A-DROP) and its companion `fd51b53cb` (REJECT) are scenario-driven
papering-over of unimplemented STOP; sendfile (REJECT) and WIFSIGNALED (->C) are
already-on-main / worker-host-coupled. The one clean *feature* is netlink
(**A-FEAT**) — but that means porting the whole `netlink.rs` module `main` rejects
by design (`AF_NETLINK`→EAFNOSUPPORT), a maintainer-buy-in decision, not a quick
win. **Implication: the amalgamation's durable upstream value is overwhelmingly
Bucket B (the broker-held-resource model → ulitebox), not portable `main`
bug-fixes.**

| verdict | size | sha | work-stream — description | why |
|:--|--:|:--|:--|:--|
| A-READY | `7/1` | `fc2b3134d` | session-iptos-shim-fix — accept setsockopt(SOL_IP, IP_TOS) | **main PR #1054 (open)**; broker-indep |
| A-READY | `11/4` | `30782b911` | session-rcvbuf-sndbuf-fix — accept SO_RCVBUF/SO_SNDBUF | **main PR #1054 (open)**; net.rs+unix.rs |
| A-DROP | `140/5` | `27393b02a` | SIG_DFL Stop signals as no-op (SIGTTIN-cascade) | portable but a silent no-op that hides unimplemented STOP (removes the error log); dropped on quality review — `main` left terminating |
| REJECT | `15/3` | `fd51b53cb` | TUI mode startup — 5 shim signal divergences | companion to the dropped SIG_DFL change (extends the "is-ignored" predicate to `Stop`, valid only once SIG_DFL Stop is a no-op) **and** broker-coupled (`broker_pty_background_read_sigttin`) — papering-over + coupled |
| REJECT | `141/46` | `13b12131b` | wave10 — SCM eventfd refs + **sendfile** | `main` already has a complete independent `sys_sendfile` (file.rs:564); amalgamation's also uses `park_if_deferred` (delayed-fork) — redundant + coupled |
| ->C | `262/281` | `e7e59d2b6` | Phase 3 r5 — **WIFSIGNALED** encoding + pidfd delegation | the encoding lives entirely in the worker-host path (`worker_*`/`wait_worker_host`/`write_worker_result`/`host_pid` + coordinator/fork_matrix.rs) — fork-migration machinery main lacks; not a portable wait-status fix |
| A-FEAT | `136/6` | `15f57bdda` | netlink-getifaddrs (increment) | this merge only adds `set_nl_pid`; the real feature is the whole `netlink.rs` module (RTM_GETADDR/getifaddrs) main lacks (`AF_NETLINK`→EAFNOSUPPORT by design), assembled across many commits — a **feature needing maintainer buy-in**, not a cherry-pick |
| ->review | `176/14` | `704336e24` | orphan-kpx | process-lifecycle — needs a manual look |
| ->B (24 merges) | 6/3 … 6065/1329 | — | broker TCP/pipe/PTY/pidfd/scm/socketpair/cwfd/epoll-local, wave-*, broker-exit-status | broker-coupled — adapt into ulitebox 6-crate broker |
| ->C (26 merges) | 6/4 … 4685/383 | — | fork-restore, vfork-quiesce, delayed-fork, CoW, seal-descriptor-table, wave-cleanup, invariants, clone-hang | fork-migration / refactor — neither target |
| ->D (3 merges) | 83/3, 632/96, 923/50 | — | audit-log-improvements, --ssh mode, audit-canonical-names | tooling (audit_query / tool_executor) |
| REJECT (5) | 4/0 … 20288/20288 | — | munmap/madvise allowlist, /dev/pts, TIOCGPTN, non-PIE-loader, line-endings | no-op / model-mismatch / noise on main |

The full per-merge ->B/->C/->D/REJECT rows are in the `<details>` raw table plus
the git analysis; the summarized rows above collapse them by verdict.

<details><summary>Raw size-ordered A-by-path table (reference; the <code>hint</code> column is a keyword heuristic with known false positives — trust the verdict ranking above)</summary>

| size (+/-) | hint | crates | work-stream — description |
|---:|:--|:--|:--|
| `4/0` | cleanish | lb_shim_linux | wave8-session — allowlist teardown munmap/madvise |
| `6/3` | broker | lb_shim_linux | brokertcpconn-cross-nonpie-legs — fix remote-exec placeholder panic (INHERIT.tcp_conn FLAG_ON 65/10 → 73/2) |
| `6/4` | forkmig | lb_runner_linux_userland | wave1-c1: fork-restore seed registry from snapshot pid |
| `7/2` | broker | lb_shim_linux | flake-fklc — host-poll fallback for broker TCP connect completion |
| `7/1` | cleanish | lb_shim_linux | session-iptos-shim-fix — silently accept setsockopt(SOL_IP, IP_TOS) |
| `9/0` | cleanish | lb_shim_linux | shim /dev/pts/ bare directory falls through to rootfs FS (flips probe to PASS) |
| `9/0` | cleanish | lb_shim_linux | shim TIOCGPTN-on-slave returns ENOTTY (flips both probes above to PASS) |
| `10/2` | forkmig | lb_shim_linux | exec-stdio-reentrancy — drop descriptor_table guard before worker_exec stdio fallbacks |
| `10/1` | broker | lb_shim_linux | wave-5 shell-static cluster — broker pipe EINTR retry on ignored signals |
| `10/0` | broker | lb_shim_linux | wave11-session — worker-host pidfd exit notification |
| `10/9` | cleanish | lb_shim_linux | wave2-c8: reject stackless clone3 fork emulation |
| `11/4` | cleanish | lb_shim_linux | session-rcvbuf-sndbuf-fix — silently accept SO_RCVBUF/SO_SNDBUF |
| `12/5` | forkmig | lb_shim_linux | flake-mtf — honor fork-quiesce interrupt in epoll SIGCHLD retry |
| `12/0` | forkmig | lb_shim_linux | wave-7 mixed cluster — delayed-fork relative sleep migration fix |
| `13/21` | broker | lb_shim_linux | wave4-session — release broker pipe transit refs at child restore ack |
| `15/3` | review | docs, lb_shim_linux | (session): TUI mode startup flips ✅ — 5 shim divergences fixed, copilot::tui.* passes end-to-end |
| `20/5` | review | lb_shim_linux | flake-fork — MTF multithread-fork flake fix (PROMOTION residual tracked) |
| `20/8` | cleanish | litebox, lb_shim_linux | wave1-c2: non-PIE loader fixes (PXEOF/PB non-pie cluster) |
| `24/6` | forkmig | lb_shim_linux | rl-fork-quiesce — fix re-entrant descriptor_table RwLock deadlock in snapshot_fd_table |
| `26/15` | broker | lb_runner_linux_userland, lb_shim_linux | broker PTY worker-exec transit ref release |
| `31/3` | broker | lb_shim_linux | wave-5 PTY+UF+PN+PIDF cluster — preserve fork fds for delayed static workers |
| `38/41` | forkmig | lb_shim_linux | seal-shim-reentrancy — statically enforce with_socket raw_descriptor_store (Phase 2) |
| `39/10` | review | lb_shim_linux | wave-5 U.server_fork nonpie cluster |
| `40/2` | forkmig | lb_shim_linux | wave5-session — CLOEXEC fork-restore + stdio drain fixes |
| `65/0` | broker | lb_shim_linux | wave9-session — pidfd transient subscriptions + broker-pipe bridge release |
| `83/3` | review | lb_runner_linux_userland, lb_shim_linux, lb_test_harness | Merge branch 'wportnoy/audit-log-improvements' into wportnoy/vscode-server-in-litebox |
| `86/3` | review | lb_shim_linux, lb_test_harness | wave9 copilot-tui — PN-child fix + find_head regression probes |
| `88/10` | forkmig | lb_shim_linux | seal-phase3 — fix concurrent_fork pthread_join hang (vfork CoW restore clobbers exiting sibling's clear_child_tid) |
| `92/80` | forkmig | lb_shim_linux | wave2-c6: allow nested delayed-fork fork (collapses RL cluster) |
| `110/12` | broker | lb_runner_linux_userland, lb_shim_linux | wportnoy/litebox-wave-4 — wave-5 PTY fixes |
| `119/10` | broker | lb_common_linux, lb_shim_linux | scm-pipe-fd-variant-fix |
| `136/6` | cleanish | lb_shim_linux, lb_test_harness | Merge branch 'wportnoy/netlink-getifaddrs' into wportnoy/vscode-server-in-litebox |
| `140/5` | cleanish | lb_shim_linux, lb_test_harness | (session): SIG_DFL Stop signals as no-op — 4th shim divergence (SIGTTIN-cascade) fixed |
| `141/46` | broker | lb_common_linux, lb_shim_linux | wave10-session — SCM eventfd receiver refs + sendfile implementation |
| `148/116` | broker | lb_platform_linux_userland, lb_runner_linux_userland, lb_shim_linux | wportnoy/broker-exit-status — retire --worker-result-fd pipe vestige |
| `152/1` | broker | docs, lb_shim_linux, lb_test_harness | (session): land session-7c1fc95d milestone — 3 shim divergences fixed, 5 minimal PTY probes added |
| `176/14` | review | lb_platform_linux_userland, lb_shim_linux, lb_test_harness | wportnoy/orphan-kpx |
| `201/353` | review | litebox, lb_shim_linux, lb_test_harness | wportnoy/invariants — PR-6 + f-static-residual |
| `235/27` | review | litebox, lb_common_linux, lb_shim_linux, lb_shim_windows | wportnoy/litebox-wave-4 — 4 platform fixes |
| `262/281` | broker | lb_platform_linux_userland, lb_runner_linux_userland, lb_shim_linux, lb_test_harness | Phase 3 follow-ups round 5 (WIFSIGNALED encoding + pidfd_send_signal delegation) |
| `263/1` | review | lb_shim_linux, lb_test_harness | phase-h-clone-hang-fix — capture dropbear clone args + add minimal probe (CL3.dropbear_clone.dpg1) |
| `319/134` | forkmig | lb_common_linux, lb_platform_linux_userland, lb_runner_linux_userland, lb_shim_linux | wportnoy/broker-restore-ack — retire --fork-restore-ack-fd pipe vestige |
| `320/1` | broker | lb_shim_linux, lb_test_harness | wave6-session — socketpair shutdown dispatch (Copilot CLI unblock) |
| `323/56` | review | .github, litebox, lb_platform_linux_userland, lb_platform_windows_userland, lb_shim_linux, lb_test_harness | lock-tracing-mutex — Mutex detector + per-thread hardening + with_socket re-entrancy fix |
| `327/3` | review | lb_shim_linux, lb_test_harness | phase-h-dropbear-child-setup — dropbear clone hang FIXED (3/5 Phase H trials now PASS) |
| `372/84` | review | .github, docs, litebox, lb_shim_linux | lock-safety-session — compile-time + runtime re-entrant-lock safety (B+C) |
| `373/36` | review | lb_common_linux, lb_runner_linux_userland, lb_shim_linux | wportnoy/litebox-wave-3 — wave-2 + wave-3 platform fixes |
| `387/9` | broker | lb_shim_linux, lb_test_harness | Merge branch 'wportnoy/pipe-bridge-fix' into wportnoy/vscode-server-in-litebox |
| `400/18` | broker | lb_shim_linux, lb_test_harness | Phase H — BrokerPty plumbing + PTY atomicity invariant tests |
| `534/1` | broker | lb_shim_linux, lb_test_harness | fork-pipe-fd-inheritance |
| `574/86` | broker | docs, lb_shim_linux, lb_test_harness | wportnoy/wave3 — third wave pushing residual litebox FAILs toward zero (4 substrate fixes + 1 test-side fix + PTY-marker investigation) |
| `608/0` | broker | lb_common_linux | cwfd-phase3 — Phase 3a fd-transfer wire frame |
| `632/96` | review | litebox, lb_tool_executor | session-tty-via-ssh — --ssh mode + collapse --interactive |
| `763/28` | review | lb_shim_linux, lb_test_harness | epoll-edge-fix — local-epoll EPOLLET edge-dedup (agent-host reactor spin) |
| `923/50` | cleanish | lb_audit_query, lb_shim_linux | audit-canonical-names — replace "other" syscall bucket with canonical snake_case names |
| `928/26` | review | lb_shim_linux, lb_test_harness, lb_tool_executor | epoll-out-surgical — VS Code server-side local-fd EPOLLET edge-dedup (node/libuv EPOLLOUT-storm spin) + /run/dropbear.pid demo-policy allowlist |
| `1086/1682` | broker | litebox, lb_common_linux, lb_platform_linux_userland, lb_runner_linux_userland, lb_shim_linux, lb_test_harness | PTY Stage B + invariants sync — eager broker PTY |
| `1364/945` | broker | lb_shim_linux, lb_test_harness | PTY dropbear emul, signalfd fixes, exhaustive RawFdRef dispatch |
| `1601/17` | forkmig | litebox, lb_shim_linux, lb_test_harness | wportnoy/vfork-quiesce-fix — Extension Host steady-state (vfork-quiesce + FS layered-cache deadlocks) |
| `1692/93` | review | litebox, lb_test_harness, lb_tool_executor | wportnoy/vscode-integration-tests — VS Code Remote Server end-to-end trials + 9P cross-process visibility fix |
| `1769/16` | review | lb_shim_linux, lb_test_harness | phase 3 follow-up harness coverage + cross-process invariants |
| `2038/1001` | forkmig | litebox, lb_platform_linux_userland, lb_runner_linux_userland, lb_shim_linux | seal-descriptor-table — statically seal descriptor_table() in the FS layer (Phase 1) |
| `3187/1704` | broker | docs, lb_runner_linux_userland, lb_shim_linux, lb_test_harness | wportnoy/wave-cleanup-2 — second wave of broker-fd fork-path consolidation |
| `4685/383` | forkmig | lb_shim_linux, lb_test_harness | wportnoy/wave-cleanup — vfork CoW substrate fix + broker-held simplifications + 911 new tests |
| `6065/1329` | review | .github, litebox, lb_shim_linux, lb_test_harness | wportnoy/binary-types-matrix-merge-blockers — 5-leg BinaryType axis + VS Code blocker fixes |
| `20288/20288` | review | lb_shim_linux | Merge branch 'fix/cleanup-line-endings' into wportnoy/vscode-server-in-litebox |

</details>

### Verified-ready (content-reviewed, dual-target, not-yet-present on `main`)

| candidate | change | broker-independent? | main today | status |
|:--|:--|:--:|:--|:--|
| **`IP_TOS` accept** | `net.rs` setsockopt `IpOption::TOS => Ok(())` (was `EOPNOTSUPP`) | yes (shim early-accept; TOS not propagated) | `net.rs:388` still `Err(EOPNOTSUPP)` | ✅ ready |
| **`SO_RCVBUF`/`SO_SNDBUF` accept** | `net.rs` + `unix.rs` setsockopt `RCVBUF\|SNDBUF => Ok(())` (was `EOPNOTSUPP`); fixed internal buffer size unchanged | yes | `net.rs:399` + `unix.rs:1517` still `Err(EOPNOTSUPP)` | ✅ ready |

Both are the same theme — *silently accept advisory socket options that Node/
libuv treat as fatal* — and mirror an existing in-repo precedent (`IP_RECVERR`,
`IP_MTU_DISCOVER`, `IP_PKTINFO` are already accepted). Motivation is concrete:
Node's `Socket.setTypeOfService` / TLS buffer sizing throw uncaught exceptions
on `EOPNOTSUPP`, tearing down the connection. Candidate for the **first**
`main` + `ulitebox` PR pair.

### Worked rejections (content review overrides the path sieve)

| candidate | why rejected for `main` |
|:--|:--|
| `TIOCGPTN-on-slave → ENOTTY` | `main file.rs:1801` already returns `ENOTTY` for **all** `TIOCGPTN`; refines a PTY-master feature the amalgamation's broker-PTY model has and main does not — no-op/inapplicable. |
| `/dev/pts/` bare-dir fall-through | `main` `file.rs` has **no** `/dev/pts/` handling — different devpts model. |
| `wave1-c2 non-PIE loader fixes` | payload is `has_interpreter()` → `needs_remote` "keep in current worker vs migrate to fresh worker host" — **worker-migration** machinery main lacks (Bucket C). |
| `wave8 munmap/madvise allowlist` | adds syscalls to a *fork-migration* no-migrate allowlist — machinery main lacks (Bucket C). |
| `fix/cleanup-line-endings` (20288/20288) | pure CRLF→LF normalization noise, not a fix. |

## Bucket B — broker-coupled → `ulitebox` (69 merges, ~110K; representative)

Adapt into ulitebox's 6-crate modular broker (state machines, policy, audit) —
**not reimplement**. This is where **this session's sandbox policy enforcement +
audit events** route. Representative (small-first):

| size (+/-) | crates | work-stream — description |
|---:|:--|:--|
| `1/0` | lb_broker | wave-7 KP.proc_child — prewarm /usr/bin/tr |
| `3/7` | lb_broker, lb_shim_linux | wave2-c5: route fixed-address execs to worker-host for node |
| `6/6` | lb_broker | fmt-fixup — restore rustfmt import ordering in net_proxy |
| `6/2` | lb_broker | Phase B.5 — SO_RCVTIMEO/SO_SNDTIMEO passthrough for broker-held TCP |
| `6/4` | lb_broker | Phase B.5 — TCS.send_recv_send.* fixes (5/5 PASS) |
| `14/27` | lb_audit_query, lb_broker | fs-allowed-complete-record — fs_allowed per-evaluation + frontier syscall pre-filter |
| `25/100` | lb_broker, lb_shim_linux | wave-5 INHERIT.signalfd cluster — preserve inherited signalfd state |
| `43/0` | lb_broker | elf-prewarm — pre-warm exec'd coreutils + deps to kill cold-cache rewrite flakes |
| `56/37` | lb_broker, lb_shim_linux, lb_tool_executor | wave3-session — broker prewarm order + pipe writer ref vfork fix |
| `65/0` | lb_broker | fs-allowed-symmetry — audit frontier shows allowed writes/creates, not just opens |
| `72/16` | lb_broker, lb_shim_linux, lb_test_harness | wave-6 copilot CLI close-out — DNS async forwarder + sendmsg + TCP keepalive |
| `73/77` | litebox, lb_broker, lb_runner_linux_userland, lb_shim_linux | phase-d-signal-kill — same-shim SIGKILL→pipe-EOF fix |
| `74/121` | lb_broker, lb_shim_linux | flake-scm — close SCM.pass_two_fds_one_msg receiver residual |
| `80/7` | lb_broker, lb_test_harness | phase-h-broker-pty-refcount-fix — preserve broker pty refs across child exec |
| `94/19` | lb_broker | flake-dropbear-bash — queue early broker inbound TCP streams |
| `94/8` | lb_broker | binet-session-5 — formula-based PTY slave-HUP trigger (Copilot CLI TUI) |

## Bucket D — tooling / harness / dashboard (131 merges, ~76K; representative)

Mostly the live-testing dashboard + harness churn (`dash-*`, `flake-*`,
`watchdog-*`, `fill-drain-*`) and demo glue. The `litebox_test_harness` is the
"crown jewel" but is **greenfield** on both targets (they have neither the
harness nor Docker in CI) — a port would set its own terms (candidate to drop
the binary-type cross-product and Docker). Representative (small-first):

| size (+/-) | crates | work-stream — description |
|---:|:--|:--|
| `1/1` | lb_test_harness | (session): bump tui_noLLM deadline 45->90 — 3/3 pass under contention |
| `2/1` | lb_tool_executor | demo-policy-varrun — allowlist /var/run/dropbear.pid (dropbear writes the /var/run path, not /run) |
| `2/2` | lb_test_harness | drop external issue reference from PTY FOLLOWUP markers |
| `3/3` | lb_tool_executor | wportnoy/vscode-demo-task-fixes — fix Setup-and-Start task (drop bogus non-PIE rustc + neutral problemMatcher) |
| `10/4` | lb_test_harness | dash-freshness-cost — 300s freshness interval (render was starving cargos) |
| `11/6` | lb_tool_executor | Merge branch 'wportnoy/dockerfile-cleanup' into wportnoy/vscode-server-in-litebox |
| `15/23` | lb_test_harness | collapse LITEBOX_TEST_JOBS default into LITEBOX_GLOBAL_JOBS |
| `15/0` | lb_tool_executor | Phase B.5 — dropbear ssh-mode opts out of broker-held inet (F.1 regression fix) |
| `24/27` | lb_test_harness | typed AgentHandle migration of mod suite |
| `27/42` | lb_test_harness | Merge branch 'wportnoy/fix-dead-code' into wportnoy/vscode-server-in-litebox |
| `28/6` | lb_test_harness | wportnoy/native-pidfd-fix — pidfd test target uses pause+signal not fixed sleep |
| `28/7` | lb_test_harness | wportnoy/invariants — fix PTY/perf-split contamination |
| `29/8` | lb_test_harness | clarify LITEBOX_COPILOT_JOBS docs (don't prescribe =1) |
| `32/2` | lb_tool_executor | wportnoy/vscode-demo-add-hosts — --add-host workaround for VS Code Server hang on CNAME-heavy DNS |

## Junk to drop (never upstream; ~170K of the raw insertion count)

`find_head_seq-audit.jsonl` (+150854), `tmp/`, `gdb-bt.txt`, `code-audit.jsonl`,
`pr-debug*.log`, `PHASE_F*_SCOPING.md`, `BRANCH_SUMMARY.md`, `CWFD_NEXT.md`,
`count_commit_words.py`, `*.deb`, `hello_ucrt.obj`, `bash-cat.tar`,
`.lb_docker_pid`.

## Next actions (all PR steps gated on user approval)

1. **[ready]** propose the advisory-sockopt accept (`IP_TOS` + `SO_RCVBUF`/
   `SO_SNDBUF`) as the first `main` PR + `ulitebox` cherry-pick pair.
2. Content-review the remaining `hint=cleanish` / `hint=review` A rows to grow
   the verified-ready shortlist (candidates to check next: `wave2-c8` stackless
   clone3 guard; `netlink-getifaddrs`; `WIFSIGNALED` encoding split out from its
   pidfd bundle; `SIG_DFL` stop-signal no-op).
3. For each approved candidate: minimal fix + inline `#[cfg(test)]` test +
   `cargo fmt`/`build`/`clippy --all-targets --all-features`/`nextest` on the
   touched crate → open both PRs together (#891/#908 style).

## Maintenance

Update this file as decomposition proceeds: flip A rows to ✅ when their PR pair
lands, move rows between buckets when content review reclassifies them, and add
verified-ready / rejection entries as they are established. Regenerate the
counts with the Methodology commands above when the amalgamation advances.
