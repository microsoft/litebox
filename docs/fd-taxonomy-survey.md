# Survey: FdClass / BrokerHandleKind dual-taxonomy collapse evaluation

## TL;DR

- **FdClass and BrokerHandleKind are entirely Linux-shim-local.** No OPTEE crate, no `litebox_broker_protocol` crate (it does not exist), no platform-layer (`litebox_platform_linux_userland/kernel`) and no core `litebox` code references either enum. Only `litebox_runner_linux_userland` references `BrokerHandleKind` (a thin re-import to parse a CLI bridge-spec string).
- **Cross-platform argument for keeping FdClass collapses.** OPTEE's shim does not classify guest fds at all (its only world is TEE-side; `litebox_shim_optee/src/msg_handler.rs:1-30` is about SMC calls, not POSIX fds). There is no platform-portability requirement protecting `FdClass`.
- **FdClass and BrokerHandleKind are NOT 1:1.** Several `RawFdRef` arms map disparate broker kinds onto the same `FdClass` (`BrokerTcpConn`/`BrokerInetDgram`/`BrokerSocketPair` all → `FdClass::UnixSocket`; `BrokerPty` → `FilesystemFd`). A naïve collapse loses information; a typed collapse is fine but the new enum must be richer than either input enum.
- **The if-chain bug in `lib.rs:2046-2120` is structurally real**: the restore loops dispatch on `entry.class == FdClass::X` first, then `broker_handle.kind == BrokerHandleKind::Y` second, with `continue` falls-through on every non-match. Eight `BrokerHandleKind` arms in the inner match return `None`/`continue` to defer to a different outer-class branch; this is the exact shape that hid the SEQPACKET bug.
- **No `#[non_exhaustive]` violations** on any of these enums (AGENTS.md says don't add them; they aren't on these).

---

## 1. Enum inventory

All citations relative to repo root `/home/wportnoy/src/litebox`.

| Enum | Crate / file:line | Variants | Cardinality | `#[non_exhaustive]`? | Wire-serialized? |
|---|---|---|---|---|---|
| `FdClass` | `litebox_shim_linux/src/syscalls/fork_snapshot.rs:387-415` | 11 (10 unconditional + `NetworkSocket` cfg-gated): `FilesystemFd`, `StdioFd`, `Pipe`, `NetworkSocket` (cfg `worker_local_inet`), `UnixSocket`, `Epoll`, `EventFd`, `Signalfd`, `Inotify`, `InetListener`, `BrokerInetRaw` | medium | no | **yes** — `to_wire`/`from_wire` `fork_snapshot.rs:1128-1168` (wire byte) |
| `BrokerHandleKind` | `litebox_shim_linux/src/syscalls/fork_snapshot.rs:295-345` | 11: `Pidfd=1`, `Eventfd=2`, `Signalfd=3`, `Pty=4`, `Pipe=5`, `UnixSocket=6`, `TcpConn=7`, `InetListener=8`, `InetDgram=9`, `SocketDgram=10`, `SocketSeqPacket=11` | medium | no | **yes** — `#[repr(u8)]` + `as_u8`/`from_u8` (same file) |
| `BrokerHandleSnapshot` (struct) | `litebox_shim_linux/src/syscalls/fork_snapshot.rs:269-287` | 5 fields: `kind`, `handle_id`, `pipe_direction: Option<BrokerPipeEnd>`, `socketpair_endpoint: Option<BrokerSocketPairEndpoint>`, `pty_role: Option<BrokerPtyRole>`, `pty_id: Option<u32>` — **Option-soup keyed by `kind`** | — | n/a | yes — written/read at `fork_snapshot.rs:1178-1296` |
| `RawFdRef<'a, FS>` | `litebox_shim_linux/src/lib.rs:2971-2996` | 14 (1 cfg-gated): `Fs`, `Net` (cfg), `Eventfd`, `Epoll`, `Unix`, `HostPassthroughFd`, `BrokerPipe`, `BrokerSocketPair`, `BrokerTcpConn`, `BrokerPty`, `Signalfd`, `Inotify`, `BrokerInetListener`, `BrokerInetDgram`, `BrokerInetRaw` | large | no | no (runtime only) |
| `WorkerExecBridgeDecision` | `litebox_shim_linux/src/lib.rs:2998-3003` | 2: `Bridge`, `NotNeeded` | small | no | no |
| `WorkerExecNoBridgeReason` | `litebox_shim_linux/src/lib.rs:3005-3011` | 3: `KernelFdInherited`, `BrokerOnlyState`, `NotWorkerExecBridgeable` | small | no | no |
| `WorkerExecBridgeState` | `litebox_shim_linux/src/lib.rs:3013-3020` | 4: `BrokerFile`, `TcpListen`, `Signalfd`, `Timerfd` (each with typed payload struct, lines 3022-3049) | small | no | not yet (most arms are `todo!()`) |
| `ForkRejectReason` | `litebox_shim_linux/src/syscalls/fork_snapshot.rs:524-541` | 6: `SharedMapping`, `UnsupportedFdClass{class: FdClass}`, `NonPortableFdMetadata`, `SharedMappingNoBackingPath`, `InotifyPresent`, `BidirectionalSocketOnMultipleStdioSlots` | small | no | embeds `FdClass` |

Per-subsystem types (each implements the `Subsystem` trait; not classification enums but each shows up as a `RawFdRef` arm and has a sibling `FdClass` membership):

| `*Subsystem` | File:line | RawFdRef arm | FdClass it lands in |
|---|---|---|---|
| `EventfdSubsystem` | `syscalls/eventfd.rs` | `Eventfd` | `EventFd` |
| `EpollSubsystem<FS>` | `syscalls/epoll.rs` | `Epoll` | `Epoll` |
| `UnixSocketSubsystem<FS>` | `syscalls/unix.rs` | `Unix` | `UnixSocket` |
| `HostPassthroughFd` | `syscalls/host_passthrough_fd.rs` | `HostPassthroughFd` | `Pipe` (re-bucketed) |
| `BrokerPipeSubsystem` | `syscalls/broker_pipe.rs` | `BrokerPipe` | `Pipe` |
| `BrokerSocketPairSubsystem` | `syscalls/broker_socketpair.rs` | `BrokerSocketPair` | `UnixSocket` |
| `BrokerTcpConnSubsystem` | `syscalls/broker_tcp_conn.rs` | `BrokerTcpConn` | `UnixSocket` ⚠ (legacy bucket) |
| `BrokerInetDgramSubsystem` | `syscalls/broker_inet_dgram.rs` | `BrokerInetDgram` | `UnixSocket` ⚠ |
| `BrokerInetListenerSubsystem` | `syscalls/broker_inet_listener.rs` | `BrokerInetListener` | `InetListener` |
| `BrokerInetRawSubsystem` | `syscalls/broker_inet_raw.rs` | `BrokerInetRaw` | `BrokerInetRaw` |
| `BrokerPtySubsystem` | `syscalls/broker_pty.rs` | `BrokerPty` | `FilesystemFd` ⚠ |
| `BrokerSocketDgramSubsystem` | `syscalls/broker_socket_dgram.rs` | — (no arm; no FdClass mapping found) | — |
| `BrokerSocketSeqPacketSubsystem` | `syscalls/broker_socket_seqpacket.rs` | — (no arm; no FdClass mapping found) | — |
| `SignalfdSubsystem` | `syscalls/signalfd.rs` | `Signalfd` | `Signalfd` |
| `InotifySubsystem` | `syscalls/inotify.rs` | `Inotify` | `Inotify` |

The "⚠" rows are where the dual taxonomy hides information: `BrokerTcpConn`, `BrokerInetDgram`, `BrokerSocketPair` all share `FdClass::UnixSocket`; `BrokerPty` shares `FdClass::FilesystemFd`. The disambiguation only lives in `BrokerHandleKind` on the snapshot side and in `RawFdRef` on the runtime side.

The two `Subsystem` types with no observed `FdClass` mapping (`BrokerSocketDgramSubsystem`, `BrokerSocketSeqPacketSubsystem`) are *exactly* the latent-bug surface the parent flagged in the SEQPACKET investigation: `BrokerHandleKind::SocketDgram`/`SocketSeqPacket` exist as variants, are deserialized, and have `None` arms in the restore if-chain (`lib.rs:2090-2091`) but **no upstream FdClass-side emission path** in `process.rs:5974-6036`.

### Parent-prompt enums that don't exist by name

The parent mentioned `WorkerExecMigrationPolicy`, `DelayedForkPolicy`, `IndependentForkPolicy`, `NoBridgeReason`. Actual names in tree are `WorkerExecBridgeDecision`, `WorkerExecBridgeState`, `WorkerExecNoBridgeReason` (see `lib.rs:2998-3049`). Functionally equivalent.

---

## 2. Conversion graph

| From | To | Site | Exhaustive? | Direction |
|---|---|---|---|---|
| `TypedFd<Subsystem>` lookup | `RawFdRef` | `lib.rs:~2840-2967` (`run_on_raw_fd`, sequential `if let Ok(...) { return f(RawFdRef::X(&fd)) }` chain) | **if-chain** (probe-each-subsystem; not compile-checked) | runtime dispatch |
| `RawFdRef` | `(FdClass, oid, meta, pair_id)` tuple | `process.rs:5970-6038` (inside `snapshot_fd_table`) | **exhaustive `match`** on `RawFdRef` variants (incl. `#[cfg(feature = "worker_local_inet")]` arm) | emit-side |
| `FdClass` | accept/reject | `process.rs:6081-6127` | **exhaustive** (no `_`; per-variant arm; comments call this out) | emit-side |
| `FdClass` | wire byte | `fork_snapshot.rs:1128-1168` (`to_wire`/`from_wire`) | exhaustive | (de)serialize |
| `BrokerHandleKind` | wire byte | `fork_snapshot.rs:321-345` (`as_u8`/`from_u8`) | exhaustive | (de)serialize |
| `&str` (CLI spec token) | `BrokerHandleKind` | `litebox_runner_linux_userland/src/lib.rs:322-332` | partial — falls through to error on unknown | parse |
| `(BrokerHandleKind, sub-tag str)` | `(pipe_direction, socketpair_endpoint, pty_role)` triple | `runner_linux_userland/src/lib.rs:339-393` | **if-chain over `match (kind, sub)`** with explicit arms but mixes "no sub" defaults | parse |
| `RawFdRef` | `WorkerExecBridgeDecision`/`...NoBridgeReason`/`...BridgeState` | `lib.rs:3052-3101` (`worker_exec_bridge_decision`) | **exhaustive `match`** (many `todo!()` arms) | runtime/exec-side |
| `entry.class` (FdClass) + `entry.metadata.broker_handle.kind` (BrokerHandleKind) | restore action | `lib.rs:2046-2207` (multiple `for entry in fd_table.entries { if entry.class != FdClass::X { continue; } … match broker_handle.kind { … } }`); also additional blocks at `lib.rs:1732, 1782, 1823, 1887, 1992, 2049, 2131, 2172, 2230` | **if-chain (the bug)** — outer `if entry.class != FdClass::X { continue }` then either inner match or `if broker_handle.kind != BrokerHandleKind::Y { continue }`. The 2055-2100 match is `match`-exhaustive over `BrokerHandleKind` but the *outer* dispatch is by if-chain across `FdClass`. New `(FdClass, BrokerHandleKind)` pairs add a restore branch in one of nine separately-edited block scopes. | restore-side |
| `FdClass` | `ForkRejectReason::UnsupportedFdClass{class}` | `process.rs:6109, 6119, 6125` | embeds `FdClass` value directly | error reporting |

Key observation: of the seven distinct conversion sites, **every emit-side and runtime-dispatch site is exhaustive (compile-checked)**. Only the restore-side dispatch (lib.rs 2020-2260+) and the runner CLI parser are if-chains. The restore-side if-chain is the bug locus.

---

## 3. OPTEE / cross-platform analysis (CRITICAL)

**Verdict: OPTEE shim uses NEITHER `FdClass` NOR `BrokerHandleKind` NOR `RawFdRef`.** The cross-platform argument for keeping the dual taxonomy does not hold.

Evidence:

- Recursive grep `FdClass|BrokerHandleKind|RawFdRef|fork_snapshot|snapshot_fd_table` over `litebox_shim_optee/`: **zero matches.** The only hit on the `fork|snapshot|FdClass|RawFd` super-pattern is `litebox_shim_optee/src/msg_handler.rs:4`, which is a module doc comment about the OP-TEE message-passing actors — unrelated to the strings.
- OPTEE's file inventory is small (`glob litebox_shim_optee/**/*.rs` → ~14 files, all about SMC calls, TEE message handling, ELF loading for TAs, crypto PTA, ldelf, ta_stack). There is **no fork, no snapshot, no fd-table, no descriptor-store** logic. OPTEE shims a TEE OS, not a POSIX kernel.
- `litebox_shim_optee/src/msg_handler.rs:1-30` confirms scope: "OP-TEE's message passing… involves multiple actors… The OP-TEE shim starts with handling an OP-TEE SMC call from the normal-world OP-TEE driver." No fd model at all.

Also verified no usage in other crates:

- `litebox_broker_protocol` — **crate does not exist** (`glob litebox_broker_protocol/**/*.rs` returned nothing).
- `litebox/src/**` (core), `litebox_common_linux/src/**`, `litebox_platform_linux_userland/src/**`, `litebox_platform_linux_kernel/src/**` — zero `FdClass`/`BrokerHandleKind`/`RawFdRef` references. (`platform_linux_userland/src/lib.rs:1959,2519` mention `create_worker_fork_snapshot_fd`, but that just passes opaque bytes — it doesn't read the taxonomy.)
- `litebox_runner_linux_userland/src/lib.rs:283, 313, 322-415, 1620, 1867, 2078, 2158-2263` — only references `BrokerHandleKind` and the snapshot types, NOT `FdClass`. The runner has its own constructor table for `BrokerHandleKind` from CLI strings; it never sees `FdClass`.
- `litebox_broker/src/cwfd/socketpair_state.rs` — single match on `fork_snapshot` string (doc comment); not a real dependency.

Implication: any taxonomy change is bounded to `litebox_shim_linux` plus a thin `litebox_runner_linux_userland` adjustment (CLI parser). The wire format is the only external commitment, and it's owned by these same two crates.

---

## 4. no_std / feature-gate / cfg considerations

- `litebox_shim_linux` declares `no_std` + `alloc` (the snapshot module imports from `alloc::string::String`, `alloc::vec::Vec`, `alloc::sync::Arc` — `fork_snapshot.rs:18-19, 360`). Any collapsed enum must remain no_std + alloc compatible. Heap types in variant data are fine (existing `BrokerHandleSnapshot` already uses `Option<…>` over alloc-friendly small types).
- Cfg-gated variants:
  - `FdClass::NetworkSocket` is `#[cfg(feature = "worker_local_inet")]` (`fork_snapshot.rs:397-398`, mirrored in `RawFdRef::Net` at `lib.rs:2979-2980`, accept/reject at `process.rs:6117-6120`, wire at `fork_snapshot.rs:1134, 1156-1157`). All sites consistently cfg-gate, so collapse must preserve this gating.
  - `BrokerHandleKind` has **no cfg-gated variants** — but `SocketDgram=10` and `SocketSeqPacket=11` are functionally dormant (no emit-side path; only the dead-code if-chain `None` arm in `lib.rs:2090-2091`).
- `BrokerHandleSnapshot` field types pull from `litebox_common_linux::broker_pipe_provider::BrokerPipeEnd`, `litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint`, `litebox_common_linux::broker_pty_provider::{BrokerPtyRole}` (`fork_snapshot.rs:276-286`). These are common-linux types, already no_std-clean. A typed enum payload would just move them inside variants.

No `#[non_exhaustive]` on any repo-owned enum in scope (verified by grep — zero hits for `non_exhaustive` near `FdClass|BrokerHandleKind|RawFdRef`). Compliant with AGENTS.md.

---

## 5. Recommendation

### Background facts that shape the recommendation

1. The two enums are **not isomorphic** (multiple `BrokerHandleKind` → same `FdClass`; one `RawFdRef::BrokerPty` even crosses class boundaries to `FdClass::FilesystemFd`). So Option A "1-for-1 collapse" is fundamentally lossy.
2. `FdClass` is the **policy axis** (accept/reject for migration — process.rs:6081-6127) and the **reopen-strategy axis** (filesystem path-reopen vs. local-recreate vs. broker-reattach). It is meaningful even where there's no broker handle.
3. `BrokerHandleKind` is the **broker-provider-dispatch axis**: pick the right `dup_handle` provider. Only meaningful when `broker_handle.is_some()`.
4. `RawFdRef` is the **runtime subsystem axis** and is already the most fine-grained — every refactor produces a typed enum that is essentially a parallel of `RawFdRef` minus the lifetime/reference shape.
5. The actual bug pattern (SEQPACKET if-chain in `lib.rs:2046-2260`) is **a restore-side dispatch problem**, not a taxonomy problem. The emit side and accept/reject side are already compile-checked exhaustive.

### Recommended: **Option B+C hybrid** (typed payload on BrokerHandle, restore-driven by one match)

Keep `FdClass` as the coarse class for accept/reject and reopen-strategy decisions (it's serving that purpose and is exhaustively matched today). Replace `BrokerHandleKind` + the Option-soup `BrokerHandleSnapshot` with a single typed enum, and rewrite the restore loop in `lib.rs:2046-2260` as a single `match` over that typed enum so the compiler enforces coverage.

Concrete shape (sketch only — not a patch):

```rust
// Replaces BrokerHandleKind + BrokerHandleSnapshot.
pub enum BrokerHandleSnapshot {
    Pidfd { handle_id: u64 },
    Eventfd { handle_id: u64 },
    Signalfd { handle_id: u64 },
    Pty { handle_id: u64, role: BrokerPtyRole, pty_id: u32 },
    Pipe { handle_id: u64, direction: BrokerPipeEnd },
    UnixSocket { handle_id: u64, endpoint: BrokerSocketPairEndpoint },
    TcpConn { handle_id: u64 },
    InetListener { handle_id: u64 },
    InetDgram { handle_id: u64 },
    SocketDgram { handle_id: u64 },
    SocketSeqPacket { handle_id: u64 },
}
```

And replace the nine `if entry.class != FdClass::X { continue }` restore blocks in `lib.rs` with one exhaustive `match` over `entry.metadata.broker_handle` (with a separate non-broker-handle path that still keys on `FdClass`).

**Pros**:
- Eliminates the if-chain anti-pattern that caused the SEQPACKET bug; compiler enforces every `BrokerHandleSnapshot` variant has a restore arm.
- Removes the per-kind `Option<…>` fields on `BrokerHandleSnapshot` (`pipe_direction`, `socketpair_endpoint`, `pty_role`, `pty_id`) — these are *invalid in 5 of 11* `BrokerHandleKind` arms today; a typed enum makes the constraint a type-level invariant.
- Keeps `FdClass`'s role in `snapshot_fd_table`'s accept/reject (`process.rs:6081-6127`) which is already exhaustive and bug-free.
- Wire format change is localized: replace the `kind: u8 + option fields` encoding (`fork_snapshot.rs:1240-1290`) with a variant-tagged encoding. Existing `as_u8`/`from_u8` already does the tag work; the variant payload encoders are straightforward.
- The `BrokerHandleKind::Signalfd → todo!()` panic at `lib.rs:2093-2097` becomes a real implementation site (or stays an explicit unimplemented variant arm — but won't silently fall through).

**Cons**:
- Wire format breaking change. Need to bump `SNAPSHOT_VERSION` (`fork_snapshot.rs:602` — currently 1) and either reject v1 or add a converter. Snapshots are short-lived (per-fork in-process serialization), so reject-old is probably fine — no on-disk persistence.
- Restore code grows by some duplicated boilerplate per variant (each variant needs its own typed `insert::<XSubsystem>` call). This is what we *want* — explicit per-kind code in one match — but it's more code than the if-chain.

**LOC / risk estimate**: ~300-450 net LOC churn in `litebox_shim_linux/src/{syscalls/fork_snapshot.rs, lib.rs, syscalls/process.rs}` plus ~30 LOC in `litebox_runner_linux_userland/src/lib.rs:313-415` (the CLI parser keys on `BrokerHandleKind` string forms; the parser output type changes to the new enum but the string-tag set is unchanged). No test-harness changes expected. Risk concentrated in (a) wire-format round-trip tests at `fork_snapshot.rs:2168-2362` (already extensive — they enumerate every kind) and (b) the runner-side bridge spec parser. **Affects**: `litebox_shim_linux` maintainers and the runner; no other crate.

### Why not the other options

- **Option A (full collapse FdClass + BrokerHandleKind → one enum)**: rejected because `FdClass::UnixSocket` ↔ `{BrokerHandleKind::UnixSocket, TcpConn, InetDgram, SocketPair}` is many-to-one and `BrokerPty` deliberately re-buckets to `FilesystemFd` to share the path-reopen restore branch. A single enum either inflates variant count, or drops the coarse bucket that drives the per-`FdClass` accept/reject. Either way the per-`FdClass` policy code stops being a single-line match and migrates into a custom helper, losing compile-time enforcement of the policy table.
- **Option C alone (typed payload only)**: most of the value of the hybrid, but if you keep the outer `if entry.class != FdClass::X { continue }` pattern in `lib.rs` you preserve the if-chain bug surface for the *class*-side dispatch. The hybrid above also rewrites the outer dispatch, which is the actual SEQPACKET bug fix.
- **Option D (status quo with compile-time mapping table)**: doesn't fix the if-chain. The original SEQPACKET bug wasn't a missing `FdClass↔BrokerHandleKind` pair — it was an `if entry.class != FdClass::UnixSocket { continue }` that should have admitted SEQPACKET. A mapping assertion wouldn't have caught it because the pair was *valid*; the dispatch was just incomplete. Not worth the build-time machinery for negligible safety gain.

---

## 6. Open questions

1. **`BrokerHandleKind::SocketDgram` and `SocketSeqPacket` are emit-side dead code.** They have variants, wire IDs, no_u8 decoders, and `None` arms in the restore if-chain (`lib.rs:2090-2091`) — but `process.rs:5970-6038` has no `RawFdRef::BrokerSocketDgram` / `BrokerSocketSeqPacket` arm and the `RawFdRef` enum (`lib.rs:2977-2996`) doesn't even contain those arms despite the subsystems existing (`syscalls/broker_socket_dgram.rs`, `syscalls/broker_socket_seqpacket.rs`). This is the *next* shoe to drop, structurally identical to the prior SEQPACKET bug. Worth confirming with the parent whether this is the in-flight `wave2-uds-seqpacket-investigate` finding.
2. **`BrokerHandleKind::Signalfd` is a live `todo!()`** in the restore match at `lib.rs:2093-2097`. The separate FdClass::Signalfd block at `lib.rs:2168-2208` actually handles it, so the `todo!()` is unreachable today because the outer-class dispatch intercepts first — but the comment "Signalfd is restored by its dedicated FdClass branch below" is exactly the dual-dispatch coupling we're trying to eliminate. Any refactor needs to fold these two locations.
3. **Wire-format reserved slots** (`fork_snapshot.rs:1140-1144` reserves wire bytes 7, 8, 9, 11 for `FdClass` — previously `TimerFd`, `PidFd`, `AnonSpecialFd`, `Other`). If we bump `SNAPSHOT_VERSION`, do we keep these reservations or compact? Probably keep — cheap and avoids accidental reuse.
4. **`BrokerPty → FilesystemFd` bucketing** (`process.rs:6020-6025`): is this still the desired classification, or a workaround for the path-reopen restore branch? A typed `BrokerHandleSnapshot::Pty` variant could let `FdClass` go back to something more honest (e.g., a hypothetical `FdClass::BrokerPty`), but only if the restore path is rewritten to drive off the broker variant. Parent should confirm.
5. **Runner CLI parser** (`runner_linux_userland/src/lib.rs:313-415`) currently constructs `BrokerHandleKind` plus `(pipe_direction, socketpair_endpoint, pty_role, pty_id)` separately and then assembles a `BrokerHandleSnapshot`. Switching to a typed enum means the parser produces the typed enum directly — the string-tag set stays the same (`"eventfd"`, `"pidfd"`, etc.) but the assembly logic changes. This is the only out-of-shim ripple.