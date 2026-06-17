# Fd-kind taxonomy: from dual taxonomy to a single `FdKind`

## Status: collapsed (landed on `wportnoy/fd-taxonomy-collapse`)

This document originally surveyed whether to collapse the Linux shim's
**dual** fork/migration fd taxonomy. That collapse has now landed. This is the
post-collapse description of the single-taxonomy design and what it replaced.

## What the snapshot side looks like now

There is **one** canonical, owned, serializable fd-kind enum:
`litebox_shim_linux::syscalls::fork_snapshot::FdKind`. It is used end-to-end on
the snapshot side — emit, wire, accept/reject, and fork restore all dispatch on
it with exhaustive `match`es (no wildcard arms; the workspace denies
`clippy::wildcard_enum_match_arm`). Adding a new fd kind fails to compile at
every site.

`FdKind` variants (each broker-held variant carries exactly its re-attach data):

| Variant | Payload | Notes |
|---|---|---|
| `FilesystemFd` | — | regular file/dir/terminal; reopened from the OFD `reopen_path`; host stdio (fds 0–2) is identified via `FdTableSnapshot::stdio_object_ids` and pre-initialised, not reopened (stdio is metadata, not a kind) |
| `UnixSocket` | — | local AF_UNIX (named/abstract `socket()+bind/connect`); recreated fresh |
| `Epoll`, `Inotify` | — | migrated via `--broker-fd-bridge` specs, not the snapshot payload (restore no-ops) |
| `HostPassthrough` | `token_id`, `direction` | real host fd via the fd-token registry |
| `Net` (cfg `worker_local_inet`) | — | legacy local smoltcp socket; rejected for migration |
| `Eventfd` / `Timerfd` / `Pidfd` | `handle_id` | the formerly-overloaded eventfd bucket, now split by semantic kind |
| `Signalfd` | `handle_id` | broker signalfd |
| `BrokerPipe` | `handle_id`, `direction: BrokerPipeEnd` | broker pipe end |
| `BrokerPty` | `handle_id`, `role: BrokerPtyRole`, `pty_id` | broker PTY endpoint |
| `BrokerSocketPair` | `handle_id`, `endpoint: BrokerSocketPairEndpoint` | AF_UNIX SOCK_STREAM socketpair |
| `BrokerSocketDgram` / `BrokerSocketSeqPacket` | `handle_id` | AF_UNIX SOCK_DGRAM / SOCK_SEQPACKET |
| `BrokerTcpConn` | `handle_id` | connected TCP |
| `BrokerInetListener` / `BrokerInetDgram` | `handle_id` | broker TCP listener / UDP |
| `BrokerInetRaw` | `handle_id` | raw IP; migration currently rejected |

Per-fd data that is **not** kind-specific (object_id, fd/status flags, OFD
`reopen_path`/`file_offset`, terminal/stdio metadata) stays in
`FdEntrySnapshot` / `OpenFileDescriptionSnapshot` / `FdMetadataSnapshot`.

The runtime side keeps `RawFdRef<'a, FS>` — it must hold live typed borrows
(`&Arc<TypedFd<…>>`) that cannot be serialized, so it cannot be the same type
as the owned `FdKind`. The single emit `match raw_fd_ref -> FdKind` converts the
borrowed runtime form to the owned snapshot form; per-subsystem
`fork_snapshot_handle()` methods return the matching broker `FdKind` variant
carrying the real broker handle.

## What was removed

The previous design had **three** parallel taxonomies plus a dead mini-one:

- `FdClass` (coarse snapshot class) — **deleted**. It lossily re-bucketed
  distinct broker kinds onto shared classes (`BrokerTcpConn` / `BrokerInetDgram`
  / `BrokerSocketPair` → `UnixSocket`; `BrokerPty` → `FilesystemFd`; eventfd +
  timerfd + pidfd → one `EventFd`), and it conflated stdio with a kind.
- `BrokerHandleSnapshot` (a second, broker-only key carried in metadata) —
  **deleted**. The snapshot side was effectively a `(class, Option<handle>)`
  product dispatched by two keys; `FdKind` makes it a single sum.
- `ReplacedSubsystem` (a dead 3-variant debug-only mini-taxonomy) — **deleted**.

`git grep` for `FdClass`, `BrokerHandleSnapshot`, and `ReplacedSubsystem` over
`*.rs` is zero.

## The exhaustiveness win

Fork restore used to dispatch via a chain of nine
`for entry { if entry.class != FdClass::X { continue } … }` blocks, with an
inner key on the broker handle and cross-branch `continue` / `todo!()` / `None`
fall-through. That if-chain shape is exactly what hid an earlier
SOCK_SEQPACKET restore bug. Restore is now a single
`for entry { match entry.kind { … } }`: every kind has one arm, the broker
re-attach reads the handle from the matched payload, and a missing case is a
compile error rather than a silent fall-through.

## Eager-broker-only

The collapse went together with committing fully to the eager-broker model:
`socketpair()` and the AF_UNIX SOCK_DGRAM / SOCK_SEQPACKET creation fast paths
are unconditionally broker-backed (the `LITEBOX_EAGER_BROKER_*` env gates and
the local-socket fallbacks are gone), and the local (non-broker)
`EventFileInner::Eventfd` variant was removed. This gives each fd kind a single
runtime representation and a single wire encoding.

## Wire format

The per-entry snapshot encoding is one `FdKind` variant-tagged blob (replacing
the old separate `class` byte + `broker_handle` / `broker_fd_token` options);
`SNAPSHOT_VERSION` is `3`. Snapshots are ephemeral per-fork in-process, so the
version bump simply rejects any stale format.

## Follow-ups (not part of the taxonomy collapse)

- Broker-held timerfd: trait + broker-side `TimerfdState` + test parity exist on
  `wportnoy/fd-tax-timerfd`; the broker timed-event firing hook and shim-side
  integration remain.
- `pidfd_open` still has a local pidfd path (`EventFileInner::Pidfd`) to retire.
- Socket/net shim unit tests need in-process mock broker providers now that
  creation is broker-only (mirroring the eventfd test mock).
