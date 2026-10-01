# Core Arithmetic Coverage Audit

## Scope And Evidence

This read-only source audit covers all **59 Rust files** listed below in the
`litebox` crate, including complete files/chunks and test modules. The
source-reviewed base is **`0f601e960`** (full commit
`0f601e96079a515e314773c599a53aa7ca8be286`) on
`weiteng/overflow-hardening`. The source-audit worktree was clean. This document
records that report; it does not constitute a new source review or a source fix.

**No candidate runtime tests were executed.** No builds, tests, regression
probes, or scheduling regressions were run during this source audit. Neither
retained candidate was dynamically reproduced. Suggested regressions below are
proposals, not evidence of execution. 32-bit and platform execution were not
validated.

Explicit truncation, wrapping, and saturating operations are excluded from
overflow findings. The ledger still records those intentional operations as
`I`. The atomic publication/accounting candidate is retained because of the
ordering window and incorrect transient accounting, not because atomic wrapping
alone establishes a vulnerability or memory corruption.

Source links are relative to this document, using `../../litebox/...` and
`../../litebox_shim_linux/...`. Line anchors refer to the source-reviewed base.

## Qualified Candidates

### C1: Conditional Accept-Path Resource Exhaustion Panic

[`allocate_same_local_port`](../../litebox/src/net/local_ports.rs#L95), called by
[`Network::accept`](../../litebox/src/net/mod.rs#L1361), unwraps
`NonZeroU16::checked_add(1)`. Retaining the listener plus 65,534 accepted sockets
reaches 65,535 references; accepting another connection panics in both debug and
release. Closing sockets decrements the count, but the backlog cap of eight
does not cap retained accepted sockets.

The [shim accept path](../../litebox_shim_linux/src/syscalls/net.rs#L1297)
reaches this increment before raw-FD insertion, and the
[default FD limit](../../litebox_shim_linux/src/syscalls/process.rs#L760) is
1,048,576. This is guest-driven with cooperating TCP peers, not
malicious-9P-server input. It requires substantial resources: roughly 64 GiB of
retained smoltcp/channel buffers on the shim path, excluding overhead. Hosts
exhausting memory earlier will not reach it.

This candidate is a conditional port-refcount resource-exhaustion panic, not
an established memory-corruption finding.

Proposed focused regression: exhaust the allocator using lightweight port
tokens; separately verify that accept propagates exhaustion without panic.
Seeding the private counter would test the boundary, not independently prove
ingress. These regressions were not executed.

### C2: Transient RX Accounting Underflow

[`StreamSocketChannel::try_read`](../../litebox/src/net/socket_channel.rs#L439)
subtracts after consuming data, while
[`push_rx_data_with`](../../litebox/src/net/socket_channel.rs#L565) publishes
ring data before incrementing availability. A concurrent receiver can consume
one published byte while the count is zero, producing `usize::MAX`; the
producer's subsequent increment restores zero.

The analogous datagram window is between queue publication and the
[`rx_count` increment](../../litebox/src/net/socket_channel.rs#L962), with
[subtraction](../../litebox/src/net/socket_channel.rs#L836) in the receive path.
Reachability is through network draining and the shim's independently locked
proxy receive path.

Atomic arithmetic wraps identically in debug and release. Ring operations remain
capacity-bounded, so the source-supported impact is temporarily incorrect
readiness, not an oversized memory access. This is an atomic
publication/accounting race; **memory corruption is not proven**. TX accounting
can also transiently exceed capacity, without proved integer overflow.

Proposed focused regression: deterministically pause after publication, consume
and inspect readiness, then resume; cover TCP and UDP. This scheduling regression
was not executed.

## Per-File Arithmetic Function Coverage Ledger

Every row represents a complete source read. Function names identify the
reviewed arithmetic-bearing surfaces. Test/helper arithmetic is summarized
where indicated rather than enumerating every test function individually.

| Code | Disposition |
|---|---|
| B | Bounded or checked arithmetic. |
| I | Explicitly intentional truncation, wrapping, or saturation; excluded from findings. |
| C | Qualified candidate described above. |
| T | Theoretical exhaustion or caller-contract limitation without a concrete supported guest trigger. |
| N | No relevant arithmetic. |

| File | Arithmetic Surfaces And Disposition |
|---|---|
| [event/mod.rs](../../litebox/src/event/mod.rs#L1) | N: event flags/interfaces. |
| [event/observer.rs](../../litebox/src/event/observer.rs#L1) | B: `prune_dead_observers`, `register_observer`, `unregister_observer`; allocated map-entry counts under lock. |
| [event/polling.rs](../../litebox/src/event/polling.rs#L1) | N: polling/wait dispatch and boolean readiness. |
| [event/wait.rs](../../litebox/src/event/wait.rs#L1) | B: `with_timeout`, `remaining_timeout`; checked deadlines and ordered durations. |
| [fd/mod.rs](../../litebox/src/fd/mod.rs#L1) | B: `insert`, `duplicate`, `drain_entries_full_covered_by`, `fd_into_specific_raw_integer`; vector/descriptor bounds. `OwnedFd::new` narrowing is bounded on the traced guest FD path. |
| [fd/tests.rs](../../litebox/src/fd/tests.rs#L1) | B: fixed-size descriptor test operations; no uncontrolled arithmetic. |
| [fs/backend.rs](../../litebox/src/fs/backend.rs#L1) | N: backend contracts, handle erasure/conversions; no unchecked numeric offset computation. |
| [fs/composer.rs](../../litebox/src/fs/composer.rs#L1) | B: `walk_directories`; component slices and checked single-component backend outcomes. |
| [fs/devices.rs](../../litebox/src/fs/devices.rs#L1) | N: device operations ignore file offsets; buffer operations are slice-bound. |
| [fs/errors.rs](../../litebox/src/fs/errors.rs#L1) | N: error definitions/conversions. |
| [fs/in_mem.rs](../../litebox/src/fs/in_mem.rs#L1) | B: `read`, `write`, `truncate`; EOF clamp, checked end, `isize::MAX` limit, fallible growth. |
| [fs/inode_allocator.rs](../../litebox/src/fs/inode_allocator.rs#L1) | T: both `next` methods and `device_id`; lifetime `u64` counters/narrowing, no practical supported 64-bit exhaustion trigger. |
| [fs/mod.rs](../../litebox/src/fs/mod.rs#L1) | N: flags, types, fixed constants. |
| [fs/nine_p/client.rs](../../litebox/src/fs/nine_p/client.rs#L1) | B: `new`, `next_tag`, `walk_once`, `read`, `write`, `readdir`, `readdir_all`; negotiated frame/count limits and checked accumulation. |
| [fs/nine_p/fcall.rs](../../litebox/src/fs/nine_p/fcall.rs#L1) | B: decoder methods, `TaggedFcall::{encode_to_buf,decode}`, serializer encoders, `DirEntry::{size,encode_to}`, `DirEntryData::{size,encode_to}`; slice/frame/wire-length bounds. Client does not encode server `Rreaddir`. |
| [fs/nine_p/mod.rs](../../litebox/src/fs/nine_p/mod.rs#L1) | B: `walk_directories`, `rgetattr_to_file_status`; checked qid counts and fallible metadata conversions. |
| [fs/nine_p/tests.rs](../../litebox/src/fs/nine_p/tests.rs#L1) | B: `DiodServer::start`, broken-transport `write`, `test_nine_p_large_read_write`; bounded retries/countdowns/remaining slices. |
| [fs/nine_p/transport.rs](../../litebox/src/fs/nine_p/transport.rs#L1) | B: `read_exact`, `write_all`, `read_to_buf`, slice/Vec `write`; counts rely on trusted transport returning no more than supplied buffer length. |
| [fs/overlay.rs](../../litebox/src/fs/overlay.rs#L1) | B: `copy_bytes`; progresses from zero with buffer-bounded counts and local upper-growth limits. Remote size alone does not place its cursor near `usize::MAX`. |
| [fs/resolver.rs](../../litebox/src/fs/resolver.rs#L1) | B: `walk_to_directory`, `walk_path`, `check_walk_permissions`, `read`, `write`, `seek`; component bounds and checked position arithmetic. |
| [fs/tar_ro.rs](../../litebox/src/fs/tar_ro.rs#L1) | B: `TarIndex::new`, `read`; checked backing offsets, vector-bounded indices, EOF clamp. |
| [fs/tests.rs](../../litebox/src/fs/tests.rs#L1) | B: both `file_offset_overflow` tests and `file_read_write`; representable max-minus-one fixtures and fixed data-length subtraction. Remaining tests use bounded fixtures. |
| [lib.rs](../../litebox/src/lib.rs#L1) | N: crate/module declarations. |
| [litebox.rs](../../litebox/src/litebox.rs#L1) | N: shared state construction/access. |
| [mm/allocator.rs](../../litebox/src/mm/allocator.rs#L1) | B: `new`, `fill_pages`, `alloc_page`, `alloc_large_page`; valid Layout/provider extents. T: `allocate_pages`, `free_pages` shifts require valid orders; traced production orders are fixed, not guest-controlled. |
| [mm/exception_table.rs](../../litebox/src/mm/exception_table.rs#L1) | B: assembly copy loops and own-image exception-table lookup. I: relative relocation wrapping. |
| [mm/mod.rs](../../litebox/src/mm/mod.rs#L1) | N: module declarations. |
| [net/errors.rs](../../litebox/src/net/errors.rs#L1) | N: errors and bounded discriminant conversions. |
| [net/local_ports.rs](../../litebox/src/net/local_ports.rs#L1) | C1: `allocate_same_local_port`. B: `ephemeral_port`, `deallocate`; range-bounded narrowing and guarded decrement. |
| [net/mod.rs](../../litebox/src/net/mod.rs#L1) | C1 caller: `accept`. B: socket/backlog allocation, `listen`, `receive`, channel draining, polling/connect timing. T: `now` uptime narrowing. Guest keepalive conversion uses fixed two hours. |
| [net/phy.rs](../../litebox/src/net/phy.rs#L1) | B: receive/transmit token consumption; fixed MTU and slice lengths, trusted platform/smoltcp contracts. |
| [net/socket_channel.rs](../../litebox/src/net/socket_channel.rs#L1) | C2: stream `try_read`/`push_rx_data_with`, datagram `try_read`/`try_recv_datagram_with`. B: stream split-slice totals, `try_write`, `pop_tx_data_with`, datagram send/consume sizes; TX accounting can transiently exceed capacity, without proved integer overflow. |
| [net/tests.rs](../../litebox/src/net/tests.rs#L1) | B: `bidi_tcp_comms`; fixed messages and returned slice lengths. |
| [path.rs](../../litebox/src/path.rs#L1) | B: `normalized_components`; parent count bounded by string components, guarded decrement. |
| [pipes.rs](../../litebox/src/pipes.rs#L1) | B: `create_pipe`, `new_pipe`, `try_read`, `try_write`; guest capacity fixed at 1 MiB. `test_blocking_channel`/`test_nonblocking_channel` totals bounded by remaining slices. |
| [platform/arch.rs](../../litebox/src/platform/arch.rs#L1) | N: architecture register interfaces. |
| [platform/common_providers/mod.rs](../../litebox/src/platform/common_providers/mod.rs#L1) | N: module declarations. |
| [platform/common_providers/reservations.rs](../../litebox/src/platform/common_providers/reservations.rs#L1) | N: reservation map operations; no relevant numeric offset arithmetic. |
| [platform/common_providers/userspace_pointers.rs](../../litebox/src/platform/common_providers/userspace_pointers.rs#L1) | B: `copy_to_raw`, `copy_from_raw`, `read_at_offset`, `write_at_offset`, `to_owned_slice`, `copy_from_slice`; checked byte sizes, signed limits, address extents. |
| [platform/mock.rs](../../litebox/src/platform/mock.rs#L1) | B: test time/counter/random-buffer operations; no production guest ingress. |
| [platform/mod.rs](../../litebox/src/platform/mod.rs#L1) | B: `to_cstring`, `copy_from_slice`. `write_slice_at_offset` range progression bounded at traced callers by real slices/mappings; unrestricted custom-provider calls not established as guest ingress. |
| [platform/page_mgmt.rs](../../litebox/src/platform/page_mgmt.rs#L1) | B: `remap_pages`; ordered/aligned ranges and successful mappings constrain addresses and copying progression. |
| [platform/trivial_providers.rs](../../litebox/src/platform/trivial_providers.rs#L1) | I: explicit wrapping offsets. B: `mutate_subslice_with` size calculations. T: transparent `read_at_offset`/`to_owned_slice` trust valid memory; located uses are mock/test providers, not demonstrated production guest ingress. |
| [shim.rs](../../litebox/src/shim.rs#L1) | N: shim interfaces and exception types/constants. |
| [sync/condvar.rs](../../litebox/src/sync/condvar.rs#L1) | N: synchronization interface. |
| [sync/futex.rs](../../litebox/src/sync/futex.rs#L1) | B: `wake`; stops at requested nonzero count. I/B: `bucket`; intentional hash truncation, fixed modulo. |
| [sync/lock_tracing.rs](../../litebox/src/sync/lock_tracing.rs#L1) | B: `flush`, held-lock indexing/counts; fixed recorder/lock caps. T: `record_unconditionally` lifetime `u64` totals. I: saturating elapsed time. |
| [sync/mod.rs](../../litebox/src/sync/mod.rs#L1) | N: synchronization interfaces/declarations. |
| [sync/mutex.rs](../../litebox/src/sync/mutex.rs#L1) | B: `spin`; zero checked before bounded countdown. |
| [sync/rwlock.rs](../../litebox/src/sync/rwlock.rs#L1) | B: `try_read`, `read`, `read_contended`, unlock/writer state arithmetic; explicit reader cap and lock ownership. T: `wake_writer` notification-sequence rollover, not a practical input-sized overflow. |
| [tls.rs](../../litebox/src/tls.rs#L1) | B: `TlsKey::with`; checked stack-nesting counters. I: `get_ptr` wrapping byte offset. |
| [utilities/anymap.rs](../../litebox/src/utilities/anymap.rs#L1) | N: typed map operations. |
| [utilities/array_index_map.rs](../../litebox/src/utilities/array_index_map.rs#L1) | B: `insert`, `remove`; backing-capacity cursor and checked generation. Currently unused. |
| [utilities/loan_list.rs](../../litebox/src/utilities/loan_list.rs#L1) | N: production intrusive list operations. B: test counters bounded by eight threads. |
| [utilities/macros.rs](../../litebox/src/utilities/macros.rs#L1) | N: macro definitions. |
| [utilities/mod.rs](../../litebox/src/utilities/mod.rs#L1) | N: module declarations. |
| [utils/id_pool.rs](../../litebox/src/utils/id_pool.rs#L1) | B: `with_capacity`, `allocate`, `recycle`, `find_free`, `grow`; `u32` capacity, bit indices below 64, checked growth. |
| [utils/mod.rs](../../litebox/src/utils/mod.rs#L1) | I: `TruncateExt::trunc`, bit reinterpretation. B: fixed doc-example counters; no uncontrolled production arithmetic. |
| [utils/rng.rs](../../litebox/src/utils/rng.rs#L1) | I: `new_from_seed`, `next_u64` wrapping multiplication. B: fixed shifts, `next_u32`, `next_u16`, `next_in_range_u32`. |

## Limits And Non-Findings

No incomplete source reads remain in the reported 59-file scope. The ledger
summarizes test/helper arithmetic rather than enumerating every test function
individually. It is not a claim of repository-wide coverage or proof that all
arithmetic outside these files is safe.

Malicious 9P servers can report huge sizes, but the existing checked resolver
updates prevent the previously identified position overflow. Ordinary local
EOF reads, successful-mapping arithmetic, and bounded FD resizing are not
retained findings. Theoretical lifetime-counter exhaustion and unproven custom
provider ingress remain qualified as `T`, not promoted to demonstrated guest
triggers.

The port-refcount candidate requires resource exhaustion with cooperating peers;
the RX candidate concerns atomic publication/accounting order and transient
readiness. Neither establishes memory corruption. No candidate runtime tests
were executed, and 32-bit/platform behavior remains unvalidated.