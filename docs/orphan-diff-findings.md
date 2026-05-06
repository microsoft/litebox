# Orphan subcommand diff findings

Scope: read-only investigation for the deleted `cow-test`, `syscall-test`, and `glibc-flow` subcommands from `ff0ad011` (`cleanup(test-harness): delete orphan main.rs subcommands and helpers`). The deleted `cow_test` and `syscall_test` implementations were inline modules in `litebox_test_harness/src/main.rs`; `git show ff0ad011 -- litebox_test_harness/src/cow_test.rs` and `.../syscall_test.rs` produced no file content in this tree.

## Verdict summary

| Deleted subcommand | Verdict | Existing coverage | Gap sketch |
| --- | --- | --- | --- |
| `cow-test` | **gap** | Partially covered by `CP.*`, `SC.*`, `SP.*`, `CWF.*`, and `P1.*` | Add focused COW/fork state coordinator probes for the direct low-level assertions not covered by shell/file-flow tests. |
| `syscall-test` | **gap** | No live coordinator coverage found for the deleted POSIX timer/sigsuspend assertions. | Add focused syscall probes for `timer_create`, `timer_settime`, and `rt_sigsuspend`/`EINTR`. |
| `glibc-flow` | **gap** | Partially covered by `NL3b`, `NL3c`, `NL3d`, `NL5`, `X48`, and `XM.node_networkInterfaces`; fork/exec/node init covered by `X.node.*`, `XDF.*`, and related `X.*` tests. | Add one explicit glibc-style netlink flow that combines the missing operations in order. |

## `cow-test`

### Deleted assertions

Recovered from `ff0ad011^:litebox_test_harness/src/main.rs` inline module `cow_test`:

- `stack_restore`: parent stack variable remains `42` after child writes `99` and exits (`main.rs:1905-1920` in the old tree).
- `heap_restore`: parent heap `Box<i32>` remains `42` after child writes `99` through the same virtual address (`old main.rs:1923-1939`).
- `post_fork_assign`: parent assignment after child exit survives (`old main.rs:1942-1957`).
- `capture_assign`: child writes `CAPTURED` to pipe; parent reads into stack buffer and stores in a new `String` (`old main.rs:1960-1997`).
- `capture_assign_heap`: child writes `HEAP_DATA`; parent stores result in heap `Vec`/`String` (`old main.rs:1999-2038`).
- `child_write_parent_read`: parent pre-fork marker remains `0xDEAD_BEEF` while child-pipe value `0xCAFE_BABE` is received (`old main.rs:2040-2073`).
- `capture_dup2_stdout`: child `dup2`s pipe write end to stdout and writes `dup2_captured` (`old main.rs:2076-2123`).
- `child_builtin_capture`: no-exec child writes `builtin_output`; parent appends it to a pre-existing `Vec<(String,String)>` while preserving prior entries (`old main.rs:2126-2177`).
- `sequential_captures`: two sequential fork/pipe captures return `first` then `second` (`old main.rs:2179-2241`).
- `capture_with_preexisting_heap`: pre-existing `HashMap` entries survive while parent inserts captured value (`old main.rs:2244-2291`).
- `pipe_position_after_fork`: parent reads `AA`, child reads from inherited pipe, parent still sees remaining data containing `CC` rather than losing stream position (`old main.rs:2294-2348`).
- `pipe_position_child_reads`: parent reads `LINE1`, child reads next line, parent still reads a line beginning with `LINE` (`old main.rs:2351-2403`).
- `inherited_fd_file_read`: parent opens a file for write, child writes via inherited fd and stays alive, parent reopens same path and reads `child-wrote-this` (`old main.rs:2406-2492`).
- `inherited_fd_exec_read`: child `dup2`s inherited write fd to stdout/stderr, execs `cross-worker-file write-and-hold`, and parent reads non-empty redirected output (`old main.rs:2495-2594`).
- `inherited_fd_exec_keep_open`: same as previous but parent keeps the write fd open while reading (`old main.rs:2597-2680`).
- `nested_capture`: nested fork/pipe/exec capture forwards inner `echo-test` output containing `ECHO_TEST_OK` to parent (`old main.rs:2683-2802`).

### Live coverage found

- `CP.{simple,pipe,multi,noexec,nested_fork,subshell_pipe,subshell_continue}.{sh,bash}.{A,AA}` exercises capture-pipe fork/exec/no-exec/nested/subshell flows through the `capture-pipe` subcommand (`special_cases.rs:403-445`). This subsumes much of `capture_dup2_stdout`, `child_builtin_capture`, `sequential_captures`, and `nested_capture` at the behavior level.
- `SC.*.{agent}` and `SP.*.{agent}` exercise shell command substitution and stdin-piped command substitution across `AGENTS`, including nested and pipeline command substitutions (`platform_fixes.rs:833-911`, `platform_fixes.rs:1273-1360`). These cover real bash-visible manifestations of several capture/heap-state cases.
- `CWF.*.{agent}` covers cross-worker file visibility and background writer cases, including child-writes/parent-reads, hold-open, redirect stdout, and builtin redirect (`platform_fixes.rs:917-1270`). This overlaps the inherited-file/redirect family, but uses shell/protocol file flows rather than the exact raw inherited-fd low-level sequence.
- `P1.pipe_eof_fork.{agent}` covers a pipe lifecycle/fork EOF case over several agents (`special_cases.rs:1297-1331`).

### Gap verdict

`cow-test` is **not fully covered**. The live tests cover many user-visible shell/capture/file flows, but no searched coordinator test directly asserts the low-level stack COW, heap COW, post-fork parent assignment, pipe read-position independence, or raw inherited-fd-with-parent-reopen invariants from the deleted module.

Proposed follow-up sketch, not implemented:

- Add a focused `COW.*` coordinator family, backed by either protocol commands or a minimal self-exe probe if the protocol cannot express raw fork/memory/fd operations.
- Test IDs:
  - `COW.stack_restore.{A,AA,D3,NP}`: child mutates stack; parent verifies original value.
  - `COW.heap_restore.{A,AA,D3,NP}`: child mutates heap address; parent verifies original value.
  - `COW.parent_post_assign.{A,AA,D3,NP}`: parent assigns after child exit and verifies value.
  - `COW.pipe_position.{A,AA,D3,NP}` and `COW.pipe_script_position.{A,AA,D3,NP}`: reproduce the deleted pipe-position assertions.
  - `COW.inherited_fd.{file_read,exec_read,exec_keep_open}.{A,AA,D3,NP}`: raw open/fork/inherited-fd/reopen assertions, avoiding timer sleeps by adding a readiness signal pipe if reimplemented.
- Protocol shape: prefer protocol-level fork/memory/fd probes if available; otherwise a small deterministic self-exe subcommand is justified because raw address-space COW and inherited fd state cannot be driven through existing `Exec`/`FsRead` alone.

## `syscall-test`

### Deleted assertions

Recovered from `ff0ad011^:litebox_test_harness/src/main.rs` inline module `syscall_test`:

- `timer_create`: `timer_create(CLOCK_MONOTONIC, SIGEV_NONE, &timer_id)` succeeds and the timer can be deleted (`old main.rs:1729-1746`).
- `rt_sigsuspend`: after installing a no-op `SIGALRM` handler and arming `alarm(1)`, `sigsuspend(empty_mask)` returns `-1` with `errno == EINTR` (`old main.rs:1749-1779`).
- `timer_settime`: create a `CLOCK_MONOTONIC`/`SIGEV_NONE` timer and arm it with `timer_settime(..., it_value=100ms)` (`old main.rs:1782-1813`).

### Live coverage found

Searches of `coordinator/matrix.rs`, `coordinator/special_cases.rs`, `coordinator/platform_fixes.rs`, and `coordinator/fork_matrix.rs` found no `timer_create`, `timer_settime`, `sigsuspend`, `SIGEV`, or `SIGALRM` coordinator assertions.

### Gap verdict

`syscall-test` is a **gap**. The deleted POSIX timer and signal-suspend assertions are not subsumed by the live coordinator tests searched.

Proposed follow-up sketch, not implemented:

- Add a focused `SYS.*` or `SCALL.*` coordinator family.
- Test IDs:
  - `SYS.timer_create.{A,AA,D3,NP}` using `timer_create(CLOCK_MONOTONIC, SIGEV_NONE)` and `timer_delete`.
  - `SYS.timer_settime.{A,AA,D3,NP}` using a non-delivering `SIGEV_NONE` timer and immediate cleanup.
  - `SYS.rt_sigsuspend_eintr.{A,AA,D3,NP}` using a signal source that avoids flaky wall-clock waits if feasible; if not, use the old `alarm(1)` shape with an explicit timeout and native-first validation.
- Protocol commands: this likely needs a small self-exe syscall probe or a new protocol command because current generic `Exec` cannot assert raw syscall return/errno values without a helper.

## `glibc-flow`

### Deleted assertions

Recovered from `ff0ad011^:litebox_test_harness/src/main.rs` under the `getifaddrs-test glibc-flow` arm:

- Open/bind a `NETLINK_ROUTE` socket via `open_nl`; fail with `GLIBC_FLOW_SOCKET_FAIL` if unavailable (`old main.rs:3564-3569`).
- For each request, use glibc-shaped `sendmsg` with `sockaddr_nl`, one `iovec`, and `msghdr` (`old main.rs:3571-3589`).
- Then use `recvmsg(MSG_PEEK | MSG_TRUNC)` with an iovec whose base is null and length is zero; require a positive returned size (`old main.rs:3591-3607`).
- Then allocate exactly that size and call `recvmsg(0)`; require a positive read (`old main.rs:3609-3624`).
- Parse netlink messages and require `NLMSG_DONE` (`old main.rs:3626-3644`).
- Run that full request cycle sequentially for `RTM_GETLINK` and then `RTM_GETADDR` on the same socket; print `GLIBC_FLOW_OK` only if both cycles find `NLMSG_DONE` (`old main.rs:3647-3677`).

### Live coverage found

- `NL3b.sendmsg_recvmsg` covers a single `RTM_GETLINK` `sendmsg`/`recvmsg` loop and requires `RTM_NEWLINK` plus `NLMSG_DONE` (`special_cases.rs:92-97`, live `main.rs:2248-2342`).
- `NL3c.double_request` covers sequential `RTM_GETLINK` then `RTM_GETADDR` on one socket, but uses `sendto` plus `recv_check`, not the glibc `sendmsg` + `MSG_PEEK|MSG_TRUNC` flow (`special_cases.rs:99-104`, live `main.rs:2344-2427`).
- `NL3d.peek_trunc` covers a single `RTM_GETLINK` `recvmsg(MSG_PEEK|MSG_TRUNC)`/sized `recvmsg(0)` cycle; it checks `peek_size == read_size && peek_size >= 20` and explicitly does not require `NLMSG_DONE` (`special_cases.rs:105-110`, live `main.rs:2429-2525`).
- `NL5.getifaddrs_full` calls libc `getifaddrs` end-to-end (`special_cases.rs:112-114`, live `main.rs:2208-2223`).
- `X48.node_networkInterfaces` and `XM.node_networkInterfaces` exercise Node.js `os.networkInterfaces()` (`special_cases.rs:120-148`, `fork_matrix.rs:487-515`).
- `X.node.{A,AA,AAA}` runs Node at multiple agent depths, `X.node_stdout_write.A` checks Node stdout, and `XDF.*.node.*` exercises delayed-fork-triggered Node execution (`fork_matrix.rs:398-455`, `fork_matrix.rs:520-675`).
- No `FX.*` tests were present in the searched coordinator files.

### Gap verdict

`glibc-flow` is a **gap**. Existing coverage covers each ingredient, but not the deleted assertion's exact combined order: same socket, `RTM_GETLINK` then `RTM_GETADDR`, each using `sendmsg`, then zero-length `recvmsg(MSG_PEEK|MSG_TRUNC)`, then sized `recvmsg(0)`, and requiring `NLMSG_DONE` for both cycles.

Proposed follow-up sketch, not implemented:

- Add `NL3e.glibc_flow` or `NL.glibc_flow.{A,AA,D3}` in `register_netlink`.
- Protocol command: `Exec` a deterministic `getifaddrs-test glibc-flow` helper if restored, or add a more direct netlink protocol command if the team wants to remove helper subcommands long-term.
- Assertions: stdout contains `GLIBC_FLOW_OK`, and failures distinguish `GETLINK`, `GETADDR`, peek, read, and missing `NLMSG_DONE`.
- Axes: at minimum `A` for single-worker parity with existing `NL*`; ideally include `AA` and a depth-2/delayed-fork agent if the concern is glibc init under fork. Keep `X48.node_networkInterfaces`/`XM.node_networkInterfaces` as higher-level Node coverage rather than treating them as a replacement for the exact netlink flow.
