# Linux Integer-Overflow Audit

## Scope and Provenance

Reviewed BASE: `0f601e96079a515e314773c599a53aa7ca8be286` (short form
`0f601e960`). The complete source audit covered **35 files: 23 in
litebox_shim_linux and 12 in litebox_common_linux**, including tests, trait
declarations, macro bodies/use sites, and inactive architecture-specific code.
The per-file/function inventory below records the coverage at BASE, not an
inventory regenerated from later source revisions.

This document transcribes the existing complete audit report. That audit was
read-only: no source changes, Cargo runs, or runtime reproductions were performed.
Explicit truncating, wrapping, and saturating operations were excluded from its
overflow search. Exact-integer calculations checked the reported 64-bit witnesses;
they did not establish runtime exploitability. The regression tests described
below were proposals in that report, not tests added or executed by the audit.

Full source reading is **not a mathematically exhaustive proof** that all
integer overflows have been eliminated. Conclusions depend on the checked caller
paths and trust assumptions described below, including successful mappings,
valid Rust slices, platform pointer validation and complete-object reads, backend
behavior, and the reviewed production callers. Changes to those dependencies or
new callers can invalidate a caller-bounded conclusion. Inactive architecture
code was read, not executed; the witnesses below are specifically 64-bit.

All source links are relative to this document and stay within this worktree.
Finding locations and the inventory describe BASE; later changes may move lines
or change implementations, so links identify files/functions without historical
line-number claims.

## Later-Change Status

Later changes fix the following BASE findings: the resize end calculation, the
old remap extent, `NonZeroPageSize::add` and the `create_mapping` unwrap/error
path, the affinity length comparison, and signed robust-list offsets. This
status records the supplied later-change information; it does not represent a
new runtime validation of those fixes by this documentation-only task.

| BASE Finding | Later Status |
|---|---|
| P1: `Vmem::resize_mapping` new end | Fixed by checked resize-end handling. |
| P2: file-backed mapping slack addition | Fixed by checked `NonZeroPageSize::add` and fallible `create_mapping` handling in place of the unwrap path. |
| P2: `VmemManager::remap_pages` old extent | Fixed by checked old remap extent. |
| P2: raw affinity dispatch length multiplication | Fixed by an overflow-free affinity comparison. |
| P2: robust-list entry/pending address calculations | Fixed by signed robust-offset handling. |
| P2, backend-conditional: `ElfFile::read_at` offset advancement | **Unresolved.** |
| API-only: public `VmemManager::get_memory_permissions` extent | **Unresolved.** Its reviewed production caller checks the extent first. |

The historical `mprotect` overflow had already been fixed at BASE; it is not an
additional unresolved finding in this report.

## Findings at BASE

### 1. P1: Overflowing mremap Growth Can Become an Unintended Shrink

In [vmem.rs](../../litebox_common_linux/src/vmem.rs),
`Vmem::resize_mapping` computes `range.start + new_size.as_usize()` unchecked.
Guest arguments flow through `Task::sys_mremap` in
[shim mm.rs](../../litebox_shim_linux/src/syscalls/mm.rs) and common syscall
validation. That validation checks flags, alignment, rounding, and nonzero new
size, but not the new extent.

On 64-bit, an existing mapping starting at `B = 0x10000000`, `old_size = 4096`,
and `new_size = 0xfffffffffffff000` is a witness. With overflow checks, the
addition panics. Without them it produces `B - 4096`, enters the shrink branch,
and requests removal of `[B-4096, B+4096)`. A preceding mapping can consequently
be removed; backend rejection instead reaches an unwrap panic.

Proposed regression: with `DummyVmemBackend`, insert distinct mappings at
`[B-4096,B)` and `[B,B+4096)`, attempt the resize, and require an error with both
mappings unchanged. Run with overflow checks both enabled and disabled.

Later status: resize-end handling is fixed.

### 2. P2: File-Backed mmap Overflows While Adding Trampoline Slack

The unchecked arithmetic is `NonZeroPageSize::add` in
[vmem.rs](../../litebox_common_linux/src/vmem.rs), invoked by `create_mapping`
before task-address-size validation. The type guarantees alignment and nonzero
size, not that addition is safe.

A guest witness is `mmap(0, 0xfffffffffffff000, PROT_READ, MAP_PRIVATE,
valid_small_file_fd, 0)`. Checked rounding and `offset + aligned_len` succeed.
A short file bypasses CoW, and `do_mmap_file_memcpy` in
[shim mm.rs](../../litebox_shim_linux/src/syscalls/mm.rs) requests
`ENSURE_SPACE_AFTER`. Adding 16 MiB panics with overflow checks; without them it
produces `0xfff000`, after which construction of the original enormous mapping
range reaches another panic.

Proposed regression: open a small readable file, issue this exact syscall, and
require `ENOMEM` without panic or mapping changes in both overflow-check modes.

Later status: `NonZeroPageSize::add` and the `create_mapping` unwrap/error path
are fixed.

### 3. P2: mremap Computes the Old Extent Before Validating It

`VmemManager::remap_pages` in [common mm.rs](../../litebox_common_linux/src/mm.rs)
computes `old_addr.as_usize() + old_size` unchecked. Syscall validation accepts
`old_addr = 4096`, `old_size = 0xfffffffffffff000`, `new_size = 4096`, and empty
flags; no mapping lookup precedes the addition.

With overflow checks this panics. Without them the end becomes zero, which
`PageRange::new` rejects. The report did not establish release-mode memory
corruption from this witness.

Proposed regression: call `task.sys_mremap` with these arguments and require
`EINVAL`, without creating a mapping.

Later status: the old remap extent is checked.

### 4. P2: Affinity-Buffer Validation Multiplies Unrestricted Guest Length

`Task::do_syscall` in [shim lib.rs](../../litebox_shim_linux/src/lib.rs) computes
`len * 8` before bounding the length. Request decoding in
[common lib.rs](../../litebox_common_linux/src/lib.rs) preserves the raw guest
`usize`.

With PID zero, a valid mask pointer, and `len = 1usize << 61`, the alignment
condition is satisfied. Multiplication panics with overflow checks and becomes
zero without them, producing `EINVAL` against the two-bit CPU set. No oversized
write was demonstrated: the successful branch copies only the actual CPU-set
bytes.

Proposed regression: exercise raw `sched_getaffinity` dispatch with that length,
not merely `sys_sched_getaffinity`, and require a non-panicking result with
consistent length validation.

Later status: the affinity comparison is overflow-free.

### 5. P2: Robust-List Cleanup Adds Guest-Controlled Offsets Unchecked

Both traversed-entry and pending-entry calculations in `wake_robust_list` in
[process.rs](../../litebox_shim_linux/src/syscalls/process.rs) use ordinary
addition at BASE. `set_robust_list` stores the guest pointer; cleanup reads
`futex_offset` as an unrestricted `usize`. Successful head reads and the
2048-entry traversal limit do not constrain these sums.

A witness is an empty list pointing back to its head, `list_op_pending = 2`,
and `futex_offset = usize::MAX`. Cleanup skips traversal, then panics on the
pending sum with overflow checks. Without them it produces address one, which
alignment validation rejects before the existing `todo!` futex-death handler.
The unimplemented handler is not itself attributed to arithmetic overflow.

Proposed regression: pass this head to `wake_robust_list` and require invalid
pending-address handling without panic; separately cover the traversed-entry
expression.

Later status: signed robust-offset handling is fixed. The witness and unsigned
description above deliberately retain the BASE behavior, not the later code.

### 6. P2, Backend-Conditional: ELF Reads Can Overflow a File Offset

`ElfFile::read_at` in [shim elf.rs](../../litebox_shim_linux/src/loader/elf.rs)
advances `offset += bytes_read as u64` unchecked. ELF parsing in
[common loader.rs](../../litebox_common_linux/src/loader.rs) caps the
program-header byte count but passes raw `e_phoff` without checking
`e_phoff + count`.

Honest in-memory/TAR files return EOF at an impossible offset, so this is not an
ordinary guest-only reproduction against those backends. A 9P server can return
one byte for a request at `u64::MAX`: the client bounds the response count, not
the offset extent, and explicit-offset resolver reads do not update/check the
file position. With overflow checks this panics; without them the next read is
at offset zero.

Proposed regression: use a mock 9P transport serving a valid ELF header with
`e_phoff = u64::MAX`, one program header, and a one-byte `Rread` at that offset.
Require an error without panic or a subsequent wrapped-offset request.

Later status: **unresolved**, retaining the backend/trust condition above.

### API-Only Gap: Public Permission Query Extent

`VmemManager::get_memory_permissions` in
[common mm.rs](../../litebox_common_linux/src/mm.rs) computes `start + len`
unchecked. The validated types permit `start = 4096` and
`len = 0xfffffffffffff000`. Its sole reviewed production caller, OP-TEE
access-rights checking, explicitly checks the sum first. No guest path bypassing
that check was demonstrated.

Proposed direct public-API regression: construct those valid aligned types and
require `None` without panic. This is an API robustness gap, separate from the
guest-reachable findings.

Later status: **unresolved**; the caller-side bound does not make the public API
itself robust to all values allowed by its argument types.

## Caller-Bounded Cases and Trust Assumptions

These were reviewed and were not reported as additional reachable overflows:

- `mprotect` had checked extent handling at BASE.
- `munmap`/`madvise` validate rounded extents before unchecked remove/reset helpers.
- Signal-stack endpoints are checked before storage.
- Successful complete-object pointer reads bound `sendmmsg`/`recvmsg` field addresses.
- CoW offsets derive from valid backing slices.
- Trampoline addresses are bounded by successful mappings and cursor checks.
- Stack pushes are bounded by the allocated stack.
- Signal indices/shifts use validated `Signal` values.
- Eventfd accumulation is checked, and epoll decrement is guarded.
- Page-fault predecessor subtraction is ordered by lookup/control flow.
- `compute_reserved_regions` is bounded by both actual callers' checked reservation arithmetic and successful mappings.

These conclusions rely on those invariants and dependent APIs, not merely on
the local expression or a validated type name. In particular, honest local-file
EOF behavior cannot be assumed for a server-controlled 9P response; and the
OP-TEE caller's extent check does not resolve the public permission-query gap.
The inventory covers the two Linux crates listed here, not every platform,
backend, or crate in the repository.

## Arithmetic Verification Recorded by the Report

Exact-integer, in-memory calculations confirmed these unchecked 64-bit results:

| Witness | Result |
|---|---|
| Resize new end | `0x0ffff000` |
| Mapping slack addition | `0x00fff000` |
| Old remap end | `0` |
| Affinity length multiplication | `0` |
| Robust pending address | `1` |
| ELF read offset advancement | `0` |

This verifies the witness arithmetic only. The original audit did not add or
execute the proposed Rust regressions. Documentation whitespace validation is
not runtime validation of either the findings or later fixes.

## Per-File Function Coverage

Repeated names include every overload/implementation; `xN` counts declarations.
Counts include trait declarations and macro bodies. Status-macro expansions
(`get_status`, `set_status`, and channel shutdown methods) were also inspected
at their use sites. The inventory includes files with no function declarations.

| File | Audited Functions |
|---|---|
| [shim/build.rs](../../litebox_shim_linux/build.rs) | `main` |
| [shim/src/channel.rs](../../litebox_shim_linux/src/channel.rs) | `is_shutdown x2`, `shutdown x2`, `is_peer_shutdown`, `new x2`, `update_pollee`, `is_empty`, `peek_and_consume_one`, `clone`, `try_write_one`, `is_full`, `is_pair`, `register_observer`, `split`, `split_pair`, `on_events`, `peek_and_consume_one_drains_queue_after_self_shutdown`, `peek_and_consume_one_drains_queue_after_peer_shutdown`, `peek_and_consume_one_returns_eagain_when_empty_and_alive`, `try_write_one_returns_epipe_after_self_shutdown`, `try_write_one_returns_epipe_after_peer_shutdown`, `shutdown_notifies_peer_pollee_hup` |
| [shim/src/lib.rs](../../litebox_shim_linux/src/lib.rs) | `new x2`, `set_initial_brk`, `brk`, `release_memory`, `deref`, `log_unsupported_fmt`, `preadv_pwritev_offset x2`, `init`, `syscall`, `exception`, `interrupt`, `enter_shim`, `litebox x2`, `default_fs x2`, `build`, `clone`, `load_program`, `memory_manager`, `perform_network_interaction`, `tcp_connection`, `platform`, `wait`, `wait_for_unix_shell_exit_code`, `initialize_stdio_in_shared_descriptors_table`, `close_on_exec`, `typed_fd`, `typed_fd_from_raw`, `to_syscall_result x4`, `pread_with_user_buf`, `do_pread_with_user_buf`, `handle_syscall_request`, `do_syscall`, `drop`, `new_test_task`, `clone_for_test`, `spawn_clone_for_test` |
| [shim/src/loader/auxv.rs](../../litebox_shim_linux/src/loader/auxv.rs) | `init_auxv` |
| [shim/src/loader/elf.rs](../../litebox_shim_linux/src/loader/elf.rs) | `find_bottom_up_gap`, `claim_bottom_up`, `new x3`, `drop`, `read_at`, `size`, `reserve`, `map_file`, `map_zero`, `protect`, `load_mapped`, `load`, `comm`, `from`, `push_u16`, `push_u32`, `push_u64`, `append_elf_header`, `append_program_header`, `minimal_elf`, `write_file`, `elf_placement_keeps_main_low_and_interpreter_high` |
| [shim/src/loader/mod.rs](../../litebox_shim_linux/src/loader/mod.rs) | No functions |
| [shim/src/loader/stack.rs](../../litebox_shim_linux/src/loader/stack.rs) | `new`, `get_cur_stack_top`, `push_bytes`, `push_usize`, `push_cstring`, `push_cstrings`, `push_pointers`, `push_aux`, `init` |
| [shim/src/stdio.rs](../../litebox_shim_linux/src/stdio.rs) | `test_stdio`, `test_stdio_flags_with_dup` |
| [shim/src/syscalls/epoll.rs](../../litebox_shim_linux/src/syscalls/epoll.rs) | `try_from`, `poll x3`, `new x4`, `stable_key`, `wait x2`, `epoll_ctl`, `add_interest`, `mod_interest`, `on_events x2`, `push`, `pop_multiple`, `clone`, `with_capacity`, `add_fd`, `scan_once`, `scan`, `revents`, `revents_with_fds`, `platform`, `setup_epoll`, `test_epoll_with_eventfd`, `test_epoll_with_pipe`, `test_poll`, `test_pselect`, `test_pselect_read_hup`, `test_pselect_invalid_fd`; status macro |
| [shim/src/syscalls/eventfd.rs](../../litebox_shim_linux/src/syscalls/eventfd.rs) | `new`, `try_read`, `read`, `try_write`, `write`, `check_io_events`, `register_observer`, `platform`, `test_semaphore_eventfd`, `test_blocking_eventfd`, `test_blocking_eventfd_no_race_on_massive_readwrite`, `test_nonblocking_eventfd`; status macro |
| [shim/src/syscalls/file.rs](../../litebox_shim_linux/src/syscalls/file.rs) | `from`, `clone`, `new x3`, `umask`, `set_max_fd`, `insert_raw_fd`, `insert_raw_fd_locked`, `insert_raw_fd_at_or_above`, `insert_raw_fd_at_or_above_locked`, `subsystem_name`, `as_fs`, `fs_only`, `dispatch`, `fmt`, `get_umask`, `cwd_prefix`, `resolve_path`, `resolve_path_at`, `do_open`, `do_openat`, `insert_raw_file_fd`, `sys_umask`, `sys_open`, `sys_openat`, `sys_ftruncate`, `sys_mknodat`, `sys_unlinkat`, `sys_read`, `do_read`, `sys_write`, `do_write`, `sys_pwrite64`, `rewind_sendfile_in_fd`, `sys_sendfile`, `espipe_for_non_seekable_offset`, `try_into_whence`, `sys_lseek`, `do_seek`, `do_mkdir`, `sys_mkdirat`, `do_close`, `remove_and_drop_descriptor`, `do_close_and_replace`, `sys_close`, `typed_fd`, `with_typed_fd`, `sys_preadv`, `sys_pwritev`, `sys_readv`, `check_iovcnt`, `check_iov_lens`, `read_from_iovec`, `write_to_iovec`, `sys_writev`, `validate_access_mode`, `do_access_mode`, `access_user`, `do_access`, `sys_faccessat`, `do_readlink`, `sys_readlink`, `sys_readlinkat`, `get_file_descriptor_flags`, `set_file_descriptor_flags`, `do_stat`, `do_path_stat`, `sys_stat`, `sys_lstat`, `sys_fstat`, `do_fstatat`, `sys_newfstatat`, `sys_statx`, `sys_fcntl`, `sys_getcwd`, `sys_chdir`, `sys_pipe2`, `sys_eventfd2`, `stdio_ioctl`, `is_stdio`, `sys_ioctl`, `sys_epoll_create`, `sys_epoll_ctl`, `sys_epoll_pwait`, `sys_ppoll`, `do_pselect`, `sys_pselect`, `do_dup`, `do_dup_inner`, `dup`, `sys_dup`, `sys_getdirent64`, `test_ppoll_count_overflow`, `write_to_iovec_returns_partial_after_later_error`, `read_from_iovec_breaks_on_eof`, `read_from_iovec_chunks_iov_larger_than_kernel_buffer`, `read_from_iovec_returns_partial_after_later_error`, `fspath_new`, `getcwd_and_chdir`, `chdir_relative_path`, `mknodat_regular_file_does_not_consume_fd_limit`, `empty_pathnames_return_enoent`, `all_path_syscalls_respect_chdir` |
| [shim/src/syscalls/misc.rs](../../litebox_shim_linux/src/syscalls/misc.rs) | `sys_getrandom`, `to_fixed_size_array`, `sys_uname`, `sys_sysinfo`, `sys_capget`, `test_getrandom`, `test_uname` |
| [shim/src/syscalls/mm.rs](../../litebox_shim_linux/src/syscalls/mm.rs) | `clone`, `eq`, `partial_cmp`, `cmp`, `align_up`, `align_down`, `do_mmap`, `do_mmap_anonymous`, `do_mmap_file`, `try_cow_mmap_file`, `do_mmap_file_memcpy`, `sys_mmap`, `sys_munmap`, `sys_munmap_raw`, `clear_file_mappings_for_range`, `sys_mprotect`, `sys_mprotect_raw`, `sys_mremap`, `sys_brk`, `sys_madvise`, `maybe_patch_on_mprotect_exec`, `init_elf_patch_state`, `check_trampoline_magic`, `apply_trap_fallback`, `maybe_patch_exec_segment`, `finalize_elf_patch`, `brk_respects_initial_break_and_shrinks_within_current_page`, `test_brk_and_madvise_length_overflow`, `test_mprotect_range_overflow`, `test_mmap_length_overflow`, `test_anonymous_mmap`, `test_file_backed_mmap`, `test_mremap`, `test_mmap_fixed_noreplace`, `test_collision_with_global_allocator`, `test_map_shared_anonymous`, `test_map_shared_anonymous_writable`, `test_map_shared_readonly_file`, `test_madvise`, `test_fallible_read` |
| [shim/src/syscalls/mod.rs](../../litebox_shim_linux/src/syscalls/mod.rs) | `get_status`, `set_status`, `write_to_user`, `read_from_user` |
| [shim/src/syscalls/net.rs](../../litebox_shim_linux/src/syscalls/net.rs) | `socket_from_raw`, `with_typed_socket`, `from x2`, `default`, `inet`, `unix`, `clone`, `initialize_socket`, `with_socket_options`, `with_socket_options_mut`, `setsockopt_common`, `setsockopt`, `getsockopt_common`, `getsockopt`, `try_accept`, `accept`, `bind`, `connect`, `listen`, `sendto`, `receive`, `get_socket_type`, `get_status`, `get_proxy`, `close_socket x3`, `parse_type_and_flags`, `sys_socket`, `do_socket`, `sys_socketpair`, `do_socketpair`, `read_sockaddr_from_user`, `write_sockaddr_to_user`, `copy_iovs_to_vec`, `sys_accept`, `do_accept`, `sys_connect`, `do_connect`, `sys_bind`, `do_bind`, `sys_listen`, `do_listen`, `sys_sendto`, `do_sendto`, `sys_sendmsg`, `do_sendmsg`, `sys_sendmmsg`, `sys_recvfrom`, `do_recvfrom`, `sys_recvmsg`, `do_recvmsg`, `sys_recvmmsg`, `sys_setsockopt`, `do_setsockopt`, `sys_getsockopt`, `do_getsockopt`, `sys_getsockname`, `do_getsockname`, `sys_getpeername`, `do_getpeername`, `sys_shutdown`, `do_shutdown`, `typed_socket x2`, `get_so_error`, `epoll_add`, `epoll_wait`, `test_tcp_socket_as_server`, `test_tcp_socket_with_external_client`, `test_tcp_socket_send`, `test_tun_blocking_send_tcp_socket`, `test_tun_nonblocking_send_tcp_socket`, `test_tun_blocking_recvfrom_tcp_socket`, `test_tun_nonblocking_recvfrom_tcp_socket`, `test_tun_blocking_recvfrom_tcp_socket_with_truncation`, `test_tun_tcp_connection_refused`, `test_tun_tcp_socket_as_client`, `blocking_udp_server_socket`, `test_tun_blocking_udp_server_socket`, `test_tun_nonblocking_udp_server_socket`, `test_tun_blocking_udp_server_socket_with_truncation`, `test_tun_udp_client_socket_without_server`, `test_tun_tcp_sockopt`, `test_tun_tcp_so_error_network_unreachable`, `test_socket_dup_and_close`, `test_unix_sockaddr_short_buffer`, `create_unix_socket`, `create_unix_server_socket`, `ppoll`, `test_unix_datagram_socket`, `test_unix_stream_socket`, `test_unix_stream_socket_refused`, `test_multiple_unix_stream_connections`, `test_multiple_blocking_unix_stream_connections`, `test_multiple_non_blocking_unix_stream_connections`, `test_unix_stream_socket_on_same_addr`, `test_unix_datagram_socket_on_same_addr`, `unix_socketpair_bidirectional`, `test_unix_socketpair_bidirectional`, `test_socketpair_race_with_concurrent_close`, `unix_socket_recv_timeout`, `test_unix_socket_recv_timeout`, `test_unix_stream_addr`, `test_unix_datagram_addr` |
| [shim/src/syscalls/pipe.rs](../../litebox_shim_linux/src/syscalls/pipe.rs) | `create_linux_pipe`, `close_linux_pipe`, `read_linux_pipe`, `write_linux_pipe`, `linux_pipe_status_flags`, `set_linux_pipe_status_flags`, `linux_pipe_mode_bits`, `metadata_to_errno` |
| [shim/src/syscalls/process.rs](../../litebox_shim_linux/src/syscalls/process.rs) | `new_process`, `new_thread`, `detach_from_process`, `drop`, `new x2`, `interrupt`, `remaining`, `nr_threads`, `wait_for_exit`, `attach_thread`, `detach_thread`, `exit_thread`, `exit_group`, `kill_other_threads`, `is_exiting`, `process`, `set_task_comm`, `sys_prctl`, `sys_arch_prctl`, `handle_futex_death`, `fetch_robust_entry`, `wake_robust_list`, `prepare_for_exit`, `sys_exit`, `sys_exit_group`, `init`, `sys_clone`, `sys_clone3`, `do_clone`, `sys_set_tid_address`, `sys_gettid`, `default`, `get_rlimit_cur`, `do_prlimit`, `sys_prlimit`, `sys_getrlimit`, `sys_setrlimit`, `sys_set_robust_list`, `sys_get_robust_list`, `real_time_as_duration_since_epoch`, `sys_clock_gettime`, `gettime_as_duration`, `duration_since_epoch_to_deadline`, `sys_clock_getres`, `sys_clock_nanosleep`, `sys_gettimeofday`, `sys_time`, `sys_alarm`, `arm_real_timer`, `sys_setitimer`, `sys_getitimer`, `sys_pause`, `sys_getpid`, `sys_getppid`, `sys_getuid`, `sys_geteuid`, `sys_getgid`, `sys_getegid`, `len`, `as_bytes`, `sys_sched_getaffinity`, `sys_futex`, `parse_shebang`, `resolve_shebang`, `sys_execve`, `copy_vector`, `load_program`, `handle_init_request`, `init_thread_context`, `test_clone_stack_overflow`, `resource_limit_cur_never_exceeds_max`, `test_arch_prctl`, `test_sched_getaffinity`, `test_prctl_set_get_name`, `test_sigint_with_custom_handler`, `test_alarm_fires_after_deadline`, `test_alarm_cancel_prevents_signal`, `test_pause_wakes_on_pending_signal`, `test_alarm_with_sigign`, `test_timer_delivers_correct_signal`, `test_parse_shebang_basic` |
| [shim/src/syscalls/signal/mod.rs](../../litebox_shim_linux/src/syscalls/signal/mod.rs) | `new_process`, `clone_for_new_task`, `reset_for_exec`, `sig_index`, `index`, `index_mut`, `new x2`, `clone`, `next`, `remove`, `push`, `is_on_stack`, `siginfo_exception`, `siginfo_kill`, `set_signal_mask`, `set_sigaltstack`, `clear_sigaltstack`, `deliver_signal`, `with_temporary_signal_mask`, `sys_rt_sigprocmask`, `sys_sigaltstack`, `sys_rt_sigreturn`, `sys_rt_sigaction`, `sys_kill`, `sys_tkill`, `sys_tgkill`, `do_kill`, `has_pending_signals`, `pending_signal_set`, `take_pending_siginfo`, `process_signals`, `check_alarm_deadline`, `queue_signals`, `is_signal_ignored`, `send_signal`, `send_shared_signal`, `force_signal`, `force_signal_with_info`, `handle_exception_request` |
| [shim/src/syscalls/signal/x86_64.rs](../../litebox_shim_linux/src/syscalls/signal/x86_64.rs) | `uctx_addr`, `sp`, `pc`, `get_signal_frame`, `write_signal_frame`, `restore_sigcontext`, `test_signal_frame_underflow` |
| [shim/src/syscalls/tests.rs](../../litebox_shim_linux/src/syscalls/tests.rs) | `test_platform`, `init_platform`, `exceptions_queue_their_corresponding_signals`, `test_fcntl`, `test_pipe2_race_with_concurrent_close`, `test_dup`, `test_getdent64`, `test_umask_behavior`, `test_rlimit_nofile`, `test_unlinkat`, `test_rwlock_readers_not_starved_after_writer_handoff`, `join_with_timeout` |
| [shim/src/syscalls/unix.rs](../../litebox_shim_linux/src/syscalls/unix.rs) | `is_unnamed`, `bind x6`, `to_key x2`, `drop x3`, `from`, `new x5`, `shutdown x7`, `listen x5`, `into_connected`, `set_backlog`, `try_connect x2`, `try_accept`, `check_io_events x5`, `register_observer x3`, `get_local_addr x6`, `new_pair x3`, `get_peer_addr x5`, `try_sendto`, `try_recvfrom`, `connected`, `with_state_ref`, `with_state_mut_ref`, `with_state`, `lookup x2`, `connect x3`, `accept x2`, `sendto x3`, `recvfrom x3`, `try_write`, `write`, `try_read`, `new_with_inner`, `new_connected_pair`, `setsockopt`, `getsockopt`; status macro |
| [shim/src/transport.rs](../../litebox_shim_linux/src/transport.rs) | `close x2`, `connect`, `drop x2`, `read`, `write`, `find_free_port`, `start`, `wait_until_ready`, `export_path`, `socket_addr`, `connect_9p`, `test_tun_nine_p_create_and_read_file`, `test_tun_nine_p_host_files_visible` |
| [shim/src/wait.rs](../../litebox_shim_linux/src/wait.rs) | `new`, `thread_handle`, `wait_cx`, `enter_from_guest`, `prepare_to_run_guest`, `check_for_interrupt` |
| [common/src/errno/generated.rs](../../litebox_common_linux/src/errno/generated.rs) | `as_str` |
| [common/src/errno/mod.rs](../../litebox_common_linux/src/errno/mod.rs) | `from x44`, `fmt x2`, `as_neg`, `from_const`, `try_from x4` |
| [common/src/lib.rs](../../litebox_common_linux/src/lib.rs) | `from x9`, `dev_major`, `dev_minor`, `statx_timestamp`, `try_from x5`, `new x2`, `single_shot`, `it_interval`, `it_value`, `rdfsbase`, `wrfsbase`, `rdgsbase`, `wrgsbase`, `rlimit_to_rlimit64`, `rlimit64_to_rlimit`, `is_shutdown_read`, `is_shutdown_write`, `try_from_raw`, `parse_futex`, `timespec64`, `timespec32`, `timespec_old`, `timeval`, `read`, `write`, `is_valid_user_fs_base`, `has_user_return_addresses x2`, `sanitize_for_user_return x2`, `syscall_arg x2`, `sys_req_arg`, `sys_req_ptr`, `get_ip x2`, `reinterpret_truncated_from_usize x7`, `reinterpret_usize_as_ptr x5` |
| [common/src/loader.rs](../../litebox_common_linux/src/loader.rs) | `phent_size`, `has_valid_magic`, `page_align_down`, `page_align_up`, `from x2`, `parse`, `has_trampoline`, `trampoline_page_range`, `parse_trampoline`, `program_headers`, `interp`, `pt_loads`, `load`, `load_trampoline`, `load_secondary_trampoline`, `read_at`, `size`, `reserve x2`, `map_file x2`, `map_zero x2`, `protect x2`, `compute_reserved_regions`, `read x3`, `write x3`, `zero x3`, `flags`, `elf_file`, `test_segment_address_overflow`, `test_entry_and_trampoline_overflow`, `assert_page_aligned`, `page_aligned_len_no_trim`, `larger_align_trims_head_and_tail`, `node_align_page_size_no_tail_trim_needed`, `non_page_aligned_len_with_large_align_trims_page_aligned_tail`, `head_plus_tail_equals_slack_when_len_page_aligned` |
| [common/src/mm.rs](../../litebox_common_linux/src/mm.rs) | `new`, `create_pages`, `create_executable_pages`, `create_writable_pages`, `create_readable_pages`, `create_inaccessible_pages`, `create_stack_pages`, `release_memory`, `overlaps`, `remap_pages`, `remove_pages`, `reset_pages`, `change_page_permissions`, `make_pages_writable`, `make_pages_executable`, `make_pages_readable`, `make_pages_inaccessible`, `make_pages_rwx`, `register_existing_mapping`, `mappings`, `get_memory_permissions`, `handle_page_fault`, `do_mmap`, `sys_munmap`, `sys_mprotect`, `sys_mremap`, `sys_madvise` |
| [common/src/physical_pointers.rs](../../litebox_common_linux/src/physical_pointers.rs) | `align_down`, `new x2`, `from_boxed`, `with_contiguous_pages x2`, `with_usize x2`, `read_at_offset x2`, `read_slice_at_offset x2`, `write_at_offset`, `write_slice_at_offset`, `map_and_get_ptr_guard`, `map_range`, `copy_to_user x3`, `copy_from_user x2`, `copy_out`, `copy_in`, `drop`, `fmt x2` |
| [common/src/signal/aarch64.rs](../../litebox_common_linux/src/signal/aarch64.rs) | No functions |
| [common/src/signal/mod.rs](../../litebox_common_linux/src/signal/mod.rs) | `as_i32`, `is_rt_signal`, `default_disposition`, `try_from`, `empty`, `is_empty`, `add`, `with`, `remove`, `contains`, `lowest_set`, `pop_lowest`, `as_u64`, `from_u64`, `into_iter`, `next`, `bitand`, `bitor`, `not`, `new_addr` |
| [common/src/signal/x86_64.rs](../../litebox_common_linux/src/signal/x86_64.rs) | No functions |
| [common/src/user_pointers.rs](../../litebox_common_linux/src/user_pointers.rs) | `from_usize x2`, `from_ptr x2`, `as_usize x2`, `is_null x2`, `cast x2`, `clone x2`, `fmt x2`, `from_platform_ptr x2`, `to_platform_ptr x2`, `read_at_offset x2`, `to_owned_slice x2`, `to_cstring`, `write_at_offset`, `write_slice_at_offset`, `copy_from_slice` |
| [common/src/vmap.rs](../../litebox_common_linux/src/vmap.rs) | `vmap`, `vmap_privileged`, `vunmap`, `validate_unowned`, `protect`, `base x2`, `size x2`, `new`, `from x2` |
| [common/src/vmem.rs](../../litebox_common_linux/src/vmem.rs) | `may_flags_for_mapping`, `from x3`, `into_iter`, `new x5`, `len`, `is_empty`, `start_and_length`, `as_usize x2`, `add`, `flags`, `is_file_backed`, `iter`, `register_existing_mapping_overwrite`, `overlapping`, `remove_mapping`, `reset_pages`, `insert_mapping`, `create_mapping`, `resize_mapping`, `move_mappings`, `protect_mapping`, `create_pages`, `get_memory_permissions`, `get_unmmaped_area`, `handle_page_fault`, `access_error`, `allocate_pages`, `deallocate_pages`, `remap_pages`, `update_permissions`, `reserved_pages`, `collect_mappings`, `test_vmm_mapping` |