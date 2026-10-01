# Remaining Crates Overflow Audit

## Scope And Status

Reviewed base: `0f601e96079a515e314773c599a53aa7ca8be286` (`0f601e960`). This document preserves the completed read-only audit of **51/51 Rust files**, including embedded tests. The per-file ledger records each file's final line and its arithmetic-bearing functions or function families; all remaining functions were also read and produced no additional overflow candidate.

The audit found two unchecked crypto-handle increments, one conditional HEKI allocation-capacity candidate, and a separate atomic-handle exhaustion concern. These remain unresolved. None establishes a short, unauthenticated runtime-input arithmetic-overflow exploit. The debug-only HEKI `modinfo` bounds issue is recorded separately and is not integer overflow.

No source edits, builds, tests, or runtime reproductions were performed during the audit. In particular, **no runtime candidate tests were executed**. Regression cases below are proposals, not executed results. The audit's final HEAD matched the reviewed base and its `git status --short` was empty. These statements describe the original audit, not subsequent worktree changes or this documentation addition.

## Qualified Findings

### 1. Plain OP-TEE Crypto-Handle Increments: Unresolved

`TeeObjMap::allocate` and `TeeCrypStateMap::allocate` compute `max_handle.0 + 1` at [object allocation](../../litebox_shim_optee/src/lib.rs#L1219) and [state allocation](../../litebox_shim_optee/src/lib.rs#L1389). TA callers are `sys_cryp_obj_alloc`/`sys_cryp_obj_close` and `sys_cryp_state_alloc`/`sys_cryp_state_free`; state allocation accepts NULL keys.

Retaining the newest handle, allocating another, then freeing the older one advances the maximum with at most two live entries. After approximately 2^32 allocations, there is no exhaustion guard: overflow-checking builds panic; unchecked release arithmetic produces reserved handle zero. Keeping the MAX entry makes subsequent allocations reuse zero and replace its entry. These are pre-existing sites, not newly introduced by the reviewed HEAD. This is a counter-exhaustion path requiring billions of calls, not an established short runtime-input exploit.

Proposed regression: seed each map near `u32::MAX`, then verify exhaustion never returns zero or replaces an existing entry. Not executed.

### 2. Signed-ELF HEKI Capacity Candidate: Unresolved

[Section allocation](../../litebox_service_heki/src/mem_integrity.rs#L104) checks `sh_offset + sh_size`, but allocates `vec![0u8; sh_size]` before establishing that the section fits the ELF or its corresponding memory container. A matching nonempty section with `sh_size > isize::MAX` and a nonoverflowing endpoint causes a capacity panic in both debug and release.

The [caller](../../litebox_service_heki/src/handlers.rs#L349) verifies the module signature first. This therefore requires an accepted, malformed signed ELF, not merely unsigned VTL0 input. The 64 MiB actual-file limit does not bound a forged section-size field. This remains a conditional allocation-capacity candidate, not a demonstrated unauthenticated arithmetic-overflow exploit.

Proposed regression: a small, structurally parseable ELF with valid supporting tables and an oversized target section should return an error before allocation. A public-path regression also needs an accepted signature fixture. Not executed.

### 3. Atomic TA Counter Exhaustion: Unresolved

[TaHandleMap::insert](../../litebox_shim_optee/src/lib.rs#L1449), called by `sys_open_bin`, uses `AtomicU32::fetch_add`. This has defined wrapping in both debug and release, not the arithmetic panic in finding 1. Repeated open/close calls can exhaust the counter with bounded live storage; after wrap, retaining an earlier handle permits its UUID mapping to be replaced.

Proposed regression: seed the counter near MAX while retaining a low-numbered handle and verify noncollision/exhaustion behavior. Not executed. HEKI's 64-bit module-token counter has a documented exhaustion assumption; no practical trigger was established here.

## Separate Bounds Issue

HEKI debug-only `parse_modinfo` directly slices an unchecked file extent after checked endpoint arithmetic. It runs **before signature verification**, so malformed unsigned ELF metadata can cause a debug-build bounds panic. This is **not integer overflow**, and that parsing path is absent in release.

Proposed regression: require an error for an out-of-file `.modinfo` extent. Not executed.

## Per-File And Function Ledger

Each row is one completely read Rust file. "None" means no relevant local integer sizing arithmetic. "Delegated" does not claim dependency internals were exhaustively audited. Final-line counts and line references describe the reviewed base.

| # | File | Final Line | Arithmetic-Bearing Functions Or Families And Disposition |
|---|---|---:|---|
| 1 | [litebox_common_optee/src/lib.rs](../../litebox_common_optee/src/lib.rs) | 2676 | `checked_syscall_copy_size`, raw syscall conversion, parameter type/value accessors, message-size/parsing/serialization helpers, SMC composition, `parse_ta_head`: checked, count-bounded, or fixed-index arithmetic. Arbitrary u32 message counts cannot overflow usize on supported x86_64; malformed internal counts can instead violate assertions. TA section extraction already hardened. |
| 2 | [litebox_common_optee/src/syscall_nr.rs](../../litebox_common_optee/src/syscall_nr.rs) | 159 | Constants/enums; none. |
| 3 | [litebox_shim_optee/src/lib.rs](../../litebox_shim_optee/src/lib.rs) | 1724 | Dispatch allocations capped; `allocate_guest_tls` currently receives only `None`/fixed PAGE_SIZE. Object/state allocators and TA registry covered by findings 1 and 3. `SessionIdPool::allocate_inner`/`recycle` guard exhaustion/subtraction; other handle conversions bounded or checked. |
| 4 | [litebox_shim_optee/src/idk.rs](../../litebox_shim_optee/src/idk.rs) | 683 | `endorsement_data_len` and endorsement output sizing checked; input capped at 1 MiB. Algorithm shifts bounded; key/certificate sizing checked or host-owned. |
| 5 | [litebox_shim_optee/src/loader/elf.rs](../../litebox_shim_optee/src/loader/elf.rs) | 342 | `read_at`/`map_file` use remaining-buffer bounds; `reserve` checks padding addition. ELF mapping/trampoline internals delegated. |
| 6 | [litebox_shim_optee/src/loader/mod.rs](../../litebox_shim_optee/src/loader/mod.rs) | 19 | Fixed constants, including 1 MiB stack multiplication. |
| 7 | [litebox_shim_optee/src/loader/ta_stack.rs](../../litebox_shim_optee/src/loader/ta_stack.rs) | 369 | `TaStack::new` subtraction safe for its sole fixed-1-MiB caller; pushes checked, increments bounded, getters derive mapped ranges. `allocate_stack` reuses saved allocation base, not untrusted ldelf output. |
| 8 | [litebox_shim_optee/src/msg_handler.rs](../../litebox_shim_optee/src/msg_handler.rs) | 1023 | Message snapshots/counts bounded; `decode_ta_request` caps memrefs; `ShmInfo::new` checks page sizing. Reads, copies, registration offsets, page strides and registered-memory views checked/bounded; registration capped and cycles rejected. |
| 9 | [litebox_shim_optee/src/session.rs](../../litebox_shim_optee/src/session.rs) | 1205 | `instance_count`, `with_ta`, registration/filter counts bounded by normal capacity/collections; IDs use guarded pool. No practical overflow established through isolated capacity-bypassing registration helpers. |
| 10 | [litebox_shim_optee/src/syscalls/cryp.rs](../../litebox_shim_optee/src/syscalls/cryp.rs) | 339 | Crypto lengths/comparisons/slices locally bounded; allocation calls reach finding 1. |
| 11 | [litebox_shim_optee/src/syscalls/ldelf.rs](../../litebox_shim_optee/src/syscalls/ldelf.rs) | 564 | `checked_map_len`, padding helpers, map/protect/trampoline spans and `read_ta_bin` checked; differences ordered. Open/close calls reach finding 3. |
| 12 | [litebox_shim_optee/src/syscalls/mm.rs](../../litebox_shim_optee/src/syscalls/mm.rs) | 168 | `find_bottom_up_gap` and `sys_mmap` check endpoints/rounding. `sys_mprotect` delegates to common code whose current `change_page_permissions` uses checked addition; historical overflow is absent at the reviewed HEAD. |
| 13 | [litebox_shim_optee/src/syscalls/mod.rs](../../litebox_shim_optee/src/syscalls/mod.rs) | 39 | Cleanup delegates unmapping; none locally. |
| 14 | [litebox_shim_optee/src/syscalls/pta.rs](../../litebox_shim_optee/src/syscalls/pta.rs) | 474 | `huk_subkey_derive` context sum bounded by sole caller to 1044 bytes; output 16-32 bytes. Session cap 100; address-half shifts and mapping sizes guarded. |
| 15 | [litebox_shim_optee/src/syscalls/tee.rs](../../litebox_shim_optee/src/syscalls/tee.rs) | 371 | Fixed alignment subtraction; `sys_check_access_rights` checks adjusted length, rounding and endpoint. Time conversion intentionally clamps. |
| 16 | [litebox_shim_optee/src/syscalls/tests.rs](../../litebox_shim_optee/src/syscalls/tests.rs) | 87 | Fixed page fixtures; u32-second millisecond calculation fits u64. |
| 17 | [litebox_service_heki/src/lib.rs](../../litebox_service_heki/src/lib.rs) | 1066 | Memory-container ranges/capacities/appends checked and fallible; physical ranges ordered and <=52 bits. Patch-record multiplication/end checked. `SymbolTable::build_from_container` rejects reversed/out-of-range intervals; increments bounded by endpoint. `Symbol::from_bytes` byte offsets fit usize on x86_64; virtual-field arithmetic is boot-only. Discontiguous-buffer/layout errors are distinct bounds concerns. |
| 18 | [litebox_service_heki/src/handlers.rs](../../litebox_service_heki/src/handlers.rs) | 819 | `load_kdata`/`protect_memory`/ringbuffer registration boot-only. Kexec endpoints checked; page-list accumulation/reservation guarded. DER lengths <=65539 total; prepared patches <=5 bytes with page-bounded offsets. Highest physical-page alignment is a representability concern, not u64 overflow. |
| 19 | [litebox_service_heki/src/mem_integrity.rs](../../litebox_service_heki/src/mem_integrity.rs) | 760 | Finding 2 and separate debug bounds issue above. Relocation spans and signature-trailer arithmetic checked; `start-1` guarded. Patch `size-1` safe because imported validation rejects zero and sizes above five. |
| 20 | [litebox_syscall_rewriter/src/lib.rs](../../litebox_syscall_rewriter/src/lib.rs) | 1240 | PHDR relocation/preflight, trailer endpoints, decode VA/chunk/scratch extents, reencoding/trampoline/preamble additions guarded. Decode advances bounded by slices; `rel32_bytes` uses i128 plus checked narrowing. Overflowing load-segment ends are skipped, not unchecked. |
| 21 | [litebox_syscall_rewriter/src/main.rs](../../litebox_syscall_rewriter/src/main.rs) | 69 | CLI: none. |
| 22 | [litebox_syscall_rewriter/tests/snapshot_tests.rs](../../litebox_syscall_rewriter/tests/snapshot_tests.rs) | 89 | Snapshot trailer checks guarded; token-index addition bounded by collection. |
| 23 | [litebox_packager/src/lib.rs](../../litebox_packager/src/lib.rs) | 683 | `parse_include`/`find_dependencies` delimiter offsets bounded by successful searches; capacities derive existing collections. Tar size widening safe; MB conversion display-only. |
| 24 | [litebox_packager/src/oci.rs](../../litebox_packager/src/oci.rs) | 1068 | OCI layer/env indices bounded; symlink recursion decrements only nonzero fixed depth. Tar/gzip/OCI internals delegated. |
| 25 | [litebox_packager/src/main.rs](../../litebox_packager/src/main.rs) | 8 | Main: none. |
| 26 | [litebox_runner_linux_on_windows_userland/build.rs](../../litebox_runner_linux_on_windows_userland/build.rs) | 6 | No relevant local integer sizing arithmetic; loading/platform operations delegated. |
| 27 | [litebox_runner_linux_on_windows_userland/src/lib.rs](../../litebox_runner_linux_on_windows_userland/src/lib.rs) | 131 | No relevant local integer sizing arithmetic; loading/platform operations delegated. |
| 28 | [litebox_runner_linux_on_windows_userland/src/main.rs](../../litebox_runner_linux_on_windows_userland/src/main.rs) | 18 | No relevant local integer sizing arithmetic; loading/platform operations delegated. |
| 29 | [litebox_runner_linux_on_windows_userland/tests/common/mod.rs](../../litebox_runner_linux_on_windows_userland/tests/common/mod.rs) | 97 | No relevant local integer sizing arithmetic; loading/platform operations delegated. Embedded C is fixture text. |
| 30 | [litebox_runner_linux_on_windows_userland/tests/loader.rs](../../litebox_runner_linux_on_windows_userland/tests/loader.rs) | 348 | No relevant local integer sizing arithmetic; loading/platform operations delegated. Embedded C is fixture text. |
| 31 | [litebox_runner_linux_userland/src/lib.rs](../../litebox_runner_linux_userland/src/lib.rs) | 414 | IDs checked/fixed; load/network/pointer operations delegated. CPU-affinity helper's sole input is CPU zero. |
| 32 | [litebox_runner_linux_userland/src/main.rs](../../litebox_runner_linux_userland/src/main.rs) | 9 | Main: none. |
| 33 | [litebox_runner_linux_userland/tests/cache.rs](../../litebox_runner_linux_userland/tests/cache.rs) | 162 | Collection counts/indices bounded; timestamps/hash operations delegated. |
| 34 | [litebox_runner_linux_userland/tests/common/mod.rs](../../litebox_runner_linux_userland/tests/common/mod.rs) | 321 | Delimiter offsets bounded. |
| 35 | [litebox_runner_linux_userland/tests/common/pty.rs](../../litebox_runner_linux_userland/tests/common/pty.rs) | 145 | PTY deadline fixed ten seconds and reads bounded by 4096-byte buffer. |
| 36 | [litebox_runner_linux_userland/tests/loader.rs](../../litebox_runner_linux_userland/tests/loader.rs) | 267 | Fixed/local fixtures, subprocess and library-managed networking; no unchecked packet-sizing implementation. |
| 37 | [litebox_runner_linux_userland/tests/run.rs](../../litebox_runner_linux_userland/tests/run.rs) | 644 | Fixed/local fixtures, subprocess and library-managed networking; no unchecked packet-sizing implementation. |
| 38 | [litebox_runner_optee_on_linux_userland/src/lib.rs](../../litebox_runner_optee_on_linux_userland/src/lib.rs) | 158 | Runner setup delegated; command support module is production-compiled. |
| 39 | [litebox_runner_optee_on_linux_userland/src/tests.rs](../../litebox_runner_optee_on_linux_userland/src/tests.rs) | 354 | `parse_uuid_or_panic` fixed indices; parameter conversion/stack sizing checked; base64 estimate delegated. `handle_ta_command_output` reaches a helper checking byte multiplication, isize capacity and pointer end before allocation. Uncapped ordinary OOM is not arithmetic overflow. |
| 40 | [litebox_runner_optee_on_linux_userland/src/main.rs](../../litebox_runner_optee_on_linux_userland/src/main.rs) | 9 | None relevant; fixture execution delegated. |
| 41 | [litebox_runner_optee_on_linux_userland/tests/run.rs](../../litebox_runner_optee_on_linux_userland/tests/run.rs) | 103 | None relevant; fixture execution delegated. |
| 42 | [litebox_util_log/src/lib.rs](../../litebox_util_log/src/lib.rs) | 145 | No local integer sizing arithmetic. |
| 43 | [litebox_util_log/src/backend_log.rs](../../litebox_util_log/src/backend_log.rs) | 108 | No local integer sizing arithmetic. |
| 44 | [litebox_util_log/src/backend_tracing.rs](../../litebox_util_log/src/backend_tracing.rs) | 210 | No local integer sizing arithmetic. |
| 45 | [litebox_util_log/src/macros.rs](../../litebox_util_log/src/macros.rs) | 88 | No local integer sizing arithmetic. |
| 46 | [litebox_util_log/tests/facade.rs](../../litebox_util_log/tests/facade.rs) | 211 | `instrumented_returning_value` multiplies i32 by two; sole fixture input is 21. |
| 47 | [litebox_util_log_macros/src/lib.rs](../../litebox_util_log_macros/src/lib.rs) | 376 | Argument parsing and instrumentation token generation; no local numeric sizing arithmetic. |
| 48 | [dev_tests/src/lib.rs](../../dev_tests/src/lib.rs) | 56 | Source traversal/header checks use fixed/existing buffers; none relevant. |
| 49 | [dev_tests/src/boilerplate.rs](../../dev_tests/src/boilerplate.rs) | 144 | Source traversal/header checks use fixed/existing buffers; none relevant. |
| 50 | [dev_tests/src/ratchet.rs](../../dev_tests/src/ratchet.rs) | 169 | Source-count aggregation uses trusted development data; excess-count subtraction occurs only in the Greater branch. No feasible overflow demonstrated. |
| 51 | [dev_bench/src/main.rs](../../dev_bench/src/main.rs) | 749 | `Summarization::summarize` uses checked u32 count and host elapsed Durations; sum overflow is theoretical, not guest-controlled. `compare_runs` uses i128 differences bounded by actual collections; delimiter offsets bounded. Floating NaN on empty comparisons is not integer overflow. |

## Audit Limits

Explicit `.trunc()`, `wrapping_*`, and `saturating_*` were excluded as requested in the original audit. No unsupported 32-bit scenarios were used to flag x86_64-only paths. Imported guards/callers were read narrowly; external parsers, crypto engines and platform implementations were not exhaustively audited.

No incomplete scoped reads remain. The ledger is coverage evidence at the reviewed base, not a claim that all repository overflows have been eliminated, that delegated implementations are safe, or that proposed regressions have passed.