# Platform Overflow Audit

## Scope and Status

Reviewed branch `weiteng/overflow-hardening` at base commit
`0f601e96079a515e314773c599a53aa7ca8be286` (`0f601e960`) in the
`litebox-overflow-hardening` worktree. All **56 scoped Rust files**, totaling
**21,348 physical lines at the reviewed base**, were read through EOF, including
test bodies and assembly. Truncated displays were recovered by additional reads;
no scoped file remained incompletely read. This report covers seven scoped crates.
Caller tracing outside those crates established input provenance and controlling
bounds only; it was not a broader repository audit.

The original audit was read-only and did not execute reproductions. Later current
uncommitted changes **FIXED Windows `Instant::checked_duration_since`**, using
seconds plus the remaining 100-nanosecond fraction. Regression testing covered
20 billion seconds and `u64::MAX` ticks. The analogous Windows `SystemTime`
calculation and LVBS `checked_shl` PFN conversion remain unresolved,
source-verified candidates. Neither is a hardware-validated exploit. No
hardware-backed tests were performed.

Disposition key:

- **Bounded:** justified by actual callers, validated ranges, owned objects or
  fixed constants; not a claim about arbitrary calls that bypass those bounds.
- **Trusted:** depends on a backend, hardware or boot-layout contract.
- **Checked:** arithmetic is explicitly checked.

Explicit `trunc`, `wrapping_*` and `saturating_*` operations were treated as
intentional. Source line numbers in the original report referred to the reviewed
base and may move in the current worktree; links here point to source files.

## Concrete Findings

### Windows Guest Sleep Duration: FIXED in Current Uncommitted Changes

At the reviewed base,
[Windows `Instant::checked_duration_since`](../../litebox_platform_windows_userland/src/lib.rs)
computed `diff * 100` in `u64`, overflowing before blocking for sufficiently large
guest-controlled sleep durations.

- **Trigger:** relative
  `clock_nanosleep(CLOCK_MONOTONIC, 0, {tv_sec: 20_000_000_000, tv_nsec: 0}, ...)`.
- **Caller path:**
  [`sys_clock_nanosleep`](../../litebox_shim_linux/src/syscalls/process.rs) ->
  `WaitContext::with_timeout` -> Windows `Instant::checked_add` -> `sleep` ->
  `commit_wait` ->
  [`remaining_timeout`](../../litebox/src/event/wait.rs) ->
  `checked_duration_since`.
- **Existing checks at the base:** the positive 64-bit timespec is accepted.
  Conversion to 100-nanosecond units and deadline addition fit on an ordinary
  running system, but converting the remaining difference back to nanoseconds
  does not fit. The later Windows millisecond clamp cannot prevent this earlier
  overflow.
- **Base impact:** overflow-checked builds panic immediately; unchecked release
  builds wrap the duration and produce an incorrect timeout. No memory corruption
  was demonstrated.
- **Current resolution:** split `diff` into `diff / 10_000_000` seconds and
  `(diff % 10_000_000) * 100` nanoseconds, then construct `Duration::new`. Only the
  bounded remainder is multiplied, so the overflowing intermediate is removed.
- **Regression evidence:** the later regression test verifies adding and
  subtracting `Duration::from_secs(20_000_000_000)`, reversed instants returning
  `None`, the full `u64::MAX`-tick difference (with a `955_161_500`-nanosecond
  remainder), and a one-second-plus-one-tick difference. These regression tests
  were reported passing in the later fix work; they were not rerun for this
  documentation-only task. An end-to-end guest syscall reproduction was not
  executed in the original audit.

### LVBS PFN High-Bit Loss: Unresolved Source-Verified Candidate

[`LvbsVtl1Gate::boot_aps`](../../litebox_platform_lvbs/src/mshv/vsm.rs) still uses
`checked_shl(12)` to convert a VTL0-supplied PFN to a physical address.

- **Trigger:** PFN `(1u64 << 52) | 1`; its shifted result is `0x1000`.
- **Caller path:** raw VTL call -> `vtlcall_dispatch` ->
  [`vsm_dispatch`, `BootAPs` arm](../../litebox_runner_lvbs/src/lib.rs) ->
  `boot_aps`. The argument is forwarded unchanged; neither shown path imposes an
  end-of-boot restriction.
- **Existing checks:** `checked_shl` checks only that the shift count is below 64,
  not whether high value bits are lost. `PhysAddr::try_new` validates the
  already-truncated result, so the example aliases a valid low physical address.
- **Impact and limit:** the alias is the same in debug and release, without an
  overflow panic. The subsequent fixed-size CPU-mask read still has VTL0 access
  checks. This establishes invalid-PFN acceptance in the source path, **not**
  arbitrary protected-memory access or memory corruption. No hardware-backed
  reproduction was performed.
- **Cheap proposed check:** assert that the example PFN returns
  `InvalidPhysicalAddress` before copying. Checked multiplication by 4096 followed
  by `PhysAddr::try_new`, or a PFN bound below `1 << 40`, rejects it. The neighboring
  OP-TEE PFN entry already uses checked multiplication. This check remains
  proposed, not a reported test pass.

## Other Candidates and Trust Assumptions

These have concrete arithmetic triggers but are not established direct guest
vulnerabilities.

### Signal-Mask API Mismatch

[Linux `record_pending_signal`](../../litebox_platform_linux_userland/src/lib.rs)
and [Windows `ThreadHandle::deliver_signal`](../../litebox_platform_windows_userland/src/lib.rs)
shift `1u32` by `signal - 1`, although `Signal::try_from` accepts 1-64. Creating and
firing a platform timer for signal 33 reaches shift count 32. Overflow-checked
builds panic; unchecked x86-64 builds can alias a lower signal bit. Windows
executes this inside a non-unwinding callback, making a panic potentially
process-fatal. Linux's outer `signum < 32` check constrains host `SIGALRM`, not the
substituted signal from `si_value`.

**The only production timer caller found requests `SIGALRM`; no guest-selected
timer-signal syscall path was found.** Proposed cheap check: platform timer tests
for signals 32, 33 and 64; reject unsupported signals or consistently widen
storage and operations. No such test pass is claimed here.

### Windows System-Clock Horizon: Unresolved Source-Verified Candidate

[`SystemTime::duration_since`](../../litebox_platform_windows_userland/src/lib.rs)
still has the analogous multiplication in both subtraction branches. A difference
exceeding `u64::MAX / 100` 100-nanosecond ticks, approximately 584.6 years, panics
with overflow checks and wraps without them. The inputs here are private
host-clock values, unlike the guest-derived future `Instant` above. Therefore
this is not an established direct guest-input vulnerability.

Proposed cheap check: synthetic FILETIME differences at that boundary, in both
ordering branches. The `Instant` fix does not resolve this calculation, and its
regression results do not validate `SystemTime`.

### Public COM-Port Construction

[`ComPort::init`](../../litebox_platform_lvbs/src/arch/x86/ioport.rs) and register
helpers add offsets to a `u16` port. A caller constructing
`ComPort::new(u16::MAX)` causes checked overflow or unchecked port wrap.
Production console ports are fixed at `0x2F8`/`0x3F8`; no guest-controlled port
path was found. Proposed cheap check: validate the entire register window before
initialization, preferably without executing I/O.

### Invalid Diagnostic Object

[`HekiRange::fmt`](../../litebox_common_lvbs/src/lib.rs) subtracts `epa - pa`; an
arbitrary public struct with `pa=1, epa=0` panics with checks and prints a wrapped
size without them. The production HEKI logging path first copies and validates
every range through `HekiPage::is_valid`, so that path cannot supply reversed
endpoints. Proposed cheap check: format an invalid range directly.

### CRNG Counter Horizon

[`LvbsCrng::reseed`](../../litebox_platform_lvbs/src/host/lvbs_impl.rs) increments
a `u64` counter unchecked. Overflow requires exhausting the counter through
reseeds; no feasible guest trigger was established. Checked builds panic and
unchecked builds wrap. Proposed cheap check: a unit-level counter-at-maximum
probe.

## File Coverage and Function Summaries

The following inventory preserves all 56 scoped files and their function-level
dispositions from the reviewed-base report, with the later Windows `Instant`
status explicitly updated. Counts: Linux kernel 16, Linux userland 2, Windows
userland 2, LVBS platform 31, common LVBS 1, LVBS runner 2, SNP runner 2.

### Linux Kernel (16 Files)

- [litebox_platform_linux_kernel/build.rs](../../litebox_platform_linux_kernel/build.rs):
  `main`/bindgen setup; no runtime arithmetic candidate.
- [litebox_platform_linux_kernel/src/lib.rs](../../litebox_platform_linux_kernel/src/lib.rs):
  `current_time` is Trusted host-clock arithmetic;
  `Instant::{checked_duration_since,checked_add,rdtsc}` are Checked or bounded
  register composition. Page-provider operations use validated `PageRange`;
  `switch_to_guest` uses fixed owned-context offsets. Zero `CPU_MHZ` is an
  initialization-contract issue, not overflow.
- [litebox_platform_linux_kernel/src/arch/mod.rs](../../litebox_platform_linux_kernel/src/arch/mod.rs):
  module declarations; no arithmetic functions.
- [litebox_platform_linux_kernel/src/arch/x86/mod.rs](../../litebox_platform_linux_kernel/src/arch/x86/mod.rs):
  module declarations; no arithmetic functions.
- [litebox_platform_linux_kernel/src/arch/x86/instructions.rs](../../litebox_platform_linux_kernel/src/arch/x86/instructions.rs):
  `rdmsr`/`wrmsr` use fixed-width register composition/splitting; no overflow
  candidate. Other instructions have no sizing arithmetic.
- [litebox_platform_linux_kernel/src/arch/x86/mm/mod.rs](../../litebox_platform_linux_kernel/src/arch/x86/mm/mod.rs):
  module declarations; no arithmetic functions.
- [litebox_platform_linux_kernel/src/arch/x86/mm/paging.rs](../../litebox_platform_linux_kernel/src/arch/x86/mm/paging.rs):
  `map_pages`, `unmap_pages`, `remap_pages`, `mprotect_pages` use validated page
  ranges and typed frames. Page increments and inclusive-end conversions are
  Bounded; frame-pointer helpers rely on the direct-map contract.
- [litebox_platform_linux_kernel/src/host/mod.rs](../../litebox_platform_linux_kernel/src/host/mod.rs):
  modules/re-exports; no arithmetic functions.
- [litebox_platform_linux_kernel/src/host/mock.rs](../../litebox_platform_linux_kernel/src/host/mock.rs):
  `alloc` rounds size and doubles alignment/allocation size. Existing
  allocator/test callers supply bounded layouts; arbitrary direct backend calls
  are outside that proof. `current_system_time` uses host timespec fields and
  intentional conversions.
- [litebox_platform_linux_kernel/src/host/snp/mod.rs](../../litebox_platform_linux_kernel/src/host/snp/mod.rs):
  modules/bindings; no arithmetic functions.
- [litebox_platform_linux_kernel/src/host/snp/ghcb.rs](../../litebox_platform_linux_kernel/src/host/snp/ghcb.rs):
  `str2u64`/`ghcb_prints` have bounded six-byte chunks; `num_to_char`/`num_to_buf`
  have in-tree bases 10/16; `set_offset_valid` uses fixed offsets and modulo-eight
  shifts. MSR encoding/decoding uses bounded fields or intentional truncation.
- [litebox_platform_linux_kernel/src/host/snp/snp_impl.rs](../../litebox_platform_linux_kernel/src/host/snp/snp_impl.rs):
  allocator sizing and `parse_alloc_result` use ABI maximum order 10; rescue
  layouts are capped upstream. `parse_result` restricts the signed error range
  before `abs`. Timeout seconds conversion is checked. Thread-counter atomics
  wrap intrinsically, with no feasible exhaustion shown.
- [litebox_platform_linux_kernel/src/host/snp/vmsa.rs](../../litebox_platform_linux_kernel/src/host/snp/vmsa.rs):
  ABI structures; no arithmetic functions.
- [litebox_platform_linux_kernel/src/mm/mod.rs](../../litebox_platform_linux_kernel/src/mm/mod.rs):
  `va_to_pa`/`pa_to_va` rely on Trusted direct-map and encryption-bit contracts;
  no violating caller established.
- [litebox_platform_linux_kernel/src/mm/pgtable.rs](../../litebox_platform_linux_kernel/src/mm/pgtable.rs):
  fixed-page allocation and constants; no variable-size overflow candidate.
- [litebox_platform_linux_kernel/src/mm/tests.rs](../../litebox_platform_linux_kernel/src/mm/tests.rs):
  mock `alloc`, `va_to_pa`, `pa_to_va`, `test_page_table`, `test_vmm_page_fault`
  use successful mappings, a 1024-entry table and fixed addresses/page counts.
  Buddy/slab tests use small fixed allocations.

### Linux Userland (2 Files)

- [litebox_platform_linux_userland/src/lib.rs](../../litebox_platform_linux_userland/src/lib.rs):
  `register_cow_region`/`lookup_cow_region` use valid static slices and checked
  ends; `read_maps` advances inside an 8192-byte buffer. `wait_on_tun`,
  `futex_timeout`, `futex_val2` use fallible/clamped conversions.
  `with_signal_alt_stack` uses Trusted host constants and a successful mapping;
  `signal_handler_exit_guest` uses an owned context. Thread/context assembly uses
  fixed offsets. `record_pending_signal`/`interrupt_signal_handler` have the
  signal API candidate above; timer conversions explicitly marked truncating are
  intentional. Tests use fixed inputs.
- [litebox_platform_linux_userland/src/page_mgmt.rs](../../litebox_platform_linux_userland/src/page_mgmt.rs):
  `allocate_pages`, `deallocate_pages`, `remap_pages`, `update_permissions`,
  `try_allocate_cow_pages` use validated ranges, successful OS mappings and valid
  CoW slices; no demonstrated overflow. `test_reserved_pages` uses fixed sizes.

### Windows Userland (2 Files)

- [litebox_platform_windows_userland/src/lib.rs](../../litebox_platform_windows_userland/src/lib.rs):
  `round_up_to_granu`/`round_down_to_granu` are Bounded by caller address limits
  and Trusted OS granularity. `read_memory_maps` and nested `module_bounds` use
  successful host extents. `XsaveLayout::get`,
  `XsaveArea::{initial_guest,restore_to_context,legacy_state_for_context}`,
  `ExtendedContext::{new,prepare_for_capture}` use widened `u32` hardware/API
  sizes and validated components. `current_time` uses fixed FILETIME composition.
  The base `Instant` conversion finding is FIXED in current uncommitted changes
  and regression tested as detailed above; the analogous `SystemTime` candidate
  remains unresolved. `deliver_signal` has the API candidate. `set_timer` clamps
  before signed negation; backend `alloc` receives rescue layouts below order 28.
  Fixed-context assembly and XSAVE tests are Bounded.
- [litebox_platform_windows_userland/src/page_mgmt.rs](../../litebox_platform_windows_userland/src/page_mgmt.rs):
  `reserve_gap`, `reserve_gaps`, `commit_pages`, `decommit_pages`, `allocate_pages`,
  `update_permissions`, `do_query_on_region`, `process_memory_range_by_regions`
  operate within reservations/intersections or bounded query segments. Successful
  reservations justify base-plus-length expressions. Prefetching and tests use
  valid ranges.

### LVBS Platform (31 Files)

- [litebox_platform_lvbs/src/lib.rs](../../litebox_platform_lvbs/src/lib.rs):
  `LvbsValidateAccess::{validate,validate_slice}` check sizes/ends.
  `LinuxKernel::new` depends on boot/linker extents; `unmap_vtl0_pages` checks its
  end. `Instant` arithmetic is Checked. Page-provider methods validate ranges.
  `vmap`/`vmap_privileged` obtain a bounded VA allocation before length
  multiplication; `vunmap` uses matching private metadata; `protect` checks page
  ends. Thread-entry assembly uses fixed owned-object offsets.
- [litebox_platform_lvbs/src/syscall_entry.rs](../../litebox_platform_lvbs/src/syscall_entry.rs):
  fixed selectors, configuration and context offsets; no variable arithmetic
  candidate.
- [litebox_platform_lvbs/src/arch/mod.rs](../../litebox_platform_lvbs/src/arch/mod.rs):
  modules; no arithmetic functions.
- [litebox_platform_lvbs/src/arch/x86/mod.rs](../../litebox_platform_lvbs/src/arch/x86/mod.rs):
  `get_core_id` masks the APIC ID; feature-enablement functions use fixed shifts.
  Bounded hardware-field operations.
- [litebox_platform_lvbs/src/arch/x86/gdt.rs](../../litebox_platform_lvbs/src/arch/x86/gdt.rs):
  constructors and `setup_gdt_tss`/`init` use fixed descriptors and owned per-CPU
  stacks; no variable overflow candidate.
- [litebox_platform_lvbs/src/arch/x86/instrs.rs](../../litebox_platform_lvbs/src/arch/x86/instrs.rs):
  MSR helpers use bounded high/low register fields; other instruction wrappers
  have no sizing arithmetic.
- [litebox_platform_lvbs/src/arch/x86/interrupts.rs](../../litebox_platform_lvbs/src/arch/x86/interrupts.rs):
  IDT initialization/handlers use fixed indices and offsets; no variable
  arithmetic candidate.
- [litebox_platform_lvbs/src/arch/x86/ioport.rs](../../litebox_platform_lvbs/src/arch/x86/ioport.rs):
  `interrupt_enable`, `fifo_control`, `modem_control`, `line_status`,
  `ComPort::init` have the public-port observation above. `write_byte` caps its
  poll counter at 1,000,000; production ports are fixed.
- [litebox_platform_lvbs/src/arch/x86/msr.rs](../../litebox_platform_lvbs/src/arch/x86/msr.rs):
  constants; no arithmetic functions.
- [litebox_platform_lvbs/src/arch/x86/timer.rs](../../litebox_platform_lvbs/src/arch/x86/timer.rs):
  fixed timer constants; deadline wrapping is explicit and intentional.
- [litebox_platform_lvbs/src/arch/x86/mm/mod.rs](../../litebox_platform_lvbs/src/arch/x86/mm/mod.rs):
  modules; no arithmetic functions.
- [litebox_platform_lvbs/src/arch/x86/mm/paging.rs](../../litebox_platform_lvbs/src/arch/x86/mm/paging.rs):
  `flush_tlb_range`, `map_pages`, `unmap_pages`, `remap_pages`, `mprotect_pages`,
  `map_phys_frame_range`, `map_non_contiguous_phys_frames`, `rollback_mapped_pages`
  use valid ranges and bounded batches/extents. `Drop` reconstructs addresses
  from indices at most 511 with fixed shifts. Frame-pointer conversions rely on
  the direct-map contract.
- [litebox_platform_lvbs/src/host/bootparam.rs](../../litebox_platform_lvbs/src/host/bootparam.rs):
  `save_vtl1_memory_info` validates positive/aligned inputs; extent addition is
  checked by later boot initialization. CPU-count handling is Trusted boot input.
- [litebox_platform_lvbs/src/host/linux.rs](../../litebox_platform_lvbs/src/host/linux.rs):
  `CpuMask::for_each_cpu` uses two words and shifts 0-63, yielding CPU IDs 0-127.
- [litebox_platform_lvbs/src/host/lvbs_impl.rs](../../litebox_platform_lvbs/src/host/lvbs_impl.rs):
  fixed allocator order 25; dynamic host allocation is unsupported.
  `LvbsCrng::fill_bytes` subtracts at most the remaining budget; `reseed` has the
  counter-horizon observation. Tests use bounded budgets.
- [litebox_platform_lvbs/src/host/mock.rs](../../litebox_platform_lvbs/src/host/mock.rs):
  test stubs; no significant arithmetic functions.
- [litebox_platform_lvbs/src/host/mod.rs](../../litebox_platform_lvbs/src/host/mod.rs):
  modules and linker hypercall-page accessor; Trusted linker address, no variable
  sizing arithmetic.
- [litebox_platform_lvbs/src/host/per_cpu_variables.rs](../../litebox_platform_lvbs/src/host/per_cpu_variables.rs):
  stack-top helpers, `init_per_cpu_variables`, XSAVE allocation/size helpers and
  mask setters use owned objects, fixed offsets or widened CPUID fields. Hardware
  sizes are Trusted; allocation arithmetic fits on x86-64.
- [litebox_platform_lvbs/src/mm/mod.rs](../../litebox_platform_lvbs/src/mm/mod.rs):
  VA/PA conversion helpers rely on the Trusted kernel direct-map extent; no actual
  extent violation shown.
- [litebox_platform_lvbs/src/mm/pgtable.rs](../../litebox_platform_lvbs/src/mm/pgtable.rs):
  fixed-page allocation/constants; no variable overflow candidate.
- [litebox_platform_lvbs/src/mm/tests.rs](../../litebox_platform_lvbs/src/mm/tests.rs):
  mock `alloc`, `va_to_pa`, `pa_to_va`, `test_page_table`, `test_vmm_page_fault`
  use bounded tables, mappings and fixed page counts. Buddy/slab allocations are
  fixed; several tests are explicitly ignored.
- [litebox_platform_lvbs/src/mm/vmap.rs](../../litebox_platform_lvbs/src/mm/vmap.rs):
  `allocate_va_range` checks guard-page/end additions and caps the region;
  `vpn_to_va` is bounded by that region. `free_va_range`/`free_va` require a
  matching allocation, which production callers preserve. Arithmetic in
  allocation/gap tests uses small fixed counts.
- [litebox_platform_lvbs/src/mshv/hvcall.rs](../../litebox_platform_lvbs/src/mshv/hvcall.rs):
  guest-ID/status/rep-count helpers use fixed or masked fields. `ptr_to_gpa`
  depends on kernel-pointer provenance; `hv_do_rep_hypercall` relies on Trusted
  hypervisor completion counts.
- [litebox_platform_lvbs/src/mshv/hvcall_mm.rs](../../litebox_platform_lvbs/src/mshv/hvcall_mm.rs):
  `hv_modify_vtl_protection_mask`, `hv_flush_virtual_address_space`,
  `hv_flush_virtual_address_list` use fixed-page request capacities, bounded
  physical ranges and caller-limited batches; explicit saturation is intentional.
- [litebox_platform_lvbs/src/mshv/hvcall_vp.rs](../../litebox_platform_lvbs/src/mshv/hvcall_vp.rs):
  `hv_vtl_populate_vp_context` uses fixed nonzero TSS size minus one; `init_vtl_ap`
  uses linker special-page stack bounds.
- [litebox_platform_lvbs/src/mshv/mod.rs](../../litebox_platform_lvbs/src/mshv/mod.rs):
  field encoders/constructors and layout tests use fixed or masked shifts and
  fixed header capacities; two VP banks cover `MAX_CORES=128`.
- [litebox_platform_lvbs/src/mshv/ringbuffer.rs](../../litebox_platform_lvbs/src/mshv/ringbuffer.rs):
  `advance_offset`, `write_fast`, `write_slow`, `RingBuffer::write` preserve
  offset/length bounds. Production registration checks `pa + size`, valid aligned
  physical endpoints and boot authorization before installation; suspected size
  overflow rejected.
- [litebox_platform_lvbs/src/mshv/vsm_intercept.rs](../../litebox_platform_lvbs/src/mshv/vsm_intercept.rs):
  `vsm_handle_intercept` composes MSR ABI fields; `advance_vtl0_rip` uses checked
  addition and injects a fault on overflow.
- [litebox_platform_lvbs/src/mshv/vsm.rs](../../litebox_platform_lvbs/src/mshv/vsm.rs):
  `protect_vtl1_physical_memory_range`, protection/unprotection, reservations and
  registry updates use checked boot extents or bounded frame ranges. `boot_aps`
  has the unresolved PFN candidate; root-key physical-address validation is
  explicit.
- [litebox_platform_lvbs/src/mshv/vtl_switch.rs](../../litebox_platform_lvbs/src/mshv/vtl_switch.rs):
  VP-mask `set`, `clear`, `is_single_vp` use bounded bank/bit indices.
  `mshv_vsm_get_code_page_offsets` checks address addition; transition assembly
  uses fixed object offsets.
- [litebox_platform_lvbs/src/mshv/vtl1_mem_layout.rs](../../litebox_platform_lvbs/src/mshv/vtl1_mem_layout.rs):
  `get_address_of_special_page` and heap/layout helpers use Trusted linker base
  plus fixed in-tree page indices; no guest-controlled index path found.

### Common LVBS (1 File)

- [litebox_common_lvbs/src/lib.rs](../../litebox_common_lvbs/src/lib.rs):
  `HekiRange::is_valid` enforces ordered 52-bit endpoints; its formatter has the
  API-only observation. `HekiPatch::is_valid` alignment subtraction is Bounded.
  `HekiPage::is_valid` validates counts/ranges before production iteration.
  `read_vtl0_contiguous` handles empty input, checks the physical end, and bounds
  page/offset calculations; `read_vtl0_val` uses fixed object size. ABI capacities
  and encoders use fixed constants/masks.

### LVBS Runner (2 Files)

- [litebox_runner_lvbs/src/lib.rs](../../litebox_runner_lvbs/src/lib.rs):
  `seed_initial_heap`/`init` use Trusted boot/linker layout, with
  extent/remaining-size checks. Dispatch forwards the BootAPs candidate;
  function-ID truncation is intentional. `optee_smc_handler_entry_inner` checks
  PFN multiplication. Session/open/invoke/close and normal-world message writers
  use message-size helpers whose `u32` counts cannot overflow `usize` arithmetic
  on x86-64; RPC physical offset addition is checked. Panic-code negation uses
  small enum values.
- [litebox_runner_lvbs/src/main.rs](../../litebox_runner_lvbs/src/main.rs):
  `apply_relocations` explicitly wraps and is excluded. `remap_to_high_canonical`
  uses Trusted boot memory, fixed page indices and kernel-offset mapping
  contracts. Startup/stack-switch assembly uses fixed offsets. `_start` narrows
  the Trusted boot CPU count under an explicit truncation annotation; no direct
  guest arithmetic finding established.

### SNP Runner (2 Files)

- [litebox_runner_snp/src/globals.rs](../../litebox_runner_snp/src/globals.rs):
  constants; no arithmetic functions.
- [litebox_runner_snp/src/main.rs](../../litebox_runner_snp/src/main.rs):
  `sandbox_kernel_init` divides Trusted CPU frequency; zero MHz is a backend
  invariant issue. `sandbox_process_init`/nested `parse_args` widen two 32-bit ABI
  lengths, so their sum fits x86-64; C-string progress is bounded by the 4024-byte
  source. Malformed lengths may fail bounds checks, but no arithmetic overflow
  was established. Other handlers use fixed masks or dispatch.

## Validation and Limitations

At the original audit, the worktree remained clean and HEAD unchanged. No source
edits, commits, builds, tests or hardware executions were performed during that
audit. The cheap checks above were proposed reproductions, not reported passes.
Those statements describe the original read-only audit, not the later dirty
worktree containing the `Instant` fix and other pre-existing changes.

The later `Instant` fix has regression-test evidence for 20 billion seconds and
`u64::MAX` ticks. Current-source inspection for this documentation task confirmed
that fix and its assertions, the unresolved `SystemTime` multiplication in both
branches, and the unresolved LVBS PFN `checked_shl` conversion. This documentation
task makes no code changes and does not rerun those tests.

No hardware-backed LVBS/SNP or other platform tests were performed. Trusted
hardware, backend and boot-layout assumptions remain assumptions, not validation
results. The inventory does not establish that all repository arithmetic is safe
or that every API-only candidate is reachable from an untrusted guest.