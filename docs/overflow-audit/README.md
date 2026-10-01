# Arithmetic Overflow Audit

## Scope

Source review performed on the independent `weiteng/overflow-hardening` worktree,
starting at `0f601e960`, not the separate page-manager branch. The review covers
all 201 repository Rust files across 22 crate directories, including build
scripts, tests, inactive platform code, and assembly in those files. Source files
were read completely; the ledgers name arithmetic-bearing functions and record
caller bounds, trusted assumptions, and candidates. External dependency internals,
generated build output, Python scripts, and hardware execution are outside scope.

Explicit `trunc`, `wrapping_*`, and `saturating_*` operations are intentional and
were not changed or reported as defects. A source audit is not a mathematical
proof that every possible overflow has been eliminated.

| Ledger | Rust Files | Coverage |
| --- | ---: | --- |
| [Linux syscall and common code](linux.md) | 35 | Function inventory and syscall/ELF caller checks |
| [Core library](core.md) | 59 | Filesystem, networking, pointers, memory, synchronization |
| [Platform code](platforms.md) | 56 | Windows, Linux, LVBS, SNP and privileged callers |
| [Remaining crates](remaining-crates.md) | 51 | OP-TEE, HEKI, rewriter, runners, packaging, tools |

## Fixed During This Pass

These changes are currently uncommitted; the detailed ledgers distinguish the
reviewed base from later fixes. No explicit intentional arithmetic was changed.

| Function | Finding and Resolution |
| --- | --- |
| `Vmem::resize_mapping` | Guest-controlled remap growth could overflow into the shrink branch and remove preceding pages. Checked new extent returns `OutOfMemory` before mutation. |
| `VmemManager::remap_pages` | Guest old-address plus old-size sum could panic before range validation. Checked extent returns the existing invalid-range error. |
| `NonZeroPageSize::add`, `Vmem::create_mapping` | File-backed mmap length plus 16 MiB slack could overflow; merely checking addition still left an unwrap panic. Addition and error propagation now reject the request. |
| `Task::do_syscall`, affinity arm | Raw guest length multiplied by eight could overflow. Validation compares actual mask byte length instead. |
| `wake_robust_list` | Guest futex offsets could overflow entry/pending address sums. Checked signed addition rejects invalid extents while preserving legitimate negative ABI offsets. |
| Windows `Instant::checked_duration_since` | Guest timeout accepted in 100ns ticks could overflow conversion to total nanoseconds. Seconds plus bounded remainder avoids the intermediate overflow. |

## Unmodified Findings and Candidates

These remain open. They are not all ordinary guest arithmetic vulnerabilities,
and none should be described as demonstrated arbitrary memory corruption.

| Function | Provenance, Consequence, and Qualification |
| --- | --- |
| LVBS `LvbsVtl1Gate::boot_aps` | VTL0 PFN `(1 << 52) | 1` passes `checked_shl(12)` as low address `0x1000`: shift-count checking does not check lost value bits. Source-verified alias; hardware reproduction not run. |
| OP-TEE `TeeObjMap::allocate`, `TeeCrypStateMap::allocate` | Plain 32-bit maximum-handle increments can panic or return reserved zero after roughly 2^32 allocate/free cycles with few live objects. Boundary regression and fallible exhaustion handling remain needed. |
| HEKI `validate_kernel_module_against_elf` section loading | An accepted malformed signed ELF can request section capacity above `isize::MAX` before file-extent validation. Conditional capacity panic; signature acceptance is a prerequisite. |
| Linux `ElfFile::read_at` | A cooperating 9P server can return bytes at an ELF-requested `u64::MAX` file offset, causing unchecked cursor accumulation to panic or wrap. Honest local EOF backends do not provide this trigger. |
| `LocalPortAllocator::allocate_same_local_port` | Checked 16-bit reference increment is unwrapped at 65,535 tokens. Accept-path exhaustion is conditional on retaining tens of thousands of sockets and sufficient memory. |
| Socket-channel RX accounting | Data/packet publication precedes atomic count increments; a concurrent consumer can temporarily underflow accounting. Readiness race candidate, not demonstrated out-of-bounds access. |
| OP-TEE `TaHandleMap::insert` | Atomic 32-bit counter wraps by definition; lifetime exhaustion can collide with retained handles. Not a plain arithmetic-panic site; collision handling remains open. |
| Windows `SystemTime::duration_since` | Total-nanoseconds intermediate can overflow for synthetic host-clock differences beyond about 585 years. Private host values, not the confirmed guest timeout path. |
| Platform timer signal-mask helpers | Signal type permits 1-64, while 32-bit masks cannot shift signals 33-64 safely. Only fixed SIGALRM production callers were found; public-platform API gap. |
| `VmemManager::get_memory_permissions` | Public API adds start and length unchecked. Sole production OP-TEE caller prechecks the sum, so direct guest reachability was not established. |

Other public-constructor, trusted-boot, and impractical lifetime-counter concerns
are recorded with their bounds in the ledgers. HEKI debug `parse_modinfo` bounds
checking and deferred ELF patch-state failure handling are separate non-overflow
concerns; this audit does not resolve them.

## Validation

- Strict Clippy passed for `litebox`, `litebox_common_linux`,
  `litebox_shim_linux`, and `litebox_platform_windows_userland`, using
  `--all-targets --all-features -- -D warnings`.
- Native serial suites: 206 unit tests and four doctests passed. Twenty-three
  9P tests requiring unavailable `diod` were excluded; three doctests remained
  intentionally ignored.
- Focused regressions cover remap old/new extent errors and neighboring mapping
  preservation, huge file-backed mmap followed by successful ordinary mmap,
  raw affinity syscall dispatch, signed robust futex offsets and pending cleanup,
  and Windows full-width tick differences.
- Remap preservation also passed with `profile.test.overflow-checks=false`.
  Full release tests were blocked by an existing debug-only `run_test_thread`
  support mismatch; the test-profile check exercises unchecked arithmetic, not
  the complete optimized release configuration.
- No LVBS/SNP hardware execution, 32-bit validation, or runtime reproduction of
  the unmodified candidates was performed.