# mem_integrity.rs Migration Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Move `mem_integrity.rs` from `litebox_platform_lvbs` to `litebox_runner_lvbs`, resolving the `ModuleMemory` type mismatch created by the Vtl0KernelInfo migration.

**Architecture:** The file moves as a new module `litebox_runner_lvbs/src/mem_integrity.rs`. Data-only types it depends on (`ModuleSignature`, `__be32`, `PkeyIdType`) move to `litebox_common_lvbs::linux`. `KernelElfError` moves to `litebox_common_lvbs::error`. The 10 crypto/ELF dependencies are added to the runner's `Cargo.toml`. After the move, the platform's `mem_integrity` module and its duplicate `ModuleMemory`/`MemoryContainer` types are removed (Phase 4 Task 7 cleanup).

**Tech Stack:** Rust, no_std, crypto crates (authenticode, cms, rsa, sha2), ELF parsing (elf, object)

---

### Task 1: Move `ModuleSignature`, `__be32`, and `PkeyIdType` to `litebox_common_lvbs::linux`

**Files:**
- Modify: `litebox_common_lvbs/src/linux.rs` — add the three types
- Modify: `litebox_platform_lvbs/src/host/linux.rs` — remove the three types, import from common
- Modify: `litebox_common_lvbs/Cargo.toml` — no changes needed (already has `zerocopy`)

**Step 1: Add types to `litebox_common_lvbs/src/linux.rs`**

Add the following after the `ListHead` definition:

```rust
#[allow(non_camel_case_types)]
pub type __be32 = u32;

#[repr(u8)]
pub enum PkeyIdType {
    PkeyIdPgp = 0,
    PkeyIdX509 = 1,
    PkeyIdPkcs7 = 2,
}

/// `module_signature` from [Linux](https://elixir.bootlin.com/linux/v6.6.85/source/include/linux/module_signature.h#L33)
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct ModuleSignature {
    pub algo: u8,
    pub hash: u8,
    pub id_type: u8,
    pub signer_len: u8,
    pub key_id_len: u8,
    _pad: [u8; 3],
    sig_len: __be32,
}

impl ModuleSignature {
    pub fn sig_len(&self) -> u32 {
        u32::from_be(self.sig_len)
    }

    /// Currently, Linux kernel only supports PKCS#7 signatures for module signing and thus `id_type` is always `PkeyIdType::PkeyIdPkcs7`.
    /// Other fields except for `sig_len` are set to zero.
    pub fn is_valid(&self) -> bool {
        self.sig_len() > 0
            && self.algo == 0
            && self.hash == 0
            && self.id_type == PkeyIdType::PkeyIdPkcs7 as u8
            && self.signer_len == 0
            && self.key_id_len == 0
    }
}
```

**Step 2: Update `litebox_platform_lvbs/src/host/linux.rs`**

Replace the local definitions of `__be32`, `PkeyIdType`, and `ModuleSignature` (lines 95-133) with re-exports:

```rust
pub use litebox_common_lvbs::linux::{ModuleSignature, PkeyIdType, __be32};
```

This preserves backward compatibility for any platform-internal imports of `crate::host::linux::ModuleSignature`.

**Step 3: Verify build**

Run: `cargo build`
Expected: Success — all existing platform consumers see `ModuleSignature` at the same path.

**Step 4: Commit**

```
Move ModuleSignature, __be32, PkeyIdType to litebox_common_lvbs::linux
```

---

### Task 2: Move `KernelElfError` to `litebox_common_lvbs::error`

**Files:**
- Modify: `litebox_common_lvbs/src/error.rs` — add `KernelElfError` enum
- Modify: `litebox_common_lvbs/Cargo.toml` — no changes needed (already has `thiserror`)

**Step 1: Add `KernelElfError` to `litebox_common_lvbs/src/error.rs`**

Add at the end of the file:

```rust
/// Errors for kernel ELF validation and relocation.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum KernelElfError {
    #[error("failed to parse ELF file")]
    ElfParseFailed,
    #[error("required section not found")]
    SectionNotFound,
}
```

**Step 2: Verify build**

Run: `cargo build`
Expected: Success.

**Step 3: Commit**

```
Add KernelElfError to litebox_common_lvbs::error
```

---

### Task 3: Add 10 new dependencies to runner's `Cargo.toml`

**Files:**
- Modify: `litebox_runner_lvbs/Cargo.toml` — add dependencies

**Step 1: Add dependencies**

Add the following to the `[dependencies]` section of `litebox_runner_lvbs/Cargo.toml`:

```toml
authenticode = { version = "0.4.3", default-features = false, features = ["object"] }
cms = { version = "0.2.3", default-features = false, features = ["alloc"] }
const-oid = { version = "0.9.6", default-features = false, features = ["db"] }
digest = { version = "0.10.7", default-features = false }
elf = { version = "0.8.0", default-features = false }
object = { version = "0.36.7", default-features = false, features = ["pe"] }
rangemap = { version = "1.5.1", features = ["const_fn"] }
rsa = { version = "0.9.10", default-features = false }
sha2 = { version = "0.10.9", default-features = false, features = ["oid"] }
thiserror = { version = "2.0.6", default-features = false }
```

**Step 2: Verify build**

Run: `cargo build`
Expected: Success — dependencies are added but not yet used.

**Step 3: Commit**

```
Add crypto and ELF dependencies to litebox_runner_lvbs for mem_integrity migration
```

---

### Task 4: Create `litebox_runner_lvbs/src/mem_integrity.rs` with migrated content

This is the main migration task. The file is copied from `litebox_platform_lvbs/src/mshv/mem_integrity.rs` with import adjustments.

**Files:**
- Create: `litebox_runner_lvbs/src/mem_integrity.rs` — the migrated module
- Modify: `litebox_runner_lvbs/src/lib.rs` — add `mod mem_integrity;`
- Modify: `litebox_runner_lvbs/src/vsm.rs` — replace platform imports with local imports

**Step 1: Create `litebox_runner_lvbs/src/mem_integrity.rs`**

Copy the entire content of `litebox_platform_lvbs/src/mshv/mem_integrity.rs` with these import changes:

1. Replace the crate-internal import block (lines 6-12):
   ```rust
   // OLD:
   use crate::{
       debug_serial_println,
       host::linux::ModuleSignature,
       mshv::vsm::ModuleMemory,
   };
   ```
   With:
   ```rust
   use crate::vsm::ModuleMemory;
   use litebox_common_lvbs::linux::ModuleSignature;
   use litebox_platform_lvbs::{debug_serial_println};
   ```

2. Replace line 31 `pub use litebox_common_lvbs::error::VerificationError;` with:
   ```rust
   use litebox_common_lvbs::error::{KernelElfError, VerificationError};
   ```

3. Remove the `KernelElfError` definition at lines 668-676 (it now lives in `litebox_common_lvbs::error`).

4. Remove `use thiserror::Error;` (line 35) since `KernelElfError` is no longer defined here.

5. All public functions (`validate_kernel_module_against_elf`, `verify_kernel_module_signature`, `verify_kernel_pe_signature`, `validate_text_poke_bp_batch`, `validate_text_patch`, `parse_modinfo`) keep their signatures unchanged. Make them `pub(crate)` since they're only used within the runner.

6. Change `pub fn parse_modinfo` to `pub(crate) fn parse_modinfo` (it's only called from `vsm.rs`).

**Step 2: Add module declaration to `litebox_runner_lvbs/src/lib.rs`**

Add `mod mem_integrity;` after the existing `mod vsm;` line.

**Step 3: Update imports in `litebox_runner_lvbs/src/vsm.rs`**

Remove the `mem_integrity` imports from the platform import block (lines 39-40 and 53-56):

```rust
// REMOVE these lines:
#[cfg(debug_assertions)]
use litebox_platform_lvbs::mshv::mem_integrity::parse_modinfo;

// REMOVE from the platform import block:
        mem_integrity::{
            validate_kernel_module_against_elf, validate_text_patch,
            verify_kernel_module_signature, verify_kernel_pe_signature,
        },
```

Replace with imports from the local module:

```rust
#[cfg(debug_assertions)]
use crate::mem_integrity::parse_modinfo;
use crate::mem_integrity::{
    validate_kernel_module_against_elf, validate_text_patch,
    verify_kernel_module_signature, verify_kernel_pe_signature,
};
```

**Step 4: Verify build**

Run: `cargo build`
Expected: Success. The runner now uses its own `mem_integrity` module with the runner's local `ModuleMemory` type.

Run: `cargo clippy`
Expected: No new warnings.

**Step 5: Commit**

```
Move mem_integrity.rs from litebox_platform_lvbs to litebox_runner_lvbs

All consumers (validate_kernel_module_against_elf, verify_kernel_module_signature,
verify_kernel_pe_signature, validate_text_patch, parse_modinfo) are in the runner.
This resolves the ModuleMemory type mismatch from the Vtl0KernelInfo migration.
```

---

### Task 5: Remove `mem_integrity.rs` from platform + Phase 4 Task 7 cleanup

Now that `mem_integrity.rs` is in the runner, clean up the platform:

1. Delete `litebox_platform_lvbs/src/mshv/mem_integrity.rs`
2. Remove `pub mod mem_integrity;` from `litebox_platform_lvbs/src/mshv/mod.rs` (line 10)
3. Remove the duplicate `ModuleMemory`, `MemoryContainer`, `Vtl0KernelInfo`, `ModuleMemoryMetadataMap`, `KexecMemoryMetadataWrapper`, `PatchDataMap`, `SymbolTable`, and related types from `litebox_platform_lvbs/src/mshv/vsm.rs` — these are the types moved to the runner in Phase 4 Task 6
4. Remove `vtl0_kernel_info: Vtl0KernelInfo` field from `LinuxKernel` struct in `litebox_platform_lvbs/src/lib.rs`
5. Remove re-exports from `litebox_platform_lvbs/src/mshv/vsm.rs` and `litebox_platform_lvbs/src/mshv/mod.rs` that are no longer needed
6. Remove any now-unused imports and dependencies from `litebox_platform_lvbs/Cargo.toml` (only if ALL consumers of a dependency were in `mem_integrity.rs` — check carefully)

**Files:**
- Delete: `litebox_platform_lvbs/src/mshv/mem_integrity.rs`
- Modify: `litebox_platform_lvbs/src/mshv/mod.rs` — remove `pub mod mem_integrity;`
- Modify: `litebox_platform_lvbs/src/mshv/vsm.rs` — remove moved types
- Modify: `litebox_platform_lvbs/src/lib.rs` — remove `vtl0_kernel_info` from `LinuxKernel`
- Possibly modify: `litebox_platform_lvbs/Cargo.toml` — remove unused deps
- Possibly modify: `litebox_platform_lvbs/src/host/linux.rs` — remove re-exports if no longer needed

**IMPORTANT:** This task requires careful analysis of which types and dependencies are still used by the platform. The implementer MUST:
- Search for usages of each type being removed before removing it
- Check each dependency in `Cargo.toml` for other users in the platform before removing it
- Build and run clippy after each removal to catch issues early

**Step 1: Delete `mem_integrity.rs` and remove module declaration**

Delete the file and remove `pub mod mem_integrity;` from `litebox_platform_lvbs/src/mshv/mod.rs`.

**Step 2: Remove moved types from `litebox_platform_lvbs/src/mshv/vsm.rs`**

Remove: `Vtl0KernelInfo`, `MemoryContainer`, `ModuleMemory`, `ModuleMemoryMetadataMap`, `KexecMemoryMetadataWrapper`, `PatchDataMap`, `SymbolTable`, and all iterator types that were moved to the runner in Phase 4 Task 6. Keep `CPU_ONLINE_MASK` and any other types still used by the platform.

**Step 3: Remove `vtl0_kernel_info` from `LinuxKernel`**

In `litebox_platform_lvbs/src/lib.rs`, remove:
- The `vtl0_kernel_info: Vtl0KernelInfo` field from `LinuxKernel` struct
- Its initialization in `LinuxKernel::new()`
- Any related imports

**Step 4: Clean up unused re-exports and imports**

Check `litebox_platform_lvbs/src/mshv/mod.rs` for re-exports that are no longer needed. Check `litebox_platform_lvbs/src/mshv/vsm.rs` for re-exports of common types that are no longer needed.

**Step 5: Clean up platform dependencies**

Check which of these deps from `litebox_platform_lvbs/Cargo.toml` are ONLY used by `mem_integrity.rs`:
- `authenticode` — likely only in `mem_integrity.rs`
- `cms` — likely only in `mem_integrity.rs`
- `const-oid` — likely only in `mem_integrity.rs`
- `elf` — likely only in `mem_integrity.rs`
- `object` — likely only in `mem_integrity.rs`
- `rsa` — likely only in `mem_integrity.rs`
- `sha2` — might be used elsewhere (check)
- `digest` — might be used elsewhere (check)
- `sha1` — check if still used
- `rangemap` — check if still used elsewhere

The implementer MUST grep for each dependency's usage before removing.

**Step 6: Verify build**

Run: `cargo build`
Run: `cargo clippy`
Run: `cargo test`
Expected: All pass (except pre-existing `litebox_runner_linux_userland` failures).

**Step 7: Commit**

```
Remove mem_integrity.rs from platform and clean up moved Vtl0KernelInfo types

Complete Phase 4 Task 7: remove Vtl0KernelInfo, ModuleMemory, MemoryContainer,
and related types from litebox_platform_lvbs now that they live in the runner.
Remove unused crypto/ELF dependencies from platform Cargo.toml.
```

---

### Task 6: Final verification (Phase 4 Task 8)

**Step 1: Full build verification**

```
cargo build
cargo clippy
cargo test
```

**Step 2: Verify no cross-crate type mismatches**

Grep for any remaining references to `litebox_platform_lvbs::mshv::mem_integrity` — should return zero matches.
Grep for any remaining references to `litebox_platform_lvbs::mshv::vsm::ModuleMemory` — should return zero matches.
Grep for any remaining references to `litebox_platform_lvbs::mshv::vsm::Vtl0KernelInfo` — should return zero matches.

**Step 3: Review import cleanliness**

Check that the runner imports `mem_integrity` functions from `crate::mem_integrity`, not from platform.
Check that no platform code imports from `mem_integrity`.

**Step 4: Commit (if any fixes needed)**

```
Final verification cleanup for mem_integrity and Vtl0KernelInfo migration
```
