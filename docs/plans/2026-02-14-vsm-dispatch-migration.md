# VSM Dispatch Migration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Move `vsm_dispatch` and all 13 functions it calls from `litebox_platform_lvbs` to `litebox_runner_lvbs`.

**Architecture:** The VSM dispatch logic belongs in the runner (the entry point), not the platform crate. The moved code will use `litebox_platform_multiplex::platform()` instead of `crate::platform_low()`. All types (`Vtl0KernelInfo`, `ModuleMemoryMetadataMap`, etc.) stay in `litebox_platform_lvbs` and are accessed via `platform()`. `PhysConstPtr`/`PhysMutPtr` stay in `litebox_shim_optee` — they depend on `platform()` for `VmapManager` and shouldn't be in a low-level common crate.

**Tech Stack:** Rust, `#![no_std]`, Hyper-V VTL1 bare-metal kernel, x86_64

**Testing note:** `litebox_runner_lvbs` requires nightly + `-Z build-std` with custom target `x86_64_vtl1.json`. It cannot be built with standard `cargo build`. We verify correctness by ensuring the default workspace build (`cargo build`) still compiles, and by reviewing that the moved code is semantically identical.

---

## Overview of Tasks

1. Make types/functions in `litebox_platform_lvbs` public for cross-crate access
2. Move VSM dispatch functions to `litebox_runner_lvbs`
3. Clean up `litebox_platform_lvbs` (remove moved code)
4. Verify default workspace build compiles

---

### Task 1: Make types/functions in `litebox_platform_lvbs` public for cross-crate access

Before moving VSM functions out, we need to ensure everything they depend on is publicly accessible from `litebox_platform_lvbs`. Currently many items use `pub(crate)` visibility.

**Files:**
- Modify: `litebox_platform_lvbs/src/mshv/vsm.rs` — make `Vtl0KernelInfo` fields and methods public
- Modify: `litebox_platform_lvbs/src/mshv/mod.rs` — ensure types are re-exported
- Modify: `litebox_platform_lvbs/src/lib.rs` — ensure `vtl0_kernel_info` field is public

**Step 1: In `litebox_platform_lvbs/src/mshv/vsm.rs`**

Change `Vtl0KernelInfo` field and method visibilities to `pub`:
- Line 1061: `pub(crate) fn set_end_of_boot` → `pub fn set_end_of_boot`
- Line 1029: `module_memory_metadata` field → make `pub`
- Line 1030: `boot_done` field → keep private (accessed via methods)
- Line 1031: `system_certs` field → keep private (accessed via methods)
- Line 1032-1033: `kexec_metadata`, `crash_kexec_metadata` → make `pub`
- Line 1034: `precomputed_patches` → make `pub`
- Line 1035-1036: `symbols`, `gpl_symbols` → make `pub`

Also change visibility of methods/functions:
- Line 1308: `pub(crate) fn protect_physical_memory_range` → `pub fn protect_physical_memory_range`
- Line 1216: `pub(crate) fn register_module_memory_metadata` → `pub fn register_module_memory_metadata`
- Line 1232: `pub(crate) fn remove` → `pub fn remove`
- Line 1238: `pub(crate) fn get_patch_targets` → `pub fn get_patch_targets`
- Line 1530: `pub(crate) fn clear_memory` → `pub fn clear_memory`
- Line 1535: `pub(crate) fn register_memory` → `pub fn register_memory`
- Line 1559: `pub(crate) fn insert_heki_range` on `KexecMemoryMetadata` → `pub fn insert_heki_range`
- Line 1567: `pub(crate) fn insert_memory_range` on `KexecMemoryMetadata` → `pub fn insert_memory_range`
- Line 1571: `pub(crate) fn clear` → `pub fn clear`
- Line 1119: `pub(crate) fn insert_heki_range` on `ModuleMemoryMetadata` → `pub fn insert_heki_range`
- Line 1132: `pub(crate) fn insert_memory_range` on `ModuleMemoryMetadata` → `pub fn insert_memory_range`
- Line 1137: `pub(crate) fn insert_patch_target` on `ModuleMemoryMetadata` → `pub fn insert_patch_target`
- Line 1144: `pub(crate) fn get_patch_targets` on `ModuleMemoryMetadata` → `pub fn get_patch_targets`
- `MemoryContainer::extend_range` (line 1429): `pub(crate)` → `pub`
- `MemoryContainer::write_bytes_from_heki_range` (line 1451): `pub(crate)` → `pub`
- `MemoryContainer::write_vtl0_phys_bytes` (line 1469): `pub(crate)` → `pub`
- `ModuleMemory::write_bytes_from_heki_range` (line 1357): `pub(crate)` → `pub`
- `ModuleMemory::extend_range` (line 1364): `pub(crate)` → `pub`

Also make `vsm::init()` public:
- Line 70: `pub(crate) fn init()` → `pub fn init()`

Make the `copy_heki_pages_from_vtl0` function public (it's currently private `fn`):
- Line 1284: `fn copy_heki_pages_from_vtl0` → `pub fn copy_heki_pages_from_vtl0`

Make the `copy_heki_patch_from_vtl0` function public:
- Line 819: `fn copy_heki_patch_from_vtl0` → `pub fn copy_heki_patch_from_vtl0`

Make the `apply_vtl0_text_patch` function public:
- Line 870: `fn apply_vtl0_text_patch` → `pub fn apply_vtl0_text_patch`

Make the `parse_certs` function public:
- Line 311: `fn parse_certs` → `pub fn parse_certs`

Make the `save_vtl0_locked_regs` function public:
- Line 1009: `fn save_vtl0_locked_regs` → `pub fn save_vtl0_locked_regs`

Also make `AlignedPage`, `MODULE_VALIDATION_MAX_SIZE`, `CPU_ONLINE_MASK` accessible:
- Line 61-63: `struct AlignedPage` → `pub struct AlignedPage`
- Line 66: `const MODULE_VALIDATION_MAX_SIZE` → `pub const MODULE_VALIDATION_MAX_SIZE`
- Line 68: `static CPU_ONLINE_MASK` → `pub static CPU_ONLINE_MASK`

**Step 2: Ensure module re-exports**

In `litebox_platform_lvbs/src/mshv/mod.rs`, ensure `pub mod vsm;` exists. The items need to be accessible as `litebox_platform_lvbs::mshv::vsm::*`.

Also ensure the following are publicly accessible from `litebox_platform_lvbs`:
- `mshv::heki::*` types
- `mshv::error::VsmError`
- `mshv::hvcall::HypervCallError`
- `mshv::hvcall_mm::hv_modify_vtl_protection_mask`
- `mshv::hvcall_vp::*`
- `mshv::mem_integrity::*`
- `mshv::ringbuffer::set_ringbuffer`
- `mshv::vtl_switch::mshv_vsm_get_code_page_offsets`
- `mshv::vtl1_mem_layout::{PAGE_SHIFT, PAGE_SIZE}`
- `host::bootparam::get_vtl1_memory_info`
- `host::per_cpu_variables::with_per_cpu_variables_mut`
- `host::linux::{CpuMask, KEXEC_SEGMENT_MAX, Kimage}`
- `arch::get_core_id`

Also in `litebox_platform_lvbs/src/lib.rs`, make `vtl0_kernel_info` field accessible:
- The `LinuxKernel` struct has `pub vtl0_kernel_info: Vtl0KernelInfo` — verify this is already `pub`.

Check each of these module declarations for `pub` visibility and update if needed.

**Step 3: Verify build**

Run: `cargo build -p litebox_platform_lvbs`
Expected: SUCCESS (possibly with warnings about unused pub items — that's fine)

**Step 4: Commit**

```bash
git add litebox_platform_lvbs/
git commit -m "refactor: make VSM types and helpers public for cross-crate access"
```

---

### Task 2: Move VSM dispatch functions to `litebox_runner_lvbs`

Move `vsm_dispatch` and all 13 functions it calls to a new `vsm.rs` module in `litebox_runner_lvbs`. Also move the helper functions `copy_heki_pages_from_vtl0`, `copy_heki_patch_from_vtl0`, `apply_vtl0_text_patch`, `parse_certs`, `save_vtl0_locked_regs`, and `protect_physical_memory_range`.

**Files:**
- Create: `litebox_runner_lvbs/src/vsm.rs` — new module with moved functions
- Modify: `litebox_runner_lvbs/src/lib.rs` — add `mod vsm;`, update `vtlcall_dispatch` to call `vsm::vsm_dispatch`
- Modify: `litebox_runner_lvbs/Cargo.toml` — add new dependencies

**Step 1: Update `litebox_runner_lvbs/Cargo.toml`**

Add these dependencies that the moved VSM code needs:
```toml
thiserror = { version = "2.0.6", default-features = false }
zerocopy = { version = "0.8", default-features = false, features = ["derive"] }
x509-cert = { version = "0.2.5", default-features = false }
```

Verify these already exist (they should):
- `litebox_platform_lvbs` (yes, line 8)
- `litebox_platform_multiplex` (yes, line 9)
- `x86_64` (yes, line 20)
- `hashbrown` (yes, line 14)
- `spin` (yes, line 13)
- `once_cell` (yes, line 15)

**Step 2: Create `litebox_runner_lvbs/src/vsm.rs`**

This file contains the moved functions. The key changes from the original:
- Replace all `crate::platform_low()` with `litebox_platform_multiplex::platform()`
- Replace `crate::` internal module paths with full crate paths:
  - `crate::mshv::*` → `litebox_platform_lvbs::mshv::*`
  - `crate::arch::get_core_id` → `litebox_platform_lvbs::arch::get_core_id`
  - `crate::host::*` → `litebox_platform_lvbs::host::*`
  - `crate::debug_serial_print!`/`crate::debug_serial_println!` → `litebox_platform_lvbs::debug_serial_print!`/`litebox_platform_lvbs::debug_serial_println!`

The file structure:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VSM functions — dispatcher and all VSM service handlers.
//!
//! These functions were migrated from `litebox_platform_lvbs::mshv::vsm`
//! to the runner crate where dispatch logic belongs.

#[cfg(debug_assertions)]
use litebox_platform_lvbs::mshv::mem_integrity::parse_modinfo;
use litebox_platform_lvbs::mshv::ringbuffer::set_ringbuffer;
use litebox_platform_lvbs::{
    arch::get_core_id,
    debug_serial_print, debug_serial_println,
    host::{
        bootparam::get_vtl1_memory_info,
        linux::{CpuMask, KEXEC_SEGMENT_MAX, Kimage},
        per_cpu_variables::with_per_cpu_variables_mut,
    },
    mshv::{
        HV_REGISTER_CR_INTERCEPT_CONTROL, HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        HV_REGISTER_CR_INTERCEPT_CR4_MASK, HV_REGISTER_VSM_PARTITION_CONFIG,
        HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, HV_SECURE_VTL_BOOT_TOKEN,
        HV_X64_REGISTER_APIC_BASE, HV_X64_REGISTER_CR0, HV_X64_REGISTER_CR4,
        HV_X64_REGISTER_CSTAR, HV_X64_REGISTER_EFER, HV_X64_REGISTER_LSTAR,
        HV_X64_REGISTER_SFMASK, HV_X64_REGISTER_STAR, HV_X64_REGISTER_SYSENTER_CS,
        HV_X64_REGISTER_SYSENTER_EIP, HV_X64_REGISTER_SYSENTER_ESP,
        HvCrInterceptControlFlags, HvPageProtFlags, HvRegisterVsmPartitionConfig,
        HvRegisterVsmVpSecureVtlConfig, VsmFunction, X86Cr0Flags, X86Cr4Flags,
        error::VsmError,
        heki::{
            HekiKdataType, HekiKernelInfo, HekiKernelSymbol, HekiKexecType, HekiPage, HekiPatch,
            HekiPatchInfo, HekiRange, MemAttr, ModMemType, mem_attr_to_hv_page_prot_flags,
            mod_mem_type_to_mem_attr,
        },
        hvcall::HypervCallError,
        hvcall_mm::hv_modify_vtl_protection_mask,
        hvcall_vp::{hvcall_get_vp_vtl0_registers, hvcall_set_vp_registers, init_vtl_ap},
        mem_integrity::{
            validate_kernel_module_against_elf, validate_text_patch,
            verify_kernel_module_signature, verify_kernel_pe_signature,
        },
        vtl1_mem_layout::{PAGE_SHIFT, PAGE_SIZE},
        vsm::{
            AlignedPage, ControlRegMap, CPU_ONLINE_MASK, KexecMemoryMetadata,
            KexecMemoryRange, MemoryContainer, ModuleMemory, ModuleMemoryMetadata,
            MODULE_VALIDATION_MAX_SIZE, NUM_CONTROL_REGS,
        },
    },
};
use litebox_platform_multiplex::platform;
use alloc::{boxed::Box, ffi::CString, string::String, vec::Vec};
use core::{
    mem,
    sync::atomic::{AtomicBool, AtomicI64, Ordering},
};
use litebox::utils::TruncateExt;
use litebox_common_linux::errno::Errno;
use spin::Once;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{PageSize, PhysFrame, Size4KiB, frame::PhysFrameRange},
};
use x509_cert::{Certificate, der::Decode};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

// Then paste the function bodies, replacing:
// - `crate::platform_low()` → `platform()`
// - `crate::platform_low().vtl0_kernel_info` → `platform().vtl0_kernel_info`
// - `crate::platform_low().copy_from_vtl0_phys::<T>(addr)` → `platform().copy_from_vtl0_phys::<T>(addr)`
// - etc.
```

The following functions are moved (copy body exactly, only changing `crate::platform_low()` → `platform()`):
1. `init()` (line 70-104)
2. `mshv_vsm_enable_aps` (line 109-112)
3. `mshv_vsm_boot_aps` (line 117-173)
4. `mshv_vsm_secure_config_vtl0` (line 176-187)
5. `mshv_vsm_configure_partition` (line 190-201)
6. `mshv_vsm_lock_regs` (line 204-247)
7. `mshv_vsm_end_of_boot` (line 250-254)
8. `mshv_vsm_protect_memory` (line 258-309)
9. `parse_certs` (line 311-332)
10. `mshv_vsm_load_kdata` (line 336-458)
11. `mshv_vsm_validate_guest_module` (line 466-580)
12. `mshv_vsm_free_guest_module_init` (line 586-624)
13. `mshv_vsm_unload_guest_module` (line 628-669)
14. `mshv_vsm_copy_secondary_key` (line 673-677)
15. `mshv_vsm_kexec_validate` (line 683-795)
16. `mshv_vsm_patch_text` (line 800-815)
17. `copy_heki_patch_from_vtl0` (line 819-866)
18. `apply_vtl0_text_patch` (line 870-903)
19. `mshv_vsm_allocate_ringbuffer_memory` (line 905-916)
20. `vsm_dispatch` (line 919-947)
21. `save_vtl0_locked_regs` (line 1009-1023)
22. `copy_heki_pages_from_vtl0` (line 1284-1302)
23. `protect_physical_memory_range` (line 1308-1319)

**Step 3: Update `litebox_runner_lvbs/src/lib.rs`**

Add `mod vsm;` near the top.

Change the import of `vsm_dispatch` in `vtlcall_dispatch` (around line 155):
```rust
// Before:
_ => vsm_dispatch(func_id, &params[1..]),
// After:
_ => vsm::vsm_dispatch(func_id, &params[1..]),
```

Also update the VSM init call. Currently in `lib.rs` there should be a call to `litebox_platform_lvbs::mshv::vsm::init()`. Change it to `vsm::init()`.

Remove the old `use litebox_platform_lvbs::mshv::vsm::vsm_dispatch;` import if it exists.

**Step 4: Commit**

```bash
git add litebox_runner_lvbs/
git commit -m "feat: move vsm_dispatch and all VSM functions to litebox_runner_lvbs"
```

---

### Task 3: Clean up `litebox_platform_lvbs` — remove moved functions

Remove the functions that were moved to `litebox_runner_lvbs` from `litebox_platform_lvbs/src/mshv/vsm.rs`. Keep all types and data structures that stay.

**Files:**
- Modify: `litebox_platform_lvbs/src/mshv/vsm.rs`

**Step 1: Remove moved functions from vsm.rs**

Remove these functions (they now live in `litebox_runner_lvbs/src/vsm.rs`):
- `init()` (lines 70-104)
- `mshv_vsm_enable_aps` (lines 109-112)
- `mshv_vsm_boot_aps` (lines 117-173)
- `mshv_vsm_secure_config_vtl0` (lines 176-187)
- `mshv_vsm_configure_partition` (lines 190-201)
- `mshv_vsm_lock_regs` (lines 204-247)
- `mshv_vsm_end_of_boot` (lines 250-254)
- `mshv_vsm_protect_memory` (lines 258-309)
- `parse_certs` (lines 311-332)
- `mshv_vsm_load_kdata` (lines 336-458)
- `mshv_vsm_validate_guest_module` (lines 466-580)
- `mshv_vsm_free_guest_module_init` (lines 586-624)
- `mshv_vsm_unload_guest_module` (lines 628-669)
- `mshv_vsm_copy_secondary_key` (lines 673-677)
- `mshv_vsm_kexec_validate` (lines 683-795)
- `mshv_vsm_patch_text` (lines 800-815)
- `copy_heki_patch_from_vtl0` (lines 819-866)
- `apply_vtl0_text_patch` (lines 870-903)
- `mshv_vsm_allocate_ringbuffer_memory` (lines 905-916)
- `vsm_dispatch` (lines 919-947)
- `save_vtl0_locked_regs` (lines 1009-1023)
- `copy_heki_pages_from_vtl0` (lines 1284-1302)
- `protect_physical_memory_range` (lines 1308-1319)

**Keep** in `vsm.rs`:
- `use` statements still needed by remaining types
- `AlignedPage` struct (line 61-63)
- `MODULE_VALIDATION_MAX_SIZE` const (line 66)
- `CPU_ONLINE_MASK` static (line 68)
- `NUM_CONTROL_REGS` const (line 949)
- `ControlRegMap` struct + impl (lines 954-1006)
- `Vtl0KernelInfo` struct + impl (lines 1028-1097)
- `ModuleMemoryMetadataMap` + related types (lines 1100-1280)
- `ModuleMemory` + `MemoryContainer` + `MemoryContainerError` (lines 1321-1511)
- `KexecMemoryMetadataWrapper` + `KexecMemoryMetadata` + related types (lines 1513-1632)
- `PatchDataMap` + `PatchDataMapError` (lines 1634-1757)
- `Symbol` + `SymbolTable` (lines 1760-1871)

**Step 2: Clean up unused imports**

Remove imports that are no longer needed after removing the functions. The remaining types only need a subset of the original imports.

**Step 3: Verify build**

Run: `cargo build -p litebox_platform_lvbs`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add litebox_platform_lvbs/
git commit -m "refactor: remove migrated VSM dispatch functions from litebox_platform_lvbs"
```

---

### Task 4: Verify full default workspace build

**Step 1: Run full build**

Run: `cargo build`
Expected: SUCCESS for all default workspace members

**Step 2: Run clippy**

Run: `cargo clippy`
Expected: No new errors (warnings are acceptable for now)

**Step 3: Final commit if any fixups needed**

```bash
git add -A
git commit -m "fix: resolve build issues from VSM dispatch migration"
```

---

## Dependency Summary

After migration:
```
litebox_runner_lvbs → litebox_platform_lvbs (types, VsmFunction, Vtl0KernelInfo, helpers)
                    → litebox_platform_multiplex (platform() accessor)
                    → litebox_shim_optee (NormalWorldConstPtr/NormalWorldMutPtr)
                    → litebox_common_linux, litebox_common_optee, litebox

litebox_shim_optee  → litebox_platform_multiplex (for PhysConstPtr/PhysMutPtr VmapManager)
                    → litebox_common_linux, etc. (unchanged)
```

## Risk Notes

1. **Cannot test runner build directly** — `litebox_runner_lvbs` requires nightly + custom target. We verify by ensuring default workspace build succeeds and by code review of the moved functions.
2. **`platform_low()` vs `platform()`** — These should be equivalent at runtime since `platform_low()` returns the same static reference that `platform()` returns (both initialized from `LinuxKernel::init()`). The key difference is `platform_low()` is crate-internal while `platform()` is the cross-crate accessor.
3. **Visibility changes** — Making items `pub` that were `pub(crate)` doesn't break anything but does expand the API surface. This is intentional for cross-crate access.

## Future Work (not in this PR)

- Replace `copy_from/to_vtl0_phys` calls with `PhysConstPtr`/`PhysMutPtr` abstractions in the moved code
- Consider moving `PhysConstPtr`/`PhysMutPtr` to a common crate once their `VmapManager` dependency is decoupled from `platform()`
