# Phase 4: Migrate Vtl0KernelInfo to the Runner — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Move `Vtl0KernelInfo` out of `LinuxKernel` (platform) into `litebox_runner_lvbs` as a standalone global variable, moving all supporting data-only types to `litebox_common_lvbs`.

**Architecture:** Data-only types (ListHead, HekiPatchInfo, HekiPatchType, MemoryRange, MemoryContainerError, PatchDataMapError, Symbol, ControlRegMap, NUM_CONTROL_REGS, HV_X64_REGISTER_* constants) move to `litebox_common_lvbs`. Logic types (Vtl0KernelInfo, MemoryContainer, ModuleMemoryMetadataMap, ModuleMemory, KexecMemoryMetadataWrapper, PatchDataMap, SymbolTable, etc.) move to `litebox_runner_lvbs`. Platform re-exports moved types and removes `vtl0_kernel_info` field from `LinuxKernel`.

**Tech Stack:** Rust no_std, litebox_common_lvbs, litebox_runner_lvbs, litebox_platform_lvbs, NormalWorldConstPtr

**Design doc:** `docs/plans/2026-02-14-vtl0-kernel-info-migration-design.md`

---

### Task 1: Move `ListHead` to `litebox_common_lvbs`

**Files:**
- Modify: `litebox_common_lvbs/src/lib.rs`
- Create: `litebox_common_lvbs/src/linux.rs`
- Modify: `litebox_platform_lvbs/src/host/linux.rs:168-175` (remove `ListHead`, add re-export)

**Step 1: Create `litebox_common_lvbs/src/linux.rs` with `ListHead`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux kernel ABI types shared between platform and runner crates.

use zerocopy::{FromBytes, IntoBytes, Immutable, KnownLayout};

/// `list_head` from [Linux](https://elixir.bootlin.com/linux/v6.6.85/source/include/linux/types.h#L190)
/// Pointer fields stored as u64 since we don't dereference them.
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ListHead {
    pub next: u64,
    pub prev: u64,
}
```

**Step 2: Add `pub mod linux;` to `litebox_common_lvbs/src/lib.rs`**

**Step 3: Update `litebox_platform_lvbs/src/host/linux.rs`**

Remove the `ListHead` definition (lines 168-175) and replace with:
```rust
pub use litebox_common_lvbs::linux::ListHead;
```

**Step 4: Build and verify**

Run: `cargo build`
Expected: PASS — `ListHead` is re-exported from same location, no consumer changes needed.

**Step 5: Commit**
```
git commit -m "Move ListHead to litebox_common_lvbs"
```

---

### Task 2: Move `HekiPatchInfo` and `HekiPatchType` to `litebox_common_lvbs`

**Files:**
- Modify: `litebox_common_lvbs/src/heki.rs`
- Modify: `litebox_platform_lvbs/src/mshv/heki.rs:10-52` (remove definitions, add re-exports)

**Step 1: Add `HekiPatchType` and `HekiPatchInfo` to `litebox_common_lvbs/src/heki.rs`**

Add imports for `ListHead` from `crate::linux::ListHead` and `zerocopy::{FromBytes, Immutable, KnownLayout}` (zerocopy may already be imported).

```rust
use crate::linux::ListHead;

#[derive(Default, Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum HekiPatchType {
    JumpLabel = 0,
    #[default]
    Unknown = 0xffff_ffff,
}

#[derive(Clone, Copy, Debug, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct HekiPatchInfo {
    /// Patch type stored as u32 for zerocopy compatibility (see `HekiPatchType`)
    pub typ_: u32,
    list: ListHead,
    /// *const `struct module` (stored as u64 since we don't dereference it)
    mod_: u64,
    pub patch_index: u64,
    pub max_patch_count: u64,
    // pub patch: [HekiPatch; *]
}

impl HekiPatchInfo {
    /// Creates a new `HekiPatchInfo` with a given buffer. Returns `None` if any field is invalid.
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        let info = Self::read_from_bytes(bytes).ok()?;
        if info.is_valid() {
            Some(info)
        } else {
            None
        }
    }

    pub fn is_valid(&self) -> bool {
        !(self.typ_ != HekiPatchType::JumpLabel as u32
            || self.patch_index == 0
            || self.patch_index > self.max_patch_count)
    }
}
```

**Step 2: Update `litebox_platform_lvbs/src/mshv/heki.rs`**

Replace the entire file content with just re-exports:
```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub use litebox_common_lvbs::heki::{
    mem_attr_to_hv_page_prot_flags, mod_mem_type_to_mem_attr, HekiKdataType, HekiKernelInfo,
    HekiKernelSymbol, HekiKexecType, HekiPage, HekiPatch, HekiPatchInfo, HekiPatchType,
    HekiRange, MemAttr, ModMemType, HEKI_MAX_RANGES, POKE_MAX_OPCODE_SIZE,
};
```

Remove the `use crate::host::linux::ListHead;` and `use zerocopy::{FromBytes, Immutable, KnownLayout};` imports that are no longer needed.

**Step 3: Build and verify**

Run: `cargo build`
Expected: PASS — `HekiPatchInfo` and `HekiPatchType` re-exported from same path.

**Step 4: Commit**
```
git commit -m "Move HekiPatchInfo and HekiPatchType to litebox_common_lvbs"
```

---

### Task 3: Move `HV_X64_REGISTER_*` constants and `ControlRegMap` to `litebox_common_lvbs`

**Files:**
- Modify: `litebox_common_lvbs/src/mshv.rs`
- Modify: `litebox_platform_lvbs/src/mshv/mod.rs:90-105` (remove constants, add re-exports)
- Modify: `litebox_platform_lvbs/src/mshv/vsm.rs:1-100` (remove `ControlRegMap` + `NUM_CONTROL_REGS`, add re-exports)

**Step 1: Add `HV_X64_REGISTER_*` constants to `litebox_common_lvbs/src/mshv.rs`**

Add after existing constants (after `HV_SECURE_VTL_BOOT_TOKEN`):

```rust
// --- HV_X64_REGISTER constants ---

pub const HV_X64_REGISTER_CR0: u32 = 0x0004_0000;
pub const HV_X64_REGISTER_CR4: u32 = 0x0004_0003;
pub const HV_X64_REGISTER_EFER: u32 = 0x0008_0001;
pub const HV_X64_REGISTER_APIC_BASE: u32 = 0x0008_0003;
pub const HV_X64_REGISTER_SYSENTER_CS: u32 = 0x0008_0005;
pub const HV_X64_REGISTER_SYSENTER_EIP: u32 = 0x0008_0006;
pub const HV_X64_REGISTER_SYSENTER_ESP: u32 = 0x0008_0007;
pub const HV_X64_REGISTER_STAR: u32 = 0x0008_0008;
pub const HV_X64_REGISTER_LSTAR: u32 = 0x0008_0009;
pub const HV_X64_REGISTER_CSTAR: u32 = 0x0008_000a;
pub const HV_X64_REGISTER_SFMASK: u32 = 0x0008_000b;
```

**Step 2: Add `ControlRegMap` and `NUM_CONTROL_REGS` to `litebox_common_lvbs/src/mshv.rs`**

```rust
pub const NUM_CONTROL_REGS: usize = 11;

/// Data structure for maintaining MSRs and control registers whose values are locked.
/// This structure is expected to be stored in per-core kernel context, so we do not protect it with a lock.
#[derive(Debug, Clone, Copy)]
pub struct ControlRegMap {
    pub entries: [(u32, u64); NUM_CONTROL_REGS],
}

impl ControlRegMap {
    pub fn init(&mut self) {
        [
            HV_X64_REGISTER_CR0,
            HV_X64_REGISTER_CR4,
            HV_X64_REGISTER_LSTAR,
            HV_X64_REGISTER_STAR,
            HV_X64_REGISTER_CSTAR,
            HV_X64_REGISTER_APIC_BASE,
            HV_X64_REGISTER_EFER,
            HV_X64_REGISTER_SYSENTER_CS,
            HV_X64_REGISTER_SYSENTER_ESP,
            HV_X64_REGISTER_SYSENTER_EIP,
            HV_X64_REGISTER_SFMASK,
        ]
        .iter()
        .enumerate()
        .for_each(|(i, &reg_name)| {
            self.entries[i] = (reg_name, 0);
        });
    }

    pub fn get(&self, reg_name: u32) -> Option<u64> {
        for entry in &self.entries {
            if entry.0 == reg_name {
                return Some(entry.1);
            }
        }
        None
    }

    pub fn set(&mut self, reg_name: u32, value: u64) {
        for entry in &mut self.entries {
            if entry.0 == reg_name {
                entry.1 = value;
                return;
            }
        }
    }

    // consider implementing a mutable iterator (if we plan to lock many control registers)
    pub fn reg_names(&self) -> [u32; NUM_CONTROL_REGS] {
        let mut names = [0; NUM_CONTROL_REGS];
        for (i, entry) in self.entries.iter().enumerate() {
            names[i] = entry.0;
        }
        names
    }
}
```

**Step 3: Update `litebox_platform_lvbs/src/mshv/mod.rs`**

Remove the 11 `HV_X64_REGISTER_*` constants (lines 91-105: CR0, CR4, EFER, APIC_BASE, SYSENTER_CS, SYSENTER_EIP, SYSENTER_ESP, STAR, LSTAR, CSTAR, SFMASK) and replace with re-exports:

```rust
pub use litebox_common_lvbs::mshv::{
    HV_X64_REGISTER_APIC_BASE, HV_X64_REGISTER_CR0, HV_X64_REGISTER_CR4,
    HV_X64_REGISTER_CSTAR, HV_X64_REGISTER_EFER, HV_X64_REGISTER_LSTAR,
    HV_X64_REGISTER_SFMASK, HV_X64_REGISTER_STAR, HV_X64_REGISTER_SYSENTER_CS,
    HV_X64_REGISTER_SYSENTER_EIP, HV_X64_REGISTER_SYSENTER_ESP,
};
```

Keep `HV_X64_REGISTER_RIP`, `HV_X64_REGISTER_LDTR`, `HV_X64_REGISTER_TR`, `HV_X64_REGISTER_IDTR`, `HV_X64_REGISTER_GDTR`, `HV_X64_REGISTER_VSM_VP_STATUS` — these are only used internally by platform.

**Step 4: Update `litebox_platform_lvbs/src/mshv/vsm.rs`**

Remove `ControlRegMap` (lines 43-100) and `NUM_CONTROL_REGS` (line 43). Add re-exports:

```rust
pub use litebox_common_lvbs::mshv::{ControlRegMap, NUM_CONTROL_REGS};
```

Remove the now-unused `HV_X64_REGISTER_*` imports from lines 10-13 (they're no longer needed since `ControlRegMap` moved to common).

**Step 5: Build and verify**

Run: `cargo build`
Expected: PASS — everything re-exported from original locations.

**Step 6: Commit**
```
git commit -m "Move ControlRegMap and HV_X64_REGISTER constants to litebox_common_lvbs"
```

---

### Task 4: Move `MemoryContainerError`, `PatchDataMapError`, and `Symbol` to `litebox_common_lvbs`

**Files:**
- Modify: `litebox_common_lvbs/src/vsm.rs`
- Modify: `litebox_common_lvbs/src/error.rs`
- Modify: `litebox_common_lvbs/Cargo.toml` (may need `alloc` for `String`/`CString`)
- Modify: `litebox_platform_lvbs/src/mshv/vsm.rs` (remove definitions, add re-exports)

**Step 1: Add `MemoryContainerError` and `PatchDataMapError` to `litebox_common_lvbs/src/error.rs`**

```rust
/// Errors for memory container operations.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum MemoryContainerError {
    #[error("failed to copy data from VTL0")]
    CopyFromVtl0Failed,
}

/// Errors for patch data map operations.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum PatchDataMapError {
    #[error("invalid HEKI patch info")]
    InvalidHekiPatchInfo,
    #[error("invalid HEKI patch")]
    InvalidHekiPatch,
}
```

**Step 2: Add `Symbol` to `litebox_common_lvbs/src/vsm.rs`**

`Symbol` uses `VsmError`, `HekiKernelSymbol`, `VirtAddr`, `alloc::{ffi::CString, string::String}`, and `core::ffi::{CStr, c_char}`.

```rust
use crate::error::VsmError;
use crate::heki::HekiKernelSymbol;
use alloc::{ffi::CString, string::String};
use core::ffi::{CStr, c_char};
use x86_64::VirtAddr;

// TODO: Use this to resolve symbols in modules
pub struct Symbol {
    _value: u64,
}

impl Symbol {
    /// Parse a symbol from a byte buffer.
    pub fn from_bytes(
        kinfo_start: usize,
        start: VirtAddr,
        bytes: &[u8],
    ) -> Result<(String, Self), VsmError> {
        let kinfo_bytes = &bytes[kinfo_start..];
        let ksym = HekiKernelSymbol::from_bytes(kinfo_bytes)?;

        let value_addr = start + core::mem::offset_of!(HekiKernelSymbol, value_offset) as u64;
        let value = value_addr
            .as_u64()
            .wrapping_add_signed(i64::from(ksym.value_offset));

        let name_offset = kinfo_start
            + core::mem::offset_of!(HekiKernelSymbol, name_offset)
            + usize::try_from(ksym.name_offset).map_err(|_| VsmError::SymbolNameOffsetInvalid)?;

        if name_offset >= bytes.len() {
            return Err(VsmError::SymbolNameOffsetInvalid);
        }
        let name_len = bytes[name_offset..]
            .iter()
            .position(|&b| b == 0)
            .ok_or(VsmError::SymbolNameNoTerminator)?;
        if name_len >= HekiKernelSymbol::KSY_NAME_LEN {
            return Err(VsmError::SymbolNameTooLong);
        }

        // SAFETY:
        // - offset is within bytes (checked above)
        // - there is a NUL terminator within bytes[offset..] (checked above)
        // - Length of name string is within spec range (checked above)
        // - bytes is still valid for the duration of this function
        let name_str = unsafe {
            let name_ptr = bytes.as_ptr().add(name_offset).cast::<c_char>();
            CStr::from_ptr(name_ptr)
        };
        let name = CString::new(
            name_str
                .to_str()
                .map_err(|_| VsmError::SymbolNameInvalidUtf8)?,
        )
        .map_err(|_| VsmError::SymbolNameInvalidUtf8)?;
        let name = name
            .into_string()
            .map_err(|_| VsmError::SymbolNameInvalidUtf8)?;
        Ok((name, Symbol { _value: value }))
    }
}
```

Note: `litebox_common_lvbs` is `#![no_std]` but already depends on `litebox` and `litebox_common_linux` which use `alloc`. Need to add `extern crate alloc;` to `litebox_common_lvbs/src/lib.rs` if not already present.

**Step 3: Update `litebox_platform_lvbs/src/mshv/vsm.rs`**

Remove `MemoryContainerError` (lines 452-457), `PatchDataMapError` (lines 621-628), `Symbol` (lines 631-684), and the `use core::ffi::{CStr, c_char};` import (line 689).

Add re-exports:
```rust
pub use litebox_common_lvbs::error::{MemoryContainerError, PatchDataMapError};
pub use litebox_common_lvbs::vsm::Symbol;
```

**Step 4: Build and verify**

Run: `cargo build`
Expected: PASS

**Step 5: Commit**
```
git commit -m "Move MemoryContainerError, PatchDataMapError, and Symbol to litebox_common_lvbs"
```

---

### Task 5: Move `MemoryRange` to `litebox_common_lvbs`

**Files:**
- Modify: `litebox_common_lvbs/src/vsm.rs`
- Modify: `litebox_platform_lvbs/src/mshv/vsm.rs:330-335` (remove `MemoryRange`)

**Step 1: Add `MemoryRange` to `litebox_common_lvbs/src/vsm.rs`**

```rust
use x86_64::{PhysAddr, VirtAddr};

/// Data structure for abstracting addressable paged memory ranges.
#[derive(Clone, Copy)]
pub struct MemoryRange {
    pub addr: VirtAddr,
    pub phys_addr: PhysAddr,
    pub len: u64,
}
```

Note: `MemoryRange` was `struct` (private) in platform, but needs to be `pub` now since `MemoryContainer` (in runner) will use it across crate boundary.

**Step 2: Remove `MemoryRange` from `litebox_platform_lvbs/src/mshv/vsm.rs` (lines 330-335)**

No re-export needed since it was private.

**Step 3: Build and verify**

Run: `cargo build`
Expected: PASS

**Step 4: Commit**
```
git commit -m "Move MemoryRange to litebox_common_lvbs"
```

---

### Task 6: Move logic types to `litebox_runner_lvbs`

This is the main task. Move `MemoryContainer`, `ModuleMemoryMetadataMap`, `ModuleMemoryMetadataIters`, `ModuleMemory`, `KexecMemoryMetadataWrapper`, `KexecMemoryMetadataIters`, `PatchDataMap`, `SymbolTable`, and `Vtl0KernelInfo` from `litebox_platform_lvbs/src/mshv/vsm.rs` to `litebox_runner_lvbs/src/vsm.rs`.

**Files:**
- Modify: `litebox_runner_lvbs/src/vsm.rs` (add all logic types)
- Modify: `litebox_runner_lvbs/Cargo.toml` (add `thiserror` dependency for error derives in existing code, `x509-cert` already present)
- Modify: `litebox_platform_lvbs/src/mshv/vsm.rs` (remove all moved types)

**Step 1: Add imports to runner's `vsm.rs`**

Add the following new imports:
```rust
use litebox_common_lvbs::{
    error::{MemoryContainerError, PatchDataMapError},
    heki::HekiPatchInfo,
    linux::ListHead,
    vsm::{MemoryRange, Symbol},
};
use core::{
    ffi::{CStr, c_char},
    marker::PhantomData,
    sync::atomic::{AtomicBool, AtomicI64, Ordering},
};
use hashbrown::HashMap;
use spin::mutex::SpinMutex;
use once_cell::race::OnceBox;
```

Note: Some of these may already be imported. Merge with existing imports.

**Step 2: Add `MemoryContainer` to runner's `vsm.rs`**

Replace `crate::platform_low().copy_from_vtl0_phys::<AlignedPage>(phys_aligned)` with `NormalWorldConstPtr`. Replace `debug_serial_println!` — it's already available in the runner.

```rust
pub(crate) struct MemoryContainer {
    range: Vec<MemoryRange>,
    buf: Vec<u8>,
}

impl Default for MemoryContainer {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryContainer {
    pub fn new() -> Self {
        Self {
            range: Vec::new(),
            buf: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get_range(&self) -> Option<Range<VirtAddr>> {
        let start_range = self.range.first()?;
        let end_range = self.range.last()?;
        Some(Range {
            start: start_range.addr,
            end: end_range.addr + end_range.len,
        })
    }

    pub fn extend_range(&mut self, heki_range: &HekiRange) -> Result<(), VsmError> {
        let addr = VirtAddr::try_new(heki_range.va).map_err(|_| VsmError::InvalidVirtualAddress)?;
        let phys_addr =
            PhysAddr::try_new(heki_range.pa).map_err(|_| VsmError::InvalidPhysicalAddress)?;
        if let Some(last_range) = self.range.last()
            && last_range.addr + last_range.len != addr
        {
            debug_serial_println!("Discontiguous address found {heki_range:?}");
            // NOTE: Intentionally not returning an error here.
            // TODO: This should be an error once patch_info is fixed from VTL0
        }
        self.range.push(MemoryRange {
            addr,
            phys_addr,
            len: heki_range.epa - heki_range.pa,
        });
        Ok(())
    }

    #[inline]
    pub fn write_bytes_from_heki_range(&mut self) -> Result<(), MemoryContainerError> {
        let mut len: usize = 0;
        if self.buf.is_empty() {
            for range in &self.range {
                let range_len: usize = range.len.truncate();
                len += range_len;
            }
            self.buf.reserve_exact(len);
        }

        let range = self.range.clone();
        for range in range {
            self.write_vtl0_phys_bytes(range.phys_addr, range.phys_addr + range.len)?;
        }
        Ok(())
    }

    pub fn write_vtl0_phys_bytes(
        &mut self,
        phys_start: PhysAddr,
        phys_end: PhysAddr,
    ) -> Result<(), MemoryContainerError> {
        let mut bytes_to_copy: usize = (phys_end - phys_start).truncate();
        let mut phys_cur = phys_start;

        while phys_cur < phys_end {
            let phys_aligned = phys_cur.align_down(Size4KiB::SIZE);
            let page = unsafe {
                NormalWorldConstPtr::<AlignedPage, PAGE_SIZE>::with_usize(
                    phys_aligned.as_u64() as usize
                )
                .and_then(|mut ptr| ptr.read_at_offset(0))
                .map_err(|_| MemoryContainerError::CopyFromVtl0Failed)?
            };

            let src_offset: usize = (phys_cur - phys_aligned).truncate();
            let src_len = core::cmp::min(bytes_to_copy, PAGE_SIZE - src_offset);
            let src = &page.0[src_offset..src_offset + src_len];

            self.buf.extend_from_slice(src);
            phys_cur += src_len as u64;
            bytes_to_copy -= src_len;
        }
        Ok(())
    }
}

impl core::ops::Deref for MemoryContainer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}
```

**Step 3: Add remaining logic types to runner's `vsm.rs`**

Copy verbatim from platform (these have no platform coupling):
- `ModuleMemoryMetadataMap` (lines 177-248)
- `ModuleMemoryMetadataIters` (lines 250-265)
- `ModuleMemory` (lines 269-323)
- `KexecMemoryMetadataWrapper` (lines 459-492)
- `KexecMemoryMetadataIters` (lines 494-503)
- `PatchDataMap` (lines 505-618)
- `SymbolTable` (lines 686-741)
- `Vtl0KernelInfo` (lines 105-174)

All should be `pub(crate)` visibility since they're runner-internal.

**Step 4: Add runner global static and accessor**

```rust
use once_cell::sync::OnceCell;

static VTL0_KERNEL_INFO: OnceCell<Vtl0KernelInfo> = OnceCell::new();

fn init_vtl0_kernel_info() {
    VTL0_KERNEL_INFO
        .set(Vtl0KernelInfo::default())
        .expect("vtl0_kernel_info already initialized");
}

fn vtl0_kernel_info() -> &'static Vtl0KernelInfo {
    VTL0_KERNEL_INFO
        .get()
        .expect("vtl0_kernel_info not initialized")
}
```

Note: `once_cell::sync::OnceCell` is appropriate for `no_std` with `alloc`. Check if `once_cell` supports `sync::OnceCell` without `std`. If not, use `spin::Once` which is already a dependency.

**Step 5: Call `init_vtl0_kernel_info()` from `vsm::init()`**

Add at the start of `init()` (before existing assertions):
```rust
if get_core_id() == 0 {
    init_vtl0_kernel_info();
}
```

Wait — `init()` already has a block for `get_core_id() == 0` at line 79. Add the call at the very start of `init()` before any assertions, or inside the existing core 0 block. The best place is at the start of `init()`, before the partition config assertion:

```rust
pub(crate) fn init() {
    if get_core_id() == 0 {
        init_vtl0_kernel_info();
    }

    assert!(
        !(get_core_id() == 0 && mshv_vsm_configure_partition().is_err()),
        // ...
```

**Step 6: Replace all `platform().vtl0_kernel_info` with `vtl0_kernel_info()`**

All 19 access sites change from `platform().vtl0_kernel_info` to `vtl0_kernel_info()`:

| Line | Before | After |
|------|--------|-------|
| 204 | `platform().vtl0_kernel_info.check_end_of_boot()` | `vtl0_kernel_info().check_end_of_boot()` |
| 249 | `platform().vtl0_kernel_info.set_end_of_boot()` | `vtl0_kernel_info().set_end_of_boot()` |
| 265 | `platform().vtl0_kernel_info.check_end_of_boot()` | `vtl0_kernel_info().check_end_of_boot()` |
| 343 | `platform().vtl0_kernel_info.check_end_of_boot()` | `vtl0_kernel_info().check_end_of_boot()` |
| 347 | `let vtl0_info = &platform().vtl0_kernel_info;` | `let vtl0_info = vtl0_kernel_info();` |
| 479-481 | `platform()\n.vtl0_kernel_info\n.get_system_certificates()` | `vtl0_kernel_info()\n.get_system_certificates()` |
| 556-558 | `platform()\n.vtl0_kernel_info\n.precomputed_patches` | `vtl0_kernel_info()\n.precomputed_patches` |
| 572-574 | `platform()\n.vtl0_kernel_info\n.module_memory_metadata` | `vtl0_kernel_info()\n.module_memory_metadata` |
| 586-588 | same pattern | same pattern |
| 594-596 | same pattern | same pattern |
| 628-630 | same pattern | same pattern |
| 636-638 | same pattern | same pattern |
| 650-652 | same pattern | same pattern |
| 655-657 | same pattern | same pattern |
| 661-663 | same pattern | same pattern |
| 688-690 | same pattern | same pattern |
| 695 | `&platform().vtl0_kernel_info.crash_kexec_metadata` | `&vtl0_kernel_info().crash_kexec_metadata` |
| 697 | `&platform().vtl0_kernel_info.kexec_metadata` | `&vtl0_kernel_info().kexec_metadata` |
| 801-803 | `platform()\n.vtl0_kernel_info\n.find_precomputed_patch(...)` | `vtl0_kernel_info()\n.find_precomputed_patch(...)` |

**Step 7: Remove unused imports from runner**

Remove from runner's imports:
- `litebox_platform_lvbs::mshv::vsm::{MemoryContainer, ModuleMemory, CPU_ONLINE_MASK}` — only `CPU_ONLINE_MASK` stays

Update to: `litebox_platform_lvbs::mshv::vsm::CPU_ONLINE_MASK`

The `platform()` import may no longer be needed if `vtl0_kernel_info` was the only remaining use — but check first. It's likely still used for other platform calls.

**Step 8: Build and verify**

Run: `cargo build`
Expected: PASS

**Step 9: Commit**
```
git commit -m "Move Vtl0KernelInfo and logic types to litebox_runner_lvbs"
```

---

### Task 7: Clean up platform — remove moved types

**Files:**
- Modify: `litebox_platform_lvbs/src/mshv/vsm.rs` (remove all moved types)
- Modify: `litebox_platform_lvbs/src/lib.rs` (remove `vtl0_kernel_info` field from `LinuxKernel`)

**Step 1: Remove moved types from `litebox_platform_lvbs/src/mshv/vsm.rs`**

Remove these (they should already be gone from the runner import, but the definitions still exist in platform):
- `Vtl0KernelInfo` (lines 105-174)
- `ModuleMemoryMetadataMap` (lines 177-248)
- `ModuleMemoryMetadataIters` (lines 250-265)
- `ModuleMemory` (lines 269-323)
- `MemoryRange` (lines 330-335 — already moved in Task 5)
- `MemoryContainer` (lines 337-449)
- `MemoryContainerError` (lines 452-457 — already moved in Task 4)
- `KexecMemoryMetadataWrapper` (lines 459-492)
- `KexecMemoryMetadataIters` (lines 494-503)
- `PatchDataMap` (lines 505-618)
- `PatchDataMapError` (lines 621-628 — already moved in Task 4)
- `Symbol` (lines 631-684 — already moved in Task 4)
- `SymbolTable` (lines 686-741)

Clean up unused imports: `alloc::boxed::Box`, `alloc::ffi::CString`, `alloc::string::String`, `alloc::vec::Vec`, `core::mem`, `core::ops::Range`, `core::sync::atomic::{AtomicBool, AtomicI64, Ordering}`, `hashbrown::HashMap`, `thiserror::Error`, `x86_64::{PhysAddr, VirtAddr, ...}`, `x509_cert::Certificate`, `spin::Once`, `core::ffi::{CStr, c_char}`.

Keep: `CpuMask`, `CPU_ONLINE_MASK`, and the re-exports for `AlignedPage`, `KexecMemoryMetadata`, etc.

**Step 2: Remove `vtl0_kernel_info` from `LinuxKernel`**

In `litebox_platform_lvbs/src/lib.rs`:

Remove from struct (line 345):
```rust
pub vtl0_kernel_info: Vtl0KernelInfo,
```

Remove from construction (line 441):
```rust
vtl0_kernel_info: Vtl0KernelInfo::new(),
```

Remove the import of `Vtl0KernelInfo` if it was explicitly imported.

**Step 3: Build and verify**

Run: `cargo build`
Expected: PASS

**Step 4: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: PASS (or only pre-existing warnings)

**Step 5: Commit**
```
git commit -m "Remove Vtl0KernelInfo and migrated types from litebox_platform_lvbs"
```

---

### Task 8: Final verification

**Step 1: Run full build**

Run: `cargo build`
Expected: PASS

**Step 2: Run clippy**

Run: `cargo clippy`
Expected: Only pre-existing warnings

**Step 3: Run tests**

Run: `cargo test`
Expected: All pass except pre-existing failures in `litebox_runner_linux_userland`

**Step 4: Verify runner import hygiene**

Check that runner's `vsm.rs` does not import any `Vtl0KernelInfo`-related types from `litebox_platform_lvbs`. The only remaining platform imports should be:
- `arch::{get_core_id}`
- `debug_serial_print`, `debug_serial_println`
- `host::{bootparam, linux, per_cpu_variables}`
- `mshv::{hvcall_mm, hvcall_vp, mem_integrity, ringbuffer, vsm::CPU_ONLINE_MASK, vtl_switch, VsmFunction, NUM_VTLCALL_PARAMS}`

**Step 5: Commit (if any fixes needed)**
