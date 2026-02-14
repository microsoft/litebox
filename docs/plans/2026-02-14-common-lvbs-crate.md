# `litebox_common_lvbs` Crate Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create `litebox_common_lvbs` crate and move all data-only types out of `litebox_platform_lvbs` to decouple the runner from the platform.

**Architecture:** Extract pure data types (bitflags, enums, structs, constants, conversion functions) that have no platform dependencies into a new shared crate. Both `litebox_platform_lvbs` and `litebox_runner_lvbs` will depend on `litebox_common_lvbs`. Platform re-exports all moved types so internal consumers need zero import changes.

**Tech Stack:** Rust no_std, bitflags, modular-bitfield, num_enum, thiserror, zerocopy, x86_64

**Verification:** `litebox_runner_lvbs` is excluded from `cargo build` default members (requires nightly + custom target). Verification is `cargo build` + `cargo clippy` on default workspace members, plus code review of runner import changes.

---

### Task 1: Create `litebox_common_lvbs` crate skeleton

**Files:**
- Create: `litebox_common_lvbs/Cargo.toml`
- Create: `litebox_common_lvbs/src/lib.rs`
- Modify: `Cargo.toml` (workspace root, line 3-23)

**Step 1: Create directory**

```bash
mkdir -p litebox_common_lvbs/src
```

**Step 2: Create `Cargo.toml`**

Create `litebox_common_lvbs/Cargo.toml`:

```toml
[package]
name = "litebox_common_lvbs"
version = "0.1.0"
edition = "2024"

[dependencies]
bitflags = "2.9.0"
modular-bitfield = { version = "0.12.0", default-features = false }
num_enum = { version = "0.7.3", default-features = false }
thiserror = { version = "2.0.6", default-features = false }
zerocopy = { version = "0.8", default-features = false, features = ["derive"] }
litebox = { path = "../litebox/", version = "0.1.0" }
litebox_common_linux = { path = "../litebox_common_linux/", version = "0.1.0" }

[target.'cfg(target_arch = "x86_64")'.dependencies]
x86_64 = { version = "0.15.2", default-features = false }

[lints]
workspace = true
```

**Step 3: Create `src/lib.rs` with module declarations**

Create `litebox_common_lvbs/src/lib.rs`:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Common data-only types for LVBS (VTL1) — shared between platform and runner crates.

#![no_std]

pub mod error;
pub mod heki;
pub mod hvcall;
pub mod mem_layout;
pub mod mshv;
pub mod vsm;
```

**Step 4: Add to workspace `members` and `default-members`**

In workspace root `Cargo.toml`, add `"litebox_common_lvbs"` to both `members` and `default-members` arrays.

**Step 5: Create empty module files**

Create these empty files (will be populated in subsequent tasks):
- `litebox_common_lvbs/src/error.rs`
- `litebox_common_lvbs/src/heki.rs`
- `litebox_common_lvbs/src/hvcall.rs`
- `litebox_common_lvbs/src/mem_layout.rs`
- `litebox_common_lvbs/src/mshv.rs`
- `litebox_common_lvbs/src/vsm.rs`

Each file should just have the copyright header:
```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
```

**Step 6: Verify build**

```bash
cargo build -p litebox_common_lvbs
```

Expected: builds successfully (empty crate).

**Step 7: Commit**

```bash
git add litebox_common_lvbs/ Cargo.toml
git commit -m "feat: create litebox_common_lvbs crate skeleton"
```

---

### Task 2: Move mshv constants and core types from `mod.rs`

Move the HV_STATUS constants, VsmFunction enum, VSM_VTL_CALL_FUNC_ID constants, register constants used by runner, bitflags, and bitfield structs that the runner imports.

**Files:**
- Modify: `litebox_common_lvbs/src/mshv.rs`
- Modify: `litebox_platform_lvbs/src/mshv/mod.rs` (lines 31-43, 100-148, 162-178, 520-668)

**Step 1: Populate `litebox_common_lvbs/src/mshv.rs`**

Move the following items from `litebox_platform_lvbs/src/mshv/mod.rs` into `litebox_common_lvbs/src/mshv.rs`:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hyper-V constants and data-only types shared between platform and runner.

use modular_bitfield::prelude::*;
use modular_bitfield::specifiers::B62;
use num_enum::TryFromPrimitive;

// --- HV_STATUS constants (mod.rs lines 31-43) ---

pub const HV_STATUS_SUCCESS: u32 = 0;
pub const HV_STATUS_INVALID_HYPERCALL_CODE: u32 = 2;
pub const HV_STATUS_INVALID_HYPERCALL_INPUT: u32 = 3;
pub const HV_STATUS_INVALID_ALIGNMENT: u32 = 4;
pub const HV_STATUS_INVALID_PARAMETER: u32 = 5;
pub const HV_STATUS_ACCESS_DENIED: u32 = 6;
pub const HV_STATUS_OPERATION_DENIED: u32 = 8;
pub const HV_STATUS_INSUFFICIENT_MEMORY: u32 = 11;
pub const HV_STATUS_INVALID_PORT_ID: u32 = 17;
pub const HV_STATUS_INVALID_CONNECTION_ID: u32 = 18;
pub const HV_STATUS_INSUFFICIENT_BUFFERS: u32 = 19;
pub const HV_STATUS_TIME_OUT: u32 = 120;
pub const HV_STATUS_VTL_ALREADY_ENABLED: u32 = 134;

// --- VSM constants (mod.rs lines 100-128) ---

pub const HV_REGISTER_VSM_PARTITION_CONFIG: u32 = 0x000d_0007;
pub const HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0: u32 = 0x000d_0010;
pub const HV_REGISTER_CR_INTERCEPT_CONTROL: u32 = 0x000e_0000;
pub const HV_REGISTER_CR_INTERCEPT_CR0_MASK: u32 = 0x000e_0001;
pub const HV_REGISTER_CR_INTERCEPT_CR4_MASK: u32 = 0x000e_0002;

pub const HV_SECURE_VTL_BOOT_TOKEN: u8 = 0xdc;

/// VTL call parameters (`param[0]`: function ID, `param[1..4]`: parameters)
pub const NUM_VTLCALL_PARAMS: usize = 4;

pub const VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL: u32 = 0x1_ffe0;
pub const VSM_VTL_CALL_FUNC_ID_BOOT_APS: u32 = 0x1_ffe1;
pub const VSM_VTL_CALL_FUNC_ID_LOCK_REGS: u32 = 0x1_ffe2;
pub const VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT: u32 = 0x1_ffe3;
pub const VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY: u32 = 0x1_ffe4;
pub const VSM_VTL_CALL_FUNC_ID_LOAD_KDATA: u32 = 0x1_ffe5;
pub const VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE: u32 = 0x1_ffe6;
pub const VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT: u32 = 0x1_ffe7;
pub const VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE: u32 = 0x1_ffe8;
pub const VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY: u32 = 0x1_ffe9;
pub const VSM_VTL_CALL_FUNC_ID_KEXEC_VALIDATE: u32 = 0x1_ffea;
pub const VSM_VTL_CALL_FUNC_ID_PATCH_TEXT: u32 = 0x1_ffeb;
pub const VSM_VTL_CALL_FUNC_ID_ALLOCATE_RINGBUFFER_MEMORY: u32 = 0x1_ffec;

// This VSM function ID for OP-TEE messages is subject to change
pub const VSM_VTL_CALL_FUNC_ID_OPTEE_MESSAGE: u32 = 0x1_fff0;

/// VSM Functions
#[derive(Debug, PartialEq, TryFromPrimitive)]
#[repr(u32)]
pub enum VsmFunction {
    // VSM/Heki functions
    EnableAPsVtl = VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL,
    BootAPs = VSM_VTL_CALL_FUNC_ID_BOOT_APS,
    LockRegs = VSM_VTL_CALL_FUNC_ID_LOCK_REGS,
    SignalEndOfBoot = VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT,
    ProtectMemory = VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY,
    LoadKData = VSM_VTL_CALL_FUNC_ID_LOAD_KDATA,
    ValidateModule = VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE,
    FreeModuleInit = VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT,
    UnloadModule = VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE,
    CopySecondaryKey = VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY,
    KexecValidate = VSM_VTL_CALL_FUNC_ID_KEXEC_VALIDATE,
    PatchText = VSM_VTL_CALL_FUNC_ID_PATCH_TEXT,
    OpteeMessage = VSM_VTL_CALL_FUNC_ID_OPTEE_MESSAGE,
    AllocateRingbufferMemory = VSM_VTL_CALL_FUNC_ID_ALLOCATE_RINGBUFFER_MEMORY,
}

// --- Bitflags (mod.rs lines 162-178) ---

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct HvPageProtFlags: u8 {
        const HV_PAGE_ACCESS_NONE = 0x0;
        const HV_PAGE_READABLE = 0x1;
        const HV_PAGE_WRITABLE = 0x2;
        const HV_PAGE_KERNEL_EXECUTABLE = 0x4;
        const HV_PAGE_USER_EXECUTABLE = 0x8;

        const _ = !0;

        const HV_PAGE_EXECUTABLE = Self::HV_PAGE_KERNEL_EXECUTABLE.bits() | Self::HV_PAGE_USER_EXECUTABLE.bits();
        const HV_PAGE_FULL_ACCESS = Self::HV_PAGE_READABLE.bits()
            | Self::HV_PAGE_WRITABLE.bits()
            | Self::HV_PAGE_EXECUTABLE.bits();
    }
}

// --- Bitfield structs (mod.rs lines 520-565) ---

#[bitfield]
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct HvRegisterVsmVpSecureVtlConfig {
    pub mbec_enabled: bool,
    pub tlb_locked: bool,
    #[skip]
    __: B62,
}

impl HvRegisterVsmVpSecureVtlConfig {
    pub fn as_u64(&self) -> u64 {
        u64::from_le_bytes(self.into_bytes())
    }
}

#[bitfield]
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct HvRegisterVsmPartitionConfig {
    pub enable_vtl_protection: bool,
    pub default_vtl_protection_mask: B4,
    pub zero_memory_on_reset: bool,
    pub deny_lower_vtl_startup: bool,
    pub intercept_acceptance: bool,
    pub intercept_enable_vtl_protection: bool,
    pub intercept_vp_startup: bool,
    pub intercept_cpuid_unimplemented: bool,
    pub intercept_unrecoverable_exception: bool,
    pub intercept_page: bool,
    #[skip]
    __: B51,
}

impl HvRegisterVsmPartitionConfig {
    /// Get the raw u64 value for compatibility with existing code
    pub fn as_u64(&self) -> u64 {
        // Convert the 8-byte array to u64
        u64::from_le_bytes(self.into_bytes())
    }

    /// Create from a u64 value for compatibility with existing code
    pub fn from_u64(value: u64) -> Self {
        Self::from_bytes(value.to_le_bytes())
    }
}

// --- CR bitflags (mod.rs lines 582-668) ---

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct X86Cr4Flags: u32 {
        const X86_CR4_VME = 1 << 0;
        const X86_CR4_PVI = 1 << 1;
        const X86_CR4_TSD = 1 << 2;
        const X86_CR4_DE = 1 << 3;
        const X86_CR4_PSE = 1 << 4;
        const X86_CR4_PAE = 1 << 5;
        const X86_CR4_MCE = 1 << 6;
        const X86_CR4_PGE = 1 << 7;
        const X86_CR4_PCE = 1 << 8;
        const X86_CR4_OSFXSR = 1 << 9;
        const X86_CR4_OSXMMEXCPT = 1 << 10;
        const X86_CR4_UMIP = 1 << 11;
        const X86_CR4_LA57 = 1 << 12;
        const X86_CR4_VMXE = 1 << 13;
        const X86_CR4_SMXE = 1 << 14;
        const X86_CR4_FSGBASE = 1 << 16;
        const X86_CR4_PCIDE = 1 << 17;
        const X86_CR4_OSXSAVE = 1 << 18;
        const X86_CR4_SMEP = 1 << 20;
        const X86_CR4_SMAP = 1 << 21;
        const X86_CR4_PKE = 1 << 22;

        const _ = !0;

        const CR4_PIN_MASK = !(Self::X86_CR4_MCE.bits()
            | Self::X86_CR4_PGE.bits()
            | Self::X86_CR4_PCE.bits()
            | Self::X86_CR4_VMXE.bits());
    }
}

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct X86Cr0Flags: u32 {
        const X86_CR0_PE = 1 << 0;
        const X86_CR0_MP = 1 << 1;
        const X86_CR0_EM = 1 << 2;
        const X86_CR0_TS = 1 << 3;
        const X86_CR0_ET = 1 << 4;
        const X86_CR0_NE = 1 << 5;
        const X86_CR0_WP = 1 << 16;
        const X86_CR0_AM = 1 << 18;
        const X86_CR0_NW = 1 << 29;
        const X86_CR0_CD = 1 << 30;
        const X86_CR0_PG = 1 << 31;

        const _ = !0;

        const CR0_PIN_MASK = Self::X86_CR0_PE.bits() | Self::X86_CR0_WP.bits() | Self::X86_CR0_PG.bits();
    }
}

bitflags::bitflags! {
    #[derive(Debug, PartialEq)]
    pub struct HvCrInterceptControlFlags: u64 {
        const CR0_WRITE = 1 << 0;
        const CR4_WRITE = 1 << 1;
        const XCR0_WRITE = 1 << 2;
        const IA32MISCENABLE_READ = 1 << 3;
        const IA32MISCENABLE_WRITE = 1 << 4;
        const MSR_LSTAR_READ = 1 << 5;
        const MSR_LSTAR_WRITE = 1 << 6;
        const MSR_STAR_READ = 1 << 7;
        const MSR_STAR_WRITE = 1 << 8;
        const MSR_CSTAR_READ = 1 << 9;
        const MSR_CSTAR_WRITE = 1 << 10;
        const MSR_APIC_BASE_READ = 1 << 11;
        const MSR_APIC_BASE_WRITE = 1 << 12;
        const MSR_EFER_READ = 1 << 13;
        const MSR_EFER_WRITE = 1 << 14;
        const GDTR_WRITE = 1 << 15;
        const IDTR_WRITE = 1 << 16;
        const LDTR_WRITE = 1 << 17;
        const TR_WRITE = 1 << 18;
        const MSR_SYSENTER_CS_WRITE = 1 << 19;
        const MSR_SYSENTER_EIP_WRITE = 1 << 20;
        const MSR_SYSENTER_ESP_WRITE = 1 << 21;
        const MSR_SFMASK_WRITE = 1 << 22;
        const MSR_TSC_AUX_WRITE = 1 << 23;
        const MSR_SGX_LAUNCH_CTRL_WRITE = 1 << 24;

        const _ = !0;
    }
}
```

**Step 2: Replace moved items in `litebox_platform_lvbs/src/mshv/mod.rs` with re-exports**

In `litebox_platform_lvbs/src/mshv/mod.rs`, replace each moved block with a `pub use litebox_common_lvbs::mshv::*` re-export. Specifically:

1. Delete lines 31-43 (HV_STATUS constants) and replace with nothing (they'll come from the glob re-export)
2. Delete lines 100-104 (HV_REGISTER_VSM/CR constants) and replace with nothing
3. Delete lines 107-148 (HV_SECURE_VTL_BOOT_TOKEN through VsmFunction enum) and replace with nothing
4. Delete lines 162-178 (HvPageProtFlags) and replace with nothing
5. Delete lines 520-565 (HvRegisterVsmVpSecureVtlConfig, HvRegisterVsmPartitionConfig) and replace with nothing
6. Delete lines 582-668 (X86Cr4Flags, X86Cr0Flags, HvCrInterceptControlFlags) and replace with nothing

Add at the top of the file (after the module declarations and existing imports):

```rust
pub use litebox_common_lvbs::mshv::{
    HV_STATUS_SUCCESS, HV_STATUS_INVALID_HYPERCALL_CODE, HV_STATUS_INVALID_HYPERCALL_INPUT,
    HV_STATUS_INVALID_ALIGNMENT, HV_STATUS_INVALID_PARAMETER, HV_STATUS_ACCESS_DENIED,
    HV_STATUS_OPERATION_DENIED, HV_STATUS_INSUFFICIENT_MEMORY, HV_STATUS_INVALID_PORT_ID,
    HV_STATUS_INVALID_CONNECTION_ID, HV_STATUS_INSUFFICIENT_BUFFERS, HV_STATUS_TIME_OUT,
    HV_STATUS_VTL_ALREADY_ENABLED,
    HV_REGISTER_VSM_PARTITION_CONFIG, HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0,
    HV_REGISTER_CR_INTERCEPT_CONTROL, HV_REGISTER_CR_INTERCEPT_CR0_MASK,
    HV_REGISTER_CR_INTERCEPT_CR4_MASK,
    HV_SECURE_VTL_BOOT_TOKEN, NUM_VTLCALL_PARAMS,
    VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL, VSM_VTL_CALL_FUNC_ID_BOOT_APS,
    VSM_VTL_CALL_FUNC_ID_LOCK_REGS, VSM_VTL_CALL_FUNC_ID_SIGNAL_END_OF_BOOT,
    VSM_VTL_CALL_FUNC_ID_PROTECT_MEMORY, VSM_VTL_CALL_FUNC_ID_LOAD_KDATA,
    VSM_VTL_CALL_FUNC_ID_VALIDATE_MODULE, VSM_VTL_CALL_FUNC_ID_FREE_MODULE_INIT,
    VSM_VTL_CALL_FUNC_ID_UNLOAD_MODULE, VSM_VTL_CALL_FUNC_ID_COPY_SECONDARY_KEY,
    VSM_VTL_CALL_FUNC_ID_KEXEC_VALIDATE, VSM_VTL_CALL_FUNC_ID_PATCH_TEXT,
    VSM_VTL_CALL_FUNC_ID_ALLOCATE_RINGBUFFER_MEMORY, VSM_VTL_CALL_FUNC_ID_OPTEE_MESSAGE,
    VsmFunction,
    HvPageProtFlags,
    HvRegisterVsmVpSecureVtlConfig, HvRegisterVsmPartitionConfig,
    X86Cr4Flags, X86Cr0Flags, HvCrInterceptControlFlags,
};
```

**Step 3: Add `litebox_common_lvbs` dependency to `litebox_platform_lvbs`**

In `litebox_platform_lvbs/Cargo.toml`, add:

```toml
litebox_common_lvbs = { path = "../litebox_common_lvbs/", version = "0.1.0" }
```

**Step 4: Verify build**

```bash
cargo build
cargo clippy
```

Expected: builds and lints cleanly. All internal consumers of these types in `litebox_platform_lvbs` (hvcall.rs, hvcall_mm.rs, vsm_intercept.rs, vtl_switch.rs) continue working because the re-exports make them available at `crate::mshv::*`.

**Step 5: Commit**

```bash
git add -A
git commit -m "refactor: move mshv constants and core types to litebox_common_lvbs"
```

---

### Task 3: Move `HypervCallError` from `hvcall.rs`

**Files:**
- Modify: `litebox_common_lvbs/src/hvcall.rs`
- Modify: `litebox_platform_lvbs/src/mshv/hvcall.rs` (lines 253-284)

**Step 1: Populate `litebox_common_lvbs/src/hvcall.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hyper-V hypercall error types.

use crate::mshv::{
    HV_STATUS_ACCESS_DENIED, HV_STATUS_INSUFFICIENT_BUFFERS, HV_STATUS_INSUFFICIENT_MEMORY,
    HV_STATUS_INVALID_ALIGNMENT, HV_STATUS_INVALID_CONNECTION_ID,
    HV_STATUS_INVALID_HYPERCALL_CODE, HV_STATUS_INVALID_HYPERCALL_INPUT,
    HV_STATUS_INVALID_PARAMETER, HV_STATUS_INVALID_PORT_ID, HV_STATUS_OPERATION_DENIED,
    HV_STATUS_TIME_OUT, HV_STATUS_VTL_ALREADY_ENABLED,
};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use thiserror::Error;

/// Errors for Hyper-V hypercalls.
#[derive(Debug, Error, TryFromPrimitive, IntoPrimitive)]
#[non_exhaustive]
#[repr(u32)]
pub enum HypervCallError {
    #[error("invalid hypercall code")]
    InvalidCode = HV_STATUS_INVALID_HYPERCALL_CODE,
    #[error("invalid hypercall input")]
    InvalidInput = HV_STATUS_INVALID_HYPERCALL_INPUT,
    #[error("invalid alignment")]
    InvalidAlignment = HV_STATUS_INVALID_ALIGNMENT,
    #[error("invalid parameter")]
    InvalidParameter = HV_STATUS_INVALID_PARAMETER,
    #[error("access denied")]
    AccessDenied = HV_STATUS_ACCESS_DENIED,
    #[error("operation denied")]
    OperationDenied = HV_STATUS_OPERATION_DENIED,
    #[error("insufficient memory")]
    InsufficientMemory = HV_STATUS_INSUFFICIENT_MEMORY,
    #[error("invalid port ID")]
    InvalidPortID = HV_STATUS_INVALID_PORT_ID,
    #[error("invalid connection ID")]
    InvalidConnectionID = HV_STATUS_INVALID_CONNECTION_ID,
    #[error("insufficient buffers")]
    InsufficientBuffers = HV_STATUS_INSUFFICIENT_BUFFERS,
    #[error("timeout")]
    TimeOut = HV_STATUS_TIME_OUT,
    #[error("VTL already enabled")]
    AlreadyEnabled = HV_STATUS_VTL_ALREADY_ENABLED,
    #[error("unknown hypercall error")]
    Unknown = 0xffff_ffff,
}
```

**Step 2: Replace `HypervCallError` in `litebox_platform_lvbs/src/mshv/hvcall.rs`**

Delete lines 253-284 (the `HypervCallError` enum definition) and add a re-export:

```rust
pub use litebox_common_lvbs::hvcall::HypervCallError;
```

Also remove the now-unused imports of `HV_STATUS_*` constants from the import block at the top of `hvcall.rs` (lines 16-20), since `HypervCallError` no longer references them locally. The remaining code in `hvcall.rs` uses `HV_STATUS_SUCCESS` via `crate::mshv::HV_STATUS_SUCCESS` (which is re-exported).

**Step 3: Verify build**

```bash
cargo build && cargo clippy
```

**Step 4: Commit**

```bash
git add -A
git commit -m "refactor: move HypervCallError to litebox_common_lvbs"
```

---

### Task 4: Move `VerificationError` from `mem_integrity.rs`

**Files:**
- Modify: `litebox_common_lvbs/src/error.rs`
- Modify: `litebox_platform_lvbs/src/mshv/mem_integrity.rs` (lines 678-705)

**Step 1: Populate the `VerificationError` section of `litebox_common_lvbs/src/error.rs`**

Note: this file will also hold `VsmError` in the next task. For now, just add `VerificationError`:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Error types for VSM operations.

use litebox_common_linux::errno::Errno;
use thiserror::Error;

use crate::hvcall::HypervCallError;

/// Errors for module signature verification.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum VerificationError {
    #[error("signature not found in module")]
    SignatureNotFound,
    #[error("invalid signature format")]
    InvalidSignature,
    #[error("invalid certificate")]
    InvalidCertificate,
    #[error("signature authentication failed")]
    AuthenticationFailed,
    #[error("failed to parse signature data")]
    ParseFailed,
    #[error("unsupported signature algorithm")]
    Unsupported,
}

impl From<VerificationError> for Errno {
    fn from(e: VerificationError) -> Self {
        match e {
            VerificationError::AuthenticationFailed => Errno::EKEYREJECTED,
            VerificationError::SignatureNotFound => Errno::ENODATA,
            VerificationError::Unsupported => Errno::ENOPKG,
            VerificationError::InvalidCertificate => Errno::ENOKEY,
            VerificationError::InvalidSignature | VerificationError::ParseFailed => Errno::ELIBBAD,
        }
    }
}
```

**Step 2: Replace in `litebox_platform_lvbs/src/mshv/mem_integrity.rs`**

Delete lines 678-705 (`VerificationError` enum + `From<VerificationError> for Errno`). Add a re-export near the top of the file:

```rust
pub use litebox_common_lvbs::error::VerificationError;
```

Remove the `use litebox_common_linux::errno::Errno;` import from `mem_integrity.rs` if it becomes unused (check if other code in that file still uses `Errno` — the `KernelElfError` type at line 670 does NOT use Errno, so it may become unused).

**Step 3: Verify build**

```bash
cargo build && cargo clippy
```

**Step 4: Commit**

```bash
git add -A
git commit -m "refactor: move VerificationError to litebox_common_lvbs"
```

---

### Task 5: Move `VsmError` from `error.rs`

**Files:**
- Modify: `litebox_common_lvbs/src/error.rs` (add VsmError below VerificationError)
- Modify: `litebox_platform_lvbs/src/mshv/error.rs`

**Step 1: Add `VsmError` to `litebox_common_lvbs/src/error.rs`**

Append below the existing `VerificationError` code:

```rust
/// Errors for Virtual Secure Mode (VSM) operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VsmError {
    // Boot/AP Initialization Errors
    #[error("failed to copy boot signal page from VTL0")]
    BootSignalPageCopyFailed,

    #[error("failed to initialize AP: {0:?}")]
    ApInitFailed(HypervCallError),

    #[error("failed to copy boot signal page to VTL0")]
    BootSignalWriteFailed,

    #[error("failed to copy cpu_online_mask from VTL0")]
    CpuOnlineMaskCopyFailed,

    #[error("code page offset overflow when computing VTL return address")]
    CodePageOffsetOverflow,

    // End-of-Boot Restriction Errors
    #[error("{0} not allowed after end of boot")]
    OperationAfterEndOfBoot(&'static str),

    // Address Validation Errors
    #[error("invalid input address")]
    InvalidInputAddress,

    #[error("address must be page-aligned")]
    AddressNotPageAligned,

    #[error("invalid physical address")]
    InvalidPhysicalAddress,

    // Memory/Data Errors
    #[error("invalid memory attributes")]
    MemoryAttributeInvalid,

    #[error("failed to copy HEKI pages from VTL0")]
    HekiPagesCopyFailed,

    #[error("invalid kernel data type")]
    KernelDataTypeInvalid,

    #[error("invalid module memory type")]
    ModuleMemoryTypeInvalid,

    // Certificate Errors
    #[error("system certificates not loaded")]
    SystemCertificatesNotLoaded,

    #[error("no system certificate found in kernel data")]
    SystemCertificatesNotFound,

    #[error("no valid system certificates parsed")]
    SystemCertificatesInvalid,

    #[error("invalid DER certificate data (expected {expected} bytes, got {actual})")]
    CertificateDerLengthInvalid { expected: usize, actual: usize },

    #[error("failed to parse certificate")]
    CertificateParseFailed,

    // Module Validation Errors
    #[error("module ELF size ({size} bytes) exceeds maximum allowed ({max} bytes)")]
    ModuleElfSizeExceeded { size: usize, max: usize },

    #[error("found unexpected relocations in loaded module")]
    ModuleRelocationInvalid,

    #[error("invalid module token")]
    ModuleTokenInvalid,

    // Kernel Symbol Table Errors
    #[error("no kernel symbol table found")]
    KernelSymbolTableNotFound,

    // Kexec Errors
    #[error("invalid kexec type")]
    KexecTypeInvalid,

    #[error("invalid kexec image segments")]
    KexecImageSegmentsInvalid,

    #[error("invalid kexec segment memory range")]
    KexecSegmentRangeInvalid,

    // Patch Errors
    #[error("precomputed patch data not found")]
    PrecomputedPatchNotFound,

    #[error("text patch validation failed")]
    TextPatchSuspicious,

    // Unsupported Operation Errors
    #[error("{0} is not supported")]
    OperationNotSupported(&'static str),

    // VTL0 Memory Copy Errors
    #[error("failed to copy data to VTL0")]
    Vtl0CopyFailed,

    // Hypercall Errors
    #[error("hypercall failed: {0:?}")]
    HypercallFailed(HypervCallError),

    // Signature Verification Errors
    #[error("signature verification failed: {0:?}")]
    SignatureVerificationFailed(VerificationError),

    // Data Parsing Errors
    #[error("buffer too small for {0}")]
    BufferTooSmall(&'static str),

    // Address/Memory Range Errors
    #[error("invalid virtual address")]
    InvalidVirtualAddress,

    #[error("discontiguous memory range")]
    DiscontiguousMemoryRange,

    // Symbol Table Errors
    #[error("symbol table data empty")]
    SymbolTableEmpty,

    #[error("symbol table data out of range")]
    SymbolTableOutOfRange,

    #[error("symbol table length not aligned to symbol size")]
    SymbolTableLengthInvalid,

    #[error("failed to parse symbol at offset {0:#x}")]
    SymbolParseFailed(usize),

    #[error("symbol name offset out of bounds")]
    SymbolNameOffsetInvalid,

    #[error("symbol name missing NUL terminator")]
    SymbolNameNoTerminator,

    #[error("symbol name exceeds maximum length")]
    SymbolNameTooLong,

    #[error("symbol name contains invalid UTF-8")]
    SymbolNameInvalidUtf8,
}

impl From<VerificationError> for VsmError {
    fn from(e: VerificationError) -> Self {
        VsmError::SignatureVerificationFailed(e)
    }
}

impl From<VsmError> for Errno {
    fn from(e: VsmError) -> Self {
        match e {
            // Address/pointer errors and memory copy failures - memory access fault
            VsmError::InvalidInputAddress
            | VsmError::InvalidPhysicalAddress
            | VsmError::InvalidVirtualAddress
            | VsmError::DiscontiguousMemoryRange
            | VsmError::BootSignalPageCopyFailed
            | VsmError::BootSignalWriteFailed
            | VsmError::CpuOnlineMaskCopyFailed
            | VsmError::HekiPagesCopyFailed
            | VsmError::Vtl0CopyFailed => Errno::EFAULT,

            // Not found errors
            VsmError::SystemCertificatesNotFound
            | VsmError::KernelSymbolTableNotFound
            | VsmError::PrecomputedPatchNotFound => Errno::ENOENT,

            // Operation not permitted after end of boot
            VsmError::OperationAfterEndOfBoot(_) => Errno::EPERM,

            // Unsupported operation
            VsmError::OperationNotSupported(_) => Errno::ENOTSUP,

            // Security/verification failures - access denied
            VsmError::TextPatchSuspicious
            | VsmError::SystemCertificatesInvalid
            | VsmError::SystemCertificatesNotLoaded => Errno::EACCES,

            // Size/range errors
            VsmError::BufferTooSmall(_)
            | VsmError::KexecSegmentRangeInvalid
            | VsmError::ModuleElfSizeExceeded { .. }
            | VsmError::CodePageOffsetOverflow
            | VsmError::SymbolNameTooLong
            | VsmError::SymbolTableOutOfRange => Errno::ERANGE,

            // Init/hardware failures - I/O error
            VsmError::ApInitFailed(_) | VsmError::HypercallFailed(_) => Errno::EIO,

            // True format/validation errors - invalid argument
            VsmError::AddressNotPageAligned
            | VsmError::MemoryAttributeInvalid
            | VsmError::KernelDataTypeInvalid
            | VsmError::ModuleMemoryTypeInvalid
            | VsmError::ModuleRelocationInvalid
            | VsmError::ModuleTokenInvalid
            | VsmError::KexecTypeInvalid
            | VsmError::KexecImageSegmentsInvalid
            | VsmError::SymbolTableEmpty
            | VsmError::SymbolTableLengthInvalid
            | VsmError::SymbolParseFailed(_)
            | VsmError::SymbolNameOffsetInvalid
            | VsmError::SymbolNameInvalidUtf8
            | VsmError::SymbolNameNoTerminator
            | VsmError::CertificateDerLengthInvalid { .. }
            | VsmError::CertificateParseFailed => Errno::EINVAL,

            // Signature verification failures delegate to VerificationError's Errno mapping
            VsmError::SignatureVerificationFailed(e) => Errno::from(e),
        }
    }
}
```

**Step 2: Replace `litebox_platform_lvbs/src/mshv/error.rs` with re-exports**

Replace the entire file content with:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Error types for VSM operations — re-exported from `litebox_common_lvbs`.

pub use litebox_common_lvbs::error::{VerificationError, VsmError};
```

**Step 3: Verify build**

```bash
cargo build && cargo clippy
```

**Step 4: Commit**

```bash
git add -A
git commit -m "refactor: move VsmError to litebox_common_lvbs"
```

---

### Task 6: Move heki types from `heki.rs`

Move `MemAttr`, `mem_attr_to_hv_page_prot_flags`, `HekiKdataType`, `HekiKexecType`, `ModMemType`, `mod_mem_type_to_mem_attr`, `HekiRange` (+ Debug impl), `HEKI_MAX_RANGES`, `HekiPage` (+ Default, IntoIterator), `HekiPatch` (+ `POKE_MAX_OPCODE_SIZE`), and `HekiKernelInfo`.

**Do NOT move:** `HekiPatchType`, `HekiPatchInfo`, `HekiKernelSymbol` — these stay in platform (they depend on `ListHead` from `host/linux.rs`).

**Files:**
- Modify: `litebox_common_lvbs/src/heki.rs`
- Modify: `litebox_platform_lvbs/src/mshv/heki.rs`

**Step 1: Populate `litebox_common_lvbs/src/heki.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! HEKI (Hypervisor Enforced Kernel Integrity) data-only types.

use crate::error::VsmError;
use crate::mem_layout::PAGE_SIZE;
use crate::mshv::HvPageProtFlags;
use core::mem;
use litebox::utils::TruncateExt;
use num_enum::TryFromPrimitive;
use x86_64::{
    structures::paging::{PageSize, Size4KiB},
    PhysAddr, VirtAddr,
};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct MemAttr: u64 {
        const MEM_ATTR_READ = 1 << 0;
        const MEM_ATTR_WRITE = 1 << 1;
        const MEM_ATTR_EXEC = 1 << 2;
        const MEM_ATTR_IMMUTABLE = 1 << 3;

        const _ = !0;
    }
}

pub fn mem_attr_to_hv_page_prot_flags(attr: MemAttr) -> HvPageProtFlags {
    let mut flags = HvPageProtFlags::empty();

    if attr.contains(MemAttr::MEM_ATTR_READ) {
        flags.set(HvPageProtFlags::HV_PAGE_READABLE, true);
        flags.set(HvPageProtFlags::HV_PAGE_USER_EXECUTABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_WRITE) {
        flags.set(HvPageProtFlags::HV_PAGE_WRITABLE, true);
    }
    if attr.contains(MemAttr::MEM_ATTR_EXEC) {
        flags.set(HvPageProtFlags::HV_PAGE_EXECUTABLE, true);
    }

    flags
}

#[derive(Default, Debug, TryFromPrimitive, PartialEq)]
#[repr(u64)]
pub enum HekiKdataType {
    SystemCerts = 0,
    RevocationCerts = 1,
    BlocklistHashes = 2,
    KernelInfo = 3,
    KernelData = 4,
    PatchInfo = 5,
    KexecTrampoline = 6,
    #[default]
    Unknown = 0xffff_ffff_ffff_ffff,
}

#[derive(Default, Debug, TryFromPrimitive, PartialEq)]
#[repr(u64)]
pub enum HekiKexecType {
    KexecImage = 0,
    KexecKernelBlob = 1,
    KexecPages = 2,
    #[default]
    Unknown = 0xffff_ffff_ffff_ffff,
}

#[derive(Clone, Copy, Default, Debug, TryFromPrimitive, PartialEq)]
#[repr(u64)]
pub enum ModMemType {
    Text = 0,
    Data = 1,
    RoData = 2,
    RoAfterInit = 3,
    InitText = 4,
    InitData = 5,
    InitRoData = 6,
    ElfBuffer = 7,
    Patch = 8,
    #[default]
    Unknown = 0xffff_ffff_ffff_ffff,
}

pub fn mod_mem_type_to_mem_attr(mod_mem_type: ModMemType) -> MemAttr {
    let mut mem_attr = MemAttr::empty();

    match mod_mem_type {
        ModMemType::Text | ModMemType::InitText => {
            mem_attr.set(MemAttr::MEM_ATTR_READ, true);
            mem_attr.set(MemAttr::MEM_ATTR_EXEC, true);
        }
        ModMemType::Data | ModMemType::RoAfterInit | ModMemType::InitData => {
            mem_attr.set(MemAttr::MEM_ATTR_READ, true);
            mem_attr.set(MemAttr::MEM_ATTR_WRITE, true);
        }
        ModMemType::RoData | ModMemType::InitRoData => {
            mem_attr.set(MemAttr::MEM_ATTR_READ, true);
        }
        _ => {}
    }

    mem_attr
}

/// `HekiRange` is a generic container for various types of memory ranges.
/// It has an `attributes` field which can be interpreted differently based on the context like
/// `MemAttr`, `KdataType`, `ModMemType`, or `KexecType`.
#[derive(Default, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct HekiRange {
    pub va: u64,
    pub pa: u64,
    pub epa: u64,
    pub attributes: u64,
}

impl HekiRange {
    #[inline]
    pub fn is_aligned<U>(&self, align: U) -> bool
    where
        U: Into<u64> + Copy,
    {
        let va = self.va;
        let pa = self.pa;
        let epa = self.epa;

        VirtAddr::new(va).is_aligned(align)
            && PhysAddr::new(pa).is_aligned(align)
            && PhysAddr::new(epa).is_aligned(align)
    }

    #[inline]
    pub fn mem_attr(&self) -> Option<MemAttr> {
        let attr = self.attributes;
        MemAttr::from_bits(attr)
    }

    #[inline]
    pub fn mod_mem_type(&self) -> ModMemType {
        let attr = self.attributes;
        ModMemType::try_from(attr).unwrap_or(ModMemType::Unknown)
    }

    #[inline]
    pub fn heki_kdata_type(&self) -> HekiKdataType {
        let attr = self.attributes;
        HekiKdataType::try_from(attr).unwrap_or(HekiKdataType::Unknown)
    }

    #[inline]
    pub fn heki_kexec_type(&self) -> HekiKexecType {
        let attr = self.attributes;
        HekiKexecType::try_from(attr).unwrap_or(HekiKexecType::Unknown)
    }

    pub fn is_valid(&self) -> bool {
        let va = self.va;
        let pa = self.pa;
        let epa = self.epa;
        let Ok(pa) = PhysAddr::try_new(pa) else {
            return false;
        };
        let Ok(epa) = PhysAddr::try_new(epa) else {
            return false;
        };
        !(VirtAddr::try_new(va).is_err()
            || epa < pa
            || (self.mem_attr().is_none()
                && self.heki_kdata_type() == HekiKdataType::Unknown
                && self.heki_kexec_type() == HekiKexecType::Unknown
                && self.mod_mem_type() == ModMemType::Unknown))
    }
}

impl core::fmt::Debug for HekiRange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let va = self.va;
        let pa = self.pa;
        let epa = self.epa;
        let attr = self.attributes;
        f.debug_struct("HekiRange")
            .field("va", &format_args!("{va:#x}"))
            .field("pa", &format_args!("{pa:#x}"))
            .field("epa", &format_args!("{epa:#x}"))
            .field("attr", &format_args!("{attr:#x}"))
            .field("type", &format_args!("{:?}", self.heki_kdata_type()))
            .field("size", &format_args!("{:?}", self.epa - self.pa))
            .finish()
    }
}

#[expect(clippy::cast_possible_truncation)]
pub const HEKI_MAX_RANGES: usize =
    ((PAGE_SIZE as u32 - u64::BITS * 3 / 8) / core::mem::size_of::<HekiRange>() as u32) as usize;

#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(align(4096))]
#[repr(C)]
pub struct HekiPage {
    /// Pointer to next page (stored as u64 since we don't dereference it)
    pub next: u64,
    pub next_pa: u64,
    pub nranges: u64,
    pub ranges: [HekiRange; HEKI_MAX_RANGES],
    pad: u64,
}

impl HekiPage {
    pub fn new() -> Self {
        // Safety: all fields are valid when zeroed (u64 zeros, array of zeroed HekiRange)
        Self::new_zeroed()
    }

    pub fn is_valid(&self) -> bool {
        if PhysAddr::try_new(self.next_pa).is_err() {
            return false;
        }
        let Some(nranges) = usize::try_from(self.nranges)
            .ok()
            .filter(|&n| n <= HEKI_MAX_RANGES)
        else {
            return false;
        };
        for heki_range in &self.ranges[..nranges] {
            if !heki_range.is_valid() {
                return false;
            }
        }
        true
    }
}

impl Default for HekiPage {
    fn default() -> Self {
        Self::new_zeroed()
    }
}

impl<'a> IntoIterator for &'a HekiPage {
    type Item = &'a HekiRange;
    type IntoIter = core::slice::Iter<'a, HekiRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges[..usize::try_from(self.nranges).unwrap_or(0)].iter()
    }
}

#[derive(Default, Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct HekiPatch {
    pub pa: [u64; 2],
    pub size: u8,
    pub code: [u8; POKE_MAX_OPCODE_SIZE],
    _padding: [u8; 2],
}
pub const POKE_MAX_OPCODE_SIZE: usize = 5;

impl HekiPatch {
    /// Creates a new `HekiPatch` with a given buffer. Returns `None` if any field is invalid.
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        let patch = Self::read_from_bytes(bytes).ok()?;
        if patch.is_valid() {
            Some(patch)
        } else {
            None
        }
    }

    pub fn is_valid(&self) -> bool {
        let Some(pa_0) = PhysAddr::try_new(self.pa[0])
            .ok()
            .filter(|&pa| !pa.is_null())
        else {
            return false;
        };
        let Some(pa_1) = PhysAddr::try_new(self.pa[1])
            .ok()
            .filter(|&pa| pa.is_null() || pa.is_aligned(Size4KiB::SIZE))
        else {
            return false;
        };
        let bytes_in_first_page = if pa_0.is_aligned(Size4KiB::SIZE) {
            core::cmp::min(PAGE_SIZE, usize::from(self.size))
        } else {
            core::cmp::min(
                (pa_0.align_up(Size4KiB::SIZE) - pa_0).truncate(),
                usize::from(self.size),
            )
        };

        !(self.size == 0
            || usize::from(self.size) > POKE_MAX_OPCODE_SIZE
            || (pa_0 == pa_1)
            || (bytes_in_first_page < usize::from(self.size) && pa_1.is_null())
            || (bytes_in_first_page == usize::from(self.size) && !pa_1.is_null()))
    }
}

#[repr(C)]
#[allow(clippy::struct_field_names)]
pub struct HekiKernelInfo {
    pub ksymtab_start: *const HekiKernelSymbol,
    pub ksymtab_end: *const HekiKernelSymbol,
    pub ksymtab_gpl_start: *const HekiKernelSymbol,
    pub ksymtab_gpl_end: *const HekiKernelSymbol,
    // Skip unused arch info
}

impl HekiKernelInfo {
    const KINFO_LEN: usize = mem::size_of::<HekiKernelInfo>();

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VsmError> {
        if bytes.len() < Self::KINFO_LEN {
            return Err(VsmError::BufferTooSmall("HekiKernelInfo"));
        }

        #[allow(clippy::cast_ptr_alignment)]
        let kinfo_ptr = bytes.as_ptr().cast::<HekiKernelInfo>();
        assert!(kinfo_ptr.is_aligned(), "kinfo_ptr is not aligned");

        // SAFETY: Casting from vtl0 buffer that contained the struct
        unsafe {
            Ok(HekiKernelInfo {
                ksymtab_start: (*kinfo_ptr).ksymtab_start,
                ksymtab_end: (*kinfo_ptr).ksymtab_end,
                ksymtab_gpl_start: (*kinfo_ptr).ksymtab_gpl_start,
                ksymtab_gpl_end: (*kinfo_ptr).ksymtab_gpl_end,
            })
        }
    }
}

/// Kernel symbol structure — used as pointer target for `HekiKernelInfo`.
/// The full struct and its methods stay in `litebox_platform_lvbs::mshv::heki`.
#[repr(C)]
#[allow(clippy::struct_field_names)]
pub struct HekiKernelSymbol {
    pub value_offset: core::ffi::c_int,
    pub name_offset: core::ffi::c_int,
    pub namespace_offset: core::ffi::c_int,
}
```

**Important:** `HekiKernelInfo` has pointer fields to `HekiKernelSymbol`. Since `HekiKernelInfo` is moving, the struct definition for `HekiKernelSymbol` must also be available in the common crate (at minimum as a type for the pointers). We move the struct definition but keep the `from_bytes`, `KSYM_LEN`, and `KSY_NAME_LEN` impls in the platform crate since they depend on `VsmError` which is now in common (so actually they could move too). Let's move the full `HekiKernelSymbol` with all its impls and consts.

Update the above to include full `HekiKernelSymbol`:

```rust
impl HekiKernelSymbol {
    pub const KSYM_LEN: usize = mem::size_of::<HekiKernelSymbol>();
    pub const KSY_NAME_LEN: usize = 512;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VsmError> {
        if bytes.len() < Self::KSYM_LEN {
            return Err(VsmError::BufferTooSmall("HekiKernelSymbol"));
        }

        #[allow(clippy::cast_ptr_alignment)]
        let ksym_ptr = bytes.as_ptr().cast::<HekiKernelSymbol>();
        assert!(ksym_ptr.is_aligned(), "ksym_ptr is not aligned");

        // SAFETY: Casting from vtl0 buffer that contained the struct
        unsafe {
            Ok(HekiKernelSymbol {
                value_offset: (*ksym_ptr).value_offset,
                name_offset: (*ksym_ptr).name_offset,
                namespace_offset: (*ksym_ptr).namespace_offset,
            })
        }
    }
}
```

**Step 2: Replace moved items in `litebox_platform_lvbs/src/mshv/heki.rs`**

Replace the entire file with re-exports + the items that stay:

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

pub use litebox_common_lvbs::heki::{
    mem_attr_to_hv_page_prot_flags, mod_mem_type_to_mem_attr, HekiKdataType, HekiKernelInfo,
    HekiKernelSymbol, HekiKexecType, HekiPage, HekiPatch, HekiRange, MemAttr, ModMemType,
    HEKI_MAX_RANGES, POKE_MAX_OPCODE_SIZE,
};

use crate::host::linux::ListHead;
use crate::mshv::error::VsmError;
use zerocopy::{FromBytes, Immutable, KnownLayout};

// --- Items that stay in platform (depend on ListHead from host/linux.rs) ---

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

**Step 3: Verify build**

```bash
cargo build && cargo clippy
```

**Step 4: Commit**

```bash
git add -A
git commit -m "refactor: move heki data types to litebox_common_lvbs"
```

---

### Task 7: Move `PAGE_SIZE` and `PAGE_SHIFT` to `mem_layout.rs`

**Files:**
- Modify: `litebox_common_lvbs/src/mem_layout.rs`
- Modify: `litebox_platform_lvbs/src/mshv/vtl1_mem_layout.rs`

**Step 1: Populate `litebox_common_lvbs/src/mem_layout.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VTL1 memory layout constants.

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;
```

**Step 2: Add re-exports to `litebox_platform_lvbs/src/mshv/vtl1_mem_layout.rs`**

At the top of the file (after the copyright header and module doc), add:

```rust
pub use litebox_common_lvbs::mem_layout::{PAGE_SIZE, PAGE_SHIFT};
```

And delete the original `PAGE_SIZE` and `PAGE_SHIFT` const definitions (lines 8-9).

**Step 3: Verify build**

```bash
cargo build && cargo clippy
```

**Step 4: Commit**

```bash
git add -A
git commit -m "refactor: move PAGE_SIZE and PAGE_SHIFT to litebox_common_lvbs"
```

---

### Task 8: Move vsm data types (`AlignedPage`, `MODULE_VALIDATION_MAX_SIZE`, `ModuleMemory*`, `KexecMemory*`)

**Files:**
- Modify: `litebox_common_lvbs/src/vsm.rs`
- Modify: `litebox_platform_lvbs/src/mshv/vsm.rs`

**Step 1: Populate `litebox_common_lvbs/src/vsm.rs`**

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VSM data-only types shared between platform and runner.

extern crate alloc;

use alloc::vec::Vec;
use crate::heki::{HekiRange, ModMemType};
use crate::mem_layout::PAGE_SIZE;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{PhysFrame, Size4KiB, frame::PhysFrameRange},
};
use zerocopy::{FromBytes, Immutable, KnownLayout};

#[derive(Copy, Clone, FromBytes, Immutable, KnownLayout)]
#[repr(align(4096))]
pub struct AlignedPage(pub [u8; PAGE_SIZE]);

// For now, we do not validate large kernel modules due to the VTL1's memory size limitation.
pub const MODULE_VALIDATION_MAX_SIZE: usize = 64 * 1024 * 1024;

// --- ModuleMemory types ---

pub struct ModuleMemoryMetadata {
    ranges: Vec<ModuleMemoryRange>,
    patch_targets: Vec<PhysAddr>,
}

impl ModuleMemoryMetadata {
    pub fn new() -> Self {
        Self {
            ranges: Vec::new(),
            patch_targets: Vec::new(),
        }
    }

    #[inline]
    pub fn insert_heki_range(&mut self, heki_range: &HekiRange) {
        let va = heki_range.va;
        let pa = heki_range.pa;
        let epa = heki_range.epa;
        self.insert_memory_range(ModuleMemoryRange::new(
            va,
            pa,
            epa,
            heki_range.mod_mem_type(),
        ));
    }

    #[inline]
    pub fn insert_memory_range(&mut self, mem_range: ModuleMemoryRange) {
        self.ranges.push(mem_range);
    }

    #[inline]
    pub fn insert_patch_target(&mut self, patch_target: PhysAddr) {
        self.patch_targets.push(patch_target);
    }

    // This function returns patch targets belonging to this module to remove them
    // from the precomputed patch data map when the module is unloaded.
    #[inline]
    pub fn get_patch_targets(&self) -> &Vec<PhysAddr> {
        &self.patch_targets
    }
}

impl Default for ModuleMemoryMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleMemoryMetadata {
    /// Returns an iterator over the memory ranges.
    pub fn iter(&self) -> core::slice::Iter<'_, ModuleMemoryRange> {
        self.ranges.iter()
    }
}

impl<'a> IntoIterator for &'a ModuleMemoryMetadata {
    type Item = &'a ModuleMemoryRange;
    type IntoIter = core::slice::Iter<'a, ModuleMemoryRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter()
    }
}

#[derive(Clone, Copy)]
pub struct ModuleMemoryRange {
    pub virt_addr: VirtAddr,
    pub phys_frame_range: PhysFrameRange<Size4KiB>,
    pub mod_mem_type: ModMemType,
}

impl ModuleMemoryRange {
    pub fn new(virt_addr: u64, phys_start: u64, phys_end: u64, mod_mem_type: ModMemType) -> Self {
        Self {
            virt_addr: VirtAddr::new(virt_addr),
            phys_frame_range: PhysFrame::range(
                PhysFrame::containing_address(PhysAddr::new(phys_start)),
                PhysFrame::containing_address(PhysAddr::new(phys_end)),
            ),
            mod_mem_type,
        }
    }
}

impl Default for ModuleMemoryRange {
    fn default() -> Self {
        Self::new(0, 0, 0, ModMemType::Unknown)
    }
}

// --- Kexec memory types ---

pub struct KexecMemoryMetadata {
    ranges: Vec<KexecMemoryRange>,
}

impl KexecMemoryMetadata {
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    #[inline]
    pub fn insert_heki_range(&mut self, heki_range: &HekiRange) {
        let va = heki_range.va;
        let pa = heki_range.pa;
        let epa = heki_range.epa;
        self.insert_memory_range(KexecMemoryRange::new(va, pa, epa));
    }

    #[inline]
    pub fn insert_memory_range(&mut self, mem_range: KexecMemoryRange) {
        self.ranges.push(mem_range);
    }

    #[inline]
    pub fn clear(&mut self) {
        self.ranges.clear();
    }
}

impl Default for KexecMemoryMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl KexecMemoryMetadata {
    /// Returns an iterator over the memory ranges.
    pub fn iter(&self) -> core::slice::Iter<'_, KexecMemoryRange> {
        self.ranges.iter()
    }
}

impl<'a> IntoIterator for &'a KexecMemoryMetadata {
    type Item = &'a KexecMemoryRange;
    type IntoIter = core::slice::Iter<'a, KexecMemoryRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter()
    }
}

#[derive(Clone, Copy)]
pub struct KexecMemoryRange {
    pub virt_addr: VirtAddr,
    pub phys_frame_range: PhysFrameRange<Size4KiB>,
}

impl KexecMemoryRange {
    pub fn new(virt_addr: u64, phys_start: u64, phys_end: u64) -> Self {
        Self {
            virt_addr: VirtAddr::new(virt_addr),
            phys_frame_range: PhysFrame::range(
                PhysFrame::containing_address(PhysAddr::new(phys_start)),
                PhysFrame::containing_address(PhysAddr::new(phys_end)),
            ),
        }
    }
}

impl Default for KexecMemoryRange {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}
```

**Step 2: Replace moved items in `litebox_platform_lvbs/src/mshv/vsm.rs`**

Add re-exports near the top of `vsm.rs`:

```rust
pub use litebox_common_lvbs::vsm::{
    AlignedPage, KexecMemoryMetadata, KexecMemoryRange, ModuleMemoryMetadata, ModuleMemoryRange,
    MODULE_VALIDATION_MAX_SIZE,
};
```

Delete the following from the file:
- `AlignedPage` struct (lines 38-40)
- `MODULE_VALIDATION_MAX_SIZE` const (line 43)
- `ModuleMemoryMetadata` struct + all impls (lines 186-250)
- `ModuleMemoryRange` struct + all impls (lines 252-276)
- `KexecMemoryMetadata` struct + all impls (lines 591-639)
- `KexecMemoryRange` struct + all impls (lines 652-674)

Keep in `vsm.rs` (they depend on platform types like `CpuMask`, `HashMap`, spin locks, `Certificate`, etc.):
- `CPU_ONLINE_MASK`
- `ControlRegMap` + `NUM_CONTROL_REGS`
- `Vtl0KernelInfo`
- `ModuleMemoryMetadataMap` + impls
- `ModuleMemoryMetadataIters`
- `KexecMemoryMetadataWrapper`
- `KexecMemoryMetadataIters`
- `PatchDataMap` + `PatchDataMapError`
- `SymbolTable` + `Symbol`
- `MemoryContainer` + `ModuleMemory` + `MemoryContainerError`

**Step 3: Verify build**

```bash
cargo build && cargo clippy
```

**Step 4: Commit**

```bash
git add -A
git commit -m "refactor: move vsm data types to litebox_common_lvbs"
```

---

### Task 9: Update `litebox_runner_lvbs` imports to use `litebox_common_lvbs`

This task updates the runner's imports so it can eventually depend on `litebox_common_lvbs` directly instead of going through `litebox_platform_lvbs` for data-only types. For now we add the dependency and update `vsm.rs` imports.

**Files:**
- Modify: `litebox_runner_lvbs/Cargo.toml`
- Modify: `litebox_runner_lvbs/src/vsm.rs` (lines 1-55, imports)

**Step 1: Add `litebox_common_lvbs` dependency**

In `litebox_runner_lvbs/Cargo.toml`, add:

```toml
litebox_common_lvbs = { path = "../litebox_common_lvbs/", version = "0.1.0" }
```

**Step 2: Update imports in `litebox_runner_lvbs/src/vsm.rs`**

Change the import block to import data-only types from `litebox_common_lvbs` instead of `litebox_platform_lvbs`. The imports from platform should only be for platform-coupled items (functions, statics, macros).

Replace lines 9-55 with:

```rust
use alloc::vec::Vec;
use litebox::utils::TruncateExt;
use litebox_common_linux::errno::Errno;
use litebox_common_lvbs::{
    error::VsmError,
    heki::{
        mem_attr_to_hv_page_prot_flags, mod_mem_type_to_mem_attr, HekiKdataType,
        HekiKernelInfo, HekiKexecType, HekiPage, HekiPatch, MemAttr, ModMemType,
    },
    hvcall::HypervCallError,
    mshv::{
        HvCrInterceptControlFlags, HvPageProtFlags, HvRegisterVsmPartitionConfig,
        HvRegisterVsmVpSecureVtlConfig, VsmFunction, X86Cr0Flags, X86Cr4Flags,
        HV_REGISTER_CR_INTERCEPT_CONTROL, HV_REGISTER_CR_INTERCEPT_CR0_MASK,
        HV_REGISTER_CR_INTERCEPT_CR4_MASK, HV_REGISTER_VSM_PARTITION_CONFIG,
        HV_REGISTER_VSM_VP_SECURE_CONFIG_VTL0, HV_SECURE_VTL_BOOT_TOKEN,
    },
    mem_layout::{PAGE_SHIFT, PAGE_SIZE},
    vsm::{
        AlignedPage, KexecMemoryMetadata, KexecMemoryRange, ModuleMemoryMetadata,
        MODULE_VALIDATION_MAX_SIZE,
    },
};
#[cfg(debug_assertions)]
use litebox_platform_lvbs::mshv::mem_integrity::parse_modinfo;
use litebox_platform_lvbs::mshv::ringbuffer::set_ringbuffer;
use litebox_platform_lvbs::{
    arch::get_core_id,
    debug_serial_print, debug_serial_println,
    host::{
        bootparam::get_vtl1_memory_info,
        linux::{CpuMask, Kimage, KEXEC_SEGMENT_MAX},
        per_cpu_variables::with_per_cpu_variables_mut,
    },
    mshv::{
        hvcall_mm::hv_modify_vtl_protection_mask,
        hvcall_vp::{hvcall_get_vp_vtl0_registers, hvcall_set_vp_registers, init_vtl_ap},
        mem_integrity::{
            validate_kernel_module_against_elf, validate_text_patch,
            verify_kernel_module_signature, verify_kernel_pe_signature,
        },
        vsm::{CPU_ONLINE_MASK, MemoryContainer, ModuleMemory},
        vtl_switch::mshv_vsm_get_code_page_offsets,
    },
};
use litebox_platform_multiplex::platform;
use x509_cert::{der::Decode, Certificate};
use x86_64::{
    structures::paging::{frame::PhysFrameRange, PageSize, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};
use zerocopy::{FromBytes, FromZeros, IntoBytes};
```

**Step 3: Verify build (code review only — runner requires nightly)**

Since `litebox_runner_lvbs` is excluded from default members, verify the default workspace still builds:

```bash
cargo build && cargo clippy
```

Then manually review the runner imports match the available types.

**Step 4: Commit**

```bash
git add -A
git commit -m "refactor: update litebox_runner_lvbs imports to use litebox_common_lvbs"
```

---

### Task 10: Final verification and cleanup

**Step 1: Full workspace build**

```bash
cargo build
cargo clippy
```

Expected: clean build, no new warnings.

**Step 2: Run tests**

```bash
cargo test
```

The `mod.rs` tests in `litebox_platform_lvbs` should still pass since re-exports make all types available at their original paths.

**Step 3: Review import cleanliness**

Verify that:
1. `litebox_common_lvbs` has NO dependencies on `litebox_platform_lvbs` (no circular dependency)
2. `litebox_platform_lvbs` depends on `litebox_common_lvbs` and re-exports everything
3. `litebox_runner_lvbs` depends on both but imports data-only types from `litebox_common_lvbs`
4. No unused imports in any modified file

**Step 4: Commit any cleanup**

```bash
git add -A
git commit -m "chore: final cleanup after litebox_common_lvbs extraction"
```
