# Phase 4 Design: Migrate Vtl0KernelInfo to the Runner

## Goal

Move `Vtl0KernelInfo` out of `LinuxKernel` (platform) and into `litebox_runner_lvbs` as a standalone global variable. Move all supporting data-only types to `litebox_common_lvbs`. Fully decouple the runner from platform for VTL0 kernel info access.

## Context

All 20+ consumers of `Vtl0KernelInfo` are in `litebox_runner_lvbs/src/vsm.rs`. No platform-internal code accesses it. Currently accessed via `platform().vtl0_kernel_info`.

## Platform-Coupled Blockers and Resolutions

### 1. `ListHead` in `HekiPatchInfo`

`ListHead` is a pure `#[repr(C)]` data struct (two `u64` fields) -- a Linux kernel ABI type with zero platform logic. Move it to `litebox_common_lvbs`. This allows `HekiPatchInfo` and `HekiPatchType` to also move to common.

### 2. `MemoryContainer::write_vtl0_phys_bytes()` calls `platform_low().copy_from_vtl0_phys`

Replace with `NormalWorldConstPtr<AlignedPage, PAGE_SIZE>` (same pattern as Phase 3). `MemoryContainer` then has no platform dependency and moves to the runner.

### 3. `MemoryContainer::extend_range()` uses `debug_serial_println!`

Replace with the runner's own `debug_serial_println!` macro (already available in the runner).

## Type Migration Plan

### To `litebox_common_lvbs` (pure data types)

- `ListHead` (from `host/linux.rs`)
- `HekiPatchInfo`, `HekiPatchType` (from `mshv/heki.rs`)
- `MemoryRange`, `MemoryContainerError`, `PatchDataMapError` (from `mshv/vsm.rs`)
- `Symbol` (from `mshv/vsm.rs`)
- `ControlRegMap` + `HV_X64_REGISTER_*` constants it uses (from `mshv/vsm.rs`)

### To `litebox_runner_lvbs` (logic types needing runtime access)

- `Vtl0KernelInfo` struct definition + `Default` impl
- `MemoryContainer` (with `NormalWorldConstPtr` replacing `platform_low()`)
- `ModuleMemoryMetadataMap`, `ModuleMemoryMetadataIters`
- `ModuleMemory`
- `KexecMemoryMetadataWrapper`, `KexecMemoryMetadataIters`
- `PatchDataMap`
- `SymbolTable`

### Stays in `litebox_platform_lvbs`

- `CpuMask`, `CPU_ONLINE_MASK`
- `Kimage`, `KexecSegment`, `KEXEC_SEGMENT_MAX`

### Removed from `litebox_platform_lvbs`

- `vtl0_kernel_info` field from `LinuxKernel`
- `Vtl0KernelInfo` construction from `setup()`

## Runner Global Design

### Static variable

```rust
static VTL0_KERNEL_INFO: OnceCell<Vtl0KernelInfo> = OnceCell::new();
```

### Init function (called from `vsm::init()`)

```rust
pub fn init_vtl0_kernel_info() {
    VTL0_KERNEL_INFO.set(Vtl0KernelInfo::default())
        .expect("vtl0_kernel_info already initialized");
}
```

### Accessor

```rust
pub fn vtl0_kernel_info() -> &'static Vtl0KernelInfo {
    VTL0_KERNEL_INFO.get().expect("vtl0_kernel_info not initialized")
}
```

### Construction

Runner owns construction entirely. `Vtl0KernelInfo::default()` creates empty containers. Data is populated later by VSM dispatch functions. Platform does not touch it.

## Consumer Migration

All 20+ access sites in `vsm.rs` change:

```rust
// Before
platform().vtl0_kernel_info.field

// After
vtl0_kernel_info().field
```

## Re-exports

Data-only types moved to `litebox_common_lvbs` are re-exported from `litebox_platform_lvbs` for external consumer compatibility.

Types moved to the runner (`Vtl0KernelInfo`, `MemoryContainer`, etc.) are NOT re-exported from platform -- they become runner-internal.
