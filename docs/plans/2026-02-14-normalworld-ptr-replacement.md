# Replace `copy_from/to_vtl0_phys` with `NormalWorldConstPtr`/`NormalWorldMutPtr` Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace all 10 `platform().copy_from/to_vtl0_phys` call sites in `litebox_runner_lvbs/src/vsm.rs` with the `NormalWorldConstPtr`/`NormalWorldMutPtr` API from `litebox_shim_optee`, eliminating the runner's dependency on platform-specific copy functions.

**Architecture:** The `NormalWorldConstPtr<T, ALIGN>` and `NormalWorldMutPtr<T, ALIGN>` types (aliases for `PhysConstPtr`/`PhysMutPtr`) provide a type-safe way to read/write VTL0 physical memory. They use the same underlying `memcpy_fallible` mechanism as `copy_from/to_vtl0_phys` but go through `VmapManager` instead of `map_vtl0_guard`. The ALIGN parameter should always be `PAGE_SIZE` (4096). Both APIs handle cross-page access internally via `with_contiguous_pages`.

**Tech Stack:** Rust no_std, `litebox_shim_optee::NormalWorldConstPtr`/`NormalWorldMutPtr`, `litebox_common_linux::vmap::PhysPointerError`

**Verification:** `cargo build` + `cargo clippy` on default workspace members. `litebox_runner_lvbs` is excluded from default build (requires nightly + custom target), so verification is build of other crates + code review of runner changes.

---

## API Mapping Reference

| Old API | New API | Notes |
|---|---|---|
| `platform().copy_from_vtl0_phys::<T>(pa)` → `Option<Box<T>>` | `NormalWorldConstPtr::<T, PAGE_SIZE>::with_usize(pa.as_u64() as usize)?.read_at_offset(0)` → `Result<Box<T>, PhysPointerError>` | Use `.ok()` to get `Option<Box<T>>` |
| `platform().copy_to_vtl0_phys::<T>(pa, &val)` → `bool` | `NormalWorldMutPtr::<T, PAGE_SIZE>::with_usize(pa.as_u64() as usize)?.write_at_offset(0, val)` → `Result<(), PhysPointerError>` | Use `.is_ok()` to get `bool`. Note: `write_at_offset` takes `value: T` by value, not `&T` |
| `platform().copy_slice_from_vtl0_phys(pa, buf)` → `bool` | `NormalWorldConstPtr::<T, PAGE_SIZE>::with_contiguous_pages(pa.as_u64() as usize, size)?.read_slice_at_offset(0, buf)` → `Result<(), PhysPointerError>` | Use `.is_ok()` for bool. Need `with_contiguous_pages` because slice may span multiple pages |
| `platform().copy_slice_to_vtl0_phys(pa, slice)` → `bool` | `NormalWorldMutPtr::<T, PAGE_SIZE>::with_contiguous_pages(pa.as_u64() as usize, size)?.write_slice_at_offset(0, slice)` → `Result<(), PhysPointerError>` | Same as above |

## Type Requirements

`PhysConstPtr<T, ALIGN>` and `PhysMutPtr<T, ALIGN>` require `T: Clone`. All types used at call sites already derive `Clone`:
- `CpuMask`: `#[derive(Clone, Copy, FromBytes, ...)]`
- `AlignedPage`: `#[derive(Copy, Clone, FromBytes, ...)]`
- `HekiPatch`: `#[derive(Clone, Copy, FromBytes, ...)]`
- `HekiPage`: `#[derive(Clone, Copy, FromBytes, ...)]`
- `u8` (slices): implements `Clone`

## All 10 Call Sites

1. **Line 117**: `copy_from_vtl0_phys::<CpuMask>(cpu_online_mask_page_addr)` — read CpuMask
2. **Line 130**: `copy_from_vtl0_phys::<AlignedPage>(boot_signal_page_addr)` — read AlignedPage
3. **Line 158**: `copy_to_vtl0_phys::<AlignedPage>(boot_signal_page_addr, &boot_signal_page_buf)` — write AlignedPage
4. **Line 834**: `copy_from_vtl0_phys::<HekiPatch>(patch_pa_0)` — read HekiPatch
5. **Line 841**: `copy_slice_from_vtl0_phys(patch_pa_0, heki_patch_bytes[..bytes_in_first_page])` — read byte slice (first page)
6. **Line 844**: `copy_slice_from_vtl0_phys(patch_pa_1, heki_patch_bytes[bytes_in_first_page..])` — read byte slice (second page)
7. **Line 873**: `copy_slice_to_vtl0_phys(heki_patch_pa_0, &heki_patch.code[..size])` — write byte slice
8. **Line 884**: `copy_slice_to_vtl0_phys(heki_patch_pa_0 + offset, patch_first)` — write byte slice (first page)
9. **Line 887**: `copy_slice_to_vtl0_phys(heki_patch_pa_1, patch_second)` — write byte slice (second page)
10. **Line 965**: `copy_from_vtl0_phys::<HekiPage>(next_pa)` — read HekiPage

---

### Task 1: Add `NormalWorldConstPtr`/`NormalWorldMutPtr` imports to vsm.rs

**Files:**
- Modify: `litebox_runner_lvbs/src/vsm.rs:1-61` (import block)

**Step 1: Update imports**

In `litebox_runner_lvbs/src/vsm.rs`, add the import for `NormalWorldConstPtr` and `NormalWorldMutPtr` (they are already imported in `lib.rs` line 45, but `vsm.rs` needs its own `use`):

```rust
use litebox_shim_optee::{NormalWorldConstPtr, NormalWorldMutPtr};
```

Add this after the existing `use litebox_platform_multiplex::platform;` line (line 54).

Also add `PAGE_SIZE as usize` as a const for the ALIGN parameter if needed. `PAGE_SIZE` is already imported from `litebox_common_lvbs::mem_layout` (line 19) as `usize`, so it can be used directly as the const generic.

**Step 2: Verify the file compiles**

This is import-only; no functional changes. Verify no conflicts.

**Step 3: Commit**

```
git add litebox_runner_lvbs/src/vsm.rs
git commit -m "refactor: add NormalWorldConstPtr/MutPtr imports to vsm.rs"
```

---

### Task 2: Replace `copy_from_vtl0_phys` calls in `mshv_vsm_boot_aps` (call sites 1, 2)

**Files:**
- Modify: `litebox_runner_lvbs/src/vsm.rs:109-164` (function `mshv_vsm_boot_aps`)

**Step 1: Replace call site 1 (line 116-120)**

Old code:
```rust
    let Some(cpu_mask) =
        (unsafe { platform().copy_from_vtl0_phys::<CpuMask>(cpu_online_mask_page_addr) })
    else {
        return Err(VsmError::CpuOnlineMaskCopyFailed);
    };
```

New code:
```rust
    let cpu_mask = unsafe {
        NormalWorldConstPtr::<CpuMask, PAGE_SIZE>::with_usize(
            cpu_online_mask_page_addr.as_u64() as usize,
        )
        .and_then(|mut ptr| ptr.read_at_offset(0))
        .map_err(|_| VsmError::CpuOnlineMaskCopyFailed)?
    };
```

Note: This changes `cpu_mask` from `Box<CpuMask>` to `Box<CpuMask>` (same type). The downstream usage on line 123 calls `cpu_mask.for_each_cpu(...)` and line 155 `CPU_ONLINE_MASK.call_once(|| cpu_mask)` which takes ownership of the Box — this works because `CPU_ONLINE_MASK` is `OnceCell<Box<CpuMask>>` (check). If it takes `CpuMask` directly, we need `*cpu_mask`.

Actually, check what `CPU_ONLINE_MASK.call_once` expects. It's `once_cell::race::OnceBox` or similar. The original code passes `cpu_mask` (a `Box<CpuMask>`) which auto-derefs for `.for_each_cpu()`. Look at line 155: `CPU_ONLINE_MASK.call_once(|| cpu_mask)` — since `copy_from_vtl0_phys` returns `Option<Box<CpuMask>>`, `cpu_mask` is `Box<CpuMask>`. The new `read_at_offset(0)` also returns `Result<Box<CpuMask>, _>`, so after `.map_err(...)` and `?`, `cpu_mask` is still `Box<CpuMask>`. No downstream changes needed.

**Step 2: Replace call site 2 (line 129-133)**

Old code:
```rust
    let Some(mut boot_signal_page_buf) =
        (unsafe { platform().copy_from_vtl0_phys::<AlignedPage>(boot_signal_page_addr) })
    else {
        return Err(VsmError::BootSignalPageCopyFailed);
    };
```

New code:
```rust
    let mut boot_signal_page_buf = unsafe {
        NormalWorldConstPtr::<AlignedPage, PAGE_SIZE>::with_usize(
            boot_signal_page_addr.as_u64() as usize,
        )
        .and_then(|mut ptr| ptr.read_at_offset(0))
        .map_err(|_| VsmError::BootSignalPageCopyFailed)?
    };
```

**Step 3: Commit**

```
git add litebox_runner_lvbs/src/vsm.rs
git commit -m "refactor: replace copy_from_vtl0_phys with NormalWorldConstPtr in boot_aps"
```

---

### Task 3: Replace `copy_to_vtl0_phys` call in `mshv_vsm_boot_aps` (call site 3)

**Files:**
- Modify: `litebox_runner_lvbs/src/vsm.rs:157-163`

**Step 1: Replace call site 3 (line 157-163)**

Old code:
```rust
    if unsafe {
        platform().copy_to_vtl0_phys::<AlignedPage>(boot_signal_page_addr, &boot_signal_page_buf)
    } {
        Ok(0)
    } else {
        Err(VsmError::BootSignalWriteFailed)
    }
```

New code:
```rust
    unsafe {
        NormalWorldMutPtr::<AlignedPage, PAGE_SIZE>::with_usize(
            boot_signal_page_addr.as_u64() as usize,
        )
        .and_then(|mut ptr| ptr.write_at_offset(0, *boot_signal_page_buf))
        .map_err(|_| VsmError::BootSignalWriteFailed)?;
    }
    Ok(0)
```

Note: `write_at_offset(0, value)` takes `T` by value. `boot_signal_page_buf` is `Box<AlignedPage>`, so we dereference with `*boot_signal_page_buf` to get the `AlignedPage` value. `AlignedPage` is `Copy`, so this is fine.

**Step 2: Commit**

```
git add litebox_runner_lvbs/src/vsm.rs
git commit -m "refactor: replace copy_to_vtl0_phys with NormalWorldMutPtr in boot_aps"
```

---

### Task 4: Replace `copy_from_vtl0_phys` call in `get_vtl0_text_patch` (call site 4)

**Files:**
- Modify: `litebox_runner_lvbs/src/vsm.rs:831-836`

**Step 1: Replace call site 4 (lines 834-836)**

Old code:
```rust
        unsafe { platform().copy_from_vtl0_phys::<HekiPatch>(patch_pa_0) }
            .map(|boxed| *boxed)
            .ok_or(VsmError::Vtl0CopyFailed)
```

New code:
```rust
        unsafe {
            NormalWorldConstPtr::<HekiPatch, PAGE_SIZE>::with_usize(patch_pa_0.as_u64() as usize)
                .and_then(|mut ptr| ptr.read_at_offset(0))
                .map(|boxed| *boxed)
                .map_err(|_| VsmError::Vtl0CopyFailed)
        }
```

**Step 2: Commit**

```
git add litebox_runner_lvbs/src/vsm.rs
git commit -m "refactor: replace copy_from_vtl0_phys with NormalWorldConstPtr in get_vtl0_text_patch"
```

---

### Task 5: Replace `copy_slice_from_vtl0_phys` calls in `get_vtl0_text_patch` (call sites 5, 6)

**Files:**
- Modify: `litebox_runner_lvbs/src/vsm.rs:838-850`

**Step 1: Replace call sites 5 and 6 (lines 840-850)**

Old code:
```rust
        let mut heki_patch = HekiPatch::new_zeroed();
        let heki_patch_bytes = heki_patch.as_mut_bytes();
        unsafe {
            if !platform().copy_slice_from_vtl0_phys(
                patch_pa_0,
                heki_patch_bytes.get_unchecked_mut(..bytes_in_first_page),
            ) || !platform().copy_slice_from_vtl0_phys(
                patch_pa_1,
                heki_patch_bytes.get_unchecked_mut(bytes_in_first_page..),
            ) {
                return Err(VsmError::Vtl0CopyFailed);
            }
        }
```

New code:
```rust
        let mut heki_patch = HekiPatch::new_zeroed();
        let heki_patch_bytes = heki_patch.as_mut_bytes();
        unsafe {
            let first_slice = heki_patch_bytes.get_unchecked_mut(..bytes_in_first_page);
            NormalWorldConstPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
                patch_pa_0.as_u64() as usize,
                first_slice.len(),
            )
            .and_then(|mut ptr| ptr.read_slice_at_offset(0, first_slice))
            .map_err(|_| VsmError::Vtl0CopyFailed)?;

            let second_slice = heki_patch_bytes.get_unchecked_mut(bytes_in_first_page..);
            NormalWorldConstPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
                patch_pa_1.as_u64() as usize,
                second_slice.len(),
            )
            .and_then(|mut ptr| ptr.read_slice_at_offset(0, second_slice))
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        }
```

Note: For slice operations, we use `with_contiguous_pages(pa, byte_len)` instead of `with_usize(pa)` because the slice may have a different length than `size_of::<T>()`. The `read_slice_at_offset(0, buf)` reads `buf.len()` elements of `T` starting at element index 0.

**Step 2: Commit**

```
git add litebox_runner_lvbs/src/vsm.rs
git commit -m "refactor: replace copy_slice_from_vtl0_phys with NormalWorldConstPtr in get_vtl0_text_patch"
```

---

### Task 6: Replace `copy_slice_to_vtl0_phys` calls in `apply_vtl0_text_patch` (call sites 7, 8, 9)

**Files:**
- Modify: `litebox_runner_lvbs/src/vsm.rs:861-894` (function `apply_vtl0_text_patch`)

**Step 1: Replace call site 7 (lines 872-879)**

Old code:
```rust
        if !unsafe {
            platform().copy_slice_to_vtl0_phys(
                heki_patch_pa_0,
                &heki_patch.code[..usize::from(heki_patch.size)],
            )
        } {
            return Err(VsmError::Vtl0CopyFailed);
        }
```

New code:
```rust
        let code_slice = &heki_patch.code[..usize::from(heki_patch.size)];
        unsafe {
            NormalWorldMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
                heki_patch_pa_0.as_u64() as usize,
                code_slice.len(),
            )
            .and_then(|mut ptr| ptr.write_slice_at_offset(0, code_slice))
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        }
```

**Step 2: Replace call sites 8 and 9 (lines 883-891)**

Old code:
```rust
        let (patch_first, patch_second) = heki_patch.code.split_at(bytes_in_first_page);

        unsafe {
            if !platform().copy_slice_to_vtl0_phys(
                heki_patch_pa_0 + patch_target_page_offset as u64,
                patch_first,
            ) || !platform().copy_slice_to_vtl0_phys(heki_patch_pa_1, patch_second)
            {
                return Err(VsmError::Vtl0CopyFailed);
            }
        }
```

New code:
```rust
        let (patch_first, patch_second) = heki_patch.code.split_at(bytes_in_first_page);

        unsafe {
            NormalWorldMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
                (heki_patch_pa_0 + patch_target_page_offset as u64).as_u64() as usize,
                patch_first.len(),
            )
            .and_then(|mut ptr| ptr.write_slice_at_offset(0, patch_first))
            .map_err(|_| VsmError::Vtl0CopyFailed)?;

            NormalWorldMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
                heki_patch_pa_1.as_u64() as usize,
                patch_second.len(),
            )
            .and_then(|mut ptr| ptr.write_slice_at_offset(0, patch_second))
            .map_err(|_| VsmError::Vtl0CopyFailed)?;
        }
```

**Step 3: Commit**

```
git add litebox_runner_lvbs/src/vsm.rs
git commit -m "refactor: replace copy_slice_to_vtl0_phys with NormalWorldMutPtr in apply_vtl0_text_patch"
```

---

### Task 7: Replace `copy_from_vtl0_phys` call in `copy_heki_pages_from_vtl0` (call site 10)

**Files:**
- Modify: `litebox_runner_lvbs/src/vsm.rs:959-976` (function `copy_heki_pages_from_vtl0`)

**Step 1: Replace call site 10 (line 965)**

Old code:
```rust
        let heki_page = (unsafe { platform().copy_from_vtl0_phys::<HekiPage>(next_pa) })?;
```

New code:
```rust
        let heki_page = unsafe {
            NormalWorldConstPtr::<HekiPage, PAGE_SIZE>::with_usize(next_pa.as_u64() as usize)
                .and_then(|mut ptr| ptr.read_at_offset(0))
                .ok()?
        };
```

Note: The original returns `Option` (using `?` on `Option`). The new code converts `Result` to `Option` via `.ok()`, then uses `?` to propagate `None`.

**Step 2: Commit**

```
git add litebox_runner_lvbs/src/vsm.rs
git commit -m "refactor: replace copy_from_vtl0_phys with NormalWorldConstPtr in copy_heki_pages_from_vtl0"
```

---

### Task 8: Remove unused `platform` import if no longer needed

**Files:**
- Modify: `litebox_runner_lvbs/src/vsm.rs:54` (import line)

**Step 1: Check if `platform()` is still used elsewhere in vsm.rs**

Search for remaining uses of `platform()` in the file. The `platform()` function is used in other places beyond `copy_from/to_vtl0_phys`:
- `platform().vtl0_kernel_info` (multiple places)
- Other platform calls

If `platform()` is still used, keep the import. If not, remove line 54: `use litebox_platform_multiplex::platform;`.

**Step 2: Check if `NormalWorldConstPtr`/`NormalWorldMutPtr` import in `lib.rs` line 45 is still needed**

The import `use litebox_shim_optee::{NormalWorldConstPtr, NormalWorldMutPtr, UserConstPtr};` in `lib.rs` is used by other parts of the runner (not just vsm.rs). Leave it as is.

**Step 3: Commit (only if changes were made)**

```
git add litebox_runner_lvbs/src/vsm.rs
git commit -m "refactor: clean up unused imports in vsm.rs after NormalWorldPtr migration"
```

---

### Task 9: Verify build and clippy

**Step 1: Run cargo build**

```bash
cargo build
```

Expected: Clean build (0 errors, 0 warnings from our crates).

**Step 2: Run cargo clippy**

```bash
cargo clippy
```

Expected: Only pre-existing warnings (missing panics docs, into_iter_without_iter), no new warnings from our changes.

**Step 3: Run cargo test**

```bash
cargo test
```

Expected: All tests pass except pre-existing failures in `litebox_runner_linux_userland`.
