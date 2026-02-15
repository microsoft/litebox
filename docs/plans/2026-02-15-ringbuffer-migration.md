# Ringbuffer Migration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Move `ringbuffer.rs` from `litebox_platform_lvbs` to `litebox_runner_lvbs`, replacing `copy_slice_to_vtl0_phys` with `NormalWorldMutPtr`, and use a function pointer so platform's `ioport::print()` can still dual-output to the ring buffer.

**Architecture:** The ring buffer currently lives in platform and uses `platform_low().copy_slice_to_vtl0_phys()` for physical memory writes. We replace that with `NormalWorldMutPtr::write_slice_at_offset()` (no platform dependency). Since `ioport::print()` (platform) needs to call into the ring buffer (runner), we add a `static PRINT_HOOK: AtomicPtr<()>` in platform that the runner sets to a `fn(fmt::Arguments)` after initializing the ring buffer.

**Tech Stack:** Rust, `no_std`, `x86_64`, `spin` crate, `NormalWorldMutPtr` from `litebox_shim_optee`

---

### Task 1: Add print hook to ioport.rs

**Files:**
- Modify: `litebox_platform_lvbs/src/arch/x86/ioport.rs`

**Step 1: Replace `ringbuffer` import with `AtomicPtr` and add the hook**

Replace the `ringbuffer` import and add a function pointer mechanism. The `print()` function will call through the hook instead of directly calling `ringbuffer()`.

In `litebox_platform_lvbs/src/arch/x86/ioport.rs`:

Remove line 6:
```rust
use crate::mshv::ringbuffer::ringbuffer;
```

Add import:
```rust
use core::sync::atomic::{AtomicPtr, Ordering};
```

Add the hook global and registration function (before `print()`):
```rust
/// Function pointer hook for auxiliary print output (e.g., ring buffer).
/// Set by the runner after initializing the ring buffer.
static PRINT_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Register a print hook function that will be called with every `print()` invocation.
///
/// # Safety
///
/// `hook` must point to a function with signature `fn(fmt::Arguments)` that is safe to call
/// from any context where `print()` is called.
pub unsafe fn register_print_hook(hook: fn(fmt::Arguments)) {
    PRINT_HOOK.store(hook as *mut (), Ordering::Release);
}
```

Replace the `print()` function body (lines 152-159):
```rust
#[doc(hidden)]
pub fn print(args: ::core::fmt::Arguments) {
    use core::fmt::Write;
    let _ = com().lock().write_fmt(args);
    let hook = PRINT_HOOK.load(Ordering::Acquire);
    if !hook.is_null() {
        let f: fn(fmt::Arguments) = unsafe { core::mem::transmute(hook) };
        f(args);
    }
}
```

**Step 2: Verify build**

Run: `cargo build`
Expected: Success (ringbuffer module still exists but `ioport.rs` no longer imports from it)

**Step 3: Commit**

```
git add litebox_platform_lvbs/src/arch/x86/ioport.rs
git commit -m "Replace direct ringbuffer call in ioport::print with function pointer hook"
```

---

### Task 2: Move ringbuffer.rs to runner with NormalWorldMutPtr

**Files:**
- Create: `litebox_runner_lvbs/src/ringbuffer.rs`
- Modify: `litebox_runner_lvbs/src/lib.rs` (add `mod ringbuffer;`)

**Step 1: Create `litebox_runner_lvbs/src/ringbuffer.rs`**

Rewrite `RingBuffer::write()` to use `NormalWorldMutPtr` instead of `copy_slice_to_vtl0_phys`. Also add the `print_to_ringbuffer` function that will be registered as the print hook.

```rust
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! RingBuffer implementation backed by VTL0 physical memory.
//!
//! Migrated from `litebox_platform_lvbs::mshv::ringbuffer`.
//! Uses `NormalWorldMutPtr` instead of `platform_low().copy_slice_to_vtl0_phys()`.

use core::fmt;
use litebox::utils::TruncateExt;
use litebox_common_lvbs::mem_layout::PAGE_SIZE;
use litebox_shim_optee::NormalWorldMutPtr;
use spin::{Mutex, Once};
use x86_64::PhysAddr;

pub struct RingBuffer {
    rb_pa: PhysAddr,
    write_offset: usize,
    size: usize,
}

impl RingBuffer {
    pub fn new(phys_addr: PhysAddr, requested_size: usize) -> Self {
        RingBuffer {
            rb_pa: phys_addr,
            write_offset: 0,
            size: requested_size,
        }
    }

    fn copy_slice_to_vtl0(&self, pa: PhysAddr, buf: &[u8]) {
        if buf.is_empty() {
            return;
        }
        // Best-effort write; ignore errors (matches original behavior which ignored the bool return).
        let _ = unsafe {
            NormalWorldMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
                pa.as_u64().truncate(),
                buf.len(),
            )
            .and_then(|mut ptr| ptr.write_slice_at_offset(0, buf))
        };
    }

    pub fn write(&mut self, buf: &[u8]) {
        // If the input buffer is longer than the ring buffer, fill the whole ring buffer with
        // the final [ring buffer size] values from the input buffer
        if buf.len() >= self.size {
            let single_slice = &buf[(buf.len() - self.size)..];
            self.copy_slice_to_vtl0(self.rb_pa, single_slice);
            self.write_offset = 0;
            return;
        }

        // Otherwise, calculate if wraparound needed
        let space_remaining: usize = self.size - self.write_offset;
        if buf.len() > space_remaining {
            let first_slice = &buf[..space_remaining];
            let wraparound_slice = &buf[space_remaining..];
            self.copy_slice_to_vtl0(self.rb_pa + self.write_offset as u64, first_slice);
            self.copy_slice_to_vtl0(self.rb_pa, wraparound_slice);
        } else {
            self.copy_slice_to_vtl0(self.rb_pa + self.write_offset as u64, buf);
        }
        self.write_offset = (self.write_offset + buf.len()) % self.size;
    }
}

impl fmt::Write for RingBuffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s.as_bytes());
        Ok(())
    }
}

static RINGBUFFER_ONCE: Once<Mutex<RingBuffer>> = Once::new();

pub fn set_ringbuffer(pa: PhysAddr, size: usize) -> &'static Mutex<RingBuffer> {
    RINGBUFFER_ONCE.call_once(|| {
        let ring_buffer = RingBuffer::new(pa, size);
        Mutex::new(ring_buffer)
    })
}

fn ringbuffer() -> Option<&'static Mutex<RingBuffer>> {
    RINGBUFFER_ONCE.get()
}

/// Print hook function registered with `ioport::register_print_hook`.
/// Called by platform's `print()` to mirror output to the ring buffer.
pub fn print_to_ringbuffer(args: fmt::Arguments) {
    if let Some(rb) = ringbuffer() {
        use fmt::Write;
        let _ = rb.lock().write_fmt(args);
    }
}
```

**Step 2: Add `mod ringbuffer;` to `litebox_runner_lvbs/src/lib.rs`**

Add after the existing `mod vsm;` line:
```rust
mod ringbuffer;
```

**Step 3: Verify build**

Run: `cargo build`
Expected: Success (new module compiles but isn't wired up yet)

**Step 4: Commit**

```
git add litebox_runner_lvbs/src/ringbuffer.rs litebox_runner_lvbs/src/lib.rs
git commit -m "Add ringbuffer module to runner using NormalWorldMutPtr"
```

---

### Task 3: Wire up runner to use new ringbuffer and register print hook

**Files:**
- Modify: `litebox_runner_lvbs/src/vsm.rs`

**Step 1: Update imports in vsm.rs**

Remove:
```rust
use litebox_platform_lvbs::mshv::ringbuffer::set_ringbuffer;
```

Add:
```rust
use crate::ringbuffer::set_ringbuffer;
```

**Step 2: Register the print hook after `set_ringbuffer` in `mshv_vsm_allocate_ringbuffer_memory`**

In `mshv_vsm_allocate_ringbuffer_memory`, after the `set_ringbuffer` call, register the print hook:

```rust
fn mshv_vsm_allocate_ringbuffer_memory(phys_addr: u64, size: usize) -> Result<i64, VsmError> {
    set_ringbuffer(PhysAddr::new(phys_addr), size);
    // Register the ring buffer print hook so ioport::print() mirrors output here.
    unsafe {
        litebox_platform_lvbs::arch::ioport::register_print_hook(
            crate::ringbuffer::print_to_ringbuffer,
        );
    }
    protect_physical_memory_range(
    // ... rest unchanged
```

**Step 3: Verify build**

Run: `cargo build`
Expected: Success

**Step 4: Commit**

```
git add litebox_runner_lvbs/src/vsm.rs
git commit -m "Wire runner ringbuffer to platform print hook"
```

---

### Task 4: Clean up platform — delete ringbuffer.rs and remove module

**Files:**
- Delete: `litebox_platform_lvbs/src/mshv/ringbuffer.rs`
- Modify: `litebox_platform_lvbs/src/mshv/mod.rs` (remove `pub mod ringbuffer;`)

**Step 1: Delete the old ringbuffer.rs**

```bash
rm litebox_platform_lvbs/src/mshv/ringbuffer.rs
```

**Step 2: Remove `pub mod ringbuffer;` from `litebox_platform_lvbs/src/mshv/mod.rs`**

Delete line 9:
```rust
pub mod ringbuffer;
```

**Step 3: Check for remaining references**

Search for `ringbuffer` in the workspace. Expect: only `litebox_runner_lvbs/src/ringbuffer.rs`, `litebox_runner_lvbs/src/vsm.rs`, `litebox_runner_lvbs/src/lib.rs`, and doc files.

**Step 4: Remove `copy_slice_to_vtl0_phys` from platform if no longer used**

Check if `copy_slice_to_vtl0_phys` has any remaining consumers. If not, delete it from `litebox_platform_lvbs/src/lib.rs`.

**Step 5: Verify build + clippy**

Run: `cargo build && cargo clippy && cargo clippy -p litebox_runner_lvbs`
Expected: Success, no new warnings

**Step 6: Commit**

```
git add -A
git commit -m "Remove ringbuffer.rs and copy_slice_to_vtl0_phys from platform"
```

---

### Task 5: Final verification

**Step 1: Full verification**

Run:
```bash
cargo build && cargo clippy && cargo test
```
Expected: All pass (same pre-existing test failures in `litebox_runner_linux_userland` only).

**Step 2: Update ratchet test if needed**

Check `dev_tests/src/ratchet.rs` — the platform static count may have decreased (lost `RINGBUFFER_ONCE`) and no change to runner (gained `RINGBUFFER_ONCE` + `PRINT_HOOK` but `PRINT_HOOK` is in platform). Verify the counts and update if needed.
