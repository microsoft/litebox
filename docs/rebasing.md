# Rebase Conflict Log

This document records all conflicts encountered when rebasing
`Vadiml1024/litebox:main` onto `microsoft/litebox:main`.

**Resolution strategy**: All conflicts were resolved by keeping the fork's (Vadiml1024) version.
Items below should be reviewed to ensure upstream changes are properly integrated where needed.

**Total conflicting files**: 13

---

## `.github/workflows/ci.yml`

### Conflict 1 (around line 34)

**Fork's version (kept):**
```
        uses: actions/setup-node@v4
        with:
          node-version: '20'
```

**Upstream's version (discarded):**
```
        uses: actions/setup-node@v6
```

### Conflict 2 (around line 88)

**Fork's version (kept):**
```

```

**Upstream's version (discarded):**
```
  build_and_test_32bit:
    name: Build and Test (32-bit)
    runs-on: ubuntu-latest
    env:
      RUSTFLAGS: -Dwarnings
    steps:
      - name: Check out repo
        uses: actions/checkout@v6
      - run: sudo apt update && sudo apt install -y gcc-multilib
      - name: Set up Rust
        run: |
          rustup toolchain install $(awk -F'"' '/channel/{print $2}' rust-toolchain.toml) --profile minimal --no-self-update --component rustfmt,clippy --target i686-unknown-linux-gnu
      - name: Set up Nextest
        uses: taiki-e/install-action@v2
        with:
          tool: nextest@${{ env.NEXTEST_VERSION }}
      - name: Install diod
        run: |
          sudo apt install -y diod
      - name: Set up tun
        run: |
          sudo ./litebox_platform_linux_userland/scripts/tun-setup.sh
      - uses: Swatinem/rust-cache@v2
      - name: Cache custom out directories
        uses: actions/cache@v5
        with:
          path: |
            target/*/build/litebox_runner_linux_userland-*/out
          key: custom-out-${{ runner.os }}-${{ github.job }}-${{ hashFiles('**/Cargo.lock') }}-${{ hashFiles('**/litebox_syscall_rewriter/**/*.rs') }}
      - run: ./.github/tools/github_actions_run_cargo build --target=i686-unknown-linux-gnu
      - run: ./.github/tools/github_actions_run_cargo nextest --target=i686-unknown-linux-gnu
      - run: |
          ./.github/tools/github_actions_run_cargo test --target=i686-unknown-linux-gnu --doc
          # We need to run `cargo test --doc` separately because doc tests
          # aren't included in nextest at the moment. See relevant discussion at
          # https://github.com/nextest-rs/nextest/issues/16
```

---

## `.github/workflows/copilot-setup-steps.yml`

### Conflict 1 (around line 13)

**Fork's version (kept):**
```
      - name: Checkout repository
        uses: actions/checkout@v4

      # Cache Cargo registry, git sources, and compiled deps
      - name: Cache Cargo dependencies
        uses: Swatinem/rust-cache@v2
        with:
          # Cache key includes Cargo.lock so it busts when deps change
          key: litebox-cargo-${{ hashFiles('**/Cargo.lock') }}

      # Pre-fetch and compile all dependencies (the biggest time saver)
      # Uses --workspace so all crate deps are warmed up at once
      - name: Pre-fetch Cargo dependencies
        run: cargo fetch

      # Pre-build dependencies in check mode to warm up the cache
      - name: Pre-build workspace dependencies
```

**Upstream's version (discarded):**
```
      - name: Checkout code
        uses: actions/checkout@v6
      - name: Set up Rust
```

---

## `Cargo.lock`

### Conflict 1 (around line 917)

**Fork's version (kept):**
```
name = "litebox_platform_linux_for_windows"
version = "0.1.0"
dependencies = [
 "libc",
 "litebox",
 "litebox_shim_windows",
 "thiserror",
```

**Upstream's version (discarded):**
```
name = "litebox_packager"
version = "0.1.0"
dependencies = [
 "anyhow",
 "clap",
 "litebox_syscall_rewriter",
 "tar",
```

---

## `dev_tests/src/ratchet.rs`

### Conflict 1 (around line 40)

**Fork's version (kept):**
```
            ("litebox_platform_linux_for_windows/", 71),
            ("litebox_platform_linux_kernel/", 5),
```

**Upstream's version (discarded):**
```
            ("litebox_platform_linux_kernel/", 6),
```

### Conflict 2 (around line 82)

**Fork's version (kept):**
```
            ("litebox_platform_lvbs/", 5),
            ("litebox_shim_linux/", 8),
            ("litebox_shim_optee/", 1),
```

**Upstream's version (discarded):**
```
            ("litebox_shim_linux/", 5),
```

---

## `litebox_platform_linux_userland/src/lib.rs`

### Conflict 1 (around line 2048)

**Fork's version (kept):**
```
        Some(guest_context_top.wrapping_sub(1))
```

**Upstream's version (discarded):**
```
        Some(guest_context_top.sub(1))
```

---

## `litebox_platform_lvbs/src/arch/x86/mm/paging.rs`

### Conflict 1 (around line 630)

**Fork's version (kept):**
```
    #[allow(dead_code)]
    pub(crate) fn change_address_space(&self) -> PhysFrame {
```

**Upstream's version (discarded):**
```
    pub(crate) fn load(&self) -> PhysFrame {
```

### Conflict 2 (around line 654)

**Fork's version (kept):**
```
    #[allow(dead_code)]
```

**Upstream's version (discarded):**
```

```

---

## `litebox_platform_lvbs/src/arch/x86/mod.rs`

### Conflict 1 (around line 30)

**Fork's version (kept):**
```
    // SAFETY: cpuid is safe to call on x86_64
    let result = unsafe { cpuid_count(CPU_VERSION_INFO, 0x0) };
```

**Upstream's version (discarded):**
```
    let result = cpuid_count(CPU_VERSION_INFO, 0x0);
```

---

## `litebox_platform_lvbs/src/lib.rs`

### Conflict 1 (around line 397)

**Fork's version (kept):**
```
    #[allow(dead_code)]
    user_contexts: UserContextMap,
```

**Upstream's version (discarded):**
```

```

---

## `litebox_platform_lvbs/src/mshv/hvcall.rs`

### Conflict 1 (around line 57)

**Fork's version (kept):**
```
    // SAFETY: cpuid is safe to call on x86_64
    let result = unsafe { cpuid_count(CPU_VERSION_INFO, 0x0) };
```

**Upstream's version (discarded):**
```
    let result = cpuid_count(CPU_VERSION_INFO, 0x0);
```

### Conflict 2 (around line 67)

**Fork's version (kept):**
```
    // SAFETY: cpuid is safe to call on x86_64
    let result = unsafe { cpuid_count(HYPERV_CPUID_INTERFACE, 0x0) };
```

**Upstream's version (discarded):**
```
    let result = cpuid_count(HYPERV_CPUID_INTERFACE, 0x0);
```

### Conflict 3 (around line 77)

**Fork's version (kept):**
```
    // SAFETY: cpuid is safe to call on x86_64
    let result = unsafe { cpuid_count(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS, 0x0) };
```

**Upstream's version (discarded):**
```
    let result = cpuid_count(HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS, 0x0);
```

---

## `litebox_runner_lvbs/Cargo.toml`

### Conflict 1 (around line 14)

**Fork's version (kept):**
```
hashbrown = { version = "0.15.2", default-features = false, features = ["inline-more"] }
```

**Upstream's version (discarded):**
```

```

---

## `litebox_runner_lvbs/rust-toolchain.toml`

### Conflict 1 (around line 5)

**Fork's version (kept):**
```
channel = "nightly-2026-01-15"
```

**Upstream's version (discarded):**
```
channel = "nightly-2025-12-31"
```

---

## `litebox_runner_snp/rust-toolchain.toml`

### Conflict 1 (around line 2)

**Fork's version (kept):**
```
channel = "nightly-2026-01-15"
```

**Upstream's version (discarded):**
```
channel = "nightly-2025-12-31"
```

---


## Post-Rebase Integration Fixes

The following additional fixes were required after rebasing to reconcile upstream API changes
with fork code that depends on those APIs:

### `litebox_platform_lvbs/src/arch/x86/mm/paging.rs`

- Renamed `change_address_space()` back to `load()` since upstream code calls this method
  (the fork had renamed it and marked it `#[allow(dead_code)]` since it wasn't used there)
- Added `clean_up()` method (from fork's original code) needed by `user_context.rs`

### `litebox_platform_lvbs/src/lib.rs`

- Added `pub(crate) mod user_context;` declaration (upstream deleted the file, fork kept it)
- Added `use crate::user_context::UserContextMap;` import
- Added `user_contexts: UserContextMap::new()` field initialization in constructor
- Added `new_user_page_table()` method (from fork's original code) needed by `user_context.rs`
- Updated `map_phys_frame_range` call to include new `exec_ranges` parameter (added by upstream)

### `litebox_platform_lvbs/src/user_context.rs`

- Updated `change_address_space()` call to `load()` to match renamed method

### `litebox_common_optee/src/lib.rs`

- Removed stale `modular_bitfield` imports (upstream replaced with manual bitfield implementation)
- Added `use litebox::utils::TruncateExt;` import (upstream dependency)

### `litebox_platform_linux_for_windows/src/lib.rs`

- Removed duplicate `use litebox_shim_windows::syscalls::ntdll::{ConsoleHandle, FileHandle, NtdllApi};` import
- Removed first (older/broken) `impl NtdllApi for LinuxPlatformForWindows` block
  that had type mismatches; kept the second complete implementation

### `litebox_platform_linux_kernel/src/lib.rs`

- Merged duplicate `use litebox::platform::{RawMutex as _, RawPointerProvider}` imports

### `dev_tests/src/ratchet.rs`

- Updated `litebox_platform_linux_kernel/` global count from 5 to 6 (upstream added a global)
- Removed `litebox_platform_lvbs/` and `litebox_shim_optee/` from `MaybeUninit` ratchet
  (upstream removed all `MaybeUninit` usage from these crates)
