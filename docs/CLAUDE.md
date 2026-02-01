# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

LiteBox is a security-focused sandboxing library OS that reduces attack surface by drastically cutting down the interface to the host. It enables running unmodified programs in sandboxed environments across various platforms (Linux userland, Windows, SEV SNP, LVBS, OP-TEE).

## Build & Test Commands

```bash
# Development workflow
cargo fmt                                        # Format code
cargo build                                      # Build default workspace members
cargo clippy --all-targets --all-features        # Lint
cargo nextest run                                # Run tests (preferred over cargo test)
cargo test --doc                                 # Run doc tests (not included in nextest)

# Run a single test
cargo nextest run test_name

# Build/test specific packages
cargo build -p litebox_runner_linux_userland
cargo nextest run -p litebox_shim_linux

# 32-bit build
cargo build --target=i686-unknown-linux-gnu

# LVBS (requires nightly, custom target)
cargo build -Z build-std-features=compiler-builtins-mem -Z build-std=core,alloc \
  --manifest-path=litebox_runner_lvbs/Cargo.toml --target litebox_runner_lvbs/x86_64_vtl1.json

# TUN device setup (required for network tests)
sudo ./litebox_platform_linux_userland/scripts/tun-setup.sh
```

## Architecture

LiteBox uses a "North-South" architecture with three component types:

### Core (`litebox` crate)
- `#![no_std]` library providing POSIX-like interface (inspired by `nix`/`rustix`)
- Requires a `platform::Provider` implementation to function
- Modules: `fd`, `fs`, `mm`, `net`, `pipes`, `sync`, `tls`, `event`, `path`

### Platforms ("South" - implement `platform::Provider` trait)
- `litebox_platform_linux_userland` - Linux userland via TUN device
- `litebox_platform_windows_userland` - Windows userland
- `litebox_platform_lvbs` - Hyper-V VTL1 kernel (custom `no_std` target)
- `litebox_platform_multiplex` - Multiplexes multiple platforms

### Shims ("North" - provide ABI compatibility)
- `litebox_shim_linux` - Linux syscall ABI, parametric in platform choice
- `litebox_shim_optee` - OP-TEE TA ABI

### Runners (complete integration examples)
- `litebox_runner_linux_userland` - Run Linux programs sandboxed on Linux
- `litebox_runner_linux_on_windows_userland` - Run Linux programs on Windows
- `litebox_runner_lvbs` - Run in Hyper-V VTL1 kernel
- `litebox_runner_optee_on_linux_userland` - Run OP-TEE TAs on Linux
- `litebox_runner_snp` - Run on AMD SEV-SNP

### Supporting Crates
- `litebox_common_linux` - Shared Linux definitions (errno, etc.)
- `litebox_common_optee` - Shared OP-TEE definitions
- `litebox_syscall_rewriter` - AOT ELF rewriting for syscall interception

## Key Traits

The `platform::Provider` trait composes:
- `RawMutexProvider` - Futex-like synchronization primitives
- `IPInterfaceProvider` - Network packet send/receive (typically TUN)
- `TimeProvider` - Monotonic instants and system time
- `PunchthroughProvider` - Auditable escape hatch for platform-specific functionality
- `DebugLogProvider` - Debug output
- `RawPointerProvider` - User pointer abstraction for user-kernel separation

## Code Guidelines

- Minimize `unsafe` code; every `unsafe` block requires a clear safety comment
- Favor `no_std` compatibility; `std` usage requires justification
- Prefer `default-features = false` for new dependencies
- Run `cargo fmt` before committing
- Workspace uses pedantic clippy lints (configured in root `Cargo.toml`)

## Special Build Configurations

- **LVBS/SNP**: Require nightly toolchain with `-Z build-std` for custom `no_std` targets
- **`litebox_runner_optee_on_linux_userland`**: Must be built separately due to feature conflicts with `litebox_runner_linux_userland`
- **Lock tracing**: Build with `--features lock_tracing`, visualize with `dev_tools/lock_viewer`
