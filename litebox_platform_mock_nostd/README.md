# litebox_platform_mock_nostd

A `#![no_std]` mock platform implementation for LiteBox, suitable for testing and development on embedded or bare-metal targets.

## Features

- **No standard library dependencies**: Pure `#![no_std]` implementation
- **Minimal resource usage**: Uses atomic operations and fixed-size structures
- **Mock implementations**: Provides placeholder implementations for all platform traits
- **Testing friendly**: Deterministic behavior for reproducible tests
- **Syscall-based I/O**: Uses raw syscalls for stdout/stderr output

## Usage

This crate provides a `MockNoStdPlatform` that implements all the necessary traits for LiteBox to function, but with minimal or no-op implementations suitable for testing environments.

```rust
use litebox_platform_mock_nostd::MockNoStdPlatform;

let platform = MockNoStdPlatform::new(None);
// Use with LiteBox
```

## Limitations

- No actual memory management (mock implementations)
- No network functionality 
- Limited I/O capabilities
- No real synchronization primitives (uses spin loops)

This platform is intended for testing and development purposes, not production use.
