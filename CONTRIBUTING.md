# Contributing

This project welcomes contributions and suggestions. Most contributions require you to
agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the
instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Development Setup

### Quick Setup (Recommended)

For the fastest development experience, run the automated setup checker:

```bash
./scripts/setup-workspace.sh
```

This will check for and guide you to install:
- Fast linker (mold or lld) - speeds up linking by 3-5x
- cargo-nextest - speeds up tests by 2-3x
- Other recommended tools

Or install manually:

```bash
# Fast linker (choose one)
sudo apt install mold        # Recommended
# OR
sudo apt install lld         # Alternative

# Fast test runner
cargo install cargo-nextest

# After installing, edit .cargo/config.toml to enable the fast linker
```

For more optimization tips, see [Workspace Setup Optimization Guide](./docs/workspace_setup_optimization.md).

### Prerequisites

#### Rust Toolchain

This project uses Rust nightly. Install Rust via [rustup](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

The repository includes a `rust-toolchain.toml` file that specifies the exact nightly version to use.

#### System Dependencies

**For Windows on Linux Development:**

If you're working on Windows-on-Linux support, you'll need the MinGW cross-compiler toolchain to build Windows test programs:

```bash
# On Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y mingw-w64

# Add Windows GNU target to Rust
rustup target add x86_64-pc-windows-gnu
```

This enables:
- Cross-compiling Rust programs to Windows PE format
- Building test executables in `windows_test_programs/`
- Testing the Windows-on-Linux runner with real Windows binaries

**Other Development Tools:**

```bash
# cargo-nextest for faster test execution (optional but recommended)
cargo install cargo-nextest

# For debugging Windows programs (optional)
sudo apt-get install -y gdb
```

### Building

Build the entire workspace:

```bash
cargo build
```

Build specific packages:

```bash
# Windows on Linux components
cargo build -p litebox_shim_windows
cargo build -p litebox_platform_linux_for_windows
cargo build -p litebox_runner_windows_on_linux_userland

# Other components
cargo build -p litebox
cargo build -p litebox_runner_linux_userland
```

### Testing

Run all tests:

```bash
cargo test
# Or with cargo-nextest
cargo nextest run
```

Run tests for specific packages:

```bash
# Windows on Linux tests
cargo test -p litebox_shim_windows -p litebox_platform_linux_for_windows -p litebox_runner_windows_on_linux_userland

# With nextest
cargo nextest run -p litebox_shim_windows
```

### Building Windows Test Programs

If you've installed MinGW (see above), you can build the Windows test programs:

```bash
cd windows_test_programs

# Build all test programs for Windows
cargo build --target x86_64-pc-windows-gnu --release

# Build specific test program
cargo build --target x86_64-pc-windows-gnu --release -p hello_cli
```

The built executables will be in:
```
windows_test_programs/target/x86_64-pc-windows-gnu/release/*.exe
```

### Running Windows Programs on Linux

After building the Windows test programs, you can run them with the Windows-on-Linux runner:

```bash
cargo run -p litebox_runner_windows_on_linux_userland -- \
  windows_test_programs/target/x86_64-pc-windows-gnu/release/hello_cli.exe
```

### Code Quality

Before submitting a pull request, ensure your code passes all quality checks:

```bash
# Format code
cargo fmt

# Check for common mistakes and style issues
cargo clippy --all-targets --all-features

# Run ratchet tests (verify constraints)
cargo test -p dev_tests

# Run all tests
cargo nextest run  # or cargo test
```

See `.github/copilot-instructions.md` for detailed coding standards and development guidelines.
