# Quick Reference: Workspace Setup

## 🚀 Speed Up Your Development (5 Minutes)

### Automated Setup (Easiest)
```bash
./scripts/setup-workspace.sh
```

This script will check your system and guide you through installing the recommended tools.

### Option 1: Fast Setup (Recommended)
```bash
# Install fast linker (choose one)
sudo apt install mold        # 3-5x faster linking
# OR
sudo apt install lld         # 2-3x faster linking

# Install fast test runner
cargo install cargo-nextest

# Enable fast linker
# Edit .cargo/config.toml and uncomment the mold/lld section
```

### Option 2: Minimal Setup
```bash
# Just install nextest for faster tests
cargo install cargo-nextest
```

## 📝 Common Commands

### Building
```bash
cargo build              # Build default workspace members
cargo check-fast         # Quick check (excludes special packages)
cargo build -p <name>    # Build specific package
```

### Testing
```bash
cargo nextest run        # Fast parallel testing
cargo test-fast          # Alias for nextest
cargo test -p <name>     # Test specific package
```

### Checking Code
```bash
cargo check-fast         # Quick workspace check
cargo clippy             # Lint checking
cargo fmt                # Format code
```

### Workspace Packages
```bash
# Skip packages requiring special toolchains
cargo check-fast         # Automatically excludes lvbs and snp

# Build specific components
cargo build -p litebox
cargo build -p litebox_runner_linux_userland
cargo build -p litebox_shim_windows
```

## ⏱️ Expected Performance

| Task | Standard | Optimized | Speedup |
|------|----------|-----------|---------|
| Incremental check | 5s | 2s | 2.5x |
| Incremental build | 15s | 5s | 3x |
| Test suite | 45s | 15s | 3x |
| Clean build | 2m | 80s | 1.5x |

## 🔧 Troubleshooting

### "linker 'clang' not found"
```bash
sudo apt install clang
```

### Fast linker not working
Comment out the linker config in `.cargo/config.toml` and use default

### Rust-analyzer is slow
Configure it to use `check-fast`:
```json
"rust-analyzer.checkOnSave.command": "check-fast"
```

## 📚 Learn More

See [docs/workspace_setup_optimization.md](./workspace_setup_optimization.md) for detailed information.
