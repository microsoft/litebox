This repository contains a Rust-based, security-focused sandboxing library OS. To maintain high code quality and consistency, please adhere to the following guidelines when contributing.

## Code Standards

### Required Before Each Commit
- Run `cargo fmt` to format all Rust files using `rustfmt`.
  - This ensures consistent code style across the codebase.

### Development Workflow
The recommended sequence during development is:
1. **Format**: `cargo fmt`
2. **Build**: `cargo build`
3. **Lint**: `cargo clippy --all-targets --all-features`
4. **Test**: `cargo nextest run`

- Full CI checks are defined in `.github/workflows/ci.yml`.

## Key Guidelines

1. Follow Rust best practices and idiomatic patterns.
2. Preserve the existing code structure and organization.
3. Minimize use of `unsafe` code. Every `unsafe` block **must** include a clear safety comment explaining why it's sound. Always prefer safe abstractions and code where possible.
4. Write unit tests for new functionality, especially if it affects public interfaces.
   - Extremely simple changes do not require explicit unit tests.
5. Document all public APIs and non-trivial implementation details.
6. Avoid introducing new dependencies unless strictly necessary. If a dependency is added:
   - It must be justified.
   - Prefer `default-features = false` in `Cargo.toml`.
7. Favor `no_std` compatibility wherever feasible.
   - Some crates in the workspace may use `std`, but this should be deliberate and justified.
