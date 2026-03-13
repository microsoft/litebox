# Use Debian Bookworm as the base image for a stable, modern environment
FROM debian:bookworm-slim

# Install system dependencies including Node.js
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    mingw-w64 \
    gdb \
    git \
    ca-certificates \
    nodejs \
    npm \
    libvulkan1 \
    mesa-vulkan-drivers \
    && rm -rf /var/lib/apt/lists/*

# Set up Rust environment variables
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# Install rustup and the specific nightly toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none \
    && chmod -R a+w $RUSTUP_HOME $CARGO_HOME

# Copy rust-toolchain.toml to install the correct toolchain version
COPY rust-toolchain.toml /tmp/rust-toolchain.toml
RUN cd /tmp && rustup show && rustup default nightly-2026-01-15 && rm /tmp/rust-toolchain.toml

# Add Windows GNU target for cross-compilation
RUN rustup target add x86_64-pc-windows-gnu

# Install cargo-nextest for faster test execution
RUN cargo install cargo-nextest --locked

# Install MCP servers for GitHub Copilot integration
# Install GitHub MCP server - provides GitHub repository access (issues, PRs, code search, etc.)
RUN npm install -g github-mcp-server@latest --unsafe-perm

# Verify installations
RUN node --version && npm --version && github-mcp-server --version || echo "github-mcp-server installed"

# Create workspace directory
WORKDIR /workspace

# Copy Cargo workspace files for dependency caching
# This layer will be cached as long as dependencies don't change
COPY Cargo.toml Cargo.lock ./
COPY litebox/Cargo.toml ./litebox/
COPY litebox_common_linux/Cargo.toml ./litebox_common_linux/
COPY litebox_common_optee/Cargo.toml ./litebox_common_optee/
COPY litebox_platform_linux_kernel/Cargo.toml ./litebox_platform_linux_kernel/
COPY litebox_platform_linux_userland/Cargo.toml ./litebox_platform_linux_userland/
COPY litebox_platform_windows_userland/Cargo.toml ./litebox_platform_windows_userland/
COPY litebox_platform_linux_for_windows/Cargo.toml ./litebox_platform_linux_for_windows/
COPY litebox_platform_lvbs/Cargo.toml ./litebox_platform_lvbs/
COPY litebox_platform_multiplex/Cargo.toml ./litebox_platform_multiplex/
COPY litebox_runner_linux_userland/Cargo.toml ./litebox_runner_linux_userland/
COPY litebox_runner_linux_on_windows_userland/Cargo.toml ./litebox_runner_linux_on_windows_userland/
COPY litebox_runner_windows_on_linux_userland/Cargo.toml ./litebox_runner_windows_on_linux_userland/
COPY litebox_runner_lvbs/Cargo.toml ./litebox_runner_lvbs/
COPY litebox_runner_optee_on_linux_userland/Cargo.toml ./litebox_runner_optee_on_linux_userland/
COPY litebox_shim_linux/Cargo.toml ./litebox_shim_linux/
COPY litebox_shim_optee/Cargo.toml ./litebox_shim_optee/
COPY litebox_shim_windows/Cargo.toml ./litebox_shim_windows/
COPY litebox_syscall_rewriter/Cargo.toml ./litebox_syscall_rewriter/
COPY litebox_runner_snp/Cargo.toml ./litebox_runner_snp/
COPY dev_tests/Cargo.toml ./dev_tests/
COPY dev_bench/Cargo.toml ./dev_bench/

# Create dummy source files to enable dependency fetching and caching
# This allows cargo to download and compile dependencies without the actual source code
RUN mkdir -p litebox/src \
    litebox_common_linux/src \
    litebox_common_optee/src \
    litebox_platform_linux_kernel/src \
    litebox_platform_linux_userland/src \
    litebox_platform_windows_userland/src \
    litebox_platform_linux_for_windows/src \
    litebox_platform_lvbs/src \
    litebox_platform_multiplex/src \
    litebox_runner_linux_userland/src \
    litebox_runner_linux_on_windows_userland/src \
    litebox_runner_windows_on_linux_userland/src \
    litebox_runner_lvbs/src \
    litebox_runner_optee_on_linux_userland/src \
    litebox_shim_linux/src \
    litebox_shim_optee/src \
    litebox_shim_windows/src \
    litebox_syscall_rewriter/src \
    litebox_runner_snp/src \
    dev_tests/src \
    dev_bench/src \
    && touch litebox/src/lib.rs \
    litebox_common_linux/src/lib.rs \
    litebox_common_optee/src/lib.rs \
    litebox_platform_linux_kernel/src/lib.rs \
    litebox_platform_linux_userland/src/lib.rs \
    litebox_platform_windows_userland/src/lib.rs \
    litebox_platform_linux_for_windows/src/lib.rs \
    litebox_platform_lvbs/src/lib.rs \
    litebox_platform_multiplex/src/lib.rs \
    litebox_runner_linux_userland/src/main.rs \
    litebox_runner_linux_on_windows_userland/src/main.rs \
    litebox_runner_windows_on_linux_userland/src/main.rs \
    litebox_runner_lvbs/src/main.rs \
    litebox_runner_optee_on_linux_userland/src/main.rs \
    litebox_shim_linux/src/lib.rs \
    litebox_shim_optee/src/lib.rs \
    litebox_shim_windows/src/lib.rs \
    litebox_syscall_rewriter/src/lib.rs \
    litebox_runner_snp/src/main.rs \
    dev_tests/src/lib.rs \
    dev_bench/src/main.rs

# Fetch all dependencies to cache them in the Docker layer
# This step will be cached as long as Cargo.toml/Cargo.lock don't change
RUN cargo fetch

# Clean up dummy files - the actual source will be mounted/copied at runtime
RUN rm -rf litebox litebox_common_linux litebox_common_optee \
    litebox_platform_linux_kernel litebox_platform_linux_userland \
    litebox_platform_windows_userland litebox_platform_linux_for_windows \
    litebox_platform_lvbs litebox_platform_multiplex \
    litebox_runner_linux_userland litebox_runner_linux_on_windows_userland \
    litebox_runner_windows_on_linux_userland litebox_runner_lvbs \
    litebox_runner_optee_on_linux_userland litebox_shim_linux \
    litebox_shim_optee litebox_shim_windows litebox_syscall_rewriter \
    litebox_runner_snp dev_tests dev_bench Cargo.toml Cargo.lock

# Set the default command
CMD ["/bin/bash"]
