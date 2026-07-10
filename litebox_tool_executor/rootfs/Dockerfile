# ═══════════════════════════════════════════════════════════════════
# LiteBox rootfs Dockerfile — multi-target build
#
# Targets:
#   litebox-base             — shared Ubuntu 24.04 foundation (not used directly)
#   litebox-test             — test harness rootfs (bash + coreutils + Node.js)
#   litebox-vscode           — VS Code Server rootfs (adds SSH, VS Code CLI+Server)
#   litebox-vscode-prewrite  — VS Code + pre-rewritten node binary (faster startup)
#   litebox-vscode-native    — VS Code Server image without litebox (native baseline)
#   litebox-agent-cli        — Copilot CLI rootfs (dropbear + Node + @github/copilot)
#
# Usage:
#   DOCKER_HOST="${DOCKER_HOST:-unix:///run/litebox-docker.sock}" \
#     docker build --target litebox-test   -t litebox-test   -f litebox_tool_executor/rootfs/Dockerfile .
#   DOCKER_HOST="${DOCKER_HOST:-unix:///run/litebox-docker.sock}" \
#     docker build --target litebox-vscode -t litebox-vscode -f litebox_tool_executor/rootfs/Dockerfile .
#   DOCKER_HOST="${DOCKER_HOST:-unix:///run/litebox-docker.sock}" \
#     docker build --target litebox-vscode-prewrite -t litebox-vscode-prewrite -f litebox_tool_executor/rootfs/Dockerfile .
#
# The explicit DOCKER_HOST default selects the native in-distro dockerd
# (Docker Desktop stays installed but is unused for litebox). If DOCKER_HOST
# is already set, keep the caller's daemon.
#
# IMPORTANT: Binaries must be bind-mounted from a Linux-native filesystem
# (WSL2 ext4), NOT from NTFS (/mnt/c/...).  Docker Desktop on Windows
# cannot mmap ELF files from NTFS bind mounts.  Build with:
#   cargo build --target-dir ~/litebox-out -p litebox_tool_executor ...
#
# Runtime (tests):
#   DOCKER_HOST="${DOCKER_HOST:-unix:///run/litebox-docker.sock}" \
#     docker run --rm --cap-add SYS_PTRACE \
#     -v \\wsl$\Ubuntu\home\USER\litebox-out\debug:/opt/litebox:ro \
#     -v \\wsl$\Ubuntu\home\USER\litebox-out\nonpie\debug:/opt/nonpie:ro \
#     litebox-test /opt/litebox/litebox_test_harness spawn-tree
#
# Runtime (VS Code Server):
#   DOCKER_HOST="${DOCKER_HOST:-unix:///run/litebox-docker.sock}" \
#     docker run --rm -p 2222:22 --cap-add SYS_PTRACE \
#     -v \\wsl$\Ubuntu\home\USER\litebox-out\debug:/opt/litebox:ro \
#     litebox-vscode /opt/litebox/litebox_tool_executor \
#       --rootfs / --vscode-server --ssh-port 22 --record-baseline
# ═══════════════════════════════════════════════════════════════════

# === Stage 1: shared base ===
FROM ubuntu:24.04 AS litebox-base

# Mark all litebox-derived images with a single label so cleanup
# scripts can scope `docker image prune` to litebox-owned images
# (`--filter label=litebox=1`) without accidentally taking out
# unrelated images sharing this Docker daemon.
LABEL litebox=1

ENV DEBIAN_FRONTEND=noninteractive

# Core packages shared by all targets.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash coreutils findutils grep sed gawk \
    ca-certificates curl xz-utils tar \
    procps less netcat-openbsd gdb gdbserver \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf bash /bin/sh

# Minimal system configuration.
# The password hash is SHA-256 of the empty string (dropbear -B accepts it).
RUN printf 'root:$5$feWUHaTYjlgIa1uw$9xrsiQaRuBfJSEx37HOmaCfa2l4MY6VGZ8/L3OJVSO9:0:0:root:/root:/usr/bin/bash\nuser:x:1000:1000:user:/root:/usr/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n' > /etc/passwd \
    && printf 'root:x:0:\nuser:x:1000:\nnogroup:x:65534:\n' > /etc/group \
    && printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n' > /etc/nsswitch.conf \
    && printf 'root:$5$feWUHaTYjlgIa1uw$9xrsiQaRuBfJSEx37HOmaCfa2l4MY6VGZ8/L3OJVSO9:20553:0:99999:7:::\n' > /etc/shadow \
    && chmod 640 /etc/shadow

# Writable directories.
# Note: /dev/fd → /proc/self/fd symlink cannot be created during build
# because /proc is not mounted. It's created at runtime by litebox or
# by the unshare --mount native baseline.
RUN mkdir -p /tmp /shared /workspaces /root /home /proc /dev \
    && echo -n from_host > /shared/host_wrote.txt \
    && [ -e /bin ] || ln -sf /usr/bin /bin \
    && echo "nameserver 10.0.0.1" > /etc/resolv.conf.litebox

# === Stage 2a: test harness rootfs ===
FROM litebox-base AS litebox-test

# Node.js — pinned version, not host-dependent.
ARG NODE_VERSION=v24.14.1
RUN curl -fsSL "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.xz" \
    | tar xJ --strip-components=1 -C /usr/local \
    && node --version

# Test harness and litebox binaries are bind-mounted at runtime:
#   /opt/litebox/   — litebox_tool_executor, litebox_broker, litebox_runner, litebox_test_harness
#   /opt/nonpie/    — litebox_test_harness (non-PIE variant)
#
# Design note: we deliberately use bind-mounts for /opt/litebox and
# /opt/nonpie rather than copying the binaries into the rootfs at
# container startup. Copying would let the broker's `elf_cache` cover
# them (the broker only sees files in the rootfs it serves via 9P,
# not files in separate kernel mount points like bind-mounts), but
# measurement on CF.rwlock_multi_6.A showed the trade-off goes the
# wrong direction:
#
#   bind-mount (current):       38.5 s/trial  — runner reads binaries
#                                                directly from host FS,
#                                                in-process patching is
#                                                fast (~0.5 s per exec).
#   copy-then-9P-serve:         60.0 s/trial  — broker rewrites once,
#                                                but every subsequent
#                                                exec reads 41 MB through
#                                                9P, which costs more
#                                                than the per-exec
#                                                runner-side patching
#                                                it would have replaced.
#
# In short: 9P serving is more expensive than direct mmap, and ELF
# patching itself isn't actually a hotspot — so don't try to "fix"
# the bind-mount choice with a 9P-routed copy unless someone has
# evidence the broker's per-byte cost has dropped.

# === Stage 2b: VS Code Server rootfs ===
FROM litebox-base AS litebox-vscode

# Additional packages for VS Code Server mode.
# System nodejs is intentionally excluded — the VS Code Server bundles its
# own Node.js at cli/servers/Stable-<commit>/server/node. Installing the
# system nodejs (v18 from Ubuntu) confuses the CLI's prerequisites check
# into thinking the server requirements aren't met.
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-sftp-server dropbear-bin git strace \
    && rm -rf /var/lib/apt/lists/*

# Dropbear SSH server.
RUN mkdir -p /etc/dropbear \
    && dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null

# VS Code CLI (latest stable).
#
# Only the alpine/musl variant (cli-alpine-x64) is distributed by Microsoft;
# cli-linux-x64 returns 404. The CLI is statically linked, but litebox's
# syscall rewriter patches syscall instructions at load time regardless of
# libc, so all CLI syscalls still go through the sandbox.
#
# The CLI is installed as both 'code' (generic) and 'code-<COMMIT>'
# (commit-specific).  The VS Code Remote-SSH install script checks for
# 'code-<COMMIT>' and skips the download when it exists.
RUN mkdir -p /root/.vscode-server \
    && curl -fsSL "https://code.visualstudio.com/sha/download?build=stable&os=cli-alpine-x64" \
       -o /tmp/vscode-cli.tar.gz \
    && tar xzf /tmp/vscode-cli.tar.gz -C /root/.vscode-server \
    && rm /tmp/vscode-cli.tar.gz \
    && VSCODE_COMMIT=$(/root/.vscode-server/code --version 2>/dev/null \
       | grep -oP 'commit \K[a-f0-9]{40}') \
    && cp /root/.vscode-server/code \
          "/root/.vscode-server/code-${VSCODE_COMMIT}" \
    && echo "CLI installed: code + code-${VSCODE_COMMIT}"

# VS Code Server — version matched to CLI commit hash.
RUN VSCODE_COMMIT=$(/root/.vscode-server/code --version 2>/dev/null | grep -oP 'commit \K[a-f0-9]{40}') \
    && echo "VS Code commit: $VSCODE_COMMIT" \
    && SERVER_DIR="/root/.vscode-server/cli/servers/Stable-${VSCODE_COMMIT}/server" \
    && mkdir -p "$SERVER_DIR" \
    && curl -fsSL "https://update.code.visualstudio.com/commit:${VSCODE_COMMIT}/server-linux-x64/stable" \
       -o /tmp/vscode-server.tar.gz \
    && tar xzf /tmp/vscode-server.tar.gz -C "$SERVER_DIR" --strip-components=1 \
    && rm /tmp/vscode-server.tar.gz \
    && test -f "$SERVER_DIR/node" \
    && echo "Server installed at $SERVER_DIR"

# VS Code data directories.
RUN mkdir -p /root/.vscode-server/data/logs \
             /root/.vscode-server/data/Machine \
             /root/.vscode-server/extensions \
    && chmod -R 755 /root/.vscode-server \
    && touch /tmp/vscode-skip-server-requirements-check

# Litebox binaries are bind-mounted at runtime:
#   /opt/litebox/ — litebox_tool_executor, litebox_broker, litebox_runner

EXPOSE 22
EXPOSE 9999

# === Stage 2c: VS Code Server with pre-rewritten rootfs ===
#
# All ELF binaries are pre-rewritten with syscall trampolines.
# This image is ONLY used under litebox — never run natively.
# The original litebox-vscode image is preserved for ad-hoc scripts.
#
# Eliminates ~10.5s of runtime rewriting:
#   node (119MB): 7.5s, libc (2MB): 2.6s, libstdc++: 0.2s, etc.
#
# Runtime rewriting stays enabled for binaries that appear later
# (e.g., VS Code extensions with native modules).
#
# Requires litebox_syscall_rewriter in the build context. Build with:
#   cargo build --release -p litebox_syscall_rewriter
#
# Usage:
#   DOCKER_HOST="${DOCKER_HOST:-unix:///run/litebox-docker.sock}" \
#     docker build --target litebox-vscode-prewrite -t litebox-vscode-prewrite \
#       -f litebox_tool_executor/rootfs/Dockerfile .
FROM litebox-vscode AS litebox-vscode-prewrite

COPY litebox_tool_executor/rootfs/litebox_syscall_rewriter /tmp/rewriter
# Rewrite guest EXECUTABLES only — NOT shared libraries. The litebox
# infrastructure (tool_executor, broker, runner) runs natively and
# links against the container's libc/ld-linux. Pre-rewriting those
# would crash the infrastructure. The broker's ElfCache handles
# shared library rewriting at runtime (cached after first load).
RUN chmod +x /tmp/rewriter \
    && SERVER_DIR=$(ls -d /root/.vscode-server/cli/servers/Stable-*/server) \
    && /tmp/rewriter "$SERVER_DIR/node" -o "$SERVER_DIR/node" \
    && /tmp/rewriter /usr/sbin/dropbear -o /usr/sbin/dropbear \
    && /tmp/rewriter /usr/bin/bash -o /tmp/bash.tmp && mv /tmp/bash.tmp /usr/bin/bash \
    && rm /tmp/rewriter

# === Stage 2d: VS Code Server WITHOUT litebox (native baseline) ===
# Verifies the Docker image works without litebox so SSH + VS Code
# issues can be attributed to litebox vs. environment problems.
#
# Usage:
#   DOCKER_HOST="${DOCKER_HOST:-unix:///run/litebox-docker.sock}" \
#     docker build --target litebox-vscode-native -t litebox-vscode-native \
#       -f litebox_tool_executor/rootfs/Dockerfile .
#   DOCKER_HOST="${DOCKER_HOST:-unix:///run/litebox-docker.sock}" \
#     docker run --rm -p 2223:22 litebox-vscode-native
#   # then in VS Code: Remote-SSH → localhost:2223 (user: root, empty password)
FROM litebox-vscode AS litebox-vscode-native

EXPOSE 22
CMD ["/usr/sbin/dropbear", "-F", "-E", "-B", "-R", "-p", "22"]

# === Stage 2e: Copilot CLI rootfs (interactive + non-interactive automation) ===
#
# Sshd-as-entry-point image used by the Copilot CLI integration scenarios
# (see `litebox_test_harness/tests/integration.rs`, `copilot::*` Trials).
# The test harness drives this image identically in both passes:
#
#   native pass : docker run litebox-agent-cli                                 \
#                   dropbear -F -E -B -R -p 22
#   litebox pass: docker run litebox-agent-cli                                 \
#                   litebox_tool_executor --rootfs / --                        \
#                   dropbear -F -E -B -R -p 22
#
# The host-side test then `ssh -tt -p <PORT> root@127.0.0.1` into the
# container and runs `copilot ...` as the remote command (or as the
# interactive shell). Empty-password root auth via dropbear `-B`.
#
# Usage:
#   docker build --target litebox-agent-cli -t litebox-agent-cli \
#     -f litebox_tool_executor/rootfs/Dockerfile .
FROM litebox-base AS litebox-agent-cli

# Node.js — pinned, matches the test-harness image to keep ABI surface
# consistent across the two rootfses.
ARG NODE_VERSION=v24.14.1
RUN curl -fsSL "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.xz" \
    | tar xJ --strip-components=1 -C /usr/local \
    && node --version

# Dropbear ssh + tools commonly invoked by the Copilot Bash tool in
# the scenarios. `dropbear-bin` mirrors `litebox-vscode`'s setup so
# the integration tests exercise the same sshd binary.
RUN apt-get update && apt-get install -y --no-install-recommends \
        dropbear-bin git jq ripgrep \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/dropbear \
    && dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null

# Allow blank-password root auth via dropbear `-B`. The litebox-base
# image ships root with a hashed password; clear it so the test can
# `sshpass -p ""` non-interactively without managing keys.
RUN passwd -d root

# Copilot CLI. Pin version so test behaviour doesn't drift silently
# with upstream releases.
ARG COPILOT_CLI_VERSION=1.0.51
RUN npm install -g "@github/copilot@${COPILOT_CLI_VERSION}" \
    && npm cache clean --force \
    && copilot --version

# Workspace mount point — the integration test bind-mounts a fresh
# per-trial fixture tree here.
RUN mkdir -p /workspace
WORKDIR /workspace

# Litebox binaries are bind-mounted at runtime under /opt/litebox/.

EXPOSE 22
