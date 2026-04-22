# ═══════════════════════════════════════════════════════════════════
# LiteBox rootfs Dockerfile — multi-target build
#
# Targets:
#   litebox-base   — shared Ubuntu 24.04 foundation (not used directly)
#   litebox-test   — test harness rootfs (bash + coreutils + Node.js)
#   litebox-vscode — VS Code Server rootfs (adds SSH, VS Code CLI+Server)
#
# Usage:
#   docker build --target litebox-test   -t litebox-test   -f litebox_tool_executor/rootfs/Dockerfile .
#   docker build --target litebox-vscode -t litebox-vscode -f litebox_tool_executor/rootfs/Dockerfile .
#
# Runtime (tests):
#   docker run --rm --cap-add SYS_PTRACE \
#     -v $(pwd)/target/debug:/opt/litebox:ro \
#     -v $(pwd)/target/nonpie/debug:/opt/nonpie:ro \
#     litebox-test /opt/litebox/litebox_test_harness spawn-tree
#
# Runtime (VS Code Server):
#   docker run --rm -p 2222:22 --cap-add SYS_PTRACE \
#     -v $(pwd)/target/debug:/opt/litebox:ro \
#     litebox-vscode /opt/litebox/litebox_tool_executor \
#       --rootfs / --vscode-server --ssh-port 22 \
#       --policy /opt/litebox/policies/demo-policy.json
# ═══════════════════════════════════════════════════════════════════

# === Stage 1: shared base ===
FROM ubuntu:24.04 AS litebox-base

ENV DEBIAN_FRONTEND=noninteractive

# Core packages shared by all targets.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash coreutils findutils grep sed gawk \
    ca-certificates curl xz-utils tar \
    procps less \
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

# === Stage 2b: VS Code Server rootfs ===
FROM litebox-base AS litebox-vscode

# Additional packages for VS Code Server mode.
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-sftp-server dropbear-bin python3-minimal nodejs git wget \
    && rm -rf /var/lib/apt/lists/* \
    && node --version

# Dropbear SSH server.
RUN mkdir -p /etc/dropbear \
    && dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null

# VS Code CLI (latest stable).
RUN mkdir -p /root/.vscode-server \
    && curl -fsSL "https://code.visualstudio.com/sha/download?build=stable&os=cli-alpine-x64" \
       -o /tmp/vscode-cli.tar.gz \
    && tar xzf /tmp/vscode-cli.tar.gz -C /root/.vscode-server \
    && rm /tmp/vscode-cli.tar.gz \
    && ls -la /root/.vscode-server/code

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
    && chmod -R 777 /root/.vscode-server \
    && touch /tmp/vscode-skip-server-requirements-check

# Litebox binaries are bind-mounted at runtime:
#   /opt/litebox/ — litebox_tool_executor, litebox_broker, litebox_runner

EXPOSE 22
