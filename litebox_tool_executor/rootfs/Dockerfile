FROM ubuntu:24.04 AS base

ARG NODE_VERSION=v24.14.1

ENV DEBIAN_FRONTEND=noninteractive

# Core utilities needed by VS Code, git, and shell tests.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    coreutils \
    findutils \
    grep \
    sed \
    gawk \
    git \
    ca-certificates \
    curl \
    wget \
    xz-utils \
    tar \
    procps \
    less \
    openssh-sftp-server \
    && rm -rf /var/lib/apt/lists/*

# Dropbear SSH server (from Ubuntu packages).
RUN apt-get update && apt-get install -y --no-install-recommends \
    dropbear-bin \
    && rm -rf /var/lib/apt/lists/*

# Node.js (pinned version, not from distro).
RUN curl -fsSL "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.xz" \
    | tar xJ -C /usr/local --strip-components=1 \
    && node --version

# Python (minimal, for VS Code extensions that need it).
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-minimal \
    && rm -rf /var/lib/apt/lists/*

# NSS libraries (required for getpwnam/getgrnam).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss-resolve \
    && rm -rf /var/lib/apt/lists/* \
    || true

# ── Configuration ──

# DNS resolver pointing at broker virtual IP.
RUN echo "nameserver 10.0.0.1" > /etc/resolv.conf

# Minimal passwd/group. root has an empty password for dropbear -B.
RUN printf 'root::0:0:root:/root:/usr/bin/bash\nuser:x:1000:1000:user:/root:/usr/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n' > /etc/passwd \
 && printf 'root:x:0:\nuser:x:1000:\nnogroup:x:65534:\n' > /etc/group \
 && printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n' > /etc/nsswitch.conf

# Dropbear host key.
RUN mkdir -p /etc/dropbear \
 && dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null

# sftp-server symlinks (dropbear and Windows scp expect different paths).
RUN mkdir -p /usr/libexec \
 && ln -sf /usr/lib/openssh/sftp-server /usr/libexec/sftp-server \
 && ln -sf /usr/lib/openssh/sftp-server /usr/lib/sftp-server

# VS Code Server data directories (writable at runtime).
RUN mkdir -p /root/.vscode-server/bin \
             /root/.vscode-server/data/logs \
             /root/.vscode-server/data/Machine \
             /root/.vscode-server/extensions \
             /root/.vscode-server/cli \
 && chmod -R 777 /root/.vscode-server

# Skip VS Code Server prerequisites check.
RUN mkdir -p /tmp && touch /tmp/vscode-skip-server-requirements-check

# Essential directories.
RUN mkdir -p /workspaces /home /shared /dev /proc

# /bin -> /usr/bin compatibility.
RUN [ -e /bin ] || ln -sf /usr/bin /bin
