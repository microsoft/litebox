FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# ── Core packages ──
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash coreutils findutils grep sed gawk git \
    ca-certificates curl wget xz-utils tar \
    procps less openssh-sftp-server \
    dropbear-bin python3-minimal \
    && rm -rf /var/lib/apt/lists/*

# ── Node.js (pinned version) ──
ARG NODE_VERSION=v24.14.1
RUN curl -fsSL "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.xz" \
    | tar xJ -C /usr/local --strip-components=1 \
    && node --version

# ── System config ──
# Note: /etc/resolv.conf is a read-only bind-mount during docker build.
# It will be set to "nameserver 10.0.0.1" at container runtime by the entrypoint.
RUN printf 'root::0:0:root:/root:/usr/bin/bash\nuser:x:1000:1000:user:/root:/usr/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n' > /etc/passwd \
    && printf 'root:x:0:\nuser:x:1000:\nnogroup:x:65534:\n' > /etc/group \
    && printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n' > /etc/nsswitch.conf

# ── Dropbear SSH ──
RUN mkdir -p /etc/dropbear \
    && dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null

# ── sftp-server symlinks ──
RUN mkdir -p /usr/libexec \
    && ln -sf /usr/lib/openssh/sftp-server /usr/libexec/sftp-server \
    && ln -sf /usr/lib/openssh/sftp-server /usr/lib/sftp-server

# ── VS Code CLI + Server (latest stable) ──
RUN mkdir -p /root/.vscode-server \
    && curl -fsSL "https://code.visualstudio.com/sha/download?build=stable&os=cli-alpine-x64" \
       -o /tmp/vscode-cli.tar.gz \
    && tar xzf /tmp/vscode-cli.tar.gz -C /root/.vscode-server \
    && rm /tmp/vscode-cli.tar.gz \
    && ls -la /root/.vscode-server/code

# Extract the commit hash from the CLI and download the matching server.
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
    && chmod -R 777 /root/.vscode-server

# ── Directory structure ──
RUN mkdir -p /tmp /workspaces /home /shared /dev /proc /root \
    && touch /tmp/vscode-skip-server-requirements-check \
    && [ -e /bin ] || ln -sf /usr/bin /bin \
    && echo "nameserver 10.0.0.1" > /etc/resolv.conf.litebox

EXPOSE 22
