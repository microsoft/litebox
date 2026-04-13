#!/bin/bash
# Download Node.js and prepare rootfs directory for VS Code Server
# Prepare a rootfs directory for VS Code Server with runtime syscall rewriting.
#
# Binaries are staged as-is (no pre-rewriting). The broker's --rewrite-syscalls
# flag rewrites ELF binaries on-the-fly when they're read over 9P. This
# simplifies rootfs preparation and supports VS Code's localServerDownload
# (where the client transfers the server tarball at connection time).
#
# Usage:
#   ./prepare-vscode-rootfs-staged.sh [output-dir]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT="${1:-$WORKSPACE/target/vscode-rootfs}"
NODE_VERSION="v24.14.1"

mkdir -p "$OUTPUT"

declare -A STAGED_LIBS

stage_lib() {
    local orig_path="$1"
    local lib_path
    lib_path=$(readlink -f "$orig_path")
    if [ "${STAGED_LIBS[$lib_path]:-}" = "1" ]; then
        if [ "$orig_path" != "$lib_path" ]; then
            local sym_dest="$OUTPUT$orig_path"
            if [ ! -e "$sym_dest" ]; then
                mkdir -p "$(dirname "$sym_dest")"
                cp "$OUTPUT$lib_path" "$sym_dest" 2>/dev/null || true
            fi
        fi
        return
    fi
    STAGED_LIBS["$lib_path"]=1
    local dest="$OUTPUT$lib_path"
    mkdir -p "$(dirname "$dest")"
    cp "$lib_path" "$dest"
    if [ "$orig_path" != "$lib_path" ]; then
        local sym_dest="$OUTPUT$orig_path"
        if [ ! -e "$sym_dest" ]; then
            mkdir -p "$(dirname "$sym_dest")"
            cp "$dest" "$sym_dest"
        fi
    fi
}

stage_deps() {
    local binary="$1"
    local deps
    deps=$(ldd "$binary" 2>/dev/null || true)
    while IFS= read -r line; do
        line=$(echo "$line" | xargs)
        [ -z "$line" ] && continue
        local lib_path=""
        if echo "$line" | grep -q "=>"; then
            lib_path=$(echo "$line" | sed -n 's/.*=> \(\/[^ ]*\).*/\1/p')
        elif echo "$line" | grep -q "^/"; then
            lib_path=$(echo "$line" | awk '{print $1}')
        fi
        if [ -n "$lib_path" ] && [ -f "$lib_path" ]; then
            stage_lib "$lib_path"
        fi
    done <<< "$deps"
}

stage_binary() {
    local host_path="$1"
    local dest_path="${2:-$host_path}"

    if [ ! -f "$host_path" ]; then
        echo "  SKIP: $host_path not found"
        return
    fi

    local dest="$OUTPUT$dest_path"
    if [ -f "$dest" ]; then
        return
    fi

    echo "  staging: $host_path -> $dest_path"
    mkdir -p "$(dirname "$dest")"
    cp "$host_path" "$dest"
    chmod +x "$dest"
    stage_deps "$host_path"
}

stage_binary_by_name() {
    local name="$1"
    local host_path
    host_path=$(which "$name" 2>/dev/null || true)
    if [ -z "$host_path" ]; then
        echo "  SKIP: $name not found on host"
        return
    fi
    host_path=$(readlink -f "$host_path")
    stage_binary "$host_path"
}

# ============================================================
echo "=== Phase 1: Download Node.js ==="
NODE_DIR="/tmp/node-${NODE_VERSION}-linux-x64"
if [ ! -f "$NODE_DIR/bin/node" ]; then
    echo "  Downloading Node.js $NODE_VERSION..."
    curl -fsSL "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.xz" \
        -o /tmp/node-download.tar.xz
    cd /tmp && tar xf node-download.tar.xz
    rm -f /tmp/node-download.tar.xz
fi
echo "  Node.js ready: $("$NODE_DIR/bin/node" --version)"

# ============================================================
echo "=== Phase 2: Stage shell + core utilities ==="
UTILS=(bash cat ls grep sort uniq wc find head tail mkdir rm cp mv echo tr sed awk
       pwd dirname basename env printenv date id uname xargs tee touch chmod
       ps pgrep kill hostname readlink ln less which whoami
       tar gzip gunzip curl wget sleep scp
       getconf nproc dd mktemp chown stat cut)

for util in "${UTILS[@]}"; do
    stage_binary_by_name "$util"
done

# ============================================================
echo "=== Phase 3: Stage git ==="
stage_binary_by_name git
# git needs its exec path helpers
GIT_EXEC_PATH=$(git --exec-path 2>/dev/null || echo "/usr/lib/git-core")
if [ -d "$GIT_EXEC_PATH" ]; then
    echo "  Staging git exec helpers from $GIT_EXEC_PATH..."
    mkdir -p "$OUTPUT$GIT_EXEC_PATH"
    for helper in "$GIT_EXEC_PATH"/git-*; do
        [ -f "$helper" ] || continue
        local_name=$(basename "$helper")
        if [ ! -f "$OUTPUT$GIT_EXEC_PATH/$local_name" ]; then
            cp "$helper" "$OUTPUT$GIT_EXEC_PATH/$local_name"
            chmod +x "$OUTPUT$GIT_EXEC_PATH/$local_name"
        fi
    done
    stage_deps "$(which git)"
fi

# ============================================================
echo "=== Phase 4: Stage Node.js ==="
stage_binary "$NODE_DIR/bin/node" "/usr/local/bin/node"
# Copy npm and npx
if [ -d "$NODE_DIR/lib/node_modules" ]; then
    echo "  Copying npm modules..."
    mkdir -p "$OUTPUT/usr/local/lib"
    cp -r "$NODE_DIR/lib/node_modules" "$OUTPUT/usr/local/lib/"
    # Create npm/npx symlinks
    mkdir -p "$OUTPUT/usr/local/bin"
    ln -sf ../lib/node_modules/npm/bin/npm-cli.js "$OUTPUT/usr/local/bin/npm"
    ln -sf ../lib/node_modules/npm/bin/npx-cli.js "$OUTPUT/usr/local/bin/npx"
fi

# ============================================================
echo "=== Phase 5: Stage Python ==="
stage_binary_by_name python3
# Stage python standard library
PYTHON_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "3.12")
PYTHON_LIB="/usr/lib/python${PYTHON_VER}"
if [ -d "$PYTHON_LIB" ]; then
    echo "  Copying Python standard library ($PYTHON_VER)..."
    mkdir -p "$OUTPUT$PYTHON_LIB"
    # Copy just the essential modules, not everything
    cp -r "$PYTHON_LIB"/*.py "$OUTPUT$PYTHON_LIB/" 2>/dev/null || true
    for subdir in collections encodings importlib json logging email http urllib; do
        if [ -d "$PYTHON_LIB/$subdir" ]; then
            cp -r "$PYTHON_LIB/$subdir" "$OUTPUT$PYTHON_LIB/"
        fi
    done
    # Copy compiled extensions
    PYTHON_DYNLOAD="/usr/lib/python${PYTHON_VER}/lib-dynload"
    if [ -d "$PYTHON_DYNLOAD" ]; then
        mkdir -p "$OUTPUT$PYTHON_DYNLOAD"
        for so in "$PYTHON_DYNLOAD"/*.so; do
            [ -f "$so" ] || continue
            cp "$so" "$OUTPUT$PYTHON_DYNLOAD/$(basename "$so")"
        done
    fi
fi

# ============================================================
echo "=== Phase 6: Stage SSL/TLS libraries and certificates ==="
# libssl and libcrypto
for lib in /usr/lib/x86_64-linux-gnu/libssl.so* /usr/lib/x86_64-linux-gnu/libcrypto.so*; do
    [ -f "$lib" ] || continue
    stage_lib "$lib"
done

# CA certificates
if [ -d /etc/ssl/certs ]; then
    echo "  Copying CA certificates..."
    mkdir -p "$OUTPUT/etc/ssl/certs"
    cp -r /etc/ssl/certs/* "$OUTPUT/etc/ssl/certs/" 2>/dev/null || true
fi
if [ -f /etc/ssl/openssl.cnf ]; then
    mkdir -p "$OUTPUT/etc/ssl"
    cp /etc/ssl/openssl.cnf "$OUTPUT/etc/ssl/"
fi

# libstdc++ (required by VS Code CLI / Node.js)
# The VS Code CLI specifically checks /lib64/libstdc++.so.6
LIBSTDCPP=$(find /usr/lib/x86_64-linux-gnu -name "libstdc++.so.6.*" -type f 2>/dev/null | head -1)
if [ -n "$LIBSTDCPP" ]; then
    stage_lib "$LIBSTDCPP"
    ln -sf "$(basename "$LIBSTDCPP")" "$OUTPUT/usr/lib/x86_64-linux-gnu/libstdc++.so.6"
    # VS Code CLI checks this exact path
    mkdir -p "$OUTPUT/lib64"
    cp "$LIBSTDCPP" "$OUTPUT/lib64/libstdc++.so.6"
    echo "  Staged libstdc++ ($(basename "$LIBSTDCPP"))"
fi

# Additional libs needed by the glibc VS Code CLI
for lib in librt.so.1 libgcc_s.so.1; do
    SRC="/lib/x86_64-linux-gnu/$lib"
    [ -f "$SRC" ] && stage_lib "$SRC"
done

# ldconfig (VS Code CLI checks for it to detect GNU environment)
# On Ubuntu, /sbin/ldconfig is a shell wrapper; use ldconfig.real instead.
LDCONFIG_REAL="/sbin/ldconfig.real"
if [ ! -f "$LDCONFIG_REAL" ]; then
    LDCONFIG_REAL=$(readlink -f /sbin/ldconfig 2>/dev/null || echo /sbin/ldconfig)
fi
if [ -f "$LDCONFIG_REAL" ]; then
    mkdir -p "$OUTPUT/sbin"
    cp "$LDCONFIG_REAL" "$OUTPUT/sbin/ldconfig"
    chmod +x "$OUTPUT/sbin/ldconfig"
    echo "  Staged ldconfig"
fi

# ============================================================
echo "=== Phase 7: Install dropbear SSH server ==="
# dropbear runs inside the sandbox as the init process. VS Code connects
# via SSH, and dropbear fork+execs bash/VS Code Server — all sharing
# one filesystem. dropbear uses fork+exec (DROPBEAR_DO_REEXEC) which is
# compatible with litebox's delayed-fork semantics (unlike OpenSSH sshd
# whose privilege separation requires concurrent parent+child execution).
DROPBEAR_DEB_DIR=$(mktemp -d)
(
    cd "$DROPBEAR_DEB_DIR"
    # Download dropbear-bin and its crypto dependencies.
    # Also download openssh-sftp-server — dropbear has no native SFTP
    # but can launch an external sftp-server binary.
    apt-get download dropbear-bin libtomcrypt1 libtommath1 openssh-sftp-server 2>/dev/null
    for deb in *.deb; do
        [ -f "$deb" ] || continue
        dpkg-deb -x "$deb" "$DROPBEAR_DEB_DIR/ext"
    done
)

# Install dropbear binary
if [ -f "$DROPBEAR_DEB_DIR/ext/usr/sbin/dropbear" ]; then
    mkdir -p "$OUTPUT/usr/sbin"
    cp "$DROPBEAR_DEB_DIR/ext/usr/sbin/dropbear" "$OUTPUT/usr/sbin/dropbear"
    chmod +x "$OUTPUT/usr/sbin/dropbear"
    echo "  Installed dropbear"
    stage_deps "$DROPBEAR_DEB_DIR/ext/usr/sbin/dropbear"
fi

# Install dropbearkey (host key generator)
if [ -f "$DROPBEAR_DEB_DIR/ext/usr/bin/dropbearkey" ]; then
    mkdir -p "$OUTPUT/usr/bin"
    cp "$DROPBEAR_DEB_DIR/ext/usr/bin/dropbearkey" "$OUTPUT/usr/bin/dropbearkey"
    chmod +x "$OUTPUT/usr/bin/dropbearkey"
    echo "  Installed dropbearkey"
fi

# Install dropbear's crypto libs (libtomcrypt, libtommath)
for lib in libtomcrypt.so.1 libtommath.so.1; do
    LIBPATH=$(find "$DROPBEAR_DEB_DIR/ext" -name "$lib*" -type f 2>/dev/null | head -1)
    if [ -n "$LIBPATH" ]; then
        stage_lib "$LIBPATH"
    fi
done

# Install sftp-server (from openssh-sftp-server package)
SFTP=$(find "$DROPBEAR_DEB_DIR/ext" -name "sftp-server" -type f 2>/dev/null | head -1)
if [ -n "$SFTP" ]; then
    mkdir -p "$OUTPUT/usr/lib/openssh"
    cp "$SFTP" "$OUTPUT/usr/lib/openssh/sftp-server"
    chmod +x "$OUTPUT/usr/lib/openssh/sftp-server"
    echo "  Installed sftp-server"
    stage_deps "$SFTP"
fi

# Symlink sftp-server where dropbear expects it (/usr/libexec/sftp-server)
mkdir -p "$OUTPUT/usr/libexec"
ln -sf /usr/lib/openssh/sftp-server "$OUTPUT/usr/libexec/sftp-server"
echo "  Symlinked /usr/libexec/sftp-server → /usr/lib/openssh/sftp-server"

# Generate host key (dropbear format)
mkdir -p "$OUTPUT/etc/dropbear"
if [ ! -f "$OUTPUT/etc/dropbear/dropbear_ed25519_host_key" ]; then
    LD_LIBRARY_PATH="$DROPBEAR_DEB_DIR/ext/usr/lib/x86_64-linux-gnu:$DROPBEAR_DEB_DIR/ext/lib/x86_64-linux-gnu" \
        "$DROPBEAR_DEB_DIR/ext/usr/bin/dropbearkey" -t ed25519 \
        -f "$OUTPUT/etc/dropbear/dropbear_ed25519_host_key" 2>/dev/null
    echo "  Generated ed25519 host key"
fi

rm -rf "$DROPBEAR_DEB_DIR"

# ============================================================
echo "=== Phase 8: Create directory structure and config ==="
# Essential directories
mkdir -p "$OUTPUT/tmp" "$OUTPUT/etc" "$OUTPUT/dev" "$OUTPUT/proc"
mkdir -p "$OUTPUT/workspaces" "$OUTPUT/root" "$OUTPUT/home"
mkdir -p "$OUTPUT/bin" "$OUTPUT/usr/bin" "$OUTPUT/usr/local/bin"

# Skip VS Code Server prerequisites check — the CLI checks for libstdc++
# and ldconfig, but the sandbox's 9P filesystem doesn't expose /lib64/
# paths reliably. The skip file tells the CLI to trust the environment.
touch "$OUTPUT/tmp/vscode-skip-server-requirements-check"

# VS Code Server data directories (writable at runtime).
# VS Code's localServerDownload will transfer the server tarball here.
mkdir -p "$OUTPUT/root/.vscode-server/bin"
mkdir -p "$OUTPUT/root/.vscode-server/data/logs"
mkdir -p "$OUTPUT/root/.vscode-server/data/Machine"
mkdir -p "$OUTPUT/root/.vscode-server/extensions"
chmod -R 777 "$OUTPUT/root/.vscode-server"

# DNS resolver pointing at broker virtual IP
echo "nameserver 10.0.0.1" > "$OUTPUT/etc/resolv.conf"

# Minimal /etc/passwd and /etc/group
# root has an empty password (no 'x' which would require /etc/shadow).
# dropbear with -B (blank passwords) accepts this for SSH login.
cat > "$OUTPUT/etc/passwd" << 'EOF'
root::0:0:root:/root:/usr/bin/bash
user:x:1000:1000:user:/root:/usr/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
EOF

cat > "$OUTPUT/etc/group" << 'EOF'
root:x:0:
user:x:1000:
nogroup:x:65534:
EOF

# NSS configuration: glibc's getpwnam/getgrnam need nsswitch.conf
# and libnss_files to read /etc/passwd and /etc/group.
cat > "$OUTPUT/etc/nsswitch.conf" << 'EOF'
passwd:   files
group:    files
shadow:   files
hosts:    files dns
EOF

# Stage libnss_files (required) and libnss_dns (for hostname resolution)
for nss_lib in libnss_files.so.2 libnss_dns.so.2; do
    if [ -f "/lib/x86_64-linux-gnu/$nss_lib" ]; then
        stage_lib "/lib/x86_64-linux-gnu/$nss_lib"
    fi
done

# Valid login shells (dropbear checks getusershell())
cat > "$OUTPUT/etc/shells" << 'EOF'
/bin/sh
/bin/bash
/usr/bin/bash
EOF

# SSH authorized keys: copy host user's public keys so VS Code
# Remote-SSH can connect without repeated password prompts.
mkdir -p "$OUTPUT/root/.ssh"
chmod 700 "$OUTPUT/root/.ssh"
AUTH_KEYS="$OUTPUT/root/.ssh/authorized_keys"
: > "$AUTH_KEYS"
for keyfile in ~/.ssh/id_ed25519.pub ~/.ssh/id_rsa.pub ~/.ssh/id_ecdsa.pub; do
    if [ -f "$keyfile" ]; then
        cat "$keyfile" >> "$AUTH_KEYS"
        echo "  Added $(basename "$keyfile") to authorized_keys"
    fi
done
if [ -s "$AUTH_KEYS" ]; then
    chmod 600 "$AUTH_KEYS"
else
    echo "  No SSH public keys found — password auth will be used"
    rm -f "$AUTH_KEYS"
fi

# OS release info (VS Code bootstrap reads this to detect platform)
cat > "$OUTPUT/etc/os-release" << 'EOF'
PRETTY_NAME="Ubuntu 24.04 LTS (LiteBox)"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04 LTS"
ID=ubuntu
ID_LIKE=debian
EOF

# Compatibility symlinks
for util in "${UTILS[@]}"; do
    real_path=$(readlink -f "$(which "$util" 2>/dev/null)" 2>/dev/null || true)
    if [ -n "$real_path" ] && [ -f "$OUTPUT$real_path" ]; then
        if [[ "$real_path" == /usr/bin/* ]] && [ ! -e "$OUTPUT/bin/$(basename "$real_path")" ]; then
            ln -sf "$real_path" "$OUTPUT/bin/$(basename "$real_path")" 2>/dev/null || true
        fi
    fi
done

# sh: VS Code bootstrap sends 'ssh litebox sh' — sh must be a real file
# (not a symlink) because the sandbox's 9P filesystem doesn't always
# resolve symlinks with absolute targets correctly.
cp "$OUTPUT/usr/bin/bash" "$OUTPUT/usr/bin/sh" 2>/dev/null || true

# python3 symlink
if [ -f "$OUTPUT/usr/bin/python3.12" ] && [ ! -f "$OUTPUT/usr/bin/python3" ]; then
    ln -sf python3.12 "$OUTPUT/usr/bin/python3"
fi

# Ensure dynamic linker is at PT_INTERP path
if [ ! -f "$OUTPUT/lib64/ld-linux-x86-64.so.2" ]; then
    mkdir -p "$OUTPUT/lib64"
    real_ld=$(readlink -f /lib64/ld-linux-x86-64.so.2 2>/dev/null || true)
    if [ -n "$real_ld" ] && [ -f "$OUTPUT$real_ld" ]; then
        cp "$OUTPUT$real_ld" "$OUTPUT/lib64/ld-linux-x86-64.so.2"
        echo "  Copied ld-linux to /lib64/"
    fi
fi

# ============================================================
echo "=== Phase 8: Pre-install VS Code CLI ==="
# Download the VS Code CLI so the bootstrap script finds it already
# installed and skips the download/install steps (which use $(cmd | pipe)
# that deadlocks in litebox's delayed-fork).
#
# Detect the local VS Code commit ID. If VS Code isn't installed or
# the commit can't be determined, skip this phase — the user can
# re-run after installing VS Code.
VSCODE_COMMIT=""
if command -v code >/dev/null 2>&1; then
    VSCODE_COMMIT=$(code --version 2>/dev/null | sed -n '2p')
fi
# Also check Windows VS Code via PowerShell (for WSL builds)
if [ -z "$VSCODE_COMMIT" ]; then
    VSCODE_COMMIT=$(powershell.exe -NoProfile -Command "(code --version 2>\$null | Select-Object -Index 1)" 2>/dev/null | tr -d '\r\n')
fi

if [ -n "$VSCODE_COMMIT" ] && echo "$VSCODE_COMMIT" | grep -qE '^[a-f0-9]{40}$'; then
    echo "  VS Code commit: $VSCODE_COMMIT"
    CLI_NAME="code-${VSCODE_COMMIT}"
    CLI_DIR="$OUTPUT/root/.vscode-server"
    CLI_PATH="$CLI_DIR/$CLI_NAME"

    if [ -f "$CLI_PATH" ]; then
        echo "  CLI already installed at $CLI_PATH"
    else
        CLI_URL="https://update.code.visualstudio.com/commit:${VSCODE_COMMIT}/cli-linux-x64/stable"
        echo "  Downloading VS Code CLI from $CLI_URL ..."
        mkdir -p "$CLI_DIR"
        TARBALL="$CLI_DIR/vscode-cli.tar.gz"
        if wget -q -O "$TARBALL" "$CLI_URL" 2>/dev/null || curl -sL -o "$TARBALL" "$CLI_URL" 2>/dev/null; then
            (cd "$CLI_DIR" && tar -xf "$TARBALL" && mv code "$CLI_NAME" && rm -f "$TARBALL")
            if [ -f "$CLI_PATH" ]; then
                chmod +x "$CLI_PATH"
                echo "  Installed VS Code CLI ($( du -h "$CLI_PATH" | cut -f1 ))"
            else
                echo "  WARNING: CLI extraction failed"
            fi
        else
            echo "  WARNING: CLI download failed (will use client download fallback)"
        fi
    fi
else
    echo "  VS Code not detected, skipping CLI pre-install"
    echo "  (re-run after installing VS Code to pre-install the CLI)"
fi

# ============================================================
echo "=== Phase 8b: Pre-install VS Code Server ==="
# The CLI (exec server) downloads and extracts the VS Code Server
# (Node.js, ~91MB) on first connection. Pre-install it so the CLI
# finds it already present. Without this, tar extraction inside
# litebox can fail due to fork limitations.
if [ -n "$VSCODE_COMMIT" ] && echo "$VSCODE_COMMIT" | grep -qE '^[a-f0-9]{40}$'; then
    SERVER_DIR="$OUTPUT/root/.vscode-server/cli/servers/Stable-${VSCODE_COMMIT}/server"
    if [ -d "$SERVER_DIR" ] && [ -f "$SERVER_DIR/node" ]; then
        echo "  VS Code Server already installed"
    else
        SERVER_URL="https://update.code.visualstudio.com/commit:${VSCODE_COMMIT}/server-linux-x64/stable"
        echo "  Downloading VS Code Server from $SERVER_URL ..."
        TARBALL="/tmp/vscode-server-$$.tar.gz"
        if wget -q -O "$TARBALL" "$SERVER_URL" 2>/dev/null || curl -sL -o "$TARBALL" "$SERVER_URL" 2>/dev/null; then
            mkdir -p "$SERVER_DIR"
            # The tarball contains a top-level vscode-server-linux-x64/ directory.
            tar -xf "$TARBALL" -C "$SERVER_DIR" --strip-components=1
            if [ -f "$SERVER_DIR/node" ]; then
                echo "  Installed VS Code Server ($(find "$SERVER_DIR" -type f | wc -l) files)"
                # Patch code-server launch scripts to avoid nested $(readlink -f)
                # subshells which can fail in litebox's delayed-fork.
                # Replace: ROOT="$(dirname "$(dirname "$(readlink -f "$0")")")"
                # With:    SCRIPT_DIR="$(dirname "$0")"; ROOT="$(dirname "$SCRIPT_DIR")"
                # This is version-independent — the pattern is the same across versions.
                for launcher in "$SERVER_DIR"/bin/code-server*; do
                    [ -f "$launcher" ] || continue
                    if grep -q 'readlink -f' "$launcher"; then
                        sed -i '/^ROOT=/c\SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$SCRIPT_DIR")"' "$launcher"
                        echo "  Patched $(basename "$launcher") to avoid readlink -f"
                    fi
                done
            else
                echo "  WARNING: Server extraction failed"
                rm -rf "$SERVER_DIR"
            fi
            rm -f "$TARBALL"
        else
            echo "  WARNING: Server download failed"
        fi
    fi
else
    echo "  Skipping (no VS Code commit detected)"
fi

# ============================================================
echo "=== Phase 9: Install VS Code bootstrap sh wrapper ==="
# VS Code sends 'ssh litebox sh' and pipes a bootstrap script.
# The bootstrap script uses $(cmd | pipe) which deadlocks in litebox.
# This wrapper intercepts the VS Code bootstrap protocol and handles
# it without pipes-in-subshells, falling back to bash for normal use.
#
# Keep the real bash as /usr/bin/bash (already installed).
cat > "$OUTPUT/usr/bin/sh" << 'SHWRAPPER'
#!/usr/bin/bash
# VS Code bootstrap interceptor.
# Detects VS Code's bootstrap script on stdin and handles the protocol
# without $(cmd | pipe). Falls back to bash for normal shell usage.
#
# IMPORTANT: This script must NEVER use $(cmd | pipe) — that pattern
# deadlocks in litebox's delayed-fork. Use temp files, single-command
# $(), and while-read loops instead.

# If we have arguments (not the VS Code 'sh' pattern), run bash directly.
if [ $# -gt 0 ] && [ "$1" != "" ]; then
    exec /usr/bin/bash "$@"
fi

# Read the bootstrap script from stdin into a temp file.
TMPSCRIPT="/tmp/.vscode-bootstrap-$$.sh"
cat > "$TMPSCRIPT"

# Check if this is a VS Code bootstrap (contains UUID marker pattern).
# Use grep on the FILE (not piped) — single command $() is safe.
UUID=$(grep -m1 '^UUID=' "$TMPSCRIPT")
UUID=${UUID#UUID=\"}
UUID=${UUID%\"}

if [ -z "$UUID" ]; then
    # Not a VS Code bootstrap — run as normal shell.
    exec /usr/bin/bash "$TMPSCRIPT"
fi

# Extract variables from the temp file.
# Each grep reads the FILE directly — no pipes in subshells.
COMMIT_ID=$(grep -m1 '^COMMIT_ID=' "$TMPSCRIPT")
COMMIT_ID=${COMMIT_ID#COMMIT_ID=\"}
COMMIT_ID=${COMMIT_ID%\"}

TOKEN=$(grep -m1 '^TOKEN=' "$TMPSCRIPT")
TOKEN=${TOKEN#TOKEN=\"}
TOKEN=${TOKEN%\"}

QUALITY=$(grep -m1 '^QUALITY=' "$TMPSCRIPT")
QUALITY=${QUALITY#QUALITY=\"}
QUALITY=${QUALITY%\"}

VSCODE_AGENT_FOLDER=$(grep -m1 '^VSCODE_AGENT_FOLDER=' "$TMPSCRIPT")
VSCODE_AGENT_FOLDER=${VSCODE_AGENT_FOLDER#VSCODE_AGENT_FOLDER=\"}
VSCODE_AGENT_FOLDER=${VSCODE_AGENT_FOLDER%\"}

LISTEN_ARGS=$(grep -m1 '^LISTEN_ARGS=' "$TMPSCRIPT")
LISTEN_ARGS=${LISTEN_ARGS#LISTEN_ARGS=\"}
LISTEN_ARGS=${LISTEN_ARGS%\"}

rm -f "$TMPSCRIPT"

# Expand $HOME in VSCODE_AGENT_FOLDER.
VSCODE_AGENT_FOLDER=${VSCODE_AGENT_FOLDER/\$HOME/$HOME}
VSCODE_AGENT_FOLDER=${VSCODE_AGENT_FOLDER/\$\{HOME\}/$HOME}
: "${VSCODE_AGENT_FOLDER:=$HOME/.vscode-server}"

CLI_NAME="code-${COMMIT_ID}"
CLI_PATH="${VSCODE_AGENT_FOLDER}/${CLI_NAME}"

# Emit the running marker.
echo "${UUID}: running"
echo "Script executing under PID: $$"

# Detect platform/arch (inline, no pipes).
PLATFORM=linux
ARCH=$(uname -m)
VSCODE_ARCH=x64
BITNESS=$(getconf LONG_BIT 2>/dev/null)
OSRELEASEID=""
if [ -f /etc/os-release ]; then
    while IFS='=' read -r key val; do
        if [ "$key" = "ID" ]; then
            OSRELEASEID=${val//\"/}
            break
        fi
    done < /etc/os-release
fi

# Check if CLI exists.
if [ ! -f "$CLI_PATH" ]; then
    echo "Installing to ${VSCODE_AGENT_FOLDER}..."
    mkdir -p "$VSCODE_AGENT_FOLDER"

    # Try wget/curl download first.
    DOWNLOAD_URL="https://update.code.visualstudio.com/commit:${COMMIT_ID}/cli-linux-x64/${QUALITY}"
    cd "$VSCODE_AGENT_FOLDER"

    DOWNLOADED=0
    if command -v wget >/dev/null 2>&1; then
        if wget --tries=1 --connect-timeout=7 -nv -O "vscode-cli-${COMMIT_ID}.tar.gz" "$DOWNLOAD_URL" 2>/dev/null; then
            DOWNLOADED=1
        fi
    fi
    if [ "$DOWNLOADED" = "0" ] && command -v curl >/dev/null 2>&1; then
        if curl --connect-timeout 7 -sL -o "vscode-cli-${COMMIT_ID}.tar.gz" "$DOWNLOAD_URL" 2>/dev/null; then
            DOWNLOADED=1
        fi
    fi

    if [ "$DOWNLOADED" = "1" ]; then
        tar -xf "vscode-cli-${COMMIT_ID}.tar.gz" 2>/dev/null
        mv code "$CLI_NAME" 2>/dev/null
        rm -f "vscode-cli-${COMMIT_ID}.tar.gz"
    fi

    if [ ! -f "$CLI_PATH" ]; then
        # Trigger client-side download (VS Code SCPs the CLI).
        echo "${UUID}%%1%%"
        echo "Trigger local server download"
        echo "${UUID}:trigger_server_download"
        echo "artifact==cli-linux-x64=="
        echo "destFolder==${VSCODE_AGENT_FOLDER}=="
        echo "destFolder2==/vscode-cli-${COMMIT_ID}.tar.gz=="
        echo "${UUID}:trigger_server_download_end"
        echo "Waiting for client to transfer server archive..."

        while [ ! -f "${VSCODE_AGENT_FOLDER}/vscode-cli-${COMMIT_ID}.tar.gz.done" ]; do
            printf ' '
            sleep 3
        done
        rm -f "${VSCODE_AGENT_FOLDER}/vscode-cli-${COMMIT_ID}.tar.gz.done"
        tar -xf "vscode-cli-${COMMIT_ID}.tar.gz" 2>/dev/null
        mv code "$CLI_NAME" 2>/dev/null
        rm -f "vscode-cli-${COMMIT_ID}.tar.gz"
    fi

    cd /
fi

if [ ! -f "$CLI_PATH" ]; then
    echo "${UUID}: start"
    echo "exitCode==205=="
    echo "${UUID}: end"
    exit 0
fi

echo "Found existing installation at ${VSCODE_AGENT_FOLDER}..."

# Start the VS Code CLI server.
# Note: --parent-process-id is omitted because litebox's delayed-fork
# migrates the CLI to a separate worker process where the sh wrapper's
# PID is not visible. The CLI would exit thinking its parent died.
echo "Starting VS Code CLI..."
export VSCODE_AGENT_FOLDER
CLI_LOG_FILE="${VSCODE_AGENT_FOLDER}/.cli.${COMMIT_ID}.log"
rm -f "$CLI_LOG_FILE"
touch "$CLI_LOG_FILE"
chmod 600 "$CLI_LOG_FILE"

VSCODE_CLI_REQUIRE_TOKEN=${TOKEN} "$CLI_PATH" command-shell \
    --cli-data-dir "$VSCODE_AGENT_FOLDER/cli" \
    --on-host 0.0.0.0 --on-port 9100 > "$CLI_LOG_FILE" 2>&1 < /dev/null &
CLI_PID=$!
echo "Spawned remote CLI: $CLI_PID"

# Wait for the server to start listening (read log file, no pipes).
LISTENING_ON=""
count=0
while [ $count -lt 15 ]; do
    count=$((count + 1))
    if [ -f "$CLI_LOG_FILE" ]; then
        # Single grep on a file — no pipe.
        LISTENING_ON=$(grep -m1 'Listening on ' "$CLI_LOG_FILE" 2>/dev/null)
        LISTENING_ON=${LISTENING_ON#*Listening on }
    fi
    if [ -n "$LISTENING_ON" ]; then
        break
    fi
    if ! kill -0 $CLI_PID 2>/dev/null; then
        echo "Exec server process not found"
        cat "$CLI_LOG_FILE" 2>/dev/null
        break
    fi
    echo "Waiting for server log..."
    sleep 1
done

# Emit result markers.
echo "${UUID}: start"
echo "listeningOn==${LISTENING_ON}=="
echo "osReleaseId==${OSRELEASEID}=="
echo "arch==${ARCH}=="
echo "vscodeArch==${VSCODE_ARCH}=="
echo "bitness==${BITNESS}=="
echo "tmpDir==/tmp=="
echo "platform==${PLATFORM}=="
echo "unpackResult==success=="
echo "didLocalDownload==0=="
echo "downloadTime===="
echo "installTime===="
echo "serverStartTime===="
echo "execServerToken==${TOKEN}=="
echo "platformDownloadPath==cli-linux-x64=="
echo "SSH_AUTH_SOCK===="
echo "DISPLAY===="
echo "${UUID}: end"

# Keep alive.
while true; do sleep 180; printf ' '; done
SHWRAPPER
chmod +x "$OUTPUT/usr/bin/sh"
echo "  Installed VS Code bootstrap sh wrapper"
TOTAL_SIZE=$(du -sh "$OUTPUT" | cut -f1)
FILE_COUNT=$(find "$OUTPUT" -type f | wc -l)

echo ""
echo "Created rootfs at $OUTPUT"
echo "  Total size: $TOTAL_SIZE"
echo "  File count: $FILE_COUNT"
echo ""
echo "Key binaries:"
for bin in node git python3 bash dropbear dropbearkey sftp-server; do
    found=$(find "$OUTPUT" -name "$bin" -type f 2>/dev/null | head -1)
    if [ -n "$found" ]; then
        echo "  $bin: ${found#$OUTPUT}"
    else
        echo "  $bin: NOT FOUND"
    fi
done
echo ""
echo "Usage (9P directory serving):"
echo "  # Start broker serving this rootfs:"
echo "  litebox_broker --root-dir $OUTPUT \\"
echo "    --network-proxy-listen /tmp/litebox-broker.sock"
echo ""
echo "  # Run node inside the sandbox:"
echo "  litebox_runner_linux_userland --unstable \\"
echo "    --network-broker /tmp/litebox-broker.sock \\"
echo "    --env 'PATH=/usr/local/bin:/usr/bin:/bin' \\"
echo "    --env 'HOME=/root' \\"
echo "    -- /usr/local/bin/node --version"
