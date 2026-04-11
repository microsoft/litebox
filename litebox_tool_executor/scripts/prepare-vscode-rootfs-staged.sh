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
echo "=== Summary ==="
TOTAL_SIZE=$(du -sh "$OUTPUT" | cut -f1)
FILE_COUNT=$(find "$OUTPUT" -type f | wc -l)

echo ""
echo "Created rootfs at $OUTPUT"
echo "  Total size: $TOTAL_SIZE"
echo "  File count: $FILE_COUNT"
echo ""
echo "Key binaries:"
for bin in node git python3 bash sshd sftp-server; do
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
