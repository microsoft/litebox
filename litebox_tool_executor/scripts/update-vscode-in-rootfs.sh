#!/bin/bash
# Update VS Code CLI and Server in an existing rootfs to match the local
# VS Code version. Run this when VS Code updates to a new commit.
#
# Usage: ./update-vscode-in-rootfs.sh [rootfs-dir]
set -euo pipefail

ROOTFS="${1:-/home/wportnoy/vscode-rootfs}"

# Detect VS Code commit from Windows host
COMMIT=""
if command -v code >/dev/null 2>&1; then
    COMMIT=$(code --version 2>/dev/null | sed -n '2p')
fi
if [ -z "$COMMIT" ]; then
    COMMIT=$(powershell.exe -NoProfile -Command '(code --version 2>$null | Select-Object -Index 1)' 2>/dev/null | tr -d '\r\n')
fi
if [ -z "$COMMIT" ] || ! echo "$COMMIT" | grep -qE '^[a-f0-9]{40}$'; then
    echo "ERROR: Could not detect VS Code commit. Is VS Code installed?"
    exit 1
fi
echo "VS Code commit: $COMMIT"

echo "=== Updating VS Code CLI ==="
CLI_PATH="$ROOTFS/root/.vscode-server/code-$COMMIT"
if [ -f "$CLI_PATH" ]; then
    echo "  CLI already installed"
else
    CLI_URL="https://update.code.visualstudio.com/commit:${COMMIT}/cli-linux-x64/stable"
    echo "  Downloading CLI from $CLI_URL..."
    TARBALL="/tmp/vscode-cli-$$.tar.gz"
    curl -sL -o "$TARBALL" "$CLI_URL"
    cd "$ROOTFS/root/.vscode-server"
    tar -xf "$TARBALL"
    mv code "code-$COMMIT"
    chmod +x "code-$COMMIT"
    rm -f "$TARBALL"
    echo "  Installed CLI ($(du -h "$CLI_PATH" | cut -f1))"
fi

echo "=== Updating VS Code Server ==="
SERVER_DIR="$ROOTFS/root/.vscode-server/cli/servers/Stable-$COMMIT/server"
if [ -d "$SERVER_DIR" ] && [ -f "$SERVER_DIR/node" ]; then
    echo "  Server already installed"
else
    SERVER_URL="https://update.code.visualstudio.com/commit:${COMMIT}/server-linux-x64/stable"
    echo "  Downloading Server from $SERVER_URL..."
    TARBALL="/tmp/vscode-server-$$.tar.gz"
    curl -sL -o "$TARBALL" "$SERVER_URL"
    mkdir -p "$SERVER_DIR"
    tar -xf "$TARBALL" -C "$SERVER_DIR" --strip-components=1
    rm -f "$TARBALL"
    echo "  Installed Server ($(find "$SERVER_DIR" -type f | wc -l) files)"
fi

echo "=== Patching code-server ROOT ==="
CODE_SERVER="$SERVER_DIR/bin/code-server"
if [ -f "$CODE_SERVER" ]; then
    GUEST_ROOT="/root/.vscode-server/cli/servers/Stable-$COMMIT/server"
    sed -i "s|^ROOT=.*|ROOT=\"${GUEST_ROOT}\"|" "$CODE_SERVER"
    echo "  $(grep '^ROOT=' "$CODE_SERVER")"
fi

echo "=== Done ==="
echo "Rootfs updated for VS Code commit $COMMIT"
