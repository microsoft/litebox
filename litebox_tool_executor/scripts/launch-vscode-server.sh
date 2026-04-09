#!/bin/bash
# Launch VS Code Server inside litebox with stdio transport.
#
# This script is the litebox equivalent of "docker exec -i" — it starts
# the broker and runner, then runs VS Code Server with inherited stdio
# so VS Code's Remote extension can connect over the stdin/stdout pipe.
#
# Usage (manual):
#   ./launch-vscode-server.sh [workspace-path]
#
# Usage (VS Code Remote):
#   Configure as a custom remote command that VS Code invokes.
#   The client writes JSON-RPC to stdin; the server responds on stdout.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKTREE="$(cd "$SCRIPT_DIR/../.." && pwd)"
BROKER="$WORKTREE/target/debug/litebox_broker"
RUNNER="$WORKTREE/target/debug/litebox_runner_linux_userland"
ROOTFS="${LITEBOX_ROOTFS:-/home/wportnoy/vscode-rootfs}"
SOCKET="/tmp/litebox-vscode-server-$$.sock"
WORKSPACE="${1:-}"

if [ ! -f "$BROKER" ]; then
    echo "ERROR: broker not found at $BROKER" >&2
    exit 1
fi
if [ ! -f "$RUNNER" ]; then
    echo "ERROR: runner not found at $RUNNER" >&2
    exit 1
fi
if [ ! -d "$ROOTFS" ]; then
    echo "ERROR: rootfs not found at $ROOTFS" >&2
    exit 1
fi

# If a workspace path was provided, place it into the rootfs
if [ -n "$WORKSPACE" ]; then
    WORKSPACE=$(readlink -f "$WORKSPACE")
    if [ ! -d "$WORKSPACE" ]; then
        echo "ERROR: workspace not found: $WORKSPACE" >&2
        exit 1
    fi
    # Copy workspace into rootfs (or symlink if on same filesystem)
    mkdir -p "$ROOTFS/workspaces"
    rm -rf "$ROOTFS/workspaces/repo"
    cp -r "$WORKSPACE" "$ROOTFS/workspaces/repo"
    echo "Workspace copied to rootfs: $WORKSPACE -> /workspaces/repo" >&2
fi

cleanup() {
    if [ -n "${BROKER_PID:-}" ]; then
        kill "$BROKER_PID" 2>/dev/null || true
        wait "$BROKER_PID" 2>/dev/null || true
    fi
    rm -f "$SOCKET"
}
trap cleanup EXIT

# Start broker in background, redirect its output to stderr
"$BROKER" --root-dir "$ROOTFS" --network-proxy-listen "$SOCKET" >&2 &
BROKER_PID=$!

# Wait for socket
for i in $(seq 1 10); do
    if [ -S "$SOCKET" ]; then
        break
    fi
    sleep 0.5
done

if [ ! -S "$SOCKET" ]; then
    echo "ERROR: Broker socket not created after 5s" >&2
    exit 1
fi

# Determine workspace folder arg for VS Code Server
FOLDER_ARG=""
if [ -d "$ROOTFS/workspaces/repo" ]; then
    FOLDER_ARG="--folder /workspaces/repo"
fi

# Launch VS Code Server inside litebox with stdio inherited.
# Broker logs go to stderr; server stdin/stdout carry the VS Code protocol.
exec "$RUNNER" --unstable \
    --network-broker "$SOCKET" \
    --nine-p-broker "$SOCKET" \
    --env "PATH=/usr/local/bin:/usr/bin:/bin:/opt/vscode-server/bin" \
    --env "HOME=/root" \
    --env "NODE_PATH=/usr/local/lib/node_modules" \
    --env "TERM=xterm-256color" \
    --env "VSCODE_AGENT_FOLDER=/root/.vscode-server" \
    -- /usr/local/bin/node /opt/vscode-server/out/server-main.js \
    --accept-server-license-terms \
    --without-connection-token \
    --disable-telemetry \
    --host 127.0.0.1 \
    --port 0 \
    $FOLDER_ARG
