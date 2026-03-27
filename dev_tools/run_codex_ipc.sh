#!/bin/bash
# Launch OpenAI Codex CLI inside the litebox sandbox using IPC networking.
#
# Runs Codex transparently — the sandbox sees the same HOME, working
# directory, and files as the host via 9P.  If a pre-built tar file exists,
# it is loaded as the initial filesystem; otherwise Codex runs directly from
# the host binary.
#
# If the broker is already running (socket exists and connectable), the script
# connects to it directly.  Otherwise it starts a broker in the background and
# cleans it up on exit.
#
# Usage: ./dev_tools/run_codex_ipc.sh [codex args...]
#
# Examples:
#   ./dev_tools/run_codex_ipc.sh                    # interactive TUI
#   ./dev_tools/run_codex_ipc.sh -q "say hello"    # one-shot prompt
#
# Prerequisite:
#   cargo build --release -p litebox_runner_linux_userland -p litebox_broker
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNNER="$REPO_ROOT/target/release/litebox_runner_linux_userland"
BROKER="$REPO_ROOT/target/release/litebox_broker"
TAR="${CODEX_TAR:-/tmp/codex_ustar.tar}"
BROKER_SOCK="${BROKER_SOCK:-/tmp/litebox-broker.sock}"
CWD="${SANDBOX_CWD:-$(pwd)}"

# --- Shared helper: test whether a Unix-domain socket is connectable. --------
broker_alive() {
    [ -S "$1" ] && python3 -c "
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect(sys.argv[1])
    s.close()
except: sys.exit(1)
" "$1" 2>/dev/null
}

# --- Locate binaries. --------------------------------------------------------
CODEX_BIN="$(which codex 2>/dev/null || true)"
if [ -z "$CODEX_BIN" ]; then
    echo "Error: codex not found on PATH" >&2
    exit 1
fi

if [ ! -x "$RUNNER" ]; then
    echo "Error: runner not found at $RUNNER" >&2
    echo "Run: cargo build --release -p litebox_runner_linux_userland" >&2
    exit 1
fi

# --- Start or reuse broker. --------------------------------------------------
STARTED_BROKER=false

cleanup() {
    if [ "$STARTED_BROKER" = true ] && [ -n "${BROKER_PID:-}" ]; then
        kill "$BROKER_PID" 2>/dev/null || true
        wait "$BROKER_PID" 2>/dev/null || true
        rm -f "$BROKER_SOCK"
    fi
}
trap cleanup EXIT

if broker_alive "$BROKER_SOCK"; then
    [ "${DEBUG:-}" = "1" ] && echo "Using existing broker at $BROKER_SOCK"
else
    rm -f "$BROKER_SOCK"

    if [ ! -x "$BROKER" ]; then
        echo "Error: broker not found at $BROKER" >&2
        echo "Run: cargo build --release -p litebox_broker" >&2
        exit 1
    fi

    RUST_LOG="${RUST_LOG:-litebox_broker=warn}" "$BROKER" \
      --root-dir / \
      --rewrite-syscalls \
      --read-only \
      --writable-path "$HOME" \
      --writable-path "$CWD" \
      --writable-path /tmp \
      --network-proxy-listen "$BROKER_SOCK" &
    BROKER_PID=$!
    STARTED_BROKER=true

    for i in $(seq 1 50); do
        if [ -S "$BROKER_SOCK" ]; then
            break
        fi
        sleep 0.1
    done
    if [ ! -S "$BROKER_SOCK" ]; then
        echo "Error: broker did not create socket at $BROKER_SOCK" >&2
        exit 1
    fi
fi

# --- Build runner arguments. -------------------------------------------------
RUNNER_ARGS=(
    -Z
    --forward-env
    --network-broker "$BROKER_SOCK"
    --nine-p-broker "$BROKER_SOCK"
    --cwd "$CWD"
    --env GIT_CONFIG_COUNT=1
    --env GIT_CONFIG_KEY_0=safe.directory
    --env "GIT_CONFIG_VALUE_0=*"
)

if [ -f "$TAR" ]; then
    RUNNER_ARGS+=(--initial-files "$TAR" --program-from-tar)
fi

# --- Run the guest. ----------------------------------------------------------
"$RUNNER" "${RUNNER_ARGS[@]}" -- "$CODEX_BIN" "$@"
