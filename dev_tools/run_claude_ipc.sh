#!/bin/bash
# Launch Claude Code inside the litebox sandbox using IPC networking.
#
# Unlike the Copilot tar workflow, Claude runs directly from the host via 9P.
# To keep the broker policy narrow while still letting Claude update its state,
# this script seeds a private writable sandbox HOME from the host's Claude
# config in a per-run temp directory.
#
# Usage: ./dev_tools/run_claude_ipc.sh [claude args...]
#
# Examples:
#   ./dev_tools/run_claude_ipc.sh --help
#   ./dev_tools/run_claude_ipc.sh -p "Print exactly OK and exit." \
#       --dangerously-skip-permissions --output-format text
#
# Prerequisite:
#   cargo build --release -p litebox_runner_linux_userland -p litebox_broker
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNNER="$REPO_ROOT/target/release/litebox_runner_linux_userland"
BROKER="$REPO_ROOT/target/release/litebox_broker"
CWD="${SANDBOX_CWD:-$(pwd)}"
HOST_HOME="${HOST_HOME:-$HOME}"
RUN_DIR="$(mktemp -d "${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/litebox-claude.XXXXXX")"
BROKER_SOCK="${BROKER_SOCK:-$RUN_DIR/broker.sock}"
SANDBOX_HOME="${SANDBOX_HOME:-$RUN_DIR/home}"
RUN_DIR_REAL="$(realpath -m "$RUN_DIR")"
SANDBOX_HOME_REAL="$(realpath -m "$SANDBOX_HOME")"
BROKER_SOCK_REAL="$(realpath -m "$BROKER_SOCK")"

case "$SANDBOX_HOME_REAL" in
    "$RUN_DIR_REAL"/*) ;;
    *)
        echo "Error: SANDBOX_HOME must stay under the helper's private run dir: $RUN_DIR_REAL" >&2
        exit 1
        ;;
esac

case "$BROKER_SOCK_REAL" in
    "$RUN_DIR_REAL"/*) ;;
    *)
        echo "Error: BROKER_SOCK must stay under the helper's private run dir: $RUN_DIR_REAL" >&2
        exit 1
        ;;
esac

if [ -e "$BROKER_SOCK_REAL" ]; then
    echo "Error: broker socket path already exists at $BROKER_SOCK_REAL" >&2
    exit 1
fi

BROKER_SOCK="$BROKER_SOCK_REAL"
SANDBOX_HOME="$SANDBOX_HOME_REAL"

CLAUDE_BIN="$(which claude 2>/dev/null || true)"
if [ -z "$CLAUDE_BIN" ]; then
    echo "Error: claude not found on PATH" >&2
    exit 1
fi

if [ ! -x "$RUNNER" ]; then
    echo "Error: runner not found at $RUNNER" >&2
    echo "Run: cargo build --release -p litebox_runner_linux_userland" >&2
    exit 1
fi

if [ ! -x "$BROKER" ]; then
    echo "Error: broker not found at $BROKER" >&2
    echo "Run: cargo build --release -p litebox_broker" >&2
    exit 1
fi

seed_sandbox_home() {
    install -d -m 700 \
        "$SANDBOX_HOME" \
        "$SANDBOX_HOME/.config" \
        "$SANDBOX_HOME/.cache" \
        "$SANDBOX_HOME/.local" \
        "$SANDBOX_HOME/.local/bin" \
        "$SANDBOX_HOME/.local/state"
    rm -rf "$SANDBOX_HOME/.claude" "$SANDBOX_HOME/.claude.json" "$SANDBOX_HOME/.claude.lock"
    rm -f "$SANDBOX_HOME/.local/bin/claude"

    if [ -d "$HOST_HOME/.claude" ]; then
        install -d -m 700 "$SANDBOX_HOME/.claude"
        cp -a "$HOST_HOME/.claude/." "$SANDBOX_HOME/.claude/"
    fi

    if [ -f "$HOST_HOME/.claude.json" ]; then
        cp -a "$HOST_HOME/.claude.json" "$SANDBOX_HOME/.claude.json"
    fi

    ln -s "$CLAUDE_BIN" "$SANDBOX_HOME/.local/bin/claude"
}

seed_sandbox_home

RUNNER_ARGS=(
    -Z
    --network-broker "$BROKER_SOCK"
    --nine-p-broker "$BROKER_SOCK"
    --cwd "$CWD"
    --env HOME="$SANDBOX_HOME"
    --env XDG_CONFIG_HOME="$SANDBOX_HOME/.config"
    --env XDG_STATE_HOME="$SANDBOX_HOME/.local/state"
    --env XDG_CACHE_HOME="$SANDBOX_HOME/.cache"
    --env SHELL=/bin/bash
    --env "PATH=$SANDBOX_HOME/.local/bin:${PATH:-/usr/local/bin:/usr/bin:/bin}"
    --env "TERM=${TERM:-xterm-256color}"
    --env GIT_CONFIG_COUNT=1
    --env GIT_CONFIG_KEY_0=safe.directory
    --env "GIT_CONFIG_VALUE_0=*"
)

append_forwarded_env() {
    local var_name="$1"
    local value

    if ! [[ "$var_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        echo "Warning: ignoring invalid env name in CLAUDE_FORWARD_ENV: $var_name" >&2
        return
    fi

    case "$var_name" in
        HOME|XDG_CONFIG_HOME|XDG_STATE_HOME|XDG_CACHE_HOME|SHELL|PATH|TERM| \
            GIT_CONFIG_COUNT|GIT_CONFIG_KEY_0|GIT_CONFIG_VALUE_0)
            return
            ;;
    esac

    if value="$(printenv "$var_name" 2>/dev/null)"; then
        RUNNER_ARGS+=(--env "$var_name=$value")
    fi
}

forward_env_list() {
    local var_name

    while IFS= read -r var_name; do
        [ -z "$var_name" ] && continue
        append_forwarded_env "$var_name"
    done < <(printf '%s' "$1" | tr ',[:space:]' '\n')
}

forward_env_list "LANG LC_ALL LC_CTYPE LC_MESSAGES TZ USER LOGNAME COLORTERM NO_COLOR FORCE_COLOR SSL_CERT_FILE SSL_CERT_DIR NIX_SSL_CERT_FILE"
forward_env_list "${CLAUDE_FORWARD_ENV:-}"

STARTED_BROKER=false

cleanup() {
    if [ "$STARTED_BROKER" = true ] && [ -n "${BROKER_PID:-}" ]; then
        kill "$BROKER_PID" 2>/dev/null || true
        wait "$BROKER_PID" 2>/dev/null || true
    fi
    rm -f "$BROKER_SOCK"
    rm -rf "$RUN_DIR"
}
trap cleanup EXIT

install -d -m 700 "$(dirname "$BROKER_SOCK")"

RUST_LOG="${RUST_LOG:-litebox_broker=warn}" "$BROKER" \
  --root-dir / \
  --rewrite-syscalls \
  --read-only \
  --writable-path "$CWD" \
  --writable-path /tmp \
  --writable-path "$SANDBOX_HOME" \
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

"$RUNNER" "${RUNNER_ARGS[@]}" -- "$CLAUDE_BIN" "$@"
