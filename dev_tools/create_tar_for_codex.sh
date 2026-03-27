#!/bin/bash
# Create a tar archive for running OpenAI Codex CLI inside the litebox sandbox.
#
# Packages the Node.js runtime, the Codex npm package, and common shell
# utilities with their shared library dependencies.  The resulting tar is
# used by run_codex_ipc.sh via --initial-files for faster cold start.
#
# Usage: ./dev_tools/create_tar_for_codex.sh [-o output.tar]
#
# Prerequisites:
#   - Build the packager: cargo build --release -p litebox_packager
#   - Codex CLI installed (npm install -g @openai/codex)
#   - Node.js installed
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKAGER="$REPO_ROOT/target/release/litebox_packager"
OUTPUT="${CODEX_TAR:-/tmp/codex_ustar.tar}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o)  OUTPUT="$2"; shift 2 ;;
        *)   echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ ! -x "$PACKAGER" ]; then
    echo "Error: packager not found at $PACKAGER" >&2
    echo "Run: cargo build --release -p litebox_packager" >&2
    exit 1
fi

# --- Locate codex and node binaries ---
CODEX_BIN="$(which codex 2>/dev/null || true)"
if [ -z "$CODEX_BIN" ] || [ ! -e "$CODEX_BIN" ]; then
    echo "Error: codex not found on PATH" >&2
    exit 1
fi
echo "Codex binary: $CODEX_BIN"

NODE_BIN="$(which node 2>/dev/null || true)"
if [ -z "$NODE_BIN" ] || [ ! -e "$NODE_BIN" ]; then
    echo "Error: node not found on PATH" >&2
    exit 1
fi
NODE_BIN="$(readlink -f "$NODE_BIN")"
echo "Node binary: $NODE_BIN"

# Resolve the codex package directory (codex bin is a symlink into node_modules)
CODEX_REAL="$(readlink -f "$CODEX_BIN")"
CODEX_PKG_DIR="$(cd "$(dirname "$CODEX_REAL")/.." && pwd)"
echo "Codex package: $CODEX_PKG_DIR"

# --- Build packager arguments ---
ARGS=()

# ELF binaries (auto-discovers shared lib dependencies via ldd)
ARGS+=("$NODE_BIN")
ARGS+=(/bin/bash /usr/bin/env /bin/dash)
ARGS+=(/usr/bin/git)
ARGS+=(/usr/bin/ls /usr/bin/cat /usr/bin/ps /usr/bin/curl)

# Git subcommands (packager resolves symlinks)
if [ -d /usr/lib/git-core ]; then
    ARGS+=(/usr/lib/git-core/git-remote-http)
    for cmd in checkout clone config fetch init ls-remote merge rev-parse; do
        ARGS+=(--include "/usr/lib/git-core/git-$cmd:usr/lib/git-core/git-$cmd")
    done
    ARGS+=(--include "/usr/lib/git-core/git-remote-https:usr/lib/git-core/git-remote-https")
fi

# Shell symlink: /bin/sh -> dash
ARGS+=(--rewrite-include "/bin/sh:bin/sh")

# NSS DNS module (dlopen'd, not found by ldd)
ARGS+=(--rewrite-include "/lib/x86_64-linux-gnu/libnss_dns.so.2:lib/x86_64-linux-gnu/libnss_dns.so.2")

# Codex npm package tree (JS files, bin wrapper, node_modules)
while IFS= read -r -d '' file; do
    rel="${file#$CODEX_PKG_DIR/}"
    tar_path="${CODEX_PKG_DIR#/}/$rel"
    ARGS+=(--include "$file:$tar_path")
done < <(find "$CODEX_PKG_DIR" -type f -print0)

# Codex bin wrapper (symlink target)
ARGS+=(--include "$CODEX_BIN:${CODEX_BIN#/}")

# Any native .node addons in the package (rewrite for syscall trampoline)
while IFS= read -r -d '' file; do
    rel="${file#$CODEX_PKG_DIR/}"
    tar_path="${CODEX_PKG_DIR#/}/$rel"
    ARGS+=(--rewrite-include "$file:$tar_path")
done < <(find "$CODEX_PKG_DIR" -name '*.node' -type f -print0)

# DNS config
RESOLV_TMPFILE="$(mktemp)"
echo "nameserver 8.8.8.8" > "$RESOLV_TMPFILE"
cleanup() { rm -f "$RESOLV_TMPFILE"; }
trap cleanup EXIT

ARGS+=(--include "$RESOLV_TMPFILE:etc/resolv.conf")
ARGS+=(--include "/etc/host.conf:etc/host.conf")
[ -f /etc/gai.conf ] && ARGS+=(--include "/etc/gai.conf:etc/gai.conf")

# SSL CA certificates
ARGS+=(--include "/etc/ssl/certs/ca-certificates.crt:etc/ssl/certs/ca-certificates.crt")

# Output
ARGS+=(-o "$OUTPUT")

echo "Creating $OUTPUT ..."
"$PACKAGER" "${ARGS[@]}"
echo "Done: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
