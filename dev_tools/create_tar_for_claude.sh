#!/bin/bash
# Create a tar archive for running Claude Code inside the litebox sandbox.
#
# Packages the Claude binary (a self-contained Bun ELF) with its shared
# library dependencies plus common shell utilities.  The resulting tar is
# used by run_claude_ipc.sh via --initial-files for faster cold start.
#
# Usage: ./dev_tools/create_tar_for_claude.sh [-o output.tar]
#
# Prerequisites:
#   - Build the packager: cargo build --release -p litebox_packager
#   - Claude CLI installed (on PATH)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKAGER="$REPO_ROOT/target/release/litebox_packager"
OUTPUT="${CLAUDE_TAR:-/tmp/claude_ustar.tar}"

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

# --- Locate claude binary ---
CLAUDE_BIN="$(which claude 2>/dev/null || true)"
if [ -z "$CLAUDE_BIN" ] || [ ! -e "$CLAUDE_BIN" ]; then
    echo "Error: claude not found on PATH" >&2
    exit 1
fi
# Resolve symlinks so the packager gets the real ELF
CLAUDE_BIN="$(readlink -f "$CLAUDE_BIN")"
echo "Claude binary: $CLAUDE_BIN"

# --- Build packager arguments ---
ARGS=()

# ELF binaries (auto-discovers shared lib dependencies via ldd)
ARGS+=("$CLAUDE_BIN")
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
