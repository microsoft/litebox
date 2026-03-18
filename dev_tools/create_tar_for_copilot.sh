#!/bin/bash
# Create a tar archive for running GitHub Copilot CLI inside the litebox sandbox.
#
# Usage: ./dev_tools/create_tar_for_copilot.sh [-o output.tar] [--ipc]
#
# Options:
#   -o FILE   Output tar path (default: /tmp/copilot_ustar.tar)
#   --ipc     Use IPC network proxy (DNS via 8.8.8.8 instead of TUN gateway)
#
# Prerequisites:
#   - Build the packager: cargo build --release -p litebox_packager
#   - Copilot CLI installed (on PATH, or at ~/.local/bin/copilot)
#   - gh CLI auth configured (gh auth login)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKAGER="$REPO_ROOT/target/release/litebox_packager"
OUTPUT="/tmp/copilot_ustar.tar"
USE_IPC=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o)       OUTPUT="$2"; shift 2 ;;
        --ipc)    USE_IPC=true; shift ;;
        *)        echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ ! -x "$PACKAGER" ]; then
    echo "Error: packager not found at $PACKAGER" >&2
    echo "Run: cargo build --release -p litebox_packager" >&2
    exit 1
fi

# --- Locate copilot binary ---
COPILOT_BIN="$(which copilot 2>/dev/null || true)"
if [ -z "$COPILOT_BIN" ] || [ ! -f "$COPILOT_BIN" ]; then
    echo "Error: copilot binary not found on PATH" >&2
    echo "Install: https://docs.github.com/en/copilot/managing-copilot/managing-github-copilot-in-your-organization/managing-the-copilot-subscription-for-your-organization/managing-your-github-copilot-enterprise-license" >&2
    exit 1
fi
echo "Copilot binary: $COPILOT_BIN"

# --- Locate gh CLI auth ---
GH_HOSTS="${GH_CONFIG_DIR:-$HOME/.config/gh}/hosts.yml"
if [ ! -f "$GH_HOSTS" ]; then
    echo "Error: gh auth config not found at $GH_HOSTS" >&2
    echo "Run: gh auth login" >&2
    exit 1
fi

# --- Locate copilot config ---
COPILOT_CONFIG_DIR="${COPILOT_DATA_DIR:-$HOME/.copilot}"

# --- Locate or extract copilot JS package ---
# The native copilot launcher extracts its JS bundle to a cache directory.
# Respect the same env vars copilot uses: XDG_CACHE_HOME, then ~/.cache.
USER_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/copilot"
STAGING_DIR=""

if [ -d "$USER_CACHE_DIR/pkg" ]; then
    # Packages already extracted in the user's cache — use them directly.
    COPILOT_CACHE_DIR="$USER_CACHE_DIR"
    echo "Using cached packages: $COPILOT_CACHE_DIR/pkg"
else
    # Run copilot --help with a temp HOME to trigger package extraction.
    STAGING_DIR="$(mktemp -d)"
    echo "Extracting copilot packages to staging dir..."
    HOME="$STAGING_DIR" "$COPILOT_BIN" --help >/dev/null 2>&1 || true
    COPILOT_CACHE_DIR="$STAGING_DIR/.cache/copilot"
    if [ ! -d "$COPILOT_CACHE_DIR/pkg" ]; then
        echo "Error: copilot package extraction failed" >&2
        echo "Expected packages at $COPILOT_CACHE_DIR/pkg" >&2
        rm -rf "$STAGING_DIR"
        exit 1
    fi
fi
COPILOT_PKG_DIR="$COPILOT_CACHE_DIR/pkg"

# --- Temp files and cleanup ---
RESOLV_TMPFILE="$(mktemp)"
if $USE_IPC; then
    echo "nameserver 8.8.8.8" > "$RESOLV_TMPFILE"
    echo "DNS: 8.8.8.8 (IPC network proxy mode)"
else
    echo "nameserver 10.0.0.1" > "$RESOLV_TMPFILE"
    echo "DNS: 10.0.0.1 (TUN gateway mode)"
fi

cleanup() {
    rm -f "$RESOLV_TMPFILE"
    if [ -n "$STAGING_DIR" ]; then
        rm -rf "$STAGING_DIR"
    fi
}
trap cleanup EXIT

declare -A SEEN_SHARED_DEPS=()
declare -A REPORTED_MISSING_DEPS=()

mark_ldd_deps_seen() {
    local elf="$1"
    while IFS= read -r dep; do
        [ -n "$dep" ] || continue
        SEEN_SHARED_DEPS["$dep"]=1
    done < <(
        ldd "$elf" 2>/dev/null | awk '
            /=> \// { print $3 }
            /^[[:space:]]*\/[^[:space:]]+/ { print $1 }
        '
    )
}

append_missing_rewrite_dep() {
    local dep="$1"
    [ -n "$dep" ] || return 0
    if [[ -n "${SEEN_SHARED_DEPS[$dep]:-}" ]]; then
        return 0
    fi
    SEEN_SHARED_DEPS["$dep"]=1
    ARGS+=(--rewrite-include "$dep:${dep#/}")
}

report_missing_dep_once() {
    local dep="$1"
    local source_file="$2"
    [ -n "$dep" ] || return 0
    if [[ -n "${REPORTED_MISSING_DEPS[$dep]:-}" ]]; then
        return 0
    fi
    REPORTED_MISSING_DEPS["$dep"]=1
    echo "WARN: missing shared library $dep (referenced by $source_file)" >&2
}

append_pkg_native_deps() {
    local file
    while IFS= read -r -d '' file; do
        local info
        info="$(file -b "$file" 2>/dev/null || true)"
        case "$info" in
            *"ELF 64-bit LSB"*x86-64*)
                ;;
            *)
                continue
                ;;
        esac

        while IFS= read -r dep; do
            [ -n "$dep" ] || continue
            case "$dep" in
                WARN:*)
                    report_missing_dep_once "${dep#WARN:}" "$file"
                    ;;
                *)
                    append_missing_rewrite_dep "$dep"
                    ;;
            esac
        done < <(
            ldd "$file" 2>/dev/null | awk '
                /=> \// { print $3 }
                /=> not found/ { print "WARN:" $1 }
                /^[[:space:]]*\/[^[:space:]]+/ { print $1 }
            '
        )
    done < <(
        find "$COPILOT_PKG_DIR" -type f \
            \( -name '*.node' -o -path '*/ripgrep/bin/linux-x64/rg' \) \
            -print0
    )
}

# --- Build include args ---

ARGS=()
BASE_ELF_INPUTS=()

# ELF binaries (auto-discovers shared lib dependencies via ldd)
BASE_ELF_INPUTS+=("$COPILOT_BIN")
BASE_ELF_INPUTS+=(/bin/bash /usr/bin/env /bin/dash)
BASE_ELF_INPUTS+=(/usr/bin/git /usr/local/bin/gh)

# Common utilities that copilot spawns via the bash tool.
# Including them in the tar avoids the broker having to rewrite them on the fly.
BASE_ELF_INPUTS+=(/usr/bin/ls /usr/bin/cat /usr/bin/ps /usr/bin/curl)

# git-remote-http is a separate ELF (not a symlink to git)
BASE_ELF_INPUTS+=(/usr/lib/git-core/git-remote-http)

for elf in "${BASE_ELF_INPUTS[@]}"; do
    ARGS+=("$elf")
    mark_ldd_deps_seen "$elf"
done

# Git subcommands that are symlinks to the main git binary.
# The packager resolves symlinks, so these become copies of the git ELF.
GIT_SYMLINK_CMDS=(
    checkout clone config fetch for-each-ref hash-object
    index-pack init ls-remote merge pack-objects reflog
    rev-parse symbolic-ref unpack-objects update-ref
)
for cmd in "${GIT_SYMLINK_CMDS[@]}"; do
    ARGS+=(--include "/usr/lib/git-core/git-$cmd:usr/lib/git-core/git-$cmd")
done
# git-remote-https is a symlink to git-remote-http
ARGS+=(--include "/usr/lib/git-core/git-remote-https:usr/lib/git-core/git-remote-https")

# NSS DNS module (loaded via dlopen, not discovered by ldd)
ARGS+=(--rewrite-include "/lib/x86_64-linux-gnu/libnss_dns.so.2:lib/x86_64-linux-gnu/libnss_dns.so.2")

# Shell symlink: /bin/sh -> dash (use --rewrite-include so it gets the
# syscall trampoline just like the /bin/dash copy from the positional args)
ARGS+=(--rewrite-include "/bin/sh:bin/sh")

# DNS and networking config
# Override resolv.conf: the host typically points at 127.0.0.53 (systemd-resolved)
# which doesn't exist inside the sandbox. In TUN mode, route through the gateway
# (10.0.0.1 where dnsmasq runs). In IPC mode, use a public DNS (8.8.8.8)
# since the broker proxies UDP transparently to the real destination.
ARGS+=(--include "$RESOLV_TMPFILE:etc/resolv.conf")
ARGS+=(--include "/etc/host.conf:etc/host.conf")
ARGS+=(--include "/etc/gai.conf:etc/gai.conf")

# SSL CA certificates
ARGS+=(--include "/etc/ssl/certs/ca-certificates.crt:etc/ssl/certs/ca-certificates.crt")

# GitHub CLI auth
ARGS+=(--include "$GH_HOSTS:tmp/.config/gh/hosts.yml")

# Copilot config (auth tokens, model preferences, trusted folders)
if [ -f "$COPILOT_CONFIG_DIR/config.json" ]; then
    ARGS+=(--include "$COPILOT_CONFIG_DIR/config.json:tmp/.copilot/config.json")
fi

# Copilot package tree (JS, WASM, native .node modules, ripgrep, etc.)
while IFS= read -r -d '' file; do
    rel="${file#$COPILOT_CACHE_DIR/}"
    ARGS+=(--include "$file:tmp/.cache/copilot/$rel")
done < <(find "$COPILOT_PKG_DIR" -type f -print0)

# Native .node modules and bundled ELF tools under the Copilot package tree are
# included above as raw files, so their transitive shared-library dependencies
# must be added explicitly for IPC-only mode where no 9P filesystem is present.
append_pkg_native_deps

# Output
ARGS+=(-o "$OUTPUT")

echo "Creating $OUTPUT ..."
"$PACKAGER" "${ARGS[@]}"
echo "Done: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
