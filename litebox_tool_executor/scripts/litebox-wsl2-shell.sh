#!/bin/bash
# WSL2 shell wrapper for litebox_runner_linux_userland.
# Runs a persistent bash shell inside the LiteBox sandbox with
# fork+pipe support. Uses bash (PIE binary) instead of busybox
# (static ET_EXEC) because the delayed fork mechanism requires PIE.

RUNNER="/mnt/c/src/litebox/target/debug/litebox_runner_linux_userland"
ROOTFS="/mnt/c/src/litebox/target/bash-sandbox.tar"
POLICY="/mnt/c/src/litebox/litebox_tool_executor/policies/demo-policy.json"
AUDIT_LOG="/mnt/c/src/litebox/target/litebox-audit.jsonl"

if [ ! -f "$ROOTFS" ]; then
    echo "ERROR: bash rootfs not found at $ROOTFS"
    echo "Build it first:"
    echo "  bash litebox_tool_executor/scripts/prepare-bash-rootfs.sh"
    exit 1
fi

echo "LiteBox Sandbox Shell (WSL2 — bash with fork+pipe support)"
echo "Pipes (|), subshells (\$()), cd, and env vars all work."
echo "Audit log: C:\\src\\litebox\\target\\litebox-audit.jsonl"
echo ""

exec "$RUNNER" --unstable \
    --initial-files "$ROOTFS" \
    --program-from-tar \
    --policy "$POLICY" \
    --env "LD_LIBRARY_PATH=/lib64:/lib/x86_64-linux-gnu:/lib" \
    --env "HOME=/" \
    --env "PATH=/usr/bin:/bin" \
    --env "TERM=xterm" \
    -- /usr/bin/bash --norc --noprofile 2>>"$AUDIT_LOG"
