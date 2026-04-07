#!/bin/bash
# WSL2 shell wrapper for litebox_runner_linux_userland.
# Each command runs in a fresh LiteBox sandbox with bash.
# Fork+pipe work because bash is a PIE binary (unlike busybox).

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
echo "Type 'exit' to quit. Simple pipes work (e.g. echo x | cat)."
echo "Multi-program pipes (ls | sort) may hang (cascaded fork limitation)."
echo "Audit log: C:\\src\\litebox\\target\\litebox-audit.jsonl"
echo ""

while true; do
    printf "sandbox\$ "
    read -r line || break
    [ "$line" = "exit" ] && break
    [ -z "$line" ] && continue
    timeout 10 "$RUNNER" --unstable \
        --initial-files "$ROOTFS" \
        --program-from-tar \
        --policy "$POLICY" \
        --env "LD_LIBRARY_PATH=/lib64:/lib/x86_64-linux-gnu:/lib" \
        --env "HOME=/" \
        --env "PATH=/usr/bin:/bin" \
        -- /usr/bin/bash --norc --noprofile -c "$line" 2>>"$AUDIT_LOG"
    rc=$?
    if [ $rc -eq 124 ]; then
        echo "[timed out — multi-fork pipe commands may hang]"
    elif [ $rc -ne 0 ]; then
        echo "[exit code: $rc]"
    fi
done
