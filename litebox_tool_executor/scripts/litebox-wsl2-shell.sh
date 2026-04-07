#!/bin/bash
# WSL2 REPL wrapper for litebox_runner_linux_userland.
# Each line typed spawns a fresh sandbox invocation, similar to
# litebox_tool_executor --interactive on Windows.

RUNNER="/mnt/c/src/litebox/target/debug/litebox_runner_linux_userland"
ROOTFS="/mnt/c/src/litebox/target/busybox-minimal.tar"
POLICY="/mnt/c/src/litebox/litebox_tool_executor/policies/demo-policy.json"
AUDIT_LOG="/mnt/c/src/litebox/target/litebox-audit.jsonl"

echo "LiteBox Sandbox Shell (WSL2 — each command runs in a fresh sandbox)"
echo "Type 'exit' to quit. Pipes (|) and subshells (\$()) will hang (no fork support)."
echo "Audit log: C:\\src\\litebox\\target\\litebox-audit.jsonl"
echo ""

while true; do
    printf "/ \$ "
    read -r line || break
    [ "$line" = "exit" ] && break
    [ -z "$line" ] && continue
    "$RUNNER" --unstable \
        --initial-files "$ROOTFS" \
        --program-from-tar \
        --policy "$POLICY" \
        -- /bin/busybox sh -c "$line" 2>>"$AUDIT_LOG"
    rc=$?
    [ $rc -ne 0 ] && echo "[exit code: $rc]"
done
