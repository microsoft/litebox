#!/bin/bash
# Check all sshd library deps are present in rootfs
ROOTFS="/home/wportnoy/vscode-rootfs"
SSHD="$ROOTFS/usr/sbin/sshd"

echo "=== Checking all sshd dependencies ==="
for lib in $(ldd "$SSHD" 2>/dev/null | grep -oP '=> \K/[^ ]+'); do
    dest="$ROOTFS$lib"
    if [ -f "$dest" ]; then
        echo "OK: $lib"
    else
        echo "MISSING: $lib"
        # Try to install it
        cp "$lib" "$dest" 2>/dev/null && echo "  -> copied from host" || echo "  -> FAILED to copy"
    fi
done

echo ""
echo "=== Retry sshd startup ==="
