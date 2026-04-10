#!/bin/bash
# Verify open questions for the sshd-in-sandbox plan
set -u

echo "=== Q1: Inbound TCP forwarding ==="
echo "Checking if broker supports inbound connections..."
grep -rn "inbound\|port_forward\|listen.*guest\|accept.*inbound" \
    /mnt/c/src/litebox-vscode-server/litebox_broker/src/ 2>/dev/null | head -5
echo ""
echo "Checking smoltcp TCP listen support..."
grep -rn "tcp.*listen\|TcpSocket.*listen\|listen.*tcp" \
    /mnt/c/src/litebox-vscode-server/litebox_broker/src/net_proxy/ 2>/dev/null | head -5
echo ""

echo "=== Q2: sshd ELF type and dependencies ==="
TMPDIR=$(mktemp -d)
cd "$TMPDIR"
apt-get download openssh-server 2>/dev/null
DEB=$(ls openssh-server*.deb 2>/dev/null | head -1)
if [ -n "$DEB" ]; then
    dpkg-deb -x "$DEB" "$TMPDIR/ext"
    echo "sshd binary:"
    file "$TMPDIR/ext/usr/sbin/sshd"
    echo ""
    echo "ELF type:"
    readelf -h "$TMPDIR/ext/usr/sbin/sshd" | grep Type
    echo ""
    echo "Dependencies:"
    ldd "$TMPDIR/ext/usr/sbin/sshd" 2>/dev/null | head -15
fi
rm -rf "$TMPDIR"
echo ""

echo "=== Q3: Fork from sshd ==="
echo "sshd forks per connection (standard behavior)."
echo "Checking litebox fork support for PIE vs ET_EXEC..."
readelf -h "$TMPDIR/ext/usr/sbin/sshd" 2>/dev/null | grep Type || echo "(already cleaned up)"
echo "If sshd is DYN (PIE), fork should work via delayed fork."
echo "If sshd is EXEC (non-PIE), fork has limitations."
echo ""

echo "=== Q4: PTY support ==="
grep -rn "openpty\|grantpt\|posix_openpt\|ptmx\|TIOCGPTN" \
    /mnt/c/src/litebox-vscode-server/litebox_shim_linux/src/ 2>/dev/null | head -5
echo ""

echo "=== Q5: Can sandbox accept inbound TCP? ==="
echo "Checking if shim supports bind+listen+accept..."
grep -rn "sys_bind\|sys_listen\|sys_accept" \
    /mnt/c/src/litebox-vscode-server/litebox_shim_linux/src/syscalls/net.rs 2>/dev/null | head -5
