#!/bin/bash
# Extract sftp-server from the openssh-sftp-server .deb package (no sudo needed)
set -eu
ROOTFS="${1:-/home/wportnoy/vscode-rootfs}"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "Downloading openssh-sftp-server..."
cd "$TMPDIR"
apt-get download openssh-sftp-server 2>/dev/null
DEB=$(ls openssh-sftp-server*.deb 2>/dev/null | head -1)
if [ -z "$DEB" ]; then
    echo "ERROR: could not download package"
    exit 1
fi

echo "Extracting sftp-server binary..."
dpkg-deb -x "$DEB" "$TMPDIR/extracted"
SFTP=$(find "$TMPDIR/extracted" -name "sftp-server" -type f | head -1)
if [ -z "$SFTP" ]; then
    echo "ERROR: sftp-server not found in package"
    exit 1
fi

echo "Installing to rootfs..."
mkdir -p "$ROOTFS/usr/lib/openssh"
cp "$SFTP" "$ROOTFS/usr/lib/openssh/sftp-server"
chmod +x "$ROOTFS/usr/lib/openssh/sftp-server"

# Stage dependencies
for lib in $(ldd "$SFTP" 2>/dev/null | grep -oP '=> \K/[^ ]+'); do
    dest="$ROOTFS$lib"
    if [ ! -f "$dest" ]; then
        mkdir -p "$(dirname "$dest")"
        cp "$lib" "$dest"
        echo "  staged: $lib"
    fi
done

echo "Done: $ROOTFS/usr/lib/openssh/sftp-server"
