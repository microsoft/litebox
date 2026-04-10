#!/bin/bash
# Install OpenSSH sshd into the litebox rootfs (no sudo needed).
# Extracts sshd from the .deb package, stages all library dependencies,
# generates a host key, and writes a minimal sshd_config.
set -eu

ROOTFS="${1:-/home/wportnoy/vscode-rootfs}"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "=== Downloading openssh-server ==="
cd "$TMPDIR"
apt-get download openssh-server 2>/dev/null
DEB=$(ls openssh-server*.deb 2>/dev/null | head -1)
if [ -z "$DEB" ]; then
    echo "ERROR: could not download openssh-server"
    exit 1
fi
dpkg-deb -x "$DEB" "$TMPDIR/ext"

echo "=== Installing sshd ==="
mkdir -p "$ROOTFS/usr/sbin"
cp "$TMPDIR/ext/usr/sbin/sshd" "$ROOTFS/usr/sbin/sshd"
chmod +x "$ROOTFS/usr/sbin/sshd"

echo "=== Staging sshd library dependencies ==="
for lib in $(ldd "$TMPDIR/ext/usr/sbin/sshd" 2>/dev/null | grep -oP '=> \K/[^ ]+'); do
    dest="$ROOTFS$lib"
    if [ ! -f "$dest" ]; then
        mkdir -p "$(dirname "$dest")"
        cp "$lib" "$dest"
        echo "  staged: $lib"
    fi
done

# Also stage transitive dependencies
for lib in $(find "$ROOTFS/lib" "$ROOTFS/usr/lib" -name "*.so*" -type f 2>/dev/null); do
    for dep in $(ldd "$lib" 2>/dev/null | grep -oP '=> \K/[^ ]+'); do
        dest="$ROOTFS$dep"
        if [ ! -f "$dest" ]; then
            mkdir -p "$(dirname "$dest")"
            cp "$dep" "$dest"
            echo "  staged (transitive): $dep"
        fi
    done
done

echo "=== Generating host key ==="
mkdir -p "$ROOTFS/etc/ssh"
if [ ! -f "$ROOTFS/etc/ssh/ssh_host_ed25519_key" ]; then
    ssh-keygen -t ed25519 -f "$ROOTFS/etc/ssh/ssh_host_ed25519_key" -N "" -q
    echo "  Generated ed25519 host key"
else
    echo "  Host key already exists"
fi

echo "=== Writing sshd_config ==="
cat > "$ROOTFS/etc/ssh/sshd_config" << 'SSHD_CONFIG'
# Minimal sshd config for litebox sandbox
Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
UsePAM no
Subsystem sftp /usr/lib/openssh/sftp-server
# Disable DNS lookups (no resolver inside sandbox for reverse DNS)
UseDNS no
# Accept any environment variables from the client
AcceptEnv *
# Log to stderr (no syslog inside sandbox)
SyslogFacility AUTH
LogLevel INFO
# Run in foreground (no daemonize — we're the init process)
# Use -D flag when starting sshd
SSHD_CONFIG
echo "  Written /etc/ssh/sshd_config"

echo "=== Creating required directories ==="
mkdir -p "$ROOTFS/var/run/sshd"  # sshd privilege separation directory
mkdir -p "$ROOTFS/run/sshd"      # alternative location

echo "=== Verifying ==="
echo "sshd: $(file "$ROOTFS/usr/sbin/sshd" | grep -o 'ELF.*')"
echo "Host key: $(ls -la "$ROOTFS/etc/ssh/ssh_host_ed25519_key")"
echo "Config: $(wc -l < "$ROOTFS/etc/ssh/sshd_config") lines"
echo ""
echo "DONE. Start sshd inside litebox with:"
echo "  /usr/sbin/sshd -D -e"
