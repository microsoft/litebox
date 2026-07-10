#!/usr/bin/env bash
# Install an isolated native dockerd for Litebox integration tests.
set -euo pipefail

DOCKER_VERSION="${DOCKER_VERSION:-29.6.1}"
DOCKER_SHA256="${DOCKER_SHA256:-b0df4a43a98d7ecb708acbdb5a34a3416e13b6e39bcbbdf296f51f0f3442b29f}"
INSTALL_DIR="/usr/local/lib/litebox-docker"
CACHE_DIR="/var/cache/litebox-docker"
DATA_ROOT="/var/lib/litebox-docker"
EXEC_ROOT="/run/litebox-docker-exec"
SOCKET="/run/litebox-docker.sock"
UNIT_NAME="litebox-dockerd.service"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"
DOCKER_GROUP="docker"
ADD_USER=1
TARGET_USER="${LITEBOX_DOCKER_USER:-${SUDO_USER:-}}"

usage() {
    cat <<USAGE
Usage: sudo bash litebox_test_harness/native-docker/install-native-dockerd.sh [options]

Options:
  --user USER       Add USER to the docker group after installation.
                    Defaults to LITEBOX_DOCKER_USER, then SUDO_USER.
  --no-usermod      Do not add any user to the docker group.
  --uninstall       Stop and remove the service and installed binaries.
  -h, --help        Show this help.

Environment:
  DOCKER_VERSION    Static Docker version to install (default: 29.6.1).
  DOCKER_SHA256     Expected SHA-256 of docker-\$DOCKER_VERSION.tgz.
USAGE
}

uninstall() {
    systemctl disable --now "$UNIT_NAME" 2>/dev/null || true
    rm -f "$UNIT_PATH"
    systemctl daemon-reload
    systemctl reset-failed "$UNIT_NAME" 2>/dev/null || true
    rm -rf "$INSTALL_DIR" "$EXEC_ROOT"
    echo "Removed $UNIT_NAME and $INSTALL_DIR."
    echo "To purge daemon state too, run: sudo rm -rf $DATA_ROOT $CACHE_DIR"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --user)
            [ "$#" -ge 2 ] || { echo "--user requires an argument" >&2; exit 2; }
            TARGET_USER="$2"
            ADD_USER=1
            shift 2
            ;;
        --no-usermod)
            ADD_USER=0
            shift
            ;;
        --uninstall)
            [ "${EUID:-$(id -u)}" -eq 0 ] || { echo "--uninstall must run as root" >&2; exit 1; }
            uninstall
            exit 0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

[ "${EUID:-$(id -u)}" -eq 0 ] || { echo "run with sudo/root" >&2; exit 1; }

case "$(uname -m)" in
    x86_64|amd64) DOCKER_ARCH="x86_64" ;;
    *) echo "unsupported architecture: $(uname -m) (expected x86_64)" >&2; exit 1 ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_UNIT="$SCRIPT_DIR/$UNIT_NAME"
[ -f "$SOURCE_UNIT" ] || { echo "missing unit file: $SOURCE_UNIT" >&2; exit 1; }

command -v curl >/dev/null || { echo "missing required command: curl" >&2; exit 1; }
command -v getent >/dev/null || { echo "missing required command: getent" >&2; exit 1; }
command -v install >/dev/null || { echo "missing required command: install" >&2; exit 1; }
command -v mktemp >/dev/null || { echo "missing required command: mktemp" >&2; exit 1; }
command -v tar >/dev/null || { echo "missing required command: tar" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "missing required command: sha256sum" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "missing required command: systemctl" >&2; exit 1; }

if ! getent group "$DOCKER_GROUP" >/dev/null; then
    groupadd --system "$DOCKER_GROUP"
fi

install -d -m0755 "$CACHE_DIR"
WORK_DIR="$(mktemp -d "$CACHE_DIR/download.XXXXXXXX")"
cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

TGZ="$WORK_DIR/docker-${DOCKER_VERSION}.tgz"
URL="https://download.docker.com/linux/static/stable/${DOCKER_ARCH}/docker-${DOCKER_VERSION}.tgz"

echo "=== downloading Docker ${DOCKER_VERSION} static binaries ==="
curl --fail --location --proto '=https' --tlsv1.2 --output "$TGZ" "$URL"
if ! printf '%s  %s\n' "$DOCKER_SHA256" "$TGZ" | sha256sum --check --status; then
    echo "checksum verification failed for $URL" >&2
    exit 1
fi

echo "=== extracting and installing daemon-side binaries to $INSTALL_DIR ==="
tar -xzf "$TGZ" -C "$WORK_DIR"
for bin in dockerd containerd containerd-shim-runc-v2 runc ctr docker-init docker-proxy docker; do
    [ -x "$WORK_DIR/docker/$bin" ] || { echo "archive missing executable: $bin" >&2; exit 1; }
done
install -d -m0755 "$INSTALL_DIR"
install -m0755 \
    "$WORK_DIR/docker/dockerd" \
    "$WORK_DIR/docker/containerd" \
    "$WORK_DIR/docker/containerd-shim-runc-v2" \
    "$WORK_DIR/docker/runc" \
    "$WORK_DIR/docker/ctr" \
    "$WORK_DIR/docker/docker-init" \
    "$WORK_DIR/docker/docker-proxy" \
    "$WORK_DIR/docker/docker" \
    "$INSTALL_DIR"/
install -d -m0710 "$DATA_ROOT"

if [ "$ADD_USER" -eq 1 ]; then
    if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != root ]; then
        id "$TARGET_USER" >/dev/null
        usermod -aG "$DOCKER_GROUP" "$TARGET_USER"
        echo "Added $TARGET_USER to group $DOCKER_GROUP (log out/in before relying on group membership)."
    else
        echo "No non-root user detected; pass --user USER or set LITEBOX_DOCKER_USER if needed."
    fi
fi

echo "=== installing systemd unit $UNIT_PATH ==="
install -m0644 "$SOURCE_UNIT" "$UNIT_PATH"
systemctl daemon-reload
systemctl enable "$UNIT_NAME"
systemctl restart "$UNIT_NAME"

echo -n "waiting for $SOCKET"
for _ in $(seq 1 60); do
    if [ -S "$SOCKET" ] && "$INSTALL_DIR/docker" -H "unix://$SOCKET" version >/dev/null 2>&1; then
        echo " up."
        echo "=== health ==="
        "$INSTALL_DIR/docker" -H "unix://$SOCKET" info --format \
            'driver={{.Driver}} cgroup={{.CgroupVersion}} runtime={{.DefaultRuntime}} root={{.DockerRootDir}}'
        ls -l "$SOCKET"
        echo "Use with: export DOCKER_HOST=unix://$SOCKET"
        exit 0
    fi
    if ! systemctl is-active --quiet "$UNIT_NAME"; then
        echo " service died:" >&2
        journalctl -u "$UNIT_NAME" -n 40 --no-pager >&2
        exit 1
    fi
    echo -n "."
    sleep 0.5
done

echo " timed out waiting for Docker daemon" >&2
journalctl -u "$UNIT_NAME" -n 40 --no-pager >&2
exit 1
