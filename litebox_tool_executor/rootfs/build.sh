#!/bin/bash
# Build the litebox rootfs from the Dockerfile and extract it.
#
# The resulting directory is owned by the current user (not root),
# so the 9P broker can read/write/unlink all files.
#
# Usage:
#   ./build.sh [output-dir]
#
# After building, pre-install VS Code CLI+Server with:
#   ../scripts/update-vscode-in-rootfs.sh <output-dir>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT="${1:-/home/$USER/vscode-rootfs}"
IMAGE_NAME="litebox-rootfs"

echo "=== Building rootfs image ==="
docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"

echo "=== Extracting rootfs to $OUTPUT ==="
mkdir -p "$OUTPUT"
CONTAINER=$(docker create "$IMAGE_NAME")
# --no-same-owner: all files owned by current user, not root.
# This ensures the 9P broker can modify everything.
docker export "$CONTAINER" | tar x -C "$OUTPUT" --no-same-owner
docker rm "$CONTAINER" >/dev/null

echo "=== Rootfs ready ==="
echo "  Location: $OUTPUT"
echo "  Owner: $(id -un):$(id -gn)"
echo "  Files: $(find "$OUTPUT" -type f | wc -l)"
echo ""
echo "Next steps:"
echo "  1. Pre-install VS Code: $SCRIPT_DIR/../scripts/update-vscode-in-rootfs.sh $OUTPUT"
echo "  2. Run litebox: litebox_tool_executor --rootfs $OUTPUT --vscode-server --ssh-port 2222"
