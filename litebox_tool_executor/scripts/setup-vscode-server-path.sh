#!/bin/bash
# Set up rootfs so VS Code Remote-SSH's bootstrap script finds the server.
# VS Code looks for the server at ~/.vscode-server/bin/<commit>/
set -eu

ROOTFS="${1:-/home/wportnoy/vscode-rootfs}"
SERVER_DIR="$ROOTFS/opt/vscode-server"

if [ ! -f "$SERVER_DIR/product.json" ]; then
    echo "ERROR: VS Code Server not found at $SERVER_DIR"
    exit 1
fi

# Extract commit ID from product.json
COMMIT=$(python3 -c "import json; print(json.load(open('$SERVER_DIR/product.json'))['commit'])")
echo "VS Code Server commit: $COMMIT"

# Create the path VS Code expects: ~/.vscode-server/bin/<commit>/
TARGET="$ROOTFS/root/.vscode-server/bin/$COMMIT"
if [ -L "$TARGET" ] || [ -d "$TARGET" ]; then
    echo "Already linked: $TARGET"
else
    mkdir -p "$(dirname "$TARGET")"
    ln -s /opt/vscode-server "$TARGET"
    echo "Created symlink: $TARGET -> /opt/vscode-server"
fi

# Also create a 'server.sh' wrapper that VS Code's script may look for
if [ ! -f "$TARGET/server.sh" ] && [ -L "$TARGET" ]; then
    # The symlink resolves to /opt/vscode-server which has bin/code-server
    echo "server.sh already available via symlink"
fi

# Verify
ls -la "$TARGET"
echo "Done. VS Code will find the server at ~/.vscode-server/bin/$COMMIT/"
