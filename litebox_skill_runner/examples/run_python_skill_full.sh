#!/bin/bash
# Complete example for running Python skills in LiteBox
# This demonstrates the full workflow including syscall rewriting

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== LiteBox Skill Runner - Full Python Example ===${NC}"
echo

# Check prerequisites
if [ ! -f "$REPO_ROOT/target/release/litebox_runner_linux_userland" ]; then
    echo -e "${YELLOW}Building litebox_runner_linux_userland...${NC}"
    cd "$REPO_ROOT"
    cargo build --release -p litebox_runner_linux_userland
fi

if [ ! -f "$REPO_ROOT/target/release/litebox_syscall_rewriter" ]; then
    echo -e "${YELLOW}Building litebox_syscall_rewriter...${NC}"
    cd "$REPO_ROOT"
    cargo build --release -p litebox_syscall_rewriter
fi

SKILLS_DIR="/tmp/skills"
if [ ! -d "$SKILLS_DIR" ]; then
    echo -e "${YELLOW}Cloning skills repository...${NC}"
    git clone --depth 1 https://github.com/anthropics/skills.git "$SKILLS_DIR"
fi

# Create a simple test skill with a simple script
TEST_SKILL_DIR="/tmp/test-litebox-skill"
rm -rf "$TEST_SKILL_DIR"
mkdir -p "$TEST_SKILL_DIR/scripts"

cat > "$TEST_SKILL_DIR/SKILL.md" << 'EOF'
---
name: litebox-test-skill
description: Simple test skill for demonstrating LiteBox execution
---

# LiteBox Test Skill

A minimal skill for testing Python execution in LiteBox.
EOF

cat > "$TEST_SKILL_DIR/scripts/hello.py" << 'EOF'
#!/usr/bin/env python3
"""Simple test script for LiteBox."""

import sys
import os

def main():
    print("=" * 60)
    print("Hello from LiteBox!")
    print("=" * 60)
    print(f"Python version: {sys.version}")
    print(f"Arguments: {sys.argv[1:]}")
    print(f"Working directory: {os.getcwd()}")
    print(f"PYTHONHOME: {os.environ.get('PYTHONHOME', 'not set')}")
    print("=" * 60)
    return 0

if __name__ == "__main__":
    sys.exit(main())
EOF

chmod +x "$TEST_SKILL_DIR/scripts/hello.py"

echo -e "${GREEN}=== Step 1: Prepare skill with Python libraries ===${NC}"
PREPARED_TAR="/tmp/test-skill-prepared.tar"
python3 "$SCRIPT_DIR/prepare_python_skill.py" "$TEST_SKILL_DIR" -o "$PREPARED_TAR"

echo
echo -e "${GREEN}=== Step 2: Attempt to run Python script in LiteBox ===${NC}"
echo -e "${YELLOW}Note: This requires syscall rewriting for Python binary and .so files${NC}"
echo

# Get Python info
PYTHON_HOME=$(python3 -c "import sys; print(sys.prefix)")
PYTHON_PATH=$(python3 -c "import sys; print(':'.join([p for p in sys.path if p and p.startswith('/usr')]))")

echo "Running command:"
echo "$REPO_ROOT/target/release/litebox_runner_linux_userland \\"
echo "    --unstable \\"
echo "    --initial-files $PREPARED_TAR \\"
echo "    --interception-backend rewriter \\"
echo "    --rewrite-syscalls \\"
echo "    --env PYTHONHOME=$PYTHON_HOME \\"
echo "    --env 'PYTHONPATH=$PYTHON_PATH' \\"
echo "    --env PYTHONDONTWRITEBYTECODE=1 \\"
echo "    /usr/bin/python3 /skill/scripts/hello.py test arg1 arg2"
echo

# Note: This will likely fail due to missing .so file rewriting in the tar
# The test in litebox_runner_linux_userland/tests/run.rs shows the proper way
# to do this, which involves rewriting each .so file individually

echo -e "${YELLOW}=== Attempting execution ===${NC}"
echo "(This may fail - see README.md for full Python support requirements)"
echo

"$REPO_ROOT/target/release/litebox_runner_linux_userland" \
    --unstable \
    --initial-files "$PREPARED_TAR" \
    --interception-backend rewriter \
    --rewrite-syscalls \
    --env "PYTHONHOME=$PYTHON_HOME" \
    --env "PYTHONPATH=$PYTHON_PATH" \
    --env "PYTHONDONTWRITEBYTECODE=1" \
    /usr/bin/python3 /skill/scripts/hello.py test arg1 arg2 || {
        echo
        echo -e "${RED}Execution failed (expected)${NC}"
        echo "This is because Python shared libraries (.so files) in the tar need to be rewritten."
        echo "See litebox_runner_linux_userland/tests/run.rs:test_runner_with_python for the"
        echo "correct implementation that rewrites all .so files before adding them to the tar."
        exit 0
    }

echo
echo -e "${GREEN}Success!${NC}"
