#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/bin/bash
# Example script showing how to run skill-creator with litebox
# This demonstrates the concept but has known limitations (see README.md)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== LiteBox Skill Runner Example ===${NC}"
echo

# Check if skills repo exists
SKILLS_DIR="/tmp/skills"
if [ ! -d "$SKILLS_DIR" ]; then
    echo -e "${YELLOW}Cloning skills repository...${NC}"
    git clone --depth 1 https://github.com/anthropics/skills.git "$SKILLS_DIR"
fi

# Build litebox_runner if needed
RUNNER_PATH="$REPO_ROOT/target/release/litebox_runner_linux_userland"
if [ ! -f "$RUNNER_PATH" ]; then
    echo -e "${YELLOW}Building litebox_runner_linux_userland...${NC}"
    cd "$REPO_ROOT"
    cargo build --release -p litebox_runner_linux_userland
fi

# Build skill_runner if needed
SKILL_RUNNER_PATH="$REPO_ROOT/target/release/litebox_skill_runner"
if [ ! -f "$SKILL_RUNNER_PATH" ]; then
    echo -e "${YELLOW}Building litebox_skill_runner...${NC}"
    cd "$REPO_ROOT"
    cargo build --release -p litebox_skill_runner
fi

echo -e "${GREEN}=== Running skill-creator example ===${NC}"
echo
echo "This example demonstrates the skill runner architecture."
echo "Note: Python execution requires additional setup (see README.md)"
echo

# Show what the command would be
echo -e "${YELLOW}Command that would be executed:${NC}"
echo "$SKILL_RUNNER_PATH \\"
echo "    $SKILLS_DIR/skills/skill-creator \\"
echo "    --script scripts/init_skill.py \\"
echo "    --runner-path $RUNNER_PATH \\"
echo "    test-skill --path /tmp/test-output"
echo

echo -e "${YELLOW}=== Current Limitations ===${NC}"
echo "1. LiteBox does not yet support shell execution"
echo "2. Python requires extensive library packaging (PYTHONHOME, PYTHONPATH, .so rewriting)"
echo "3. See README.md for implementation details and workarounds"
echo

echo -e "${GREEN}=== Testing Skill Structure ===${NC}"
echo "Verifying skill-creator structure..."
SKILL_PATH="$SKILLS_DIR/skills/skill-creator"
if [ -f "$SKILL_PATH/SKILL.md" ]; then
    echo -e "${GREEN}✓${NC} SKILL.md found"
    echo "  Extracting metadata..."
    head -10 "$SKILL_PATH/SKILL.md"
else
    echo -e "${RED}✗${NC} SKILL.md not found"
    exit 1
fi

if [ -d "$SKILL_PATH/scripts" ]; then
    echo -e "${GREEN}✓${NC} scripts/ directory found"
    echo "  Scripts available:"
    ls -1 "$SKILL_PATH/scripts/"
else
    echo -e "${RED}✗${NC} scripts/ directory not found"
fi

echo
echo -e "${GREEN}=== Next Steps ===${NC}"
echo "To enable full Python execution:"
echo "1. Package Python libraries (see litebox_runner_linux_userland/tests/run.rs:test_runner_with_python)"
echo "2. Set PYTHONHOME and PYTHONPATH environment variables"
echo "3. Rewrite syscalls in all Python .so files"
echo
echo "For now, the skill runner demonstrates the architecture and file handling."
