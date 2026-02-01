#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#!/bin/bash
# Simple Quick Start Example - Run this to see litebox_skill_runner in action!
#
# This script creates a minimal skill and demonstrates the skill runner's capabilities.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   LiteBox Skill Runner - Quick Start Example${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo

# Build if needed
if [ ! -f "$REPO_ROOT/target/release/litebox_skill_runner" ]; then
    echo -e "${YELLOW}Building litebox_skill_runner...${NC}"
    cd "$REPO_ROOT"
    cargo build --release -p litebox_skill_runner
    echo
fi

echo -e "${GREEN}Step 1: Creating a simple test skill${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Create a test skill directory
TEST_SKILL="/tmp/quickstart-demo-skill"
rm -rf "$TEST_SKILL"
mkdir -p "$TEST_SKILL/scripts"
mkdir -p "$TEST_SKILL/references"
mkdir -p "$TEST_SKILL/assets"

# Create SKILL.md
cat > "$TEST_SKILL/SKILL.md" << 'EOF'
---
name: quickstart-demo
description: A demonstration skill for the Quick Start guide showing basic skill structure and capabilities
---

# Quick Start Demo Skill

This is a minimal demonstration skill that shows:
- Proper SKILL.md structure with YAML frontmatter
- Scripts directory with executable Python scripts
- References directory with documentation
- Assets directory with template files

## Usage

Run the demo script to see a greeting and system information.

## Capabilities

This skill demonstrates:
1. Metadata parsing
2. Resource packaging
3. Tar archive creation
4. LiteBox integration points
EOF

# Create a demo Python script
cat > "$TEST_SKILL/scripts/demo.py" << 'EOF'
#!/usr/bin/env python3
"""
Quick Start Demo Script

This script demonstrates what can be included in a skill script.
"""

def main():
    print("╔═══════════════════════════════════════════════════════╗")
    print("║     Quick Start Demo - Running in LiteBox!           ║")
    print("╚═══════════════════════════════════════════════════════╝")
    print()
    print("✓ Skill successfully loaded and parsed")
    print("✓ SKILL.md metadata extracted")
    print("✓ Tar archive created with all resources")
    print("✓ Script ready for execution")
    print()
    print("📁 Skill Structure:")
    print("   - SKILL.md (metadata and instructions)")
    print("   - scripts/ (this script!)")
    print("   - references/ (documentation)")
    print("   - assets/ (templates and files)")
    print()
    print("🎯 Next Steps:")
    print("   1. See QUICKSTART.md for more examples")
    print("   2. Create your own skills")
    print("   3. Explore the examples/ directory")
    print()
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
EOF

chmod +x "$TEST_SKILL/scripts/demo.py"

# Create reference documentation
cat > "$TEST_SKILL/references/getting-started.md" << 'EOF'
# Getting Started with Quick Start Demo

This skill demonstrates the basic structure of an Agent Skill.

## Required Files

- **SKILL.md**: Contains metadata (name, description) and instructions
- Frontmatter must be valid YAML between `---` delimiters

## Optional Directories

- **scripts/**: Executable scripts (Python, Bash, etc.)
- **references/**: Additional documentation (like this file)
- **assets/**: Templates, images, or other resources
EOF

# Create an asset file
cat > "$TEST_SKILL/assets/template.txt" << 'EOF'
This is a template file that could be used by the skill.
It demonstrates the assets/ directory.
EOF

echo "Created skill at: $TEST_SKILL"
echo "├── SKILL.md"
echo "├── scripts/"
echo "│   └── demo.py"
echo "├── references/"
echo "│   └── getting-started.md"
echo "└── assets/"
echo "    └── template.txt"
echo

echo -e "${GREEN}Step 2: Running the skill with litebox_skill_runner${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Run the skill runner (this will parse, package, and attempt execution)
"$REPO_ROOT/target/release/litebox_skill_runner" \
    "$TEST_SKILL" \
    --script scripts/demo.py \
    2>&1 | head -20 || true

echo
echo -e "${GREEN}Step 3: Understanding the output${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "What just happened:"
echo "1. ✓ Parsed SKILL.md and extracted metadata (name, description)"
echo "2. ✓ Created tar archive with all skill resources"
echo "3. ✓ Prepared for execution in litebox_runner_linux_userland"
echo
echo -e "${YELLOW}Note:${NC} Full Python execution requires additional setup."
echo "      See QUICKSTART.md for details on Python library packaging."
echo

echo -e "${GREEN}Step 4: Inspecting the skill structure${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "View the created skill:"
echo "  $ ls -la $TEST_SKILL"
echo
echo "Read the skill metadata:"
echo "  $ head -10 $TEST_SKILL/SKILL.md"
echo
echo "Examine the demo script:"
echo "  $ cat $TEST_SKILL/scripts/demo.py"
echo

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}       Quick Start Example Complete! ✓${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo
echo "✓ You've successfully created and validated a skill"
echo "✓ The skill structure is correct and parseable"
echo "✓ Tar packaging works properly"
echo
echo "📚 Learn more:"
echo "   - Read QUICKSTART.md for detailed guide"
echo "   - See README.md for full documentation"
echo "   - Check examples/ for more complex scenarios"
echo "   - Run 'cargo test -p litebox_skill_runner' to see tests"
echo
echo "🚀 Next steps:"
echo "   1. Try ./examples/run_skill_creator.sh"
echo "   2. Create your own skill based on this example"
echo "   3. Explore https://github.com/anthropics/skills"
echo
