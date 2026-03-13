#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Quick setup script for LiteBox workspace optimization
# This script helps configure your development environment for faster builds

set -e

echo "🚀 LiteBox Workspace Setup Optimizer"
echo "===================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Check Rust installation
if ! command_exists cargo; then
    print_status "$RED" "❌ Rust is not installed. Please install it from https://rustup.rs/"
    exit 1
fi

print_status "$GREEN" "✅ Rust is installed"

# Check for fast linker
echo ""
echo "Checking for fast linkers..."

LINKER_TO_USE=""
if command_exists mold; then
    print_status "$GREEN" "✅ mold is installed (fastest option)"
    LINKER_TO_USE="mold"
elif command_exists lld; then
    print_status "$YELLOW" "⚠️  lld is installed (fast option)"
    LINKER_TO_USE="lld"
else
    print_status "$YELLOW" "⚠️  No fast linker found"
    echo ""
    echo "To speed up linking by 3-5x, install one of these:"
    echo "  • mold (recommended): sudo apt install mold"
    echo "  • lld (alternative):  sudo apt install lld"
fi

# Check for clang
if ! command_exists clang; then
    print_status "$YELLOW" "⚠️  clang is not installed (needed for fast linker)"
    echo "Install with: sudo apt install clang"
fi

# Check for nextest
echo ""
echo "Checking for cargo-nextest..."
if command_exists cargo-nextest; then
    print_status "$GREEN" "✅ cargo-nextest is installed"
else
    print_status "$YELLOW" "⚠️  cargo-nextest is not installed"
    echo "Install for 2-3x faster tests: cargo install cargo-nextest"
fi

# Summary
echo ""
echo "=================================="
echo "✨ Setup Check Complete!"
echo "=================================="
echo ""

if [ -n "$LINKER_TO_USE" ]; then
    echo "✅ Fast linker available: $LINKER_TO_USE (3-5x faster linking)"
    echo "   To enable: Edit .cargo/config.toml and uncomment the $LINKER_TO_USE section"
fi

if command_exists cargo-nextest; then
    echo "✅ cargo-nextest available (2-3x faster tests)"
fi

echo ""
echo "Quick commands:"
echo "  • cargo check-fast    - Quick workspace check"
echo "  • cargo test-fast     - Fast parallel testing"
echo "  • cargo build         - Build default members"
echo ""
echo "For more info: See docs/workspace_setup_optimization.md"
echo ""
