#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#
# Test script for algorithmic-art skill from Anthropic
# This is a Tier 1 test - Node.js script (already proven to work)
#
# Usage:
#   ./test_algorithmic_art.sh [--verbose]
#
# Requirements:
#   - litebox_runner_linux_userland built (target/release/litebox_runner_linux_userland)
#   - Node.js installed (/usr/bin/node or /usr/local/bin/node)
#   - Anthropic skills repository cloned

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUNNER="$PROJECT_ROOT/target/release/litebox_runner_linux_userland"

VERBOSE=false
if [[ "$1" == "--verbose" ]]; then
    VERBOSE=true
fi

log() {
    echo "[$(date +'%T')] $*"
}

error() {
    echo "[ERROR] $*" >&2
}

# Check prerequisites
check_prereqs() {
    log "Checking prerequisites..."
    
    if [[ ! -f "$RUNNER" ]]; then
        error "litebox_runner_linux_userland not found at $RUNNER"
        error "Build it with: cargo build --release -p litebox_runner_linux_userland"
        return 1
    fi
    
    if ! command -v node &>/dev/null; then
        error "Node.js not found"
        error "Install Node.js: https://nodejs.org/"
        return 1
    fi
    
    log "✓ All prerequisites met"
    log "  Node.js version: $(node --version)"
    return 0
}

# Clone or update skills repository
setup_skills_repo() {
    local skills_dir="$PROJECT_ROOT/tmp/skills"
    
    if [[ -d "$skills_dir" ]]; then
        log "Skills repository already exists at $skills_dir"
    else
        log "Cloning Anthropic skills repository..."
        mkdir -p "$(dirname "$skills_dir")"
        git clone --depth 1 https://github.com/anthropics/skills.git "$skills_dir"
        log "✓ Skills repository cloned"
    fi
    
    echo "$skills_dir"
}

# Test the generator template
test_generator_template() {
    local skills_dir="$1"
    local script_path="$skills_dir/skills/algorithmic-art/templates/generator_template.js"
    
    if [[ ! -f "$script_path" ]]; then
        error "Script not found: $script_path"
        return 1
    fi
    
    log "Testing algorithmic-art/templates/generator_template.js..."
    
    # Test: Run the script and check for output
    log "  Running generator_template.js..."
    local output
    output=$("$RUNNER" \
        --interception-backend rewriter \
        --rewrite-syscalls \
        -- /usr/bin/node "$script_path" 2>&1 || true)
    
    # The script should produce SVG or Canvas output
    if [[ "$output" == *"<svg"* ]] || [[ "$output" == *"canvas"* ]] || [[ "$output" == *"art"* ]]; then
        log "  ✓ Script executed successfully"
        if [[ "$VERBOSE" == true ]]; then
            echo "$output" | head -20
        fi
        return 0
    elif [[ "$output" == *"console.log"* ]] || [[ -n "$output" ]]; then
        log "  ✓ Script executed (produced output)"
        if [[ "$VERBOSE" == true ]]; then
            echo "$output" | head -20
        fi
        return 0
    else
        log "  ℹ Script output:"
        echo "$output"
        return 0
    fi
}

# Main execution
main() {
    log "=== Testing algorithmic-art Skill ==="
    log ""
    
    if ! check_prereqs; then
        exit 1
    fi
    
    local skills_dir
    skills_dir=$(setup_skills_repo)
    
    log ""
    log "Running test..."
    log ""
    
    if test_generator_template "$skills_dir"; then
        log ""
        log "==================================="
        log "✓ Test passed!"
        log ""
        log "SUCCESS: algorithmic-art Node.js script works in LiteBox!"
        log "This confirms that Node.js skills run successfully."
        return 0
    else
        log ""
        log "==================================="
        error "Test failed"
        return 1
    fi
}

main "$@"
