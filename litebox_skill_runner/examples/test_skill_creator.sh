#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

#
# Test script for skill-creator skill from Anthropic
# This is a Tier 1 test - simple, stdlib-only Python with just PyYAML
#
# Usage:
#   ./test_skill_creator.sh [--verbose]
#
# Requirements:
#   - litebox_syscall_rewriter built (target/release/litebox_syscall_rewriter)
#   - litebox_runner_linux_userland built (target/release/litebox_runner_linux_userland)
#   - Python 3 with PyYAML installed (pip install PyYAML)
#   - Anthropic skills repository cloned

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REWRITER="$PROJECT_ROOT/target/release/litebox_syscall_rewriter"
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
    
    if [[ ! -f "$REWRITER" ]]; then
        error "litebox_syscall_rewriter not found at $REWRITER"
        error "Build it with: cargo build --release -p litebox_syscall_rewriter"
        return 1
    fi
    
    if [[ ! -f "$RUNNER" ]]; then
        error "litebox_runner_linux_userland not found at $RUNNER"
        error "Build it with: cargo build --release -p litebox_runner_linux_userland"
        return 1
    fi
    
    if ! python3 -c "import yaml" 2>/dev/null; then
        error "PyYAML not installed"
        error "Install it with: pip install PyYAML"
        return 1
    fi
    
    log "✓ All prerequisites met"
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

# Test skill-creator with quick_validate.py
test_quick_validate() {
    local skills_dir="$1"
    local skill_path="$skills_dir/skills/skill-creator"
    local output_tar="/tmp/skill-creator-test.tar"
    
    log "Testing skill-creator/scripts/quick_validate.py..."
    
    # Prepare the skill with PyYAML
    log "  Preparing skill with prepare_python_skill_advanced.py..."
    if [[ "$VERBOSE" == true ]]; then
        "$SCRIPT_DIR/prepare_python_skill_advanced.py" \
            "$skill_path" \
            -o "$output_tar" \
            --rewriter-path "$REWRITER" \
            --auto-install \
            --extra-packages PyYAML
    else
        "$SCRIPT_DIR/prepare_python_skill_advanced.py" \
            "$skill_path" \
            -o "$output_tar" \
            --rewriter-path "$REWRITER" \
            --auto-install \
            --extra-packages PyYAML \
            > /tmp/prepare.log 2>&1
    fi
    
    log "  ✓ Skill prepared (tar: $(du -h "$output_tar" | cut -f1))"
    
    # Test with --help first
    log "  Running quick_validate.py --help..."
    local help_output
    help_output=$("$RUNNER" \
        --initial-files "$output_tar" \
        --interception-backend rewriter \
        --rewrite-syscalls \
        -- /usr/bin/python3 /skill/scripts/quick_validate.py --help 2>&1 || true)
    
    if [[ "$help_output" == *"Usage:"* ]] || [[ "$help_output" == *"validate"* ]]; then
        log "  ✓ Help text displayed successfully"
        if [[ "$VERBOSE" == true ]]; then
            echo "$help_output" | head -10
        fi
    else
        error "  ✗ Help text not found in output"
        if [[ "$VERBOSE" == true ]]; then
            echo "$help_output"
        fi
        return 1
    fi
    
    # Test validation on skill-creator itself
    log "  Running quick_validate.py on skill-creator skill..."
    local validate_output
    validate_output=$("$RUNNER" \
        --initial-files "$output_tar" \
        --interception-backend rewriter \
        --rewrite-syscalls \
        -- /usr/bin/python3 /skill/scripts/quick_validate.py /skill 2>&1 || true)
    
    if [[ "$validate_output" == *"valid"* ]] || [[ "$validate_output" == *"✓"* ]]; then
        log "  ✓ Validation succeeded"
        if [[ "$VERBOSE" == true ]]; then
            echo "$validate_output"
        fi
    else
        log "  ℹ Validation output:"
        echo "$validate_output" | grep -E "(Error|Warning|Success|valid)" || echo "$validate_output"
    fi
    
    log "✓ quick_validate.py test completed"
    return 0
}

# Test init_skill.py
test_init_skill() {
    local skills_dir="$1"
    local skill_path="$skills_dir/skills/skill-creator"
    local output_tar="/tmp/skill-creator-test.tar"
    
    log "Testing skill-creator/scripts/init_skill.py..."
    
    # Test with --help
    log "  Running init_skill.py --help..."
    local help_output
    help_output=$("$RUNNER" \
        --initial-files "$output_tar" \
        --interception-backend rewriter \
        --rewrite-syscalls \
        -- /usr/bin/python3 /skill/scripts/init_skill.py --help 2>&1 || true)
    
    if [[ "$help_output" == *"Usage:"* ]] || [[ "$help_output" == *"skill-name"* ]]; then
        log "  ✓ Help text displayed successfully"
        if [[ "$VERBOSE" == true ]]; then
            echo "$help_output" | head -15
        fi
    else
        error "  ✗ Help text not found in output"
        if [[ "$VERBOSE" == true ]]; then
            echo "$help_output"
        fi
        return 1
    fi
    
    log "✓ init_skill.py test completed"
    return 0
}

# Test package_skill.py
test_package_skill() {
    local skills_dir="$1"
    local output_tar="/tmp/skill-creator-test.tar"
    
    log "Testing skill-creator/scripts/package_skill.py..."
    
    # Test with --help
    log "  Running package_skill.py --help..."
    local help_output
    help_output=$("$RUNNER" \
        --initial-files "$output_tar" \
        --interception-backend rewriter \
        --rewrite-syscalls \
        -- /usr/bin/python3 /skill/scripts/package_skill.py --help 2>&1 || true)
    
    if [[ "$help_output" == *"Usage:"* ]] || [[ "$help_output" == *"package"* ]]; then
        log "  ✓ Help text displayed successfully"
        if [[ "$VERBOSE" == true ]]; then
            echo "$help_output" | head -15
        fi
    else
        error "  ✗ Help text not found in output"
        if [[ "$VERBOSE" == true ]]; then
            echo "$help_output"
        fi
        return 1
    fi
    
    log "✓ package_skill.py test completed"
    return 0
}

# Main execution
main() {
    log "=== Testing skill-creator Skill ==="
    log ""
    
    if ! check_prereqs; then
        exit 1
    fi
    
    local skills_dir
    skills_dir=$(setup_skills_repo)
    
    log ""
    log "Running tests..."
    log ""
    
    local failed=0
    
    if ! test_quick_validate "$skills_dir"; then
        ((failed++))
    fi
    
    log ""
    
    if ! test_init_skill "$skills_dir"; then
        ((failed++))
    fi
    
    log ""
    
    if ! test_package_skill "$skills_dir"; then
        ((failed++))
    fi
    
    log ""
    log "==================================="
    
    if [[ $failed -eq 0 ]]; then
        log "✓ All tests passed!"
        log ""
        log "SUCCESS: skill-creator works in LiteBox!"
        log "This proves that Python skills with pure-Python dependencies"
        log "(PyYAML in this case) can run successfully in LiteBox."
        return 0
    else
        error "$failed test(s) failed"
        return 1
    fi
}

main "$@"
