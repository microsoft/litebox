# Agent Skills Support in LiteBox - Implementation Summary

## Overview

This implementation adds support for running [Agent Skills](https://agentskills.io) within LiteBox sandboxed environments. Agent Skills are modular packages that extend AI agent capabilities by providing specialized knowledge, workflows, and tools.

## What Was Implemented

### 1. New Package: `litebox_skill_runner`

A Rust command-line tool that:
- ✅ Parses `.skill` files (zip archives) and skill directories
- ✅ Extracts SKILL.md metadata (YAML frontmatter: name, description)
- ✅ Creates tar archives containing all skill resources
- ✅ Integrates with `litebox_runner_linux_userland` for execution
- ✅ Supports Python and shell script detection (though shell execution has limitations)

### 2. Architecture

```
┌─────────────────────┐
│  Agent Skill        │
│  (.skill file or    │
│   directory)        │
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│ litebox_skill_runner│
│ - Parse SKILL.md    │
│ - Extract metadata  │
│ - Create tar        │
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│ litebox_runner_     │
│ linux_userland      │
│ - Load tar          │
│ - Execute in sandbox│
└─────────────────────┘
```

### 3. Example Scripts

Created three demonstration scripts:

1. **`run_skill_creator.sh`**: Demonstrates skill structure validation
   - Clones the Anthropic skills repository
   - Validates the skill-creator skill structure
   - Shows SKILL.md parsing
   - Documents current limitations

2. **`prepare_python_skill.py`**: Helper for Python skill preparation
   - Packages Python standard libraries
   - Creates tar archives with skill + Python libs
   - Generates example commands for execution
   - Shows required environment variables

3. **`run_python_skill_full.sh`**: Full Python execution demonstration
   - Creates a test skill
   - Packages with Python libraries
   - Attempts execution in LiteBox
   - Documents expected behavior and limitations

### 4. Documentation

Comprehensive README covering:
- Implementation status (proof-of-concept)
- Known limitations
- Usage examples
- Architecture details
- Future work needed

## Skill Structure

Skills follow the Agent Skills specification:

```
skill-name/
├── SKILL.md          # Required: metadata + instructions
├── scripts/          # Optional: executable scripts
├── references/       # Optional: reference documentation
└── assets/           # Optional: templates, images, etc.
```

## Current Capabilities

✅ **Working:**
- Skill file parsing (.skill zip files)
- SKILL.md metadata extraction
- Tar archive creation
- Integration with litebox_runner_linux_userland
- Skill structure validation

⚠️ **Partially Working:**
- Python script execution (requires additional setup)
- See examples for workarounds

❌ **Not Working:**
- Shell script execution (LiteBox limitation)
- Direct Python execution without manual setup

## Known Limitations

### 1. No Shell Support
LiteBox does not support running `/bin/sh` or `/bin/bash`:
- Shell scripts cannot be executed
- Skills that depend on shell features won't work
- This is an architectural limitation of LiteBox

### 2. Python Execution Complexity

#### Version and Module Handling

**Python Version Management:**
- Uses system Python interpreter (default: `/usr/bin/python3`)
- Version-specific library paths (e.g., `/usr/lib/python3.12/`)
- No virtual environment support
- Only one Python version per execution
- Detection: `python3 --version` or `sys.version_info`

**Module Resolution Strategy:**
1. Python searches `PYTHONPATH` environment variable
2. Falls back to `PYTHONHOME` locations
3. All paths must exist in tar filesystem
4. Import fails if module not found or incompatible

**Standard Library Modules:**
- Location: `/usr/lib/python3.X/`
- Must be completely packaged into tar
- Version-specific (3.10 ≠ 3.11 ≠ 3.12)
- Typical size: 50-100 MB

**Third-Party Module Handling:**
```
System packages (apt):     /usr/lib/python3/dist-packages/
User packages (pip):       /usr/local/lib/python3.X/dist-packages/
Development packages:      /usr/local/lib/python3.X/site-packages/
```

**Binary Extension Modules (.so files):**
- Critical modules: `_ssl`, `_json`, `_socket`, `math`, `_datetime`
- Scientific: `numpy`, `pandas`, `scipy` (if installed)
- Each `.so` file must be rewritten individually with `litebox_syscall_rewriter`
- File naming: `module.cpython-3XX-ARCH-linux-gnu.so`
- Must preserve permissions and paths

**Module Compatibility Matrix:**
| Module Type | Status | Notes |
|-------------|--------|-------|
| Pure Python | ✅ Works | No syscall rewriting needed |
| Stdlib with .so | ⚠️ Requires rewriting | Must rewrite all .so files |
| Third-party pure | ✅ Works | If properly packaged |
| Third-party binary | ⚠️ Requires rewriting | Complex dependencies |
| Write-dependent | ❌ Fails | Tar filesystem is read-only |
| Kernel-dependent | ❌ Fails | LiteBox limitations |

#### Complete Setup Requirements

Running Python scripts requires:
- ✅ Python binary included in tar filesystem
- ✅ Python standard library packaged (version-matched)
- ✅ All `.so` files (binary + extensions) rewritten individually
- ✅ Environment variables set correctly:
  - `PYTHONHOME=/usr` - Python installation prefix
  - `PYTHONPATH=/usr/lib/python3.12:...` - Module search paths
  - `PYTHONDONTWRITEBYTECODE=1` - Prevent .pyc creation (read-only fs)
- ✅ All third-party modules packaged with dependencies
- ✅ Binary extension modules rewritten per-file

**Example Python Environment Setup:**
```bash
# Detect version
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")

# Collect paths
STDLIB=/usr/lib/python${PYTHON_VERSION}
DYNLOAD=/usr/lib/python${PYTHON_VERSION}/lib-dynload
DISTPKG=/usr/lib/python3/dist-packages

# Package all paths into tar
# Rewrite each .so file:
for so_file in $(find $STDLIB $DYNLOAD $DISTPKG -name "*.so" 2>/dev/null); do
    litebox_syscall_rewriter "$so_file" "$tar_staging/$so_file"
done

# Set environment
export PYTHONHOME=/usr
export PYTHONPATH=$STDLIB:$DYNLOAD:$DISTPKG
export PYTHONDONTWRITEBYTECODE=1
```

**Reference Implementation:** See `litebox_runner_linux_userland/tests/run.rs:test_runner_with_python` for the complete setup process.

### 3. Stateless Execution
- Skills are assumed to be stateless
- No persistent storage between runs
- All state is ephemeral within the sandbox

## Usage Example

```bash
# Basic skill structure validation
litebox_skill_runner /path/to/skill-creator \
    --script scripts/init_skill.py \
    my-skill --path /output

# With full setup (requires manual preparation)
# See prepare_python_skill.py for details
```

## Testing

Tested with:
- skill-creator from Anthropic skills repository
- Custom test skills
- Python script packaging and tar creation
- Skill structure validation

## Future Work

To enable full Python and shell script execution:

1. **Automate Python Setup**
   - Script to rewrite .so files
   - Automatic Python binary packaging
   - Environment variable management

2. **Shell Support**
   - Add shell support to LiteBox core
   - Enable `/bin/sh` and `/bin/bash` execution

3. **Additional Interpreters**
   - Node.js support
   - Ruby support
   - Other scripting languages

4. **Persistent Storage**
   - Support for stateful skills
   - File system persistence between runs

5. **Integration Tests**
   - Automated testing of skill execution
   - CI/CD integration

6. **Error Handling**
   - Better diagnostics
   - Clearer error messages
   - Debugging support

## Security Considerations

- All execution happens within LiteBox sandbox
- Syscall interception (seccomp or rewriter backend)
- Limited host filesystem access
- No direct network access without TUN configuration
- Python libraries are read-only in tar filesystem

## Files Added/Modified

### New Files
- `litebox_skill_runner/Cargo.toml` - Package manifest
- `litebox_skill_runner/src/main.rs` - Main implementation
- `litebox_skill_runner/README.md` - Documentation
- `litebox_skill_runner/examples/run_skill_creator.sh` - Demo script
- `litebox_skill_runner/examples/prepare_python_skill.py` - Python helper
- `litebox_skill_runner/examples/run_python_skill_full.sh` - Full example

### Modified Files
- `Cargo.toml` - Added litebox_skill_runner to workspace members
- `Cargo.lock` - Updated with new dependencies

## Dependencies Added

- `serde` + `serde_yaml` - YAML frontmatter parsing
- `zip` - .skill file extraction
- `tar` - Tar archive creation
- `tempfile` - Temporary directory management
- `clap` - CLI argument parsing
- `anyhow` - Error handling

## Conclusion

This implementation provides a solid foundation for Agent Skills support in LiteBox. While full Python and shell script execution require additional work, the architecture is in place and the path forward is clear. The proof-of-concept successfully demonstrates:

1. Skills can be parsed and validated
2. Resources can be packaged for LiteBox
3. Integration with litebox_runner_linux_userland works
4. Limitations are well-documented
5. Examples show the way forward

The implementation is production-ready for skill structure validation and can be extended incrementally to support full script execution as LiteBox capabilities expand.
