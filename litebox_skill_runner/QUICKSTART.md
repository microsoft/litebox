# Quick Start Guide: Running Agent Skills in LiteBox

This guide will help you quickly get started with running Agent Skills in a LiteBox sandbox.

## Prerequisites

- Ubuntu/x86_64 Linux system
- Rust toolchain installed
- Git installed
- Python 3 (optional, for Python skill examples)

## 5-Minute Setup

### Step 1: Build the Tools

```bash
# Clone the repository (if you haven't already)
git clone https://github.com/lpcox/aw-litebox.git
cd aw-litebox

# Build the skill runner and litebox runner
cargo build --release -p litebox_skill_runner
cargo build --release -p litebox_runner_linux_userland
```

Build time: ~2-3 minutes on a modern system.

### Step 2: Run the First Example

We provide a ready-to-run example that validates skill structure:

```bash
# Run the skill structure validation example
./litebox_skill_runner/examples/run_skill_creator.sh
```

**What this does:**
- Clones the Anthropic skills repository
- Validates the `skill-creator` skill structure
- Shows how SKILL.md metadata is parsed
- Demonstrates tar packaging

**Expected output:**
```
=== LiteBox Skill Runner Example ===
✓ SKILL.md found
  Extracting metadata...
---
name: skill-creator
description: Guide for creating effective skills...
```

### Step 3: Try a Simple Custom Skill

Let's create and run a minimal skill:

```bash
# Create a simple test skill
mkdir -p /tmp/my-first-skill/scripts

# Create SKILL.md with metadata
cat > /tmp/my-first-skill/SKILL.md << 'EOF'
---
name: hello-skill
description: A simple hello world skill for testing
---

# Hello Skill

This is a minimal skill that demonstrates the basic structure.

## Usage

Run the hello script to see a greeting.
EOF

# Create a simple Python script
cat > /tmp/my-first-skill/scripts/hello.py << 'EOF'
#!/usr/bin/env python3
print("Hello from LiteBox!")
print("This skill is running in a sandboxed environment.")
EOF

chmod +x /tmp/my-first-skill/scripts/hello.py

# Validate the skill structure (parsing and tar creation)
./target/release/litebox_skill_runner \
    /tmp/my-first-skill \
    --script scripts/hello.py \
    2>&1 | head -10
```

**What you'll see:**
- The skill metadata is successfully parsed
- Tar archive is created with skill resources
- Note about Python execution requirements

## Understanding the Output

When you run the skill runner, you'll see:

1. **Skill Loading:** Confirmation that SKILL.md was parsed
   ```
   Loaded skill: hello-skill
   Description: A simple hello world skill for testing
   ```

2. **Tar Creation:** The skill is packaged for LiteBox
   ```
   Script: scripts/hello.py
   Tar file: /tmp/...
   ```

3. **Limitations Note:** Information about execution requirements

## Current Capabilities

✅ **What Works:**
- Parsing `.skill` files (zip archives) and skill directories
- Extracting SKILL.md metadata (name, description)
- Creating tar archives with all skill resources
- Validating skill structure
- Integration with litebox_runner_linux_userland
- **Shell scripts (`/bin/sh`) - Full support!**
- **Node.js scripts - Full support!**
- **Basic Bash scripts - Working (as of 2026-02-03)!**

⚠️ **What Needs Setup:**
- **Python Scripts:** Require packaging Python libraries and binary (see Advanced section below)
  - We provide automated tools: `prepare_python_skill_advanced.py`
- **Bash Scripts:** Basic support now available (as of 2026-02-03)
  - May have limitations with advanced features

✅ **What Works Out of the Box:**
- **Shell Scripts (`/bin/sh`):** Full support, works perfectly!
- **Node.js Scripts:** Full support, works perfectly!
- **Basic Bash:** Should work for most scripts

## Skill Structure Basics

A valid skill must have this structure:

```
my-skill/
├── SKILL.md          # Required: Metadata and instructions
├── scripts/          # Optional: Executable scripts
├── references/       # Optional: Documentation
└── assets/           # Optional: Templates, images
```

### Minimal SKILL.md Example

```markdown
---
name: my-skill-name
description: A clear description of what this skill does
---

# My Skill Name

Add instructions and guidelines here.
```

**Required fields in frontmatter:**
- `name`: Hyphenated identifier (e.g., `data-analyzer`)
- `description`: Complete description of the skill's purpose

## Testing Your Skills

The skill runner includes comprehensive unit tests:

```bash
# Run all tests
cargo test -p litebox_skill_runner

# Run with verbose output
cargo test -p litebox_skill_runner -- --nocapture
```

**Test coverage includes:**
- YAML frontmatter parsing
- Skill metadata extraction
- Tar archive creation
- Error handling for invalid skills
- Multi-line descriptions
- Optional resource directories

## Troubleshooting

### Error: "Failed to open SKILL.md"
**Solution:** Ensure your skill directory contains a `SKILL.md` file with proper YAML frontmatter.

### Error: "YAML frontmatter must start with ---"
**Solution:** Check that SKILL.md begins with `---` on the first line.

### Error: "Failed to parse YAML frontmatter"
**Solution:** Validate your YAML syntax. Ensure `name` and `description` fields are present.

### Python execution doesn't work
**Expected:** Full Python execution requires additional setup (see Advanced section).
**Current status:** Architecture is proven, but automation is needed.

## Advanced: Running Python Scripts

For full Python script execution, additional setup is required. We provide helper scripts, but understanding the requirements is important.

### Python Version and Module Handling

#### Python Version
- **System Python**: Uses the system's installed Python (default: `/usr/bin/python3`)
- **Version Detection**: Automatically detected via `python3 --version`
  - Example: Python 3.12.3
- **Version-Specific Paths**: Python libraries are version-specific
  - Standard library: `/usr/lib/python3.12/`
  - Extensions: `/usr/lib/python3.12/lib-dynload/`
  - Packages: `/usr/lib/python3/dist-packages/`
- **Custom Python**: Use `--python-path` to specify a different interpreter
- **No Multiple Versions**: Only one Python version can be used per execution

#### Module Resolution

**Standard Library Modules** (built-in Python):
```
Required paths to package:
- /usr/lib/python3.X/              # Core Python modules
- /usr/lib/python3.X/lib-dynload/  # C extension modules
- /usr/lib/python312.zip           # Compressed stdlib (if exists)
```

**Third-Party Modules** (installed via pip/apt):
```
Common locations to package:
- /usr/lib/python3/dist-packages/     # System packages (apt)
- /usr/local/lib/python3.X/dist-packages/  # User packages (pip)
```

**Module Import Process**:
1. Python looks in paths specified by `PYTHONPATH` environment variable
2. Falls back to default locations from `PYTHONHOME`
3. All paths must exist in the tar filesystem
4. Import fails if paths are missing or modules unavailable

#### Binary Extension Modules (.so files)

Python modules with C extensions require special handling:

**Common Extension Modules:**
- `_ssl.cpython-312-x86_64-linux-gnu.so` - SSL support
- `_json.cpython-312-x86_64-linux-gnu.so` - JSON parsing
- `_socket.cpython-312-x86_64-linux-gnu.so` - Network sockets
- `math.cpython-312-x86_64-linux-gnu.so` - Math functions
- Any NumPy, Pandas, or other scientific computing libraries

**Required Processing:**
1. Identify all `.so` files in Python paths
2. Run `litebox_syscall_rewriter` on each file individually
3. Replace original files in tar with rewritten versions
4. Preserve file permissions and directory structure

**Example Rewriting Process:**
```bash
# For each .so file in Python lib directories
for so_file in $(find /usr/lib/python3.12 -name "*.so"); do
    litebox_syscall_rewriter "$so_file" "$tar_dir$so_file"
done
```

### Module Compatibility

**✓ Compatible Modules:**
- Pure Python modules (no C extensions)
- Standard library modules (with proper packaging)
- Binary modules with syscall rewriting

**⚠️ Limited Support:**
- Modules requiring file system write access (tar is read-only)
- Modules using advanced syscalls not handled by LiteBox
- Modules with complex native dependencies

**✗ Incompatible:**
- Modules requiring kernel features not in LiteBox
- Modules needing `/proc` or `/sys` access
- Some networking modules (depends on LiteBox config)

### Setup Helper Script

We provide a helper to package Python libraries:

```bash
# Step 1: Prepare the skill with Python libraries
./litebox_skill_runner/examples/prepare_python_skill.py \
    /tmp/my-first-skill \
    -o /tmp/my-skill-with-python.tar

# Step 2: Review the generated command
# The script will show you the exact litebox_runner_linux_userland command needed
```

**What the helper does:**
1. Detects system Python version
2. Finds all Python library paths
3. Packages them into tar archive
4. Generates environment variables needed

**What it doesn't do (yet):**
- Syscall rewriting of `.so` files (must be done manually)
- Verification of module compatibility
- Dependency resolution for third-party packages

### Complete Python Execution Example

For reference, here's what a complete Python setup looks like:

```bash
# Detect Python environment
PYTHON_HOME=$(python3 -c "import sys; print(sys.prefix)")
PYTHON_PATH=$(python3 -c "import sys; print(':'.join([p for p in sys.path if p and p.startswith('/usr')]))")
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)

# Package Python libraries into tar (with .so rewriting)
# See litebox_runner_linux_userland/tests/run.rs:test_runner_with_python

# Run with litebox
litebox_runner_linux_userland \
    --unstable \
    --initial-files /path/to/skill-with-python.tar \
    --interception-backend rewriter \
    --rewrite-syscalls \
    --env "PYTHONHOME=$PYTHON_HOME" \
    --env "PYTHONPATH=$PYTHON_PATH" \
    --env "PYTHONDONTWRITEBYTECODE=1" \
    /usr/bin/python3 /skill/scripts/script.py
```

**Environment Variables Explained:**
- `PYTHONHOME`: Tells Python where to find standard library
- `PYTHONPATH`: Additional paths to search for modules  
- `PYTHONDONTWRITEBYTECODE`: Prevents .pyc creation (tar is read-only)

### Troubleshooting Python Issues

**ModuleNotFoundError:**
- Check that module path is in `PYTHONPATH`
- Verify module files are in the tar archive
- Ensure Python version matches packaged libraries

**ImportError with .so files:**
- Verify `.so` file was rewritten with `litebox_syscall_rewriter`
- Check file permissions are preserved
- Ensure all dependent `.so` files are also rewritten

**"No module named 'encodings'":**
- Standard library not properly packaged
- Check `/usr/lib/python3.X/` is in tar
- Verify `PYTHONHOME` is set correctly

## Examples Gallery

The repository includes several example scripts:

1. **`run_skill_creator.sh`** - Validates skill structure with skill-creator
2. **`prepare_python_skill.py`** - Helper for Python library packaging
3. **`run_python_skill_full.sh`** - Demonstrates Python execution workflow

## Next Steps

1. **Explore existing skills:** Check out https://github.com/anthropics/skills
2. **Create your own skill:** Follow the Agent Skills specification at https://agentskills.io
3. **Read the docs:** See `README.md` for detailed architecture and API reference
4. **Run the tests:** Validate your setup with `cargo test -p litebox_skill_runner`

## Getting Help

- **Documentation:** See `README.md` and `IMPLEMENTATION.md` in the `litebox_skill_runner/` directory
- **Issues:** Check GitHub issues for known limitations and workarounds
- **Examples:** Study the provided example scripts for working patterns

## Summary

You now have:
- ✅ Built the skill runner tools
- ✅ Run your first skill validation
- ✅ Created a custom skill
- ✅ Understood the basic workflow
- ✅ Learned the current capabilities and limitations

The skill runner successfully demonstrates the architecture for running Agent Skills in LiteBox. While full Python and shell execution require additional work (documented in the examples), the foundation is solid and extensible.

## Quick Reference

```bash
# Build tools
cargo build --release -p litebox_skill_runner

# Validate a skill
./target/release/litebox_skill_runner /path/to/skill --script scripts/script.py

# Run tests
cargo test -p litebox_skill_runner

# Run examples
./litebox_skill_runner/examples/run_skill_creator.sh
```

For more detailed information, see:
- `README.md` - Complete documentation
- `IMPLEMENTATION.md` - Technical details
- `examples/` - Working examples
