# LiteBox Skill Runner Examples

This directory contains helper scripts and examples for running Agent Skills in LiteBox.

## Quick Start

### 1. Build Required Tools

```bash
# From repository root
cd /path/to/aw-litebox

# Build the runner
cargo build --release -p litebox_runner_linux_userland

# Build the syscall rewriter (required for Python)
cargo build --release -p litebox_syscall_rewriter
```

### 2. Prepare a Python Skill

```bash
# Clone Anthropic skills repository
git clone https://github.com/anthropics/skills.git /tmp/skills

# Prepare a skill for LiteBox execution
./litebox_skill_runner/examples/prepare_python_skill_advanced.py \
    /tmp/skills/skills/skill-creator \
    -o /tmp/skill-creator.tar \
    --rewriter-path ./target/release/litebox_syscall_rewriter
```

### 3. Run Integration Tests

```bash
# Test a specific skill
./litebox_skill_runner/examples/test_anthropic_skills.sh --skill skill-creator

# Test all available skills
./litebox_skill_runner/examples/test_anthropic_skills.sh --all
```

## Scripts Overview

### prepare_python_skill_advanced.py

**Purpose:** Automate Python skill preparation with .so rewriting

**Features:**
- Automatic Python version detection
- Smart library path discovery
- Automatic .so file rewriting with litebox_syscall_rewriter
- Progress reporting
- Ready-to-use command generation

**Usage:**
```bash
./prepare_python_skill_advanced.py SKILL_DIR -o OUTPUT.tar [--rewriter-path PATH]
```

**Example:**
```bash
./prepare_python_skill_advanced.py \
    /tmp/skills/skills/skill-creator \
    -o /tmp/skill-creator.tar \
    --rewriter-path ./target/release/litebox_syscall_rewriter
```

**Output:**
- Creates a tar archive with:
  - Skill files
  - Python interpreter
  - Standard library (rewritten .so files)
  - All necessary dependencies
- Prints ready-to-use execution command

### test_anthropic_skills.sh

**Purpose:** Integration testing with real Anthropic skills

**Features:**
- Tests multiple skills from the Anthropic repository
- Automatic skill preparation
- Detailed test reporting
- Success/failure tracking

**Usage:**
```bash
# Test a specific skill
./test_anthropic_skills.sh --skill SKILL_NAME

# Test all skills
./test_anthropic_skills.sh --all
```

**Available Skills:**
- `skill-creator` - Skill creation and validation tools
- `pdf` - PDF manipulation scripts
- `pptx` - PowerPoint manipulation (Node.js + Python)

**Example:**
```bash
./test_anthropic_skills.sh --skill skill-creator
```

**Output:**
- Test execution logs in `/tmp/litebox-skill-tests/`
- Summary of passed/failed tests
- Detailed error information for failures

### prepare_python_skill.py

**Purpose:** Basic Python skill preparation (legacy)

**Note:** Use `prepare_python_skill_advanced.py` for new work. This script is kept for backward compatibility.

**Features:**
- Basic library packaging
- No .so rewriting (manual setup required)

### Other Scripts

- `quickstart_demo.sh` - Quick demonstration of skill runner
- `run_python_skill_full.sh` - Example Python skill execution
- `run_skill_creator.sh` - Specific skill-creator example

## Skill Preparation Workflow

### For Python Skills

1. **Identify Dependencies**
   ```bash
   # Check what imports the script uses
   grep -E "^import |^from " /path/to/skill/scripts/*.py
   ```

2. **Prepare Skill Archive**
   ```bash
   ./prepare_python_skill_advanced.py \
       /path/to/skill \
       -o skill.tar \
       --rewriter-path ./target/release/litebox_syscall_rewriter
   ```

3. **Execute Skill**
   ```bash
   # Use the command printed by prepare_python_skill_advanced.py
   # Or use litebox_runner_linux_userland directly:
   
   ./target/release/litebox_runner_linux_userland \
       --unstable \
       --initial-files skill.tar \
       --interception-backend rewriter \
       --rewrite-syscalls \
       --env PYTHONHOME=/usr \
       --env "PYTHONPATH=/usr/lib/python3.12:/usr/lib/python3/dist-packages" \
       --env PYTHONDONTWRITEBYTECODE=1 \
       /usr/bin/python3 /skill/scripts/YOUR_SCRIPT.py [args...]
   ```

### For Node.js Skills

1. **Prepare Skill Archive**
   ```bash
   # Node.js skills don't need special preparation
   # Just create a tar with the skill
   tar -cf skill.tar -C /path/to/skill .
   ```

2. **Execute Skill**
   ```bash
   ./target/release/litebox_runner_linux_userland \
       --unstable \
       --initial-files skill.tar \
       --interception-backend rewriter \
       --rewrite-syscalls \
       /usr/bin/node /skill/scripts/YOUR_SCRIPT.js [args...]
   ```

### For Shell Scripts

1. **Prepare Skill Archive**
   ```bash
   tar -cf skill.tar -C /path/to/skill .
   ```

2. **Execute Skill**
   ```bash
   ./target/release/litebox_runner_linux_userland \
       --unstable \
       --initial-files skill.tar \
       --interception-backend rewriter \
       --rewrite-syscalls \
       /bin/sh /skill/scripts/YOUR_SCRIPT.sh [args...]
   ```

## Troubleshooting

### Python .so Files Not Rewritten

**Symptom:** Python execution fails with syscall errors

**Solution:** Ensure litebox_syscall_rewriter is built and the path is correct:
```bash
cargo build --release -p litebox_syscall_rewriter
./prepare_python_skill_advanced.py ... --rewriter-path ./target/release/litebox_syscall_rewriter
```

### Python Module Not Found

**Symptom:** `ModuleNotFoundError` when running Python script

**Solution:** Check that the module is in the packaged paths:
1. Verify module is in system Python: `python3 -c "import MODULE"`
2. Check PYTHONPATH includes the module location
3. For external modules, they must be in system site-packages

### Skill Directory Not Found

**Symptom:** "Skill directory not found" error

**Solution:** Ensure the path points to a valid skill directory with SKILL.md:
```bash
ls -la /path/to/skill/SKILL.md  # Should exist
```

### Integration Tests Fail

**Symptom:** All integration tests fail immediately

**Solution:** Check prerequisites:
```bash
# Check runner exists
ls -la ./target/release/litebox_runner_linux_userland

# Check rewriter exists
ls -la ./target/release/litebox_syscall_rewriter

# Check Python exists
which python3
```

## Performance Considerations

### First Run vs. Cached Execution

- **First run:** Includes syscall rewriting overhead (~10-15 seconds for Python)
- **Cached run:** Uses pre-rewritten binaries (~0.3-0.5 seconds)

### Tar File Sizes

- Shell script skill: < 1 MB
- Node.js skill: ~50 MB (with dependencies)
- Python skill: ~100 MB (with full stdlib)

### Optimization Tips

1. **Minimize Python libraries:** Only package what's needed
2. **Reuse tar archives:** Cache prepared skills for multiple runs
3. **Use stdlib-only when possible:** Faster and smaller

## Contributing

When adding new examples or tests:

1. Follow existing naming conventions
2. Add comprehensive documentation
3. Include usage examples
4. Test with multiple skills
5. Update this README

## References

- [Agent Skills Specification](https://agentskills.io)
- [Anthropic Skills Repository](https://github.com/anthropics/skills)
- [LiteBox Documentation](../../README.md)
- [Skill Runner Documentation](../README.md)

## License

MIT License - see [LICENSE](../../LICENSE) file for details.
