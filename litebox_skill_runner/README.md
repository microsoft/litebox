# LiteBox Skill Runner

A tool for executing [Agent Skills](https://agentskills.io) within LiteBox sandboxed environments.

## Overview

Agent Skills are modular packages that extend AI capabilities by providing specialized knowledge, workflows, and tools. This tool enables the architectural framework for running skill scripts within a LiteBox sandbox on Ubuntu/x86 Linux systems.

## Current Status

This is a **proof-of-concept implementation** that demonstrates the architecture for running Agent Skills in LiteBox. The tool successfully:

✅ Parses `.skill` files (zip archives) and skill directories  
✅ Extracts SKILL.md metadata (name, description)  
✅ Creates tar archives with skill resources  
✅ Integrates with litebox_runner_linux_userland  
✅ Demonstrates the execution architecture  

## Known Limitations

### 1. No Shell Support
LiteBox currently does not support running a shell (`/bin/sh`, `/bin/bash`). This means:
- Shell scripts (`.sh` files) cannot be executed directly
- Skills that rely on shell features will not work
- Only direct binary execution (e.g., Python interpreter) is supported

### 2. Python Execution Complexity

#### Python Version Handling
- **System Python Only**: The skill runner uses the system's Python interpreter (default: `/usr/bin/python3`)
- **Version Detection**: Automatically detects the Python version from the system (e.g., Python 3.12)
- **No Virtual Environments**: Python virtual environments (venv/virtualenv) are not currently supported
- **Custom Python Path**: Can be specified via `--python-path` option if using a different Python installation

#### Python Module Management
Running Python scripts requires extensive manual setup:

**Standard Library Modules:**
- Must be explicitly packaged into the tar filesystem
- Location: Usually `/usr/lib/python3.X/` and `/usr/lib/python3/dist-packages/`
- Environment variables required:
  - `PYTHONHOME`: Python installation prefix (e.g., `/usr`)
  - `PYTHONPATH`: Colon-separated list of module search paths
  - `PYTHONDONTWRITEBYTECODE=1`: Prevents .pyc creation (tar is read-only)

**Third-Party Modules:**
- System-installed packages (via apt/pip) must be packaged
- Location: `/usr/local/lib/python3.X/dist-packages/` or similar
- All paths must be included in `PYTHONPATH`
- Pure Python modules work if properly packaged
- Binary modules (`.so` files) require syscall rewriting (see below)

**Binary Extensions (.so files):**
- All Python extension modules (`.so` files) must have syscalls rewritten before packaging
- This includes modules like: `_ssl`, `_json`, `_socket`, `numpy`, etc.
- Syscall rewriting is required for LiteBox's seccomp/rewriter backend
- Process: Use `litebox_syscall_rewriter` on each `.so` file before adding to tar

**Module Import Limitations:**
- Modules that require write access will fail (tar filesystem is read-only)
- Modules that use features not supported by LiteBox may fail
- C extension modules need proper syscall rewriting

#### Complete Python Setup Requirements
1. ✅ Python binary must be included in tar filesystem
2. ✅ Python standard library must be packaged
3. ✅ All `.so` files (Python binary + extensions) must have syscalls rewritten
4. ✅ Environment variables must be set: `PYTHONHOME`, `PYTHONPATH`, `PYTHONDONTWRITEBYTECODE`
5. ✅ All third-party modules must be packaged with proper paths
6. ✅ Binary extension modules must be rewritten individually

**Example Python Setup:**
```python
# Detect Python version and paths
python_version = "3.12"  # From system
python_home = "/usr"
python_paths = [
    "/usr/lib/python3.12",
    "/usr/lib/python3.12/lib-dynload",
    "/usr/lib/python3/dist-packages"
]

# All paths must be packaged in tar
# All .so files must be rewritten with litebox_syscall_rewriter
```

**See** `litebox_runner_linux_userland/tests/run.rs:test_runner_with_python` for a reference implementation showing the complete Python setup process with per-file `.so` rewriting.

**See** `examples/prepare_python_skill.py` for a helper script that packages Python libraries (note: does not handle .so rewriting yet).

### 3. Stateless Assumption
Skills are assumed to be stateless for now (no persistent storage between runs).

## Usage

### Basic Command

```bash
litebox_skill_runner <skill-path> --script <script-path> [script-args...]
```

### Options

- `<skill-path>`: Path to .skill file (zip) or skill directory
- `--script <path>`: Script to execute within the skill (relative path from skill root, e.g., `scripts/init_skill.py`)
- `--runner-path`: Path to litebox_runner_linux_userland binary (default: `../target/release/litebox_runner_linux_userland`)
- `--python-path`: Python interpreter path (default: `/usr/bin/python3`)
- `[script-args...]`: Additional arguments to pass to the script

### Example: Testing Skill Structure

The skill runner can parse and validate skill structures:

```bash
# Clone the skills repository
git clone https://github.com/anthropics/skills.git /tmp/skills

# Test skill structure parsing
cd /path/to/aw-litebox
./litebox_skill_runner/examples/run_skill_creator.sh
```

This demonstrates successful skill parsing and tar packaging, but notes that full Python execution requires additional setup.

## Building

```bash
cargo build --release -p litebox_skill_runner
```

The binary will be available at `target/release/litebox_skill_runner`.

## Examples

The `examples/` directory contains demonstration scripts:

- `run_skill_creator.sh`: Shows skill structure validation
- `prepare_python_skill.py`: Helper to package Python libraries
- `run_python_skill_full.sh`: Demonstrates Python execution attempt (with expected limitations)

## Implementation Details

### Skill Structure

A skill consists of:
- `SKILL.md`: Metadata (YAML frontmatter) and instructions
- `scripts/`: Optional executable scripts (Python, Bash, etc.)
- `references/`: Optional reference documentation
- `assets/`: Optional asset files (templates, images, etc.)

### Execution Architecture

1. **Load and Parse**: Read skill from .skill zip or directory
2. **Extract Metadata**: Parse YAML frontmatter from SKILL.md
3. **Create Tar**: Package all skill resources into a tar archive
4. **Execute via LiteBox**: Run with litebox_runner_linux_userland using:
   - `--initial-files` (tar archive path)
   - `--interception-backend seccomp` or `rewriter`
   - `--rewrite-syscalls` (for rewriter backend)
   - Environment variables as needed

### Filesystem Layout

Within the LiteBox sandbox, the skill is mounted at `/skill/`:
```
/skill/
  ├── SKILL.md
  ├── scripts/
  ├── references/
  └── assets/
```

Scripts are executed with paths relative to the skill root (e.g., `/skill/scripts/init_skill.py`).

## Future Work

The following enhancements would enable full Python and shell script execution:

- [ ] Add shell support in LiteBox core
- [ ] Automate Python binary and library packaging
- [ ] Implement syscall rewriting for .so files in tar archives
- [ ] Support for other interpreters (Node.js, Ruby, etc.)
- [ ] Interactive skill execution with stdin/stdout
- [ ] Better error handling and diagnostics
- [ ] Integration tests for full skill execution
- [ ] Persistent storage support for stateful skills

## Example Skills

See the [Anthropic Skills Repository](https://github.com/anthropics/skills) for examples:
- `skill-creator`: Tools for creating new skills
- `pdf-editor`: PDF manipulation utilities
- `docx-editor`: Document editing capabilities
- And many more...

## References

- [Agent Skills Specification](https://agentskills.io)
- [Anthropic Skills Repository](https://github.com/anthropics/skills)
- [LiteBox Documentation](../README.md)

## Contributing

Contributions are welcome! Please see the main LiteBox [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](../LICENSE) file for details.
