# Quick-Start Testing Guide for Anthropic Skills

**Purpose:** Simple, step-by-step guide to test Anthropic Skills in LiteBox  
**Target Audience:** Developers testing LiteBox skill compatibility  
**Last Updated:** 2026-02-07

## Prerequisites

### 1. Build LiteBox
```bash
cd /path/to/aw-litebox
cargo build --release -p litebox_runner_linux_userland
cargo build --release -p litebox_syscall_rewriter
```

### 2. Clone Anthropic Skills Repository
```bash
git clone https://github.com/anthropics/skills.git
cd skills
```

### 3. Verify Prerequisites
```bash
# Check for Python 3
python3 --version  # Should be 3.11+

# Check for Node.js
node --version  # Should be 18+

# Check for shell
/bin/sh --version
```

## Testing Tier 1 Skills (Quick Wins)

### Test 1: skill-creator (Python + PyYAML) ⭐ TOP PRIORITY

**Expected Success Rate:** 95%  
**Test Time:** ~30 minutes  
**Why This First:** Proves Python packaging automation works

#### Step 1: Install Dependencies
```bash
cd skills/skill-creator
pip install pyyaml  # Pure Python, no .so files
```

#### Step 2: Package the Skill
```bash
cd /path/to/aw-litebox
./litebox_skill_runner/examples/prepare_python_skill_advanced.py \
    /path/to/skills/skill-creator \
    -o /tmp/skill-creator.tar \
    --rewriter-path ./target/release/litebox_syscall_rewriter
```

#### Step 3: Test init_skill.py
```bash
cd /path/to/aw-litebox
./target/release/litebox_runner_linux_userland \
    --tar /tmp/skill-creator.tar \
    -- /usr/bin/python3 /skill/scripts/init_skill.py test-skill /tmp/output
```

**Expected Output:**
```
Created skill directory: /tmp/output/test-skill
Generated skill.yaml
Generated README.md
```

#### Step 4: Test quick_validate.py
```bash
./target/release/litebox_runner_linux_userland \
    --tar /tmp/skill-creator.tar \
    -- /usr/bin/python3 /skill/scripts/quick_validate.py /skills
```

**Expected Output:**
```
Validating skills...
✓ skill-creator: Valid
✓ pdf: Valid
...
```

#### Step 5: Test package_skill.py
```bash
./target/release/litebox_runner_linux_userland \
    --tar /tmp/skill-creator.tar \
    -- /usr/bin/python3 /skill/scripts/package_skill.py \
        /skill /tmp/output.skill
```

**Expected Output:**
```
Packaging skill...
Created: /tmp/output.skill
```

#### Troubleshooting skill-creator
- **Error: "No module named 'yaml'"** - PyYAML not packaged correctly
  - Solution: Re-run prepare_python_skill_advanced.py with -v for verbose output
- **Error: "File not found"** - Path mappings incorrect
  - Solution: Check tar contents with `tar -tf /tmp/skill-creator.tar | head -20`
- **Error: "Permission denied"** - .so files not rewritten
  - Solution: Verify rewriter ran with `--rewriter-path` flag

---

### Test 2: web-artifacts-builder (Shell)

**Expected Success Rate:** 100%  
**Test Time:** ~15 minutes  
**Why This:** Proves shell support works end-to-end

#### Step 1: Package the Skill
```bash
cd /path/to/aw-litebox
tar -czf /tmp/web-artifacts.tar \
    -C /path/to/skills/web-artifacts-builder .
```

#### Step 2: Test init-artifact.sh
```bash
./target/release/litebox_runner_linux_userland \
    --tar /tmp/web-artifacts.tar \
    -- /bin/sh /skill/scripts/init-artifact.sh \
        "Test Artifact" /tmp/output
```

**Expected Output:**
```
Creating artifact: Test Artifact
Generated index.html
Generated styles.css
```

#### Step 3: Test update-artifact.sh
```bash
./target/release/litebox_runner_linux_userland \
    --tar /tmp/web-artifacts.tar \
    -- /bin/sh /skill/scripts/update-artifact.sh \
        /tmp/output "New content"
```

**Expected Output:**
```
Updating artifact...
Modified index.html
```

#### Troubleshooting web-artifacts-builder
- **Error: "Command not found"** - Shell binary missing
  - Solution: Ensure `/bin/sh` is in tar filesystem
- **Error: "Syscall not implemented"** - Missing syscall
  - Solution: Check logs for specific syscall, file bug report

---

### Test 3: algorithmic-art (Node.js)

**Expected Success Rate:** 100%  
**Test Time:** ~15 minutes  
**Why This:** Proves Node.js support works end-to-end

#### Step 1: Package the Skill
```bash
cd /path/to/aw-litebox
tar -czf /tmp/algorithmic-art.tar \
    -C /path/to/skills/algorithmic-art .
```

#### Step 2: Test generator_template.js
```bash
./target/release/litebox_runner_linux_userland \
    --tar /tmp/algorithmic-art.tar \
    -- node /skill/templates/generator_template.js
```

**Expected Output:**
```javascript
// Generated art code
function generateArt() {
  // ...
}
```

#### Troubleshooting algorithmic-art
- **Error: "Node.js not found"** - Node binary missing
  - Solution: Ensure node is installed and accessible
- **Warning: "non-blocking fd"** - Cosmetic warning, safe to ignore
  - This is a known warning and doesn't affect functionality

---

## Testing Tier 2 Skills (Moderate Complexity)

### Test 4: pdf (Python + pypdf + Pillow)

**Expected Success Rate:** 70%  
**Test Time:** ~2 hours  

#### Phase 1: pypdf-only scripts (5 scripts)
1. `check_fillable_fields.py`
2. `extract_form_field_info.py`
3. `fill_fillable_fields.py`
4. `fill_pdf_form_with_annotations.py`
5. `check_bounding_boxes.py`

```bash
# Install pypdf
pip install pypdf

# Package the skill
./litebox_skill_runner/examples/prepare_python_skill_advanced.py \
    /path/to/skills/pdf \
    -o /tmp/pdf.tar \
    --rewriter-path ./target/release/litebox_syscall_rewriter

# Test check_fillable_fields.py
./target/release/litebox_runner_linux_userland \
    --tar /tmp/pdf.tar \
    -- /usr/bin/python3 /skill/scripts/check_fillable_fields.py \
        /path/to/test.pdf
```

#### Phase 2: Pillow scripts (2 scripts)
1. `convert_pdf_to_images.py`
2. `create_validation_image.py`

```bash
# Install Pillow (has C extensions)
pip install pillow

# Re-package with Pillow
./litebox_skill_runner/examples/prepare_python_skill_advanced.py \
    /path/to/skills/pdf \
    -o /tmp/pdf-pillow.tar \
    --rewriter-path ./target/release/litebox_syscall_rewriter

# Test create_validation_image.py
./target/release/litebox_runner_linux_userland \
    --tar /tmp/pdf-pillow.tar \
    -- /usr/bin/python3 /skill/scripts/create_validation_image.py \
        /path/to/test.pdf /tmp/output.png
```

---

### Test 5: docx (Python + defusedxml)

**Expected Success Rate:** 70%  
**Test Time:** ~1 hour  

```bash
# Install defusedxml
pip install defusedxml

# Package the skill
./litebox_skill_runner/examples/prepare_python_skill_advanced.py \
    /path/to/skills/docx \
    -o /tmp/docx.tar \
    --rewriter-path ./target/release/litebox_syscall_rewriter

# Test a docx manipulation script
./target/release/litebox_runner_linux_userland \
    --tar /tmp/docx.tar \
    -- /usr/bin/python3 /skill/scripts/[script_name].py \
        /path/to/test.docx
```

---

### Test 6: pptx (Python + python-pptx + Pillow + Node.js)

**Expected Success Rate:** 75%  
**Test Time:** ~2 hours  

#### Phase 1: Node.js script (html2pptx.js)
```bash
# Package and test
tar -czf /tmp/pptx.tar -C /path/to/skills/pptx .

./target/release/litebox_runner_linux_userland \
    --tar /tmp/pptx.tar \
    -- node /skill/scripts/html2pptx.js /path/to/input.html /tmp/output.pptx
```

#### Phase 2: Python scripts
```bash
# Install dependencies
pip install python-pptx pillow

# Package with .so rewriting
./litebox_skill_runner/examples/prepare_python_skill_advanced.py \
    /path/to/skills/pptx \
    -o /tmp/pptx-python.tar \
    --rewriter-path ./target/release/litebox_syscall_rewriter

# Test a script
./target/release/litebox_runner_linux_userland \
    --tar /tmp/pptx-python.tar \
    -- /usr/bin/python3 /skill/scripts/[script_name].py \
        /path/to/test.pptx
```

---

## Common Troubleshooting

### Python Issues

#### "No module named 'X'"
**Cause:** Python package not installed or not included in tar  
**Solution:**
1. Verify package installed: `pip list | grep X`
2. Check package in site-packages: `ls -la ~/.local/lib/python3.X/site-packages/`
3. Re-run prepare_python_skill_advanced.py with -v flag

#### "cannot open shared object file"
**Cause:** .so file not rewritten with litebox_syscall_rewriter  
**Solution:**
1. Find all .so files: `find ~/.local/lib/python3.X -name "*.so"`
2. Verify rewriter ran: Check prepare_python_skill_advanced.py output
3. Manually rewrite if needed:
   ```bash
   ./target/release/litebox_syscall_rewriter \
       /path/to/file.so \
       /path/to/file.so.rewritten
   ```

#### "Python version mismatch"
**Cause:** Packaged Python stdlib doesn't match interpreter version  
**Solution:**
1. Check Python version: `python3 --version`
2. Ensure PYTHONPATH points to matching version
3. Re-package with correct version

### Shell Issues

#### "Syscall not implemented"
**Cause:** Script uses syscall not yet implemented in LiteBox  
**Solution:**
1. Check logs for specific syscall name
2. File bug report with syscall details
3. Try using /bin/sh instead of /bin/bash
4. Rewrite script to avoid problematic syscall

### Node.js Issues

#### "Warning: unsupported shared futex"
**Cause:** Cosmetic warning from Node.js threading  
**Solution:** Safe to ignore, doesn't affect functionality

#### "Module not found"
**Cause:** Node.js module not in tar filesystem  
**Solution:**
1. Run `npm install` in skill directory
2. Include node_modules in tar
3. Verify paths with `tar -tf /tmp/skill.tar | grep node_modules`

---

## Testing Checklist

### Before Testing
- [ ] Built litebox_runner_linux_userland (release mode)
- [ ] Built litebox_syscall_rewriter (release mode)
- [ ] Cloned Anthropic skills repository
- [ ] Verified Python 3.11+ installed
- [ ] Verified Node.js 18+ installed
- [ ] Verified /bin/sh available

### Tier 1 Testing (Quick Wins)
- [ ] Tested skill-creator (Python + PyYAML)
  - [ ] init_skill.py works
  - [ ] quick_validate.py works
  - [ ] package_skill.py works
- [ ] Tested web-artifacts-builder (Shell)
  - [ ] init-artifact.sh works
  - [ ] update-artifact.sh works
- [ ] Tested algorithmic-art (Node.js)
  - [ ] generator_template.js works

### Tier 2 Testing (Moderate Complexity)
- [ ] Tested pdf scripts
  - [ ] pypdf-only scripts work (5 scripts)
  - [ ] Pillow scripts work (2 scripts)
- [ ] Tested docx scripts
  - [ ] defusedxml scripts work
- [ ] Tested pptx scripts
  - [ ] Node.js script works
  - [ ] Python scripts work

### Documentation
- [ ] Updated CAPABILITIES.md with test results
- [ ] Updated EVALUATION_YYYY-MM-DD.md with findings
- [ ] Documented any new issues found
- [ ] Created bug reports for failures

---

## Results Documentation Template

After testing, document results in `EVALUATION_YYYY-MM-DD.md`:

```markdown
## Test Results - [Date]

### skill-creator
**Status:** ✅ PASS / ❌ FAIL / 🟡 PARTIAL  
**Scripts Tested:** init_skill.py, quick_validate.py, package_skill.py  
**Pass Rate:** X/3 (XX%)  
**Issues Found:** [List any issues]  
**Notes:** [Any observations]

### web-artifacts-builder
**Status:** ✅ PASS / ❌ FAIL / 🟡 PARTIAL  
**Scripts Tested:** init-artifact.sh, update-artifact.sh  
**Pass Rate:** X/2 (XX%)  
**Issues Found:** [List any issues]  
**Notes:** [Any observations]

[Continue for each skill tested...]
```

---

## Quick Reference: Testing Priorities

### Week 1 (Quick Wins)
1. ⭐ skill-creator - Highest priority, proves Python works
2. ✅ web-artifacts-builder - Proves shell works
3. ✅ algorithmic-art - Proves Node.js works

**Goal:** 3/16 skills working (19%)

### Week 2 (Moderate Complexity)
4. 🟡 pdf (pypdf subset) - Proves pure Python packages work
5. 🟡 docx - Proves XML processing works
6. 🟡 xlsx - Proves spreadsheet processing works

**Goal:** 6/16 skills working (38%)

### Week 3 (Complex)
7. 🟡 pdf (Pillow scripts) - Proves C extensions work
8. 🟡 pptx - Proves mixed Python/Node.js works
9. 🟡 slack-gif-creator - Proves complex dependencies work

**Goal:** 9/16 skills working (56%)

### Future (Infrastructure-Dependent)
10. 🔴 mcp-builder - Requires network access
11. 🔴 webapp-testing - Requires browser support

**Goal:** 11/16 skills working (69%) when infrastructure ready

---

**Quick-Start Guide Version:** 1.0  
**Created:** 2026-02-07  
**Last Updated:** 2026-02-07  
**Next Review:** After Tier 1 testing complete
