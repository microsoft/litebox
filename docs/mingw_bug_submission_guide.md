# How to Submit the MinGW CRT Bug Report

This guide explains how to submit the bug report to the MinGW-w64 project.

## Option 1: SourceForge Bug Tracker (Recommended)

### Steps:

1. **Visit the MinGW-w64 Bug Tracker:**
   - URL: https://sourceforge.net/p/mingw-w64/bugs/
   - You'll need a SourceForge account (free)

2. **Create New Ticket:**
   - Click "Create Ticket" button
   - Category: Select "crt" (C Runtime Library)

3. **Fill in the Ticket:**
   - **Summary:** `__do_global_ctors_aux crashes calling -1 sentinel as function pointer`
   - **Description:** Copy content from `mingw_bug_submission.md`
   - **Priority:** High
   - **Attachments:** Consider attaching test case binary or reproduction script

4. **Additional Information:**
   - Include link to full bug report: https://github.com/Vadiml1024/litebox/blob/main/docs/mingw_crt_ctor_list_bug_report.md
   - Mention workaround implementation if asked

## Option 2: MinGW-w64 Mailing List

### Steps:

1. **Subscribe to the List:**
   - Main list: mingw-w64-public@lists.sourceforge.net
   - Subscribe: https://sourceforge.net/p/mingw-w64/mailman/

2. **Compose Email:**
   - **Subject:** `[BUG] __do_global_ctors_aux crashes on -1 sentinel in __CTOR_LIST__`
   - **Body:** Use content from `mingw_bug_submission.md`
   - **Format:** Plain text preferred, code blocks in monospace

3. **Include:**
   - Reproduction steps
   - Expected vs actual behavior
   - Suggested fix
   - Link to full report for reference

## Option 3: GCC Bugzilla (Alternative)

Since MinGW-w64 uses GCC's CRT code:

1. **Visit GCC Bugzilla:**
   - URL: https://gcc.gnu.org/bugzilla/
   - Create account if needed

2. **Report Bug:**
   - Product: gcc
   - Component: other
   - Target: x86_64-w64-mingw32
   - Summary: Same as above
   - Description: From `mingw_bug_submission.md`

## Option 4: LLVM/Clang (For Awareness)

While not the primary source of the bug, LLVM/Clang developers should be aware:

1. **LLVM Discourse:**
   - URL: https://discourse.llvm.org/
   - Category: "Compilers"
   - Tag: [mingw], [windows], [constructors]

2. **Title:** `MinGW CRT bug affects programs using @llvm.global_ctors`

3. **Link to:** Full bug report and mention it affects Rust cross-compilation

## Recommended Approach

**Best Strategy:**
1. **Primary:** Submit to MinGW-w64 SourceForge bug tracker (most direct)
2. **Secondary:** Post to mingw-w64-public mailing list for discussion
3. **Follow-up:** Monitor for responses and provide additional info as requested

## Documents to Reference

When submitting, you can reference:

- **Full Technical Report:** `docs/mingw_crt_ctor_list_bug_report.md`
- **Concise Submission:** `docs/mingw_bug_submission.md`
- **Workaround Code:** `litebox_shim_windows/src/loader/pe.rs`

## What to Expect

1. **Initial Response:** May take days to weeks
2. **Discussion:** Maintainers may ask for:
   - Additional test cases
   - Specific MinGW version info
   - Disassembly or binary samples
3. **Resolution:** Could be:
   - Patch submitted and merged
   - Workaround documented
   - Requires further investigation

## Additional Resources

- **MinGW-w64 Project:** https://www.mingw-w64.org/
- **Source Repository:** https://github.com/mirror/mingw-w64
- **Documentation:** https://mingw-w64.org/doku.php
- **IRC:** #mingw-w64 on OFTC network

## Contact

If you have questions about this bug report:
- Open an issue in the LiteBox repository
- Reference the bug report documents
- Mention you found the issue through Windows-on-Linux development

---

**Note:** This bug affects real-world usage, particularly Rust cross-compilation to Windows. A prompt fix would benefit the entire MinGW ecosystem.
