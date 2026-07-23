// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

fn objdump(objdump_cmd: &str, binary: &[u8]) -> String {
    use std::io::Write;
    use std::process::Command;
    use tempfile::NamedTempFile;

    let trampoline_range = trampoline_range(binary);
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(binary).unwrap();

    // Run objdump on the temporary file and capture the output
    let output = Command::new(objdump_cmd)
        .arg("-d")
        .arg(temp_file.path())
        .output()
        .unwrap();

    let mut lines = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.contains("/tmp/"))
        .map(|line| normalize_objdump_line(line, trampoline_range.as_ref()))
        .collect::<Vec<_>>();
    let first_content = lines
        .iter()
        .position(|line| !line.is_empty())
        .unwrap_or(lines.len());
    lines.drain(..first_content);
    lines.join("\n")
}

/// Return the first objdump-like command that exists on the host from
/// `candidates`, or `None` if none are available.
fn find_objdump(candidates: &[&str]) -> Option<String> {
    use std::process::Command;
    candidates
        .iter()
        .find(|cmd| {
            Command::new(cmd)
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
        })
        .map(|cmd| (*cmd).to_owned())
}

fn trampoline_range(binary: &[u8]) -> Option<std::ops::Range<u64>> {
    const MAGIC: &[u8; 8] = litebox_syscall_rewriter::TRAMPOLINE_MAGIC;

    if binary.len() < 32 {
        return None;
    }

    let header = &binary[binary.len() - 32..];
    if &header[..8] != MAGIC {
        return None;
    }
    let vaddr = u64::from_le_bytes(header[16..24].try_into().unwrap());
    let size = u64::from_le_bytes(header[24..32].try_into().unwrap());
    (size != 0).then_some(vaddr..vaddr.checked_add(size)?)
}

fn normalize_objdump_line(line: &str, trampoline_range: Option<&std::ops::Range<u64>>) -> String {
    let Some((address, rest)) = line.split_once(':') else {
        return line.trim_end().to_owned();
    };
    let tokens: Vec<_> = rest.split_whitespace().collect();

    // A control-transfer into the trampoline appears as a branch mnemonic
    // (`jmp` on x86, `b`/`bl` on AArch64) followed by an absolute target. When
    // that target lands in the trampoline region, render it relative to the
    // trampoline base so the snapshot is independent of the trampoline's exact
    // address. Other branches (and same-mnemonic branches that stay in the
    // original code) are left untouched.
    if let Some(trampoline_range) = trampoline_range {
        for (i, token) in tokens.iter().enumerate() {
            if !matches!(*token, "jmp" | "b" | "bl") {
                continue;
            }
            if let Some(target) = tokens
                .get(i + 1)
                .and_then(|t| u64::from_str_radix(t.trim_start_matches("0x"), 16).ok())
                && trampoline_range.contains(&target)
            {
                let offset = target - trampoline_range.start;
                return format!("{address}:\t<trampoline-{token}+0x{offset:x}>");
            }
        }
    }

    // GNU and LLVM objdump differ in whitespace, capitalization, comments,
    // and some numeric formatting. Keep snapshots focused on instructions
    // rather than the disassembler that happened to be available.
    let code_len = tokens
        .iter()
        .take_while(|token| {
            matches!(token.len(), 2 | 8) && token.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .count();
    if code_len != 0 && code_len < tokens.len() {
        let machine_code = tokens[..code_len].join(" ").to_ascii_lowercase();
        let instruction = tokens[code_len..]
            .iter()
            .take_while(|token| !matches!(**token, "//" | "#"))
            .map(|token| {
                let token = token.to_ascii_lowercase();
                if token == "#0" {
                    "#0x0".to_owned()
                } else if let Some(value) = token.strip_prefix("0x")
                    && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    value.to_owned()
                } else {
                    token
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
            .replace(", ", ",");
        return format!("{address}:\t{machine_code}\t{instruction}");
    }

    line.trim_end().to_owned()
}

const HELLO_INPUT_64: &[u8] = include_bytes!("hello");
const HELLO_INPUT_AARCH64: &[u8] = include_bytes!("hello-aarch64");

fn run_snapshot_test(objdump_cmd: &str, input: &[u8], snapshot: &str) {
    let output = litebox_syscall_rewriter::hook_syscalls_in_elf(input, None).unwrap();
    let diff = similar::udiff::unified_diff(
        similar::Algorithm::Myers,
        &objdump(objdump_cmd, input),
        &objdump(objdump_cmd, &output),
        3,
        Some(("original", "rewritten")),
    );

    insta::assert_snapshot!(snapshot, diff);
}

#[test]
fn snapshot_test_hello_world_x86_64() {
    run_snapshot_test("objdump", HELLO_INPUT_64, "hello-diff");
}

#[test]
fn snapshot_test_hello_world_aarch64() {
    // The `hello-aarch64` fixture exercises every rewrite path: an `MSR
    // TPIDR_EL0` write (→ branch into an MSR gate), an `MRS TPIDR_EL0` read
    // (→ branch into an MRS gate), and several `SVC #0`s. Only `MRS XZR,
    // TPIDR_EL0` is left native, and the fixture has none.
    // objdump only disassembles the original `.text`, so the diff captures the
    // call-site rewriting, not the appended trampoline's gate internals.
    //
    // The host objdump usually cannot disassemble AArch64; prefer a cross or
    // LLVM objdump. Skip (rather than fail) when no capable tool is installed,
    // so x86-only dev environments still pass.
    let Some(objdump_cmd) = find_objdump(&["aarch64-linux-gnu-objdump", "llvm-objdump"]) else {
        eprintln!(
            "skipping snapshot_test_hello_world_aarch64: no AArch64-capable objdump \
             (install binutils-aarch64-linux-gnu or llvm)"
        );
        return;
    };
    run_snapshot_test(&objdump_cmd, HELLO_INPUT_AARCH64, "hello-aarch64-diff");
}
