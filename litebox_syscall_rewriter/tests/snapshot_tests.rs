// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

fn objdump(binary: &[u8]) -> String {
    use std::io::Write;
    use std::process::Command;
    use tempfile::NamedTempFile;

    let trampoline_range = trampoline_range(binary);
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(binary).unwrap();

    // Run objdump on the temporary file and capture the output
    let output = Command::new("objdump")
        .arg("-d")
        .arg(temp_file.path())
        .output()
        .unwrap();

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.contains("/tmp/"))
        .map(|line| normalize_objdump_line(line, trampoline_range.as_ref()))
        .collect::<Vec<_>>()
        .join("\n")
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
    let Some(trampoline_range) = trampoline_range else {
        return line.trim_end().to_owned();
    };
    let Some((address, rest)) = line.split_once(':') else {
        return line.trim_end().to_owned();
    };
    let tokens: Vec<_> = rest.split_whitespace().collect();
    let Some((mnemonic_idx, mnemonic)) = tokens
        .iter()
        .enumerate()
        .find(|(_, token)| !token.chars().all(|ch| ch.is_ascii_hexdigit()))
    else {
        return line.trim_end().to_owned();
    };
    if *mnemonic == "jmp"
        && let Some(target) = tokens
            .get(mnemonic_idx + 1)
            .and_then(|token| u64::from_str_radix(token.trim_start_matches("0x"), 16).ok())
        && trampoline_range.contains(&target)
    {
        let offset = target - trampoline_range.start;
        return format!("{address}:\t<trampoline-jmp+0x{offset:x}>");
    }
    line.trim_end().to_owned()
}

const HELLO_INPUT_64: &[u8] = include_bytes!("hello");

fn run_snapshot_test(input: &[u8], snapshot: &str) {
    let output = litebox_syscall_rewriter::hook_syscalls_in_elf(input, None).unwrap();
    let diff = similar::udiff::unified_diff(
        similar::Algorithm::Myers,
        &objdump(input),
        &objdump(&output),
        3,
        Some(("original", "rewritten")),
    );

    insta::assert_snapshot!(snapshot, diff);
}

#[test]
fn snapshot_test_hello_world_x86_64() {
    run_snapshot_test(HELLO_INPUT_64, "hello-diff");
}
