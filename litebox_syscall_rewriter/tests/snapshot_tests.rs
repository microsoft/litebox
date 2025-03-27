fn objdump(binary: &[u8]) -> String {
    use std::io::Write;
    use std::process::Command;
    use tempfile::NamedTempFile;

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
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

const HELLO_INPUT: &[u8] = include_bytes!("hello");

#[test]
fn snapshot_test_hello_world() {
    let output = litebox_syscall_rewriter::hook_syscalls_in_elf(HELLO_INPUT, None).unwrap();
    let diff = similar::udiff::unified_diff(
        similar::Algorithm::Myers,
        &objdump(HELLO_INPUT),
        &objdump(&output),
        3,
        Some(("original", "rewritten")),
    );
    insta::assert_snapshot!("hello-diff", diff);
}
