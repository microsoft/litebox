#[cfg(target_arch = "x86_64")]
#[test]
fn test_runner_hello_ta() {
    let output = std::process::Command::new("cargo")
        .args(["build", "-p", "litebox_runner_optee_on_linux_userland"])
        .output()
        .expect("Failed to build litebox_runner_optee_on_linux_userland");
    assert!(
        output.status.success(),
        "failed to build litebox_runner_optee_on_linux_userland {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );

    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "-p",
            "litebox_runner_optee_on_linux_userland",
            "--",
            "tests/hello-ta.elf.hooked",
            "tests/hello-ta-cmds.json",
        ])
        .output()
        .expect("Failed to run litebox_runner_optee_on_linux_userland against hello-ta.elf {:?}");
    assert!(
        output.status.success(),
        "failed to run litebox_runner_optee_on_linux_userland against hello-ta.elf {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_runner_random_ta() {
    let output = std::process::Command::new("cargo")
        .args(["build", "-p", "litebox_runner_optee_on_linux_userland"])
        .output()
        .expect("Failed to build litebox_runner_optee_on_linux_userland");
    assert!(
        output.status.success(),
        "failed to build litebox_runner_optee_on_linux_userland {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );

    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "-p",
            "litebox_runner_optee_on_linux_userland",
            "--",
            "tests/random-ta.elf.hooked",
            "tests/random-ta-cmds.json",
        ])
        .output()
        .expect("Failed to run litebox_runner_optee_on_linux_userland against random-ta.elf {:?}");
    assert!(
        output.status.success(),
        "failed to run litebox_runner_optee_on_linux_userland against random-ta.elf {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_runner_aes_ta() {
    let output = std::process::Command::new("cargo")
        .args(["build", "-p", "litebox_runner_optee_on_linux_userland"])
        .output()
        .expect("Failed to build litebox_runner_optee_on_linux_userland");
    assert!(
        output.status.success(),
        "failed to build litebox_runner_optee_on_linux_userland {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );

    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "-p",
            "litebox_runner_optee_on_linux_userland",
            "--",
            "tests/aes-ta.elf.hooked",
            "tests/aes-ta-cmds.json",
        ])
        .output()
        .expect("Failed to run litebox_runner_optee_on_linux_userland against aes-ta.elf {:?}");
    assert!(
        output.status.success(),
        "failed to run litebox_runner_optee_on_linux_userland against aes-ta.elf {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_runner_kmpp_ta() {
    let output = std::process::Command::new("cargo")
        .args(["build", "-p", "litebox_runner_optee_on_linux_userland"])
        .output()
        .expect("Failed to build litebox_runner_optee_on_linux_userland");
    assert!(
        output.status.success(),
        "failed to build litebox_runner_optee_on_linux_userland {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );

    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "-p",
            "litebox_runner_optee_on_linux_userland",
            "--",
            "tests/kmpp-ta.elf.hooked",
            "tests/kmpp-ta-cmds.json",
        ])
        .output()
        .expect("Failed to run litebox_runner_optee_on_linux_userland against kmpp-ta.elf {:?}");
    assert!(
        output.status.success(),
        "failed to run litebox_runner_optee_on_linux_userland against kmpp-ta.elf {:?}",
        std::str::from_utf8(output.stderr.as_slice()).unwrap()
    );
}
