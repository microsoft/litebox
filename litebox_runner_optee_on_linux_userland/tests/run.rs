#![cfg(target_arch = "x86_64")]

fn run(name: &str) {
    let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_optee_on_linux_userland")
        .unwrap_or_else(|_| {
            env!("CARGO_BIN_EXE_litebox_runner_optee_on_linux_userland").to_string()
        });

    let mut command = std::process::Command::new(&binary_path);
    command.args([
        &"tests/ldelf.elf.hooked".to_string(),
        &format!("tests/{name}.elf.hooked"),
        &format!("tests/{name}-cmds.json"),
    ]);
    println!("Running `{command:?}`");
    let status = command.status().unwrap_or_else(|err| {
        panic!("Failed to run litebox_runner_optee_on_linux_userland against {name}.elf: {err}")
    });
    assert!(
        status.success(),
        "failed to run litebox_runner_optee_on_linux_userland against {name}.elf: {status}",
    );
}

#[test]
fn test_runner_hello_ta() {
    run("hello-ta");
}

#[test]
fn test_runner_random_ta() {
    run("random-ta");
}

#[test]
fn test_runner_aes_ta() {
    run("aes-ta");
}

#[test]
fn test_runner_kmpp_ta() {
    run("kmpp-ta");
}
