// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(target_arch = "x86_64")]

use std::path::PathBuf;

fn rewrite_binary(input: &str, output: &str) {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let status = std::process::Command::new(&cargo)
        .args([
            "run",
            "-p",
            "litebox_syscall_rewriter",
            "--",
            input,
            "-o",
            output,
        ])
        .status()
        .unwrap_or_else(|err| panic!("Failed to run litebox_syscall_rewriter on {input}: {err}"));

    assert!(
        status.success(),
        "litebox_syscall_rewriter failed on {input}: {status}"
    );
}

fn run(name: &str) {
    let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_optee_on_linux_userland")
        .unwrap_or_else(|_| {
            env!("CARGO_BIN_EXE_litebox_runner_optee_on_linux_userland").to_string()
        });

    // Create a temporary directory for the hooked binaries
    let temp_dir = std::env::temp_dir().join(format!("litebox_test_{name}_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

    let ldelf_input = PathBuf::from("tests/ldelf.elf");
    let ldelf_hooked = temp_dir.join("ldelf.elf.hooked");
    let ta_input = PathBuf::from(format!("tests/{name}.elf"));
    let ta_hooked = temp_dir.join(format!("{name}.elf.hooked"));

    // Generate hooked binaries on the fly
    rewrite_binary(
        ldelf_input.to_str().unwrap(),
        ldelf_hooked.to_str().unwrap(),
    );
    rewrite_binary(ta_input.to_str().unwrap(), ta_hooked.to_str().unwrap());

    let cmds_path = format!("tests/{name}-cmds.json");

    let mut command = std::process::Command::new(&binary_path);
    command.args([
        ldelf_hooked.to_str().unwrap(),
        ta_hooked.to_str().unwrap(),
        &cmds_path,
    ]);
    println!("Running `{command:?}`");
    let status = command.status().unwrap_or_else(|err| {
        panic!("Failed to run litebox_runner_optee_on_linux_userland against {name}.elf: {err}")
    });

    // Clean up temporary files
    let _ = std::fs::remove_dir_all(&temp_dir);

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

/// Extract the TA UUID from a raw ELF binary's `.ta_head` section and
/// return it as a standard string.
fn extract_ta_uuid_from_elf(elf_path: &str) -> String {
    let data = std::fs::read(elf_path).expect("Failed to read ELF file");
    let ta_head = litebox_common_optee::parse_ta_head(&data)
        .expect("Failed to parse .ta_head section from ELF");
    let uuid = ta_head.uuid;
    let r = &uuid.clock_seq_and_node;
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid.time_low,
        uuid.time_mid,
        uuid.time_hi_and_version,
        r[0],
        r[1],
        r[2],
        r[3],
        r[4],
        r[5],
        r[6],
        r[7]
    )
}

const SIGN_ENCRYPT_URL: &str =
    "https://raw.githubusercontent.com/OP-TEE/optee_os/refs/heads/master/scripts/sign_encrypt.py";

/// Download `sign_encrypt.py` from the upstream OP-TEE repository into `dest`.
fn download_sign_encrypt_py(dest: &std::path::Path) {
    let status = std::process::Command::new("curl")
        .args(["-fsSL", "-o", dest.to_str().unwrap(), SIGN_ENCRYPT_URL])
        .status()
        .expect("Failed to run curl to download sign_encrypt.py");
    assert!(
        status.success(),
        "Failed to download sign_encrypt.py from {SIGN_ENCRYPT_URL}: {status}"
    );
}

/// Run a signed TA test.
fn run_signed(name: &str, algo: &str) {
    let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_optee_on_linux_userland")
        .unwrap_or_else(|_| {
            env!("CARGO_BIN_EXE_litebox_runner_optee_on_linux_userland").to_string()
        });

    let test_label = format!(
        "{name}_signed_{}",
        algo.to_lowercase().replace("tee_alg_", "")
    );
    let temp_dir =
        std::env::temp_dir().join(format!("litebox_test_{test_label}_{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

    // Step 1: Generate RSA-2048 private key
    let key_path = temp_dir.join("test_key.pem");
    let status = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key_path.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to run openssl genpkey");
    assert!(status.success(), "openssl genpkey failed: {status}");

    // Step 2: Rewrite syscalls on ldelf and TA ELF
    let ldelf_input = PathBuf::from("tests/ldelf.elf");
    let ldelf_hooked = temp_dir.join("ldelf.elf.hooked");
    let ta_input = PathBuf::from(format!("tests/{name}.elf"));
    let ta_hooked = temp_dir.join(format!("{name}.elf.hooked"));

    rewrite_binary(
        ldelf_input.to_str().unwrap(),
        ldelf_hooked.to_str().unwrap(),
    );
    rewrite_binary(ta_input.to_str().unwrap(), ta_hooked.to_str().unwrap());

    // Step 3: Extract UUID from the hooked ELF
    let uuid_str = extract_ta_uuid_from_elf(ta_hooked.to_str().unwrap());
    println!("TA UUID: {uuid_str}");

    // Step 4: Download sign_encrypt.py and sign the hooked ELF
    let sign_script = temp_dir.join("sign_encrypt.py");
    download_sign_encrypt_py(&sign_script);

    let signed_ta_path = temp_dir.join(format!("{name}.ta"));
    let status = std::process::Command::new("python3")
        .args([
            sign_script.to_str().unwrap(),
            "sign-enc",
            "--uuid",
            &uuid_str,
            "--ta-version",
            "1",
            "--in",
            ta_hooked.to_str().unwrap(),
            "--out",
            signed_ta_path.to_str().unwrap(),
            "--key",
            key_path.to_str().unwrap(),
            "--algo",
            algo,
        ])
        .status()
        .expect("Failed to run sign_encrypt.py");
    assert!(status.success(), "sign_encrypt.py failed: {status}");

    // Verify the signed TA file was created and starts with SHDR magic
    let signed_data = std::fs::read(&signed_ta_path).expect("Failed to read signed TA");
    assert!(signed_data.len() > 20, "Signed TA file too small");
    let magic = u32::from_le_bytes(signed_data[0..4].try_into().unwrap());
    assert_eq!(magic, 0x4f545348, "Signed TA should start with SHDR magic");

    // Step 5: Extract the RSA public key in DER format for verification
    let pub_key_der = temp_dir.join("test_key_pub.der");
    let status = std::process::Command::new("openssl")
        .args([
            "rsa",
            "-in",
            key_path.to_str().unwrap(),
            "-pubout",
            "-outform",
            "DER",
            "-RSAPublicKey_out",
            "-out",
            pub_key_der.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to run openssl rsa");
    assert!(
        status.success(),
        "openssl rsa public key export failed: {status}"
    );

    // Step 6: Run the signed TA through the runner with the verification key
    let cmds_path = format!("tests/{name}-cmds.json");
    let mut command = std::process::Command::new(&binary_path);
    command.args([
        ldelf_hooked.to_str().unwrap(),
        signed_ta_path.to_str().unwrap(),
        &cmds_path,
        "--verification-key",
        pub_key_der.to_str().unwrap(),
    ]);
    println!("Running signed TA test ({algo}): `{command:?}`");
    let status = command.status().unwrap_or_else(|err| {
        panic!(
            "Failed to run litebox_runner_optee_on_linux_userland against signed {name}.ta: {err}"
        )
    });

    let _ = std::fs::remove_dir_all(&temp_dir);

    assert!(
        status.success(),
        "failed to run litebox_runner_optee_on_linux_userland against signed {name}.ta ({algo}): {status}",
    );
}

#[test]
fn test_runner_hello_ta_signed_pkcs1v15() {
    run_signed("hello-ta", "TEE_ALG_RSASSA_PKCS1_V1_5_SHA256");
}

#[test]
fn test_runner_hello_ta_signed_pss() {
    run_signed("hello-ta", "TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256");
}
