// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{env, fs, path::PathBuf};

const CERT_ENV: &str = "LITEBOX_TA_VERIFY_CERT";
const CERT_OUTPUT_NAME: &str = "ta-signing-cert.der";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rerun-if-env-changed=LITEBOX_LDELF");
    println!("cargo::rerun-if-env-changed={CERT_ENV}");

    let out_dir = env::var_os("OUT_DIR")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "OUT_DIR is not set"))?;
    let out_dir = PathBuf::from(out_dir);
    let ldelf_output = out_dir.join("ldelf.elf");

    if let Some(ldelf) = env::var_os("LITEBOX_LDELF") {
        let ldelf = PathBuf::from(ldelf);
        println!("cargo:rerun-if-changed={}", ldelf.display());
        fs::copy(ldelf, ldelf_output)?;
    } else {
        fs::write(ldelf_output, [])?;
    }

    let cert_output = out_dir.join(CERT_OUTPUT_NAME);

    let Some(source) = env::var_os(CERT_ENV) else {
        fs::write(cert_output, [])?;
        return Ok(());
    };
    let source = PathBuf::from(source);
    println!("cargo::rerun-if-changed={}", source.display());

    let certificate = fs::read(&source)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", source.display()));
    assert!(!certificate.is_empty(), "TA signing certificate is empty");
    use x509_cert::{Certificate, der::Decode};
    Certificate::from_der(&certificate).unwrap_or_else(|error| {
        panic!(
            "{} is not a valid DER-encoded X.509 certificate: {error}",
            source.display()
        )
    });
    fs::write(cert_output, certificate)?;
    Ok(())
}
