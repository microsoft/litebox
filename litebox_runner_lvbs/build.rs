// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=LITEBOX_LDELF");

    let out_dir = std::env::var_os("OUT_DIR")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "OUT_DIR is not set"))?;
    let output = PathBuf::from(out_dir).join("ldelf.elf");

    if let Some(ldelf) = std::env::var_os("LITEBOX_LDELF") {
        let ldelf = PathBuf::from(ldelf);
        println!("cargo:rerun-if-changed={}", ldelf.display());
        std::fs::copy(ldelf, output)?;
    } else {
        std::fs::write(output, [])?;
    }

    Ok(())
}
