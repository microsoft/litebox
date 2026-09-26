// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{env, fs, path::PathBuf};

const KEY_ENV: &str = "LITEBOX_TA_VERIFY_KEY";
const OUTPUT_NAME: &str = "ta-signing-public.der";

fn main() {
    println!("cargo::rerun-if-env-changed={KEY_ENV}");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    let output = out_dir.join(OUTPUT_NAME);

    let Some(source) = env::var_os(KEY_ENV) else {
        fs::write(output, []).expect("failed to create empty TA verification key placeholder");
        return;
    };
    let source = PathBuf::from(source);
    println!("cargo::rerun-if-changed={}", source.display());

    let key = fs::read(&source)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", source.display()));
    assert!(!key.is_empty(), "TA verification key is empty");
    fs::write(output, key).expect("failed to copy TA verification key");
}
