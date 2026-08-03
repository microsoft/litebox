// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs;
use std::path::PathBuf;

include!("src/loader/api_set_mappings.rs");

const MAPPINGS_SOURCE: &str = "src/loader/api_set_mappings.rs";
const OUTPUT_FILE: &str = "api_set_namespace.bin";

fn main() {
    println!("cargo::rerun-if-changed={MAPPINGS_SOURCE}");

    let namespace = litebox_common_windows::loader::build_api_set_namespace(API_SET_MAPPINGS)
        .expect("failed to build API-set namespace");
    let output =
        PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is not set")).join(OUTPUT_FILE);
    fs::write(output, namespace).expect("failed to write API-set namespace");
}
