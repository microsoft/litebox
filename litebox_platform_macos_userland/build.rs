// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::env;
use std::error::Error;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn xcrun<I, S>(arguments: I) -> Result<Output, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("/usr/bin/xcrun").args(arguments).output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "xcrun failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into())
    }
}

fn compile(
    source: &Path,
    object: &Path,
    sdk: &str,
    deployment_target: &str,
) -> Result<(), Box<dyn Error>> {
    let minimum_version = format!("-mmacosx-version-min={deployment_target}");
    xcrun([
        OsStr::new("--sdk"),
        OsStr::new("macosx"),
        OsStr::new("clang"),
        OsStr::new("-arch"),
        OsStr::new("arm64"),
        OsStr::new("-isysroot"),
        OsStr::new(sdk),
        OsStr::new(&minimum_version),
        OsStr::new("-fPIC"),
        OsStr::new("-std=c17"),
        OsStr::new("-Wall"),
        OsStr::new("-Wextra"),
        OsStr::new("-Werror"),
        OsStr::new("-c"),
        source.as_os_str(),
        OsStr::new("-o"),
        object.as_os_str(),
    ])?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=src/hvf_sdk.c");
    println!("cargo:rerun-if-changed=src/hvf_monitor.S");
    for variable in [
        "MACOSX_DEPLOYMENT_TARGET",
        "DEVELOPER_DIR",
        "SDKROOT",
        "TOOLCHAINS",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }

    if env::var("CARGO_CFG_TARGET_OS")? != "macos"
        || env::var("CARGO_CFG_TARGET_ARCH")? != "aarch64"
    {
        return Ok(());
    }

    let sdk = String::from_utf8(xcrun(["--sdk", "macosx", "--show-sdk-path"])?.stdout)?;
    let sdk = sdk.trim();
    let deployment_target =
        env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "11.0".to_owned());
    let out = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is not set")?);
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("CARGO_MANIFEST_DIR is not set")?);
    let sdk_object = out.join("hvf_sdk.o");
    let monitor_object = out.join("hvf_monitor.o");
    let archive = out.join("liblitebox_hvf_sdk.a");

    compile(
        &manifest.join("src/hvf_sdk.c"),
        &sdk_object,
        sdk,
        &deployment_target,
    )?;
    compile(
        &manifest.join("src/hvf_monitor.S"),
        &monitor_object,
        sdk,
        &deployment_target,
    )?;
    xcrun([
        OsStr::new("--sdk"),
        OsStr::new("macosx"),
        OsStr::new("ar"),
        OsStr::new("rcs"),
        archive.as_os_str(),
        sdk_object.as_os_str(),
        monitor_object.as_os_str(),
    ])?;

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=litebox_hvf_sdk");
    println!("cargo:rustc-link-lib=framework=Hypervisor");
    Ok(())
}
