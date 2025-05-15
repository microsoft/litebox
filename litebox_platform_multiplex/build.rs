fn main() {
    let out_path =
        std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("platform_type.rs");

    let platform_type = if cfg!(feature = "platform_linux_userland") {
        "pub type Platform = litebox_platform_linux_userland::LinuxUserland;"
    } else if cfg!(feature = "platform_lvbs") {
        "pub type Platform = litebox_platform_lvbs::host::LvbsLinuxKernel;"
    } else {
        panic!("No platform specified.")
    };

    std::fs::write(out_path, platform_type).expect("Couldn't write file!");
}
