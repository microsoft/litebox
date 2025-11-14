use std::path::PathBuf;

#[cfg(debug_assertions)]
const KERNEL_PATH: &str =
    "../target/x86_64-unknown-litebox/debug/litebox_runner_optee_on_hypervisor";
#[cfg(not(debug_assertions))]
const KERNEL_PATH: &str =
    "../target/x86_64-unknown-litebox/release/litebox_runner_optee_on_hypervisor";

fn main() {
    let kernel = PathBuf::from(KERNEL_PATH);

    #[cfg(debug_assertions)]
    let bios_path = PathBuf::from("../target/x86_64-unknown-litebox/debug/bios.img");
    #[cfg(not(debug_assertions))]
    let bios_path = PathBuf::from("../target/x86_64-unknown-litebox/release/bios.img");
    bootloader::BiosBoot::new(&kernel)
        .create_disk_image(&bios_path)
        .unwrap();

    println!("cargo:rustc-env=BIOS_PATH={}", bios_path.display());
}
