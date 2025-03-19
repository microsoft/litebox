use litebox::{fs::{FileSystem, Mode}, platform::trivial_providers::ImpossiblePunchthroughProvider};
use litebox_platform_multiplex::{set_platform, Platform};
use litebox_shim_linux::{litebox_fs, set_fs};

fn install_dir(path: &str) {
    litebox_fs()
        .mkdir(path, Mode::RWXU | Mode::RWXG | Mode::RWXO)
        .expect("Failed to create directory");
}

fn init_platform() {
    let platform = unsafe { Platform::new_for_test(ImpossiblePunchthroughProvider {}) };
    set_platform(platform);

    let mut in_mem_fs =
        litebox::fs::in_mem::FileSystem::new(litebox_platform_multiplex::platform());
    in_mem_fs.with_root_privileges(|fs| {
        fs.chmod("/", Mode::RWXU | Mode::RWXG | Mode::RWXO)
            .expect("Failed to set permissions on root");
    });
    set_fs(in_mem_fs);

    install_dir("/lib64");
}

fn main() {
    init_platform();
}