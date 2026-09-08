// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

mod cache;
mod common;
#[path = "common/broker.rs"]
mod test_broker;

use std::ffi::CString;

use litebox_platform_linux_userland::LinuxUserland as Platform;

struct TestLauncher {
    platform: &'static Platform,
    shim_builder: litebox_shim_linux::LinuxShimBuilder<Platform>,
    fs: litebox_shim_linux::DefaultFS<Platform>,
}

impl TestLauncher {
    fn init_platform(
        tar_data: &'static [u8],
        initial_files: &[&str],
        installed_files: &[(&str, Vec<u8>)],
    ) -> Self {
        let platform = Platform::new();
        let mode = litebox_broker_core::fs::Mode::RWXU
            | litebox_broker_core::fs::Mode::RWXG
            | litebox_broker_core::fs::Mode::RWXO;
        let mut directories = std::collections::BTreeSet::new();
        for path in initial_files {
            directories.extend(
                std::path::Path::new(path)
                    .parent()
                    .into_iter()
                    .flat_map(std::path::Path::ancestors)
                    .filter(|path| {
                        *path != std::path::Path::new("/") && !path.as_os_str().is_empty()
                    })
                    .map(std::path::Path::to_path_buf),
            );
        }
        for (path, _) in installed_files {
            directories.extend(
                std::path::Path::new(path)
                    .parent()
                    .into_iter()
                    .flat_map(std::path::Path::ancestors)
                    .filter(|path| {
                        *path != std::path::Path::new("/") && !path.as_os_str().is_empty()
                    })
                    .map(std::path::Path::to_path_buf),
            );
        }
        let mut directories: Vec<_> = directories.into_iter().collect();
        directories.sort_by_key(|path| path.components().count());
        let mut entries = vec![(
            "/".to_string(),
            litebox_broker_core::fs::in_mem::InitialNode::Directory {
                mode,
                owner: litebox_broker_core::fs::UserInfo::ROOT,
            },
        )];
        entries.extend(directories.into_iter().map(|path| {
            (
                path.to_string_lossy().into_owned(),
                litebox_broker_core::fs::in_mem::InitialNode::Directory {
                    mode,
                    owner: litebox_broker_core::fs::UserInfo::ROOT,
                },
            )
        }));
        entries.extend(initial_files.iter().map(|path| {
            (
                (*path).to_string(),
                litebox_broker_core::fs::in_mem::InitialNode::File {
                    mode,
                    owner: litebox_broker_core::fs::UserInfo::ROOT,
                    data: std::fs::read(path).unwrap().into(),
                },
            )
        }));
        entries.extend(installed_files.iter().map(|(path, data)| {
            (
                (*path).to_string(),
                litebox_broker_core::fs::in_mem::InitialNode::File {
                    mode,
                    owner: litebox_broker_core::fs::UserInfo::ROOT,
                    data: data.clone().into(),
                },
            )
        }));
        let in_mem = litebox_broker_core::fs::in_mem::InMem::<Platform>::new_initialized(entries);
        let tar_data = if tar_data.is_empty() {
            litebox_broker_core::fs::tar_ro::EMPTY_TAR_FILE.into()
        } else {
            tar_data.into()
        };
        let backend = litebox_broker_core::fs::composer::Composer::builder()
            .mount_nestable("/", |allocators| {
                litebox_broker_core::fs::overlay::Overlay::<Platform>::new(
                    in_mem,
                    litebox_broker_core::fs::tar_ro::TarRo::new(tar_data, allocators.next()),
                    allocators.next(),
                )
            })
            .mount("/dev", litebox_broker_core::fs::devices::Devices::new)
            .build()
            .unwrap();
        let litebox = test_broker::litebox(platform, backend);
        let shim_builder =
            litebox_shim_linux::LinuxShimBuilder::new_with_litebox(platform, litebox);
        let fs = shim_builder.brokered_fs();
        Self {
            platform,
            shim_builder,
            fs,
        }
    }

    fn test_load_exec_common(self, executable_path: &str) {
        let argv = vec![
            CString::new(executable_path).unwrap(),
            CString::new("hello").unwrap(),
        ];
        let envp = vec![
            CString::new("PATH=/bin").unwrap(),
            CString::new("HOME=/").unwrap(),
        ];
        let fs = std::sync::Arc::new(self.fs);
        let shim = self.shim_builder.build();
        let program = shim
            .load_program(fs, self.platform.init_task(), executable_path, argv, envp)
            .unwrap();
        unsafe {
            litebox_platform_linux_userland::run_thread(
                program.entrypoints,
                &mut litebox_common_linux::PtRegs::default(),
            );
        }
        assert_eq!(
            program.process.wait(),
            0,
            "process exited with non-zero code"
        );
    }
}

#[test]
fn test_load_exec_dynamic() {
    let path = common::compile("./tests/hello.c", "hello_dylib", false, false);

    let files_to_install = common::find_dependencies(path.to_str().unwrap());

    let executable_path = "/hello_dylib";
    let executable_data = std::fs::read(path).unwrap();

    let launcher = TestLauncher::init_platform(
        &[],
        &files_to_install
            .iter()
            .map(std::string::String::as_str)
            .collect::<Vec<_>>(),
        &[(executable_path, executable_data)],
    );
    launcher.test_load_exec_common(executable_path);
}

#[test]
fn test_load_exec_static() {
    let path = common::compile("./tests/hello.c", "hello_exec", true, false);

    let executable_path = "/hello_exec";
    let executable_data = std::fs::read(path).unwrap();

    let launcher = TestLauncher::init_platform(&[], &[], &[(executable_path, executable_data)]);

    launcher.test_load_exec_common(executable_path);
}

const HELLO_WORLD_NOLIBC: &str = r#"
// gcc tests/test.c -o test -static -nostdlib (-m32)
#if defined(__x86_64__)
int write(int fd, const char *buf, int length)
{
    int ret;

    asm("mov %1, %%eax\n\t"
        "mov %2, %%edi\n\t"
        "mov %3, %%rsi\n\t"
        "mov %4, %%edx\n\t"
        "syscall\n\t"
        "mov %%eax, %0"
        : "=r" (ret)
        : "i" (1), // x86-64 SYS_write
          "r" (fd),
          "r" (buf),
          "r" (length)
        : "%eax", "%edi", "%rsi", "%edx");

    return ret;
}

_Noreturn void exit_group(int code)
{
    for (;;) {
        asm("mov %0, %%eax\n\t"
            "mov %1, %%edi\n\t"
            "syscall\n\t"
            :
            : "i" (231), // x86-64 SYS_exit_group
              "r" (code)
            : "%eax", "%edi");
    }
}
#elif defined(__i386__)
int write(int fd, const char *buf, int length)
{
    int ret;

    asm("mov %1, %%eax\n\t"
        "mov %2, %%ebx\n\t"
        "mov %3, %%ecx\n\t"
        "mov %4, %%edx\n\t"
        "int $0x80\n\t"
        "mov %%eax, %0"
        : "=r" (ret)
        : "i" (4), // i386 SYS_write
          "g" (fd),
          "g" (buf),
          "g" (length)
        : "%eax", "%ebx", "%ecx", "%edx");

    return ret;
}
_Noreturn void exit_group(int code)
{
    for (;;) {
        asm("mov %0, %%eax\n\t"
            "mov %1, %%ebx\n\t"
            "int $0x80\n\t"
            :
            : "i" (252), // i386 SYS_exit_group
              "r" (code)
            : "%eax", "%ebx");
    }
}
#elif defined(__aarch64__)
int write(int fd, const char *buf, int length)
{
    register long x8 asm("x8") = 64; // AArch64 SYS_write
    register long x0 asm("x0") = fd;
    register long x1 asm("x1") = (long)buf;
    register long x2 asm("x2") = length;

    asm volatile("svc #0"
        : "+r" (x0)
        : "r" (x8), "r" (x1), "r" (x2)
        : "memory");

    return (int)x0;
}

_Noreturn void exit_group(int code)
{
    for (;;) {
        register long x8 asm("x8") = 94; // AArch64 SYS_exit_group
        register long x0 asm("x0") = code;

        asm volatile("svc #0"
            :
            : "r" (x8), "r" (x0)
            : "memory");
    }
}
#else
#error "Unsupported architecture"
#endif

int main() {
    // use write to print a string
    write(1, "Hello, World!\n", 14);
    return 0;
}

void _start() {
    exit_group(main());
}
"#;

#[test]
fn test_syscall_rewriter() {
    let dir_path = env!("CARGO_TARGET_TMPDIR").to_string();
    let src_path = std::path::Path::new(dir_path.as_str()).join("hello_exec_nolibc.c");
    std::fs::write(src_path.clone(), HELLO_WORLD_NOLIBC).unwrap();
    let path = std::path::Path::new(dir_path.as_str()).join("hello_exec_nolibc");
    common::compile(
        src_path.to_str().unwrap(),
        path.to_str().unwrap(),
        true,
        true,
    );

    // rewrite the hello_exec_nolibc
    let hooked_path = std::path::Path::new(dir_path.as_str()).join("hello_exec_nolibc.hooked");
    let _ = std::fs::remove_file(hooked_path.clone());
    let rewrite_success = common::rewrite_with_cache(&path, &hooked_path, &[]);
    assert!(rewrite_success, "failed to run syscall rewriter");

    let executable_path = "/hello_exec_nolibc.hooked";
    let executable_data = std::fs::read(hooked_path).unwrap();

    let launcher = TestLauncher::init_platform(&[], &[], &[(executable_path, executable_data)]);
    launcher.test_load_exec_common(executable_path);
}
