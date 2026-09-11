// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

#[cfg(target_arch = "x86_64")]
const MULTIARCH_LIB_DIR: &str = "lib/x86_64-linux-gnu";
#[cfg(target_arch = "aarch64")]
const MULTIARCH_LIB_DIR: &str = "lib/aarch64-linux-gnu";

#[must_use]
pub(crate) struct Runner {
    command: std::process::Command,
    dir_path: PathBuf,
    tar_dir: PathBuf,
    unique_name: String,
    cmd_path: PathBuf,
    cmd_args: Vec<OsString>,
    #[cfg(target_os = "linux")]
    managed_proxy_hosts: Vec<OsString>,
    #[cfg(target_os = "linux")]
    use_userland_broker: bool,
    #[cfg(target_os = "linux")]
    in_process_mode: bool,
    has_run: bool,
}

#[allow(
    dead_code,
    reason = "loader.rs and run.rs use different parts of this shared test helper"
)]
impl Runner {
    pub(crate) fn new(target: &Path, unique_name: &str) -> Self {
        Self::new_inner(target, unique_name, true)
    }

    pub(crate) fn new_pre_rewritten(target: &Path, unique_name: &str) -> Self {
        Self::new_inner(target, unique_name, false)
    }

    fn new_inner(target: &Path, unique_name: &str, rewrite_target: bool) -> Self {
        let dir_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));

        let tar_dir = dir_path.join(format!("tar_files_{unique_name}"));
        let dirs_to_create = ["lib64", MULTIARCH_LIB_DIR, "lib32"];
        for dir in dirs_to_create {
            std::fs::create_dir_all(tar_dir.join(dir)).unwrap();
        }
        std::fs::create_dir_all(tar_dir.join("out")).unwrap();

        let target_guest_path = std::path::absolute(target).unwrap();
        let target_dest_path = tar_dir.join(target_guest_path.strip_prefix("/").unwrap());
        if rewrite_target {
            let success = super::rewrite_with_cache(target, &target_dest_path, &[]);
            assert!(success, "failed to run litebox_syscall_rewriter");
        } else {
            std::fs::create_dir_all(target_dest_path.parent().unwrap()).unwrap();
            std::fs::copy(target, &target_dest_path).unwrap();
        }

        let libs = super::find_dependencies(target.to_str().unwrap());
        for file in &libs {
            let file_path = Path::new(file.as_str());
            let dest_path = tar_dir.join(&file[1..]);
            let success = super::rewrite_with_cache(file_path, &dest_path, &[]);
            assert!(
                success,
                "failed to run litebox_syscall_rewriter for {}",
                file_path.to_str().unwrap()
            );
        }

        let binary_path = std::env::var("NEXTEST_BIN_EXE_litebox_runner_linux_userland")
            .unwrap_or_else(|_| env!("CARGO_BIN_EXE_litebox_runner_linux_userland").to_string());

        let mut command = std::process::Command::new(binary_path);
        command.args([
            "--unstable",
            "--env",
            "LD_LIBRARY_PATH=/lib64:/lib32:/lib",
            "--env",
            "HOME=/",
            "--program-from-tar",
        ]);

        Self {
            command,
            dir_path,
            tar_dir,
            cmd_path: target_guest_path,
            cmd_args: Vec::new(),
            #[cfg(target_os = "linux")]
            managed_proxy_hosts: Vec::new(),
            #[cfg(target_os = "linux")]
            use_userland_broker: true,
            #[cfg(target_os = "linux")]
            in_process_mode: false,
            has_run: false,
            unique_name: unique_name.to_owned(),
        }
    }

    pub(crate) fn tar_dir(&self) -> &Path {
        &self.tar_dir
    }

    pub(crate) fn env(&mut self, env: impl AsRef<OsStr>) -> &mut Self {
        self.command.arg("--env").arg(env);
        self
    }

    pub(crate) fn envs(&mut self, envs: impl IntoIterator<Item = impl AsRef<OsStr>>) -> &mut Self {
        for env in envs {
            self.env(env);
        }
        self
    }

    pub(crate) fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.cmd_args.push(arg.as_ref().to_os_string());
        self
    }

    pub(crate) fn args(&mut self, args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> &mut Self {
        for arg in args {
            self.arg(arg);
        }
        self
    }

    pub(crate) fn guest_program_path(&mut self, guest_path: &str) -> &mut Self {
        self.cmd_path = PathBuf::from(guest_path);
        self
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn broker_socket(&mut self, control_socket_path: &Path) -> &mut Self {
        self.use_userland_broker = false;
        self.command
            .arg("--broker-control-channel")
            .arg(control_socket_path);
        self
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    pub(crate) fn use_in_process_runner(&mut self) -> &mut Self {
        self.use_userland_broker = true;
        self.in_process_mode = true;
        self
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn use_userland_broker(&mut self) -> &mut Self {
        self.use_userland_broker = true;
        self
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn allow_proxy_host(&mut self, host: impl AsRef<OsStr>) -> &mut Self {
        self.managed_proxy_hosts.push(host.as_ref().to_os_string());
        self
    }

    pub(crate) fn with_fs_path(&mut self, f: impl FnOnce(&Path)) -> &mut Self {
        f(&self.tar_dir);
        self
    }

    pub(crate) fn run(&mut self) {
        self.run_inner(false);
    }

    #[must_use]
    pub(crate) fn output(&mut self) -> Vec<u8> {
        self.run_inner(true)
    }

    fn prepare_command(&mut self) {
        assert!(!self.has_run);
        self.has_run = true;
        let tar_file = self
            .dir_path
            .join(format!("rootfs_{}.tar", self.unique_name));
        let tar_success = super::create_tar_with_cache(&self.tar_dir, &tar_file, &self.unique_name);
        assert!(tar_success, "failed to create tar file");
        println!("Tar file ready at: {}", tar_file.to_str().unwrap());

        self.command
            .arg("--initial-files")
            .arg(&tar_file)
            .arg(&self.cmd_path)
            .args(&self.cmd_args);

        #[cfg(target_os = "linux")]
        if self.use_userland_broker || !self.managed_proxy_hosts.is_empty() {
            let runner = self.command.get_program().to_os_string();
            let runner_arguments = self
                .command
                .get_args()
                .filter(|argument| *argument != "--unstable")
                .map(OsStr::to_os_string)
                .collect::<Vec<_>>();
            let broker = Path::new(&runner).with_file_name("litebox-broker-userland");
            let proxy = Path::new(&runner).with_file_name("litebox_egress_proxy");
            assert!(
                broker.is_file(),
                "userland broker tests require a workspace build producing {}",
                broker.display()
            );
            if !self.managed_proxy_hosts.is_empty() {
                assert!(
                    proxy.is_file(),
                    "managed proxy tests require a workspace build producing {}",
                    proxy.display()
                );
            }
            let mut command = std::process::Command::new(broker);
            for host in &self.managed_proxy_hosts {
                command.arg("--allow-host").arg(host);
            }
            command.arg("--fs-initial-files").arg(&tar_file);
            if self.in_process_mode {
                command.args(["--unstable", "--in-process-runner"]);
            } else {
                command.arg("--runner").arg(runner);
            }
            command.args(runner_arguments);
            self.command = command;
        }
    }

    fn run_inner(&mut self, capture_stdout: bool) -> Vec<u8> {
        self.prepare_command();
        self.command.stderr(std::process::Stdio::inherit());
        if !capture_stdout {
            self.command.stdout(std::process::Stdio::inherit());
        }
        println!("Running `{:?}`", self.command);
        let output = self
            .command
            .output()
            .expect("Failed to run litebox_runner_linux_userland");
        assert!(
            output.status.success(),
            "failed to run litebox_runner_linux_userland: {}",
            output.status
        );
        output.stdout
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn spawn_with_stdio(
        &mut self,
        stdin: std::process::Stdio,
        stdout: std::process::Stdio,
        stderr: std::process::Stdio,
    ) -> std::process::Child {
        self.prepare_command();
        self.command.stdin(stdin).stdout(stdout).stderr(stderr);
        println!("Running `{:?}`", self.command);
        self.command
            .spawn()
            .expect("Failed to spawn litebox_runner_linux_userland")
    }
}
