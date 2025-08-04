use clap::Parser as _;
use litebox_runner_linux_on_windows_userland::CliArgs;

fn main() -> anyhow::Result<()> {
    litebox_runner_linux_on_windows_userland::run(CliArgs::parse())
}

