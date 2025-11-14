fn main() {
    let bios_path = env!("BIOS_PATH");

    let mut cmd = std::process::Command::new("qemu-system-x86_64");
    cmd.arg("-machine")
        .arg("q35")
        .arg("-cpu")
        .arg("max")
        .arg("-m")
        .arg("512M")
        .arg("-drive")
        .arg(format!("format=raw,file={bios_path}"))
        .arg("-nographic")
        .arg("-no-reboot");
    let mut child = cmd.spawn().unwrap();
    child.wait().unwrap();
}
