#!/bin/sh

# qemu-system-x86_64 -machine q35 -cpu max -m 256M -drive format=raw,file=../target/x86_64-unknown-litebox/debug/bios.img -nographic -no-reboot -d int,guest_errors -device isa-debug-exit,iobase=0xf4,iosize=0x04
sudo qemu-system-x86_64 -machine q35 -cpu max -enable-kvm -m 256M -drive format=raw,file=../target/x86_64-unknown-litebox/debug/bios.img -nographic -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04
