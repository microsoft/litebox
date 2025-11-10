#!/bin/sh

# sudo qemu-system-x86_64 -cpu host -m 1G -enable-kvm -drive format=raw,file=../target/x86_64-unknown-litebox/debug/bootimage-litebox_runner_optee_on_machine.bin -nographic -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04
# qemu-system-x86_64 -machine q35 -cpu max -m 256M -drive format=raw,file=../target/x86_64-unknown-litebox/debug/bootimage-litebox_runner_optee_on_machine.bin -nographic -no-reboot -d int,guest_errors -device isa-debug-exit,iobase=0xf4,iosize=0x04
qemu-system-x86_64 -machine q35 -cpu max -m 256M -drive format=raw,file=../target/x86_64-unknown-litebox/debug/bootimage-litebox_runner_optee_on_machine.bin -nographic -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04
