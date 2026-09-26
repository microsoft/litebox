/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS {
    . = 0;
    _memory_base = .;
    . = 0x200000;
    .text : ALIGN(0x1000) {
        _text_start = .;
        KEEP(*(.text._start))
        *(.text .text.*)
        . = ALIGN(0x1000);
        _text_end = .;
    }
    /* QEMU needs a PT_NOTE containing XEN_ELFNOTE_PHYS32_ENTRY. */
    .note : ALIGN(4) { KEEP(*(.note.Xen)) }
    .rodata : ALIGN(0x1000) {
        *(.rodata .rodata.*)
        . = ALIGN(4);
        __start_ex_table = .;
        KEEP(*(ex_table))
        __stop_ex_table = .;
    }
    .data : ALIGN(0x1000) {
        *(.data .data.*)
        *(.got .got.*)
    }
    .bss (NOLOAD) : ALIGN(0x1000) {
        *(.bss .bss.*)
        *(COMMON)
    }
    .rela.dyn : ALIGN(8) {
        _rela_start = .;
        *(.rela .rela.*)
        _rela_end = .;
    }
    . = ALIGN(0x1000);
    _image_end = .;
    ASSERT(_start == 0x200000, "PVH entry must match the boot note")
    ASSERT(_image_end <= 0x1000000, "image overlaps PVH boot scratch")

    /* Fixed-address page tables/GDT and 512 KiB boot scratch, as in boot.S.
       Reserve in a PT_LOAD so QEMU won't place boot payloads here. */
    . = 0x1000000;
    .boot_scratch (NOLOAD) : { . += 0x80000; }
    _heap_start = .;
    ASSERT(_heap_start == 0x1080000, "scratch layout disagrees with boot.S")

    /DISCARD/ : {
        *(.dynamic .dynsym .dynstr .dynbss)
        *(.eh_frame .eh_frame_hdr)
        *(.comment .note.GNU-stack .gnu.hash .hash)
    }
}
