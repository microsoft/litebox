/* Linked at 0 as PIE; the boot stub (src/boot.rs) relocates the image to
 * its KERNEL_OFFSET alias. */
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
    . = 0x0;
    _memory_base = .;

    . = 0x200000;

    /* `_start` must be at PVH_ENTRY_ADDR (src/boot.rs); see the ASSERT. */
    .text : ALIGN(0x200000) {
        _text_start = .;
        KEEP(*(.text._start))
        *(.text .text.*)
        *(.got)
        _text_end = .;
    }

    /* PVH boot note (XEN_ELFNOTE_PHYS32_ENTRY). */
    .note : ALIGN(4) {
        KEEP(*(.note.Xen))
    }

    .data : ALIGN(0x200000) {
        _data_start = .;
        *(.rodata .rodata.*)
        *(.data .data.*)

        /* Exception table for fallible memory operations (memcpy_fallible, etc.) */
        . = ALIGN(4);
        __start_ex_table = .;
        KEEP(*(ex_table))
        __stop_ex_table = .;

        _data_end = .;

        . = ALIGN(0x1000);
        _bss_start = .;
        *(.bss .bss.*)
        _bss_end = .;
    }

    .rela.dyn : ALIGN(0x200000) {
        _rela_start = .;
        *(.rela.text .rela.text*)
        *(.rela.data .rela.data*)
        *(.rela.rodata .rela.rodata*)
        *(.rela.got .rela.got*)
        *(.rela.bss .rela.bss*)
        *(.rela.dyn)
        _rela_end = .;
    }

    . = ALIGN(0x1000);
    _image_end = .;

    ASSERT(_start == 0x200000, "_start is not at PVH_ENTRY_ADDR (0x200000)")

    /* Must match BOOT_SCRATCH_BASE in src/boot.rs. In use until the heap is
       seeded, so the heap starts above it. */
    ASSERT(_image_end <= 0x1000000, "image has grown into the boot scratch region at 0x1000000")
    . = 0x1000000;
    _boot_scratch_start = .;
    .boot_scratch (NOLOAD) : {
        . = . + 0x80000;
    }
    _boot_scratch_end = .;

    . = ALIGN(0x1000);
    _heap_start = .;

    /DISCARD/ :
    {
        *(.rela.debug .rela.debug*)
        *(.dynamic) *(.dynsym) *(.dynstr) *(.dynbss)
        *(.eh_frame .eh_frame*)
        *(.comment*)
        *(.gnu.hash*)
        *(.hash)
    }
    .debug :
    {
        *(.debug .debug* )
    }
}
