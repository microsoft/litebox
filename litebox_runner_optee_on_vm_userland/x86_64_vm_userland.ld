/* Static PIE linked at 0: the kernel loads it at its runner-image area and
 * applies its relative relocations. Requirements (see
 * `litebox_shim_vm_kernel::loader`): no page mixes permissions, and the image
 * fits the area. */
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
    . = 0;

    .text : ALIGN(0x1000) {
        KEEP(*(.text._start))
        *(.text .text.*)
    }

    /* The only `syscall` instruction; the kernel accepts calls only here. */
    .kabi_gate : ALIGN(0x1000) {
        KEEP(*(.kabi_gate))
    }

    .rodata : ALIGN(0x1000) {
        *(.rodata .rodata.*)
        . = ALIGN(4);
        __start_ex_table = .;
        KEEP(*(ex_table))
        __stop_ex_table = .;
    }

    /* Read by the kernel's loader. */
    .rela.dyn : ALIGN(8) { *(.rela.*) }
    .dynsym : { *(.dynsym) }
    .dynstr : { *(.dynstr) }
    .gnu.hash : { *(.gnu.hash) }
    .hash : { *(.hash) }

    .data : ALIGN(0x1000) {
        *(.data.rel.ro .data.rel.ro.*)
        *(.data .data.*)
        *(.got .got.*)
    }

    .dynamic : { *(.dynamic) }

    .bss (NOLOAD) : ALIGN(0x1000) {
        *(.bss .bss.*)
        *(COMMON)
    }

    . = ALIGN(0x1000);
    _image_end = .;
    ASSERT(_image_end <= 0x10000000, "the runner image exceeds the kernel's runner-image area")

    /DISCARD/ : {
        *(.eh_frame .eh_frame*)
        *(.comment*)
        *(.note*)
    }
}
