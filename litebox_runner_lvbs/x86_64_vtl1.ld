OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
    . = 0x8000000;
    _memory_base = .;

    /*  CONFIG_PHYSICAL_START=0x8200000 */
    . = 0x8200000;

    /* CONFIG_PHYSICAL_ALIGN=0x200000 */

    .text : ALIGN(0x200000) {
        _text_start = .;
        KEEP(*(.text._start))
        *(.text .text.*)
        *(.got)

        . = ALIGN(0x1000);
        _hypercall_page_start = .;
        KEEP(*(.hypercall_page))
        _hypercall_page_end = .;

        _text_end = .;
    }
    .data : ALIGN(0x200000) { 
        _data_start = .;
        *(.rodata .rodata.*)
        *(.data .data.*)
        _data_end = .;

        . = ALIGN(0x1000);
        _bss_start = .;
        *(.bss .bss.*)
        _bss_end = .;
    }

    . = ALIGN(0x1000);
    _heap_start = .;
    
    /DISCARD/ :
    {
        *(.dynamic) *(.dynsym) *(.dynstr) *(.dynbss)
        *(.eh_frame .eh_frame*)
        *(.comment*)
        *(.gnu.hash*)
        *(.hash)
        *(.note.*)
    }
    .debug :
    {
        *(.debug .debug* )
    }
}
