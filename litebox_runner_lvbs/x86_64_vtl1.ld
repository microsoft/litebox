OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
    . = 0x0;
    _memory_base = .;

    /*  CONFIG_PHYSICAL_START=0x200000 */
    . = 0x200000;

    /* CONFIG_PHYSICAL_ALIGN=0x200000 */

    .text : ALIGN(0x200000) {
        _text_start = .;
        KEEP(*(.text._start))
        *(.text .text.*)
        *(.got)
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

    /* Relocation section for position-independent execution */
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
    _heap_start = .;
    
    /DISCARD/ :
    {
        *(.rela.debug .rela.debug*)
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
