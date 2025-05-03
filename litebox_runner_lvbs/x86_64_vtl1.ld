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
        *(.text._start)
        *(.text.*)
        *(.got)
    }
    .data : ALIGN(0x200000) { 
        *(.rodata .rodata.*)
        *(.data .data.*)
        . = ALIGN(0x1000);
        _hypercall_page = . ;
        . = ALIGN(0x1000);
        _ta_data_start = . ;
        KEEP(*(.binary_data))
        _ta_data_end = . ;
    }
    .rela : ALIGN(0x1000) {
        *(.rela .rela.* )
    }
    .bss : ALIGN(0x1000) {
        *(.bss .bss.*)
    }
    
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
