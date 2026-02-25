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

    /* Hyper-V hypercall code page: Hyper-V sets up executable code here at runtime
       via wrmsr to HV_X64_MSR_HYPERCALL. Call to this page results in a hypercall.
       Placed in its own page-aligned section so it can be marked executable in
       the page tables (DEP). */
    .hvcall_page : ALIGN(0x1000) {
        _hvcall_page_start = .;
        KEEP(*(.hvcall_page))
        . = _hvcall_page_start + 0x1000;
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
