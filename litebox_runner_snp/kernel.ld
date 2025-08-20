OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)
SECTIONS
{
	. = 0x0;
    .head.text : {
        _head = . ;
        KEEP(*(.head.text))
        _ehead = . ;
    }
	.text   :
	{
		*(.text .text.*)
		*(.got)
	}
	. = ALIGN(0x1000);
	.data	: 
	{ 
		*(.rodata .rodata.*)
		*(.data .data.*)
		
	}
	.rela	:
	{
		*(.rela .rela.* )
	}
	. = ALIGN(0x1000);
	.bss	: 
	{
		*(.bss .bss.*)
	}
    
	/DISCARD/	:
	{
        *(.dynamic) *(.dynsym) *(.dynstr) *(.dynbss)
		*(.eh_frame .eh_frame*)
		*(.comment*)
		*(.gnu.hash*)
		*(.hash)
        *(.note.*)
	}
	.debug	:
	{
		*(.debug .debug* )
	}
}
