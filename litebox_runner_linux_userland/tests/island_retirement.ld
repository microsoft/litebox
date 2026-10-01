/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */
ENTRY(retirement_entry)
PHDRS { code PT_LOAD FILEHDR PHDRS FLAGS(5); }
SECTIONS {
    . = 0x1000;
    .text.site : { *(.text.site) } :code
    .text.continuation : { *(.text.continuation) } :code
    /DISCARD/ : { *(.note*) *(.eh_frame*) *(.data*) *(.dynamic*) *(.dyn*) *(.gnu*) *(.hash*) }
}
