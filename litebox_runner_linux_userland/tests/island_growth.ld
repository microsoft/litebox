/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license.
   Adapted from the read-only trampoline branch's runtime_growth.ld. */
ENTRY(first)
PHDRS {
    first PT_LOAD FILEHDR PHDRS FLAGS(5);
    second PT_LOAD FLAGS(5);
}
SECTIONS {
    . = 0x1000;
    .text.first : { *(.text.first) } :first
    . = ALIGN(4096) + 4096;
    .text.second : { *(.text.second) } :second
    /DISCARD/ : { *(.note*) *(.eh_frame*) *(.data*) *(.dynamic*) *(.dyn*) *(.gnu*) *(.hash*) }
}
