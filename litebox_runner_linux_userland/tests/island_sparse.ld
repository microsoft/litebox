/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */
ENTRY(first)
PHDRS {
    first PT_LOAD FILEHDR PHDRS FLAGS(5);
    second PT_LOAD FLAGS(5);
}
SECTIONS {
    . = 0x1000;
    .text.first : { *(.text.first) } :first
    . = 0x10001000;
    .text.second : { *(.text.second) } :second
    /DISCARD/ : { *(.note*) *(.eh_frame*) *(.data*) *(.dynamic*) *(.dyn*) *(.gnu*) *(.hash*) }
}
