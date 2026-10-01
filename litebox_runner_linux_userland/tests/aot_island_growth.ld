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
    /* Three full pages for the three 169-slot serialized islands. */
    . = ALIGN(4096) + 3 * 4096;
    .text.second : { *(.text.second) } :second
    /DISCARD/ : { *(.note*) *(.eh_frame*) *(.data*) *(.dynamic*) *(.dyn*) *(.gnu*) *(.hash*) }
}
