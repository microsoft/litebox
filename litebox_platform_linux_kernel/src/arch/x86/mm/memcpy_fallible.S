// memory copy with exception handling.
//
// Input:
// rdi destination
// rsi source
// rcx count
//
// Output:
// rcx uncopied bytes or 0 if successful.
.text
.global __memcpy_fallible
.code64
__memcpy_fallible: # (dst: *mut u8, src: *const u8, size: usize) -> usize
    mov rcx, rdx
.move:
    rep movsb

.memcpy_exit:
    mov rax, rcx
    ret

// TODO: implement exception handling
.pushsection .ex_table, "a"
    .align 8
    .quad [.move]
    .quad [.memcpy_exit]
.popsection