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
.global __lb_memcpy_fallible
.code64
__lb_memcpy_fallible: # (dst: *mut u8, src: *const u8, size: usize) -> usize
    mov rcx, rdx
.move:
    rep movsb

.memcpy_exit:
    mov rax, rcx
    ret

.pushsection .ex_table, "a"
    .align 4
    .long .move - .
    .long .memcpy_exit - .
.popsection
