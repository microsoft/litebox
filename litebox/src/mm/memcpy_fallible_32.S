// memory copy with exception handling for x86 32-bit.
//
// Input:
// [esp+4]  destination
// [esp+8]  source  
// [esp+12] count
//
// Output:
// eax uncopied bytes or 0 if successful.
.text
.global __lb_memcpy_fallible
.code32
__lb_memcpy_fallible: # (dst: *mut u8, src: *const u8, size: usize) -> usize
    push esi
    push edi
    push ecx

    # Load parameters from stack
    mov edi, [esp + 16]   # dst (16 = 4*3 pushed regs + 4 return addr)
    mov esi, [esp + 20]   # src
    mov ecx, [esp + 24]   # size

.move:
    rep movsb

.memcpy_exit:
    mov eax, ecx  # Return remaining uncopied bytes

    pop ecx
    pop edi
    pop esi
    ret

.pushsection .ex_table, "a"
    .align 4
    .long .move - .
    .long .memcpy_exit - .
.popsection
