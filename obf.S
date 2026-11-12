.text
.global obf_guard
obf_guard:
    mov %rdi, %rax
    test %esi, %esi
    jne 1f
    push %rbx
    push %r12
1:
    lea 1(%rcx), %r11
    imul %rcx, %r11
    and $1, %r11
    jne 3f
    jmp 2f
3:
    .byte 0xe8

2:
    lea 4f(%rip), %r10
    add %rdx, %r10
    jmp *%r10

4:
    ret

/* obf_guard2: identity at runtime, like obf_guard, but the dead branch is
 * gated by a genuine opaque predicate instead of a caller-guaranteed
 * invariant: x*(x+1) is always even for ANY integer x (one of a pair of
 * consecutive integers is always even), so the taken branch doesn't
 * depend on what the caller happens to pass. The dead branch starts a
 * different multi-byte opcode (0x0f, a two-byte-opcode prefix) than
 * obf_guard's 0xe8, so a linear disassembler desyncs differently here. */
.global obf_guard2
obf_guard2:
    mov %rdi, %rax
    mov %esi, %r11d
    lea 1(%r11), %r9d
    imul %r9d, %r11d
    and $1, %r11d
    jne 5f
    jmp 6f
5:
    .byte 0x0f

6:
    lea 7f(%rip), %r10
    add %rdx, %r10
    jmp *%r10

7:
    ret

.section .note.GNU-stack,"",@progbits
