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

.section .note.GNU-stack,"",@progbits
