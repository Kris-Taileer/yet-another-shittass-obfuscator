/* Демонстрационная ЖЕРТВА (target): freestanding, статическая, non-PIE.
   Печатает строку и выходит через прямые syscall, без libc.
   asm-пролог выравнивает стек (иначе -O2 + SSE падает на входе). */

static long sc3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r)
        : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

void real_main(void) {
    const char msg[] = "hello from the protected binary!\n";
    sc3(1, 1, (long)msg, sizeof(msg) - 1);   /* write(1, msg, len) */
    sc3(60, 0, 0, 0);                         /* exit(0)            */
    __builtin_unreachable();
}

__asm__(
".global _start\n"
"_start:\n"
"   xor %rbp, %rbp\n"
"   and $-16, %rsp\n"     /* 16-байтное выравнивание стека */
"   call real_main\n"
"   hlt\n"
);
