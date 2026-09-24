static long sc3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r)
        : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

void real_main(void) {
    const char msg[] = "hello from the protected binary!\n";
    sc3(1, 1, (long)msg, sizeof(msg) - 1);
    sc3(60, 0, 0, 0);
    __builtin_unreachable();
}

__asm__(
".global _start\n"
"_start:\n"
"   xor %rbp, %rbp\n"
"   and $-16, %rsp\n"
"   call real_main\n"
"   hlt\n"
);
