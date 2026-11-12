#include <stdint.h>
#include <stddef.h>
#include "container.h"
#include "ks.h"
#include "obf.h"

#define STUB_BASE 0x200000UL
#define CONTAINER_ADDR (STUB_BASE + 0x2000UL)

static long syscall3(long number, long a, long b, long c) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return result;
}
static long syscall6(long number, long a, long b, long c, long d, long e, long f) {
    long result;
    register long r10 __asm__("r10") = d;
    register long r8  __asm__("r8") = e;
    register long r9  __asm__("r9") = f;
    __asm__ volatile("syscall" : "=a"(result): "a"(number), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return result;
}

static long  sys_read (long fd, void *buf, long n) { return syscall3(0, fd, (long)buf, n); }
static long  sys_open (const char *path) { return syscall3(2, (long)path, 0, 0); }
static long  sys_close(long fd) { return syscall3(3, fd, 0, 0); }
static void *sys_mmap (void *addr, long len, long prot, long flags) {
    return (void *)syscall6(9, (long)addr, len, prot, flags, -1, 0);
}
static long  sys_mprotect(void *addr, long len, long prot) {
    return syscall3(10, (long)addr, len, prot);
}
static void  sys_exit(long code) { syscall3(60, code, 0, 0); }
static long  sys_ptrace_traceme(void) { return syscall3(101, 0, 0, 0); }
static long  sys_install_segv_handler(void *action) {
    return syscall6(13, 11, (long)action, 0, 8, 0, 0);
}
static long  sys_install_alarm_handler(void *action) {
    return syscall6(13, 14, (long)action, 0, 8, 0, 0);
}
static long  sys_fork(void) { return syscall3(57, 0, 0, 0); }
static long  sys_wait4(long pid, int *status) { return syscall6(61, pid, (long)status, 0, 0, 0, 0); }

struct timeval_raw { long tv_sec; long tv_usec; };
struct itimerval_raw { struct timeval_raw it_interval; struct timeval_raw it_value; };
static long  sys_setitimer(struct itimerval_raw *new_value) {
    return syscall3(38, 0, (long)new_value, 0);
}

#define PAGE_NONE 0
#define PAGE_READ 1
#define PAGE_WRITE 2
#define PAGE_EXEC 4

#define MAP_PRIVATE_ANON_FIXED (2 | 0x20 | 0x10)


static uint64_t page_start(uint64_t address) { return address & ~0xFFFULL; }
static uint64_t page_end(uint64_t address) { return (address + 0xFFF) & ~0xFFFULL; }

static uint8_t read_decrypted(const uint8_t *data, size_t index, uint64_t key, uint64_t key_base) {
    return (uint8_t)(data[index] ^ keystream_byte(key, key_base + index));
}

static void decompress_segment(const uint8_t *input, size_t input_size, uint8_t *output, uint64_t key, uint64_t key_base) {
    size_t in_pos  = 0;
    size_t out_pos = 0;

    while (in_pos < input_size) {
        uint8_t flags = read_decrypted(input, in_pos, key, key_base);
        in_pos++;

        for (int bit = 0; bit < 8 && in_pos < input_size; bit++) {
            int is_literal = (flags >> bit) & 1;

            if (is_literal) {
                output[out_pos++] = read_decrypted(input, in_pos, key, key_base);
                in_pos++;
            } else {
                uint8_t byte0 = read_decrypted(input, in_pos, key, key_base); in_pos++;
                uint8_t byte1 = read_decrypted(input, in_pos, key, key_base); in_pos++;

                unsigned distance = ((((unsigned)byte1 >> 4) << 8) | byte0) + 1;
                unsigned length   = (byte1 & 0x0F) + 3;

                for (unsigned k = 0; k < length; k++) {
                    output[out_pos] = output[out_pos - distance];
                    out_pos++;
                }
            }
        }
    }
}

/* A successful PTRACE_TRACEME makes *this* process a tracee of its real
 * parent for the rest of its life -- every later self-raised SIGSEGV (our
 * lazy-unpack mechanism) would then stop waiting for a tracer that will
 * never PTRACE_CONT it, deadlocking forever. So the probe runs in a
 * throwaway child that does nothing but attempt it and report the
 * verdict via its exit code; the real process never becomes a tracee. */
static int debugger_present_ptrace(void) {
    long pid = sys_fork();
    if (pid == 0) {
        sys_exit(sys_ptrace_traceme() < 0 ? 1 : 0);
    }
    if (pid < 0) return 0;

    int status = 0;
    sys_wait4(pid, &status);
    int exited_normally = (status & 0x7f) == 0;
    int exit_code = (status >> 8) & 0xff;
    return (exited_normally && exit_code == 1) ? 1 : 0;
}

static int debugger_present_status(void) {
    char buffer[512];
    long fd = sys_open("/proc/self/status");
    if (fd < 0) return 0;
    long n = sys_read(fd, buffer, sizeof(buffer) - 1);
    sys_close(fd);
    if (n <= 0) return 0;
    buffer[n] = 0;

    for (long i = 0; i + 10 < n; i++) {
        int matches = buffer[i+0]=='T' && buffer[i+1]=='r' && buffer[i+2]=='a' && buffer[i+3]=='c' && buffer[i+4]=='e' && buffer[i+5]=='r' && buffer[i+6]=='P' && buffer[i+7]=='i' && buffer[i+8]=='d' &&
            buffer[i+9]==':';
        if (matches) {
            long j = i + 10;
            while (buffer[j] == ' ' || buffer[j] == '\t') j++;
            return buffer[j] != '0' ? 1 : 0;
        }
    }
    return 0;
}

static uint64_t cpu_timestamp(void) {
    unsigned low, high;
    __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
    return ((uint64_t)high << 32) | low;
}
static int debugger_present_timing(void) {
    uint64_t start = cpu_timestamp();
    volatile int dummy = 0;
    for (int i = 0; i < 1000; i++) dummy += i;
    uint64_t elapsed = cpu_timestamp() - start;
    return elapsed > 5000000ULL ? 1 : 0;
}

/* packer overwrites these 8 bytes in stub.bin with a fresh random key per
 * build; must stay byte-identical to CLEAN_KEY so the patcher's pattern
 * search finds exactly one match. volatile so the load can't be folded
 * into the CLEAN_KEY immediate at compile time. */
static volatile uint64_t g_build_key = CLEAN_KEY;

static uint64_t compute_key(void) {
    uint64_t key = g_build_key;
    key ^= (uint64_t)debugger_present_ptrace() * 0xD1B54A32D192ED03ULL;
    key ^= (uint64_t)debugger_present_status() * 0xCA5A826395121157ULL;
    key ^= (uint64_t)debugger_present_timing() * 0x2545F4914F6CDD1DULL;
    return key;
}

static uint64_t g_key;
static Container g_container_storage;
static const Container *g_container;
static const uint8_t *g_blob;
static uint8_t g_segment_ready[MAX_SEGS];

static void decrypt_container(Container *out, const Container *in, uint64_t key) {
    const uint8_t *src = (const uint8_t *)in;
    uint8_t *dst = (uint8_t *)out;
    for (size_t i = 0; i < sizeof(Container); i++) {
        dst[i] = src[i] ^ keystream_byte(key, CONTAINER_KEYSTREAM_BASE + i);
    }
}

extern void return_from_signal(void);
__asm__(
    ".text\n"
    ".global return_from_signal\n"
    "return_from_signal:\n"
    "   mov $15, %rax\n"
    "   syscall\n"
);

static void on_page_fault(int signal_number, void *signal_info, void *context) {
    (void)signal_number;
    (void)context;
    uint64_t fault_address = (uint64_t)*(void **)((char *)signal_info + 16);

    for (uint32_t i = 0; i < g_container->nsegs; i++) {
        const SegDesc *segment = &g_container->segs[i];
        uint64_t start = page_start(segment->vaddr);
        uint64_t end   = page_end(segment->vaddr + segment->memsz);

        if (fault_address >= start && fault_address < end) {
            if (!g_segment_ready[i]) {
                sys_mprotect((void *)start, end - start, PAGE_READ | PAGE_WRITE);
                decompress_segment(g_blob + segment->blob_off, segment->blob_len,(uint8_t *)segment->vaddr, g_key, segment->blob_off);

                long permissions = 0;
                if (segment->flags & 4) permissions |= PAGE_READ;
                if (segment->flags & 2) permissions |= PAGE_WRITE;
                if (segment->flags & 1) permissions |= PAGE_EXEC;
                sys_mprotect((void *)start, end - start, permissions);
                g_segment_ready[i] = 1;
            }
            return;
        }
    }
    sys_exit(139);
}

/* Reading a process's memory through /proc/pid/mem or a core dump bypasses
 * page-protection flags entirely -- it walks physical pages directly, so
 * merely mprotect'ing a decrypted segment back to PROT_NONE leaves the
 * plaintext sitting there for any such tool to read. This handler
 * physically wipes segments that were decrypted but are not the one
 * currently faulting, so a snapshot taken between ticks only ever catches
 * a few live segments in the clear, never the whole unpacked image at
 * once. The wiped segment is simply lazily re-decrypted on next touch via
 * the normal on_page_fault path. */
static void on_decay_tick(int signal_number, void *signal_info, void *context) {
    (void)signal_number;
    (void)signal_info;
    (void)context;

    for (uint32_t i = 0; i < g_container->nsegs; i++) {
        if (!g_segment_ready[i]) continue;

        const SegDesc *segment = &g_container->segs[i];
        uint64_t start = page_start(segment->vaddr);
        uint64_t end   = page_end(segment->vaddr + segment->memsz);

        sys_mprotect((void *)start, end - start, PAGE_READ | PAGE_WRITE);
        for (uint8_t *p = (uint8_t *)start; p < (uint8_t *)end; p++) *p = 0;
        sys_mprotect((void *)start, end - start, PAGE_NONE);
        g_segment_ready[i] = 0;
    }
}

struct signal_action {
    void *handler;
    unsigned long flags;
    void *restorer;
    unsigned long mask;
};
#define FLAG_SIGINFO 4
#define FLAG_RESTORER 0x04000000
#define FLAG_RESTART 0x10000000


void stub_main(void) {
    const Container *raw_container = (const Container *)CONTAINER_ADDR;
    g_blob = (const uint8_t *)raw_container + sizeof(Container);
    g_key = compute_key();
    uint64_t nonzero = cpu_timestamp() | 1ULL;
    g_key = obf_guard(g_key, nonzero, 0, 0);

    decrypt_container(&g_container_storage, raw_container, g_key);
    g_container = &g_container_storage;
    if (g_container_storage.nsegs > MAX_SEGS) sys_exit(139);
    g_key = obf_guard2(g_key, (uint64_t)g_container_storage.nsegs, 0, 0);

    for (uint32_t i = 0; i < g_container->nsegs; i++) {
        const SegDesc *segment = &g_container->segs[i];
        uint64_t start = page_start(segment->vaddr);
        uint64_t end = page_end(segment->vaddr + segment->memsz);
        sys_mmap((void *)start, end - start, PAGE_NONE, MAP_PRIVATE_ANON_FIXED);
        g_segment_ready[i] = 0;
    }

    struct signal_action action;
    action.handler = (void *)on_page_fault;
    action.flags = FLAG_SIGINFO | FLAG_RESTORER;
    action.restorer = (void *)return_from_signal;
    action.mask = 0;
    sys_install_segv_handler(&action);

    struct signal_action decay_action;
    decay_action.handler = (void *)on_decay_tick;
    decay_action.flags = FLAG_SIGINFO | FLAG_RESTORER | FLAG_RESTART;
    decay_action.restorer = (void *)return_from_signal;
    decay_action.mask = 0;
    sys_install_alarm_handler(&decay_action);

    struct itimerval_raw decay_timer;
    decay_timer.it_interval.tv_sec = 0;
    decay_timer.it_interval.tv_usec = 50000;
    decay_timer.it_value.tv_sec = 0;
    decay_timer.it_value.tv_usec = 50000;
    sys_setitimer(&decay_timer);

    void (*original_program)(void) = (void (*)(void))obf_guard2(g_container->orig_entry, nonzero, 0, 0);
    original_program();

    sys_exit(0);
}

__asm__(
    ".section .text.entry,\"ax\"\n"
    ".global stub_entry\n"
    "stub_entry:\n"
    "   xor %rbp, %rbp\n"
    "   and $-16, %rsp\n"
    "   call stub_main\n"
    "   hlt\n"
    ".text\n"
);
