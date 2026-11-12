#ifndef CONTAINER_H
#define CONTAINER_H
#include <stdint.h>
#include <stdint.h>

#define MAX_SEGS 8
#define CONTAINER_MAGIC 0x4F42465543ULL

/* Raw bytes of the ORIGINAL binary's own program header table, carried
 * through so the stub can patch AT_PHDR/AT_PHNUM/AT_ENTRY in the real
 * auxv to describe the wrapped program instead of the stub's own single
 * combined segment. Without this, glibc's startup walks AT_PHDR looking
 * for things like PT_TLS/PT_GNU_RELRO, finds the stub's unrelated phdr
 * table instead, and leaves internal globals it expects to populate at
 * zero -- which is exactly the kind of "runs fine standalone, crashes
 * once packed" bug this is for. */
#define MAX_ORIG_PHDR_BYTES 2048

/* Keystream index space for encrypting the Container struct itself, kept
 * far away from the blob's own index space (segment blob_off/i) so the
 * same build key never reuses keystream bytes across the two. */
#define CONTAINER_KEYSTREAM_BASE (1ULL << 40)

typedef struct {
    uint64_t vaddr;
    uint64_t memsz;
    uint64_t filesz;
    uint32_t flags;
    uint32_t _pad;
    uint64_t blob_off;
    uint64_t blob_len;
    uint64_t raw_len;

} SegDesc;


typedef struct {
    uint64_t magic;
    uint64_t orig_entry;
    uint32_t nsegs;
    uint32_t _pad;
    SegDesc segs[MAX_SEGS];
    uint32_t orig_phnum;
    uint32_t _pad2;
    unsigned char orig_phdr_raw[MAX_ORIG_PHDR_BYTES];
} Container;

 #endif
