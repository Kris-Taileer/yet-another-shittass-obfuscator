#ifndef CONTAINER_H
#define CONTAINER_H
#include <stdint.h>
#include <stdint.h>

#define MAX_SEGS 8
#define CONTAINER_MAGIC 0x4F42465543ULL

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
} Container;

 #endif
