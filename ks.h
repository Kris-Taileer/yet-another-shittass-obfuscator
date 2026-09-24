#ifndef KS_H
#define KS_H
#include <stdint.h>

#define CLEAN_KEY 0xA5A5A5A5DEADBEEFULL

static inline uint64_t scramble(uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static inline uint8_t keystream_byte (uint64_t key, uint64_t i) {
    return (uint8_t)(scramble(key ^ (i * 0x100000001B3ULL)) & 0xFF);
}

#endif
