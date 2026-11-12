#ifndef OBF_H
#define OBF_H
#include <stdint.h>

extern uint64_t obf_guard(uint64_t a, uint64_t nz, uint64_t z1, uint64_t z2);
extern uint64_t obf_guard2(uint64_t a, uint64_t v, uint64_t z1, uint64_t z2);

#endif
