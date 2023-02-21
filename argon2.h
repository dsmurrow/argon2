#ifndef ARGON2_H
#define ARGON2_H

#include <inttypes.h>

uint8_t *argon2d(uint8_t*, uint32_t, const uint8_t*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
uint8_t *argon2i(uint8_t*, uint32_t, const uint8_t*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

#endif

