/*
 * Argon2 implementation
 *
 * Copyright 2023
 * Daniel Murrow
 *
 * You may use this work under the terms of LGPL Version 3.
 *
 * https://www.gnu.org/licenses/lgpl-3.0.txt
 *
 * You should have received a copy of this license along
 * with this software. If not, you can find it at the above URL.
 */

#ifndef ARGON2_H
#define ARGON2_H

#include <inttypes.h>

uint8_t *argon2d(uint8_t*, uint32_t, const uint8_t*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
uint8_t *argon2i(uint8_t*, uint32_t, const uint8_t*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

#endif

