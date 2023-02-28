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

#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <inttypes.h>
#include <stddef.h>

uint8_t *blake2b(uint8_t*, uint8_t*, size_t, uint8_t);

#endif

