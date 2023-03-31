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

struct argon2_params
{
	uint8_t *password, *salt;
	uint32_t pass_len, salt_len;
	uint32_t parallelism;
	uint32_t tag_length;
	uint32_t memory;
	uint32_t iterations;
};

uint8_t *argon2d(const struct argon2_params*);
uint8_t *argon2i(const struct argon2_params*);

#endif

