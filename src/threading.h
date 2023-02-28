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

#ifndef ARGON2_THREADING_H
#define ARGON2_THREADING_H

#include <stddef.h>

#if defined(__linux__) || defined(__apple__)

typedef void*				a2thread_args_t;
typedef void*				a2thread_ret_t;

#define A2THREAD_RETURN			NULL
#define A2THREAD_FUNCTION_PREMISE	void*
#elif defined(_MSC_VER)
#include <windows.h>

typedef LPVOID				a2thread_args_t;

#define A2THREAD_RETURN			0
#define A2THREAD_FUNCTION_PREMISE	DWORD WINAPI
#endif

struct a2thread_context;

#ifndef _MSC_VER
typedef a2thread_ret_t (*a2thread_function_t)(a2thread_args_t);
#else
typedef LPTHREAD_START_ROUTINE 		a2thread_function_t;
#endif


struct a2thread_context *a2thread_init(size_t);
int a2thread_destroy(struct a2thread_context*);

int a2thread_wait_or_broadcast(struct a2thread_context*, size_t);

int a2thread_assign(struct a2thread_context*, size_t, a2thread_function_t, a2thread_args_t);
int a2thread_join(struct a2thread_context*);

#endif
