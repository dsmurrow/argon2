#ifndef ARGON2_THREADING_H
#define ARGON2_THREADING_H

#include <stddef.h>

#if defined(__linux__) || defined(__apple__)

typedef void*				a2thread_args_t;
typedef void*				a2thread_ret_t;

#define A2THREAD_FUNCTION_PREMISE	void*
#elif defined(_MSC_VER)
#include <windows.h>

typedef LPVOID				a2thread_args_t;
typedef DWORD				a2thread_ret_t;

#define A2THREAD_FUNCTION_PREMISE	DWORD WINAPI
#endif

struct a2thread_context;

typedef a2thread_ret_t (*a2thread_function_t)(a2thread_args_t);

struct a2thread_context *a2thread_init(size_t);
int a2thread_destroy(struct a2thread_context*);

int a2thread_wait_or_broadcast(struct a2thread_context*, size_t);

int a2thread_assign(struct a2thread_context*, size_t, a2thread_function_t, a2thread_args_t);
int a2thread_join(struct a2thread_context*);

#endif
