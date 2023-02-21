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

#include "threading.h"

#include <stdlib.h>

#if defined(__linux__) || defined(__apple__)
#include <pthread.h>
#define A2PTHREAD

#define A2THREAD_CANCEL(thread)		pthread_cancel(thread)
#define A2THREAD_EXIT			pthread_exit(NULL)

typedef size_t				a2size;

typedef pthread_t			a2thread_t;
typedef pthread_mutex_t			a2thread_mutex_t;
typedef pthread_cond_t			a2thread_cond_t;

#define A2THREAD_MUTEX_INIT(v)		pthread_mutex_init(&v, NULL)
#define A2THREAD_MUTEX_DESTROY(v)	pthread_mutex_destroy(&v)
#define A2THREAD_MUTEX_LOCK(v)		pthread_mutex_lock(&v)
#define A2THREAD_MUTEX_UNLOCK(v)	pthread_mutex_unlock(&v)

#define A2THREAD_COND_INIT(v)		pthread_cond_init(&v, NULL)
#define A2THREAD_COND_DESTROY(v)	pthread_cond_destroy(&v)
#define A2THREAD_COND_WAIT(cond, mutex)	pthread_cond_wait(&cond, &mutex)
#define A2THREAD_COND_WAKE(cond)	pthread_cond_broadcast(&cond)

#elif defined(_MSC_VER)
#define A2WINDOWS

#define A2THREAD_CANCEL(thread)		TerminateThread(thread, 0)
#define A2THREAD_EXIT			ExitThread(0)

typedef DWORD				a2size;

typedef HANDLE				a2thread_t
typedef CRITICAL_SECTION 		a2thread_mutex_t;
typedef CONDITION_VARIABLE		a2thread_cond_t;

#define A2THREAD_MUTEX_INIT(v)		InitializeCriticalSection(&v)
#define A2THREAD_MUTEX_DESTROY(v)	DeleteCriticalSection(&v)
#define A2THREAD_MUTEX_LOCK(v)		EnterCriticalSection(&v)
#define A2THREAD_MUTEX_UNLOCK(v)	LeaveCriticalSection(&v)

#define A2THREAD_COND_INIT(v)		InitializeConditionVariable(&v)
#define A2THREAD_COND_DESTROY(v)	DeleteConditionVariable(&v)
#define A2THREAD_COND_WAIT(cond, mutex)	!SleepConditionVariable(&cond, &mutex, INFINITE)
#define A2THREAD_COND_WAKE(cond)	WakeConditionVariable(&cond)
#endif

struct a2thread_context
{
	a2size n_threads;
	a2thread_t *threads;

	size_t count;
	a2thread_mutex_t count_mutex, cond_mutex;
	a2thread_cond_t cond; /* TODO: store thread return contents in struct? */
};


struct a2thread_context *a2thread_init(size_t n_threads)
{
	struct a2thread_context *ctx = malloc(sizeof(struct a2thread_context));

	if(ctx == NULL) return NULL;

	ctx->n_threads = n_threads;
	ctx->threads = malloc(n_threads * sizeof(a2thread_t));

	ctx->count = 0;
	
	A2THREAD_MUTEX_INIT(ctx->count_mutex);
	A2THREAD_MUTEX_INIT(ctx->cond_mutex);

	A2THREAD_COND_INIT(ctx->cond);

	return ctx;
}

int a2thread_destroy(struct a2thread_context *ctx)
{
	if(ctx == NULL) return -1;

	free(ctx->threads);

	A2THREAD_MUTEX_DESTROY(ctx->count_mutex);
	A2THREAD_MUTEX_DESTROY(ctx->cond_mutex);

	A2THREAD_COND_DESTROY(ctx->cond);

	free(ctx);
}

int a2thread_wait_or_broadcast(struct a2thread_context *ctx, size_t i)
{
	if(ctx->n_threads == 1) return 0;

	A2THREAD_MUTEX_LOCK(ctx->count_mutex);
	if(ctx->count == ctx->n_threads - 1)
	{
		ctx->count = 0;
		A2THREAD_MUTEX_UNLOCK(ctx->count_mutex);

		A2THREAD_MUTEX_LOCK(ctx->cond_mutex);
		A2THREAD_COND_WAKE(ctx->cond);
		A2THREAD_MUTEX_UNLOCK(ctx->cond_mutex);
	}
	else /* TODO: Make other threads fail when one does */
	{
		ctx->count++;
		A2THREAD_MUTEX_UNLOCK(ctx->count_mutex);

		A2THREAD_MUTEX_LOCK(ctx->cond_mutex);
		if(A2THREAD_COND_WAIT(ctx->cond, ctx->cond_mutex))
		{
			A2THREAD_MUTEX_UNLOCK(ctx->cond_mutex);
			A2THREAD_EXIT;
		}
		A2THREAD_MUTEX_UNLOCK(ctx->cond_mutex);
	}
}

int a2thread_assign(struct a2thread_context *ctx, size_t i, a2thread_function_t f, a2thread_args_t args)
{
	if(ctx->n_threads == 1)
	{
		f(args);
		return 0;
	}

#ifdef A2PTHREAD
	return pthread_create(&ctx->threads[i], NULL, f, args);
#elif A2WINDOWS
	ctx->threads[i] = CreateThread(NULL, 0, f, args, 0, NULL);
#endif

	return 0;
}

int a2thread_join(struct a2thread_context *ctx)
{
	if(ctx == NULL) return -1;

	if(ctx->n_threads == 1) return 0;

#ifdef A2PTHREAD
	for(a2size i = 0; i < ctx->n_threads; i++)
		pthread_join(ctx->threads[i], NULL);
#elif A2WINDOWS
	WaitForMultipleObjects(ctx->n_threads, ctx->threads, TRUE, INFINITE);

	for(a2size i = 0; i < ctx->n_threads; i++)
		CloseHandle(ctx->threads[i]);
#endif

	return 0;
}

