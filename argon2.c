#include "blake2b.h"
#include "threading.h"

#include <stdlib.h>

#define SL 4

#define CEIL(dividend, divisor) (((dividend) / (divisor)) + ((dividend) % (divisor) != 0))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define ROTR64(n, offset)  (((n) >> (offset)) ^ ((n) << (64 - (offset))))
#define TRUNC(n) ((n) & 0xFFFFFFFF)

typedef uint8_t block_t[1024];
typedef uint64_t argon_register_t[2];

struct argon2_context
{
	block_t **blocks;
	uint32_t p, q, m_prime, t, y;
};

struct argon2_pass_instance
{
	block_t *values;
	uint32_t l;
	uint64_t cursor;
};

struct argon2_pass_context
{
	uint32_t r, s;
	struct argon2_pass_instance *inst;
	const struct argon2_context *ctx;
};

struct threading_args
{
	struct a2thread_context *threads;
	struct argon2_context *ctx;
	uint32_t l_start, l_end;
};

static void clear_block(block_t block)
{
	for(uint_fast16_t i = 0; i < 1024; i++)
		block[i] = 0;
}

static void xor_blocks(block_t a, block_t b)
{
	uint_fast16_t i;
	for(i = 0; i < 1024; i++)
		a[i] ^= b[i];
}

static void blake_G(uint64_t *a, uint64_t *b, uint64_t *c, uint64_t *d)
{ 
	*a += *b + (2 * TRUNC(*a) * TRUNC(*b));
	*d = ROTR64(*d ^ *a, 32);
	*c += *d + (2 * TRUNC(*c) * TRUNC(*d));
	*b = ROTR64(*b ^ *c, 24);
	*a += *b + (2 * TRUNC(*a) * TRUNC(*b));
	*d = ROTR64(*d ^ *a, 16);
	*c += *d + (2 * TRUNC(*c) * TRUNC(*d));
	*b = ROTR64(*b ^ *c, 63);
}

static void P(argon_register_t *S[8])
{
	uint64_t *v[16];

	for(int i = 0; i < 8; i++)
	{
		v[2 * i] = S[i][1];
		v[(2 * i) + 1] = S[i][0];
	}

	blake_G(v[0], v[4], v[8], v[12]);
	blake_G(v[1], v[5], v[9], v[13]);
	blake_G(v[2], v[6], v[10], v[14]);
	blake_G(v[3], v[7], v[11], v[15]);

	blake_G(v[0], v[5], v[10], v[15]);
	blake_G(v[1], v[6], v[11], v[12]);
	blake_G(v[2], v[7], v[8], v[13]);
	blake_G(v[3], v[4], v[9], v[14]);
}
/* this is fucking gross */
static void G(block_t dest, block_t X, block_t Y)
{
	union data
	{
		block_t block;
		argon_register_t reg[64];
	};

	uint_fast16_t i, j;
	union data Z;
	argon_register_t *P_input[8];

	for(i = 0; i < 1024; i++)
	{
		dest[i] = X[i] ^ Y[i];
		Z.block[i] = dest[i];
	}

	for(i = 0; i < 8; i++)
	{
		for(j = 0; j < 8; j++)
			P_input[j] = &Z.reg[(i * 8) + j];

		P(P_input);
	}

	for(i = 0; i < 8; i++)
	{
		for(j = 0; j < 8; j++)
			P_input[j] = &Z.reg[i + (j * 8)];

		P(P_input);
	}

	for(i = 0; i < 1024; i++)
		dest[i] ^= Z.block[i];
}

static void concat_long(uint8_t *buffer, uint64_t *i, uint64_t n)
{
	uint8_t *p = (uint8_t*) &n;
	uint_fast8_t j;

	for(j = 0; j < sizeof(uint64_t); j++)
		buffer[*(i++)] = p[j];
}

static void G2(block_t dest,
		uint64_t r, uint64_t l, uint64_t s, uint64_t m_prime, uint64_t t, uint64_t y, uint64_t i)
{
	uint64_t index = 0;
	block_t Z, blank;

	clear_block(Z);
	clear_block(blank);

	concat_long(&Z[0], &index, r);
	concat_long(&Z[0], &index, l);
	concat_long(&Z[0], &index, s);
	concat_long(&Z[0], &index, m_prime);
	concat_long(&Z[0], &index, t);
	concat_long(&Z[0], &index, y);
	concat_long(&Z[0], &index, i);

	G(dest, blank, Z);
	G(dest, blank, dest);
}

static void compute_a2i_values(struct argon2_pass_context *ctx)
{
	uint64_t i;
	uint64_t len = CEIL(ctx->ctx->q, 128 * SL);

	ctx->inst->cursor = 0;

	for(i = 0; i < len; i++)
	{
		G2(ctx->inst->values[i], ctx->r, ctx->inst->l, ctx->s, ctx->ctx->m_prime, ctx->ctx->t, ctx->ctx->y, i + 1);
	}
}

static block_t *get_reference_block(struct argon2_pass_context *ctx, uint32_t j)
{
	uint32_t l;
	uint64_t J_1, J_2, x, y, z;
	uint64_t Rlen = 0;

	const uint64_t two_32 = (UINT64_C(1) << 32);

	block_t *ret = NULL;
	block_t **R = malloc(ctx->ctx->q * sizeof(block_t*));

	if(R == NULL) return NULL;

	if(ctx->ctx->y == 0)
	{
		J_1 = *(uint32_t*) &ctx->ctx->blocks[ctx->inst->l][j - 1][0];
		J_2 = *(uint32_t*) &ctx->ctx->blocks[ctx->inst->l][j - 1][sizeof(uint32_t)];
	}
	else if(ctx->ctx->y == 1)
	{
		J_1 = *(uint32_t*) &ctx->inst->values[ctx->inst->cursor];
		ctx->inst->cursor += sizeof(uint32_t);

		J_2 = *(uint32_t*) &ctx->inst->values[ctx->inst->cursor];
		ctx->inst->cursor += sizeof(uint32_t);
	}
	else return NULL;

	/* mapping J_1 and J_2 */
	l = J_2 % ctx->ctx->p;

	if(l == ctx->inst->l || (ctx->r == 0 && ctx->s == 0))
	{
		for(uint32_t i = 0; i < j - 1; i++)
		{
			R[i] = &ctx->ctx->blocks[ctx->inst->l][i];
			Rlen++;
		}
	}
	else
	{
		size_t i, r_index;
		size_t start_of_this_segment = (ctx->ctx->q / SL) * ctx->s;
		size_t start_of_next_segment = (ctx->ctx->q / SL) * ((ctx->s + 1) % SL);
		size_t end = start_of_next_segment == 0 ? start_of_this_segment : ctx->ctx->q;

		for(r_index = 0, i = start_of_next_segment; i != start_of_this_segment; r_index++)
		{
			R[r_index] = &ctx->ctx->blocks[l][i];
			Rlen++;

			i = (i + 1) % ctx->ctx->q;
		}

		if(j == start_of_this_segment) Rlen--;
	}

	x = (J_1 * J_1) / two_32;
	y = (Rlen * x) / two_32;
	z = Rlen - 1 - y;

	ret = R[z];

	free(R);
	return ret;
}

static A2THREAD_FUNCTION_PREMISE pass(a2thread_args_t thargs) /* TODO: generalize return value */
{
	int compute_new_values_flag;
	uint32_t j, l, l_start, l_end;
	block_t *reference;
	struct threading_args *args = (struct threading_args*) thargs;
	struct argon2_context *ctx = args->ctx;
	struct argon2_pass_instance *instances = NULL;
	struct argon2_pass_context pass_ctx =
	{
		.ctx = ctx,
	};

	l_start = args->l_start;
	l_end = args->l_end;

	instances = calloc(l_end - l_start, sizeof(struct argon2_pass_instance));
	if(instances == NULL) return NULL;


	for(l = 0; l < (l_end - l_start); l++)
	{
		if(ctx->y == 1)
		{
			instances[l].values = malloc(CEIL(ctx->q, 128 * SL) * sizeof(block_t));
			if(instances[l].values == NULL)
			{
				for(j = 0; j < l; j++)
					free(instances[j].values);
				free(instances);

				return NULL;
			}
		}

		instances[l].l = l;
	}

	for(pass_ctx.r = 1; pass_ctx.r <= ctx->t; pass_ctx.r++)
	{
		/* first pass */
		if(pass_ctx.r == 1)
		{
			for(j = 2, pass_ctx.s = 0; j < ctx->q; j++)
			{
				compute_new_values_flag = 0;

				if(j % (ctx->q / SL) == 0) /* if at first block in new segment */
				{
					pass_ctx.s++; /* TODO: remember to wait for other segments to catch up */
					if(ctx->y == 1) compute_new_values_flag = 1;
				}
				else if(ctx->y == 1 && j == 2) /* if this is first value of j and we're still in the first segment */
					compute_new_values_flag = 1;

				for(l = l_start; l < l_end; l++)
				{
					pass_ctx.inst = &instances[l - l_start];

					if(compute_new_values_flag)
						compute_a2i_values(&pass_ctx);

					reference = get_reference_block(&pass_ctx, j);
					G(ctx->blocks[l][j], ctx->blocks[l][j], *reference);
				}
			}
		}
		else
		{
			block_t temp;

			pass_ctx.s = 0;

			for(l = l_start; l < l_end; l++)
			{
				pass_ctx.inst = &instances[l - l_start];

				reference = get_reference_block(&pass_ctx, 0);
				G(temp, ctx->blocks[l][ctx->q - 1], *reference);
				xor_blocks(ctx->blocks[l][0], temp);
			}

			for(j = 1; j < ctx->q; j++)
			{
				compute_new_values_flag = 0;

				if(j % (ctx->q / SL) == 0)
				{
					pass_ctx.s++; /* TODO: wait */
					if(ctx->y == 1) compute_new_values_flag = 1;
				}
				else if(ctx->y == 1 && j == 1) compute_new_values_flag = 1;


				for(l = l_start; l < l_end; l++)
				{
					pass_ctx.inst = &instances[l - l_start];

					if(compute_new_values_flag)
						compute_a2i_values(&pass_ctx);

					reference = get_reference_block(&pass_ctx, j);
					G(temp, ctx->blocks[l][j - 1], *reference);
					xor_blocks(ctx->blocks[l][j], temp);
				}
			}
		}
	}

	if(ctx->y == 1)
	{
		for(l = l_start; l < l_end; l++)
			free(instances[l].values);
		free(instances);
	}

	return NULL;
}

static void concat_int(uint8_t *buffer, uint64_t *i, uint32_t n)
{
	uint8_t *p = (uint8_t*) &n;
	uint_fast8_t j;

	for(j = 0; j < sizeof(uint32_t); j++)
		buffer[*(i++)] = p[j]; 
}

static uint8_t *H_prime(block_t dest, const uint8_t *message, uint32_t ml, uint32_t output_len)
{
	uint8_t *message_prime = NULL;
	uint8_t *digest = NULL;
	uint64_t i, j, k;
	size_t prime_len = sizeof(uint32_t) + (ml * sizeof(uint8_t));
	int we_allocated_digest = 0;

	if(message == NULL) return NULL;
	if(dest == NULL)
	{
		we_allocated_digest = 1;
		digest = malloc(output_len * sizeof(uint8_t));
		if(digest == NULL) return NULL;
	}
	else
		digest = &dest[0];

	if(output_len <= 64)
	{
		message_prime = malloc(prime_len);
		if(message_prime == NULL)
		{
			if(we_allocated_digest) free(digest);
			return NULL;
		}

		i = 0;
		concat_int(message_prime, &i, output_len);
		for(j = 0; j < ml; i++, j++)
			message_prime[i] = message[j];

		blake2b(digest, message_prime, prime_len, output_len);
	}
	else
	{
		uint32_t rounds = CEIL(output_len, 32) - 1;
		uint32_t partial_bytes_needed = output_len - (32 * rounds);

		size_t total_needed = (64 * rounds) + partial_bytes_needed;
		message_prime = malloc(MAX(prime_len, total_needed));
		if(message_prime == NULL)
		{
			if(we_allocated_digest) free(digest);
			return NULL;
		}

		i = 0;
		concat_int(message_prime, &i, output_len);
		for(j = 0; j < ml; i++, j++)
			message_prime[i] = message[j];

		blake2b(message_prime, message_prime, prime_len, 64);
		i = 64;

		for(j = 1; j < rounds; i += 64, j++)
			blake2b(&message_prime[i], &message_prime[i - 64], 64, 64);

		blake2b(&message_prime[i], &message_prime[i - 64], 64, partial_bytes_needed);
		i += partial_bytes_needed;

		if(i != total_needed)
		{
			if(we_allocated_digest) free(digest);
			free(message_prime);

			return NULL;
		}

		for(i = 0, k = 0; i < rounds; i++)
			for(j = 0; j < 32; j++, k++)
				digest[k] = message_prime[(i * 64) + j];

		for(j = 0; j < partial_bytes_needed; j++, k++)
			digest[k] = message_prime[(i * 64) + j];
	}

	free(message_prime);

	return digest;
}

static uint8_t *ARGON2(uint8_t *P, uint32_t pl,
		const uint8_t *S, uint32_t sl,
		uint32_t p, uint32_t T, uint32_t m, uint32_t t,
		uint32_t v, uint32_t y)
{
	uint8_t *buffer = NULL;
	uint8_t *H_0 = NULL;
	uint64_t i = 0, j, H0_len, pass_start, pass_end;
	block_t *C;
	struct argon2_context ctx =
	{
		.p = p,
		.t = t,
		.y = y
	};
	struct a2thread_context *thread_context;
	struct threading_args *thargs;

	/* Calculate how long the first buffer will be. We have 8
	 * inputs of fixed (and same) length */
	uint64_t buffer_length = (sizeof(uint32_t) * UINT64_C(8));
	buffer_length += pl; /* Now we add the inputs of variable length */
	buffer_length += sl;

	if((pl > 0 && P == NULL) || (sl > 0 && S == NULL) || sl < 8
	   || p < 1 || p > 0xFFFFFF || T < 4 || m < 8 * p || t < 1 || v != 0x13 || y > 2)
		return NULL;

	buffer = malloc(buffer_length * sizeof(uint8_t));
	if(buffer == NULL) return NULL;

	concat_int(buffer, &i, p);
	concat_int(buffer, &i, T);
	concat_int(buffer, &i, m);
	concat_int(buffer, &i, t);
	concat_int(buffer, &i, v);
	concat_int(buffer, &i, y);

	pass_start = i;
	concat_int(buffer, &i, pl);
	for(j = 0; j < pl; i++, j++)
	{
		buffer[i] = P[j];
		P[j] = 0; /* clear password from memory */
	}
	pass_end = i;

	concat_int(buffer, &i, sl);
	for(j = 0; j < sl; i++, j++)
		buffer[i] = S[j];

	if(i != buffer_length)
	{
		free(buffer);
		return NULL;
	}

	H0_len = (64 * sizeof(uint8_t)) + (2 * sizeof(uint32_t));
	H_0 = malloc(H0_len);
	if(H_0 == NULL)
	{
		free(buffer);
		return NULL;
	}
	H_0 = blake2b(H_0, buffer, buffer_length, 64);
	
	for(i = pass_start; i < pass_end; i++)
		buffer[i] = 0; /* clear password from buffer in case it doesn't get cleared after being freed */
	free(buffer);

	ctx.m_prime = (m / (4 * p)) * 4 * p;
	ctx.q = ctx.m_prime / p;
	ctx.blocks = malloc(p * sizeof(block_t*));
	if(ctx.blocks == NULL)
	{
		free(H_0);
		return NULL;
	}

	for(i = 0; i < p; i++)
	{
		ctx.blocks[i] = malloc(ctx.q * sizeof(block_t));
		if(ctx.blocks[i] == NULL)
		{
			for(j = 0; j < i; j++)
				free(ctx.blocks[i]);
			free(ctx.blocks);
			free(H_0);
			return NULL;
		}
	}


	for(i = 0; i < p; i++)
	{
		pass_start = 64; /*pass_start is now just a placeholder */
		concat_int(H_0, &pass_start, 0);
		concat_int(H_0, &pass_start, (uint32_t) i);
		H_prime(ctx.blocks[i][0], H_0, H0_len, 1024);

		pass_start = 64;
		concat_int(H_0, &pass_start, 1);
		concat_int(H_0, &pass_start, (uint32_t) i);
		H_prime(ctx.blocks[i][1], H_0, H0_len, 1024);

		// TODO: make multithreaded calls to pass()
	}

	free(H_0);

	thargs = malloc(p * sizeof(struct threading_args));
	if(thargs == NULL)
	{
		for(i = 0; i < p; i++)
			free(ctx.blocks[i]);
		free(ctx.blocks);
	}

	thread_context = a2thread_init(p);
	if(thread_context == NULL)
	{
		free(thargs);

		for(i = 0; i < p; i++)
			free(ctx.blocks[i]);
		free(ctx.blocks);
	}

	for(i = 0; i < p; i++)
	{
		thargs[i].l_start = i;
		thargs[i].l_end = i + 1;
		thargs[i].ctx = &ctx;
		thargs[i].threads = thread_context;

		a2thread_assign(thread_context, i, &pass, (a2thread_args_t) &thargs[i]);
	}

	free(thargs);
	a2thread_destroy(thread_context);

	C = &ctx.blocks[0][ctx.q - 1];
	for(i = 0; i < p; i++)
		xor_blocks(*C, ctx.blocks[i][ctx.q - 1]);

	buffer = H_prime(NULL, (uint8_t*) &(*C[0]), 1024, T);

	for(i = 0; i < p; i++)
		free(ctx.blocks[i]);
	free(ctx.blocks);

	return buffer;
}

