#include "blake2b.h"

#include <stdio.h>
#include <stdlib.h>

#if defined(__linux__) || defined(__apple__)
#pragma GCC diagnostic ignored "-Wshift-count-overflow"
#endif

#define bb 128

/* Ripped from RFC 7693 */
#define ROTR64(n, offset) (((n) >> (offset)) ^ ((n) << (64 - (offset))))

static const uint8_t R1 = 32,
	             R2 = 24,
		     R3 = 16,
		     R4 = 63;

static const uint64_t blake2b_iv[8] = {
       0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
       0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
       0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
       0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

static const uint8_t blake2b_sigma[12][16] = {
           { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
           { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
           { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
           { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
           { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
           { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
           { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
           { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
           { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
           { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
           { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
           { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

static void G(uint64_t v[16],
		uint8_t a, uint8_t b, uint8_t c, uint8_t d,
		uint64_t x, uint64_t y)
{
	v[a] += v[b] + x;
	v[d] = ROTR64(v[d] ^ v[a], R1);
	v[c] += v[d];
	v[b] = ROTR64(v[b] ^ v[c], R2);
	v[a] += v[b] + y;
	v[d] = ROTR64(v[d] ^ v[a], R3);
	v[c] += v[d];
	v[b] = ROTR64(v[b] ^ v[c], R4);
}

static void F(uint64_t h[8], uint64_t m[16], uint64_t t[2], int f)
{
	int i;
	uint64_t v[16];

	/* v[0..7] := h[0..7] */
	for(i = 0; i < 8; i++)
		v[i] = h[i];
	/* v[8..15] := IV[0..7] */
	for(; i < 16; i++)
		v[i] = blake2b_iv[i - 8];

	v[12] ^= t[0]; /* v[12] ^ (t mod 2**w) */
	v[13] ^= t[1]; /* v[13] ^ (t >> w) */

	if(f) v[14] = ~v[14];

	for(i = 0; i < 12; i++)
	{
		const uint8_t *s = blake2b_sigma[i];

		G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
		G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
		G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
		G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

		G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
		G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
		G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
		G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
	}

	for(i = 0; i < 8; i++)
	{
		h[i] ^= v[i] ^ v[i + 8];
	}
}

/* Function is keyless */
static uint8_t *BLAKE2B(uint64_t (*d)[16], size_t dd, uint64_t ll[2], uint8_t nn)
{
	uint8_t *digest = malloc(nn * sizeof(uint8_t));
	uint8_t bytes[8];
	uint64_t i, j;
	uint64_t t[2] = {0, 0}, h[8];

	if(digest == NULL) return NULL;

	/* h[0..7] = IV[0..7] */
	for(i = 0; i < 8; i++)
		h[i] = blake2b_iv[i];

	h[0] ^= 0x01010000 ^ nn;

	if(dd > 1)
	{
		for(i = 0; i < dd - 1; i++)
		{
			if(UINT64_MAX - t[0] <= bb) t[1]++;
			t[0] += bb;

			F(h, d[i], t, 0);
		}
	}

	F(h, d[dd - 1], ll, 1);

	for(i = 0; i < nn; i++)
	{
		if(i % 8 == 0)
		{
			for(j = 0; j < 8; j++)
			{
				uint16_t offset = 8 * j;
				uint64_t mask = 0xFF;
				mask <<= offset;

				bytes[j] = (h[i / 8] & (mask)) >> offset;
			}
		}

		digest[i] = bytes[i % 8];
	}

	return digest;
}

uint8_t *blake2b(uint8_t *message, size_t len, uint8_t nn)
{
	uint64_t (*blocks)[16], ll[2];
	size_t i;
	size_t dd = len > 0 ? (len / bb) + (len % bb != 0) : 1;

	if(message == NULL) return NULL;

	blocks = calloc(dd, sizeof(uint64_t[16]));

	for(i = 0; i < len; i++)
	{
		uint64_t big_boy = message[i];
		big_boy <<= 8 * (i % 8);

		blocks[i / bb][(i % bb) / 8] |= big_boy;
	}

	ll[0] = len & UINT64_MAX;
	if(sizeof(size_t) > 8) ll[1] = len >> 64;
	else ll[1] = 0;

	return BLAKE2B(blocks, dd, ll, nn);
}

