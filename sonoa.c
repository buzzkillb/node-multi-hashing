#include "sonoa.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_echo.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_gost.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"

void sonoa_hash(const char* input, char* output, uint32_t len)
{

    	sph_echo512_context         ctx_echo;
    	sph_skein512_context        ctx_skein;
    	sph_fugue512_context        ctx_fugue;
    	sph_gost512_context         ctx_gost;
    	sph_bmw512_context          ctx_bmw;
    	sph_jh512_context           ctx_jh;
    	sph_keccak512_context       ctx_keccak;

	uint32_t hash[16];

        sph_echo512_init(&ctx_echo);
        sph_echo512(&ctx_echo, input, len);
        sph_echo512_close(&ctx_echo, hash);

        sph_skein512_init(&ctx_skein);
        sph_skein512(&ctx_skein, hash, 64);
        sph_skein512_close(&ctx_skein, hash);

        sph_fugue512_init(&ctx_fugue);
        sph_fugue512(&ctx_fugue, hash, 64);
        sph_fugue512_close(&ctx_fugue, hash);

        sph_gost512_init(&ctx_gost);
        sph_gost512(&ctx_gost, hash, 64);
        sph_gost512_close(&ctx_gost, hash);

        sph_bmw512_init(&ctx_bmw);
        sph_bmw512(&ctx_bmw, hash, 64);
        sph_bmw512_close(&ctx_bmw, hash);

        sph_jh512_init(&ctx_jh);
        sph_jh512(&ctx_jh, hash, 64);
        sph_jh512_close(&ctx_jh, hash);

        sph_keccak512_init(&ctx_keccak);
        sph_keccak512(&ctx_keccak, hash, 64);
        sph_keccak512_close(&ctx_keccak, hash);

	memcpy(output, hash, 32);
}

