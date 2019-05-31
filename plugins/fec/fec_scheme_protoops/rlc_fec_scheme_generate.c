#include <picoquic_internal.h>
#include "../fec.h"
#include "../../helpers.h"
#include "../gmp/mini-gmp.c"
#include "../prng/tinymt32.c"



static inline void get_coefs(picoquic_cnx_t *cnx, tinymt32_t *prng, uint32_t seed, int n, uint8_t coefs[n]) {
    tinymt32_init(prng, seed);
    int i;
    for (i = 0 ; i < n ; i++) {
        coefs[i] = (uint8_t) tinymt32_generate_uint32(prng);
        if (coefs[i] == 0)
            coefs[i] = 1;
    }
}

/**
 * fec_block_t* fec_block = (fec_block_t *) cnx->protoop_inputv[0];
 *
 * Output: return code (int)
 */
protoop_arg_t fec_generate_repair_symbols(picoquic_cnx_t *cnx)
{
    tinymt32_t prng;
    prng.mat1 = 0x8f7011ee;
    prng.mat2 = 0xfc78ff1f;
    prng.tmat = 0x3793fdff;
    fec_block_t* fec_block = (fec_block_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    PROTOOP_PRINTF(cnx, "GENERATING SYMBOLS WITH RLC\n");
    if (fec_block->total_repair_symbols == 0
        || fec_block->total_source_symbols < 1
        || fec_block->current_source_symbols != fec_block->total_source_symbols) {
        PROTOOP_PRINTF(cnx, "IMPOSSIBLE TO GENERATE\n");
        return 1;
    }

    uint16_t max_length = 0;

    for_each_source_symbol(fec_block, source_symbol_t *source_symbol) {
        max_length = MAX(source_symbol->data_length, max_length);
    }


    uint8_t i, j;
    uint8_t *coefs = my_malloc(cnx, fec_block->total_source_symbols*sizeof(uint8_t));
    mpz_t tmp;
    mpz_t res;
    mpz_init(cnx, tmp);
    mpz_init(cnx, res);
    mpz_t *knowns = my_malloc(cnx, fec_block->total_source_symbols*sizeof(mpz_t));
    for (i = 0 ; i < fec_block->total_source_symbols ; i++) {
        mpz_init(cnx, knowns[i]);
        mpz_import(knowns[i], fec_block->source_symbols[i]->data_length, 1, 1, fec_block->source_symbols[i]->data);
    }
    for (i = 0 ; i < fec_block->total_repair_symbols ; i++) {
        repair_fpid_t rfpid;
        rfpid.raw = 0;
        rfpid.fec_block_number = fec_block->fec_block_number;
        rfpid.symbol_number = i;
        get_coefs(cnx, &prng, rfpid.source_fpid.raw, fec_block->total_source_symbols, coefs);
        mpz_mul_ui(res, knowns[0], coefs[0]);
        for (j = 1 ; j < fec_block->total_source_symbols ; j++) {
            mpz_mul_ui(tmp, knowns[j], coefs[j]);
            mpz_add(res, res, tmp);
        }

        uint16_t sizeinbytes = (uint16_t) mpz_bytes_count(res);
        repair_symbol_t *rs = malloc_repair_symbol(cnx, rfpid, sizeinbytes);
        uint64_t count;
        mpz_export(rs->data, &count, 1, 1, res);
        if (count != rs->data_length) {
            PROTOOP_PRINTF(cnx, "GMP WROTE A DIFFERENT AMOUNT OF BYTES THAN SIGNALED: %u instead of %u\n", count, rs->data_length);
            mpz_clear(tmp);
            mpz_clear(res);
            for (i = 0 ; i < fec_block->total_source_symbols ; i++) {
                mpz_clear(knowns[i]);
            }
            my_free(cnx, coefs);
            my_free(cnx, knowns);
            return 1;
        }
        fec_block->repair_symbols[i] = rs;

    }

    mpz_clear(tmp);
    mpz_clear(res);
    for (i = 0 ; i < fec_block->total_source_symbols ; i++) {
        mpz_clear(knowns[i]);
    }
    my_free(cnx, coefs);
    my_free(cnx, knowns);
    return 0;
}
