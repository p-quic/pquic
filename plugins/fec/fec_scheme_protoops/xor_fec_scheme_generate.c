
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "memory.h"
#include "../fec_protoops.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif


static inline void xor(uint8_t *a, uint8_t *b, uint8_t *container, int size_a, int size_b) {
    int size = MIN(size_a, size_b);
    int n_64 = size/8;
    int i;
    uint64_t *a64 = (uint64_t  *) a;
    uint64_t *b64 = (uint64_t  *) b;
    uint64_t *container64 = (uint64_t  *) container;
    // should be faster by doing XOR on 8-bytes words directly
    for (i = 0 ; i < n_64 ; i++) {
        container64[i] = a64[i] ^ b64[i];
    }
    for (i = n_64*8 ; i < size ; i++) {
        container[i] = a[i] ^ b[i];
    }
    if (size_a < size_b) {
        for (; i < size_b ; i++)
            container[i] = b[i];
    } else {
        for (; i < size_b ; i++)
            container[i] = a[i];
    }
}

/**
 * fec_block_t* fec_block = (fec_block_t *) cnx->protoop_inputv[0];
 *
 * Output: return code (int)
 */
protoop_arg_t fec_generate_repair_symbols(picoquic_cnx_t *cnx)
{
    fec_block_t* fec_block = (fec_block_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    PROTOOP_PRINTF(cnx, "GENERATING SYMBOLS AFTER CALL, BEFORE MEMORY ACCESS, %p\n", fec_block->total_source_symbols);
    if (fec_block->total_repair_symbols != 1
            || fec_block->total_source_symbols < 1
            || fec_block->current_source_symbols != fec_block->total_source_symbols) {
        PROTOOP_PRINTF(cnx, "IMPOSSIBLE TO GENERATE\n");
        return 1;
    }
    uint16_t max_length = 0;
    PROTOOP_PRINTF(cnx, "GENERATING SYMBOLS FOR BLOCK %u\n", fec_block->fec_block_number);
    source_symbol_t *source_symbol = NULL;
    for_each_source_symbol_nobreak(fec_block, source_symbol) {
        if (source_symbol) {
            max_length = MAX(source_symbol->data_length, max_length);
        }
    }

    repair_fpid_t rfpid;
    rfpid.raw = 0;
    rfpid.fec_block_number = fec_block->fec_block_number;
    repair_symbol_t *rs = malloc_repair_symbol(cnx, rfpid, max_length);


    int i = 0;
    for_each_source_symbol_nobreak(fec_block, source_symbol) {
        if (source_symbol) {
            xor(rs->data, source_symbol->data, rs->data,
                rs->data_length, source_symbol->data_length);
            i++;
        }
    }

    rs->fec_scheme_specific = 0;
    fec_block->repair_symbols[0] = rs;
    return 0;
}

