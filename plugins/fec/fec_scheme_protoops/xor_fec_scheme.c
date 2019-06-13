
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
protoop_arg_t fec_recover(picoquic_cnx_t *cnx)
{
    fec_block_t* fec_block = (fec_block_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    PROTOOP_PRINTF(cnx, "TRYING TO RECOVER SYMBOLS FOR BLOCK %u !\n", fec_block->fec_block_number);
    if (fec_block->total_repair_symbols != 1
            || fec_block->current_source_symbols + fec_block->current_repair_symbols != fec_block->total_source_symbols) {
        PROTOOP_PRINTF(cnx, "NO RECOVERY TO DO\n");
        return 1;
    }
    repair_symbol_t *rs = fec_block->repair_symbols[0];
    uint16_t max_length = rs->data_length;
    uint8_t missing_offset = 0;
    int i;
    for (i = 0 ; i < fec_block->total_source_symbols ; i++) {
        if (!fec_block->source_symbols[i]) {
            missing_offset = i;
        }
    }
    source_fpid_t sfpid;
    sfpid.fec_block_number = fec_block->fec_block_number;
    sfpid.symbol_number = missing_offset;
    source_symbol_t *ss = malloc_source_symbol_with_data(cnx, sfpid, rs->data, max_length);

    source_symbol_t *source_symbol = NULL;
    for_each_source_symbol_nobreak(fec_block, source_symbol) {
        if (source_symbol) {
            xor(ss->data, source_symbol->data, ss->data,
                ss->data_length, source_symbol->data_length);
        }
    }

    fec_block->source_symbols[missing_offset] = ss;
    return 0;
}
