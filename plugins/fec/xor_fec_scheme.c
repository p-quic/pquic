
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "memory.h"
#include "bpf.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif


static inline void xor(uint8_t *a, uint8_t *b, uint8_t *container, int size) {
    int n_64 = size/8;
    int i;
    uint64_t *a64 = (uint64_t  *) a;
    uint64_t *b64 = (uint64_t  *) b;
    uint64_t *container64 = (uint64_t  *) container;
    // should be faster by doing XOR on 8-bytes words directly
    for (i = 0 ; i < size/8 ; i++) {
        container64[i] = a64[i] ^ b64[i];
    }
    for (i = (size/8)*8 ; i < size ; i++) {
        container[i] = a[i] ^ b[i];
    }
}

/**
 * fec_block_t* fec_block = (fec_block_t *) cnx->protoop_inputv[0];
 *
 * Output: return code (int)
 */
protoop_arg_t fec_recover(picoquic_cnx_t *cnx)
{
    fec_block_t* fec_block = (fec_block_t *) cnx->protoop_inputv[0];
    PROTOOP_PRINTF(cnx, "TRYING TO RECOVER SYMBOLS FOR BLOCK %u !\n", fec_block->fec_block_number);
    if (fec_block->total_repair_symbols != 1
            || fec_block->current_source_symbols + fec_block->current_repair_symbols != fec_block->total_source_symbols) {
        PROTOOP_PRINTF(cnx, "NO RECOVERY TO DO\n");
        return 1;
    }
    uint16_t max_length = 0;
    uint8_t missing_offset = 0;
    uint8_t i;
    for (i = 0 ; i < fec_block->total_source_symbols ; i++) {
        if (!fec_block->source_symbols[i]) {
            missing_offset = i;
            continue;
        }
        max_length = MAX(fec_block->source_symbols[i]->data_length, max_length);
    }
    source_fpid_t sfpid;
    sfpid.fec_block_number = fec_block->fec_block_number;
    sfpid.symbol_number = missing_offset;
    source_symbol_t *ss = malloc_source_symbol(cnx, sfpid, max_length);

    for_each_source_symbol(fec_block, source_symbol_t *source_symbol) {
        if (source_symbol) {
            xor(ss->data, source_symbol->data, ss->data,
                MIN(ss->data_length, source_symbol->data_length));
        }
    }

    PROTOOP_PRINTF(cnx, "RECOVERING BLOCK %u (XOR)\n", fec_block->fec_block_number);
    fec_block->source_symbols[missing_offset] = ss;
    return 0;
}


/**
 * fec_block_t* fec_block = (fec_block_t *) cnx->protoop_inputv[0];
 *
 * Output: return code (int)
 */
protoop_arg_t fec_generate_repair_symbols(picoquic_cnx_t *cnx)
{
    PROTOOP_PRINTF(cnx, "GENERATING SYMBOLS AFTER CALL, BEFORE MEMORY ACCESS !\n");
    fec_block_t* fec_block = (fec_block_t *) cnx->protoop_inputv[0];
    if (fec_block->total_repair_symbols != 1
            || fec_block->total_source_symbols < 1
            || fec_block->current_source_symbols != fec_block->total_source_symbols)
        return 1;
    uint16_t max_length = 0;
    PROTOOP_PRINTF(cnx, "GENERATING SYMBOLS FOR BLOCK %u\n", fec_block->fec_block_number);

    for_each_source_symbol(fec_block, source_symbol_t *source_symbol) {
        max_length = MAX(source_symbol->data_length, max_length);
    }

    repair_fpid_t rfpid;
    rfpid.raw = 0;
    rfpid.fec_block_number = fec_block->fec_block_number;
    repair_symbol_t *rs = malloc_repair_symbol(cnx, rfpid, max_length);

    for_each_source_symbol(fec_block, source_symbol_t *source_symbol) {
        if (source_symbol) {
            xor(rs->data, source_symbol->data, rs->data,
                MIN(rs->data_length, source_symbol->data_length));
        }
    }

    fec_block->repair_symbols[0] = rs;
    return 0;
}

