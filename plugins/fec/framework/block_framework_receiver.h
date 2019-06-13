#include "../../helpers.h"
#include "../fec.h"

#define INITIAL_FEC_BLOCK_NUMBER 0
#define MAX_QUEUED_REPAIR_SYMBOLS 6
#define DEFAULT_N 30
#define DEFAULT_K 25


static __attribute__((always_inline)) void *create_framework_receiver(picoquic_cnx_t *cnx, fec_scheme_t fs) {
    return fs;
}

static __attribute__((always_inline)) fec_block_t *get_fec_block(bpf_state *state, uint32_t fbn){
    return state->fec_blocks[fbn % MAX_FEC_BLOCKS];
}

static __attribute__((always_inline)) void add_fec_block(bpf_state *state, fec_block_t *fb){
    state->fec_blocks[fb->fec_block_number % MAX_FEC_BLOCKS] = fb;
}

static __attribute__((always_inline)) void remove_and_free_fec_block(picoquic_cnx_t *cnx, bpf_state *state, fec_block_t *fb){
    state->fec_blocks[fb->fec_block_number % MAX_FEC_BLOCKS] = NULL;
    free_fec_block(cnx, fb, false);
}

// returns true if the symbol has been successfully processed
// returns false otherwise: the symbol can be destroyed
static __attribute__((always_inline)) bool block_receive_repair_symbol(picoquic_cnx_t *cnx, repair_symbol_t *rs, uint8_t nss, uint8_t nrs){
    bpf_state *state = get_bpf_state(cnx);
    uint32_t fbn = rs->fec_block_number;
    fec_block_t *fb = get_fec_block(state, fbn);
    // there exists an older FEC block
    // TODO: disambiguate block numbers: watch for possible wrapping or delayed packets
    if (fb && fb->fec_block_number < rs->fec_block_number) {
        remove_and_free_fec_block(cnx, state, fb);
        fb = NULL;
    } else if (fb && fb->fec_block_number > rs->fec_block_number) {
        // keep current FEC block and discard repair symbol
        return false;
    }
    if (!fb)
        fb = malloc_fec_block(cnx, rs->fec_block_number);
    fb->total_source_symbols = nss;
    fb->total_repair_symbols = nrs;
    add_fec_block(state, fb);
    if (!add_repair_symbol_to_fec_block(rs, fb)) {
        return false;
    }
    PROTOOP_PRINTF(cnx, "RECEIVED RS: CURRENT_SS = %u, CURRENT_RS = %u, TOTAL_SS = %u\n", fb->current_source_symbols, fb->current_repair_symbols, fb->total_source_symbols);
    if (fb->current_source_symbols + fb->current_repair_symbols >= fb->total_source_symbols) {
        recover_block(cnx, state, fb);
        remove_and_free_fec_block_at(cnx, state, fb->fec_block_number);
    }
    return true;
}

// returns true if the symbol has been successfully processed
// returns false otherwise: the symbol can be destroyed
//FIXME: we pass the state in the parameters because the call to get_bpf_state leads to an error when loading the code
static __attribute__((always_inline)) bool block_receive_source_symbol(picoquic_cnx_t *cnx, bpf_state *state, source_symbol_t *ss, bool recover){
    uint32_t fbn = ss->fec_block_number;
    fec_block_t *fb = get_fec_block(state, fbn);
    // there exists an older FEC block
    if (fb && fb->fec_block_number != ss->fec_block_number) {
        remove_and_free_fec_block(cnx, state, fb);
        fb = NULL;
    }
    if (!fb)
        fb = malloc_fec_block(cnx, ss->fec_block_number);
    add_fec_block(state, fb);
    if (!add_source_symbol_to_fec_block(ss, fb)) {
        return false;
    }
    PROTOOP_PRINTF(cnx, "RECEIVED SS %u: BLOCK = %u, CURRENT_SS = %u, CURRENT_RS = %u, TOTAL_SS = %u, TOTAL_RS = %u\n", ss->fec_block_offset, fb->fec_block_number, fb->current_source_symbols, fb->current_repair_symbols, fb->total_source_symbols, fb->total_repair_symbols);
    if (!state->in_recovery && recover && fb->current_repair_symbols > 0 && fb->current_source_symbols + fb->current_repair_symbols >= fb->total_source_symbols) {
        recover_block(cnx, state, fb);
        remove_and_free_fec_block_at(cnx, state, fb->fec_block_number);
    }
    return true;
}