#include "picoquic_internal.h"
#include "../../helpers.h"
#include "memory.h"
#include "memcpy.h"
#include "../bpf.h"

#define INITIAL_SYMBOL_ID 1
#define DEFAULT_N 30
#define DEFAULT_K 25
#define RECEIVE_BUFFER_MAX_LENGTH 30

#define MIN(a, b) ((a < b) ? a : b)

typedef struct {
    source_symbol_t *fec_window[RECEIVE_BUFFER_MAX_LENGTH];
} window_fec_framework_receiver_t;

static __attribute__((always_inline)) fec_block_t *get_fec_block(bpf_state *state, uint32_t fbn){
    return state->fec_blocks[fbn % MAX_FEC_BLOCKS];
}

static __attribute__((always_inline)) void add_fec_block_at(bpf_state *state, fec_block_t *fb, uint32_t where) {
    state->fec_blocks[where % MAX_FEC_BLOCKS] = fb;
}

static __attribute__((always_inline)) window_fec_framework_receiver_t *create_framework_receiver(picoquic_cnx_t *cnx) {
    window_fec_framework_receiver_t *wff = my_malloc(cnx, sizeof(window_fec_framework_receiver_t));
    if (wff)
        my_memset(wff, 0, sizeof(window_fec_framework_receiver_t));
    return wff;
}

// returns true if the symbol has been successfully processed
// returns false otherwise: the symbol can be destroyed
static __attribute__((always_inline)) int receive_repair_symbol(picoquic_cnx_t *cnx, repair_symbol_t *rs, uint8_t nss, uint8_t nrs){
    bpf_state *state = get_bpf_state(cnx);
    uint32_t source_symbol_id = rs->repair_fec_payload_id.fec_scheme_specific;
    fec_block_t *fb = get_fec_block(state, source_symbol_id);
    // there exists an older FEC block
    // FIXME: we currently decide to allow only one FEC Block per source_symbol_id
    if (fb && fb->total_source_symbols != nss) {
        remove_and_free_fec_block_at(cnx, state, source_symbol_id);
        fb = NULL;
    }
    if (!fb)
        fb = malloc_fec_block(cnx, rs->fec_block_number);
    fb->total_source_symbols = nss;
    fb->total_repair_symbols = nrs;
    add_fec_block_at(state, fb, source_symbol_id);
    if (!add_repair_symbol_to_fec_block(rs, fb)) {
        return false;
    }
    PROTOOP_PRINTF(cnx, "RECEIVED RS: CURRENT_SS = %u, CURRENT_RS = %u, TOTAL_SS = %u\n", fb->current_source_symbols, fb->current_repair_symbols, fb->total_source_symbols);
    if (fb->current_source_symbols + fb->current_repair_symbols >= fb->total_source_symbols) {
        recover_block(cnx, state, fb);
    }
    return true;
}

static __attribute__((always_inline)) void populate_fec_block(picoquic_cnx_t *cnx, window_fec_framework_receiver_t *wff, fec_block_t *fb) {
    for (uint32_t i = fb->fec_block_number ; i < fb->fec_block_number + fb->total_source_symbols; i++) {
        if (wff->fec_window[i % RECEIVE_BUFFER_MAX_LENGTH] && wff->fec_window[i % RECEIVE_BUFFER_MAX_LENGTH]->source_fec_payload_id.raw == i) {
            fb->current_source_symbols++;
            fb->source_symbols[i-fb->fec_block_number] = wff->fec_window[i % RECEIVE_BUFFER_MAX_LENGTH];
        }
    }
}

// returns true if the symbol has been successfully processed
// returns false otherwise: the symbol can be destroyed
//FIXME: we pass the state in the parameters because the call to get_bpf_state leads to an error when loading the code
static __attribute__((always_inline)) bool receive_source_symbol(picoquic_cnx_t *cnx, bpf_state *state, window_fec_framework_receiver_t *wff, source_symbol_t *ss){
    int idx = ss->source_fec_payload_id.raw % RECEIVE_BUFFER_MAX_LENGTH;
    if (wff->fec_window[idx]) {
        // the same symbol is already present: nothing to do
        if (wff->fec_window[idx]->source_fec_payload_id.raw == ss->source_fec_payload_id.raw)
            return false;
        // another symbol is present: remove it
        my_free(cnx, wff->fec_window[idx]);
        wff->fec_window[idx] = NULL;
    }

    wff->fec_window[idx] = ss;
    // let's find all the blocks protecting this symbol to see if we can recover the remaining
    for (int i = 0 ; i < MAX_FEC_BLOCKS ; i++) {
        if (state->fec_blocks[i]) {
            fec_block_t *fb = state->fec_blocks[i];
            if (fb->fec_block_number <= ss->source_fec_payload_id.raw && ss->source_fec_payload_id.raw < fb->fec_block_number + fb->total_source_symbols) {
                // the FEC block protects this symbol
                populate_fec_block(cnx, wff, fb);
                PROTOOP_PRINTF(cnx, "RECEIVED SS %u: BLOCK = (%u, %u), CURRENT_SS = %u, CURRENT_RS = %u, TOTAL_SS = %u, TOTAL_RS = %u\n", ss->source_fec_payload_id.raw,
                        fb->fec_block_number, fb->fec_block_number+fb->total_source_symbols, fb->current_source_symbols,
                        fb->current_repair_symbols, fb->total_source_symbols, fb->total_repair_symbols);
                if (fb->current_repair_symbols > 0 && fb->current_source_symbols + fb->current_repair_symbols >= fb->total_source_symbols) {
                    recover_block(cnx, state, fb);
                }
            }
        }
    }
    return true;
}