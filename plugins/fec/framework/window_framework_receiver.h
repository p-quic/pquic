
#include "../../helpers.h"

#define RECEIVE_BUFFER_MAX_LENGTH 30

#define MIN(a, b) ((a < b) ? a : b)


#define MAX_AMBIGUOUS_ID_GAP ((uint32_t) 0x200*2)       // the max ambiguous ID gap depends on the max number of source symbols that can be protected by a Repair Symbol


typedef struct {
    uint32_t highest_removed;
    fec_scheme_t fs;
    source_symbol_t *fec_window[RECEIVE_BUFFER_MAX_LENGTH];
} window_fec_framework_receiver_t;

static __attribute__((always_inline)) fec_block_t *get_fec_block(bpf_state *state, uint32_t fbn){
    return state->fec_blocks[fbn % MAX_FEC_BLOCKS];
}

static __attribute__((always_inline)) void add_fec_block_at(bpf_state *state, fec_block_t *fb, uint32_t where) {
    state->fec_blocks[where % MAX_FEC_BLOCKS] = fb;
}

static __attribute__((always_inline)) window_fec_framework_receiver_t *create_framework_receiver(picoquic_cnx_t *cnx, fec_scheme_t fs) {
    window_fec_framework_receiver_t *wff = my_malloc(cnx, sizeof(window_fec_framework_receiver_t));
    if (wff) {
        my_memset(wff, 0, sizeof(window_fec_framework_receiver_t));
        wff->fs = fs;
    }
    return wff;
}

static __attribute__((always_inline)) void populate_fec_block(picoquic_cnx_t *cnx, window_fec_framework_receiver_t *wff, fec_block_t *fb) {
    uint8_t n = 0;
    for (uint32_t i = fb->fec_block_number ; i < fb->fec_block_number + fb->total_source_symbols; i++) {
        if (wff->fec_window[i % RECEIVE_BUFFER_MAX_LENGTH] && wff->fec_window[i % RECEIVE_BUFFER_MAX_LENGTH]->source_fec_payload_id.raw == i) {
            n++;
            fb->source_symbols[i-fb->fec_block_number] = wff->fec_window[i % RECEIVE_BUFFER_MAX_LENGTH];
        }
    }
    fb->current_source_symbols = n;
}

static __attribute__((always_inline)) void remove_and_free_repair_symbols(picoquic_cnx_t *cnx, fec_block_t *fb){
    for(int i = 0 ; i < fb->total_repair_symbols; i++){
        repair_symbol_t *rs = fb->repair_symbols[i];
        if (rs) {
            free_repair_symbol(cnx, rs);
            fb->repair_symbols[i] = NULL;
        }
    }
    fb->current_repair_symbols = 0;

}

// returns true if the symbol has been successfully processed
// returns false otherwise: the symbol can be destroyed
static __attribute__((always_inline)) int window_receive_repair_symbol(picoquic_cnx_t *cnx, repair_symbol_t *rs, uint8_t nss, uint8_t nrs){
    bpf_state *state = get_bpf_state(cnx);
    uint32_t source_symbol_id = rs->repair_fec_payload_id.fec_scheme_specific;
    fec_block_t *fb = get_fec_block(state, source_symbol_id);
    // there exists an older FEC block
    // FIXME: we currently decide to allow only one FEC Block per source_symbol_id
    if (fb && (fb->fec_block_number != source_symbol_id || fb->total_source_symbols != nss)) {
        remove_and_free_repair_symbols(cnx, fb);    // we don't remove the source symbols: they can be used for something else
        my_free(cnx, fb);
        state->fec_blocks[source_symbol_id % MAX_FEC_BLOCKS] = NULL;
        fb = NULL;
    }
    if (!fb)
        fb = malloc_fec_block(cnx, source_symbol_id);
    fb->total_source_symbols = nss;
    fb->total_repair_symbols = nrs;
    add_fec_block_at(state, fb, source_symbol_id);
    if (!add_repair_symbol_to_fec_block(rs, fb)) {
        return false;
    }
    populate_fec_block(cnx, state->framework_receiver, fb);
    PROTOOP_PRINTF(cnx, "RECEIVED RS: CURRENT_SS = %u, CURRENT_RS = %u, TOTAL_SS = %u\n", fb->current_source_symbols, fb->current_repair_symbols, fb->total_source_symbols);
    window_fec_framework_receiver_t *wff = state->framework_receiver;
    if (fb->fec_block_number > wff->highest_removed && fb->current_source_symbols + fb->current_repair_symbols >= fb->total_source_symbols) {
        recover_block(cnx, state, fb);
        // we don't free anything, it will be freed when new symbols are received
    }
    fb->current_source_symbols = 0; // "depopulate" the block
    return true;
}

static __attribute__((always_inline)) void try_to_recover_from_symbol(picoquic_cnx_t *cnx, bpf_state *state, window_fec_framework_receiver_t *wff, source_symbol_t *ss) {
    if (ss->source_fec_payload_id.raw <= wff->highest_removed)
        return;
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
                    // we don't free anything, it will be free when new symbols are received
                }
            }
        }
    }
}

// returns true if the symbol has been successfully processed
// returns false otherwise: the symbol can be destroyed
//FIXME: we pass the state in the parameters because the call to get_bpf_state leads to an error when loading the code
static __attribute__((always_inline)) bool window_receive_source_symbol(picoquic_cnx_t *cnx, bpf_state *state, window_fec_framework_receiver_t *wff, source_symbol_t *ss, bool recover){
    int idx = ss->source_fec_payload_id.raw % RECEIVE_BUFFER_MAX_LENGTH;
    if (wff->fec_window[idx]) {
        // the same symbol is already present: nothing to do
        if (wff->fec_window[idx]->source_fec_payload_id.raw == ss->source_fec_payload_id.raw)
            return false;
        wff->highest_removed = MAX(wff->fec_window[idx]->source_fec_payload_id.raw, wff->highest_removed);
        // another symbol is present: remove it
        free_source_symbol(cnx, wff->fec_window[idx]);
        wff->fec_window[idx] = NULL;
    }

    wff->fec_window[idx] = ss;
    PROTOOP_PRINTF(cnx, "RECEIVED SYMBOL %u\n", ss->source_fec_payload_id.raw);
    // let's find all the blocks protecting this symbol to see if we can recover the remaining
    // we don't recover symbols if we already are in recovery mode
    if (!state->in_recovery && recover) {
        try_to_recover_from_symbol(cnx, state, wff, ss);
    } else {
        PROTOOP_PRINTF(cnx, "RECEIVED SYMBOL %u BUT DIDN'T TRY TO RECOVER\n", ss->source_fec_payload_id.raw);
    }
    return true;
}