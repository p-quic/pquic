#include "picoquic_internal.h"
#include "block_framework.h"
#include "memory.h"
#include "memcpy.h"


typedef struct {
    char underlying_fec_scheme[8];
    uint32_t oldest_fec_block_number : 24;
    uint8_t *current_packet;
    uint16_t current_packet_length;
    block_fec_framework_t *block_fec_framework;
    fec_block_t *fec_blocks[MAX_FEC_BLOCKS]; // ring buffer
} bpf_state;

static inline bpf_state *initialize_bpf_state(picoquic_cnx_t *cnx)
{
    bpf_state *state = (bpf_state *) my_malloc(cnx, sizeof(bpf_state));
    if (!state) return NULL;
    my_memset(state, 0, sizeof(bpf_state));
    state->block_fec_framework = new_block_fec_framework(cnx);
    if (!state->block_fec_framework) {
        my_free(cnx, state);
        return NULL;
    }
    return state;
}

static inline bpf_state *get_bpf_state(picoquic_cnx_t *cnx)
{
    int allocated = 0;
    bpf_state **state_ptr = (bpf_state **) get_opaque_data(cnx, FEC_OPAQUE_ID, sizeof(bpf_state *), &allocated);
    if (!state_ptr) return NULL;
    if (allocated) {
        *state_ptr = initialize_bpf_state(cnx);
    }
    return *state_ptr;
}

static inline int helper_write_source_fpid_frame(picoquic_cnx_t *cnx, source_fpid_frame_t *f, uint8_t *bytes, size_t bytes_max, size_t *consumed) {
    if (bytes_max <  (1 + sizeof(source_fpid_t)))
        return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    *bytes = SOURCE_FPID_TYPE;
    bytes++;
    encode_u32(f->source_fpid.raw, bytes);
    *consumed = (1 + sizeof(source_fpid_t));
    return 0;
}

static inline int helper_write_fec_frame(picoquic_cnx_t *cnx, bpf_state *state, uint8_t *bytes, size_t bytes_max, size_t *consumed) {
    if (bytes_max <= (1 + sizeof(fec_frame_header_t)))
        return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    *bytes = FEC_TYPE;
    bytes++;
    *consumed = 0;
    block_fec_framework_t *bff = state->block_fec_framework;
    PROTOOP_PRINTF(cnx, "BYTES_MAX_BEFORE = %u", bytes_max);
    int ret = write_fec_frame(cnx, bff, bytes_max-1, consumed, bytes);
    if (*consumed)
        (*consumed)++;  // add the type byte

    return ret;
}

static inline fec_block_t *get_fec_block(bpf_state *state, uint32_t fbn){
    return state->fec_blocks[fbn % MAX_FEC_BLOCKS];
}

static inline void add_fec_block(bpf_state *state, fec_block_t *fb){
    state->fec_blocks[fb->fec_block_number % MAX_FEC_BLOCKS] = fb;
}

static inline void remove_and_free_fec_block(picoquic_cnx_t *cnx, bpf_state *state, fec_block_t *fb){
    free_fec_block(cnx, fb, false);
    state->fec_blocks[fb->fec_block_number % MAX_FEC_BLOCKS] = NULL;
}
static inline int recover_block(picoquic_cnx_t *cnx, bpf_state *state, fec_block_t *fb){

    protoop_arg_t args[3], outs[1];
    args[0] = (protoop_arg_t) fb;
    protoop_params_t pp = get_pp_noparam("fec_recover", 1, args, outs);
    int ret = (int) plugin_run_protoop(cnx, &pp);
    state->fec_blocks[fb->fec_block_number] = NULL;
    remove_and_free_fec_block(cnx, state, fb);

    return ret;

}

// returns true if the symbol has been successfully processed
// returns false otherwise: the symbol can be destroyed
static inline int received_repair_symbol_helper(picoquic_cnx_t *cnx, repair_symbol_t *rs, uint8_t nss, uint8_t nrs){
    bpf_state *state = get_bpf_state(cnx);
    uint32_t fbn = rs->fec_block_number;
    fec_block_t *fb = get_fec_block(state, fbn);
    // there exists an older FEC block
    // TODO: disambiguate block numbers: watch for possible wrapping or delayed packets
    if (fb && fb->fec_block_number < rs->fec_block_number) {
        remove_and_free_fec_block(cnx, state, fb);
        fb = NULL;
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
    }
    return true;
}

// returns true if the symbol has been successfully processed
// returns false otherwise: the symbol can be destroyed
//FIXME: we pass the state in the parameters because the call to get_bpf_state leads to an error when loading the code
static inline bool received_source_symbol_helper(picoquic_cnx_t *cnx, bpf_state *state, source_symbol_t *ss){
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
    PROTOOP_PRINTF(cnx, "RECEIVED SS: CURRENT_SS = %u, CURRENT_RS = %u, TOTAL_SS = %u, TOTAL_RS = %u\n", fb->current_source_symbols, fb->current_repair_symbols, fb->total_source_symbols, fb->total_repair_symbols);
    if (fb->current_repair_symbols > 0 && fb->current_source_symbols + fb->current_repair_symbols >= fb->total_source_symbols) {
        recover_block(cnx, state, fb);
    }
    return true;
}

static inline int sent_source_symbol_helper(picoquic_cnx_t *cnx, source_symbol_t *ss) {
    bpf_state *state = get_bpf_state(cnx);
    return protect_source_symbol(cnx, state->block_fec_framework, ss);
}

// protects the packet and writes the source_fpid
static inline int protect_packet(picoquic_cnx_t *cnx, source_fpid_t *source_fpid, uint8_t *data, uint16_t length){
    PROTOOP_PRINTF(cnx, "BEFORE PROTECT PACKET OF SIZE %u\n", (unsigned long) length);
    bpf_state *state = get_bpf_state(cnx);
    // write the source fpid
    source_fpid->fec_block_number = state->block_fec_framework->current_block_number;
    source_fpid->symbol_number = state->block_fec_framework->current_block->current_source_symbols;

    source_symbol_t *ss = malloc_source_symbol_with_data(cnx, *source_fpid, data, length);
    if (!ss)
        return -1;
    PROTOOP_PRINTF(cnx, "PROTECT PACKET OF SIZE %u\n", (unsigned long) length);
    int ret = protect_source_symbol(cnx, state->block_fec_framework, ss);
    if (ret) {
        free_source_symbol(cnx, ss);
        return ret;
    }
    return 0;
}

static inline int process_fec_protected_packet(picoquic_cnx_t *cnx, source_fpid_t source_fpid, uint8_t *data, uint16_t length){
    source_symbol_t *ss = malloc_source_symbol_with_data(cnx, source_fpid, data, length);
    bpf_state *state = get_bpf_state(cnx);
    received_source_symbol_helper(cnx, state, ss);
    return 0;
}

// assumes that the data_length field of the frame is safe
static inline int process_fec_frame_helper(picoquic_cnx_t *cnx, fec_frame_t *frame) {
    // TODO: here, we don't handle the case where repair symbols are split into several frames. We should do it.
    repair_symbol_t *rs = malloc_repair_symbol_with_data(cnx, frame->header->repair_fec_payload_id, frame->data,
                                                         frame->header->data_length);
    return received_repair_symbol_helper(cnx, rs, frame->header->nss, frame->header->nrs);
}
