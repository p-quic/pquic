#include "picoquic_internal.h"
#include "plugin.h"
#include "memory.h"
#include "memcpy.h"

#define FEC_OPAQUE_ID 0xFEC
#define MAX_FEC_BLOCKS 50    // maximum number of idle source blocks handled concurrently
#define MAX_SYMBOLS_PER_FEC_BLOCK 256    // maximum number of idle source blocks handled concurrently

#define DECODE_FEC_FRAME (PROTOOPID_DECODE_FRAMES + 0x30)

#define PREPARE_NEW_CONNECTION_ID_FRAME (PROTOOPID_SENDER + 0x48)
#define PREPARE_MP_ACK_FRAME (PROTOOPID_SENDER + 0x49)
#define PREPARE_ADD_ADDRESS_FRAME (PROTOOPID_SENDER + 0x4a)

#define FEC_TYPE 0x0a

#define DEFAULT_FEC_SCHEME "xor"


typedef struct {
    uint16_t data_length : 15;
    bool fin_bit : 1;
    uint8_t offset;
    uint64_t repair_fec_payload_id;
    uint8_t nss;
    uint8_t nrs;
} fec_frame_header_t;

// TODO: handle cases when my_malloc returns NULL

// TODO: to save memory with a block FEC Scheme, remove the block number from the FPIDs and place it in the source block itself
typedef struct {
    union {
        uint64_t repair_fec_payload_id;
        struct {
            uint32_t fec_scheme_specific;
            uint32_t fec_block_number : 24;
            uint8_t symbol_number;
        };
    };
    uint16_t data_length : 15;
    uint8_t *data;
} repair_symbol_t;

typedef struct {
    union {
        uint32_t source_fec_payload_id;
        struct {
            uint32_t fec_block_number : 24;
            uint8_t fec_block_offset;
        };
    };
    uint16_t data_length: 15;
    uint8_t *data;
} source_symbol_t;

typedef struct {
    fec_frame_header_t *header;
    uint8_t data[];
} fec_frame_t;

typedef struct {
    uint32_t fec_block_number;
    uint8_t total_source_symbols;
    uint8_t total_repair_symbols;
    uint8_t current_source_symbols;
    uint8_t current_repair_symbols;
    source_symbol_t *source_symbols[MAX_SYMBOLS_PER_FEC_BLOCK];
    repair_symbol_t *repair_symbols[MAX_SYMBOLS_PER_FEC_BLOCK];
} fec_block_t;


typedef struct {
    char underlying_fec_scheme[8];
    uint32_t oldest_fec_block_number : 24;
    fec_block_t *fec_blocks[MAX_FEC_BLOCKS]; // ring buffer
} bpf_state;

static bpf_state *initialize_bpf_state(picoquic_cnx_t *cnx)
{
    bpf_state *state = (bpf_state *) my_malloc(cnx, sizeof(bpf_state));
    if (!state) return NULL;
    my_memset(state, 0, sizeof(bpf_state));
    return state;
}

static bpf_state *get_bpf_state(picoquic_cnx_t *cnx)
{
    int allocated = 0;
    bpf_state **state_ptr = (bpf_state **) get_opaque_data(cnx, FEC_OPAQUE_ID, sizeof(bpf_state *), &allocated);
    if (!state_ptr) return NULL;
    if (allocated) {
        *state_ptr = initialize_bpf_state(cnx);
    }
    return *state_ptr;
}

// assumes that size if safe
static source_symbol_t *malloc_source_symbol(picoquic_cnx_t *cnx, uint32_t source_fpid, uint8_t *data, uint16_t size) {
    source_symbol_t *s = (source_symbol_t *) my_malloc(cnx, sizeof(source_symbol_t));
    uint8_t *data_cpy = (uint8_t *) my_malloc(cnx, size);
    if (!s || !data_cpy)
        return NULL;
    
    my_memcpy(data_cpy, data, size);
    s->source_fec_payload_id = source_fpid;
    s->data = data_cpy;
    s->data_length = size;
    return s;
}

// assumes that size if safe
static repair_symbol_t *malloc_repair_symbol(picoquic_cnx_t *cnx, uint64_t repair_fpid, uint8_t *data, uint16_t size) {
    repair_symbol_t *s = (repair_symbol_t *) my_malloc(cnx, sizeof(repair_symbol_t));
    uint8_t *data_cpy = (uint8_t *) my_malloc(cnx, size);
    if (!s || !data_cpy)
        return NULL;
    
    my_memcpy(data_cpy, data, size);
    s->repair_fec_payload_id = repair_fpid;
    s->data = data_cpy;
    s->data_length = size;
    return s;
}

static fec_block_t *malloc_fec_block(picoquic_cnx_t *cnx, uint32_t fbn){
    fec_block_t *fb = (fec_block_t *) my_malloc(cnx, sizeof(fec_block_t));
    my_memset(fb, 0, sizeof(fec_block_t));
    fb->fec_block_number = fbn;
    return fb;
}

static void free_source_symbol(picoquic_cnx_t *cnx, source_symbol_t *s) {
    my_free(cnx, s->data);
    my_free(cnx, s);
}

static void free_repair_symbol(picoquic_cnx_t *cnx, repair_symbol_t *s) {
    my_free(cnx, s->data);
    my_free(cnx, s);
}

static void free_fec_block(picoquic_cnx_t *cnx, fec_block_t *b) {
    int i = 0;
    for (i = 0 ; i < MAX_SYMBOLS_PER_FEC_BLOCK; i++) {
        if (b->source_symbols[i]) {
            free_source_symbol(cnx, b->source_symbols[i]);
            if (!(--b->current_source_symbols)) // we freed everything
                break;
        }
    }

    for (i = 0 ; i < MAX_SYMBOLS_PER_FEC_BLOCK; i++) {
        if (b->repair_symbols[i]) {
            free_repair_symbol(cnx, b->repair_symbols[i]);
            if (!(--b->current_repair_symbols)) // we freed everything
                break;
        }
    }
    my_free(cnx, b);
}

static fec_block_t *get_fec_block(bpf_state *state, uint32_t fbn){
    return state->fec_blocks[fbn % MAX_FEC_BLOCKS];
}

static void add_fec_block(bpf_state *state, fec_block_t *fb){
    state->fec_blocks[fb->fec_block_number % MAX_FEC_BLOCKS] = fb;
}

static void remove_and_free_fec_block(picoquic_cnx_t *cnx, bpf_state *state, fec_block_t *fb){
    free_fec_block(cnx, fb);
    state->fec_blocks[fb->fec_block_number % MAX_FEC_BLOCKS] = NULL;
}

static int add_repair_symbol_to_fec_block(repair_symbol_t *rs, fec_block_t *fb){
    if (!fb->repair_symbols[rs->symbol_number]) {
        fb->repair_symbols[rs->symbol_number] = rs;
        fb->current_repair_symbols++;
        return 1;
    }
    return 0;
}

static int add_source_symbol_to_fec_block(source_symbol_t *ss, fec_block_t *fb){
    if (!fb->source_symbols[ss->fec_block_offset]) {
        fb->source_symbols[ss->fec_block_offset] = ss;
        fb->current_source_symbols++;
        return 1;
    }
    return 0;
}

static void recover_block(picoquic_cnx_t *cnx, bpf_state *state, fec_block_t *fb){
    state->fec_blocks[fb->fec_block_number] = NULL;
    remove_and_free_fec_block(cnx, state, fb);
}

static int process_repair_symbol_helper(picoquic_cnx_t *cnx, repair_symbol_t *rs, uint8_t nss, uint8_t nrs){
    bpf_state *state = get_bpf_state(cnx);
    uint32_t fbn = rs->fec_block_number;
    fec_block_t *fb = get_fec_block(state, fbn);
    // there exists an older FEC block
    if (fbn && fb->fec_block_number != rs->fec_block_number) {
        remove_and_free_fec_block(cnx, state, fb);
        fb = malloc_fec_block(cnx, rs->fec_block_number);
    }
    fb->total_source_symbols = nss;
    fb->total_repair_symbols = nrs;
    add_fec_block(state, fb);
    add_repair_symbol_to_fec_block(rs, fb);
    if (fb->current_source_symbols + fb->current_repair_symbols >= fb->total_source_symbols) {
        recover_block(cnx, state, fb);
    }
    return 1;
}

static int process_source_symbol_helper(picoquic_cnx_t *cnx, source_symbol_t *ss){
    bpf_state *state = get_bpf_state(cnx);
    uint32_t fbn = ss->fec_block_number;
    fec_block_t *fb = get_fec_block(state, fbn);
    // there exists an older FEC block
    if (fbn && fb->fec_block_number != ss->fec_block_number) {
        remove_and_free_fec_block(cnx, state, fb);
        fb = malloc_fec_block(cnx, ss->fec_block_number);
    }
    add_fec_block(state, fb);
    add_source_symbol_to_fec_block(ss, fb);
    if (fb->current_source_symbols + fb->current_repair_symbols >= fb->total_source_symbols) {
        recover_block(cnx, state, fb);
    }
    return 1;
}

//static int process_fec_protected_packet(){
//
//}

// assumes that the data_length field of the frame is safe
static int process_fec_frame_helper(picoquic_cnx_t *cnx, fec_frame_t *frame) {
    repair_symbol_t *rs = malloc_repair_symbol(cnx, frame->header->repair_fec_payload_id, frame->data,
                                               frame->header->data_length);
    return process_repair_symbol_helper(cnx, rs, frame->header->nss, frame->header->nrs);
}
