#include "picoquic_internal.h"
#include "plugin.h"
#include "fec.h"
#include "../helpers.h"
#include "memory.h"
#include "memcpy.h"

#define INITIAL_FEC_BLOCK_NUMBER 0
#define MAX_QUEUED_REPAIR_SYMBOLS 150
#define DEFAULT_N 11
#define DEFAULT_K 9

typedef uint32_t fec_block_number;

typedef struct {
    repair_symbol_t *repair_symbol;
    uint8_t nss;
    uint8_t nrs;
} queue_item;

typedef struct {
    fec_block_number current_block_number: 24;
    fec_block_t *current_block;
    uint8_t n;
    uint8_t k;
    queue_item repair_symbols_queue[MAX_QUEUED_REPAIR_SYMBOLS];
    int repair_symbols_queue_head;
    int repair_symbols_queue_length;
    int queue_byte_offset;  // current byte offset in the current repair symbol
    int queue_piece_offset; // current piece number of the current repair symbol
} block_fec_framework_t;


static inline block_fec_framework_t *new_block_fec_framework(picoquic_cnx_t *cnx) {
    block_fec_framework_t *bff = my_malloc(cnx, sizeof(block_fec_framework_t));
    if (!bff)
        return NULL;
    my_memset(bff, 0, sizeof(block_fec_framework_t));
    bff->current_block = malloc_fec_block(cnx, INITIAL_FEC_BLOCK_NUMBER);
    if (!bff->current_block) {
        my_free(cnx, bff);
        return NULL;
    }
    bff->n = DEFAULT_N;
    bff->k = DEFAULT_K;
    bff->current_block->total_source_symbols = bff->k;
    bff->current_block->total_repair_symbols = bff->n - bff->k;
    return bff;
}

static inline bool ready_to_send(block_fec_framework_t *bff) {
    return (bff->current_block->current_source_symbols == bff->k);
}

static inline bool has_repair_symbols_to_send(block_fec_framework_t *bff) {
    return bff->repair_symbols_queue_length > 0;
}

static inline bool has_repair_symbol_at_index(block_fec_framework_t *bff, int idx) {
    return bff->repair_symbols_queue[idx].repair_symbol != NULL;
}

static inline void remove_item_at_index(picoquic_cnx_t *cnx, block_fec_framework_t *bff, int idx) {
    free_repair_symbol(cnx, bff->repair_symbols_queue[idx].repair_symbol);
    bff->repair_symbols_queue[idx].repair_symbol = NULL;
    bff->repair_symbols_queue[idx].nss = 0;
    bff->repair_symbols_queue[idx].nrs = 0;
}

static inline void put_item_at_index(block_fec_framework_t *bff, int idx, repair_symbol_t *rs, uint8_t nss, uint8_t nrs) {
    bff->repair_symbols_queue[idx].repair_symbol = rs;
    bff->repair_symbols_queue[idx].nss = nss;
    bff->repair_symbols_queue[idx].nrs = nrs;
}

// adds a repair symbol in the queue waiting for the symbol to be sent
static inline void queue_repair_symbol(picoquic_cnx_t *cnx, block_fec_framework_t *bff, repair_symbol_t *rs, fec_block_t *fb){
    int idx = ((uint32_t) rs->repair_fec_payload_id.source_fpid.raw) % MAX_QUEUED_REPAIR_SYMBOLS;
    if (has_repair_symbol_at_index(bff, idx)) {
        remove_item_at_index(cnx, bff, idx);
        if (bff->repair_symbols_queue_length > 1 && bff->repair_symbols_queue_head == idx) {
            // the head is the next symbol
            bff->repair_symbols_queue_head = ( (uint32_t) bff->repair_symbols_queue_head + 1) % MAX_QUEUED_REPAIR_SYMBOLS;
            bff->queue_byte_offset = 0;
        }
        bff->repair_symbols_queue_length--;
    }
    put_item_at_index(bff, idx, rs, fb->total_source_symbols, fb->total_repair_symbols);
    if (bff->repair_symbols_queue_length == 0) {
        bff->repair_symbols_queue_head = idx;
        bff->queue_byte_offset = 0;
    }
    bff->repair_symbols_queue_length++;
}

// adds a repair symbol in the queue waiting for the symbol to be sent
static inline void queue_repair_symbols(picoquic_cnx_t *cnx, block_fec_framework_t *bff, repair_symbol_t *rss[], int number_of_symbols, fec_block_t *fec_block){
    int i;
    for (i = 0 ; i < number_of_symbols ; i++) {
        queue_repair_symbol(cnx, bff, rss[i], fec_block);
    }
}

static inline size_t get_repair_payload_from_queue(picoquic_cnx_t *cnx, block_fec_framework_t *bff, size_t bytes_max, fec_frame_header_t *ffh, uint8_t *bytes){
    if (bff->repair_symbols_queue_length == 0)
        return 0;
    repair_symbol_t *rs = bff->repair_symbols_queue[bff->repair_symbols_queue_head].repair_symbol;
    size_t amount = (rs->data_length - bff->queue_byte_offset) <= bytes_max ? (rs->data_length - bff->queue_byte_offset) : bytes_max;
    // copy
    my_memcpy(bytes, rs->data, amount);
    // move forward in the symbol's buffer
    bff->queue_byte_offset += amount;
    bff->queue_piece_offset++;

    ffh->repair_fec_payload_id = rs->repair_fec_payload_id;
    ffh->offset = (uint8_t) bff->queue_piece_offset;
    ffh->nss = bff->repair_symbols_queue[bff->repair_symbols_queue_head].nss;
    ffh->nrs = bff->repair_symbols_queue[bff->repair_symbols_queue_head].nrs;
    ffh->data_length = (uint16_t) amount;
    ffh->fin_bit = bff->queue_byte_offset == rs->data_length;
    protoop_arg_t args[2];
    args[0] = amount;
    args[1] = bytes_max;
    helper_protoop_printf(cnx, "DEQUEUE %u BYTES, BYTES_MAX = %u\n", args, 2);
    if (bff->queue_byte_offset == rs->data_length) {
        // this symbol has been sent: free the symbol and remove it from the queue
        remove_item_at_index(cnx, bff, bff->repair_symbols_queue_head);
        bff->repair_symbols_queue_head = ((uint32_t) bff->repair_symbols_queue_head + 1) % MAX_QUEUED_REPAIR_SYMBOLS;
        bff->queue_byte_offset = 0;
        bff->queue_piece_offset = 0;
        bff->repair_symbols_queue_length--;
        args[0] = (uint32_t) bff->repair_symbols_queue_length;
        helper_protoop_printf(cnx, "QUEUE LENGTH = %u\n", args, 1);
    }
    return amount;
}

static inline int write_fec_frame(picoquic_cnx_t *cnx, block_fec_framework_t *bff, size_t bytes_max, size_t *consumed, uint8_t *bytes) {
    if (bytes_max < sizeof(fec_frame_header_t))
        return -1;
    fec_frame_header_t ffh;
    // copy the frame payload
    get_repair_payload_from_queue(cnx, bff, bytes_max - sizeof(fec_frame_header_t), &ffh, bytes + sizeof(fec_frame_header_t));
    // copy the frame header
    write_fec_frame_header(&ffh, bytes);
    *consumed = sizeof(fec_frame_header_t) + ffh.data_length;
    return 0;
}

static inline void generate_and_queue_repair_symbols(picoquic_cnx_t *cnx, block_fec_framework_t *bff){
    // TODO: perform the generation and remove the 6 following lines
    uint8_t *data = (uint8_t *) "lorem ipsum lorem upsum";
    repair_symbol_t* generated_symbols[2];
    repair_fpid_t rfpid;
    rfpid.raw = 0;
    generated_symbols[0] = malloc_repair_symbol(cnx, rfpid, data, 11);
    generated_symbols[1] = malloc_repair_symbol(cnx, rfpid, data, 23);
    uint8_t number_of_symbols = 2;
    // end TODO remove
    uint8_t i;
    for (i = 0 ; i < number_of_symbols ; i++) {
        generated_symbols[i]->fec_block_number = bff->current_block_number;
        generated_symbols[i]->symbol_number = i;
    }
    queue_repair_symbols(cnx, bff, generated_symbols, number_of_symbols, bff->current_block);
}

static inline int sent_block(picoquic_cnx_t *cnx, block_fec_framework_t *ff) {
    // TODO: uncomment that and free it the right way
    free_fec_block(cnx, ff->current_block, true);
    ff->current_block_number++;
    ff->current_block = malloc_fec_block(cnx, ff->current_block_number);
    helper_protoop_printf(cnx, "SENT BLOCK!!\n", NULL, 0);
    if (!ff->current_block)
        return -1;
    ff->current_block->total_source_symbols = ff->k;
    ff->current_block->total_repair_symbols = ff->n - ff->k;
    return 0;
}

static inline int protect_source_symbol(picoquic_cnx_t *cnx, block_fec_framework_t *bff, source_symbol_t *ss){
    if (!add_source_symbol_to_fec_block(ss, bff->current_block))
        return -1;
    if (ready_to_send(bff)) {
        generate_and_queue_repair_symbols(cnx, bff);
        sent_block(cnx, bff);
    }
    return 0;
}

static inline void destroy_block_fec_framework(picoquic_cnx_t *cnx, block_fec_framework_t *bff){
    my_free(cnx, bff->current_block);
    my_free(cnx, bff);
}