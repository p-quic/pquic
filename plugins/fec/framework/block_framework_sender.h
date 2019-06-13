#include "../fec.h"
#include "../../helpers.h"
#include "../fec_protoops.h"

#define INITIAL_FEC_BLOCK_NUMBER 0
#define MAX_QUEUED_REPAIR_SYMBOLS 6

typedef uint32_t fec_block_number;

typedef struct {
    repair_symbol_t *repair_symbol;
    uint8_t nss;
    uint8_t nrs;
} queue_item;

typedef struct {
    fec_scheme_t fec_scheme;
    fec_redundancy_controller_t controller;
    fec_block_number current_block_number: 24;
    fec_block_t *current_block;
    queue_item repair_symbols_queue[MAX_QUEUED_REPAIR_SYMBOLS];
    int repair_symbols_queue_head;
    int repair_symbols_queue_length;
    int queue_byte_offset;  // current byte offset in the current repair symbol
    int queue_piece_offset; // current piece number of the current repair symbol
} block_fec_framework_t;


static __attribute__((always_inline)) block_fec_framework_t *create_framework_sender(picoquic_cnx_t *cnx, fec_redundancy_controller_t controller, fec_scheme_t fs) {
    block_fec_framework_t *bff = my_malloc(cnx, sizeof(block_fec_framework_t));
    if (!bff)
        return NULL;
    my_memset(bff, 0, sizeof(block_fec_framework_t));
    bff->current_block = malloc_fec_block(cnx, INITIAL_FEC_BLOCK_NUMBER);
    if (!bff->current_block) {
        my_free(cnx, bff);
        return NULL;
    }
    uint8_t n = 0;
    uint8_t k = 0;
    get_redundancy_parameters(cnx, bff->controller, false, &n, &k);
    bff->current_block->total_source_symbols = k;
    bff->current_block->total_repair_symbols = n - k;
    bff->controller = controller;
    bff->fec_scheme = fs;
    return bff;
}

static __attribute__((always_inline)) bool ready_to_send(picoquic_cnx_t *cnx, block_fec_framework_t *bff) {
    uint8_t k = 0;
    get_redundancy_parameters(cnx, bff->controller, false, NULL, &k);
    return (bff->current_block->current_source_symbols >= k);
}

static __attribute__((always_inline)) bool has_repair_symbol_at_index(block_fec_framework_t *bff, int idx) {
    return bff->repair_symbols_queue[idx].repair_symbol != NULL;
}

static __attribute__((always_inline)) void remove_item_at_index(picoquic_cnx_t *cnx, block_fec_framework_t *bff, int idx) {
    free_repair_symbol(cnx, bff->repair_symbols_queue[idx].repair_symbol);
    bff->repair_symbols_queue[idx].repair_symbol = NULL;
    bff->repair_symbols_queue[idx].nss = 0;
    bff->repair_symbols_queue[idx].nrs = 0;
}

static __attribute__((always_inline)) void put_item_at_index(block_fec_framework_t *bff, int idx, repair_symbol_t *rs, uint8_t nss, uint8_t nrs) {
    bff->repair_symbols_queue[idx].repair_symbol = rs;
    bff->repair_symbols_queue[idx].nss = nss;
    bff->repair_symbols_queue[idx].nrs = nrs;
}

// adds a repair symbol in the queue waiting for the symbol to be sent
static __attribute__((always_inline)) void queue_repair_symbol(picoquic_cnx_t *cnx, block_fec_framework_t *bff, repair_symbol_t *rs, fec_block_t *fb){
    int idx = ((uint32_t) bff->repair_symbols_queue_head + bff->repair_symbols_queue_length) % MAX_QUEUED_REPAIR_SYMBOLS;
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
static __attribute__((always_inline)) void queue_repair_symbols(picoquic_cnx_t *cnx, block_fec_framework_t *bff, repair_symbol_t *rss[], int number_of_symbols, fec_block_t *fec_block){
    int i;
    for (i = 0 ; i < number_of_symbols ; i++) {
        queue_repair_symbol(cnx, bff, rss[i], fec_block);
    }
}

static __attribute__((always_inline)) size_t get_repair_payload_from_queue(picoquic_cnx_t *cnx, block_fec_framework_t *bff, size_t bytes_max, fec_frame_header_t *ffh, uint8_t *bytes){
    if (bff->repair_symbols_queue_length == 0)
        return 0;
    repair_symbol_t *rs = bff->repair_symbols_queue[bff->repair_symbols_queue_head].repair_symbol;
    // FIXME: temporarily ensure that the repair symbols are not split into multiple frames
    if (bytes_max < rs->data_length) {
        PROTOOP_PRINTF(cnx, "NOT ENOUGH BYTES TO SEND SYMBOL: %u < %u\n", bytes_max, rs->data_length);
        return 0;
    }
    size_t amount = ((rs->data_length - bff->queue_byte_offset) <= bytes_max) ? (rs->data_length - bff->queue_byte_offset) : bytes_max;
    // copy
    my_memcpy(bytes, rs->data + bff->queue_byte_offset, amount);
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
    if (bff->queue_byte_offset == rs->data_length) {
        // this symbol has been sent: free the symbol and remove it from the queue
        remove_item_at_index(cnx, bff, bff->repair_symbols_queue_head);
        bff->repair_symbols_queue_head = ((uint32_t) bff->repair_symbols_queue_head + 1) % MAX_QUEUED_REPAIR_SYMBOLS;
        bff->queue_byte_offset = 0;
        bff->queue_piece_offset = 0;
        bff->repair_symbols_queue_length--;
        args[0] = (uint32_t) bff->repair_symbols_queue_length;
    }
    return amount;
}

//TODO: currently unprovable
static __attribute__((always_inline)) int reserve_fec_frames(picoquic_cnx_t *cnx, block_fec_framework_t *bff, size_t size_max) {
    if (size_max <= sizeof(fec_frame_header_t))
        return -1;
    while (bff->repair_symbols_queue_length != 0) {
        // FIXME: bourrin
        fec_frame_t *ff = my_malloc(cnx, sizeof(fec_frame_t));
        if (!ff)
            return PICOQUIC_ERROR_MEMORY;
        uint8_t *bytes = my_malloc(cnx, (unsigned int) (size_max - (1 + sizeof(fec_frame_header_t))));
        if (!bytes)
            return PICOQUIC_ERROR_MEMORY;
        // copy the frame payload
        size_t payload_size = get_repair_payload_from_queue(cnx, bff, size_max - sizeof(fec_frame_header_t) - 1, &ff->header, bytes);
        if (!payload_size)
            return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        ff->data = bytes;
        reserve_frame_slot_t *slot = (reserve_frame_slot_t *) my_malloc(cnx, sizeof(reserve_frame_slot_t));
        if (!slot)
            return PICOQUIC_ERROR_MEMORY;
        my_memset(slot, 0, sizeof(reserve_frame_slot_t));
        slot->frame_type = FEC_TYPE;
        slot->nb_bytes = 1 + sizeof(fec_frame_header_t) + payload_size;
        slot->frame_ctx = ff;
        slot->is_congestion_controlled = true;

        size_t reserved_size = reserve_frames(cnx, 1, slot);
        if (reserved_size < slot->nb_bytes) {
            PROTOOP_PRINTF(cnx, "Unable to reserve frame slot\n");
            my_free(cnx, ff->data);
            my_free(cnx, ff);
            my_free(cnx, slot);
            return 1;
        }
    }
    return 0;
}

static __attribute__((always_inline)) int generate_and_queue_repair_symbols(picoquic_cnx_t *cnx, block_fec_framework_t *bff, bool flush){
    protoop_arg_t args[3];
    protoop_arg_t outs[1];
    args[0] = (protoop_arg_t) bff->current_block;
    args[1] = (protoop_arg_t) bff->fec_scheme;

    uint8_t n = 0;
    uint8_t k = 0;
    get_redundancy_parameters(cnx, bff->controller, flush, &n, &k);
    bff->current_block->total_source_symbols = bff->current_block->current_source_symbols;
    bff->current_block->total_repair_symbols = n - k;

    int ret = (int) run_noparam(cnx, "fec_generate_repair_symbols", 2, args, outs);
    if (!ret) {
        PROTOOP_PRINTF(cnx, "SUCCESSFULLY GENERATED\n");
        uint8_t i = 0;
        for_each_repair_symbol(bff->current_block, repair_symbol_t *rs) {
            rs->fec_block_number = bff->current_block_number;
            rs->symbol_number = i++;
        }

        queue_repair_symbols(cnx, bff, bff->current_block->repair_symbols, bff->current_block->total_repair_symbols, bff->current_block);
    }

    if ((int) run_noparam(cnx, "should_send_repair_symbols", 0, NULL, NULL)) {
        reserve_fec_frames(cnx, bff, PICOQUIC_MAX_PACKET_SIZE);
    }
    return ret;
}

static __attribute__((always_inline)) int sent_block(picoquic_cnx_t *cnx, block_fec_framework_t *ff, fec_block_t *fb) {
    if (fb != ff->current_block) free_fec_block(cnx, fb, false);
    else {
        free_fec_block(cnx, ff->current_block, true);
        ff->current_block_number++;
        ff->current_block = malloc_fec_block(cnx, ff->current_block_number);
        if (!ff->current_block)
            return -1;
        uint8_t n = 0;
        uint8_t k = 0;
        get_redundancy_parameters(cnx, ff->controller, false, &n, &k);
        ff->current_block->total_source_symbols = k;
        ff->current_block->total_repair_symbols = n - k;
    }
    return 0;
}

static __attribute__((always_inline)) source_fpid_t get_source_fpid(block_fec_framework_t *bff){
    source_fpid_t s;
    s.fec_block_number = bff->current_block_number;
    s.symbol_number = bff->current_block->current_source_symbols;
    return s;
}

// sets the source FPID of the Source Symbol and protects it.
static __attribute__((always_inline)) int protect_source_symbol(picoquic_cnx_t *cnx, block_fec_framework_t *bff, source_symbol_t *ss){
    ss->source_fec_payload_id.fec_block_number = bff->current_block_number;
    ss->source_fec_payload_id.symbol_number = bff->current_block->current_source_symbols;
    if (!add_source_symbol_to_fec_block(ss, bff->current_block))
        return -1;
    if (ready_to_send(cnx, bff)) {
        generate_and_queue_repair_symbols(cnx, bff, false);
        sent_block(cnx, bff,bff->current_block);
    }
    PROTOOP_PRINTF(cnx, "SYMBOL PROTECTED\n");
    return 0;
}

static __attribute__((always_inline)) int flush_fec_block(picoquic_cnx_t *cnx, block_fec_framework_t *bff) {
    fec_block_t *fb = bff->current_block;
    if (fb->current_source_symbols >= 1) {
        fb->total_source_symbols = fb->current_source_symbols;
        fb->total_repair_symbols = fb->current_source_symbols < fb->total_repair_symbols ? fb->current_source_symbols : fb->total_repair_symbols;
        PROTOOP_PRINTF(cnx, "FLUSH FEC BLOCK: %u source symbols, %u repair symbols\n", fb->total_source_symbols, fb->total_repair_symbols);
        generate_and_queue_repair_symbols(cnx, bff, true);
        sent_block(cnx, bff, fb);
    }
    return 0;
}