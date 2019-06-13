#include "../fec.h"
#include "../../helpers.h"
#include "../fec_protoops.h"

#define INITIAL_SYMBOL_ID 1
#define MAX_QUEUED_REPAIR_SYMBOLS 6
#define RECEIVE_BUFFER_MAX_LENGTH 30

#define MIN(a, b) ((a < b) ? a : b)

typedef uint32_t fec_block_number;

typedef struct {
    repair_symbol_t *repair_symbol;
    uint8_t nss;
    uint8_t nrs;
} queue_item;

typedef struct {
    fec_scheme_t fec_scheme;
    fec_redundancy_controller_t controller;
    source_symbol_t *fec_window[RECEIVE_BUFFER_MAX_LENGTH];
    queue_item repair_symbols_queue[MAX_QUEUED_REPAIR_SYMBOLS];
    uint32_t max_id;
    uint32_t min_id;
    uint32_t highest_sent_id;
    uint32_t smallest_in_transit;
    uint32_t highest_in_transit;
    int window_length;
    int repair_symbols_queue_head;
    int repair_symbols_queue_length;
    int queue_byte_offset;  // current byte offset in the current repair symbol
    int queue_piece_offset; // current piece number of the current repair symbol
} window_fec_framework_t;


static __attribute__((always_inline)) window_fec_framework_t *create_framework_sender(picoquic_cnx_t *cnx, fec_redundancy_controller_t controller, fec_scheme_t fs) {
    window_fec_framework_t *wff = (window_fec_framework_t *) my_malloc(cnx, sizeof(window_fec_framework_t));
    if (!wff)
        return NULL;
    my_memset(wff, 0, sizeof(window_fec_framework_t));
    wff->highest_sent_id = INITIAL_SYMBOL_ID-1;
    wff->controller = controller;
    wff->fec_scheme = fs;
    return wff;
}

static __attribute__((always_inline)) void sfpid_has_landed(window_fec_framework_t *wff, source_fpid_t sfpid) {
    wff->smallest_in_transit = MAX(wff->smallest_in_transit, sfpid.raw);
    wff->highest_in_transit = MAX(wff->highest_in_transit, sfpid.raw);
}

static __attribute__((always_inline)) void sfpid_takes_off(window_fec_framework_t *wff, source_fpid_t sfpid) {
    wff->highest_in_transit = MAX(wff->highest_in_transit, sfpid.raw);
    wff->smallest_in_transit = MIN(wff->smallest_in_transit, sfpid.raw);
}

static __attribute__((always_inline)) bool ready_to_send(picoquic_cnx_t *cnx, window_fec_framework_t *wff) {
    uint8_t k = 0;
    get_redundancy_parameters(cnx, wff->controller, false, NULL, &k);
    return (wff->max_id-wff->highest_sent_id >= k);
}

static __attribute__((always_inline)) bool has_repair_symbol_at_index(window_fec_framework_t *wff, int idx) {
    return wff->repair_symbols_queue[idx].repair_symbol != NULL;
}

static __attribute__((always_inline)) void remove_item_at_index(picoquic_cnx_t *cnx, window_fec_framework_t *wff, int idx) {
    free_repair_symbol(cnx, wff->repair_symbols_queue[idx].repair_symbol);
    wff->repair_symbols_queue[idx].repair_symbol = NULL;
    wff->repair_symbols_queue[idx].nss = 0;
    wff->repair_symbols_queue[idx].nrs = 0;
}

static __attribute__((always_inline)) void put_item_at_index(window_fec_framework_t *wff, int idx, repair_symbol_t *rs, uint8_t nss, uint8_t nrs) {
    wff->repair_symbols_queue[idx].repair_symbol = rs;
    wff->repair_symbols_queue[idx].nss = nss;
    wff->repair_symbols_queue[idx].nrs = nrs;
}

// adds a repair symbol in the queue waiting for the symbol to be sent
static __attribute__((always_inline)) void queue_repair_symbol(picoquic_cnx_t *cnx, window_fec_framework_t *wff, repair_symbol_t *rs, fec_block_t *fb){
    int idx = ((uint32_t) ((uint32_t) wff->repair_symbols_queue_head + wff->repair_symbols_queue_length)) % MAX_QUEUED_REPAIR_SYMBOLS;
    if (has_repair_symbol_at_index(wff, idx)) {
        remove_item_at_index(cnx, wff, idx);
        if (wff->repair_symbols_queue_length > 1 && wff->repair_symbols_queue_head == idx) {
            // the head is the next symbol
            wff->repair_symbols_queue_head = ((uint32_t) ( (uint32_t) wff->repair_symbols_queue_head + 1)) % MAX_QUEUED_REPAIR_SYMBOLS;
            wff->queue_byte_offset = 0;
        }
        wff->repair_symbols_queue_length--;
    }
    put_item_at_index(wff, idx, rs, fb->total_source_symbols, fb->total_repair_symbols);
    if (wff->repair_symbols_queue_length == 0) {
        wff->repair_symbols_queue_head = idx;
        wff->queue_byte_offset = 0;
    }
    wff->repair_symbols_queue_length++;
}

// adds a repair symbol in the queue waiting for the symbol to be sent
static __attribute__((always_inline)) void queue_repair_symbols(picoquic_cnx_t *cnx, window_fec_framework_t *wff, repair_symbol_t *rss[], int number_of_symbols, fec_block_t *fec_block){
    int i;
    for (i = 0 ; i < number_of_symbols ; i++) {
        queue_repair_symbol(cnx, wff, rss[i], fec_block);
    }
}

static __attribute__((always_inline)) size_t get_repair_payload_from_queue(picoquic_cnx_t *cnx, window_fec_framework_t *wff, size_t bytes_max, fec_frame_header_t *ffh, uint8_t *bytes){
    if (wff->repair_symbols_queue_length == 0)
        return 0;
    repair_symbol_t *rs = wff->repair_symbols_queue[wff->repair_symbols_queue_head].repair_symbol;
    // FIXME: temporarily ensure that the repair symbols are not split into multiple frames
    if (bytes_max < rs->data_length) {
        PROTOOP_PRINTF(cnx, "NOT ENOUGH BYTES TO SEND SYMBOL: %u < %u\n", bytes_max, rs->data_length);
        return 0;
    }
    size_t amount = ((rs->data_length - wff->queue_byte_offset) <= bytes_max) ? (rs->data_length - wff->queue_byte_offset) : bytes_max;
    // copy
    my_memcpy(bytes, rs->data + wff->queue_byte_offset, amount);
    // move forward in the symbol's buffer
    wff->queue_byte_offset += amount;
    wff->queue_piece_offset++;

    ffh->repair_fec_payload_id = rs->repair_fec_payload_id;
    PROTOOP_PRINTF(cnx, "GET RS WITH FEC SCHEME SPECIFIC %u\n", ffh->repair_fec_payload_id.fec_scheme_specific);
    ffh->offset = (uint8_t) wff->queue_piece_offset;
    ffh->nss = wff->repair_symbols_queue[wff->repair_symbols_queue_head].nss;
    ffh->nrs = wff->repair_symbols_queue[wff->repair_symbols_queue_head].nrs;
    ffh->data_length = (uint16_t) amount;
    ffh->fin_bit = wff->queue_byte_offset == rs->data_length;
    protoop_arg_t args[2];
    args[0] = amount;
    args[1] = bytes_max;
    if (wff->queue_byte_offset == rs->data_length) {
        // this symbol has been sent: free the symbol and remove it from the queue
        remove_item_at_index(cnx, wff, wff->repair_symbols_queue_head);
        wff->repair_symbols_queue_head = ((uint32_t) wff->repair_symbols_queue_head + 1) % MAX_QUEUED_REPAIR_SYMBOLS;
        wff->queue_byte_offset = 0;
        wff->queue_piece_offset = 0;
        wff->repair_symbols_queue_length--;
        args[0] = (uint32_t) wff->repair_symbols_queue_length;
    }
    return amount;
}

//TODO: currently unprovable
static __attribute__((always_inline)) int reserve_fec_frames(picoquic_cnx_t *cnx, window_fec_framework_t *wff, size_t size_max) {
    if (size_max <= sizeof(fec_frame_header_t))
        return -1;
    while (wff->repair_symbols_queue_length != 0) {
        // FIXME: bourrin
        fec_frame_t *ff = my_malloc(cnx, sizeof(fec_frame_t));
        if (!ff)
            return PICOQUIC_ERROR_MEMORY;
        uint8_t *bytes = my_malloc(cnx, (unsigned int) (size_max - (1 + sizeof(fec_frame_header_t))));
        if (!bytes)
            return PICOQUIC_ERROR_MEMORY;
        // copy the frame payload
        size_t payload_size = get_repair_payload_from_queue(cnx, wff, size_max - sizeof(fec_frame_header_t) - 1, &ff->header, bytes);
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
        PROTOOP_PRINTF(cnx, "RESERVE FEC FRAMES\n");
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

static __attribute__((always_inline)) void remove_source_symbol_from_window(picoquic_cnx_t *cnx, window_fec_framework_t *wff, source_symbol_t *ss){
    if (ss) {
        int idx = (int) (ss->source_fec_payload_id.raw % RECEIVE_BUFFER_MAX_LENGTH);
        if (wff->fec_window[idx] && wff->fec_window[idx]->source_fec_payload_id.raw == ss->source_fec_payload_id.raw) {
            if (wff->fec_window[idx]->source_fec_payload_id.raw == wff->min_id) wff->min_id++;
            free_source_symbol(cnx, wff->fec_window[idx]);
            wff->fec_window[idx] = NULL;
            // one less symbol
            wff->window_length--;
        }
    }
}


static __attribute__((always_inline)) void remove_source_symbols_from_block_and_window(picoquic_cnx_t *cnx, window_fec_framework_t *wff, fec_block_t *fb){
    for (int i = 0 ; i < fb->total_source_symbols ; i++) {
        source_symbol_t *ss = fb->source_symbols[i];
        remove_source_symbol_from_window(cnx, wff, ss);
        fb->source_symbols[i] = NULL;
    }
    fb->total_source_symbols = 0;
    fb->current_source_symbols = 0;
}

static __attribute__((always_inline)) int generate_and_queue_repair_symbols(picoquic_cnx_t *cnx, window_fec_framework_t *wff, bool flush){
    protoop_arg_t args[3];
    protoop_arg_t outs[1];

    // build the block to generate the symbols

    fec_block_t *fb = malloc_fec_block(cnx, 0);
    if (!fb)
        return PICOQUIC_ERROR_MEMORY;

    args[0] = (protoop_arg_t) fb;
    args[1] = (protoop_arg_t) wff;
    args[2] = flush;

    int ret = 0;
    bool should_send_rs = (bool) run_noparam(cnx, "should_send_repair_symbols", 0, NULL, NULL);
    if (should_send_rs) {
        ret = (int) run_noparam(cnx, "window_select_symbols_to_protect", 3, args, outs);
        if (ret) {
            my_free(cnx, fb);
            PROTOOP_PRINTF(cnx, "ERROR WHEN SELECTING THE SYMBOLS TO PROTECT\n");
            return ret;
        }
        if (fb->total_source_symbols > 0) {
            PROTOOP_PRINTF(cnx, "PROTECT FEC BLOCK OF %u INFLIGHT SYMBOLS, SFPID = %u\n", fb->total_source_symbols, fb->source_symbols[0]->source_fec_payload_id.raw);
            args[1] = (protoop_arg_t) wff->fec_scheme;
            ret = (int) run_noparam(cnx, "fec_generate_repair_symbols", 2, args, outs);
            if (!ret) {
                PROTOOP_PRINTF(cnx, "SUCCESSFULLY GENERATED\n");
                uint8_t i = 0;
                for_each_repair_symbol(fb, repair_symbol_t *rs) {
                        rs->fec_block_number = 0;
                        rs->symbol_number = i++;
                        rs->fec_scheme_specific = fb->source_symbols[0]->source_fec_payload_id.raw;
                    }
                queue_repair_symbols(cnx, wff, fb->repair_symbols, fb->total_repair_symbols, fb);
                uint32_t last_id = fb->source_symbols[fb->total_source_symbols-1]->source_fec_payload_id.raw;
                // we don't free the source symbols: they can still be used afterwards
                // we don't free the repair symbols, they are queued and will be free afterwards
                // so we only free the fec block
                wff->highest_sent_id = MAX(last_id, wff->highest_sent_id);
                reserve_fec_frames(cnx, wff, PICOQUIC_MAX_PACKET_SIZE);
            }
        } else {
            PROTOOP_PRINTF(cnx, "NO SYMBOL TO PROTECT\n");
        }
    }


    my_free(cnx, fb);
    return ret;
}


static __attribute__((always_inline)) source_fpid_t get_source_fpid(window_fec_framework_t *wff){
    source_fpid_t s;
    s.raw = wff->max_id + 1;
    return s;
}

static __attribute__((always_inline)) int protect_source_symbol(picoquic_cnx_t *cnx, window_fec_framework_t *wff, source_symbol_t *ss){
    ss->source_fec_payload_id.raw = ++wff->max_id;
    int idx = (int) (ss->source_fec_payload_id.raw % RECEIVE_BUFFER_MAX_LENGTH);
    remove_source_symbol_from_window(cnx, wff, wff->fec_window[idx]);
    wff->fec_window[idx] = ss;
    if (wff->window_length == 0) {
        wff->min_id = wff->max_id = ss->source_fec_payload_id.raw;
    }
    // one more symbol
    wff->window_length++;


    if (ready_to_send(cnx, wff)) {
        generate_and_queue_repair_symbols(cnx, wff, false);
    }
    return 0;
}

static __attribute__((always_inline)) int flush_fec_window(picoquic_cnx_t *cnx, window_fec_framework_t *wff) {
    if (wff->max_id - wff->highest_sent_id >= 1) {
        PROTOOP_PRINTF(cnx, "FLUSH FEC WINDOW\n");
        generate_and_queue_repair_symbols(cnx, wff, true);
    }
    return 0;
}