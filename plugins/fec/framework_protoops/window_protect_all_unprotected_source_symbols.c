#include "../framework/window_framework_sender.h"
#include "../framework/window_framework_receiver.h"


protoop_arg_t window_select_symbols_to_protect(picoquic_cnx_t *cnx)
{
    fec_block_t *fb = (fec_block_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    window_fec_framework_t *wff = (window_fec_framework_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    bool flush = get_cnx(cnx, AK_CNX_INPUT, 2);
    uint32_t min_start_index = (wff->max_id > RECEIVE_BUFFER_MAX_LENGTH-1) ? (wff->max_id - (RECEIVE_BUFFER_MAX_LENGTH-1)) : 0;
    uint32_t start_index = MAX(wff->highest_sent_id + 1, min_start_index);
    for (int i = start_index ; i <= wff->max_id ; i++) {
        fb->source_symbols[i-start_index] = wff->fec_window[((uint32_t) i) % RECEIVE_BUFFER_MAX_LENGTH];
        fb->current_source_symbols++;
    }
    fb->total_source_symbols = fb->current_source_symbols;

    uint8_t n = 0;
    uint8_t k = 0;
    get_redundancy_parameters(cnx, wff->controller, flush, &n, &k);
    fb->total_repair_symbols = MIN(n-k, fb->total_source_symbols);

    return 0;
}