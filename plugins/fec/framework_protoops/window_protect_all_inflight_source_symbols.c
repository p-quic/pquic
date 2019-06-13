#include "../framework/window_framework_sender.h"
#include "../framework/window_framework_receiver.h"


protoop_arg_t window_select_symbols_to_protect(picoquic_cnx_t *cnx)
{
    fec_block_t *fb = (fec_block_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    window_fec_framework_t *wff = (window_fec_framework_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    bool flush = get_cnx(cnx, AK_CNX_INPUT, 2);
    fb->current_source_symbols = 0;
    PROTOOP_PRINTF(cnx, "SELECT, SMALLEST = %u, HIGHEST = %u\n", wff->smallest_in_transit, wff->highest_in_transit);
    for (int i = MAX(wff->smallest_in_transit, wff->highest_in_transit - MIN(RECEIVE_BUFFER_MAX_LENGTH, wff->highest_in_transit)) ; i <= wff->highest_in_transit ; i++) {
        source_symbol_t *ss = wff->fec_window[((uint32_t) i) % RECEIVE_BUFFER_MAX_LENGTH];
        if (ss && ss->source_fec_payload_id.raw == i) {
            fb->source_symbols[fb->current_source_symbols++] = ss;
        }
    }
    fb->total_source_symbols = fb->current_source_symbols;

    uint8_t n = 0;
    uint8_t k = 0;
    get_redundancy_parameters(cnx, wff->controller, flush, &n, &k);
    fb->total_repair_symbols = MIN(n-k, fb->total_source_symbols);

    return 0;
}