#include "../framework/window_framework_sender.c"
#include "../framework/window_framework_receiver.c"


protoop_arg_t window_select_symbols_to_protect(picoquic_cnx_t *cnx)
{
    fec_block_t *fb = (fec_block_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    window_fec_framework_t *wff = (window_fec_framework_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    for (int i = wff->highest_sent_id + 1 ; i <= wff->max_id ; i++) {
        fb->source_symbols[i-(wff->highest_sent_id+1)] = wff->fec_window[((uint32_t) i) % RECEIVE_BUFFER_MAX_LENGTH];
        fb->current_source_symbols++;
    }
    fb->total_source_symbols = fb->current_source_symbols;
    fb->total_repair_symbols = MIN(wff->n-wff->k, fb->total_source_symbols);

    return 0;
}