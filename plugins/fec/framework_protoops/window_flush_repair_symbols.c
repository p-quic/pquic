#include "../framework/window_framework_sender.h"


protoop_arg_t window_flush_repair_symbols(picoquic_cnx_t *cnx)
{
    window_fec_framework_t *wff = (window_fec_framework_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    return (protoop_arg_t) flush_fec_window(cnx, wff);
}