#include "../framework/window_framework_sender.h"
#include "../framework/window_framework_receiver.h"


protoop_arg_t fec_protect_source_symbol(picoquic_cnx_t *cnx)
{
    window_fec_framework_t *wff = (window_fec_framework_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    source_symbol_t *ss = (source_symbol_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    return (protoop_arg_t) protect_source_symbol(cnx, wff, ss);
}