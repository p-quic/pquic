#include "../framework/window_framework_sender.c"
#include "../framework/window_framework_receiver.c"


protoop_arg_t window_get_source_fpid(picoquic_cnx_t *cnx)
{
    window_fec_framework_t *wff = (window_fec_framework_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    return (protoop_arg_t) get_source_fpid(wff).raw;
}