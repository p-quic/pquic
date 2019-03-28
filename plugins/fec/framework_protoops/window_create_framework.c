#include "../framework/window_framework_sender.c"
#include "../framework/window_framework_receiver.c"


protoop_arg_t create_framework(picoquic_cnx_t *cnx)
{
    window_fec_framework_t *wffs = create_framework_sender(cnx);
    if (!wffs) {
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) NULL);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) NULL);
        return PICOQUIC_ERROR_MEMORY;
    }
    window_fec_framework_receiver_t *wffr = create_framework_receiver(cnx);    // is currently always NULL
    if (!wffr) {
        my_free(cnx, wffs);
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) NULL);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) NULL);
        return PICOQUIC_ERROR_MEMORY;
    }
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) wffr);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) wffs);
    return 0;
}