#include "../framework/window_framework_sender.h"
#include "../framework/window_framework_receiver.h"
#include "../fec_scheme_protoops/rlc_fec_scheme_gf256.h"


protoop_arg_t create_framework(picoquic_cnx_t *cnx)
{
    fec_scheme_t receiver_scheme = (fec_scheme_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    fec_scheme_t sender_scheme = (fec_scheme_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    fec_redundancy_controller_t controller = (fec_scheme_t ) get_cnx(cnx, AK_CNX_INPUT, 2);
//    rlc_gf256_fec_scheme_t *fs = sender_scheme;
//    PROTOOP_PRINTF(cnx, "MULTABLE FROM FRAMEWORK = %p\n", (protoop_arg_t) fs->table_mul);
    window_fec_framework_t *wffs = create_framework_sender(cnx, controller, sender_scheme);
    if (!wffs) {
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) NULL);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) NULL);
        return PICOQUIC_ERROR_MEMORY;
    }
    window_fec_framework_receiver_t *wffr = create_framework_receiver(cnx, receiver_scheme);
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