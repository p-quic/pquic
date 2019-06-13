#include "../framework/block_framework_sender.h"
#include "../framework/block_framework_receiver.h"


protoop_arg_t create_framework(picoquic_cnx_t *cnx)
{
    fec_scheme_t receiver_scheme = (fec_scheme_t ) get_cnx(cnx, AK_CNX_INPUT, 0);
    fec_scheme_t sender_scheme = (fec_scheme_t ) get_cnx(cnx, AK_CNX_INPUT, 1);
    fec_redundancy_controller_t controller = (fec_scheme_t ) get_cnx(cnx, AK_CNX_INPUT, 2);
    block_fec_framework_t *bffs = create_framework_sender(cnx, controller, sender_scheme);
    if (!bffs) {
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) NULL);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) NULL);
    }
    void *bffr = create_framework_receiver(cnx, receiver_scheme);    // is currently always NULL
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) bffr);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) bffs);
    return 0;
}