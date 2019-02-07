#include "../framework/block_framework_sender.h"
#include "../framework/block_framework_receiver.c"


protoop_arg_t create_framework(picoquic_cnx_t *cnx)
{
    block_fec_framework_t *bffs = create_framework_sender(cnx);
    if (!bffs) {
        set_cnx(cnx, CNX_AK_OUTPUT, 0, (protoop_arg_t) NULL);
        set_cnx(cnx, CNX_AK_OUTPUT, 1, (protoop_arg_t) NULL);
    }
    void *bffr = create_framework_receiver(cnx);    // is currently always NULL
    set_cnx(cnx, CNX_AK_OUTPUT, 0, (protoop_arg_t) bffr);
    set_cnx(cnx, CNX_AK_OUTPUT, 1, (protoop_arg_t) bffs);
    return 0;
}