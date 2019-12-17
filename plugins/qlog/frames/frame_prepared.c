#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    size_t consumed = (size_t) get_cnx(cnx, AK_CNX_RETURN_VALUE, 0);
    if (consumed > 0) {
        uint8_t *bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
        size_t skip_consumed = 0;
        int pure_ack = 0;
        helper_skip_frame(cnx, bytes, consumed, &skip_consumed, &pure_ack);
    }
    return 0;
}