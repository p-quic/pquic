#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    if (get_cnx(cnx, AK_CNX_RETURN_VALUE, 0)) {
        LOG_EVENT(cnx, "TRANSPORT", "ACK_NEEDED", "", "{\"path\": \"%p\", \"pc\": %d}", get_cnx(cnx, AK_CNX_INPUT, 2), get_cnx(cnx, AK_CNX_INPUT, 1));
    }
    return 0;
}