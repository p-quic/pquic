#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    if (get_cnx(cnx, AK_CNX_RETURN_VALUE, 0)) {
        char *reason = (char *) get_cnx(cnx, AK_CNX_OUTPUT, 2);
        LOG_EVENT(cnx, "RECOVERY", "RETRANSMIT_NEEDED", reason, "{\"path\": \"%p\", \"pc\": %d}", get_cnx(cnx, AK_CNX_INPUT, 1), get_cnx(cnx, AK_CNX_INPUT, 0));
    }
    return 0;
}