#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    if (get_cnx(cnx, AK_CNX_RETURN_VALUE, 0)) {
        picoquic_packet_t *p = (picoquic_packet_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
        char *reason = (char *) get_cnx(cnx, AK_CNX_OUTPUT, 1);
        uint64_t retransmit_time = get_cnx(cnx, AK_CNX_OUTPUT, 2);
        LOG_EVENT(cnx, "RECOVERY", "RETRANSMIT_NEEDED", reason, "{\"path\": \"%p\", \"pc\": %d, \"pn\": %lu, \"retransmit_time\": %lu}", get_pkt(p, AK_PKT_SEND_PATH), get_pkt(p, AK_PKT_CONTEXT), get_pkt(p, AK_PKT_SEQUENCE_NUMBER), retransmit_time);
    }
    return 0;
}