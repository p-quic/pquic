#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    if (get_cnx(cnx, AK_CNX_RETURN_VALUE, 0)) {
        picoquic_packet_t *p = (picoquic_packet_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
        char *reason = (char *) get_cnx(cnx, AK_CNX_OUTPUT, 1);
        uint64_t retransmit_time = get_cnx(cnx, AK_CNX_OUTPUT, 2);
        LOG_EVENT(cnx, "recovery", "packet_lost", reason, "{\"path\": \"%p\", \"packet_type\": \"%s\", \"packet_number\": \"%" PRIu64 "\", \"retransmit_time\": %" PRIu64 "}", get_pkt(p, AK_PKT_SEND_PATH), (protoop_arg_t) ptype(get_pkt(p, AK_PKT_TYPE)), get_pkt(p, AK_PKT_SEQUENCE_NUMBER), retransmit_time);
    }
    return 0;
}