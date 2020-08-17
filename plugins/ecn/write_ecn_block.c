#include "picoquic.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

static __attribute__((always_inline)) size_t varint_len(uint64_t val) {
    if (val <= 63) {
        return 1;
    } else if (val <= 16383) {
        return 2;
    } else if (val <= 1073741823) {
        return 4;
    } else if (val <= 4611686018427387903) {
        return 8;
    }
    return 0;
}

protoop_arg_t write_ecn_block(picoquic_cnx_t *cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    size_t bytes_max = (size_t) get_cnx(cnx, AK_CNX_INPUT, 1);
    picoquic_packet_context_t *pkt_ctx = (picoquic_packet_context_t *) get_cnx(cnx, AK_CNX_INPUT, 2);
    size_t consumed = 0;

    int ret = 0;

    ecn_counters_t *cnts = (ecn_counters_t *) get_pkt_ctx_metadata(cnx, pkt_ctx, META_PKT_CTX_ECN_COUNTERS);
    if (cnts == NULL) {
        goto exit;
    }

    if (bytes_max < varint_len(cnts->ecn_ect0_marked_pkts) + varint_len(cnts->ecn_ect1_marked_pkts) + varint_len(cnts->ecn_ect_ce_marked_pkts)) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else {
        consumed += picoquic_varint_encode(bytes + consumed, bytes_max - consumed, cnts->ecn_ect0_marked_pkts);
        consumed += picoquic_varint_encode(bytes + consumed, bytes_max - consumed, cnts->ecn_ect1_marked_pkts);
        consumed += picoquic_varint_encode(bytes + consumed, bytes_max - consumed, cnts->ecn_ect_ce_marked_pkts);
    }

exit:
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) consumed);
    return (protoop_arg_t) ret;
}