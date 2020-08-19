#include "bpf.h"

/**
 * See "header_parsed"
 * cnx->protoop_inputv[0] = picoquic_packet_header *ph
 * cnx->protoop_inputv[1] = picoquic_path_t *path
 * cnx->protoop_inputv[2] = size_t length
 *
 * Output: None
 */
protoop_arg_t header_parsed(picoquic_cnx_t *cnx)
{
    bpf_data *bpfd = get_bpf_data(cnx);
    picoquic_packet_header *ph = (picoquic_packet_header *) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_path_t *path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    picoquic_packet_context_t *pkt_ctx = (picoquic_packet_context_t *) get_path(path, AK_PATH_PKT_CTX, get_ph(ph, AK_PH_PC));

    ecn_counters_t *cnts = (ecn_counters_t *) get_pkt_ctx_metadata(cnx, pkt_ctx, META_PKT_CTX_ECN_COUNTERS);
    if (cnts == NULL) {
        cnts = my_malloc(cnx, sizeof(ecn_counters_t));
        if (cnts)
            my_memset(cnts, 0, sizeof(ecn_counters_t));
        set_pkt_ctx_metadata(cnx, pkt_ctx, META_PKT_CTX_ECN_COUNTERS, (protoop_arg_t) cnts);
    }

    if (cnts == NULL)
        return 0;

    switch (bpfd->ecn_val) {
        case 0x02:
            PROTOOP_PRINTF(cnx, "ECT0++\n");
            cnts->ecn_ect0_marked_pkts++;
            break;
        case 0x01:
            PROTOOP_PRINTF(cnx, "ECT1++\n");
            cnts->ecn_ect1_marked_pkts++;
            break;
        case 0x03:
            PROTOOP_PRINTF(cnx, "CE++\n");
            cnts->ecn_ect_ce_marked_pkts++;
            break;
        default:
            break;
    }

    return 0;
}