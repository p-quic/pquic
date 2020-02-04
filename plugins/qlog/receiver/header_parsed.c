#include "../bpf.h"

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
    qlog_t *qlog = get_qlog_t(cnx);
    picoquic_packet_header *ph = (picoquic_packet_header *) get_cnx(cnx, AK_CNX_INPUT, 0);
    my_memcpy(&qlog->pkt_hdr, ph, sizeof(qlog->pkt_hdr));
    return 0;
}