#include "bpf.h"

/**
 * Input: None
 *
 * Output: None
 */
protoop_arg_t set_output_file(picoquic_cnx_t *cnx)
{
    qlog_t *qlog = get_qlog_t(cnx);
    if (qlog->fd == -1) {
        qlog->fd = (int) get_cnx(cnx, AK_CNX_INPUT, 0);
        qlog->hdr.reference_time = qlog->head ? qlog->head->reference_time : picoquic_current_time();
        qlog->hdr.vantage_point = get_cnx(cnx, AK_CNX_CLIENT_MODE, 0) ? QLOG_VANTAGE_POINT_CLIENT : QLOG_VANTAGE_POINT_SERVER;
        write_header(cnx, qlog);
    }
    return 0;
}