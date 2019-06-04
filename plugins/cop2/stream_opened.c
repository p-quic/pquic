#include "../helpers.h"
#include "bpf.h"


/**
 * See PROTOOP_NOPARAM_STREAM_OPENED
 */
protoop_arg_t stream_opened(picoquic_cnx_t *cnx)
{
    get_cop2_metrics(cnx)->quic_metrics.streams_opened++;
    return 0;
}