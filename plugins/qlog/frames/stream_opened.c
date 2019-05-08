#include "../bpf.h"

protoop_arg_t stream_created(picoquic_cnx_t *cnx) {
    LOG_EVENT(cnx, "STREAMS", "STREAM_CREATED", "", "{\"ptr\": \"%p\", \"stream_id\": %lu}", get_cnx(cnx, AK_CNX_INPUT, 0), get_cnx(cnx, AK_CNX_INPUT, 1));
    return 0;
}