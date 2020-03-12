#include "../bpf.h"

protoop_arg_t stream_created(picoquic_cnx_t *cnx) {
    LOG_EVENT(cnx, "transport", "stream_state_updated", "", "{\"ptr\": \"%p\", \"stream_id\": \"%" PRIu64 "\", \"new\": \"open\"}", get_cnx(cnx, AK_CNX_INPUT, 0), get_cnx(cnx, AK_CNX_INPUT, 1));
    return 0;
}