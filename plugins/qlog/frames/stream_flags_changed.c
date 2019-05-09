#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    LOG_EVENT(cnx, "STREAMS", "STREAM_FLAGS", "", "{\"ptr\": \"%p\", \"stream_id\": %lu, \"stream_flags\": %d}", get_cnx(cnx, AK_CNX_INPUT, 0), get_cnx(cnx, AK_CNX_INPUT, 1), get_cnx(cnx, AK_CNX_INPUT, 2));
    return 0;
}