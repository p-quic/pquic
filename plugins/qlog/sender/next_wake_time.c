#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    LOG_EVENT(cnx, "TRANSPORT", "NEXT_WAKE_TIME", "", "{\"time\": %" PRIu64 "}", get_cnx(cnx, AK_CNX_NEXT_WAKE_TIME, 0));
    return 0;
}