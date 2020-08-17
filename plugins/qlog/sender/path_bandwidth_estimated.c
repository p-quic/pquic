#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    picoquic_path_t* path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    LOG_EVENT(cnx, "recovery", "metrics_updated", "", "{\"cc_path\": \"%p\", \"bandwidth\": \"%lu\"}", (protoop_arg_t) path_x, get_path(path_x, AK_PATH_BANDWIDTH_ESTIMATE, 0));
    return 0;
}