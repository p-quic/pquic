#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    helper_log_frame(cnx, "{\"frame_type\": \"handshake_done\"}");
    return 0;
}