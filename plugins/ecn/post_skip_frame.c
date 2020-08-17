#include "bpf.h"

protoop_arg_t post(picoquic_cnx_t *cnx) {
    get_bpf_data(cnx)->in_skip_frame = false;
    return 0;
}