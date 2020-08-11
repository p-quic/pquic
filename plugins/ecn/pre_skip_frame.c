#include "bpf.h"

protoop_arg_t pre(picoquic_cnx_t *cnx) {
    get_bpf_data(cnx)->in_skip_frame = true;
    return 0;
}