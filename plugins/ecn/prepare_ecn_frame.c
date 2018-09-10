#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

static void prepare_u64(uint8_t *bytes, uint64_t val) {
    *(bytes + 7) = val;
    for (int i = 6; i>= 0; i--) {
        val >>= 8;
        *(bytes + i) = val;
    }
}

protoop_arg_t prepare_ecn_frame(picoquic_cnx_t *cnx)
{    
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    size_t bytes_max = (size_t) cnx->protoop_inputv[1];
    size_t consumed = (size_t) cnx->protoop_inputv[2];

    int ret = 0;
    bpf_data *bpfd = (bpf_data *) get_opaque_data(cnx, ECN_OPAQUE_ID, sizeof(bpf_data));

    if (bytes_max < 25) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else {
        bytes[0] = ECN_FRAME_TYPE;
        prepare_u64(&bytes[1], bpfd->ecn_ect0_marked_pkts);
        prepare_u64(&bytes[9], bpfd->ecn_ect1_marked_pkts);
        prepare_u64(&bytes[17], bpfd->ecn_ect_ce_marked_pkts);
        consumed = 25;
    }

    cnx->protoop_outputc_callee = 1;
    cnx->protoop_outputv[0] = (protoop_arg_t) consumed;

    return (protoop_arg_t) ret;
}