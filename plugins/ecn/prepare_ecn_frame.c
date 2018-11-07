#include "picoquic.h"
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

/** FIXME BROKEN */
protoop_arg_t prepare_ecn_frame(picoquic_cnx_t *cnx)
{    
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    size_t bytes_max = (size_t) get_cnx(cnx, CNX_AK_INPUT, 1);
    size_t consumed = (size_t) get_cnx(cnx, CNX_AK_INPUT, 2);

    int ret = 0;
    bpf_data *bpfd = get_bpf_data(cnx);

    if (bytes_max < 25) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else {
        bytes[0] = ECN_FRAME_TYPE;
        prepare_u64(&bytes[1], bpfd->ecn_ect0_marked_pkts);
        prepare_u64(&bytes[9], bpfd->ecn_ect1_marked_pkts);
        prepare_u64(&bytes[17], bpfd->ecn_ect_ce_marked_pkts);
        consumed = 25;
    }

    set_cnx(cnx, CNX_AK_OUTPUT, 0, (protoop_arg_t) consumed);

    return (protoop_arg_t) ret;
}