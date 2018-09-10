#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

static uint8_t *parse_u64(uint8_t *bytes, uint64_t *val) {
    *val = *bytes++;
    for (int i = 1; i < 8; i++) {
        *val <<= 8;
        *val += *bytes++;
    }
    return bytes;
}

/**
 * cnx->protoop_inputv[0] = uint8_t* bytes
 * cnx->protoop_inputv[1] = const uint8_t* bytes_max
 *
 * Output: uint8_t* bytes
 */
protoop_arg_t decode_ecn_frame(picoquic_cnx_t *cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (uint8_t *) cnx->protoop_inputv[1];
    
    bpf_data *bpfd = (bpf_data *)get_opaque_data(cnx, ECN_OPAQUE_ID, sizeof(bpf_data));

    uint8_t first_byte = bytes[0];
    uint64_t ect0, ect1, ectce;

    if (first_byte != ECN_FRAME_TYPE || bytes_max - bytes < 25) {
        bytes = NULL;
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
    }
    else
    {
        bytes = parse_u64(bytes, &ect0);
        bytes = parse_u64(bytes, &ect1);
        bytes = parse_u64(bytes, &ectce);

        if (bpfd->ecn_ect0_remote_pkts <= ect0 && bpfd->ecn_ect1_remote_pkts <= ect1 && bpfd->ecn_ect_ce_remote_pkts <= ectce) {
            bpfd->ecn_ect0_remote_pkts = ect0;
            bpfd->ecn_ect1_remote_pkts = ect1;
            bpfd->ecn_ect_ce_remote_pkts = ectce;
        }
    }
        

    return (protoop_arg_t) bytes;
}