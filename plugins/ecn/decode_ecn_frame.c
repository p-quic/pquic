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
 * The interface for the decode_frame protocol operation is the same for all:
 * uint8_t* bytes = cnx->protoop_inputv[0]
 * const uint8_t* bytes_max = cnx->protoop_inputv[1]
 * uint64_t current_time = cnx->protoop_inputv[2]
 * int epoch = cnx->protoop_inputv[3]
 * int ack_needed = cnx->protoop_inputv[4]
 *
 * Output: uint8_t* bytes
 * cnx->protoop_outputv[0] = ack_needed
 */
protoop_arg_t decode_ecn_frame(picoquic_cnx_t *cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (uint8_t *) cnx->protoop_inputv[1];
    int ack_needed = (int) cnx->protoop_inputv[4];
    
    bpf_data *bpfd = get_bpf_data(cnx);

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
        
    cnx->protoop_outputc_callee = 1;
    cnx->protoop_outputv[0] = (protoop_arg_t) ack_needed;
    return (protoop_arg_t) bytes;
}