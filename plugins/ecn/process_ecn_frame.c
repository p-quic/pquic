#include "picoquic.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_ack_frame(picoquic_cnx_t *cnx)
{ 
    ecn_frame_t *frame = (ecn_frame_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    bpf_data *bpfd = get_bpf_data(cnx);

    if (bpfd->ecn_ect0_remote_pkts <= frame->ect0 && bpfd->ecn_ect1_remote_pkts <= frame->ect1 && bpfd->ecn_ect_ce_remote_pkts <= frame->ectce) {
        bpfd->ecn_ect0_remote_pkts = frame->ect0;
        bpfd->ecn_ect1_remote_pkts = frame->ect1;
        bpfd->ecn_ect_ce_remote_pkts = frame->ectce;
    }

    return 0;
}