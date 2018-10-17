#include "picoquic_internal.h"
#include "bpf.h"


/**
 * cnx->protoop_inputv[0] = fec_frame_t* frame
 *
 * Output: uint8_t* bytes
 */
protoop_arg_t decode_fec_frame(picoquic_cnx_t *cnx)
{
    fec_frame_t *frame = (fec_frame_t *) cnx->protoop_inputv[0];
    process_fec_frame_helper(cnx, frame);
    return (protoop_arg_t) 0;
}