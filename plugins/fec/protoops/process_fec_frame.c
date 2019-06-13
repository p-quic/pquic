#include "picoquic.h"
#include "../fec_protoops.h"


/**
 * cnx->protoop_inputv[0] = fec_frame_t* frame
 *
 * Output: uint8_t* bytes
 */
protoop_arg_t process_fec_frame(picoquic_cnx_t *cnx)
{
    fec_frame_t *frame = (fec_frame_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    PROTOOP_PRINTF(cnx, "PROCESS FEC FRAME\n");
    process_fec_frame_helper(cnx, frame);
    my_free(cnx, frame->data);
    return (protoop_arg_t) 0;
}