#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

protoop_arg_t parse_mp_ack_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 0;
    int is_retransmittable = 0;
    mp_ack_frame_t *frame = my_malloc(cnx, sizeof(mp_ack_frame_t));
    if (!frame) {
        helper_protoop_printf(cnx, "Failed to allocate memory for mp_ack_frame_t\n", NULL, 0);
        cnx->protoop_outputc_callee = 3;
        cnx->protoop_outputv[0] = (protoop_arg_t) frame;
        cnx->protoop_outputv[1] = (protoop_arg_t) ack_needed;
        cnx->protoop_outputv[2] = (protoop_arg_t) is_retransmittable;
        return (protoop_arg_t) NULL;
    }

    if ((bytes = helper_frames_varint_decode(bytes+1, bytes_max, &frame->path_id)) == NULL)
    {
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_new_connection_id);
        my_free(cnx, frame);
        frame = NULL;
    } else {
        /* I'm really lazy, but this should do the trick */
        ack_frame_t *ack_frame;
        bytes = helper_parse_frame(cnx, picoquic_frame_type_ack, bytes - 1, bytes_max, (void **) &ack_frame, &ack_needed, &is_retransmittable);
        if (bytes) {
            /* Simply perform a memcpy */
            my_memcpy(&frame->ack, ack_frame, sizeof(ack_frame_t));
            /* And free ack_frame */
            my_free(cnx, ack_frame);
        }
    }

    cnx->protoop_outputc_callee = 3;
    cnx->protoop_outputv[0] = (protoop_arg_t) frame;
    cnx->protoop_outputv[1] = (protoop_arg_t) ack_needed;
    cnx->protoop_outputv[2] = (protoop_arg_t) is_retransmittable;
    return (protoop_arg_t) bytes;
}