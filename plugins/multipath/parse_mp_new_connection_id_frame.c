#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

protoop_arg_t parse_mp_new_connection_id_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    mp_new_connection_id_frame_t *frame = my_malloc(cnx, sizeof(mp_new_connection_id_frame_t));
    if (!frame) {
        helper_protoop_printf(cnx, "Failed to allocate memory for new_connection_id_frame_t\n", NULL, 0);
        cnx->protoop_outputc_callee = 3;
        cnx->protoop_outputv[0] = (protoop_arg_t) frame;
        cnx->protoop_outputv[1] = (protoop_arg_t) ack_needed;
        cnx->protoop_outputv[2] = (protoop_arg_t) is_retransmittable;
        return (protoop_arg_t) NULL;
    }

    if ((bytes = helper_frames_varint_decode(bytes+1, bytes_max, &frame->path_id))                 == NULL ||
        (bytes = helper_frames_varint_decode(bytes, bytes_max, &frame->ncidf.sequence))            == NULL ||
        (bytes = helper_frames_uint8_decode(bytes, bytes_max, &frame->ncidf.connection_id.id_len)) == NULL ||
        (bytes = (bytes + frame->ncidf.connection_id.id_len + 16 <= bytes_max ? bytes : NULL))     == NULL)
    {
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_new_connection_id);
        my_free(cnx, frame);
        frame = NULL;
    }
    else
    {
        /* Memory bounds have been checked, so everything should be safe now */
        my_memcpy(&frame->ncidf.connection_id.id, bytes, frame->ncidf.connection_id.id_len);
        bytes += frame->ncidf.connection_id.id_len;
        my_memcpy(&frame->ncidf.stateless_reset_token, bytes, 16);
        bytes += 16;
    }

    cnx->protoop_outputc_callee = 3;
    cnx->protoop_outputv[0] = (protoop_arg_t) frame;
    cnx->protoop_outputv[1] = (protoop_arg_t) ack_needed;
    cnx->protoop_outputv[2] = (protoop_arg_t) is_retransmittable;
    return (protoop_arg_t) bytes;
}