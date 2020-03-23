#include "bpf.h"

protoop_arg_t parse_mp_new_connection_id_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);

    int ack_needed = 1;
    int is_retransmittable = 1;
    mp_new_connection_id_frame_t *frame = my_malloc(cnx, sizeof(mp_new_connection_id_frame_t));
    if (!frame) {
        helper_protoop_printf(cnx, "Failed to allocate memory for new_connection_id_frame_t\n", NULL, 0);
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
        set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->path_id))  == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ncidf.sequence))            == NULL ||
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

    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
    set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
    return (protoop_arg_t) bytes;
}