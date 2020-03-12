#include "bpf.h"

protoop_arg_t parse_path_update(picoquic_cnx_t *cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);

    int ack_needed = 1;
    int is_retransmittable = 1;
    path_update_t *frame = my_malloc(cnx, sizeof(path_update_t));
    if (!frame) {
        helper_protoop_printf(cnx, "Failed to allocate memory for path_update_t\n", NULL, 0);
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
        set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->closed_path_id)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->proposed_path_id)) == NULL)
    {
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, PATH_UPDATE_TYPE);
        my_free(cnx, frame);
        frame = NULL;
    }

    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
    set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
    return (protoop_arg_t) bytes;
}