#include "bpf.h"

protoop_arg_t parse_mp_ack_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);

    uint64_t frame_type;
    bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_type);

    int ack_needed = 0;
    int is_retransmittable = 0;
    uniflows_frame_t *frame = my_malloc(cnx, sizeof(uniflows_frame_t));
    if (!frame) {
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
        PROTOOP_PRINTF(cnx, "Failed to allocate memory for mp_ack_frame_t\n");
        bytes = NULL;
        goto exit;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->sequence)) == NULL)
    {
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
        PROTOOP_PRINTF(cnx, "Cannot parse sequence\n");
        my_free(cnx, frame);
        frame = NULL;
        goto exit;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->receiving_uniflows)) == NULL)
    {
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
        PROTOOP_PRINTF(cnx, "Cannot parse receiving_uniflows\n");
        my_free(cnx, frame);
        frame = NULL;
        goto exit;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->active_sending_uniflows)) == NULL)
    {
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
        PROTOOP_PRINTF(cnx, "Cannot parse active_sending_uniflows\n");
        my_free(cnx, frame);
        frame = NULL;
        goto exit;
    }

    for (int i = 0; i < frame->receiving_uniflows; i++) {
        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->receiving_uniflow_infos[i].uniflow_id)) == NULL)
        {
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
            PROTOOP_PRINTF(cnx, "Cannot parse uniflow_id\n");
            my_free(cnx, frame);
            frame = NULL;
            goto exit;
        }

        if (bytes >= bytes_max) {
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
            PROTOOP_PRINTF(cnx, "Cannot parse local_address_id\n");
            my_free(cnx, frame);
            frame = NULL;
            goto exit;
        }
        my_memcpy(&frame->receiving_uniflow_infos[i].local_address_id, bytes, 1);
        bytes++;
    }

    for (int i = 0; i < frame->active_sending_uniflows; i++) {
        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->sending_uniflow_infos[i].uniflow_id)) == NULL)
        {
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
            PROTOOP_PRINTF(cnx, "Cannot parse uniflow_id\n");
            my_free(cnx, frame);
            frame = NULL;
            goto exit;
        }

        if (bytes >= bytes_max) {
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
            PROTOOP_PRINTF(cnx, "Cannot parse local_address_id\n");
            my_free(cnx, frame);
            frame = NULL;
            goto exit;
        }
        my_memcpy(&frame->sending_uniflow_infos[i].local_address_id, bytes, 1);
        bytes++;
    }

    exit:
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
    set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
    return (protoop_arg_t) bytes;
}