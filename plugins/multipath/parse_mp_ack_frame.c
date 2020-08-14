#include "bpf.h"

protoop_arg_t parse_mp_ack_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);

    uint64_t frame_type;
    bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_type);

    int ack_needed = 0;
    int is_retransmittable = 0;
    mp_ack_frame_t *frame = my_malloc(cnx, sizeof(mp_ack_frame_t));
    if (!frame) {
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
        PROTOOP_PRINTF(cnx, "Failed to allocate memory for mp_ack_frame_t\n");
        bytes = NULL;
        goto exit;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->uniflow_id)) == NULL)
    {
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
        PROTOOP_PRINTF(cnx, "Cannot parse path ID\n");
        my_free(cnx, frame);
        frame = NULL;
        goto exit;
    } else {
        frame->ack.is_ack_ecn = frame_type == MP_ACK_ECN_TYPE;

        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack.largest_acknowledged)) == NULL ||
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack.ack_delay))            == NULL) {
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
            PROTOOP_PRINTF(cnx, "Cannot parse largest acknowledged or ack delay\n");
            my_free(cnx, frame);
            frame = NULL;
            goto exit;
        }

        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack.ack_block_count)) == NULL) {
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
            PROTOOP_PRINTF(cnx, "Cannot parse ack block count\n");
            my_free(cnx, frame);
            frame = NULL;
            goto exit;
        }

        /** \todo FIXME */
        if (frame->ack.ack_block_count > 63) {
            PROTOOP_PRINTF(cnx, "MP_ACK frame parsing error: does not support ack_blocks > 63 elements\n");
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
            my_free(cnx, frame);
            frame = NULL;
            goto exit;
        }

        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack.first_ack_block)) == NULL) {
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
            PROTOOP_PRINTF(cnx, "Cannot parse first ACK block\n");
            my_free(cnx, frame);
            frame = NULL;
            goto exit;
        }

        for (int i = 0; i < frame->ack.ack_block_count; i++) {
            if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack.ack_blocks[i].gap))                  == NULL ||
                (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack.ack_blocks[i].additional_ack_block)) == NULL)
            {
                helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
                PROTOOP_PRINTF(cnx, "Cannot parse an ACK block\n");
                my_free(cnx, frame);
                frame = NULL;
                goto exit;
            }
        }

        if (frame->ack.is_ack_ecn && (bytes = helper_parse_ecn_block(cnx, bytes, bytes_max, &frame->ack.ecn_block)) == NULL) {
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
            PROTOOP_PRINTF(cnx, "Cannot parse ecn block\n");
            my_free(cnx, frame);
            frame = NULL;
            goto exit;
        }
    }

exit:
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
    set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
    return (protoop_arg_t) bytes;
}