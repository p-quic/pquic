#include "bpf.h"

protoop_arg_t parse_mp_ack_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);

    int ack_needed = 0;
    int is_retransmittable = 0;
    mp_ack_frame_t *frame = my_malloc(cnx, sizeof(mp_ack_frame_t));
    if (!frame) {
        helper_protoop_printf(cnx, "Failed to allocate memory for mp_ack_frame_t\n", NULL, 0);
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
        set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->path_id)) == NULL)
    {
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            MP_ACK_TYPE);
        helper_protoop_printf(cnx, "Cannot parse path ID\n", NULL, 0);
        my_free(cnx, frame);
        frame = NULL;
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
        set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
        return (protoop_arg_t) NULL;
    } else {
        frame->ack.is_ack_ecn = 0;

        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack.largest_acknowledged)) == NULL ||
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack.ack_delay))            == NULL)
        {
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
                MP_ACK_TYPE);
            helper_protoop_printf(cnx, "Cannot parse largest acknowledged or ack delay\n", NULL, 0);
            my_free(cnx, frame);
            frame = NULL;
            set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
            set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
            set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
            return (protoop_arg_t) NULL;
        }

        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack.ack_block_count)) == NULL) {
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
                MP_ACK_TYPE);
            helper_protoop_printf(cnx, "Cannot parse ack block count\n", NULL, 0);
            my_free(cnx, frame);
            frame = NULL;
            set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
            set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
            set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
            return (protoop_arg_t) NULL;
        }

        /** \todo FIXME */
        if (frame->ack.ack_block_count > 63) {
            helper_protoop_printf(cnx, "MP_ACK frame parsing error: does not support ack_blocks > 63 elements\n", NULL, 0);
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
                MP_ACK_TYPE);
            my_free(cnx, frame);
            frame = NULL;
            set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
            set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
            set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
            return (protoop_arg_t) NULL;
        }

        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack.first_ack_block)) == NULL) {
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
                MP_ACK_TYPE);
            helper_protoop_printf(cnx, "Cannot parse first ACK block\n", NULL, 0);
            my_free(cnx, frame);
            frame = NULL;
            set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
            set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
            set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
            return (protoop_arg_t) NULL;
        }

        for (int i = 0; i < frame->ack.ack_block_count; i++) {
            if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack.ack_blocks[i].gap))                  == NULL ||
                (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack.ack_blocks[i].additional_ack_block)) == NULL)
            {
                helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
                    MP_ACK_TYPE);
                helper_protoop_printf(cnx, "Cannot parse an ACK block\n", NULL, 0);
                my_free(cnx, frame);
                frame = NULL;
                set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
                set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
                set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
                    return (protoop_arg_t) NULL;
            }
        }
    }

    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
    set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
    return (protoop_arg_t) bytes;
}