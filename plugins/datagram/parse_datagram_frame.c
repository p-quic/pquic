#include "../helpers.h"
#include "bpf.h"

protoop_arg_t parse_datagram_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    datagram_frame_t *frame = (datagram_frame_t *) my_malloc(cnx, sizeof(datagram_frame_t));
    uint8_t frame_type;
    my_memcpy(&frame_type, bytes, 1);
    bytes++;

    if (!frame) {
        //PROTOOP_PRINTF(cnx, "Failed to allocate memory for add_address_frame_t\n");
        bytes = NULL;
        goto exit;
    }

    if (HAS_ID(frame_type)) {
        size_t varint_len = picoquic_varint_decode(bytes, bytes_max - bytes, &frame->datagram_id);
        if (varint_len == 0) {
            //PROTOOP_PRINTF(cnx, "Failed to decode datagram frame id field\n");
            bytes = NULL;
            my_free(cnx, frame);
            frame = NULL;
            goto exit;
        }
        bytes += varint_len;
    } else {
        frame->datagram_id = 0;
    }

    if (HAS_LEN(frame_type)) {
        size_t varint_len = picoquic_varint_decode(bytes, bytes_max - bytes, &frame->length);
        if (varint_len == 0) {
            //PROTOOP_PRINTF(cnx, "Failed to decode datagram frame length field\n");
            bytes = NULL;
            my_free(cnx, frame);
            frame = NULL;
            goto exit;
        }
        bytes += varint_len;
    } else {
        frame->length = bytes_max - bytes;
    }

    if ((bytes_max - bytes) < frame->length) {
        //PROTOOP_PRINTF(cnx, "Not enough bytes left to parse datagram frame, expected %d got %d\n", frame->length, bytes_max - bytes);
        bytes = NULL;
        my_free(cnx, frame);
        frame = NULL;
        goto exit;
    }

    frame->datagram_data_ptr = bytes;
    bytes += frame->length;
    //PROTOOP_PRINTF(cnx, "Parsed a %d-byte long datagram frame\n", frame->length);

exit:
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) true); // should be acked asap
    set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) false); // must not be retransmitted
    return (protoop_arg_t) bytes;
}