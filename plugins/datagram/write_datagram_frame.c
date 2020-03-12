#include "../helpers.h"
#include "bpf.h"

protoop_arg_t write_datagram_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    datagram_frame_t *frame = (datagram_frame_t*) get_cnx(cnx, AK_CNX_INPUT, 2);
    size_t consumed = 0;

    if (frame != NULL) {
        if (frame->datagram_data_ptr != NULL) {
            if (frame->length > 0) {
                uint8_t frame_type = FT_DATAGRAM | FT_DATAGRAM_LEN;
                size_t length_required = 1 + varint_len(frame->length) + frame->length;
#ifdef DATAGRAM_WITH_ID
                frame_type |= FT_DATAGRAM_ID;
                length_required += varint_len(frame->datagram_id);
#endif

                if (bytes_max - bytes < length_required)  {
                    PROTOOP_PRINTF(cnx, "Not enough space in the buffer left to encode the DATAGRAM frame, expected %" PRIu64 " and got %" PRIu64 "\n", length_required, bytes_max - bytes);
                    my_free(cnx, frame->datagram_data_ptr);
                    my_free(cnx, frame);
                    return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                }

                size_t varint_len = picoquic_varint_encode(bytes, bytes_max - bytes, frame_type);
                if (varint_len == 0) {
                    PROTOOP_PRINTF(cnx, "Failed to encode the frame type %" PRIu64 " as varint\n", frame_type);
                    return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                }
                bytes += varint_len;
                consumed += varint_len;

                if(HAS_ID(frame_type)) {
                    varint_len = picoquic_varint_encode(bytes, bytes_max - bytes, frame->datagram_id);
                    if (varint_len == 0) {
                        PROTOOP_PRINTF(cnx, "Failed to encode the datagram id %" PRIu64 " as varint\n", frame->datagram_id);
                        return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                    }
                    bytes += varint_len;
                    consumed += varint_len;
                }
                if(HAS_LEN(frame_type)) {
                    varint_len = picoquic_varint_encode(bytes, bytes_max - bytes, frame->length);
                    if (varint_len == 0) {
                        PROTOOP_PRINTF(cnx, "Failed to encode the length %" PRIu64 " as varint\n", frame->length);
                        return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                    }
                    bytes += varint_len;
                    consumed += varint_len;
                }
                my_memcpy(bytes, frame->datagram_data_ptr, frame->length);
                consumed += frame->length;
                datagram_memory_t *m = get_datagram_memory(cnx);
                if (frame->length <= m->send_buffer) {
                    m->send_buffer -= frame->length;
                } else {
                    m->send_buffer = 0;
                }
                PROTOOP_PRINTF(cnx, "Send buffer size %d\n", m->send_buffer);

                my_free(cnx, frame->datagram_data_ptr);
            } else {
                PROTOOP_PRINTF(cnx, "The frame ctx contained a length of 0\n");
            }
        } else {
            PROTOOP_PRINTF(cnx, "The frame ctx contained a NULL pointer\n");
        }
        my_free(cnx, frame);
    }

    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) consumed);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);

    return 0;
}