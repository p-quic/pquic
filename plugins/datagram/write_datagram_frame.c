#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

protoop_arg_t write_datagram_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];
    struct iovec *message = (struct iovec *) cnx->protoop_inputv[2];
    size_t consumed = 0;

    if (message != NULL) {
        if (message->iov_base != NULL) {
            if (message->iov_len > 0) {
                if (bytes_max - bytes < 1 + message->iov_len) {
                    PROTOOP_PRINTF(cnx, "Not enough space in the buffer left to encode the DATAGRAM frame, expected %lu and got %lu\n", 1 + message->iov_len, bytes_max - bytes);
                    my_free(cnx, message->iov_base);
                    my_free(cnx, message);
                    return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                }

                if (bytes_max - bytes == 1 + message->iov_len) {
                    size_t varint_len = picoquic_varint_encode(bytes, bytes_max - bytes, FRAME_TYPE_DATAGRAM);
                    if (varint_len == 0) {
                        PROTOOP_PRINTF(cnx, "Failed to encode the frame type %lu as varint\n", FRAME_TYPE_DATAGRAM);
                        return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                    }
                    bytes += varint_len;
                    consumed += varint_len;
                } else {
                    size_t varint_len = picoquic_varint_encode(bytes, bytes_max - bytes, FRAME_TYPE_DATAGRAM_WITH_LEN);
                    if (varint_len == 0) {
                        PROTOOP_PRINTF(cnx, "Failed to encode the frame type %lu as varint\n", FRAME_TYPE_DATAGRAM_WITH_LEN);
                        return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                    }
                    bytes += varint_len;
                    consumed += varint_len;
                    varint_len = picoquic_varint_encode(bytes, bytes_max - bytes, message->iov_len);
                    if (varint_len == 0) {
                        PROTOOP_PRINTF(cnx, "Failed to encode the length %lu as varint\n", message->iov_len);
                        return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                    }
                    bytes += varint_len;
                    consumed += varint_len;
                }

                my_memcpy(bytes, message->iov_base, message->iov_len);
                consumed += message->iov_len;

                my_free(cnx, message->iov_base);
            } else {
                PROTOOP_PRINTF(cnx, "The frame ctx contained a length of 0\n");
            }
        } else {
            PROTOOP_PRINTF(cnx, "The frame ctx contained a NULL pointer\n");
        }
        my_free(cnx, message);
    }

    cnx->protoop_outputc_callee = 1;
    cnx->protoop_outputv[0] = (protoop_arg_t) consumed;

    return 0;
}