#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"

#define VARINT_LEN(bytes) (1U << (((bytes)[0] & 0xC0) >> 6))


static uint8_t* frames_fixed_skip(uint8_t* bytes, const uint8_t* bytes_max, size_t size)
{
    return (bytes += size) <= bytes_max ? bytes : NULL;
}


static uint8_t* frames_varint_skip(uint8_t* bytes, const uint8_t* bytes_max)
{
    return bytes < bytes_max ? frames_fixed_skip(bytes, bytes_max, (uint64_t)VARINT_LEN(bytes)) : NULL;
}

static uint8_t* frames_uint8_decode(uint8_t* bytes, const uint8_t* bytes_max, uint8_t* n)
{
    if (bytes < bytes_max) {
        *n = *bytes++;
    } else {
        bytes = NULL;
    }
    return bytes;
}

static uint8_t* skip_connection_id_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    uint8_t cid_length;

    if ((bytes = frames_varint_skip(bytes+1, bytes_max))              != NULL &&
        (bytes = frames_uint8_decode(bytes,  bytes_max, &cid_length)) != NULL)
    {
        bytes = frames_fixed_skip(bytes, bytes_max, cid_length + 16);
    }

    return bytes;
}

/**
 * The interface for the decode_frame protocol operation is the same for all:
 * uint8_t* bytes = cnx->protoop_inputv[0]
 * const uint8_t* bytes_max = cnx->protoop_inputv[1]
 * uint64_t current_time = cnx->protoop_inputv[2]
 * int epoch = cnx->protoop_inputv[3]
 * int ack_needed = cnx->protoop_inputv[4]
 *
 * Output: uint8_t* bytes
 * cnx->protoop_outputv[0] = ack_needed
 */
protoop_arg_t decode_new_connection_id_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];
    int ack_needed = (int) cnx->protoop_inputv[4];

    ack_needed = 1;

    /* TODO: store the connection ID in order to support migration. */
    if ((bytes = skip_connection_id_frame(bytes, bytes_max)) == NULL) {
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_new_connection_id);
    }

    cnx->protoop_outputc_callee = 1;
    cnx->protoop_outputv[0] = (protoop_arg_t) ack_needed;
    return (protoop_arg_t) bytes;
}