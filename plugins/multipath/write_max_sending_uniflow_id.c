#include "bpf.h"

/**
 * See PROTOOP_PARAM_WRITE_TRANSPORT_PARAMETER
 */
protoop_arg_t write_max_sending_uniflow_id(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint16_t max_length = (const uint16_t) get_cnx(cnx, AK_CNX_INPUT, 1);

    size_t consumed = 0;

    uint64_t max_sending_uniflow_id = 2;
    size_t value_l = picoquic_varint_encode(bytes, max_length, max_sending_uniflow_id);

    if (value_l > 0) {
        consumed = value_l;
    }

    return (protoop_arg_t) consumed;
}