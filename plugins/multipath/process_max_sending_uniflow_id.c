#include "bpf.h"

/**
 * See PROTOOP_PARAM_PROCESS_TRANSPORT_PARAMETER
 */
protoop_arg_t process_max_sending_uniflow_id(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    size_t length = (size_t) get_cnx(cnx, AK_CNX_INPUT, 1);

    bpf_data *bpfd = get_bpf_data(cnx);
    bpfd->tp_received = 1;

    bytes = picoquic_frames_varint_decode(bytes, bytes + length, &bpfd->received_max_sending_uniflow);
    int inject_plugin = 1;

    return (protoop_arg_t) inject_plugin;
}