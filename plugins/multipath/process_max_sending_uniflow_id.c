#include "bpf.h"

/**
 * See PROTOOP_PARAM_PROCESS_TRANSPORT_PARAMETER
 */
protoop_arg_t process_max_sending_uniflow_id(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    size_t length = (size_t) get_cnx(cnx, AK_CNX_INPUT, 1);

    /* TODO actually process the value provided by the peer */
    int inject_plugin = 1;

    return (protoop_arg_t) inject_plugin;
}