#include "../../helpers.h"

/**
 * See PROTOOP_NOPARAM_STREAM_ALWAYS_ENCODE_LENGTH
 */

protoop_arg_t stream_always_encode_length(picoquic_cnx_t* cnx) {
    set_cnx(cnx, AK_CNX_OUTPUT, 0, true);
    return 0;
}