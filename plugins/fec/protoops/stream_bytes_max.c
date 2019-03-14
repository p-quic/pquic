
#include <picoquic.h>
#include <picoquic_internal.h>
#include "../../helpers.h"
#include "../framework/block_framework_sender.h"

/**
 * See PROTOOP_NOPARAM_STREAM_BYTES_MAX
 */

protoop_arg_t stream_bytes_max(picoquic_cnx_t* cnx) {
    size_t bytes_max = get_cnx(cnx, CNX_AK_INPUT, 0);
    // FIXME there is one more byte than needed (?) in the overhead, but without it, it doesn't work. Find out why
    size_t overhead = 1 + (1 + sizeof(uint64_t)) + (DEFAULT_K/2 + sizeof(fec_frame_header_t));
    set_cnx(cnx, CNX_AK_OUTPUT, 0, (bytes_max && bytes_max > overhead) ? bytes_max-overhead : bytes_max);
    return 0;
}