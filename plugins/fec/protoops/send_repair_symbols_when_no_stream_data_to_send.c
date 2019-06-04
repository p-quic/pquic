#include "../../helpers.h"

/**
 * returns true when no ready stream is found
 */
protoop_arg_t should_send_repair_symbols(picoquic_cnx_t *cnx)
{
    // if no stream data to send, do not protect anything anymore
    void *ret = (void *) run_noparam(cnx, "find_ready_stream", 0, NULL, NULL);
    return (protoop_arg_t) (ret == NULL);
}