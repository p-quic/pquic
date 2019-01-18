
#include <picoquic.h>

/**
 * returns always true
 */
protoop_arg_t should_send_repair_symbols(picoquic_cnx_t *cnx)
{
    return true;
}