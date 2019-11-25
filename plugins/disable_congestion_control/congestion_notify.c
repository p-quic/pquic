
#include <picoquic.h>
#include <getset.h>
#include <stdint.h>





/**
 * See PROTOOP_NOPARAM_CONGESTION_ALGORITHM_NOTIFY
 */
protoop_arg_t congestion_algorithm_notify(picoquic_cnx_t *cnx)
{
    picoquic_path_t* path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    set_path(path_x, AK_PATH_CWIN, 0, UINT64_MAX);
    return 0;
}
