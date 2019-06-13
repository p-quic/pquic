#include "picoquic.h"
#include "getset.h"

// sets as output the pointer towards the controller's state
protoop_arg_t create_constant_redundancy_controller(picoquic_cnx_t *cnx)
{
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) NULL);
    return 0;
}