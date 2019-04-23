#include <picoquic.h>
#include <getset.h>

protoop_arg_t create_fec_scheme(picoquic_cnx_t *cnx)
{
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) NULL);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) NULL);
    return 0;
}
