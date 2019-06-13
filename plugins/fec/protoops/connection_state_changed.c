

#include "../fec_protoops.h"


protoop_arg_t connection_state_changed(picoquic_cnx_t *cnx)
{
    // We ensure to laod the FEC frameworks and schemes as soon as possible in the connection life
    picoquic_state_enum from_state = (picoquic_state_enum) get_cnx(cnx, AK_CNX_INPUT, 0);
    if (from_state == picoquic_state_client_init || from_state == picoquic_state_server_almost_ready)
        get_bpf_state(cnx);
    return 0;
}