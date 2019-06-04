#include "../helpers.h"
#include "bpf.h"


protoop_arg_t state_changed(picoquic_cnx_t *cnx)
{
    picoquic_state_enum cnx_state = (picoquic_state_enum) get_cnx(cnx, AK_CNX_STATE, 0);
    if (cnx_state == picoquic_state_disconnected) {
        datagram_memory_t *m = get_datagram_memory(cnx);
        if (m->socket_fds[PLUGIN_SOCKET] != -1) {
            close(m->socket_fds[PLUGIN_SOCKET]);
            m->socket_fds[PLUGIN_SOCKET] = -1;
        }
        if (m->socket_fds[APP_SOCKET] != -1) {
            close(m->socket_fds[APP_SOCKET]);
            m->socket_fds[APP_SOCKET] = -1;
        }
    }
    return 0;
}