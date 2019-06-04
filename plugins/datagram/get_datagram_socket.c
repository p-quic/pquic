#include <sys/socket.h>
#include <sys/un.h>

#include "../helpers.h"
#include "bpf.h"

protoop_arg_t get_datagram_socket(picoquic_cnx_t* cnx)
{
    datagram_memory_t *m = get_datagram_memory(cnx);
    if (m->socket_fds[PLUGIN_SOCKET] == -1 && m->socket_fds[APP_SOCKET] == -1) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, m->socket_fds) == -1) {
            PROTOOP_PRINTF(cnx, "Failed to allocate Unix socket pair!\n");
        }
    }
    return (protoop_arg_t) m->socket_fds[APP_SOCKET];
}