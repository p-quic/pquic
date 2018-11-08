#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

protoop_arg_t process_datagram_frame(picoquic_cnx_t* cnx)
{
    datagram_frame_t *frame = (datagram_frame_t *) cnx->protoop_inputv[0];
    datagram_memory_t *m = get_datagram_memory(cnx);
    if (m->socket_fds[PLUGIN_SOCKET] != -1) {
        // Send the datagram as a message on the socket
        ssize_t ret = write(m->socket_fds[PLUGIN_SOCKET], frame->datagram_data_ptr, frame->length);
        PROTOOP_PRINTF(cnx, "Wrote %d bytes to the message socket\n", ret);
        picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_current_time());
        return (protoop_arg_t) (ret > 0);
    }
    return 0;
}