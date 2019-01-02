#include "picoquic.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

protoop_arg_t process_datagram_frame(picoquic_cnx_t* cnx)
{
    datagram_frame_t *frame = (datagram_frame_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    uint64_t current_time = (uint64_t) get_cnx(cnx, CNX_AK_INPUT, 1);
    picoquic_path_t *path_x = (picoquic_path_t*) get_cnx(cnx, CNX_AK_INPUT, 3);
    datagram_memory_t *m = get_datagram_memory(cnx);

    if (m->socket_fds[PLUGIN_SOCKET] != -1) {
        if (frame->datagram_id == 0) { // Send the datagram as a message on the socket
            return send_datagram_to_application(m, cnx, frame);
        } else {  // Place the datagram in the buffer
            received_datagram_t *r = (received_datagram_t *) my_malloc(cnx, sizeof(received_datagram_t));
            if (r == NULL) {
                PROTOOP_PRINTF(cnx, "Failed to allocate received_datagram_t\n");
                return 1;
            }
            r->datagram = (datagram_frame_t *) my_malloc(cnx, sizeof(datagram_frame_t));
            if (r->datagram == NULL) {
                PROTOOP_PRINTF(cnx, "Failed to allocate datagram_frame_t\n");
                return 1;
            }
            my_memcpy(r->datagram, frame, sizeof(datagram_frame_t));
            r->datagram->datagram_data_ptr = (uint8_t *) my_malloc(cnx, (unsigned int) frame->length);
            my_memcpy(r->datagram->datagram_data_ptr, frame->datagram_data_ptr, frame->length);
            r->delivery_deadline = current_time + get_max_rtt_difference(cnx, path_x) + 100000;
            insert_into_datagram_buffer(m, r);
            process_datagram_buffer(m, cnx);
            if (m->datagram_buffer != NULL && get_cnx(cnx, CNX_AK_NEXT_WAKE_TIME, 0) > m->datagram_buffer->delivery_deadline) {
                picoquic_reinsert_cnx_by_wake_time(cnx, m->datagram_buffer->delivery_deadline);
            }
        }
    }
    return 0;
}