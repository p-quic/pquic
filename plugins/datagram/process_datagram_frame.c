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
        } else {  // Tries to place the datagram in the buffer
            received_datagram_t *r = NULL;
            // While we were not able to allocate memory for reordering, but are able to reclaim some from existing data in the buffer
            while ((r == NULL || r->datagram == NULL || r->datagram->datagram_data_ptr == NULL) && m->datagram_buffer != NULL) {
                r = (received_datagram_t *) my_malloc(cnx, sizeof(received_datagram_t));
                if (r == NULL) {
                    send_head_datagram_buffer(m, cnx);
                    break;
                }
                r->datagram = (datagram_frame_t *) my_malloc(cnx, sizeof(datagram_frame_t));
                if (r->datagram == NULL) {
                    my_free(cnx, r);
                    send_head_datagram_buffer(m, cnx);
                    break;
                }
                r->datagram->datagram_data_ptr = (uint8_t *) my_malloc(cnx, (unsigned int) frame->length);
                if (r->datagram->datagram_data_ptr == NULL) {
                    my_free(cnx, r->datagram);
                    my_free(cnx, r);
                    send_head_datagram_buffer(m, cnx);
                }
            }
            if (r == NULL || r->datagram == NULL || r->datagram->datagram_data_ptr == NULL) {
                PROTOOP_PRINTF(cnx, "Unable to reclaim enough memory to reserve buffer slot\n");
                send_datagram_to_application(m, cnx, frame);
                return 0;
            }

            while (m->recv_buffer + frame->length > RECV_BUFFER) {
                send_head_datagram_buffer(m, cnx);
            }

            r->datagram->datagram_id = frame->datagram_id;
            r->datagram->length = frame->length;
            my_memcpy(r->datagram->datagram_data_ptr, frame->datagram_data_ptr, frame->length);
            r->delivery_deadline = current_time + ((get_max_rtt_difference(cnx, path_x)*5)/4);
            insert_into_datagram_buffer(m, r);
            process_datagram_buffer(m, cnx);

            PROTOOP_PRINTF(cnx, "Recv buffer size %d\n", m->recv_buffer);
        }
    }
    return 0;
}