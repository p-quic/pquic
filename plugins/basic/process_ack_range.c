#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"

/**
 * picoquic_packet_context_enum pc = cnx->protoop_inputv[0]
 * uint64_t highest = cnx->protoop_inputv[1]
 * uint64_t range = cnx->protoop_inputv[2]
 * picoquic_packet_t* ppacket = cnx->protoop_inputv[3]
 * uint64_t current_time = cnx->protoop_inputv[4]
 *
 * Output: int ret
 */
protoop_arg_t process_ack_range(picoquic_cnx_t *cnx)
{
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) cnx->protoop_inputv[0];
    uint64_t highest = (uint64_t) cnx->protoop_inputv[1];
    uint64_t range = (uint64_t) cnx->protoop_inputv[2];
    picoquic_packet_t* ppacket = (picoquic_packet_t*) cnx->protoop_inputv[3];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[4];

    picoquic_packet_t* p = ppacket;
    int ret = 0;
    /* Compare the range to the retransmit queue */
    while (p != NULL && range > 0) {
        if (p->sequence_number > highest) {
            p = p->next_packet;
        } else {
            if (p->sequence_number == highest) {
                /* TODO: RTT Estimate */
                picoquic_packet_t* next = p->next_packet;
                picoquic_path_t * old_path = p->send_path;

                if ((picoquic_congestion_algorithm_t *) get_cnx(cnx, CNX_AK_CONGESTION_CONTROL_ALGORITHM, 0) != NULL) {
                    helper_congestion_algorithm_notify(cnx, old_path,
                        picoquic_congestion_notification_acknowledgement, 0, p->length, 0, current_time);
                }

                /* If the packet contained an ACK frame, perform the ACK of ACK pruning logic */
                helper_process_possible_ack_of_ack_frame(cnx, p);

                /* If packet is larger than the current MTU, update the MTU */
                if ((p->length + p->checksum_overhead) > old_path->send_mtu) {
                    old_path->send_mtu = (uint32_t)(p->length + p->checksum_overhead);
                    old_path->mtu_probe_sent = 0;
                }

                /* Any acknowledgement shows progress */
                p->send_path->pkt_ctx[pc].nb_retransmit = 0;

                helper_dequeue_retransmit_packet(cnx, p, 1);
                p = next;
            }

            range--;
            highest--;
        }
    }

    ppacket = p;

    cnx->protoop_outputc_callee = 1;
    cnx->protoop_outputv[0] = (protoop_arg_t) ppacket;

    return (protoop_arg_t) ret;
}