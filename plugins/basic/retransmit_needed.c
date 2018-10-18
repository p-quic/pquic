#include "picoquic_internal.h"
#include "plugin.h"
#include "memcpy.h"
#include "../helpers.h"

/**
 * cnx->protoop_inputv[0] = picoquic_packet_context_enum pc
 * cnx->protoop_inputv[1] = picoquic_path_t * path_x
 * cnx->protoop_inputv[2] = uint64_t current_time
 * cnx->protoop_inputv[3] = picoquic_packet* packet
 * cnx->protoop_inputv[4] = size_t send_buffer_max
 * cnx->protoop_inputv[5] = int is_cleartext_mode
 * cnx->protoop_inputv[6] = uint32_t header_length
 *
 * Regular output: int length
 * cnx->protoop_outputv[0] = int is_cleartext_mode
 * cnx->protoop_outputv[1] = uint32_t header_length
 */
protoop_arg_t retransmit_needed(picoquic_cnx_t *cnx)
{
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) cnx->protoop_inputv[0];
    picoquic_path_t * path_x = (picoquic_path_t *) cnx->protoop_inputv[1];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[2];
    picoquic_packet_t* packet = (picoquic_packet_t *) cnx->protoop_inputv[3];
    size_t send_buffer_max = (size_t) cnx->protoop_inputv[4];
    int is_cleartext_mode = (int) cnx->protoop_inputv[5];
    uint32_t header_length = (uint32_t) cnx->protoop_inputv[6];

    uint32_t length = 0;
    bool stop = false;
    protoop_id_t reason = NULL;

    for (int i = 0; i < cnx->nb_paths; i++) {
        picoquic_path_t* orig_path = cnx->path[i];
        picoquic_packet_t* p = orig_path->pkt_ctx[pc].retransmit_oldest;
        /* TODO: while packets are pure ACK, drop them from retransmit queue */
        while (p != NULL) {
            int should_retransmit = 0;
            int timer_based_retransmit = 0;
            uint64_t lost_packet_number = p->sequence_number;
            picoquic_packet_t* p_next = p->next_packet;
            uint8_t * new_bytes = packet->bytes;
            int ret = 0;

            length = 0;
            /* Get the packet type */

            should_retransmit = helper_retransmit_needed_by_packet(cnx, p, current_time, &timer_based_retransmit, &reason);

            if (should_retransmit == 0) {
                /*
                * Always retransmit in order. If not this one, then nothing.
                * But make an exception for 0-RTT packets.
                */
                if (p->ptype == picoquic_packet_0rtt_protected) {
                    p = p_next;
                    continue;
                } else {
                    break;
                }
            } else {
                /* check if this is an ACK only packet */
                int packet_is_pure_ack = 1;
                int do_not_detect_spurious = 1;
                int frame_is_pure_ack = 0;
                uint8_t* old_bytes = p->bytes;
                size_t frame_length = 0;
                size_t byte_index = 0; /* Used when parsing the old packet */
                size_t checksum_length = 0;
                /* TODO: should be the path on which the packet was transmitted */
                picoquic_path_t * old_path = p->send_path;

                header_length = 0;

                if (p->ptype == picoquic_packet_0rtt_protected) {
                    /* Only retransmit as 0-RTT if contains crypto data */
                    int contains_crypto = 0;
                    byte_index = p->offset;

                    if (p->is_evaluated == 0) {
                        while (ret == 0 && byte_index < p->length) {
                            if (old_bytes[byte_index] == picoquic_frame_type_crypto_hs) {
                                contains_crypto = 1;
                                packet_is_pure_ack = 0;
                                break;
                            }
                            ret = helper_skip_frame(cnx, &p->bytes[byte_index],
                                p->length - byte_index, &frame_length, &frame_is_pure_ack);
                            byte_index += frame_length;
                        }
                        p->contains_crypto = contains_crypto;
                        p->is_pure_ack = packet_is_pure_ack;
                        p->is_evaluated = 1;
                    } else {
                        contains_crypto = p->contains_crypto;
                        packet_is_pure_ack = p->is_pure_ack;
                    }

                    if (contains_crypto) {
                        length = helper_predict_packet_header_length(cnx, picoquic_packet_0rtt_protected, path_x);
                        packet->ptype = picoquic_packet_0rtt_protected;
                        packet->offset = length;
                    } else if (cnx->cnx_state < picoquic_state_client_ready) {
                        should_retransmit = 0;
                    } else {
                        length = helper_predict_packet_header_length(cnx, picoquic_packet_1rtt_protected_phi0, path_x);
                        packet->ptype = picoquic_packet_1rtt_protected_phi0;
                        packet->offset = length;
                    }
                } else {
                    length = helper_predict_packet_header_length(cnx, p->ptype, path_x);
                    packet->ptype = p->ptype;
                    packet->offset = length;
                }

                if (should_retransmit != 0) {
                    packet->sequence_number = path_x->pkt_ctx[pc].send_sequence;
                    packet->send_path = path_x;
                    packet->pc = pc;

                    header_length = length;

                    if (p->ptype == picoquic_packet_1rtt_protected_phi0 || p->ptype == picoquic_packet_1rtt_protected_phi1 || p->ptype == picoquic_packet_0rtt_protected) {
                        is_cleartext_mode = 0;
                    } else {
                        is_cleartext_mode = 1;
                    }

                    if ((p->length + p->checksum_overhead) > old_path->send_mtu) {
                        /* MTU probe was lost, presumably because of packet too big */
                        old_path->mtu_probe_sent = 0;
                        old_path->send_mtu_max_tried = (uint32_t)(p->length + p->checksum_overhead);
                        /* MTU probes should not be retransmitted */
                        packet_is_pure_ack = 1;
                        do_not_detect_spurious = 0;
                    } else {
                        checksum_length = helper_get_checksum_length(cnx, is_cleartext_mode);

                        /* Copy the relevant bytes from one packet to the next */
                        byte_index = p->offset;

                        while (ret == 0 && byte_index < p->length) {
                            ret = helper_skip_frame(cnx, &p->bytes[byte_index],
                                p->length - byte_index, &frame_length, &frame_is_pure_ack);

                            /* Check whether the data was already acked, which may happen in
                            * case of spurious retransmissions */
                            if (ret == 0 && frame_is_pure_ack == 0) {
                                ret = helper_check_stream_frame_already_acked(cnx, &p->bytes[byte_index],
                                    frame_length, &frame_is_pure_ack);
                            }

                            /* Prepare retransmission if needed */
                            if (ret == 0 && !frame_is_pure_ack) {
                                if (helper_is_stream_frame_unlimited(&p->bytes[byte_index])) {
                                    /* Need to PAD to the end of the frame to avoid sending extra bytes */
                                    while (checksum_length + length + frame_length < send_buffer_max) {
                                        new_bytes[length] = picoquic_frame_type_padding;
                                        length++;
                                    }
                                }
                                my_memcpy(&new_bytes[length], &p->bytes[byte_index], frame_length);
                                length += (uint32_t)frame_length;
                                packet_is_pure_ack = 0;
                            }
                            byte_index += frame_length;
                        }
                    }

                    /* Update the number of bytes in transit and remove old packet from queue */
                    /* If not pure ack, the packet will be placed in the "retransmitted" queue,
                    * in order to enable detection of spurious restransmissions */
                    helper_dequeue_retransmit_packet(cnx, p, packet_is_pure_ack & do_not_detect_spurious);

                    /* If we have a good packet, return it */
                    if (packet_is_pure_ack) {
                        length = 0;
                    } else {
                        if (timer_based_retransmit != 0) {
                            if (orig_path->pkt_ctx[pc].nb_retransmit > 4) {
                                /*
                                * Max retransmission count was exceeded. Disconnect.
                                */
                                /* DBG_PRINTF("%s\n", "Too many retransmits, disconnect"); */
                                picoquic_set_cnx_state(cnx, picoquic_state_disconnected);
                                helper_callback_function(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
                                length = 0;
                                stop = true;
                                break;
                            } else {
                                orig_path->pkt_ctx[pc].nb_retransmit++;
                                orig_path->pkt_ctx[pc].latest_retransmit_time = current_time;
                            }
                        }

                        if (should_retransmit != 0) {
                            /*
                            if (p->ptype < picoquic_packet_1rtt_protected_phi0) {
                                // protoop_printf(cnx, (protoop_arg_t) p->pc);
                                DBG_PRINTF("Retransmit packet type %d, pc=%d, seq = %llx, is_client = %d\n",
                                    p->ptype, p->pc,
                                    (unsigned long long)p->sequence_number, cnx->client_mode);
                            }
                            */

                            /* special case for the client initial */
                            if (p->ptype == picoquic_packet_initial && cnx->client_mode != 0) {
                                while (length < (send_buffer_max - checksum_length)) {
                                    new_bytes[length++] = 0;
                                }
                            }
                            packet->length = length;
                            cnx->nb_retransmission_total++;

                            helper_congestion_algorithm_notify(cnx, old_path,
                                (timer_based_retransmit == 0) ? picoquic_congestion_notification_repeat : picoquic_congestion_notification_timeout,
                                0, 0, lost_packet_number, current_time);

                            stop = true;

                            break;
                        }
                    }
                }
            }
            /*
            * If the loop is continuing, this means that we need to look
            * at the next candidate packet.
            */
            p = p_next;
        }

        if (stop) {
            break;
        }
    }

    cnx->protoop_outputv[0] = is_cleartext_mode;
    cnx->protoop_outputv[1] = header_length;
    cnx->protoop_outputv[2] = (protoop_arg_t) reason;
    cnx->protoop_outputc_callee = 3;

    return (protoop_arg_t) ((int) length);
}