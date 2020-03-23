#include "picoquic.h"
#include "plugin.h"
#include "memcpy.h"
#include "../helpers.h"

/**
 * See PROTOOP_NOPARAM_RETRANSMIT_NEEDED
 */
protoop_arg_t retransmit_needed(picoquic_cnx_t *cnx)
{
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_path_t * path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    uint64_t current_time = (uint64_t) get_cnx(cnx, AK_CNX_INPUT, 2);
    picoquic_packet_t* packet = (picoquic_packet_t *) get_cnx(cnx, AK_CNX_INPUT, 3);
    size_t send_buffer_max = (size_t) get_cnx(cnx, AK_CNX_INPUT, 4);
    int is_cleartext_mode = (int) get_cnx(cnx, AK_CNX_INPUT, 5);
    uint32_t header_length = (uint32_t) get_cnx(cnx, AK_CNX_INPUT, 6);

    uint32_t length = 0;
    bool stop = false;
    char *reason = NULL;

    int nb_paths = (int) get_cnx(cnx, AK_CNX_NB_PATHS, 0);

    for (int i = 0; i < nb_paths; i++) {
        picoquic_path_t* orig_path = (picoquic_path_t*) get_cnx(cnx, AK_CNX_PATH, i);
        picoquic_packet_context_t *orig_pkt_ctx = (picoquic_packet_context_t *) get_path(orig_path, AK_PATH_PKT_CTX, pc);
        picoquic_packet_t* p = (picoquic_packet_t *) get_pkt_ctx(orig_pkt_ctx, AK_PKTCTX_RETRANSMIT_OLDEST);
        /* TODO: while packets are pure ACK, drop them from retransmit queue */
        while (p != NULL) {
            int should_retransmit = 0;
            int timer_based_retransmit = 0;
            uint64_t lost_packet_number = (uint64_t) get_pkt(p, AK_PKT_SEQUENCE_NUMBER);
            picoquic_packet_t* p_next = (picoquic_packet_t *) get_pkt(p, AK_PKT_NEXT_PACKET);
            picoquic_packet_type_enum ptype = (picoquic_packet_type_enum) get_pkt(p, AK_PKT_TYPE);
            uint8_t * new_bytes = (uint8_t *) get_pkt(packet, AK_PKT_BYTES);
            int ret = 0;

            length = 0;
            /* Get the packet type */

            should_retransmit = helper_retransmit_needed_by_packet(cnx, p, current_time, &timer_based_retransmit, &reason, NULL);

            if (should_retransmit == 0) {
                /*
                * Always retransmit in order. If not this one, then nothing.
                * But make an exception for 0-RTT packets.
                */
                if (ptype == picoquic_packet_0rtt_protected) {
                    p = p_next;
                    continue;
                } else {
                    break;
                }
            } else {
                /* check if this is an ACK only packet */
                int contains_crypto = (int) get_pkt(p, AK_PKT_CONTAINS_CRYPTO);
                int packet_is_pure_ack = (int) get_pkt(p, AK_PKT_IS_PURE_ACK);
                int do_not_detect_spurious = 1;
                int frame_is_pure_ack = 0;
                uint8_t* old_bytes = (uint8_t *) get_pkt(p, AK_PKT_BYTES);
                size_t frame_length = 0;
                size_t byte_index = 0; /* Used when parsing the old packet */
                size_t checksum_length = 0;
                /* TODO: should be the path on which the packet was transmitted */
                picoquic_path_t * old_path = (picoquic_path_t *) get_pkt(p, AK_PKT_SEND_PATH);
                uint32_t poffset = (uint32_t) get_pkt(p, AK_PKT_OFFSET);
                uint32_t plength = (uint32_t) get_pkt(p, AK_PKT_LENGTH);

                header_length = 0;

                if (ptype == picoquic_packet_0rtt_protected) {
                    /* Only retransmit as 0-RTT if contains crypto data */
                    int contains_crypto = 0;
                    byte_index = poffset;

                    picoquic_state_enum cnx_state = (picoquic_state_enum) get_cnx(cnx, AK_CNX_STATE, 0);

                    if (contains_crypto) {
                        length = helper_predict_packet_header_length(cnx, picoquic_packet_0rtt_protected, path_x);
                        set_pkt(packet, AK_PKT_TYPE, picoquic_packet_0rtt_protected);
                        set_pkt(packet, AK_PKT_OFFSET, length);
                    } else if (cnx_state < picoquic_state_client_ready) {
                        should_retransmit = 0;
                    } else {
                        length = helper_predict_packet_header_length(cnx, picoquic_packet_1rtt_protected_phi0, path_x);
                        set_pkt(packet, AK_PKT_TYPE, picoquic_packet_1rtt_protected_phi0);
                        set_pkt(packet, AK_PKT_OFFSET, length);
                    }
                } else {
                    length = helper_predict_packet_header_length(cnx, ptype, path_x);
                    set_pkt(packet, AK_PKT_TYPE, ptype);
                    set_pkt(packet, AK_PKT_OFFSET, length);
                }

                if (should_retransmit != 0) {
                    picoquic_packet_context_t *pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, AK_PATH_PKT_CTX, pc);
                    set_pkt(packet, AK_PKT_SEQUENCE_NUMBER, (uint64_t) get_pkt_ctx(pkt_ctx, AK_PKTCTX_SEND_SEQUENCE));
                    set_pkt(packet, AK_PKT_SEND_PATH, (protoop_arg_t) path_x);
                    set_pkt(packet, AK_PKT_CONTEXT, pc);

                    header_length = length;

                    if (ptype == picoquic_packet_1rtt_protected_phi0 || ptype == picoquic_packet_1rtt_protected_phi1 || ptype == picoquic_packet_0rtt_protected) {
                        is_cleartext_mode = 0;
                    } else {
                        is_cleartext_mode = 1;
                    }

                    uint32_t old_send_mtu = (uint32_t) get_path(old_path, AK_PATH_SEND_MTU, 0);
                    uint32_t pchecksum_overhead = (uint32_t) get_pkt(p, AK_PKT_CHECKSUM_OVERHEAD);
                    if ((plength + pchecksum_overhead) > old_send_mtu) {
                        /* MTU probe was lost, presumably because of packet too big */
                        set_path(old_path, AK_PATH_MTU_PROBE_SENT, 0, 0);
                        set_path(old_path, AK_PATH_SEND_MTU_MAX_TRIED, 0, (protoop_arg_t)(plength + pchecksum_overhead));
                        /* MTU probes should not be retransmitted */
                        packet_is_pure_ack = 1;
                        do_not_detect_spurious = 0;
                    } else {
                        checksum_length = helper_get_checksum_length(cnx, is_cleartext_mode);

                        /* Copy the relevant bytes from one packet to the next */
                        byte_index = poffset;

                        while (ret == 0 && byte_index < plength) {
                            ret = helper_skip_frame(cnx, &old_bytes[byte_index],
                                plength - byte_index, &frame_length, &frame_is_pure_ack);

                            /* Check whether the data was already acked, which may happen in
                            * case of spurious retransmissions */
                            if (ret == 0 && frame_is_pure_ack == 0) {
                                ret = helper_check_stream_frame_already_acked(cnx, &old_bytes[byte_index],
                                    frame_length, &frame_is_pure_ack);
                            }

                            /* Prepare retransmission if needed */
                            if (ret == 0 && !frame_is_pure_ack) {
                                if (helper_is_stream_frame_unlimited(&old_bytes[byte_index])) {
                                    /* Need to PAD to the end of the frame to avoid sending extra bytes */
                                    while (checksum_length + length + frame_length < send_buffer_max) {
                                        my_memset(&new_bytes[length], picoquic_frame_type_padding, 1);
                                        length++;
                                    }
                                }
                                my_memcpy(&new_bytes[length], &old_bytes[byte_index], frame_length);
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
                            uint64_t nb_retransmit = (uint64_t) get_pkt_ctx(orig_pkt_ctx, AK_PKTCTX_NB_RETRANSMIT);
                            if (nb_retransmit > 4) {
                                /*
                                * Max retransmission count was exceeded. Disconnect.
                                */
                                /* DBG_PRINTF("%s\n", "Too many retransmits, disconnect"); */
                                picoquic_set_cnx_state(cnx, picoquic_state_disconnected);
                                helper_callback_function(cnx, 0, NULL, 0, picoquic_callback_close);
                                length = 0;
                                stop = true;
                                break;
                            } else {
                                set_pkt_ctx(orig_pkt_ctx, AK_PKTCTX_NB_RETRANSMIT, nb_retransmit + 1);
                                set_pkt_ctx(orig_pkt_ctx, AK_PKTCTX_LATEST_RETRANSMIT_TIME, current_time);
                            }
                        }

                        if (should_retransmit != 0) {
                            int client_mode = (int) get_cnx(cnx, AK_CNX_CLIENT_MODE, 0);
                            /* special case for the client initial */
                            if (ptype == picoquic_packet_initial && client_mode != 0) {
                                my_memset(&new_bytes[length], 0, (send_buffer_max - checksum_length) - length);
                            }
                            set_pkt(packet, AK_PKT_LENGTH, length);
                            set_cnx(cnx, AK_CNX_NB_RETRANSMISSION_TOTAL, 0, get_cnx(cnx, AK_CNX_NB_RETRANSMISSION_TOTAL, 0) + 1);

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

    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) is_cleartext_mode);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) header_length);
    set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) reason);

    return (protoop_arg_t) ((int) length);
}