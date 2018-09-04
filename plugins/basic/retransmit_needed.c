#include "picoquic_internal.h"
#include "plugin.h"
#include "memcpy.h"

static void protoop_printf(picoquic_cnx_t *cnx, protoop_arg_t arg)
{
    protoop_arg_t args[1];
    args[0] = (protoop_arg_t) arg;
    plugin_run_protoop(cnx, PROTOOPID_PRINTF, 1, args, NULL);
}

static int retransmit_needed_by_packet(picoquic_cnx_t *cnx, picoquic_packet_t *p, uint64_t current_time, int *timer_based_retransmit)
{
    protoop_arg_t outs[PROTOOPARGS_MAX], args[3];
    args[0] = (protoop_arg_t) p;
    args[1] = (protoop_arg_t) current_time;
    args[2] = (protoop_arg_t) *timer_based_retransmit;
    int ret = (int) plugin_run_protoop(cnx, PROTOOPID_RETRANSMIT_NEEDED_BY_PACKET, 3, args, outs);
    *timer_based_retransmit = (int) outs[0];
    return ret;
}

static void congestion_algorithm_notify(picoquic_cnx_t *cnx, picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification, uint64_t rtt_measurement, uint64_t nb_bytes_acknowledged,
    uint64_t lost_packet_number, uint64_t current_time)
{
    protoop_arg_t args[6];
    args[0] = (protoop_arg_t) path_x;
    args[1] = (protoop_arg_t) notification;
    args[2] = (protoop_arg_t) rtt_measurement;
    args[3] = (protoop_arg_t) nb_bytes_acknowledged;
    args[4] = (protoop_arg_t) lost_packet_number;
    args[5] = (protoop_arg_t) current_time;
    plugin_run_protoop(cnx, PROTOOPID_CONGESTION_ALGORITHM_NOTIFY, 6, args, NULL);
}

static void callback_function(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes,
    size_t length, picoquic_call_back_event_t fin_or_event, void* callback_ctx)
{
    protoop_arg_t args[5];
    args[0] = (protoop_arg_t) stream_id;
    args[1] = (protoop_arg_t) bytes;
    args[2] = (protoop_arg_t) length;
    args[3] = (protoop_arg_t) fin_or_event;
    args[4] = (protoop_arg_t) callback_ctx;
    plugin_run_protoop(cnx, PROTOOPID_CALLBACK_FUNCTION, 5, args, NULL);
}

static int skip_frame(picoquic_cnx_t *cnx, uint8_t* bytes, size_t bytes_max, size_t* consumed, int* pure_ack)
{
    protoop_arg_t args[4], outs[PROTOOPARGS_MAX];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) bytes_max;
    args[2] = (protoop_arg_t) *consumed;
    args[3] = (protoop_arg_t) *pure_ack;
    int ret = (int) plugin_run_protoop(cnx, PROTOOPID_SKIP_FRAME, 4, args, outs);
    *consumed = (size_t) outs[0];
    *pure_ack = (int) outs[1];
    return ret;
}

static int check_stream_frame_already_acked(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max, int* no_need_to_repeat)
{
    protoop_arg_t args[3], outs[PROTOOPARGS_MAX];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) bytes_max;
    args[2] = (protoop_arg_t) *no_need_to_repeat;
    int ret = (int) plugin_run_protoop(cnx, PROTOOPID_CHECK_STREAM_FRAME_ALREADY_ACKED, 3, args, outs);
    *no_need_to_repeat = (int) outs[0];
    return ret;
}

static uint32_t predict_packet_header_length(picoquic_cnx_t *cnx, picoquic_packet_type_enum packet_type)
{
    protoop_arg_t args[1], outs[PROTOOPARGS_MAX];
    args[0] = (protoop_arg_t) packet_type;
    return (uint32_t) plugin_run_protoop(cnx, PROTOOPID_PREDICT_PACKET_HEADER_LENGTH, 1, args, NULL);
}

static uint32_t get_checksum_length(picoquic_cnx_t* cnx, int is_cleartext_mode)
{
    protoop_arg_t args[1];
    args[0] = (protoop_arg_t) is_cleartext_mode;
    return (uint32_t) plugin_run_protoop(cnx, PROTOOPID_GET_CHECKSUM_LENGTH, 1, args, NULL);
}

static int is_stream_frame_unlimited(const uint8_t* bytes)
{
    return PICOQUIC_BITS_CLEAR_IN_RANGE(bytes[0], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max, 0x02);
}

static void dequeue_retransmit_packet(picoquic_cnx_t* cnx, picoquic_packet_t* p, int should_free)
{
    protoop_arg_t args[2];
    args[0] = (protoop_arg_t) p;
    args[1] = (protoop_arg_t) should_free;
    plugin_run_protoop(cnx, PROTOOPID_DEQUEUE_RETRANSMIT_PACKET, 2, args, NULL);
}

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

    picoquic_packet_t* p = cnx->pkt_ctx[pc].retransmit_oldest;
    uint32_t length = 0;

    /* TODO: while packets are pure ACK, drop them from retransmit queue */
    while (p != NULL) {
        int should_retransmit = 0;
        int timer_based_retransmit = 0;
        uint64_t lost_packet_number = p->sequence_number;
        picoquic_packet_t* p_next = p->next_packet;
        //picoquic_packet_header ph;
        int ret = 0;
        //picoquic_cnx_t* pcnx = cnx;

        length = 0;
        /* Get the packet type */

        should_retransmit = retransmit_needed_by_packet(cnx, p, current_time, &timer_based_retransmit);

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
            uint8_t* bytes = packet->bytes;
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

                while (ret == 0 && byte_index < p->length) {
                    if (bytes[byte_index] == picoquic_frame_type_crypto_hs) {
                        contains_crypto = 1;
                        packet_is_pure_ack = 0;
                        break;
                    }
                    ret = skip_frame(cnx, &p->bytes[byte_index],
                        p->length - byte_index, &frame_length, &frame_is_pure_ack);
                    byte_index += frame_length;
                }
                byte_index = 0;

                if (contains_crypto) {
                    length = predict_packet_header_length(cnx, picoquic_packet_0rtt_protected);
                    packet->ptype = picoquic_packet_0rtt_protected;
                    packet->offset = length;
                } else if (cnx->cnx_state < picoquic_state_client_ready) {
                    should_retransmit = 0;
                } else {
                    length = predict_packet_header_length(cnx, picoquic_packet_1rtt_protected_phi0);
                    packet->ptype = picoquic_packet_1rtt_protected_phi0;
                    packet->offset = length;
                }
            } else {
                length = predict_packet_header_length(cnx, p->ptype);
                packet->ptype = p->ptype;
                packet->offset = length;
            }

            if (should_retransmit != 0) {
                packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
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
                    checksum_length = get_checksum_length(cnx, is_cleartext_mode);

                    /* Copy the relevant bytes from one packet to the next */
                    byte_index = p->offset;

                    while (ret == 0 && byte_index < p->length) {
                        ret = skip_frame(cnx, &p->bytes[byte_index],
                            p->length - byte_index, &frame_length, &frame_is_pure_ack);

                        /* Check whether the data was already acked, which may happen in 
                         * case of spurious retransmissions */
                        if (ret == 0 && frame_is_pure_ack == 0) {
                            ret = check_stream_frame_already_acked(cnx, &p->bytes[byte_index],
                                frame_length, &frame_is_pure_ack);
                        }

                        /* Prepare retransmission if needed */
                        if (ret == 0 && !frame_is_pure_ack) {
                            if (is_stream_frame_unlimited(&p->bytes[byte_index])) {
                                /* Need to PAD to the end of the frame to avoid sending extra bytes */
                                while (checksum_length + length + frame_length < send_buffer_max) {
                                    bytes[length] = picoquic_frame_type_padding;
                                    length++;
                                }
                            }
                            my_memcpy(&bytes[length], &p->bytes[byte_index], frame_length);
                            length += (uint32_t)frame_length;
                            packet_is_pure_ack = 0;
                        }
                        byte_index += frame_length;
                    }
                }

                /* Update the number of bytes in transit and remove old packet from queue */
                /* If not pure ack, the packet will be placed in the "retransmitted" queue,
                 * in order to enable detection of spurious restransmissions */
                dequeue_retransmit_packet(cnx, p, packet_is_pure_ack & do_not_detect_spurious);

                /* If we have a good packet, return it */
                if (packet_is_pure_ack) {
                    length = 0;
                    should_retransmit = 0;
                } else {
                    if (timer_based_retransmit != 0) {
                        if (cnx->pkt_ctx[pc].nb_retransmit > 4) {
                            /*
                             * Max retransmission count was exceeded. Disconnect.
                             */
                            /* DBG_PRINTF("%s\n", "Too many retransmits, disconnect"); */
                            cnx->cnx_state = picoquic_state_disconnected;
                            callback_function(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
                            length = 0;
                            should_retransmit = 0;
                            break;
                        } else {
                            cnx->pkt_ctx[pc].nb_retransmit++;
                            cnx->pkt_ctx[pc].latest_retransmit_time = current_time;
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
                                bytes[length++] = 0;
                            }
                        }
                        packet->length = length;
                        cnx->nb_retransmission_total++;

                        congestion_algorithm_notify(cnx, old_path,
                            (timer_based_retransmit == 0) ? picoquic_congestion_notification_repeat : picoquic_congestion_notification_timeout,
                            0, 0, lost_packet_number, current_time);

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

    cnx->protoop_outputv[0] = is_cleartext_mode;
    cnx->protoop_outputv[1] = header_length;
    cnx->protoop_outputc_callee = 2;

    return (protoop_arg_t) ((int) length);
}