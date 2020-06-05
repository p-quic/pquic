#include "picoquic.h"
#include "plugin.h"
#include "../helpers.h"

/**
 * See PROTOOP_NOPARAM_UPDATE_RTT
 */
protoop_arg_t schedule_frames_on_path(picoquic_cnx_t *cnx)
{
    picoquic_packet_t* packet = (picoquic_packet_t*) get_cnx(cnx, AK_CNX_INPUT, 0);
    size_t send_buffer_max = (size_t) get_cnx(cnx, AK_CNX_INPUT, 1);
    uint64_t current_time = (uint64_t) get_cnx(cnx, AK_CNX_INPUT, 2);
    picoquic_packet_t* retransmit_p = (picoquic_packet_t*) get_cnx(cnx, AK_CNX_INPUT, 3);
    picoquic_path_t* from_path = (picoquic_path_t*) get_cnx(cnx, AK_CNX_INPUT, 4);
    char* reason = (char*) get_cnx(cnx, AK_CNX_INPUT, 5);

    int ret = 0;
    uint32_t length = 0;
    int is_cleartext_mode = 0;
    uint32_t checksum_overhead = helper_get_checksum_length(cnx, is_cleartext_mode);

    /* FIXME cope with different path MTUs */
    picoquic_path_t *path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);
    uint32_t path_send_mtu = (uint32_t) get_path(path_x, AK_PATH_SEND_MTU, 0);

    uint32_t send_buffer_min_max = (send_buffer_max > path_send_mtu) ? path_send_mtu : (uint32_t)send_buffer_max;
    int retransmit_possible = 1;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;
    size_t data_bytes = 0;
    uint32_t header_length = 0;
    uint8_t* bytes = (uint8_t *) get_pkt(packet, AK_PKT_BYTES);
    picoquic_packet_type_enum packet_type = picoquic_packet_1rtt_protected_phi0;

    /* TODO: manage multiple streams. */
    picoquic_stream_head* stream = NULL;
    int tls_ready = helper_is_tls_stream_ready(cnx);
    stream = helper_find_ready_stream(cnx);

    picoquic_stream_head* plugin_stream = helper_find_ready_plugin_stream(cnx);

    /* First enqueue frames that can be fairly sent, if any */
    /* Only schedule new frames if there is no planned frames */

    queue_t *reserved_frames = (queue_t *) get_cnx(cnx, AK_CNX_RESERVED_FRAMES, 0);
    if (queue_peek(reserved_frames) == NULL) {
        stream = helper_schedule_next_stream(cnx, send_buffer_min_max - checksum_overhead - length, path_x);
        picoquic_frame_fair_reserve(cnx, path_x, stream, send_buffer_min_max - checksum_overhead - length);
    }

    picoquic_packet_type_enum ptype = (picoquic_packet_type_enum) get_pkt(packet, AK_PKT_TYPE);
    char * retrans_reason = NULL;
    if (ret == 0 && retransmit_possible &&
        (length = helper_retransmit_needed(cnx, pc, path_x, current_time, packet, send_buffer_min_max, &is_cleartext_mode, &header_length, &retrans_reason)) > 0) {
        if (reason != NULL) {
            run_noparam(cnx, retrans_reason, 1, (protoop_arg_t *) packet, NULL);
        }
        /* Set the new checksum length */
        checksum_overhead = helper_get_checksum_length(cnx, is_cleartext_mode);
        /* Check whether it makes sense to add an ACK at the end of the retransmission */
        /* Don't do that if it risks mixing clear text and encrypted ack */
        if (is_cleartext_mode == 0 && ptype != picoquic_packet_0rtt_protected) {
            if (helper_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                send_buffer_min_max - checksum_overhead - length, &data_bytes)
                == 0) {
                length += (uint32_t)data_bytes;
                set_pkt(packet, AK_PKT_LENGTH, length);
            }
        }
        /* document the send time & overhead */
        set_pkt(packet, AK_PKT_IS_PURE_ACK, 0);
        set_pkt(packet, AK_PKT_SEND_TIME, current_time);
        set_pkt(packet, AK_PKT_CHECKSUM_OVERHEAD, checksum_overhead);
    }
    else if (ret == 0) {
        uint64_t cwin = get_path(path_x, AK_PATH_CWIN, 0);
        uint64_t bytes_in_transit = get_path(path_x, AK_PATH_BYTES_IN_TRANSIT, 0);
        picoquic_packet_context_t *pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, AK_PATH_PKT_CTX, pc);
        int challenge_response_to_send = (int) get_path(path_x, AK_PATH_CHALLENGE_RESPONSE_TO_SEND, 0);
        int challenge_verified = (int) get_path(path_x, AK_PATH_CHALLENGE_VERIFIED, 0);
        uint64_t challenge_time = (uint64_t) get_path(path_x, AK_PATH_CHALLENGE_TIME, 0);
        uint64_t retransmit_timer = (uint64_t) get_path(path_x, AK_PATH_RETRANSMIT_TIMER, 0);
        queue_t *retry_frames = (queue_t *) get_cnx(cnx, AK_CNX_RETRY_FRAMES, 0);

        length = helper_predict_packet_header_length(
                cnx, packet_type, path_x);
        set_pkt(packet, AK_PKT_TYPE, packet_type);
        set_pkt(packet, AK_PKT_OFFSET, length);
        header_length = length;
        uint64_t sequence_number = (uint64_t) get_pkt_ctx(pkt_ctx, AK_PKTCTX_SEND_SEQUENCE);
        set_pkt(packet, AK_PKT_SEQUENCE_NUMBER, sequence_number);
        set_pkt(packet, AK_PKT_SEND_TIME, current_time);
        set_pkt(packet, AK_PKT_SEND_PATH, (protoop_arg_t) path_x);

        if (helper_is_ack_needed(cnx, current_time, pc, path_x) == 0
            && challenge_response_to_send == 0
            && (challenge_verified == 1 || current_time < challenge_time + retransmit_timer)) {
            if (ret == 0 && send_buffer_max > path_send_mtu && helper_is_mtu_probe_needed(cnx, path_x)) {
                length = helper_prepare_mtu_probe(cnx, path_x, header_length, checksum_overhead, bytes);
                set_pkt(packet, AK_PKT_IS_MTU_PROBE, 1);
                set_pkt(packet, AK_PKT_LENGTH, length);
                set_pkt(packet, AK_PKT_IS_CONGESTION_CONTROLLED, 0);
                set_path(path_x, AK_PATH_MTU_PROBE_SENT, 0, 1);
                set_pkt(packet, AK_PKT_IS_PURE_ACK, 0);
            } else {
                length = 0;
            }
        } else {
            if (challenge_verified == 0 &&
                current_time >= (challenge_time + retransmit_timer)) {
                if (helper_prepare_path_challenge_frame(cnx, &bytes[length],
                                                            send_buffer_min_max - checksum_overhead - length,
                                                            &data_bytes, path_x) == 0) {
                    length += (uint32_t) data_bytes;
                    set_path(path_x, AK_PATH_CHALLENGE_TIME, 0, current_time);
                    uint8_t challenge_repeat_count = (uint8_t) get_path(path_x, AK_PATH_CHALLENGE_REPEAT_COUNT, 0);
                    challenge_repeat_count++;
                    set_path(path_x, AK_PATH_CHALLENGE_REPEAT_COUNT, 0, challenge_repeat_count);
                    set_pkt(packet, AK_PKT_IS_CONGESTION_CONTROLLED, 1);


                    if (challenge_repeat_count > PICOQUIC_CHALLENGE_REPEAT_MAX) {
                        PROTOOP_PRINTF(cnx, "%s\n", "Too many challenge retransmits, disconnect");
                        picoquic_set_cnx_state(cnx, picoquic_state_disconnected);
                        helper_callback_function(cnx, 0, NULL, 0, picoquic_callback_close);
                        length = 0;
                    }
                }
            }

            picoquic_state_enum cnx_state = get_cnx(cnx, AK_CNX_STATE, 0);

            if (cnx_state != picoquic_state_disconnected) {
                size_t consumed = 0;
                unsigned int is_pure_ack = (unsigned int) get_pkt(packet, AK_PKT_IS_PURE_ACK);
                ret = helper_scheduler_write_new_frames(cnx, &bytes[length],
                                                        send_buffer_min_max - checksum_overhead - length,
                                                        length - get_pkt(packet, AK_PKT_OFFSET), packet,
                                                        &consumed, &is_pure_ack);
                set_pkt(packet, AK_PKT_IS_PURE_ACK, is_pure_ack);
                if (!ret && consumed > send_buffer_min_max - checksum_overhead - length) {
                    ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                } else if (!ret) {
                    length += consumed;
                    picoquic_path_t *path_0 = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);
                    /* FIXME: Sorry, I'm lazy, this could be easily fixed by making this a PO.
                        * This is needed by the way the cwin is now handled. */
                    if (path_x == path_0 && (header_length != length || helper_is_ack_needed(cnx, current_time, pc, path_x))) {
                        if (helper_prepare_ack_frame(cnx, current_time, pc, &bytes[length], send_buffer_min_max - checksum_overhead - length, &data_bytes) == 0) {
                            length += (uint32_t)data_bytes;
                        }
                    }

                    if (cwin > bytes_in_transit) {
                        /* if present, send tls data */
                        if (tls_ready) {
                            ret = helper_prepare_crypto_hs_frame(cnx, 3, &bytes[length],
                                                                    send_buffer_min_max - checksum_overhead - length, &data_bytes);

                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                if (data_bytes > 0)
                                {
                                    set_pkt(packet, AK_PKT_IS_PURE_ACK, 0);
                                    set_pkt(packet, AK_PKT_CONTAINS_CRYPTO, 1);
                                    set_pkt(packet, AK_PKT_IS_CONGESTION_CONTROLLED, 1);
                                }
                            }
                        }
                        /* if present, send path response. This ensures we send it on the right path */
                        #define PICOQUIC_CHALLENGE_LENGTH 8
                        if (challenge_response_to_send && send_buffer_min_max - checksum_overhead - length >= PICOQUIC_CHALLENGE_LENGTH + 1) {
                            /* This is not really clean, but it will work */
                            my_memset(&bytes[length], picoquic_frame_type_path_response, 1);
                            uint8_t *challenge_response = (uint8_t *) get_path(path_x, AK_PATH_CHALLENGE_RESPONSE, 0);
                            my_memcpy(&bytes[length+1], challenge_response, PICOQUIC_CHALLENGE_LENGTH);
                            set_path(path_x, AK_PATH_CHALLENGE_RESPONSE_TO_SEND, 0, 0);
                            length += PICOQUIC_CHALLENGE_LENGTH + 1;
                            set_pkt(packet, AK_PKT_IS_CONGESTION_CONTROLLED, 1);
                        }
                        /* If necessary, encode the max data frame */
                        uint64_t data_received = get_cnx(cnx, AK_CNX_DATA_RECEIVED, 0);
                        uint64_t maxdata_local = get_cnx(cnx, AK_CNX_MAXDATA_LOCAL, 0);
                        if (ret == 0 && 2 * data_received > maxdata_local) {
                            ret = helper_prepare_max_data_frame(cnx, 2 * data_received, &bytes[length],
                                                                    send_buffer_min_max - checksum_overhead - length, &data_bytes);

                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                if (data_bytes > 0)
                                {
                                    set_pkt(packet, AK_PKT_IS_PURE_ACK, 0);
                                    set_pkt(packet, AK_PKT_IS_CONGESTION_CONTROLLED, 1);
                                }
                            }
                            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                ret = 0;
                            }
                        }
                        /* If necessary, encode the max stream data frames */
                        if (ret == 0) {
                            ret = helper_prepare_required_max_stream_data_frames(cnx, &bytes[length],
                                                                                    send_buffer_min_max - checksum_overhead - length, &data_bytes);
                        }

                        if (ret == 0) {
                            length += (uint32_t)data_bytes;
                            if (data_bytes > 0)
                            {
                                set_pkt(packet, AK_PKT_IS_PURE_ACK, 0);
                                set_pkt(packet, AK_PKT_IS_CONGESTION_CONTROLLED, 1);
                            }
                        }

                        /* If required, request for plugins */
                        uint8_t plugin_requested = (uint8_t) get_cnx(cnx, AK_CNX_PLUGIN_REQUESTED, 0);
                        if (ret == 0 && !plugin_requested) {
                            int is_retransmittable = 1;
                            uint16_t pids_to_request_size = (uint16_t) get_cnx(cnx, AK_CNX_PIDS_TO_REQUEST_SIZE, 0);
                            plugin_req_pid_t *pid_to_request;
                            uint64_t pid_id;
                            char *plugin_name;

                            for (int i = 0; ret == 0 && i < pids_to_request_size; i++) {
                                pid_to_request = (plugin_req_pid_t *) get_cnx(cnx, AK_CNX_PIDS_TO_REQUEST, i);
                                pid_id = (uint64_t) get_preq(pid_to_request, AK_PIDREQ_PID_ID);
                                plugin_name = (char *) get_preq(pid_to_request, AK_PIDREQ_PLUGIN_NAME);
                                ret = helper_write_plugin_validate_frame(cnx, &bytes[length], &bytes[send_buffer_min_max - checksum_overhead],
                                    pid_id, plugin_name, &data_bytes, &is_retransmittable);
                                if (ret == 0) {
                                    length += (uint32_t)data_bytes;
                                    if (data_bytes > 0)
                                    {
                                        set_pkt(packet, AK_PKT_IS_PURE_ACK, 0);
                                        set_pkt(packet, AK_PKT_IS_CONGESTION_CONTROLLED, 1);
                                        set_preq(pid_to_request, AK_PIDREQ_REQUESTED, 1);
                                    }
                                }
                                else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                    ret = 0;
                                }
                            }
                            set_cnx(cnx, AK_CNX_PLUGIN_REQUESTED, 0, 1);
                        }

                        /* Encode the plugin frame, or frames */
                        while (plugin_stream != NULL) {
                            size_t stream_bytes_max = helper_stream_bytes_max(cnx, send_buffer_min_max - checksum_overhead - length, header_length, bytes);
                            ret = helper_prepare_plugin_frame(cnx, plugin_stream, &bytes[length],
                                                                stream_bytes_max, &data_bytes);
                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                if (data_bytes > 0)
                                {
                                    set_pkt(packet, AK_PKT_IS_PURE_ACK, 0);
                                    set_pkt(packet, AK_PKT_IS_CONGESTION_CONTROLLED, 1);
                                }

                                if (stream_bytes_max > checksum_overhead + length + 8) {
                                    plugin_stream = helper_find_ready_plugin_stream(cnx);
                                }
                                else {
                                    break;
                                }
                            }
                            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                ret = 0;
                                break;
                            }
                        }

                        size_t stream_bytes_max = helper_stream_bytes_max(cnx, send_buffer_min_max - checksum_overhead - length, header_length, bytes);
                        stream = helper_schedule_next_stream(cnx, stream_bytes_max, path_x);

                        /* Encode the stream frame, or frames */
                        while (stream != NULL) {
                            ret = helper_prepare_stream_frame(cnx, stream, &bytes[length],
                                                              stream_bytes_max, &data_bytes);
                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                if (data_bytes > 0)
                                {
                                    set_pkt(packet, AK_PKT_IS_PURE_ACK, 0);
                                    set_pkt(packet, AK_PKT_IS_CONGESTION_CONTROLLED, 1);
                                }

                                if (stream_bytes_max > checksum_overhead + length + 8) {
                                    stream_bytes_max = helper_stream_bytes_max(cnx, send_buffer_min_max - checksum_overhead - length, header_length, bytes);
                                    stream = helper_schedule_next_stream(cnx, stream_bytes_max, path_x);
                                } else {
                                    break;
                                }
                            } else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                ret = 0;
                                break;
                            }
                        }

                        if (length == 0 || length == header_length) {
                            /* Don't flood the network with packets! */
                            length = 0;
                        } else if (length > 0 && length != header_length && length + checksum_overhead <= PICOQUIC_RESET_PACKET_MIN_SIZE) {
                            uint32_t pad_size = PICOQUIC_RESET_PACKET_MIN_SIZE - checksum_overhead - length + 1;
                            my_memset(&bytes[length], 0, pad_size);
                        }
                    }
                }
            }

        }
    }

    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) path_x);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, length);
    set_cnx(cnx, AK_CNX_OUTPUT, 2, header_length);
    return (protoop_arg_t) ret;
}