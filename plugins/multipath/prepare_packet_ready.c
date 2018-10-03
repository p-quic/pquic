#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

/**
 * cnx->protoop_inputv[0] = picoquic_path_t *path_x
 * cnx->protoop_inputv[1] = picoquic_packet_t* packet
 * cnx->protoop_inputv[2] = uint64_t current_time
 * cnx->protoop_inputv[3] = uint8_t* send_buffer
 * cnx->protoop_inputv[4] = size_t send_buffer_max
 * cnx->protoop_inputv[5] = size_t send_length
 *
 * Output: error code (int)
 * cnx->protoop_outputv[0] = size_t send_length
 * cnx->protoop_outputv[1] = picoquic_path_t *path_x
 */
protoop_arg_t prepare_packet_ready(picoquic_cnx_t *cnx)
{
    picoquic_path_t *path_x = (picoquic_path_t *) cnx->protoop_inputv[0];
    picoquic_packet_t* packet = (picoquic_packet_t *) cnx->protoop_inputv[1];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[2];
    uint8_t* send_buffer = (uint8_t *) cnx->protoop_inputv[3];
    size_t send_buffer_max = (size_t) cnx->protoop_inputv[4];
    /* Why do we keep this as regular int and not pointer? Because if we provide this to
     * an eBPF VM, there is no guarantee that this pointer will be part of context memory...
     */
    size_t send_length = (size_t) cnx->protoop_inputv[5];

    /* Select the path */
    path_x = cnx->path[0];

    bpf_data *bpfd = get_bpf_data(cnx);
    path_data_t *pd = NULL;
    uint8_t selected_path_index = 255;
    for (int i = 0; i < bpfd->nb_proposed; i++) {
        pd = &bpfd->paths[i];
        /* If we are the client, activate the path */
        /* FIXME hardcoded */
        if (cnx->client_mode && pd->state == 1 && pd->path_id % 2 == 0) {
            pd->state = 2;
            addr_data_t *adl = NULL;
            addr_data_t *adr = NULL;
            if (pd->path_id == 2) {
                pd->loc_addr_id = 1;
                adl = &bpfd->loc_addrs[0];
                pd->path->local_addr_len = (adl->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
                my_memcpy(&pd->path->local_addr, adl->sa, pd->path->local_addr_len);
                pd->path->if_index_local = (unsigned long) adl->if_index;
                pd->rem_addr_id = 1;
                adr = &bpfd->rem_addrs[0];
                pd->path->peer_addr_len = (adr->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
                my_memcpy(&pd->path->peer_addr, adr->sa, pd->path->peer_addr_len);
            } else {
                // Path id is 4
                pd->loc_addr_id = 2;
                adl = &bpfd->loc_addrs[1];
                pd->path->local_addr_len = (adl->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
                my_memcpy(&pd->path->local_addr, adl->sa, pd->path->local_addr_len);
                pd->path->if_index_local = (unsigned long) adl->if_index;
                pd->rem_addr_id = 1;
                adr = &bpfd->rem_addrs[0];
                pd->path->peer_addr_len = (adr->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
                my_memcpy(&pd->path->peer_addr, adr->sa, pd->path->peer_addr_len);
            }
        }
        if (pd->state == 2) {
            if (path_x == cnx->path[0]) {
                path_x = pd->path;
                selected_path_index = i;
            } else if (bpfd->last_path_index_sent != i) {
                path_x = pd->path;
                selected_path_index = i;
            }
        }
    }
    bpfd->last_path_index_sent = selected_path_index;

    int ret = 0;
    /* TODO: manage multiple streams. */
    picoquic_stream_head* stream = NULL;
    picoquic_packet_type_enum packet_type = picoquic_packet_1rtt_protected_phi0;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;
    int tls_ready = 0;
    int is_cleartext_mode = 0;
    int is_pure_ack = 1;
    size_t data_bytes = 0;
    int retransmit_possible = 1;
    uint32_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint32_t length = 0;
    uint32_t checksum_overhead = helper_get_checksum_length(cnx, is_cleartext_mode);
    uint32_t send_buffer_min_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : (uint32_t)send_buffer_max;
    picoquic_path_t *path_0 = cnx->path[0];


    /* Verify first that there is no need for retransmit or ack
     * on initial or handshake context. This does not deal with EOED packets,
     * as they are handled from within the general retransmission path */
    if (ret == 0) {
        length = helper_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
            path_x, packet, send_buffer_min_max, current_time, &header_length);

        if (length == 0) {
            length = helper_prepare_packet_old_context(cnx, picoquic_packet_context_handshake,
                path_x, packet, send_buffer_min_max, current_time, &header_length);
        }
    }

    if (length == 0) {
        tls_ready = helper_is_tls_stream_ready(cnx);
        stream = helper_find_ready_stream(cnx);
        packet->pc = pc;

        if (ret == 0 && retransmit_possible &&
            (length = helper_retransmit_needed(cnx, pc, path_x, current_time, packet, send_buffer_min_max, &is_cleartext_mode, &header_length)) > 0) {
            /* Set the new checksum length */
            checksum_overhead = helper_get_checksum_length(cnx, is_cleartext_mode);
            /* Check whether it makes sense to add an ACK at the end of the retransmission */
            /* Don't do that if it risks mixing clear text and encrypted ack */
            if (is_cleartext_mode == 0 && packet->ptype != picoquic_packet_0rtt_protected) {
                if (path_x == path_0) {
                    if (helper_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                    send_buffer_min_max - checksum_overhead - length, &data_bytes)
                    == 0) {
                        length += (uint32_t)data_bytes;
                        packet->length = length;
                    }
                } else {
                    if (helper_prepare_mp_ack_frame(cnx, current_time, pc, &bytes[length],
                    send_buffer_min_max - checksum_overhead - length, &data_bytes, path_x) == 0) {
                        length += (uint32_t)data_bytes;
                        packet->length = length;
                    }
                }
            }
            /* document the send time & overhead */
            is_pure_ack = 0;
            packet->send_time = current_time;
            packet->checksum_overhead = checksum_overhead;
        }
        else if (ret == 0) {
            length = helper_predict_packet_header_length(
                cnx, packet_type, path_x);
            packet->ptype = packet_type;
            packet->offset = length;
            header_length = length;
            packet->sequence_number = path_x->pkt_ctx[pc].send_sequence;
            packet->send_time = current_time;
            packet->send_path = path_x;

            if (((stream == NULL && tls_ready == 0 && cnx->first_misc_frame == NULL) || path_x->cwin <= path_x->bytes_in_transit)
                && helper_is_ack_needed(cnx, current_time, pc, path_x) == 0
                && (path_x->challenge_verified == 1 || current_time < path_x->challenge_time + path_x->retransmit_timer)) {
                if (ret == 0 && send_buffer_max > path_x->send_mtu
                    && path_x->cwin > path_x->bytes_in_transit && helper_is_mtu_probe_needed(cnx, path_x)) {
                    length = helper_prepare_mtu_probe(cnx, path_x, header_length, checksum_overhead, bytes);
                    packet->length = length;
                    path_x->mtu_probe_sent = 1;
                    is_pure_ack = 0;
                }
                else {
                    length = 0;
                }
            }
            else {
                if (path_x->challenge_verified == 0 && current_time >= (path_x->challenge_time + path_x->retransmit_timer)) {
                    if (helper_prepare_path_challenge_frame(cnx, &bytes[length],
                        send_buffer_min_max - checksum_overhead - length, &data_bytes, path_x) == 0) {
                        length += (uint32_t)data_bytes;
                        path_x->challenge_time = current_time;
                        path_x->challenge_repeat_count++;


                        if (path_x->challenge_repeat_count > PICOQUIC_CHALLENGE_REPEAT_MAX) {
                            //DBG_PRINTF("%s\n", "Too many challenge retransmits, disconnect");
                            cnx->cnx_state = picoquic_state_disconnected;
                            helper_callback_function(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
                            length = 0;
                        }
                    }
                }

                if (cnx->cnx_state != picoquic_state_disconnected) {
                    if (path_x == path_0) {
                        if (helper_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                            send_buffer_min_max - checksum_overhead - length, &data_bytes)
                            == 0) {
                            length += (uint32_t)data_bytes;
                        }
                    } else {
                        if (helper_prepare_mp_ack_frame(cnx, current_time, pc, &bytes[length],
                        send_buffer_min_max - checksum_overhead - length, &data_bytes, path_x) == 0) {
                            length += (uint32_t)data_bytes;
                        }
                    }

                    if (path_x->cwin > path_x->bytes_in_transit) {
                        /* if present, send tls data */
                        if (tls_ready) {
                            ret = helper_prepare_crypto_hs_frame(cnx, 3, &bytes[length],
                                send_buffer_min_max - checksum_overhead - length, &data_bytes);

                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                if (data_bytes > 0)
                                {
                                    is_pure_ack = 0;
                                }
                            }
                        }
                        /* Try to send two CIDs for 2 paths IDS */
                        if (bpfd->nb_proposed_snt == 0) {
                            helper_prepare_mp_new_connection_id_frame(cnx, &bytes[length], send_buffer_min_max - checksum_overhead - length, &data_bytes, 2, current_time);
                            length += (uint32_t)data_bytes;
                            helper_prepare_mp_new_connection_id_frame(cnx, &bytes[length], send_buffer_min_max - checksum_overhead - length, &data_bytes, 4, current_time);
                            length += (uint32_t)data_bytes;
                            /* And also send add address by the way */
                            helper_prepare_add_address_frame(cnx, &bytes[length], send_buffer_min_max - checksum_overhead - length, &data_bytes);
                            length += (uint32_t)data_bytes;
                        }
                        /* If present, send misc frame */
                        while (cnx->first_misc_frame != NULL) {
                            ret = helper_prepare_first_misc_frame(cnx, &bytes[length],
                                send_buffer_min_max - checksum_overhead - length, &data_bytes);
                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                            }
                            else {
                                if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                    ret = 0;
                                }
                                break;
                            }
                        }
                        /* If necessary, encode the max data frame */
                        if (ret == 0 && 2 * cnx->data_received > cnx->maxdata_local) {
                            ret = helper_prepare_max_data_frame(cnx, 2 * cnx->data_received, &bytes[length],
                                send_buffer_min_max - checksum_overhead - length, &data_bytes);

                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                if (data_bytes > 0)
                                {
                                    is_pure_ack = 0;
                                }
                            }
                            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                ret = 0;
                            }
                        }
                        /* If necessary, encode the max stream data frames */
                        ret = helper_prepare_required_max_stream_data_frames(cnx, &bytes[length],
                            send_buffer_min_max - checksum_overhead - length, &data_bytes);

                        if (ret == 0) {
                            length += (uint32_t)data_bytes;
                            if (data_bytes > 0)
                            {
                                is_pure_ack = 0;
                            }
                        }
                        /* Encode the stream frame, or frames */
                        while (stream != NULL) {
                            ret = helper_prepare_stream_frame(cnx, stream, &bytes[length],
                                send_buffer_min_max - checksum_overhead - length, &data_bytes);

                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                if (data_bytes > 0)
                                {
                                    is_pure_ack = 0;
                                }

                                if (send_buffer_max > checksum_overhead + length + 8) {
                                    stream = helper_find_ready_stream(cnx);
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

                        if (length + checksum_overhead <= PICOQUIC_RESET_PACKET_MIN_SIZE) {
                            uint32_t pad_size = PICOQUIC_RESET_PACKET_MIN_SIZE - checksum_overhead - length + 1;
                            for (uint32_t i = 0; i < pad_size; i++) {
                                bytes[length++] = 0;
                            }
                        }
                    }
                }
            }
        }

        if (cnx->cnx_state != picoquic_state_disconnected) {
            /* If necessary, encode and send the keep alive packet!
             * We only send keep alive packets when no other data is sent!
             */
            if (is_pure_ack == 0)
            {
                cnx->latest_progress_time = current_time;
            }
            else if (
                cnx->keep_alive_interval != 0
                && cnx->latest_progress_time + cnx->keep_alive_interval <= current_time && length == 0) {
                length = helper_predict_packet_header_length(
                    cnx, packet_type, path_x);
                packet->ptype = packet_type;
                packet->pc = pc;
                packet->offset = length;
                header_length = length;
                packet->sequence_number = path_x->pkt_ctx[pc].send_sequence;
                packet->send_path = path_x;
                packet->send_time = current_time;
                bytes[length++] = picoquic_frame_type_ping;
                bytes[length++] = 0;
                cnx->latest_progress_time = current_time;
            }
        }
    }

    helper_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        &send_length, send_buffer, send_buffer_min_max, path_x, current_time);

    helper_cnx_set_next_wake_time(cnx, current_time);

    cnx->protoop_outputc_callee = 2;
    cnx->protoop_outputv[0] = (protoop_arg_t) send_length;
    cnx->protoop_outputv[1] = (protoop_arg_t) path_x;

    return (protoop_arg_t) ret;
}