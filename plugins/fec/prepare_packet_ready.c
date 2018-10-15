#include "picoquic_internal.h"
#include "bpf.h"


#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

static inline bpf_state *initialize_bpf_state_2(picoquic_cnx_t *cnx)
{
    bpf_state *state = (bpf_state *) my_malloc(cnx, sizeof(bpf_state));
    if (!state) return NULL;
    my_memset(state, 0, sizeof(bpf_state));
    state->block_fec_framework = new_block_fec_framework(cnx);
    if (!state->block_fec_framework) {
        my_free(cnx, state);
        return NULL;
    }
    return state;
}

static inline bpf_state *get_bpf_state_2(picoquic_cnx_t *cnx)
{
    int allocated = 0;
    bpf_state **state_ptr = (bpf_state **) get_opaque_data(cnx, FEC_OPAQUE_ID, sizeof(bpf_state *), &allocated);
    if (!state_ptr) return NULL;
    if (allocated) {
        *state_ptr = initialize_bpf_state_2(cnx);
    }
    return *state_ptr;
}


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

    /* Set the path to be the initial one */
    path_x = cnx->path[0];

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
    source_fpid_t *sfpid = NULL;
    uint32_t length_frames = 0;
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
                if (helper_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                                               send_buffer_min_max - checksum_overhead - length, &data_bytes)
                    == 0) {
                    length += (uint32_t)data_bytes;
                    length_frames += (uint32_t)data_bytes;
                    packet->length = length;
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

            PROTOOP_PRINTF(cnx, "LENGTH == %u, MAX_BYTES = %d, stream = %p, tls_ready = %d, first_misc_frame = %p\n",
                    length, send_buffer_min_max - checksum_overhead - length, (protoop_arg_t) stream, (protoop_arg_t) tls_ready, (protoop_arg_t) cnx->first_misc_frame);
            if (((stream == NULL && tls_ready == 0 && cnx->first_misc_frame == NULL) || path_x->cwin <= path_x->bytes_in_transit)
                && helper_is_ack_needed(cnx, current_time, pc, path_x) == 0
                && (path_x->challenge_verified == 1 || current_time < path_x->challenge_time + path_x->retransmit_timer)) {
                PROTOOP_PRINTF(cnx, "BLOCKED\n");
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
                if (path_x->cwin <= path_x->bytes_in_transit)
                    PROTOOP_PRINTF(cnx, "CONGESTION BLOCKED\n");
                if ((stream == NULL && tls_ready == 0 && cnx->first_misc_frame == NULL))
                    PROTOOP_PRINTF(cnx, "NO STREAM DATA TO SEND\n");
            }
            else {
                PROTOOP_PRINTF(cnx, "HERE\n");
                if (path_x->challenge_verified == 0 && current_time >= (path_x->challenge_time + path_x->retransmit_timer)) {
                    if (helper_prepare_path_challenge_frame(cnx, &bytes[length],
                                                              send_buffer_min_max - checksum_overhead - length, &data_bytes, path_x) == 0) {
                        length += (uint32_t)data_bytes;
                        length_frames += (uint32_t)data_bytes;
                        path_x->challenge_time = current_time;
                        path_x->challenge_repeat_count++;


                        if (path_x->challenge_repeat_count > PICOQUIC_CHALLENGE_REPEAT_MAX) {
                            cnx->cnx_state = picoquic_state_disconnected;
                            helper_callback_function(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
                            length = 0;
                        }
                    }
                }

                if (cnx->cnx_state != picoquic_state_disconnected) {

                    bpf_state *state = get_bpf_state_2(cnx);
                    block_fec_framework_t *bff = state->block_fec_framework;

                    if (helper_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                                                   send_buffer_min_max - checksum_overhead - length, &data_bytes)
                        == 0) {
                        length += (uint32_t)data_bytes;
                        length_frames += (uint32_t)data_bytes;
                    }

                    if (has_repair_symbols_to_send(bff)) {
                        protoop_arg_t args[5];
                        PROTOOP_PRINTF(cnx, "BM = %u, LENGTH_FRAMES = %u\n", send_buffer_min_max - checksum_overhead - length, length_frames);
                        ret = helper_write_fec_frame(cnx, state, bytes+length, send_buffer_min_max - checksum_overhead - length, &data_bytes);

                        args[0] = bytes[length + 0];
                        args[1] = bytes[length + 1];
                        args[2] = bytes[length + 2];
                        args[3] = bytes[length + 3];
                        args[4] = bytes[length + 4];
                        helper_protoop_printf(cnx, "BYTES = 0x%x 0x%x 0x%x 0x%x 0x%x \n", args, 5);
                        if (ret == 0) {
                            protoop_arg_t args[1];
                            args[0] = data_bytes;
                            helper_protoop_printf(cnx, "PRODUCED FRAME OF %u BYTES\n", args, 1);
                            // TODO: if we use varint (unlikely), the following won't work anymore
                            // remember the position of the source_fpid, to write the correct source_fpid afterwards
                            length += (uint32_t)data_bytes;
                            length_frames += (uint32_t)data_bytes;
                            if (data_bytes > 0) {
                                is_pure_ack = 0;
                            }
                        } else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                            ret = 0;
                        }
                        PROTOOP_PRINTF(cnx, "ADDED FEC FRAME\n");
                    }

                    if (path_x->cwin > path_x->bytes_in_transit) {
                        /* if present, send tls data */
                        if (tls_ready) {
                            ret = helper_prepare_crypto_hs_frame(cnx, 3, &bytes[length],
                                                                   send_buffer_min_max - checksum_overhead - length, &data_bytes);

                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                length_frames += (uint32_t)data_bytes;
                                if (data_bytes > 0)
                                {
                                    is_pure_ack = 0;
                                }
                            }
                        }
                        /* If present, send misc frame */
                        while (cnx->first_misc_frame != NULL) {
                            ret = helper_prepare_first_misc_frame(cnx, &bytes[length],
                                                                    send_buffer_min_max - checksum_overhead - length, &data_bytes);
                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                length_frames += (uint32_t)data_bytes;
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
                                length_frames += (uint32_t)data_bytes;
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
                        if (ret == 0) {
                            ret = helper_prepare_required_max_stream_data_frames(cnx, &bytes[length],
                                                                                   send_buffer_min_max - checksum_overhead - length, &data_bytes);
                        }

                        if (ret == 0) {
                            length += (uint32_t)data_bytes;
                            length_frames += (uint32_t)data_bytes;
                            if (data_bytes > 0)
                            {
                                is_pure_ack = 0;
                            }
                        }

                        if (stream != NULL && send_buffer_min_max - checksum_overhead - length > sizeof(source_fpid_frame_t) + 1
                             && send_buffer_min_max - checksum_overhead - length - 1 - sizeof(source_fpid_frame_t) > 15) {
                            // add the source fpid frames
                            source_fpid_frame_t spf;
                            ret = helper_write_source_fpid_frame(cnx, &spf, &bytes[length], send_buffer_min_max - checksum_overhead - length, &data_bytes);
                            if (ret == 0) {
                                // TODO: if we use varint (unlikely), the following won't work anymore
                                // remember the position of the source_fpid, to write the correct source_fpid afterwards
                                uint32_t decoded = decode_u32(bytes + length + 1);
                                sfpid = (source_fpid_t *) &decoded;
                                length += (uint32_t) data_bytes;
                                length_frames += (uint32_t) data_bytes;
                                PROTOOP_PRINTF(cnx, "PROTECT PACKET, BLOCK NUMBER = %u, DATA_BYTES = %u\n", sfpid->fec_block_number, data_bytes);
                                if (data_bytes > 0) {
                                    is_pure_ack = 0;
                                }
                            } else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                ret = 0;
                            }
                        }

                        /* Encode the stream frame, or frames */
                        while (stream != NULL && send_buffer_min_max - checksum_overhead - length > sizeof(fec_frame_header_t) + 1) {
                            PROTOOP_PRINTF(cnx, "ADD STREAM FRAME OF MAX %u BYTES\n", send_buffer_min_max - (sizeof(fec_frame_header_t) + 1) - checksum_overhead - length);
                            // FIXME: quick hack to ensure that the repair symbols are not split
                            ret = helper_prepare_stream_frame(cnx, stream, &bytes[length],
                                                                send_buffer_min_max - (sizeof(fec_frame_header_t) + 1) - checksum_overhead - length, &data_bytes);

                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                length_frames += (uint32_t)data_bytes;
                                PROTOOP_PRINTF(cnx, "ADDED SF OF %u BYTES\n", data_bytes);
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

    if (sfpid){
        PROTOOP_PRINTF(cnx, "PPACKET %u\n", length_frames);
        protect_packet(cnx, sfpid, bytes + header_length, (uint16_t) (length_frames));
    }


    helper_finalize_and_protect_packet(cnx, packet,
                                         ret, length, header_length, checksum_overhead,
                                         &send_length, send_buffer, send_buffer_min_max, path_x, current_time);

    helper_cnx_set_next_wake_time(cnx, current_time);

    cnx->protoop_outputc_callee = 2;
    cnx->protoop_outputv[0] = (protoop_arg_t) send_length;
    cnx->protoop_outputv[1] = (protoop_arg_t) path_x;

    PROTOOP_PRINTF(cnx, "SEND PACKET, ret = %d, frames_length = %d, send_length = %d \n", ret, length_frames, send_length);
    return (protoop_arg_t) ret;
}