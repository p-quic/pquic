#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

static uint8_t *decode_ecn_frame(picoquic_cnx_t *cnx, uint8_t *bytes, const uint8_t* bytes_max)
{
    protoop_arg_t args[2];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) bytes_max;
    protoop_params_t pp = get_pp_noparam("decode_ecn_frame", 2, args, NULL);
    return (uint8_t *) plugin_run_protoop(cnx, &pp);
}

/**
 * cnx->protoop_inputv[0] = uint8_t* bytes
 * cnx->protoop_inputv[1] = size_t bytes_maxsize
 * cnx->protoop_inputv[2] = int epoch
 * cnx->protoop_inputv[3] = uint64_t current_time
 * picoquic_path_t* path_x = cnx->protoop_inputv[4]
 *
 * Output: error code (int)
 */
protoop_arg_t decode_frames(picoquic_cnx_t *cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    size_t bytes_maxsize = (size_t) cnx->protoop_inputv[1];
    int epoch = (int) cnx->protoop_inputv[2];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[3];
    picoquic_path_t *path_x = (picoquic_path_t *) cnx->protoop_inputv[4];

    const uint8_t *bytes_max = bytes + bytes_maxsize;
    int ack_needed = 0;
    picoquic_packet_context_enum pc = helper_context_from_epoch(epoch);
    picoquic_packet_context_t * pkt_ctx = &path_x->pkt_ctx[pc];

    while (bytes != NULL && bytes < bytes_max) {
        uint8_t first_byte = bytes[0];

        if (PICOQUIC_IN_RANGE(first_byte, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            if (epoch != 1 && epoch != 3) {
                // DBG_PRINTF("Data frame (0x%x), when only TLS stream is expected", first_byte);
                helper_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, first_byte);
                bytes = NULL;
                break;
            }

            bytes = helper_decode_stream_frame(cnx, bytes, bytes_max, current_time);
            ack_needed = 1;

        } else if (first_byte == picoquic_frame_type_ack) {
            if (epoch == 1) {
                // DBG_PRINTF("Ack frame (0x%x) not expected in 0-RTT packet", first_byte);
                helper_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, first_byte);
                bytes = NULL;
                break;
            }
            bytes = helper_decode_ack_frame(cnx, bytes, bytes_max, current_time, epoch);
        } else if (first_byte == picoquic_frame_type_ack_ecn) {
            if (epoch == 1) {
                // DBG_PRINTF("Ack-ECN frame (0x%x) not expected in 0-RTT packet", first_byte);
                helper_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, first_byte);
                bytes = NULL;
                break;
            }
            bytes = helper_decode_ack_ecn_frame(cnx, bytes, bytes_max, current_time, epoch);
        } else if (epoch != 1 && epoch != 3 && first_byte != picoquic_frame_type_padding
                                            && first_byte != picoquic_frame_type_path_challenge
                                            && first_byte != picoquic_frame_type_path_response
                                            && first_byte != picoquic_frame_type_connection_close
                                            && first_byte != picoquic_frame_type_crypto_hs) {
            helper_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, first_byte);
            bytes = NULL;
            break;

        } else {
            switch (first_byte) {
            case picoquic_frame_type_padding:
                bytes = helper_skip_0len_frame(bytes, bytes_max);
                break;
            case picoquic_frame_type_reset_stream:
                bytes = helper_decode_stream_reset_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_connection_close:
                bytes = helper_decode_connection_close_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_application_close:
                bytes = helper_decode_application_close_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_max_data:
                bytes = helper_decode_max_data_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_max_stream_data:
                bytes = helper_decode_max_stream_data_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_max_stream_id:
                bytes = helper_decode_max_stream_id_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_ping:
                bytes = helper_skip_0len_frame(bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_blocked:
                bytes = helper_decode_blocked_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_stream_blocked:
                bytes = helper_decode_stream_blocked_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_stream_id_needed:
                bytes = helper_decode_stream_id_needed_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_new_connection_id:
                bytes = helper_decode_connection_id_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_stop_sending:
                bytes = helper_decode_stop_sending_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_path_challenge:
                bytes = helper_decode_path_challenge_frame(cnx, bytes, bytes_max);
                break;
            case picoquic_frame_type_path_response:
                bytes = helper_decode_path_response_frame(cnx, bytes, bytes_max);
                break;
            case picoquic_frame_type_crypto_hs:
                bytes = helper_decode_crypto_hs_frame(cnx, bytes, bytes_max, epoch);
                ack_needed = 1;
                break;
            case picoquic_frame_type_new_token:
                bytes = helper_decode_new_token_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case ECN_FRAME_TYPE:
                bytes = decode_ecn_frame(cnx, bytes, bytes_max);
                break;
            default: {
                //helper_protoop_printf(cnx, first_byte);
                uint64_t frame_id64;
                if ((bytes = helper_frames_varint_decode(bytes, bytes_max, &frame_id64)) != NULL) {
                    /* Not implemented yet! */
                    helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_id64);
                    bytes = NULL;
                }
                break;
            }
            }
        }
    }

    if (bytes != NULL && ack_needed != 0) {
        cnx->latest_progress_time = current_time;
        pkt_ctx->ack_needed = 1;
    }

    return (protoop_arg_t) (bytes != NULL ? 0 : PICOQUIC_ERROR_DETECTED);
}
