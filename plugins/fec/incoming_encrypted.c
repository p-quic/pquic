
#include "fnv1a.h"
#include "picoquic_internal.h"
#include "tls_api.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "plugin.h"
#include "memory.h"
#include "bpf.h"

/**
 * uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
 * picoquic_packet_header* ph = (picoquic_packet_header *) cnx->protoop_inputv[1];
 * struct sockaddr* addr_from = (struct sockaddr *) cnx->protoop_inputv[2];
 * uint64_t current_time = (uint64_t) cnx->protoop_inputv[3];
 *
 * Output: return code (int)
 */
protoop_arg_t incoming_encrypted(picoquic_cnx_t *cnx)
{
    /* Is argc at the right value? */
    if (cnx->protoop_inputc != 4) {
        printf("Not matching number of arguments: %d != %d\n", cnx->protoop_inputc, 4);
        return PICOQUIC_ERROR_PROTOCOL_OPERATION_UNEXEPECTED_ARGC;
    }

    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    picoquic_packet_header* ph = (picoquic_packet_header *) cnx->protoop_inputv[1];
    struct sockaddr* addr_from = (struct sockaddr *) cnx->protoop_inputv[2];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[3];

    int ret = 0;
    picoquic_packet_context_enum pc = ph->pc;
    picoquic_path_t* path_x = picoquic_get_incoming_path(cnx, ph);

    if (!path_x) {
        ret = PICOQUIC_ERROR_CNXID_CHECK;
    } else if (cnx->cnx_state < picoquic_state_client_almost_ready) {
        /* handshake is not complete. Just ignore the packet */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    } else if (cnx->cnx_state == picoquic_state_disconnected) {
        /* Connection is disconnected. Just ignore the packet */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }
    else {
        /* Packet is correct */
        if (ph->pn64 > path_x->pkt_ctx[pc].first_sack_item.end_of_sack_range) {
            cnx->current_spin = ph->spin ^ cnx->client_mode;
            if (ph->has_spin_bit && cnx->current_spin != cnx->prev_spin) {
                // got an edge
                cnx->prev_spin = cnx->current_spin;
                cnx->spin_edge = 1;
                cnx->spin_vec = (ph->spin_vec == 3) ? 3 : (ph->spin_vec + 1);
                cnx->spin_last_trigger = picoquic_get_quic_time(cnx->quic);
            }
        }

        /* Do not process data in closing or draining modes */
        if (cnx->cnx_state >= picoquic_state_closing_received) {
            /* only look for closing frames in closing modes */
            if (cnx->cnx_state == picoquic_state_closing) {
                int closing_received = 0;

                ret = picoquic_decode_closing_frames(cnx,
                                                     bytes + ph->offset, ph->payload_length, &closing_received);

                if (ret == 0) {
                    if (closing_received) {
                        if (cnx->client_mode) {
                            cnx->cnx_state = picoquic_state_disconnected;
                        }
                        else {
                            cnx->cnx_state = picoquic_state_draining;
                        }
                    }
                    else {
                        path_x->pkt_ctx[ph->pc].ack_needed = 1;
                    }
                }
            }
            else {
                /* Just ignore the packets in closing received or draining mode */
                ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
            }
        }
        else {
            /* Compare the packet address to the current path value */
            if (picoquic_compare_addr((struct sockaddr *)&path_x->peer_addr,
                                      (struct sockaddr *)addr_from) != 0)
            {
                uint8_t buffer[16];
                size_t challenge_length;
                /* Address origin different than expected. Update */
                path_x->peer_addr_len = (addr_from->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
                my_memcpy(&path_x->peer_addr, addr_from, path_x->peer_addr_len);
                /* Reset the path challenge */
                path_x->challenge = picoquic_public_random_64();
                path_x->challenge_verified = 0;
                path_x->challenge_time = current_time + path_x->retransmit_timer;
                path_x->challenge_repeat_count = 0;
                /* Create a path challenge misc frame */
                if (picoquic_prepare_path_challenge_frame(cnx, buffer, sizeof(buffer),
                                                          &challenge_length, path_x) == 0) {
                    if (picoquic_queue_misc_frame(cnx, buffer, challenge_length)) {
                        /* if we cannot send the challenge, just accept packets */
                        path_x->challenge_verified = 1;
                    }
                }
            }

            // TODO: find a way to retrieve fpids
            malloc_source_symbol(cnx, 0, bytes + ph->offset, ph->payload_length);

            /* Accept the incoming frames */
            protoop_arg_t args[5];
            args[0] = (protoop_arg_t) bytes + ph->offset;
            args[1] = (protoop_arg_t) ph->payload_length;
            args[2] = (protoop_arg_t) ph->epoch;
            args[3] = (protoop_arg_t) current_time;
            args[4] = (protoop_arg_t) path_x;
            plugin_run_protoop(cnx, "decode_frames", 5, args, NULL);
//            ret = picoquic_decode_frames(cnx,
//                                         bytes + ph->offset, ph->payload_length, ph->epoch, current_time, path_x);
        }

        if (ret == 0) {
            /* Processing of TLS messages  */
            ret = picoquic_tls_stream_process(cnx);
        }
    }

    return (protoop_arg_t) ret;
}