/**
 * File containing functions related to encrypted packet incoming.
 */

#include "picoquic_internal.h"
#include "plugin.h"
#include "tls_api.h"
#include <string.h>

int incoming_encrypted_check_cid(picoquic_cnx_t *cnx)
{
    int ret = 0;

    if (picoquic_compare_connection_id(&cnx->rcv_ph->dest_cnx_id, &cnx->local_cnxid) != 0) {
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
        /* The nxt_state is implemented as a stack; the latest added one is the first one to be run */
        plugin_push_nxt_state(cnx, PROTOOPID_TLS_STREAM_PROCESS);
        plugin_push_nxt_state(cnx, PROTOOPID_PROCESS_CORRECT_PACKET);
        plugin_push_nxt_state(cnx, PROTOOPID_HANDLE_SPINBIT);
    }

    if (ret != 0) {
        cnx->protoop_stop = 1;
    }
    return ret;
}

int incoming_encrypted_handle_spinbit(picoquic_cnx_t *cnx)
{
    picoquic_packet_header* ph = cnx->rcv_ph;
    picoquic_packet_context_enum pc = ph->pc;

    if (ph->pn64 > cnx->pkt_ctx[pc].first_sack_item.end_of_sack_range) {
        cnx->current_spin = ph->spin ^ cnx->client_mode;
        if (ph->has_spin_bit && cnx->current_spin != cnx->prev_spin) {
            // got an edge 
            cnx->prev_spin = cnx->current_spin;
            cnx->spin_edge = 1;
            cnx->spin_vec = (ph->spin_vec == 3) ? 3 : (ph->spin_vec + 1);
            cnx->spin_last_trigger = picoquic_get_quic_time(cnx->quic);
        }
    }

    return 0;
}

int incoming_encrypted_process_correct(picoquic_cnx_t *cnx)
{
    int ret = 0;
    uint8_t *bytes = cnx->rcv_bytes;
    picoquic_packet_header* ph = cnx->rcv_ph;
    struct sockaddr *addr_from = cnx->rcv_addr_from;
    uint64_t current_time = cnx->current_time;

    /* Do not process data in closing or draining modes */
    if (cnx->cnx_state >= picoquic_state_closing_received) {
        /* only look for closing frames in closing modes */
        if (cnx->cnx_state == picoquic_state_closing) {
            int closing_received = 0;

            ret = picoquic_decode_closing_frames(
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
                    cnx->pkt_ctx[ph->pc].ack_needed = 1;
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
        if (picoquic_compare_addr((struct sockaddr *)&cnx->path[0]->peer_addr,
            (struct sockaddr *)addr_from) != 0)
        {
            uint8_t buffer[16];
            size_t challenge_length;
            /* Address origin different than expected. Update */
            cnx->path[0]->peer_addr_len = (addr_from->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
            memcpy(&cnx->path[0]->peer_addr, addr_from, cnx->path[0]->peer_addr_len);
            /* Reset the path challenge */
            cnx->path[0]->challenge = picoquic_public_random_64();
            cnx->path[0]->challenge_verified = 0;
            cnx->path[0]->challenge_time = current_time + cnx->path[0]->retransmit_timer;
            cnx->path[0]->challenge_repeat_count = 0;
            /* Create a path challenge misc frame */
            if (picoquic_prepare_path_challenge_frame(buffer, sizeof(buffer),
                &challenge_length, cnx->path[0]) == 0) {
                if (picoquic_queue_misc_frame(cnx, buffer, challenge_length)) {
                    /* if we cannot send the challenge, just accept packets */
                    cnx->path[0]->challenge_verified = 1;
                }
            }
        }
        /* Accept the incoming frames */
        ret = picoquic_decode_frames(cnx,
            bytes + ph->offset, ph->payload_length, ph->epoch, current_time);
    }

    if (ret != 0) {
        cnx->protoop_stop = 1;
    }

    return ret;
}

void incoming_encrypted_register(picoquic_cnx_t *cnx)
{
    cnx->ops[PROTOOPID_INCOMING_ENCRYPTED_START] = &incoming_encrypted_check_cid;
    cnx->ops[PROTOOPID_HANDLE_SPINBIT] = &incoming_encrypted_handle_spinbit;
    cnx->ops[PROTOOPID_PROCESS_CORRECT_PACKET] = &incoming_encrypted_process_correct;
    /* cnx->ops[PROTOOPID_DECODE_FRAME] = &picoquic_decode_frames; */

    cnx->ops[PROTOOPID_TLS_STREAM_PROCESS] = &picoquic_tls_stream_process;
}