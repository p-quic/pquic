/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "fnv1a.h"
#include "picoquic_internal.h"
#include "tls_api.h"
#include <stdlib.h>
#include <string.h>
#include "plugin.h"
#include "memory.h"
#include "logger.h"

/*
 * Sending logic.
 *
 * Data is sent over streams. This is instantiated by the "Post to stream" command, which
 * chains data to the head of stream structure. Data is unchained when it sent for the
 * first time.
 * 
 * Data is sent in packets, which contain stream frames and possibly other frames.
 * The retransmission logic operates on packets. If a packet is seen as lost, the
 * important frames that it contains will have to be retransmitted.
 *
 * Unacknowledged packets are kept in a chained list. Packets get removed from that
 * list during the processing of acknowledgements. Packets are marked lost when a
 * sufficiently older packet is acknowledged, or after a timer. Lost packets
 * generate new packets, which are queued in the chained list.
 *
 * Stream 0 is special, in the sense that it cannot be closed or reset, and is not
 * subject to flow control.
 */
int picoquic_add_to_stream(picoquic_cnx_t* cnx, uint64_t stream_id,
    const uint8_t* data, size_t length, int set_fin)
{
    int ret = 0;
    int is_unidir = 0;
    picoquic_stream_head* stream = NULL;

    stream = picoquic_find_stream(cnx, stream_id, 0);

    if (stream == NULL) {
        /* Need to check that the ID is authorized */

        /* Check parity */
        if (IS_CLIENT_STREAM_ID(stream_id) != cnx->client_mode) {
            ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
        }

        if (ret == 0) {
            stream = picoquic_create_stream(cnx, stream_id);

            if (stream == NULL) {
                ret = PICOQUIC_ERROR_MEMORY;
            } else if (is_unidir) {
                /* Mark the stream as already finished in remote direction */
                picoquic_add_stream_flags(cnx, stream, picoquic_stream_flag_fin_signalled | picoquic_stream_flag_fin_received);
            }
        }
    }

    if (ret == 0 && set_fin) {
        if ((stream->stream_flags & picoquic_stream_flag_fin_notified) != 0) {
            /* app error, notified the fin twice*/
            if (length > 0) {
                ret = -1;
            }
        } else {
            picoquic_add_stream_flags(cnx, stream, picoquic_stream_flag_fin_notified);
        }
    }

    /* If our side has sent RST_STREAM or received STOP_SENDING, we should not send anymore data. */
    if (STREAM_RESET_SENT(stream) || STREAM_STOP_SENDING_RECEIVED(stream)) {
        ret = -1;
    }

    if (ret == 0 && length > 0) {
        picoquic_stream_data* stream_data = (picoquic_stream_data*)malloc(sizeof(picoquic_stream_data));

        if (stream_data == 0) {
            ret = -1;
        } else {
            stream_data->bytes = (uint8_t*)malloc(length);

            if (stream_data->bytes == NULL) {
                free(stream_data);
                stream_data = NULL;
                ret = -1;
            } else {
                picoquic_stream_data** pprevious = &stream->send_queue;
                picoquic_stream_data* next = stream->send_queue;

                memcpy(stream_data->bytes, data, length);
                stream_data->length = length;
                stream_data->offset = 0;
                stream_data->next_stream_data = NULL;

                while (next != NULL) {
                    pprevious = &next->next_stream_data;
                    next = next->next_stream_data;
                }

                *pprevious = stream_data;
                stream->sending_offset += length;
            }
        }

        LOG_EVENT(cnx, "APPLICATION", "ADD_TO_STREAM", "", "{\"stream\": \"%p\", \"stream_id\": %lu, \"data_ptr\": \"%p\", \"length\": %lu, \"fin\": %d, \"queued_size\": %lu}", stream, stream->stream_id, data, length, set_fin, stream->sending_offset - stream->sent_offset);

        picoquic_cnx_set_next_wake_time(cnx, picoquic_get_quic_time(cnx->quic), 1);
    }

    return ret;
}

int picoquic_reset_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint16_t local_stream_error)
{
    int ret = 0;
    picoquic_stream_head* stream = NULL;

    stream = picoquic_find_stream(cnx, stream_id, 1);

    if (stream == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else if ((stream->stream_flags & picoquic_stream_flag_fin_sent) != 0) {
        ret = PICOQUIC_ERROR_STREAM_ALREADY_CLOSED;
    }
    else if ((stream->stream_flags & picoquic_stream_flag_reset_requested) == 0) {
        stream->local_error = local_stream_error;
        picoquic_add_stream_flags(cnx, stream, picoquic_stream_flag_reset_requested);
        LOG_EVENT(cnx, "STREAMS", "RESET_STREAM", "", "{\"stream\": \"%p\", \"stream_id\": %lu, \"error\": %d}", stream, stream_id, local_stream_error);
    }

    picoquic_cnx_set_next_wake_time(cnx, picoquic_get_quic_time(cnx->quic), 1);

    return ret;
}

int picoquic_stop_sending(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint16_t local_stream_error)
{
    int ret = 0;
    picoquic_stream_head* stream = NULL;

    stream = picoquic_find_stream(cnx, stream_id, 1);

    if (stream == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else if ((stream->stream_flags & picoquic_stream_flag_reset_received) != 0) {
        ret = PICOQUIC_ERROR_STREAM_ALREADY_CLOSED;
    }
    else if ((stream->stream_flags & picoquic_stream_flag_stop_sending_requested) == 0) {
        stream->local_stop_error = local_stream_error;
        picoquic_add_stream_flags(cnx, stream, picoquic_stream_flag_stop_sending_requested);
        LOG_EVENT(cnx, "STREAMS", "STOP_SENDING", "", "{\"stream\": \"%p\", \"stream_id\": %lu, \"error\": %d}", stream, stream_id, local_stream_error);
    }

    picoquic_cnx_set_next_wake_time(cnx, picoquic_get_quic_time(cnx->quic), 1);

    return ret;
}

/*
 * Sending plugins
 */
int picoquic_add_to_plugin_stream(picoquic_cnx_t* cnx, uint64_t pid_id,
    const uint8_t* data, size_t length, int set_fin)
{
    int ret = 0;
    int is_unidir = 1;
    picoquic_stream_head* stream = NULL;

    stream = picoquic_find_plugin_stream(cnx, pid_id, 0);

    if (stream == NULL) {
        /* Need to check that the ID is authorized */

        /* Check that it is initiated by the server */
        if (cnx->client_mode) {
            ret = PICOQUIC_ERROR_INVALID_PLUGIN_STREAM_ID;
        }

        if (ret == 0) {
            stream = picoquic_create_plugin_stream(cnx, pid_id);

            if (stream == NULL) {
                ret = PICOQUIC_ERROR_MEMORY;
            } else if (is_unidir) {
                /* Mark the stream as already finished in remote direction */
                picoquic_add_stream_flags(cnx, stream, picoquic_stream_flag_fin_signalled | picoquic_stream_flag_fin_received);
            }
        }
    }

    if (ret == 0 && set_fin) {
        if ((stream->stream_flags & picoquic_stream_flag_fin_notified) != 0) {
            /* app error, notified the fin twice*/
            if (length > 0) {
                ret = -1;
            }
        } else {
            picoquic_add_stream_flags(cnx, stream, picoquic_stream_flag_fin_notified);
        }
    }

    /* If our side has sent RST_STREAM or received STOP_SENDING, we should not send anymore data. */
    if (STREAM_RESET_SENT(stream) || STREAM_STOP_SENDING_RECEIVED(stream)) {
        ret = -1;
    }

    if (ret == 0 && length > 0) {
        picoquic_stream_data* stream_data = (picoquic_stream_data*)malloc(sizeof(picoquic_stream_data));

        if (stream_data == 0) {
            ret = -1;
        } else {
            stream_data->bytes = (uint8_t*)malloc(length);

            if (stream_data->bytes == NULL) {
                free(stream_data);
                stream_data = NULL;
                ret = -1;
            } else {
                picoquic_stream_data** pprevious = &stream->send_queue;
                picoquic_stream_data* next = stream->send_queue;

                memcpy(stream_data->bytes, data, length);
                stream_data->length = length;
                stream_data->offset = 0;
                stream_data->next_stream_data = NULL;

                while (next != NULL) {
                    pprevious = &next->next_stream_data;
                    next = next->next_stream_data;
                }

                *pprevious = stream_data;
            }
        }

        LOG_EVENT(cnx, "APPLICATION", "ADD_TO_PLUGIN_STREAM", "", "{\"stream\": \"%p\", \"pid_id\": %lu, \"data_ptr\": \"%p\", \"length\": %lu, \"fin\": %d}", stream, stream->stream_id, data, length, set_fin);

        picoquic_cnx_set_next_wake_time(cnx, picoquic_get_quic_time(cnx->quic), 1);
    }

    return ret;
}

/*
 * Packet management
 */

picoquic_packet_t* picoquic_create_packet(picoquic_cnx_t *cnx)
{
    picoquic_packet_t* packet = (picoquic_packet_t*)malloc(sizeof(picoquic_packet_t));

    if (packet != NULL) {
        memset(packet, 0, sizeof(picoquic_packet_t));
        packet->is_pure_ack = 1;
    }

    return packet;
}

void picoquic_destroy_packet(picoquic_packet_t *p)
{
    if (p->metadata) {

        plugin_struct_metadata_t *current_md, *tmp;

        HASH_ITER(hh, p->metadata, current_md, tmp) {
            HASH_DEL(p->metadata,current_md);  /* delete; users advances to next */
            free(current_md);            /* optional- if you want to free  */
        }
    }
    free(p);
}

void picoquic_update_payload_length(
    uint8_t* bytes, size_t pnum_index, size_t header_length, size_t packet_length)
{
    if ((bytes[0] & 0x80) != 0 && header_length > 6 && packet_length > header_length && packet_length < 0x4000)
    {
        picoquic_varint_encode_16(bytes + pnum_index - 2, (uint16_t)(packet_length - header_length));
    }
}

uint32_t picoquic_predict_packet_header_length_11(
    picoquic_packet_type_enum packet_type,
    picoquic_connection_id_t dest_cnx_id,
    picoquic_connection_id_t srce_cnx_id)
{
    uint32_t length = 0;

    if (packet_type == picoquic_packet_1rtt_protected_phi0 || packet_type == picoquic_packet_1rtt_protected_phi1) {
        /* Compute length of a short packet header */

        length = 1 + dest_cnx_id.id_len + 4;
    }
    else {
        /* Compute length of a long packet header */
        length = 1 + /* version */ 4 + /* cnx_id prefix */ 1 + dest_cnx_id.id_len + srce_cnx_id.id_len + /* segment length */ 2 + /* seq num */ 4;
    }

    return length;
}

/**
 * See PROTOOP_NOPARAM_GET_DESTINATION_CONNECTION_ID
 */
protoop_arg_t get_destination_connection_id(picoquic_cnx_t* cnx)
{
    /* Don't use all the argument here */
    picoquic_packet_type_enum packet_type = (picoquic_packet_type_enum) cnx->protoop_inputv[0];

    picoquic_connection_id_t *dest_cnx_id = NULL;

    if ((packet_type == picoquic_packet_initial ||
            packet_type == picoquic_packet_0rtt_protected)
            && picoquic_is_connection_id_null(cnx->path[0]->remote_cnxid))
    {
        dest_cnx_id = &cnx->initial_cnxid;
    }
    else
    {
        dest_cnx_id = &cnx->path[0]->remote_cnxid;
    }

    return (protoop_arg_t) dest_cnx_id;
}

picoquic_connection_id_t *picoquic_get_destination_connection_id(
    picoquic_cnx_t* cnx, picoquic_packet_type_enum packet_type,
    picoquic_path_t* path_x)
{
    return (picoquic_connection_id_t*) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_GET_DESTINATION_CONNECTION_ID, NULL,
        packet_type, path_x);
}

uint32_t picoquic_create_packet_header(
    picoquic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type,
    picoquic_path_t* path_x,
    uint64_t sequence_number,
    uint8_t* bytes,
    uint32_t * pn_offset,
    uint32_t * pn_length)
{
    uint32_t length = 0;
    picoquic_connection_id_t dest_cnx_id = * (picoquic_get_destination_connection_id(cnx, packet_type, path_x));

    /* Prepare the packet header */
    if (packet_type == picoquic_packet_1rtt_protected_phi0 || packet_type == picoquic_packet_1rtt_protected_phi1) {
        /* Create a short packet -- using 32 bit sequence numbers for now */
        uint8_t K = (packet_type == picoquic_packet_1rtt_protected_phi0) ? 0 : 0x40;
        const uint8_t C = 0x30;
        uint8_t spin_vec = (uint8_t)(cnx->spin_vec);
        uint8_t spin_bit = (uint8_t)((cnx->current_spin) << 2);

        if (!cnx->spin_edge) spin_vec = 0;
        else {
            cnx->spin_edge = 0;
            uint64_t dt = picoquic_get_quic_time(cnx->quic) - cnx->spin_last_trigger;
            if (dt > PICOQUIC_SPIN_VEC_LATE) { // DELAYED
                spin_vec = 1;
                // fprintf(stderr, "Delayed Outgoing Spin=%d DT=%ld\n", cnx->current_spin, dt);
            }
        }

        length = 0;
        bytes[length++] = (K | C | spin_bit | spin_vec);
        length += picoquic_format_connection_id(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, dest_cnx_id);

        *pn_offset = length;
        *pn_length = 4;
        picoquic_headint_encode_32(&bytes[length], sequence_number);
        length += 4;
    }
    else {
        /* Create a long packet */

        switch (packet_type) {
        case picoquic_packet_initial:
            bytes[0] = 0xFF;
            break;
        case picoquic_packet_retry:
            bytes[0] = 0xFE;
            break;
        case picoquic_packet_handshake:
            bytes[0] = 0xFD;
            break;
        case picoquic_packet_0rtt_protected:
            bytes[0] = 0xFC;
            break;
        default:
            bytes[0] = 0x80;
            break;
        }
        length = 1;
        if ((cnx->cnx_state == picoquic_state_client_init || cnx->cnx_state == picoquic_state_client_init_sent) && packet_type == picoquic_packet_initial) {
            picoformat_32(&bytes[length], cnx->proposed_version);
        }
        else {
            picoformat_32(&bytes[length],
                picoquic_supported_versions[cnx->version_index].version);
        }
        length += 4;

        bytes[length++] = picoquic_create_packet_header_cnxid_lengths(dest_cnx_id.id_len, path_x->local_cnxid.id_len);

        length += picoquic_format_connection_id(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, dest_cnx_id);
        length += picoquic_format_connection_id(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, path_x->local_cnxid);

        /* Special case of packet initial -- encode token as part of header */
        if (packet_type == picoquic_packet_initial) {
            length += (uint32_t)picoquic_varint_encode(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, cnx->retry_token_length);
            if (cnx->retry_token_length > 0) {
                memcpy(&bytes[length], cnx->retry_token, cnx->retry_token_length);
                length += cnx->retry_token_length;
            }
        }

        if (packet_type == picoquic_packet_retry) {
            /* No payload length and no sequence number for Retry */
            *pn_offset = 0;
            *pn_length = 0;
        } else {
            /* Reserve two bytes for payload length */
            bytes[length++] = 0;
            bytes[length++] = 0;
            /* Encode the sequence number */
            *pn_offset = length;
            *pn_length = 4;
            picoquic_headint_encode_32(&bytes[length], sequence_number);
            length += 4;
        }
    }

    return length;
}

/**
 * See PROTOOP_NOPARAM_PREDICT_PACKET_HEADER_LENGTH
 */
protoop_arg_t predict_packet_header_length(picoquic_cnx_t *cnx)
{
    picoquic_packet_type_enum packet_type = (picoquic_packet_type_enum) cnx->protoop_inputv[0];
    /* Don't use path here */

    uint32_t header_length = 0;

    if (packet_type == picoquic_packet_1rtt_protected_phi0 || 
        packet_type == picoquic_packet_1rtt_protected_phi1) {
        /* Compute length of a short packet header */
        header_length = 1 + cnx->path[0]->remote_cnxid.id_len + 4;
    }
    else {
        /* Compute length of a long packet header */
        header_length = 1 + /* version */ 4 + /* cnx_id prefix */ 1;

        /* add dest-id length */
        if ((packet_type == picoquic_packet_initial ||
            packet_type == picoquic_packet_0rtt_protected)
            && picoquic_is_connection_id_null(cnx->path[0]->remote_cnxid)) {
            header_length += cnx->initial_cnxid.id_len;
        }
        else {
            header_length += cnx->path[0]->remote_cnxid.id_len;
        }

        /* add srce-id length */
        header_length += cnx->path[0]->local_cnxid.id_len;

        /* add length of payload length and packet number */
        header_length += 2 + 4;

        /* add length of tokens for initial packets */
        if (packet_type == picoquic_packet_initial) {
            uint8_t useless[16];
            header_length += (uint32_t)picoquic_varint_encode(useless, 16, cnx->retry_token_length);
            header_length += (uint32_t)cnx->retry_token_length;
        }
    }

    return (protoop_arg_t) header_length;
}

uint32_t picoquic_predict_packet_header_length(
    picoquic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type,
    picoquic_path_t* path_x)
{
    return (uint32_t) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREDICT_PACKET_HEADER_LENGTH, NULL,
        packet_type, path_x);
}

/**
 * See PROTOOP_NOPARAM_GET_CHECKSUM_LENGTH
 */
protoop_arg_t get_checksum_length(picoquic_cnx_t *cnx)
{
    int is_cleartext_mode = (int) cnx->protoop_inputv[0];
    uint32_t ret = 16;

    if (is_cleartext_mode || cnx->crypto_context[2].aead_encrypt == NULL) {
        ret = picoquic_aead_get_checksum_length(cnx->crypto_context[0].aead_encrypt);
    } else {
        ret = picoquic_aead_get_checksum_length(cnx->crypto_context[2].aead_encrypt);
    }

    return (protoop_arg_t) ret;
}

/*
 * Management of packet protection
 */
uint32_t picoquic_get_checksum_length(picoquic_cnx_t* cnx, int is_cleartext_mode)
{
    return (uint32_t) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_GET_CHECKSUM_LENGTH, NULL,
        is_cleartext_mode);
}

uint32_t picoquic_protect_packet(picoquic_cnx_t* cnx, 
    picoquic_packet_type_enum ptype,
    uint8_t * bytes, 
    picoquic_path_t* path_x,
    uint64_t sequence_number,
    uint32_t length, uint32_t header_length,
    uint8_t* send_buffer, uint32_t send_buffer_max,
    void * aead_context, void* pn_enc)
{
    uint32_t send_length;
    uint32_t h_length;
    uint32_t pn_offset = 0;
    size_t sample_offset = 0;
    size_t sample_size = picoquic_pn_iv_size(pn_enc);
    uint32_t pn_length = 0;
    uint32_t aead_checksum_length = (uint32_t)picoquic_aead_get_checksum_length(aead_context);

    /* Create the packet header just before encrypting the content */
    h_length = picoquic_create_packet_header(cnx, ptype, path_x,
        sequence_number, send_buffer, &pn_offset, &pn_length);
    /* Make sure that the payload length is encoded in the header */
    /* Using encryption, the "payload" length also includes the encrypted packet length */
    picoquic_update_payload_length(send_buffer, pn_offset, h_length - pn_length, length + aead_checksum_length);

    LOG {
        picoquic_connection_id_t dest_cnx_id = *(picoquic_get_destination_connection_id(cnx, ptype, path_x));
        char dest_id_str[(dest_cnx_id.id_len) + 1];
        snprintf_bytes(dest_id_str, (dest_cnx_id.id_len * 2) + 1, dest_cnx_id.id, dest_cnx_id.id_len);

        uint32_t payload_length = (length + aead_checksum_length) - (h_length - pn_length);

        if (ptype == picoquic_packet_1rtt_protected_phi0 || ptype == picoquic_packet_1rtt_protected_phi1) {
            LOG_EVENT(cnx, "TRANSPORT", "SHORT_HEADER_CREATED", "", "{\"type\": \"%s\", \"dcid\": \"%s\", \"pn\": %lu, \"payload_length\": %d}", picoquic_log_ptype_name(ptype), dest_id_str, sequence_number, payload_length);
        } else LOG {
            char srce_id_str[(path_x->local_cnxid.id_len) + 1];
            snprintf_bytes(srce_id_str, (path_x->local_cnxid.id_len * 2) + 1, path_x->local_cnxid.id, path_x->local_cnxid.id_len);

            LOG_EVENT(cnx, "TRANSPORT", "LONG_HEADER_CREATED", "", "{\"type\": \"%s\", \"dcid\": \"%s\", \"scid\": \"%s\", \"pn\": %lu, \"payload_length\": %d}", picoquic_log_ptype_name(ptype), dest_id_str, srce_id_str, sequence_number, payload_length);
        }
    }

    /* If fuzzing is required, apply it*/
    if (cnx->quic->fuzz_fn != NULL) {
        if (h_length == header_length) {
            memcpy(bytes, send_buffer, header_length);
        }
        length = cnx->quic->fuzz_fn(cnx->quic->fuzz_ctx, cnx, bytes,
            send_buffer_max - aead_checksum_length, length, header_length);
        if (h_length == header_length) {
            memcpy(send_buffer, bytes, header_length);
        }
    }

    /* Encrypt the packet */
    send_length = (uint32_t)picoquic_aead_encrypt_generic(send_buffer + /* header_length */ h_length,
        bytes + header_length, length - header_length,
        sequence_number, send_buffer, /* header_length */ h_length, aead_context);

    send_length += /* header_length */ h_length;

    /* Next, encrypt the PN -- The sample is located after the pn_offset */
    sample_offset = /* header_length */ pn_offset + 4;

    if (sample_offset + sample_size > send_length)
    {
        sample_offset = send_length - sample_size;
    }

    if (pn_offset < sample_offset)
    {
        /* Encode */
        picoquic_pn_encrypt(pn_enc, send_buffer + sample_offset, send_buffer + /* pn_offset */ pn_offset, 
            send_buffer + /* pn_offset */ pn_offset, pn_length);
    }

    /* if needed, log the segment */
    if (cnx->quic->F_log != NULL) {
        picoquic_log_outgoing_segment(cnx->quic->F_log, 1, cnx,
            bytes, sequence_number, length,
            send_buffer, send_length);
    }

    return send_length;
}

/*
 * Reset the pacing data after CWIN is updated
 */

void picoquic_update_pacing_data(picoquic_path_t * path_x)
{
    path_x->packet_time_nano_sec = path_x->smoothed_rtt * 1000ull * path_x->send_mtu;
    path_x->packet_time_nano_sec /= path_x->cwin;

    path_x->pacing_margin_micros = 16 * path_x->packet_time_nano_sec;
    if (path_x->pacing_margin_micros > (path_x->rtt_min / 8)) {
        path_x->pacing_margin_micros = (path_x->rtt_min / 8);
    }
    if (path_x->pacing_margin_micros < 1000) {
        path_x->pacing_margin_micros = 1000;
    }
}

/* 
 * Update the pacing data after sending a packet
 */
void picoquic_update_pacing_after_send(picoquic_path_t * send_path, uint64_t current_time)
{
    if (send_path->next_pacing_time < current_time) {
        send_path->next_pacing_time = current_time;
        send_path->pacing_reminder_nano_sec = 0;
    } else {
        send_path->pacing_reminder_nano_sec += send_path->packet_time_nano_sec;
        send_path->next_pacing_time += (send_path->pacing_reminder_nano_sec >> 10);
        send_path->pacing_reminder_nano_sec &= 0x3FF;
    }
}

/*
 * Final steps in packet transmission: queue for retransmission, etc
 */

void picoquic_queue_for_retransmit(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    size_t length, uint64_t current_time)
{
    picoquic_packet_context_enum pc = packet->pc;

    if (packet->is_congestion_controlled) {
        packet->send_length = length;
        path_x->bytes_in_transit += packet->send_length;
        LOG_EVENT(cnx, "CONGESTION_CONTROL", "BYTES_IN_TRANSIT_UPDATE", "QUEUE_FOR_RETRANSMIT", "{\"path\": \"%p\", \"bytes_in_transit\": %lu}", path_x, path_x->bytes_in_transit);
    }

    /* Manage the double linked packet list for retransmissions */
    packet->previous_packet = NULL;
    if (path_x->pkt_ctx[pc].retransmit_newest == NULL) {
        packet->next_packet = NULL;
        path_x->pkt_ctx[pc].retransmit_oldest = packet;
    } else {
        packet->next_packet = path_x->pkt_ctx[pc].retransmit_newest;
        packet->next_packet->previous_packet = packet;
    }
    path_x->pkt_ctx[pc].retransmit_newest = packet;

    /* Update the pacing data */
    picoquic_update_pacing_after_send(path_x, current_time);
}

void remove_registered_plugin_frames(picoquic_cnx_t *cnx, int received, picoquic_packet_t *p) {

    /* If the packet contained plugin frames, update their counters */
    picoquic_packet_plugin_frame_t* pppf = p->plugin_frames;
    picoquic_packet_plugin_frame_t* tmp;
    while (pppf) {
        tmp = pppf;
        tmp->plugin->bytes_in_flight -= tmp->bytes;
        pppf = tmp->next;
        LOG_EVENT(cnx, "PLUGINS", "BYTES_IN_FLIGHT_UPDATE", "DEQUEUE_RETRANSMIT_PACKET", "{\"plugin\": \"%s\", \"bytes_in_flight\": %lu}", tmp->plugin->name, tmp->plugin->bytes_in_flight);
        protoop_prepare_and_run_param(cnx, &PROTOOP_PARAM_NOTIFY_FRAME, tmp->rfs->frame_type, NULL, tmp->rfs, received);
        free(tmp);
    }
    p->plugin_frames = NULL;
}

/**
 * See PROTOOP_NOPARAM_DEQUEUE_RETRANSMIT_PACKET
 */
protoop_arg_t dequeue_retransmit_packet(picoquic_cnx_t *cnx)
{
    picoquic_packet_t *p = (picoquic_packet_t *) cnx->protoop_inputv[0];
    int should_free = (int) cnx->protoop_inputv[1];

    size_t dequeued_length = p->send_length;
    picoquic_packet_context_enum pc = p->pc;
    picoquic_path_t* send_path = p->send_path;

    if (p->previous_packet == NULL) {
        send_path->pkt_ctx[pc].retransmit_newest = p->next_packet;
    }
    else {
        p->previous_packet->next_packet = p->next_packet;
    }

    if (p->next_packet == NULL) {
        send_path->pkt_ctx[pc].retransmit_oldest = p->previous_packet;
    }
    else {
#ifdef _DEBUG
        if (p->next_packet->pc != pc) {
            DBG_PRINTF("Inconsistent PC in queue, %d vs %d\n", p->next_packet->pc, pc);
        }

        if (p->next_packet->previous_packet != p) {
            DBG_PRINTF("Inconsistent chain of packets, pc = %d\n", pc);
        }
#endif
        p->next_packet->previous_packet = p->previous_packet;
    }

    /* Account for bytes in transit, for congestion control, only if the packet is marked as contributing to congestion */
    if (p->is_congestion_controlled) {
        if (p->send_path->bytes_in_transit > dequeued_length) {
            p->send_path->bytes_in_transit -= dequeued_length;
        } else {
            p->send_path->bytes_in_transit = 0;
        }
        LOG_EVENT(cnx, "CONGESTION_CONTROL", "BYTES_IN_TRANSIT_UPDATE", "DEQUEUE_RETRANSMIT_PACKET", "{\"path\": \"%p\", \"bytes_in_transit\": %lu}", p->send_path, p->send_path->bytes_in_transit);
    }

    remove_registered_plugin_frames(cnx, should_free, p);
    if (should_free) {
        picoquic_destroy_packet(p);
    }
    else {
        LOG_EVENT(cnx, "RECOVERY", "PACKET_LOSS", "DEQUEUE_RETRANSMIT_PACKET", "{\"path\": \"%p\", \"pc\": %d, \"pn\": %lu}", p->send_path, p->pc, p->sequence_number);
        protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PACKET_WAS_LOST, NULL, p, send_path);

        p->next_packet = NULL;

        /* add this packet to the retransmitted list */
        if (send_path->pkt_ctx[pc].retransmitted_oldest == NULL) {
            send_path->pkt_ctx[pc].retransmitted_newest = p;
            send_path->pkt_ctx[pc].retransmitted_oldest = p;
            p->previous_packet = NULL;
        }
        else {
            send_path->pkt_ctx[pc].retransmitted_oldest->next_packet = p;
            p->previous_packet = send_path->pkt_ctx[pc].retransmitted_oldest;
            send_path->pkt_ctx[pc].retransmitted_oldest = p;
        }
    }

    return 0;
}

void picoquic_dequeue_retransmit_packet(picoquic_cnx_t* cnx, picoquic_packet_t* p, int should_free)
{
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_DEQUEUE_RETRANSMIT_PACKET, NULL,
        p, should_free);
}

/**
 * See PROTOOP_NOPARAM_DEQUEUE_RETRANSMITTED_PACKET
 */
protoop_arg_t dequeue_retransmitted_packet(picoquic_cnx_t *cnx)
{
    picoquic_packet_t *p = (picoquic_packet_t *)cnx->protoop_inputv[0];

    picoquic_packet_context_enum pc = p->pc;
    picoquic_path_t* send_path = p->send_path;

    if (p->previous_packet == NULL) {
        send_path->pkt_ctx[pc].retransmitted_newest = p->next_packet;
    }
    else {
        p->previous_packet->next_packet = p->next_packet;
    }

    if (p->next_packet == NULL) {
        send_path->pkt_ctx[pc].retransmitted_oldest = p->previous_packet;
    }
    else {
#ifdef _DEBUG
        if (p->next_packet->pc != pc) {
            DBG_PRINTF("Inconsistent PC in queue, %d vs %d\n", p->next_packet->pc, pc);
        }

        if (p->next_packet->previous_packet != p) {
            DBG_PRINTF("Inconsistent chain of packets, pc = %d\n", pc);
        }
#endif
        p->next_packet->previous_packet = p->previous_packet;
    }

    picoquic_destroy_packet(p);

    return 0;
}

void picoquic_dequeue_retransmitted_packet(picoquic_cnx_t* cnx, picoquic_packet_t* p)
{
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_DEQUEUE_RETRANSMITTED_PACKET, NULL,
        p);
}


/*
 * Final steps of encoding and protecting the packet before sending
 */

/**
 * See PROTOOP_NOPARAM_FINALIZE_AND_PROTECT_PACKET
 */
protoop_arg_t finalize_and_protect_packet(picoquic_cnx_t *cnx)
{
    picoquic_packet_t * packet = (picoquic_packet_t *) cnx->protoop_inputv[0];
    int ret = (int) cnx->protoop_inputv[1];
    uint32_t length = (uint32_t) cnx->protoop_inputv[2];
    uint32_t header_length = (uint32_t) cnx->protoop_inputv[3];
    uint32_t checksum_overhead = (uint32_t) cnx->protoop_inputv[4];
    size_t send_length = (size_t) cnx->protoop_inputv[5];
    uint8_t * send_buffer = (uint8_t *) cnx->protoop_inputv[6];
    uint32_t send_buffer_max = (uint32_t) cnx->protoop_inputv[7];
    picoquic_path_t * path_x = (picoquic_path_t *) cnx->protoop_inputv[8];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[9];

    if (length != 0 && length < header_length) {
        length = 0;
    }

    if (ret == 0 && length > 0) {
        packet->length = length;
        path_x->pkt_ctx[packet->pc].send_sequence++;

        switch (packet->ptype) {
        case picoquic_packet_version_negotiation:
            /* Packet is not encrypted */
            break;
        case picoquic_packet_initial:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, path_x, packet->sequence_number,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[0].aead_encrypt, cnx->crypto_context[0].pn_enc);
            break;
        case picoquic_packet_handshake:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, path_x, packet->sequence_number,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[2].aead_encrypt, cnx->crypto_context[2].pn_enc);
            break;
        case picoquic_packet_retry:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, path_x, packet->sequence_number,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[0].aead_encrypt, cnx->crypto_context[0].pn_enc);
            break;
        case picoquic_packet_0rtt_protected:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, path_x, packet->sequence_number,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[1].aead_encrypt, cnx->crypto_context[1].pn_enc);
            break;
        case picoquic_packet_1rtt_protected_phi0:
        case picoquic_packet_1rtt_protected_phi1:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, path_x, packet->sequence_number,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[3].aead_encrypt, cnx->crypto_context[3].pn_enc);
            break;
        default:
            /* Packet type error. Do nothing at all. */
            length = 0;
            break;
        }

        send_length = length;

        if (length > 0) {
            packet->checksum_overhead = checksum_overhead;
            picoquic_queue_for_retransmit(cnx, path_x, packet, length, current_time);
        } else {
            send_length = 0;
        }
    }
    else {
        send_length = 0;
    }

    return (protoop_arg_t) send_length;
}

void picoquic_finalize_and_protect_packet(picoquic_cnx_t *cnx, picoquic_packet_t * packet, int ret, 
    uint32_t length, uint32_t header_length, uint32_t checksum_overhead,
    size_t * send_length, uint8_t * send_buffer, uint32_t send_buffer_max, 
    picoquic_path_t * path_x, uint64_t current_time)
{
    /* MP: Instead of hooking the following operation every time this function is called, we place it here */
    picoquic_packet_header ph = { 0 };
    picoquic_cnx_t *pcnx = cnx;
    if (picoquic_parse_packet_header(cnx->quic, packet->bytes, length, (struct sockaddr *) &path_x->local_addr, &ph, &pcnx, false) == 0) {
        picoquic_before_sending_segment(cnx, &ph, path_x, packet, length + checksum_overhead);
    }

    /* Yes, the helper macro does not handle more than 9 arguments... Too bad! */
    protoop_arg_t args [10];
    args[0] = (protoop_arg_t) packet;
    args[1] = (protoop_arg_t) ret;
    args[2] = (protoop_arg_t) length;
    args[3] = (protoop_arg_t) header_length;
    args[4] = (protoop_arg_t) checksum_overhead;
    args[5] = (protoop_arg_t) *send_length;
    args[6] = (protoop_arg_t) send_buffer;
    args[7] = (protoop_arg_t) send_buffer_max;
    args[8] = (protoop_arg_t) path_x;
    args[9] = (protoop_arg_t) current_time;
    protoop_params_t pp = { .pid = &PROTOOP_NOPARAM_FINALIZE_AND_PROTECT_PACKET, .inputc = 10, .inputv = args, .outputv = NULL, .caller_is_intern = true };
    *send_length  = (size_t) plugin_run_protoop_internal(cnx, &pp);
}

/**
 * See PROTOOP_NOPARAM_RETRANSMIT_NEEDED_BY_PACKET
 */
protoop_arg_t retransmit_needed_by_packet(picoquic_cnx_t *cnx)
{
    picoquic_packet_t *p = (picoquic_packet_t *) cnx->protoop_inputv[0];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[1];
    int timer_based = (int) cnx->protoop_inputv[2];

    picoquic_packet_context_enum pc = p->pc;
    picoquic_path_t* send_path = p->send_path;
    int64_t delta_seq = send_path->pkt_ctx[pc].highest_acknowledged - p->sequence_number;
    int should_retransmit = 0;
    char* reason = NULL;
    uint64_t retransmit_time;
    int is_timer_based = 0;

    if (delta_seq > 0) {
        /* By default, we use timer based RACK logic to absorb out of order deliveries */
        retransmit_time = p->send_time + send_path->smoothed_rtt + (send_path->smoothed_rtt >> 3);
        is_timer_based = 0;

        /* RACK logic fails when the smoothed RTT is too small, in which case we
         * rely on dupack logic possible, or on a safe estimate of the RACK delay if it
         * is not */
        if (delta_seq < 3) {
            uint64_t rack_timer_min = send_path->pkt_ctx[pc].latest_time_acknowledged + PICOQUIC_RACK_DELAY;
            if (retransmit_time < rack_timer_min) {
                retransmit_time = rack_timer_min;
            }
        } 
    } else {
        /* There has not been any higher packet acknowledged, thus we fall back on timer logic. */
        uint64_t rto = (send_path->pkt_ctx[pc].nb_retransmit == 0) ?
            send_path->retransmit_timer : (1000000ull << (send_path->pkt_ctx[pc].nb_retransmit - 1));
        retransmit_time = p->send_time + rto;
        is_timer_based = 1;
    }
    if (p->ptype == picoquic_packet_0rtt_protected) {
        /* Special case for 0RTT packets */
        if (cnx->cnx_state != picoquic_state_client_almost_ready &&
            cnx->cnx_state != picoquic_state_server_almost_ready &&
            cnx->cnx_state != picoquic_state_client_ready &&
            cnx->cnx_state != picoquic_state_server_ready) {
            /* Set the retransmit time ahead of current time since the connection is not ready */
            retransmit_time = current_time + send_path->smoothed_rtt + PICOQUIC_RACK_DELAY;
        }
        /* TODO: if early data was skipped by the server, we should retransmit
         * immediately. However, there is not good API to do that */
    }

    if (current_time >= retransmit_time) {
        should_retransmit = 1;
        if (is_timer_based) {
            timer_based = 1;
            reason = PROTOOPID_NOPARAM_RETRANSMISSION_TIMEOUT;

        } else {
            timer_based = 0;
            reason = PROTOOPID_NOPARAM_FAST_RETRANSMIT;
        }
    } else {
        timer_based = 0;
    }

    protoop_save_outputs(cnx, timer_based, reason);

    return (protoop_arg_t) should_retransmit;
}

/*
 * If a retransmit is needed, fill the packet with the required
 * retransmission. Also, prune the retransmit queue as needed.
 *
 * TODO: consider that the retransmit timer is per path, from the path on
 * which the packet was first sent, but the retransmission may be on 
 * a different path, with different MTU.
 */

static int picoquic_retransmit_needed_by_packet(picoquic_cnx_t* cnx,
    picoquic_packet_t* p, uint64_t current_time, int* timer_based, char **reason)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int should_retransmit = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_RETRANSMIT_NEEDED_BY_PACKET, outs,
        p, current_time, *timer_based);
    *timer_based = (int) outs[0];
    if (reason != NULL) {
        *reason = (char *) outs[1];
    }
    return should_retransmit;
}

void register_plugin_in_pkt(picoquic_packet_t* packet, protoop_plugin_t* p, uint64_t bytes, reserve_frame_slot_t *rfs)
{
    /* If there is no plugin frame in packet, just create the node! */
    if (packet->plugin_frames == NULL) {
        packet->plugin_frames = malloc(sizeof(picoquic_packet_plugin_frame_t));
        if (!packet->plugin_frames) {
            printf("WARNING: cannot allocate memory for picoquic_packet_plugin_frame_t!\n");
            return;
        }
        packet->plugin_frames->plugin = p;
        packet->plugin_frames->bytes = bytes;
        packet->plugin_frames->rfs = rfs;
        packet->plugin_frames->next = NULL;
        return;
    }

    /* Before, we aggregated the results from a same plugin. However, since we want to keep some context for each
       reserved frame, we do not this anymore.
    */
    picoquic_packet_plugin_frame_t* new_plugin_frames = malloc(sizeof(picoquic_packet_plugin_frame_t));
    if (!new_plugin_frames) {
        printf("WARNING: cannot allocate memory for picoquic_packet_plugin_frame_t!\n");
        return;
    }
    new_plugin_frames->plugin = p;
    new_plugin_frames->bytes = bytes;
    new_plugin_frames->rfs = rfs;
    new_plugin_frames->next = packet->plugin_frames;
    packet->plugin_frames = new_plugin_frames;
}


protoop_arg_t scheduler_write_new_frames(picoquic_cnx_t *cnx) {
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    size_t max_bytes = (size_t) cnx->protoop_inputv[1];
    picoquic_packet_t *packet = (picoquic_packet_t *) cnx->protoop_inputv[2];

    unsigned int is_pure_ack = 1;
    
    reserve_frame_slot_t *rfs;
    reserve_frame_slot_t *first_retry = NULL;
    protoop_arg_t outs[PROTOOPARGS_MAX];
    size_t data_bytes;
    int ret = 0;
    size_t length = 0;
    int is_retransmittable = 0;
    /* First, retry previously considered frames */
    /* FIXME ugly code duplication, but the retry has a slightly different behaviour when retrying the packet */
    while ((rfs = (reserve_frame_slot_t *) queue_peek(cnx->retry_frames)) != NULL &&
           rfs != first_retry &&
           rfs->nb_bytes <= (max_bytes - length)) {
        rfs = (reserve_frame_slot_t *) queue_dequeue(cnx->retry_frames);
        /* If it has not been computed before, compute it now */
        if (PROTOOP_PARAM_WRITE_FRAME.hash == 0) {
            PROTOOP_PARAM_WRITE_FRAME.hash = hash_value_str(PROTOOP_PARAM_WRITE_FRAME.id);
        }
        if (PROTOOP_PARAM_NOTIFY_FRAME.hash == 0) {
            PROTOOP_PARAM_NOTIFY_FRAME.hash = hash_value_str(PROTOOP_PARAM_NOTIFY_FRAME.id);
        }
        ret = (int) protoop_prepare_and_run_param(cnx, &PROTOOP_PARAM_WRITE_FRAME, (param_id_t) rfs->frame_type, outs,
                                                  &bytes[length], &bytes[length + rfs->nb_bytes], rfs->frame_ctx);
        data_bytes = (size_t) outs[0];
        is_retransmittable = (int) outs[1];
        /* TODO FIXME consumed */
        protoop_plugin_t *p = rfs->p;
        if (ret == 0 && data_bytes > 0 && data_bytes <= rfs->nb_bytes) {
            length += (uint32_t) data_bytes;
            /* Keep track of the bytes sent by the plugin */
            p->bytes_in_flight += (uint64_t) data_bytes;
            p->bytes_total += (uint64_t) data_bytes;
            p->frames_total += 1;
            /* Keep track if the packet should be retransmitted or not */
            if (is_retransmittable) {
                is_pure_ack = 0;
            }
            packet->is_congestion_controlled |= rfs->is_congestion_controlled;
            /* And let the packet know that it has plugin bytes */
            register_plugin_in_pkt(packet, p, (uint64_t) data_bytes, rfs);
        } else if (ret == PICOQUIC_MISCCODE_RETRY_NXT_PKT) {
            if (first_retry == NULL) {
                first_retry = rfs;
            }
            /* Put the reservation in the retry queue, for the next packet */
            queue_enqueue(cnx->retry_frames, rfs);
        } else {
            if (data_bytes > rfs->nb_bytes) {
                printf("WARNING: plugin %s reserved frame %lu for %lu bytes, but wrote %lu; erasing the frame\n",
                       cnx->current_plugin->name, rfs->frame_type, rfs->nb_bytes, data_bytes);
            }
            memset(&bytes[length], 0, rfs->nb_bytes);
            protoop_prepare_and_run_param(cnx, &PROTOOP_PARAM_NOTIFY_FRAME, rfs->frame_type, NULL, rfs, 2);
        }

        if (ret == PICOQUIC_MISCCODE_RETRY_NXT_PKT) {
            ret = 0;
        }
    }

    /* Second, empty the reserved frames */
    while ((rfs = (reserve_frame_slot_t *) queue_peek(cnx->reserved_frames)) != NULL &&
           rfs->nb_bytes <= (max_bytes - length)) {
        rfs = (reserve_frame_slot_t *) queue_dequeue(cnx->reserved_frames);
        /* If it has not been computed before, compute it now */
        if (PROTOOP_PARAM_WRITE_FRAME.hash == 0) {
            PROTOOP_PARAM_WRITE_FRAME.hash = hash_value_str(PROTOOP_PARAM_WRITE_FRAME.id);
        }
        if (PROTOOP_PARAM_NOTIFY_FRAME.hash == 0) {
            PROTOOP_PARAM_NOTIFY_FRAME.hash = hash_value_str(PROTOOP_PARAM_NOTIFY_FRAME.id);
        }
        ret = (int) protoop_prepare_and_run_param(cnx, &PROTOOP_PARAM_WRITE_FRAME, (param_id_t) rfs->frame_type, outs,
                                                  &bytes[length], &bytes[length + rfs->nb_bytes], rfs->frame_ctx);
        data_bytes = (size_t) outs[0];
        is_retransmittable = (int) outs[1];
        /* TODO FIXME consumed */
        protoop_plugin_t *p = rfs->p;
        if (ret == 0 && data_bytes > 0 && data_bytes <= rfs->nb_bytes) {
            length += (uint32_t) data_bytes;
            /* Keep track of the bytes sent by the plugin */
            p->bytes_in_flight += (uint64_t) data_bytes;
            p->bytes_total += (uint64_t) data_bytes;
            p->frames_total += 1;
            /* Keep track if the packet should be retransmitted or not */
            if (is_retransmittable) {
                is_pure_ack = 0;
            }
            packet->is_congestion_controlled |= rfs->is_congestion_controlled;
            /* And let the packet know that it has plugin bytes */
            register_plugin_in_pkt(packet, p, (uint64_t) data_bytes, rfs);
        } else if (ret == PICOQUIC_MISCCODE_RETRY_NXT_PKT) {
            /* Put the reservation in the retry queue, for the next packet */
            queue_enqueue(cnx->retry_frames, rfs);
        } else {
            if (data_bytes > rfs->nb_bytes) {
                if (cnx->current_plugin != NULL)
                    printf("WARNING: plugin %s reserved frame %lu for %lu bytes, but wrote %lu; erasing the frame\n",
                           cnx->current_plugin->name, rfs->frame_type, rfs->nb_bytes, data_bytes);
                else
                    printf("WARNING: plugin %p reserved frame %lu for %lu bytes, but wrote %lu; erasing the frame\n",
                           cnx->current_plugin, rfs->frame_type, rfs->nb_bytes, data_bytes);
            }
            memset(&bytes[length], 0, rfs->nb_bytes);
            protoop_prepare_and_run_param(cnx, &PROTOOP_PARAM_NOTIFY_FRAME, rfs->frame_type, NULL, rfs, 2);
        }

        if (ret == PICOQUIC_MISCCODE_RETRY_NXT_PKT) {
            ret = 0;
        }
    }

    protoop_save_outputs(cnx, length, is_pure_ack);
    return ret;
}

// bytes = starting point of the buffer
// max_bytes: max amont of bytes that can be used for the new frames
int picoquic_scheduler_write_new_frames(picoquic_cnx_t *cnx, uint8_t *bytes, size_t max_bytes, picoquic_packet_t *packet, size_t *consumed, unsigned int *is_pure_ack) {
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_SCHEDULER_WRITE_NEW_FRAMES, outs,
        bytes, max_bytes, packet);
    *consumed = (size_t) outs[0];
    *is_pure_ack &= outs[1];
    return ret;
}


/**
 * See PROTOOP_NOPARAM_RETRANSMIT_NEEDED
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
    char* reason = NULL;

    for (int i = 0; i < cnx->nb_paths; i++) {
        picoquic_path_t* orig_path = cnx->path[i];
        picoquic_packet_t* p = orig_path->pkt_ctx[pc].retransmit_oldest;
        /* TODO: while packets are pure ACK, drop them from retransmit queue */
        while (p != NULL) {
            if (!p->is_pure_ack && !p->is_mtu_probe && p->send_length > send_buffer_max) {
                // if the packet is too big to be retransmitted, then give up
                //TODO: retransmit parts of the packet
                length = 0;
                break;
            }
            int should_retransmit = 0;
            int timer_based_retransmit = 0;
            uint64_t lost_packet_number = p->sequence_number;
            picoquic_packet_t* p_next = p->next_packet;
            uint8_t * new_bytes = packet->bytes;
            int ret = 0;

            length = 0;
            /* Get the packet type */

            should_retransmit = picoquic_retransmit_needed_by_packet(cnx, p, current_time, &timer_based_retransmit, &reason);

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
                int do_not_detect_spurious = 1;
                int frame_is_pure_ack = 0;
                size_t frame_length = 0;
                size_t byte_index = 0; /* Used when parsing the old packet */
                size_t checksum_length = 0;
                /* TODO: should be the path on which the packet was transmitted */
                picoquic_path_t * old_path = p->send_path;

                header_length = 0;

                if (p->ptype == picoquic_packet_0rtt_protected) {
                    /* Only retransmit as 0-RTT if contains crypto data */
                    byte_index = p->offset;

                    if (p->contains_crypto) {
                        /* Because path_x must be old_path */
                        length = picoquic_predict_packet_header_length(cnx, picoquic_packet_0rtt_protected, old_path);
                        packet->ptype = picoquic_packet_0rtt_protected;
                        packet->offset = length;
                    } else if (cnx->cnx_state < picoquic_state_client_ready) {
                        should_retransmit = 0;
                    } else {
                        length = picoquic_predict_packet_header_length(cnx, picoquic_packet_1rtt_protected_phi0, path_x);
                        packet->ptype = picoquic_packet_1rtt_protected_phi0;
                        packet->offset = length;
                    }
                } else {
                    length = picoquic_predict_packet_header_length(cnx, p->ptype, path_x);
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

                    /* Update the number of bytes in transit and remove old packet from queue */
                    /* If not pure ack, the packet will be placed in the "retransmitted" queue,
                    * in order to enable detection of spurious restransmissions */
                    int packet_is_pure_ack = p->is_pure_ack;
                    int written_non_pure_ack_frames = 0;

                    if (p->is_mtu_probe && p->length > old_path->send_mtu) {
                        /* MTU probe was lost, presumably because of packet too big */
                        old_path->mtu_probe_sent = 0;
                        old_path->send_mtu_max_tried = (uint32_t)(p->length);
                        /* MTU probes should not be retransmitted */
                        packet_is_pure_ack = 1;
                        do_not_detect_spurious = 0;
                    } else {
                        checksum_length = picoquic_get_checksum_length(cnx, is_cleartext_mode);
                        /* Copy the relevant bytes from one packet to the next */
                        byte_index = p->offset;

                        bool has_unlimited_frame = false;
                        while (ret == 0 && byte_index < p->length) {
                            ret = picoquic_skip_frame(cnx, &p->bytes[byte_index],
                                p->length - byte_index, &frame_length, &frame_is_pure_ack);

                            /* Check whether the data was already acked, which may happen in 
                            * case of spurious retransmissions */
                            if (ret == 0 && frame_is_pure_ack == 0) {
                                ret = picoquic_check_stream_frame_already_acked(cnx, &p->bytes[byte_index],
                                    frame_length, &frame_is_pure_ack);
                            }
                            /* Prepare retransmission if needed */
                            // FIXME: if the packet contained a retransmittable plugin frame, it will be retransmitted while the plugin thinks it has been lost...
                            // FIXME: At the end, the plugin frames must never be retransmitted and use notify to perform retransmission
                            if (ret == 0 && !frame_is_pure_ack) {
                                if (picoquic_is_stream_frame_unlimited(&p->bytes[byte_index])) {
                                    has_unlimited_frame = true;
                                    /* We are at the last frame of the packet, let's put all the plugin frames before it */
                                    size_t consumed = 0;
                                    int new_plugin_frame_is_pure_ack = 0;
                                    if (!packet_is_pure_ack && checksum_length + length + frame_length < send_buffer_max) {
                                        picoquic_scheduler_write_new_frames(cnx, &new_bytes[length], send_buffer_max - checksum_length - length - frame_length, packet, &consumed, (unsigned int *) &new_plugin_frame_is_pure_ack);
                                        if (consumed > 0) {
                                            // we might have written non-pure-ack frames
                                            written_non_pure_ack_frames |= !new_plugin_frame_is_pure_ack;
                                        }
                                        length += consumed;
                                    }
                                    /* Need to PAD to the end of the frame to avoid sending extra bytes */
                                    while (checksum_length + length + frame_length < send_buffer_max) {
                                        new_bytes[length] = picoquic_frame_type_padding;
                                        length++;
                                    }
                                }
                                DBG_PRINTF("%lu <= %lu", length + frame_length + checksum_length, send_buffer_max);
                                if (length + frame_length + checksum_length <= send_buffer_max) {
                                    memcpy(&new_bytes[length], &p->bytes[byte_index], frame_length);
                                    length += (uint32_t)frame_length;
                                    // we have written non-pure-ack frames
                                    written_non_pure_ack_frames |= !frame_is_pure_ack;
                                }
                            }
                            byte_index += frame_length;
                        }
                        if (!packet_is_pure_ack && !has_unlimited_frame && checksum_length + length < send_buffer_max) {
                            // there is remaining space in the packet
                            size_t consumed = 0;
                            picoquic_scheduler_write_new_frames(cnx, &new_bytes[length], send_buffer_max - length - checksum_length, packet, &consumed, (unsigned int *) &frame_is_pure_ack);
                            length += consumed;
                            if (consumed > 0) {
                                // we might have written non-pure-ack frames
                                written_non_pure_ack_frames |= !frame_is_pure_ack;
                            }
                        }
                    }

                    if (written_non_pure_ack_frames)
                        packet->is_pure_ack = 0;

                    picoquic_dequeue_retransmit_packet(cnx, p, p->is_pure_ack & do_not_detect_spurious);

                    /* If we have a good packet, return it */
                    if (packet_is_pure_ack) {
                        length = 0;
                    } else {
                        /* We should also consider if some action was recently observed to consider that it is actually a RTO... */
                        uint64_t retrans_timer = orig_path->pkt_ctx[pc].time_stamp_largest_received + orig_path->smoothed_rtt;
                        if (orig_path->pkt_ctx[pc].latest_retransmit_time >= orig_path->pkt_ctx[pc].time_stamp_largest_received) {
                            retrans_timer = orig_path->pkt_ctx[pc].latest_retransmit_time + orig_path->smoothed_rtt;
                        }
                        /* Or any packet acknowledged */
                        if (orig_path->pkt_ctx[pc].latest_progress_time + orig_path->smoothed_rtt > retrans_timer) {
                            retrans_timer = orig_path->pkt_ctx[pc].latest_progress_time + orig_path->smoothed_rtt;
                        }
                        
                        bool is_timer_based = false;
                        uint64_t retrans_cc_notification_timer = orig_path->pkt_ctx[pc].latest_retransmit_cc_notification_time + orig_path->smoothed_rtt;
                        if (timer_based_retransmit != 0 && current_time >= retrans_timer) {
                            is_timer_based = true;
                            if (orig_path->pkt_ctx[pc].nb_retransmit > 5) {
                                /*
                                * Max retransmission count was exceeded. Disconnect.
                                */
                                DBG_PRINTF("%s\n", "Too many retransmits, disconnect");
                                picoquic_set_cnx_state(cnx, picoquic_state_disconnected);
                                if (cnx->callback_fn) {
                                    (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
                                }
                                length = 0;
                                stop = true;
                                break;
                            } else {
                                orig_path->pkt_ctx[pc].latest_retransmit_time = current_time;
                                if (current_time >= retrans_cc_notification_timer) {
                                    orig_path->pkt_ctx[pc].nb_retransmit++;
                                }
                            }
                        }

                        if (should_retransmit != 0) {
                            if (p->ptype < picoquic_packet_1rtt_protected_phi0) {
                                DBG_PRINTF("Retransmit packet type %d, pc=%d, seq = %llx, is_client = %d\n",
                                    p->ptype, p->pc,
                                    (unsigned long long)p->sequence_number, cnx->client_mode);
                            }

                            /* special case for the client initial */
                            if (p->ptype == picoquic_packet_initial && cnx->client_mode != 0) {
                                while (length < (send_buffer_max - checksum_length)) {
                                    new_bytes[length++] = 0;
                                }
                            }
                            packet->length = length;
                            cnx->nb_retransmission_total++;

                            if (current_time >= retrans_cc_notification_timer && cnx->congestion_alg != NULL) {
                                orig_path->pkt_ctx[pc].latest_retransmit_cc_notification_time = current_time;
                                picoquic_congestion_algorithm_notify_func(cnx, old_path,
                                    (is_timer_based) ? picoquic_congestion_notification_timeout : picoquic_congestion_notification_repeat,
                                    0, 0, lost_packet_number, current_time);
                            }

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

    protoop_save_outputs(cnx, is_cleartext_mode, header_length, reason);

    return (protoop_arg_t) ((int) length);
}

int picoquic_retransmit_needed(picoquic_cnx_t* cnx,
    picoquic_packet_context_enum pc,
    picoquic_path_t * path_x, uint64_t current_time,
    picoquic_packet_t* packet, size_t send_buffer_max, int* is_cleartext_mode, uint32_t* header_length, char **reason)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_RETRANSMIT_NEEDED, outs,
        pc, path_x, current_time, packet, send_buffer_max, *is_cleartext_mode, *header_length);
    *is_cleartext_mode = (int) outs[0];
    *header_length = (uint32_t) outs[1];
    if (reason != NULL) {
        *reason = (char *) outs[2];
    }
    return ret;
}

/*
 * Returns true if there is nothing to repeat in the retransmission queue
 */
int picoquic_is_cnx_backlog_empty(picoquic_cnx_t* cnx)
{
    int backlog_empty = 1;

    for (picoquic_packet_context_enum pc = 0;
        backlog_empty == 1 && pc < picoquic_nb_packet_context; pc++)
    {
        for (int i = 0; i < cnx->nb_paths && backlog_empty == 1; i++) {
            picoquic_path_t* path_x = cnx->path[i];
            picoquic_packet_t* p = path_x->pkt_ctx[pc].retransmit_oldest;

            while (p != NULL && backlog_empty == 1) {
                /* check if this is an ACK only packet */
                if (!p->is_pure_ack) {
                    backlog_empty = 0;
                }
                p = p->previous_packet;
            }
        }
    }

    return backlog_empty;
}

/* Decide whether MAX data need to be sent or not */
int picoquic_should_send_max_data(picoquic_cnx_t* cnx)
{
    int ret = 0;

    if (2 * cnx->data_received > cnx->maxdata_local)
        ret = 1;

    return ret;
}

/* Decide whether to send an MTU probe */
int picoquic_is_mtu_probe_needed(picoquic_cnx_t* cnx, picoquic_path_t * path_x)
{
    int ret = 0;

    if ((cnx->cnx_state == picoquic_state_client_ready || cnx->cnx_state == picoquic_state_server_ready) && path_x->mtu_probe_sent == 0 && (path_x->send_mtu_max_tried == 0 || (path_x->send_mtu + 10) < path_x->send_mtu_max_tried)) {
        ret = 1;
    }

    return ret;
}

/**
 * See PROTOOP_NOPARAM_PREPARE_MTU_PROBE
 */
protoop_arg_t prepare_mtu_probe(picoquic_cnx_t* cnx)
{
    picoquic_path_t * path_x = (picoquic_path_t *) cnx->protoop_inputv[0];
    uint32_t header_length = (uint32_t) cnx->protoop_inputv[1];
    uint32_t checksum_length = (uint32_t) cnx->protoop_inputv[2];
    uint8_t* bytes = (uint8_t*) cnx->protoop_inputv[3];

    uint32_t probe_length;
    uint32_t length = header_length;
    

    if (path_x->send_mtu_max_tried == 0) {
        if (cnx->remote_parameters.max_packet_size > 0) {
            probe_length = cnx->remote_parameters.max_packet_size;
            
            if (cnx->quic->mtu_max > 0 && (int)probe_length > cnx->quic->mtu_max) {
                probe_length = cnx->quic->mtu_max;
            } else if (probe_length > PICOQUIC_MAX_PACKET_SIZE) {
                probe_length = PICOQUIC_MAX_PACKET_SIZE;
            }
            if (probe_length < path_x->send_mtu) {
                probe_length = path_x->send_mtu;
            }
        } else if (cnx->quic->mtu_max > 0) {
            probe_length = cnx->quic->mtu_max;
        } else {
            probe_length = PICOQUIC_PRACTICAL_MAX_MTU;
        }
    } else {
        probe_length = (path_x->send_mtu + path_x->send_mtu_max_tried) / 2;
    }

    bytes[length++] = picoquic_frame_type_ping;
    bytes[length++] = 0;
    memset(&bytes[length], 0, probe_length - checksum_length - length);

    return (protoop_arg_t) probe_length - checksum_length;
}

/* Prepare an MTU probe packet */
uint32_t picoquic_prepare_mtu_probe(picoquic_cnx_t* cnx,
    picoquic_path_t * path_x,
    uint32_t header_length, uint32_t checksum_length,
    uint8_t* bytes)
{
    return (uint32_t) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREPARE_MTU_PROBE, NULL,
        path_x, header_length, checksum_length, bytes);   
}

protoop_plugin_t *get_next_plugin(picoquic_cnx_t *cnx, protoop_plugin_t *t)
{
    if (t->hh.next != NULL) {
        return t->hh.next;
    }
    /* Otherwise, it is the first one */
    return cnx->plugins;
}

/* Special wake up decision logic in initial state */
/* TODO: tie with per path scheduling */
static void picoquic_cnx_set_next_wake_time_init(picoquic_cnx_t* cnx, uint64_t current_time)
{
    uint64_t next_time = cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX;
    picoquic_stream_head* stream = NULL;
    int timer_based = 0;
    int blocked = 1;
    int pacing = 0;
    picoquic_path_t * path_x = cnx->path[0];
    int pc_ready_flag = 1 << picoquic_packet_context_initial;

    if (cnx->tls_stream[0].send_queue == NULL) {
        if (cnx->crypto_context[1].aead_encrypt != NULL &&
            cnx->tls_stream[1].send_queue != NULL) {
            pc_ready_flag |= 1 << picoquic_packet_context_application;
        }
        else if (cnx->crypto_context[2].aead_encrypt != NULL &&
            cnx->tls_stream[1].send_queue == NULL) {
            pc_ready_flag |= 1 << picoquic_packet_context_handshake;
        }
    }

    if (next_time < current_time)
    {
        next_time = current_time;
        blocked = 0;
    }
    else
    {

        for (picoquic_packet_context_enum pc = 0; blocked == 0 && pc < picoquic_nb_packet_context; pc++) {
            for (int i = 0; blocked == 0 && i < cnx->nb_paths; i++) {
                path_x = cnx->path[i];
                picoquic_packet_t* p = path_x->pkt_ctx[pc].retransmit_oldest;

                if ((pc_ready_flag & (1 << pc)) == 0) {
                    continue;
                }

                while (p != NULL)
                {
                    if (p->ptype < picoquic_packet_0rtt_protected) {
                        if (picoquic_retransmit_needed_by_packet(cnx, p, current_time, &timer_based, NULL)) {
                            blocked = 0;
                        }
                        break;
                    }
                    p = p->next_packet;
                }

                if (blocked != 0)
                {
                    if (picoquic_is_ack_needed(cnx, current_time, pc, path_x)) {
                        blocked = 0;
                    }
                }
            }
        }

        if (blocked != 0)
        {
            for (int i = 0; blocked != 0 && pacing == 0 && i < cnx->nb_paths; i++) {
                path_x = cnx->path[i];
                if (path_x->cwin > path_x->bytes_in_transit && path_x->challenge_verified == 1) {
                    if (picoquic_should_send_max_data(cnx) ||
                        picoquic_is_tls_stream_ready(cnx) ||
                        (cnx->crypto_context[1].aead_encrypt != NULL && (stream = picoquic_find_ready_stream(cnx)) != NULL)) {
                        if (path_x->next_pacing_time < current_time + path_x->pacing_margin_micros) {
                            blocked = 0;
                        }
                        else {
                            pacing = 1;
                        }
                    }
                }
            }
        }

        if (blocked == 0) {
            next_time = current_time;
        }
        else if (pacing != 0) {
            next_time = path_x->next_pacing_time;
        }
        else {
            for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
                for (int i = 0; i < cnx->nb_paths; i++) {
                    path_x = cnx->path[i];
                    picoquic_packet_t* p = path_x->pkt_ctx[pc].retransmit_oldest;

                    if ((pc_ready_flag & (1 << pc)) == 0) {
                        continue;
                    }

                    /* Consider delayed ACK */
                    if (path_x->pkt_ctx[pc].ack_needed) {
                        if (path_x->pkt_ctx[pc].highest_ack_time + path_x->pkt_ctx[pc].ack_delay_local < next_time)
                        next_time = path_x->pkt_ctx[pc].highest_ack_time + path_x->pkt_ctx[pc].ack_delay_local;
                    }

                    while (p != NULL &&
                        p->ptype == picoquic_packet_0rtt_protected &&
                        p->contains_crypto == 0) {
                        p = p->next_packet;
                    }

                    if (p != NULL) {
                        if (path_x->pkt_ctx[pc].nb_retransmit == 0) {
                            if (p->send_time + path_x->retransmit_timer < next_time) {
                                next_time = p->send_time + path_x->retransmit_timer;
                            }
                        }
                        else {
                            if (p->send_time + (1000000ull << (path_x->pkt_ctx[pc].nb_retransmit - 1)) < next_time) {
                                next_time = p->send_time + (1000000ull << (path_x->pkt_ctx[pc].nb_retransmit - 1));
                            }
                        }
                    }
                }
            }
        }
    }

    /* Consider path challenges */
    for (int i = 0; i < cnx->nb_paths; i++) {
        path_x = cnx->path[i];
        if (blocked != 0 && path_x->challenge_verified == 0) {
            uint64_t next_challenge_time = path_x->challenge_time + path_x->retransmit_timer;
            if (next_challenge_time <= current_time) {
                next_time = current_time;
            } else if (next_challenge_time < next_time) {
                next_time = next_challenge_time;
            }
        }
    }

    /* reset the connection at its new logical position */
    picoquic_reinsert_by_wake_time(cnx->quic, cnx, next_time);
}

protoop_arg_t has_congestion_controlled_plugin_frames_to_send(picoquic_cnx_t *cnx) {
    protoop_arg_t ret = 0;
    protoop_plugin_t *p = cnx->first_drr;

    if(p) {
        do {
            if (queue_peek(p->block_queue_cc)) {
                ret = 1;
                break;
            }
        } while (!ret && (p = get_next_plugin(cnx, p)) != cnx->first_drr);
    }
    return ret;
}

bool picoquic_has_congestion_controlled_plugin_frames_to_send(picoquic_cnx_t *cnx) {
    return (bool) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_HAS_CONGESTION_CONTROLLED_PLUGIN_FRAMEMS_TO_SEND, NULL, NULL);
}

/**
 * See PROTOOP_NOPARAM_SET_NEXT_WAKE_TIME
 */
protoop_arg_t set_next_wake_time(picoquic_cnx_t *cnx)
{
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[0];
    uint32_t last_pkt_length = (uint32_t) cnx->protoop_inputv[1];
    uint64_t next_time = cnx->latest_progress_time + PICOQUIC_MICROSEC_SILENCE_MAX * (2 - cnx->client_mode);
    picoquic_stream_head* stream = NULL;
    int timer_based = 0;
    int blocked = 1;
    int pacing = 0;
    int ret = 0;


    if (cnx->cnx_state < picoquic_state_client_ready)
    {
        picoquic_cnx_set_next_wake_time_init(cnx, current_time);
        return 0;
    }

    if (cnx->cnx_state == picoquic_state_disconnecting || cnx->cnx_state == picoquic_state_handshake_failure || cnx->cnx_state == picoquic_state_closing_received) {
        blocked = 0;
    }

    for (int i = 0; last_pkt_length > 0 && blocked != 0 && i < cnx->nb_paths; i++) {
        picoquic_path_t * path_x = cnx->path[i];
        if (path_x->cwin > path_x->bytes_in_transit && picoquic_is_mtu_probe_needed(cnx, path_x)) {
            blocked = 0;
        }
        if (path_x->cwin > path_x->bytes_in_transit && picoquic_has_booked_plugin_frames(cnx)) {
            blocked = 0;
        }
    }

    picoquic_path_t * path_x = cnx->path[0];
    if (blocked != 0) {
        for (int i = 0; blocked != 0 && pacing == 0 && i < cnx->nb_paths; i++) {
            path_x = cnx->path[i];
            for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
                picoquic_packet_t* p = path_x->pkt_ctx[pc].retransmit_oldest;

                if (p != NULL && ret == 0 && picoquic_retransmit_needed_by_packet(cnx, p, current_time, /* &ph,*/ &timer_based, NULL)) {
                    blocked = 0;
                }
                else if (picoquic_is_ack_needed(cnx, current_time, pc, path_x)) {
                    blocked = 0;
                }
            }

            if (blocked != 0) {
                if (path_x->cwin > path_x->bytes_in_transit) {
                    if (picoquic_should_send_max_data(cnx) ||
                        picoquic_is_tls_stream_ready(cnx) ||
                        ((cnx->cnx_state == picoquic_state_client_ready || cnx->cnx_state == picoquic_state_server_ready) &&
                                ((stream = picoquic_find_ready_stream(cnx)) != NULL || picoquic_has_congestion_controlled_plugin_frames_to_send(cnx)))) {
                        if (path_x->next_pacing_time < current_time + path_x->pacing_margin_micros) {
                            blocked = 0;
                        }
                        else {
                            pacing = 1;
                        }
                    }
                }
            }
        }
    }

    if (blocked == 0 || (cnx->wake_now && pacing == 0)) {
        next_time = current_time;
    } else if (pacing != 0) {
        next_time = path_x->next_pacing_time;
    } else {
        for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
            for (int i = 0; i < cnx->nb_paths; i++) {
                path_x = cnx->path[i];
                picoquic_packet_t* p = path_x->pkt_ctx[pc].retransmit_oldest;
                /* Consider delayed ACK */
                if (path_x->pkt_ctx[pc].ack_needed) {
                    uint64_t ack_time = path_x->pkt_ctx[pc].highest_ack_time + path_x->pkt_ctx[pc].ack_delay_local;

                    if (ack_time < next_time) {
                        next_time = ack_time;
                    }
                }

                /* Consider delayed RACK */
                if (p != NULL) {
                    int64_t delta_seq = path_x->pkt_ctx[pc].highest_acknowledged - p->sequence_number;
                    if (path_x->pkt_ctx[pc].latest_time_acknowledged > p->send_time  // we already received an acknowledgement for an older packet, so there is a hole. Identical to checking delta_seq > 0
                        && p->send_time + path_x->smoothed_rtt + (path_x->smoothed_rtt >> 3) < next_time
                        && p->ptype != picoquic_packet_0rtt_protected) {
                        next_time = p->send_time + path_x->smoothed_rtt + (path_x->smoothed_rtt >> 3); // we retransmit the packet after at least 9/8*rtt

                        /* RACK logic fails when the smoothed RTT is too small, in which case we
                         * rely on dupack logic possible, or on a safe estimate of the RACK delay if it
                         * is not */
                        if (delta_seq < 3) {
                            uint64_t rack_timer_min = path_x->pkt_ctx[pc].latest_time_acknowledged + PICOQUIC_RACK_DELAY; // ensure at least a safe delay of PICOQUIC_RACK_DELAY
                            if (next_time < rack_timer_min)
                                next_time = rack_timer_min;
                        }

                    }

                    if (path_x->pkt_ctx[pc].nb_retransmit == 0) {
                        if (p->send_time + path_x->retransmit_timer < next_time) {
                            next_time = p->send_time + path_x->retransmit_timer;
                        }
                    }
                    else {
                        if (p->send_time + (1000000ull << (path_x->pkt_ctx[pc].nb_retransmit - 1)) < next_time) {
                            next_time = p->send_time + (1000000ull << (path_x->pkt_ctx[pc].nb_retransmit - 1));
                        }
                    }
                }
            }
        }

        for (int i = 0; i < cnx->nb_paths; i++) {
            path_x = cnx->path[i];
            /* Consider path challenges */
            if (path_x->challenge_verified == 0) {
                uint64_t next_challenge_time = path_x->challenge_time + path_x->retransmit_timer;
                if (current_time < next_challenge_time) {
                    if (next_time > next_challenge_time) {
                        next_time = next_challenge_time;
                    }
                }
            }

            /* Consider keep alive */
            if (cnx->keep_alive_interval != 0 && next_time > (cnx->latest_progress_time + cnx->keep_alive_interval)) {
                next_time = cnx->latest_progress_time + cnx->keep_alive_interval;
            }
        }
    }
    cnx->wake_now = 0;
    /* reset the connection at its new logical position */
    picoquic_reinsert_by_wake_time(cnx->quic, cnx, next_time);

    return 0;
}

/* Decide the next time at which the connection should send data */
/* TODO: tie with per path scheduling */
void picoquic_cnx_set_next_wake_time(picoquic_cnx_t* cnx, uint64_t current_time, uint32_t last_pkt_length)
{
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_SET_NEXT_WAKE_TIME, NULL,
        current_time, last_pkt_length);
}

/* Prepare the next packet to 0-RTT packet to send in the client initial
 * state, when 0-RTT is available
 */
int picoquic_prepare_packet_0rtt(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length)
{
    int ret = 0;
    picoquic_stream_head* stream = NULL;
    picoquic_packet_type_enum packet_type = picoquic_packet_0rtt_protected;
    size_t data_bytes = 0;
    int padding_required = 0;
    uint32_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint32_t length = 0;
    uint32_t checksum_overhead = picoquic_aead_get_checksum_length(cnx->crypto_context[1].aead_encrypt);

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    stream = picoquic_find_ready_stream(cnx);
    length = picoquic_predict_packet_header_length(cnx, packet_type, path_x);
    packet->ptype = picoquic_packet_0rtt_protected;
    packet->offset = length;
    header_length = length;
    packet->pc = picoquic_packet_context_application;
    packet->sequence_number = path_x->pkt_ctx[picoquic_packet_context_application].send_sequence;
    packet->send_time = current_time;
    packet->send_path = path_x;
    packet->checksum_overhead = checksum_overhead;

    if (packet->sequence_number == 0 && send_buffer_max < PICOQUIC_ENFORCED_INITIAL_MTU) {
        /* Special case in which the 0-RTT packet is coalesced with initial packet */
        padding_required = 1;
    }

    if ((stream == NULL && cnx->first_misc_frame == NULL && padding_required == 0) || 
        (PICOQUIC_DEFAULT_0RTT_WINDOW <= path_x->bytes_in_transit + send_buffer_max)) {
        length = 0;
    } else {
        /* If present, send misc frame */
        while (cnx->first_misc_frame != NULL) {
            ret = picoquic_prepare_first_misc_frame(cnx, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes);

            if (ret == 0) {
                length += (uint32_t)data_bytes;
            } else {
                break;
            }
        }
        /* Encode the stream frame */
        while ((stream = picoquic_schedule_next_stream(cnx, send_buffer_max - checksum_overhead - length, path_x)) != NULL) {
            ret = picoquic_prepare_stream_frame(cnx, stream, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes);
            if (ret == 0) {
                length += (uint32_t) data_bytes;
            }
        }
        /* Add padding if required */
        if (padding_required) {
            while (length < send_buffer_max - checksum_overhead) {
                bytes[length++] = 0;
            }
        }
    }

    packet->is_congestion_controlled = 1;
    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, (uint32_t)send_buffer_max, path_x, current_time);

    if (length > 0) {
        /* Accounting of zero rtt packets sent */
        cnx->nb_zero_rtt_sent++;
    }

    picoquic_cnx_set_next_wake_time(cnx, current_time, length);

    return ret;
}

/* Get packet type from epoch */
picoquic_packet_type_enum picoquic_packet_type_from_epoch(int epoch)
{
    picoquic_packet_type_enum ptype;

    switch (epoch) {
    case 0:
        ptype = picoquic_packet_initial;
        break;
    case 1:
        ptype = picoquic_packet_0rtt_protected;
        break;
    case 2:
        ptype = picoquic_packet_handshake;
        break;
    case 3:
        ptype = picoquic_packet_1rtt_protected_phi0;
        break;
    default:
        ptype = picoquic_packet_error;
        break;
    }

    return ptype;
}


/**
 * See PROTOOP_NOPARAM_PREPARE_PACKET_OLD_CONTEXT
 */
protoop_arg_t prepare_packet_old_context(picoquic_cnx_t* cnx)
{
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) cnx->protoop_inputv[0];
    picoquic_path_t * path_x = (picoquic_path_t *) cnx->protoop_inputv[1];
    picoquic_packet_t* packet = (picoquic_packet_t *) cnx->protoop_inputv[2];
    size_t send_buffer_max = (size_t) cnx->protoop_inputv[3];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[4];
    uint32_t header_length = (uint32_t) cnx->protoop_inputv[5];

    if (cnx->handshake_complete_time) {
        uint64_t max_rto = 0;
        for (int p = 0; p < cnx->nb_paths; p++) {
            picoquic_path_t *path = cnx->path[p];
            if (path->retransmit_timer > max_rto) {
                max_rto = path->retransmit_timer;
            }
        }
        if (cnx->handshake_complete_time + (3 * max_rto) < picoquic_current_time()) {
            // we won't consider old contexts anymore: empty the retransmit queue
            while(path_x->pkt_ctx[pc].retransmit_oldest) {
                picoquic_dequeue_retransmit_packet(cnx, path_x->pkt_ctx[pc].retransmit_oldest, 1);
            }
            protoop_save_outputs(cnx, 0);
            return 0;
        }
    }

    int is_cleartext_mode = (pc == picoquic_packet_context_initial) ? 1 : 0;
    uint32_t length = 0;
    size_t data_bytes = 0;
    uint32_t checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);

    header_length = 0;

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    char * retransmit_reason = NULL;
    length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, packet, send_buffer_max,
        &is_cleartext_mode, &header_length, &retransmit_reason);
    if (length > 0 && retransmit_reason != NULL) {
        protoop_id_t pid = { .id = retransmit_reason };
        pid.hash = hash_value_str(pid.id);
        protoop_prepare_and_run_noparam(cnx, &pid, NULL, packet);
    }

    if (length == 0 && path_x->pkt_ctx[pc].ack_needed != 0 &&
        pc != picoquic_packet_context_application) {
        packet->ptype =
            (pc == picoquic_packet_context_initial) ? picoquic_packet_initial :
            (pc == picoquic_packet_context_handshake) ? picoquic_packet_handshake :
                picoquic_packet_0rtt_protected;
        length = picoquic_predict_packet_header_length(cnx, packet->ptype, path_x);
        packet->offset = length;
        header_length = length;
        packet->sequence_number = path_x->pkt_ctx[pc].send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;
    }

    if (length > 0) {
        if (packet->ptype != picoquic_packet_0rtt_protected) {
            /* Check whether it makes sens to add an ACK at the end of the retransmission */
            if (picoquic_prepare_ack_frame(cnx, current_time, pc, &packet->bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes)
                == 0) {
                length += (uint32_t)data_bytes;
            }
        }
        packet->length = length;
        /* document the send time & overhead */
        packet->send_time = current_time;
        packet->checksum_overhead = checksum_overhead;
        packet->pc = pc;
    } else {
        packet->is_pure_ack = 1;
    }

    protoop_save_outputs(cnx, header_length);    

    return (protoop_arg_t) length;
}

/* Prepare a required repetition or ack  in a previous context */
uint32_t picoquic_prepare_packet_old_context(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc,
    picoquic_path_t * path_x, picoquic_packet_t* packet, size_t send_buffer_max, uint64_t current_time, uint32_t * header_length)
{
    protoop_arg_t outs[1];
    uint32_t length = (uint32_t) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREPARE_PACKET_OLD_CONTEXT, outs,
        pc, path_x, packet, send_buffer_max, current_time, *header_length);
    *header_length = (uint32_t) outs[0];
    return length;
}

/* Prepare the next packet to send when in one of the client initial states */
int picoquic_prepare_packet_client_init(picoquic_cnx_t* cnx, picoquic_path_t ** path, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length)
{
    int ret = 0;
    int tls_ready = 0;
    picoquic_packet_type_enum packet_type = 0;
    uint32_t checksum_overhead = 8;
    int is_cleartext_mode = 1;
    size_t data_bytes = 0;
    int retransmit_possible = 0;
    uint32_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint32_t length = 0;
    int epoch = 0;
    picoquic_packet_context_enum pc = picoquic_packet_context_initial;
    /* This packet MUST be sent on initial path */
    *path = cnx->path[0];
    picoquic_path_t* path_x = *path;

    if (cnx->tls_stream[0].send_queue == NULL) {
        if (cnx->crypto_context[1].aead_encrypt != NULL &&
            cnx->tls_stream[1].send_queue != NULL) {
            epoch = 1;
            pc = picoquic_packet_context_application;
        } else if (cnx->crypto_context[2].aead_encrypt != NULL && 
            cnx->tls_stream[1].send_queue == NULL) {
            epoch = 2;
            pc = picoquic_packet_context_handshake;
        } 
    }

    packet_type = picoquic_packet_type_from_epoch(epoch);
    LOG_EVENT(cnx, "TRANSPORT", "PREPARE_PACKET", "", "{\"type\": \"%s\"}", picoquic_log_ptype_name(packet_type));
    PUSH_LOG_CTX(cnx, "\"packet_type\": \"%s\"", picoquic_log_ptype_name(packet_type));

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    /* Prepare header -- depend on connection state */
    /* TODO: 0-RTT work. */
    switch (cnx->cnx_state) {
    case picoquic_state_client_init:
        break;
    case picoquic_state_client_init_sent:
    case picoquic_state_client_init_resent:
        retransmit_possible = 1;
        break;
    case picoquic_state_client_renegotiate:
        packet_type = picoquic_packet_initial;
        break;
    case picoquic_state_client_handshake_start:
        retransmit_possible = 1;
        break;
    case picoquic_state_client_handshake_progress:
        retransmit_possible = 1;
        break;
    case picoquic_state_client_almost_ready:
        break;
    default:
        ret = -1;
        break;
    }

    /* If context is handshake, verify first that there is no need for retransmit or ack
     * on initial context */
    if (ret == 0 && epoch > 0) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
            path_x, packet, send_buffer_max, current_time, &header_length);
    }

    if (ret == 0 && epoch > 1 && length == 0) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_application,
            path_x, packet, send_buffer_max, current_time, &header_length);
    }

    /* If there is nothing to send in previous context, check this one too */
    if (length == 0) {
        checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);
        packet->checksum_overhead = checksum_overhead;
        packet->pc = pc;

        tls_ready = picoquic_is_tls_stream_ready(cnx);

        char * reason = NULL;
        if (ret == 0 && retransmit_possible &&
            (length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, packet, send_buffer_max, &is_cleartext_mode, &header_length, &reason)) > 0) {
            /* Check whether it makes sens to add an ACK at the end of the retransmission */
            if (reason != NULL) {
                protoop_id_t pid = { .id = reason };
                pid.hash = hash_value_str(pid.id);
                protoop_prepare_and_run_noparam(cnx, &pid, NULL, packet);
            }
            if (epoch != 1) {
                if (picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                    send_buffer_max - checksum_overhead - length, &data_bytes)
                    == 0) {
                    length += (uint32_t)data_bytes;
                }
            } 
            /* document the send time & overhead */
            packet->length = length;
            packet->send_time = current_time;
            packet->checksum_overhead = checksum_overhead;
            packet->is_pure_ack = 0;
        }
        else if (ret == 0 && is_cleartext_mode && tls_ready == 0
            && cnx->first_misc_frame == NULL && path_x->pkt_ctx[pc].ack_needed == 0) {
            /* when in a clear text mode, only send packets if there is
            * actually something to send, or resend */

            packet->length = 0;
        }
        else if (ret == 0) {
            if (cnx->crypto_context[epoch].aead_encrypt == NULL) {
                packet->length = 0;
            }
            else {
                length = picoquic_predict_packet_header_length(cnx, packet_type, path_x);
                packet->ptype = packet_type;
                packet->offset = length;
                header_length = length;
                packet->sequence_number = path_x->pkt_ctx[pc].send_sequence;
                packet->send_time = current_time;
                packet->send_path = path_x;

                if ((tls_ready == 0 || path_x->cwin <= path_x->bytes_in_transit)
                    && (cnx->cnx_state == picoquic_state_client_almost_ready
                        || picoquic_is_ack_needed(cnx, current_time, pc, path_x) == 0)
                    && cnx->first_misc_frame == NULL) {
                    length = 0;
                }
                else {
                    if (epoch != 1 && path_x->pkt_ctx[pc].ack_needed) {
                        ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                            send_buffer_max - checksum_overhead - length, &data_bytes);
                        if (ret == 0) {
                            length += (uint32_t)data_bytes;
                            data_bytes = 0;
                        }
                        else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                            ret = 0;
                        }
                    }
                    /* If present, send misc frame */
                    while (cnx->first_misc_frame != NULL) {
                        ret = picoquic_prepare_first_misc_frame(cnx, &bytes[length],
                            send_buffer_max - checksum_overhead - length, &data_bytes);
                        if (ret == 0) {
                            length += (uint32_t)data_bytes;
                            data_bytes = 0;
                        }
                        else {
                            if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                ret = 0;
                            }
                            break;
                        }
                    }

                    if (ret == 0 && path_x->cwin > path_x->bytes_in_transit) {
                        /* Encode the crypto handshake frame */
                        if (tls_ready != 0) {
                            ret = picoquic_prepare_crypto_hs_frame(cnx, epoch,
                                &bytes[length],
                                send_buffer_max - checksum_overhead - length, &data_bytes);

                            if (ret == 0) {
                                if (data_bytes > 0) {
                                    packet->is_pure_ack = 0;
                                    packet->contains_crypto = 1;
                                    packet->is_congestion_controlled = 1;
                                }
                                length += (uint32_t)data_bytes;
                            }
                            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                ret = 0;
                            }
                        }

                        if (packet_type == picoquic_packet_initial && 
                            cnx->crypto_context[1].aead_encrypt == NULL) {
                            /* Pad to minimum packet length. But don't do that if the
                             * initial packet will be coalesced with 0-RTT packet */
                            while (length < send_buffer_max - checksum_overhead) {
                                bytes[length++] = 0;
                            }
                        }

                        if (packet_type == picoquic_packet_0rtt_protected) {
                            cnx->nb_zero_rtt_sent++;
                        }
                    }

                    /* If stream zero packets are sent, progress the state */
                    if (ret == 0 && tls_ready != 0 && data_bytes > 0 && 
                        cnx->tls_stream[epoch].send_queue == NULL) {
                        switch (cnx->cnx_state) {
                        case picoquic_state_client_init:
                            picoquic_set_cnx_state(cnx, picoquic_state_client_init_sent);
                            path_x->next_pacing_time = current_time + 10000;
                            break;
                        case picoquic_state_client_renegotiate:
                            picoquic_set_cnx_state(cnx, picoquic_state_client_init_resent);
                            break;
                        case picoquic_state_client_almost_ready:
                            if (cnx->tls_stream[0].send_queue == NULL &&
                                cnx->tls_stream[1].send_queue == NULL &&
                                cnx->tls_stream[2].send_queue == NULL) {
                                picoquic_set_cnx_state(cnx, picoquic_state_client_ready);
                            }
                            break;
                        default:
                            break;
                        }
                    }
                }
            }
        }
    }

    if (ret == 0 && length == 0 && cnx->crypto_context[1].aead_encrypt != NULL) {
        /* Consider sending 0-RTT */
        ret = picoquic_prepare_packet_0rtt(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length);
    } else {
        packet->is_congestion_controlled = 1;
        picoquic_finalize_and_protect_packet(cnx, packet,
            ret, length, header_length, checksum_overhead,
            send_length, send_buffer, (uint32_t)send_buffer_max, path_x, current_time);

        if (cnx->cnx_state != picoquic_state_draining) {
            picoquic_cnx_set_next_wake_time(cnx, current_time, length);
        }
    }
    POP_LOG_CTX(cnx);

    return ret;
}

/* Prepare the next packet to send when in one the server initial states */
int picoquic_prepare_packet_server_init(picoquic_cnx_t* cnx, picoquic_path_t ** path, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length)
{
    int ret = 0;
    int tls_ready = 0;
    int epoch = 0;
    picoquic_packet_type_enum packet_type = picoquic_packet_initial;
    picoquic_packet_context_enum pc = picoquic_packet_context_initial;
    uint32_t checksum_overhead = 8;
    int is_cleartext_mode = 1;
    size_t data_bytes = 0;
    uint32_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint32_t length = 0;
    char * reason = NULL;  // The potential reason for retransmitting a packet
    /* This packet MUST be sent on initial path */
    *path = cnx->path[0];
    picoquic_path_t* path_x = *path;

    if (cnx->crypto_context[2].aead_encrypt != NULL &&
        cnx->tls_stream[0].send_queue == NULL) {
        epoch = 2;
        pc = picoquic_packet_context_handshake;
        packet_type = picoquic_packet_handshake;
    }

    LOG_EVENT(cnx, "TRANSPORT", "PREPARE_PACKET", "", "{\"type\": \"%s\"}", picoquic_log_ptype_name(packet_type));
    PUSH_LOG_CTX(cnx, "\"packet_type\": \"%s\"", picoquic_log_ptype_name(packet_type));

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;


    /* If context is handshake, verify first that there is no need for retransmit or ack
    * on initial context */
    if (ret == 0 && pc == picoquic_packet_context_handshake) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
            path_x, packet, send_buffer_max, current_time, &header_length);
    }

    if (length == 0) {

        checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);

        tls_ready = picoquic_is_tls_stream_ready(cnx);

        length = picoquic_predict_packet_header_length(cnx, packet_type, path_x);
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = path_x->pkt_ctx[pc].send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;
        packet->pc = pc;

        if (tls_ready != 0 && path_x->cwin <= path_x->bytes_in_transit && path_x->challenge_time == 0) {
            /* Should send a path challenge and get a reply before sending more data */
            path_x->challenge_verified = 0;
        }

        if (path_x->challenge_verified == 0) {
            if (path_x->challenge_time + path_x->retransmit_timer <= current_time || path_x->challenge_time == 0) {
                /* When blocked, repeat the path challenge or wait */
                if (picoquic_prepare_path_challenge_frame(cnx, &bytes[length],
                    send_buffer_max - checksum_overhead - length, &data_bytes, path_x) == 0) {
                    length += (uint32_t)data_bytes;
                    path_x->challenge_time = current_time;
                    path_x->challenge_repeat_count++;
                }
                /* add an ACK just to be nice */
                if (picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                    send_buffer_max - checksum_overhead - length, &data_bytes)
                    == 0) {
                    length += (uint32_t)data_bytes;
                }

                if (path_x->challenge_repeat_count > PICOQUIC_CHALLENGE_REPEAT_MAX) {
                    DBG_PRINTF("%s\n", "Too many challenge retransmits, disconnect");
                    picoquic_set_cnx_state(cnx, picoquic_state_disconnected);
                    if (cnx->callback_fn) {
                        (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
                    }
                    length = 0;
                }

                packet->length = length;
            }
        }
        else if ((tls_ready != 0 && path_x->cwin > path_x->bytes_in_transit) 
            || path_x->pkt_ctx[pc].ack_needed) {
            if (picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes)
                == 0) {
                length += (uint32_t)data_bytes;
                data_bytes = 0;
            }

            /* Encode the crypto frame */
            ret = picoquic_prepare_crypto_hs_frame(cnx, epoch, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes);
            if (ret == 0) {
                if (data_bytes > 0) {
                    packet->is_pure_ack = 0;
                    packet->contains_crypto = 1;
                    packet->is_congestion_controlled = 1;
                }
                length += (uint32_t)data_bytes;
            }
            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                /* todo: reset offset to previous position? */
                ret = 0;
            }

            /* progress the state if the epoch data is all sent */

            if (ret == 0 && tls_ready != 0 && data_bytes > 0 && cnx->tls_stream[epoch].send_queue == NULL) {
                if (epoch == 2 && picoquic_tls_client_authentication_activated(cnx->quic) == 0) {
                    picoquic_set_cnx_state(cnx, picoquic_state_server_ready);
                }
                else {
                    picoquic_set_cnx_state(cnx, picoquic_state_server_handshake);
                }
            }

            packet->length = length;

        }
        else  if ((length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, packet, send_buffer_max, &is_cleartext_mode, &header_length, &reason)) > 0) {
            if (reason != NULL) {
                protoop_id_t pid = { .id = reason };
                pid.hash = hash_value_str(pid.id);
                protoop_prepare_and_run_noparam(cnx, &pid, NULL, packet);
            }
            /* Set the new checksum length */
            checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);
            /* Check whether it makes sens to add an ACK at the end of the retransmission */
            if (picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes)
                == 0) {
                length += (uint32_t)data_bytes;
                packet->length = length;
            }
            /* document the send time & overhead */
            packet->send_time = current_time;
            packet->checksum_overhead = checksum_overhead;
            packet->is_pure_ack = 0;
        }
        else if (path_x->pkt_ctx[pc].ack_needed) {
            /* when in a handshake mode, send acks asap. */
            length = picoquic_predict_packet_header_length(cnx, packet_type, path_x);

            if (picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes)
                == 0) {
                length += (uint32_t)data_bytes;
                packet->length = length;
            }
        } else {
            length = 0;
            packet->length = 0;
        }
    }

    packet->is_congestion_controlled = 1;
    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, (uint32_t)send_buffer_max, path_x, current_time);

    picoquic_cnx_set_next_wake_time(cnx, current_time, length);

    POP_LOG_CTX(cnx);

    return ret;
}

/* Prepare the next packet to send when in one the closing states */
int picoquic_prepare_packet_closing(picoquic_cnx_t* cnx, picoquic_path_t ** path, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length)
{
    int ret = 0;
    /* TODO: manage multiple streams. */
    picoquic_packet_type_enum packet_type = 0;
    uint32_t checksum_overhead = 8;
    int is_cleartext_mode = 1;
    uint32_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint32_t length = 0;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;

    /* TODO: sent on others than initial path */
    *path = cnx->path[0];
    picoquic_path_t* path_x = *path;

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    /* Prepare header -- depend on connection state */
    /* TODO: 0-RTT work. */
    switch (cnx->cnx_state) {
    case picoquic_state_handshake_failure:
        /* TODO: check whether closing can be requested in "initial" mode */
        if (cnx->crypto_context[2].aead_encrypt != NULL) {
            pc = picoquic_packet_context_handshake;
            packet_type = picoquic_packet_handshake;
        }
        else {
            pc = picoquic_packet_context_initial;
            packet_type = picoquic_packet_initial;
        }
        break;
    case picoquic_state_disconnecting:
        packet_type = picoquic_packet_1rtt_protected_phi0;
        is_cleartext_mode = 0;
        break;
    case picoquic_state_closing_received:
        packet_type = picoquic_packet_1rtt_protected_phi0;
        is_cleartext_mode = 0;
        break;
    case picoquic_state_closing:
        packet_type = picoquic_packet_1rtt_protected_phi0;
        is_cleartext_mode = 0;
        break;
    case picoquic_state_draining:
        packet_type = picoquic_packet_1rtt_protected_phi0;
        is_cleartext_mode = 0;
        break;
    case picoquic_state_disconnected:
        ret = PICOQUIC_ERROR_DISCONNECTED;
        break;
    default:
        ret = -1;
        break;
    }

    /* At this stage, we don't try to retransmit any old packet, whether in
     * the current context or in previous contexts. */

    if (length == 0) {
        checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);
        packet->pc = pc;

        if (ret == 0 && cnx->cnx_state == picoquic_state_closing_received) {
            /* Send a closing frame, move to closing state */
            size_t consumed = 0;
            uint64_t exit_time = cnx->latest_progress_time + 3 * path_x->retransmit_timer;

            length = picoquic_predict_packet_header_length(cnx, packet_type, path_x);
            packet->ptype = packet_type;
            packet->offset = length;
            header_length = length;
            packet->sequence_number = path_x->pkt_ctx[pc].send_sequence;
            packet->send_time = current_time;
            packet->send_path = path_x;

            /* Send the disconnect frame */
            ret = picoquic_prepare_connection_close_frame(cnx, bytes + length,
                send_buffer_max - checksum_overhead - length, &consumed);

            if (ret == 0) {
                length += (uint32_t)consumed;
            }
            picoquic_set_cnx_state(cnx, picoquic_state_draining);
            picoquic_reinsert_by_wake_time(cnx->quic, cnx, exit_time);
        }
        else if (ret == 0 && cnx->cnx_state == picoquic_state_closing) {
            /* if more than 3*RTO is elapsed, move to disconnected */
            uint64_t exit_time = cnx->latest_progress_time + 3 * path_x->retransmit_timer;

            if (current_time >= exit_time) {
                picoquic_set_cnx_state(cnx, picoquic_state_disconnected);
            }
            else if (current_time >= cnx->next_wake_time) {
                uint64_t delta_t = path_x->rtt_min;
                uint64_t next_time = 0;

                if (delta_t * 2 < path_x->retransmit_timer) {
                    delta_t = path_x->retransmit_timer / 2;
                }
                /* if more than N packet received, repeat and erase */
                if (path_x->pkt_ctx[pc].ack_needed) {
                    size_t consumed = 0;
                    length = picoquic_predict_packet_header_length(
                        cnx, packet_type, path_x);
                    packet->ptype = packet_type;
                    packet->offset = length;
                    header_length = length;
                    packet->sequence_number = path_x->pkt_ctx[pc].send_sequence;
                    packet->send_time = current_time;
                    packet->send_path = path_x;

                    /* Resend the disconnect frame */
                    if (cnx->local_error == 0) {
                        ret = picoquic_prepare_application_close_frame(cnx, bytes + length,
                            send_buffer_max - checksum_overhead - length, &consumed);
                    }
                    else {
                        ret = picoquic_prepare_connection_close_frame(cnx, bytes + length,
                            send_buffer_max - checksum_overhead - length, &consumed);
                    }
                    if (ret == 0) {
                        length += (uint32_t)consumed;
                    }
                    path_x->pkt_ctx[pc].ack_needed = 0;
                }
                next_time = current_time + delta_t;
                if (next_time > exit_time) {
                    next_time = exit_time;
                }
                picoquic_reinsert_by_wake_time(cnx->quic, cnx, next_time);
            }
        }
        else if (ret == 0 && cnx->cnx_state == picoquic_state_draining) {
            /* Nothing is ever sent in the draining state */
            /* if more than 3*RTO is elapsed, move to disconnected */
            uint64_t exit_time = cnx->latest_progress_time + 3 * path_x->retransmit_timer;

            if (current_time >= exit_time) {
                picoquic_set_cnx_state(cnx, picoquic_state_disconnected);
            }
            else {
                picoquic_reinsert_by_wake_time(cnx->quic, cnx, exit_time);
            }
            length = 0;
        }
        else if (ret == 0 && (cnx->cnx_state == picoquic_state_disconnecting || cnx->cnx_state == picoquic_state_handshake_failure)) {
            length = picoquic_predict_packet_header_length(
                cnx, packet_type, path_x);
            packet->ptype = packet_type;
            packet->offset = length;
            header_length = length;
            packet->sequence_number = path_x->pkt_ctx[pc].send_sequence;
            packet->send_time = current_time;
            packet->send_path = path_x;

            /* send either app close or connection close, depending on error code */
            size_t consumed = 0;
            uint64_t delta_t = path_x->rtt_min;

            if (2 * delta_t < path_x->retransmit_timer) {
                delta_t = path_x->retransmit_timer / 2;
            }

            /* add a final ack so receiver gets clean state */
            ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                send_buffer_max - checksum_overhead - length, &consumed);
            if (ret == 0) {
                length += (uint32_t)consumed;
            }

            consumed = 0;
            /* Send the disconnect frame */
            if (cnx->local_error == 0) {
                ret = picoquic_prepare_application_close_frame(cnx, bytes + length,
                    send_buffer_max - checksum_overhead - length, &consumed);
            }
            else {
                ret = picoquic_prepare_connection_close_frame(cnx, bytes + length,
                    send_buffer_max - checksum_overhead - length, &consumed);
            }

            if (ret == 0) {
                length += (uint32_t)consumed;
            }

            if (cnx->cnx_state == picoquic_state_handshake_failure) {
                picoquic_set_cnx_state(cnx, picoquic_state_disconnected);
            }
            else {
                picoquic_set_cnx_state(cnx, picoquic_state_closing);
            }
            cnx->latest_progress_time = current_time;
            picoquic_reinsert_by_wake_time(cnx->quic, cnx, current_time + delta_t);
            path_x->pkt_ctx[pc].ack_needed = 0;

            if (cnx->callback_fn) {
                (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
            }
        }
        else {
            length = 0;
        }
    }

    packet->is_congestion_controlled = 1;
    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, (uint32_t)send_buffer_max, path_x, current_time);

    return ret;
}

/**
 * See PROTOOP_NOPARM_SELECT_SENDING_PATH
 */
protoop_arg_t select_sending_path(picoquic_cnx_t *cnx)
{
    /* Set the path to be the initial one */
    return (protoop_arg_t) cnx->path[0];
}

picoquic_path_t *picoquic_select_sending_path(picoquic_cnx_t *cnx, picoquic_packet_t* retransmit_p, picoquic_path_t* from_path, char* reason)
{
    return (picoquic_path_t *) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_SELECT_SENDING_PATH, NULL,
        retransmit_p, from_path, reason);
}

/* This implements a deficit round robin with bursts */
void picoquic_frame_fair_reserve(picoquic_cnx_t *cnx, picoquic_path_t *path_x, picoquic_stream_head* stream, uint64_t frame_mss)
{
    /* If there is no plugin, there is no frame to reserve! */
    if (!cnx->plugins) {
        return;
    }
    /* Handle the first call */
    if (!cnx->first_drr) {
        cnx->first_drr = cnx->plugins;
    }
    /* Find if reservations were made */
    protoop_plugin_t *p, *tmp_p;
    reserve_frames_block_t *block;

    uint64_t plugin_use = 0;
    uint64_t num_plugins = 0;

    /* FIXME this is not fair... Introduce DRR */
    HASH_ITER(hh, cnx->plugins, p, tmp_p) {
        plugin_use += p->bytes_in_flight;
        num_plugins += 1;
    }

    uint64_t max_plugin_cwin = path_x->cwin * (1000 - cnx->core_rate) / 1000;
    uint64_t total_plugin_bytes_in_flight = 0;

    /*
    if (stream != NULL && plugin_use >= max_plugin_cwin) {
        printf("Fair reserve over rate! Stream %p plugin_use %lu max_plugin_cwin %lu\n", stream, plugin_use, max_plugin_cwin);
        // Don't go over the guaranteed rate!
        return;
    }
    */

    bool should_wake_now = false;
    uint64_t queued_bytes = 0;

    p = cnx->first_drr;

    /* First pass: consider only under-rated plugins with CC */
    do {
        while ((block = queue_peek(p->block_queue_cc)) != NULL &&
                queued_bytes < frame_mss &&
                !(stream != NULL && plugin_use >= max_plugin_cwin) &&
                (!block->is_congestion_controlled || path_x->bytes_in_transit < path_x->cwin))
        {
            should_wake_now |= !block->low_priority;    // we should wake now as soon as there is a high priority block
            block = (reserve_frames_block_t *) queue_dequeue(p->block_queue_cc);
            for (int i = 0; i < block->nb_frames; i++) {
                /* Not the most efficient way, but will do the trick */
                block->frames[i].p = p;
                queue_enqueue(cnx->reserved_frames, &block->frames[i]);
            }
            /* Update queued bytes counter */
            queued_bytes += block->total_bytes;
            LOG {
                char ftypes_str[250];
                size_t ftypes_ofs = 0;
                for (int i = 0; i < block->nb_frames; i++) {
                    ftypes_ofs += snprintf(ftypes_str + ftypes_ofs, sizeof(ftypes_str) - ftypes_ofs, "%lu%s", block->frames[i].frame_type, i < block->nb_frames - 1 ? ", " : "");
                }
                LOG_EVENT(cnx, "PLUGINS", "ENQUEUE_FRAMES", "FRAME_FAIR_RESERVE_UNDER_RATED", "{\"plugin\": \"%s\", \"nb_frames\": %d, \"total_bytes\": %lu, \"is_cc\": %d, \"frames\": [%s]}", p->name, block->nb_frames, block->total_bytes, block->is_congestion_controlled, ftypes_str);
            }
            /* Free the block */
            free(block);
        }
        total_plugin_bytes_in_flight += p->bytes_in_flight;
    } while ((p = get_next_plugin(cnx, p)) != cnx->first_drr && total_plugin_bytes_in_flight < max_plugin_cwin);
    p = cnx->first_drr;
    /* Second pass: consider all plugins with non CC */
    do {
        while ((block = queue_peek(p->block_queue_non_cc)) != NULL &&
                queued_bytes < frame_mss &&
                (!block->is_congestion_controlled || path_x->bytes_in_transit < path_x->cwin))
        {
            should_wake_now |= !block->low_priority;    // we should wake now as soon as there is a high priority block
            block = (reserve_frames_block_t *) queue_dequeue(p->block_queue_non_cc);
            for (int i = 0; i < block->nb_frames; i++) {
                /* Not the most efficient way, but will do the trick */
                block->frames[i].p = p;
                queue_enqueue(cnx->reserved_frames, &block->frames[i]);
            }
            /* Update queued bytes counter */
            queued_bytes += block->total_bytes;
            LOG {
                char ftypes_str[250];
                size_t ftypes_ofs = 0;
                for (int i = 0; i < block->nb_frames; i++) {
                    ftypes_ofs += snprintf(ftypes_str + ftypes_ofs, sizeof(ftypes_str) - ftypes_ofs, "%lu%s", block->frames[i].frame_type, i < block->nb_frames - 1 ? ", " : "");
                }
                LOG_EVENT(cnx, "PLUGINS", "ENQUEUE_FRAMES", "FRAME_FAIR_RESERVE", "{\"plugin\": \"%s\", \"nb_frames\": %d, \"total_bytes\": %lu, \"is_cc\": %d, \"frames\": [%s]}", p->name, block->nb_frames, block->total_bytes, block->is_congestion_controlled, ftypes_str);
            }
            /* Free the block */
            free(block);
        }
        total_plugin_bytes_in_flight += p->bytes_in_flight;
    } while ((p = get_next_plugin(cnx, p)) != cnx->first_drr);
    /* Now we put all we could */
    cnx->first_drr = get_next_plugin(cnx, p);
    cnx->wake_now = 0;

    /* Finally, put the first pointer to the next one */
    if (should_wake_now) {
        /* If we scheduled a frame but no app data and we have congestion allowance, let's wake again */
        if (stream == NULL || total_plugin_bytes_in_flight < max_plugin_cwin) {
            cnx->wake_now = 1;
        }
    }
}

/**
 * See PROTOOPID_NOPARAM_SCHEDULE_FRAMES_ON_PATH
 */
protoop_arg_t schedule_frames_on_path(picoquic_cnx_t *cnx)
{
    picoquic_packet_t* packet = (picoquic_packet_t*) cnx->protoop_inputv[0];
    size_t send_buffer_max = (size_t) cnx->protoop_inputv[1];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[2];
    picoquic_packet_t* retransmit_p = (picoquic_packet_t*) cnx->protoop_inputv[3];
    picoquic_path_t* from_path = (picoquic_path_t*) cnx->protoop_inputv[4];
    char* reason = (char*) cnx->protoop_inputv[5];

    int ret = 0;
    uint32_t length = 0;
    int is_cleartext_mode = 0;
    uint32_t checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);

    /* FIXME cope with different path MTUs */
    picoquic_path_t *path_x = cnx->path[0];
    PUSH_LOG_CTX(cnx, "\"path\": \"%p\"", path_x);

    uint32_t send_buffer_min_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : (uint32_t)send_buffer_max;
    int retransmit_possible = 1;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;
    size_t data_bytes = 0;
    uint32_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    picoquic_packet_type_enum packet_type = picoquic_packet_1rtt_protected_phi0;

    /* TODO: manage multiple streams. */
    picoquic_stream_head* stream = NULL;
    int tls_ready = picoquic_is_tls_stream_ready(cnx);
    stream = picoquic_find_ready_stream(cnx);
    picoquic_stream_head* plugin_stream = NULL;
    plugin_stream = picoquic_find_ready_plugin_stream(cnx);


    /* First enqueue frames that can be fairly sent, if any */
    /* Only schedule new frames if there is no planned frames */
    if (queue_peek(cnx->reserved_frames) == NULL) {
        stream = picoquic_schedule_next_stream(cnx, send_buffer_min_max - checksum_overhead - length, path_x);
        picoquic_frame_fair_reserve(cnx, path_x, stream, send_buffer_min_max - checksum_overhead - length);
    }

    char * retrans_reason = NULL;
    if (ret == 0 && retransmit_possible &&
        (length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, packet, send_buffer_min_max, &is_cleartext_mode, &header_length, &retrans_reason)) > 0) {
        if (reason != NULL) {
            protoop_id_t pid = { .id = retrans_reason };
            pid.hash = hash_value_str(pid.id);
            protoop_prepare_and_run_noparam(cnx, &pid, NULL, packet);
        }
        /* Set the new checksum length */
        checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);
        /* Check whether it makes sense to add an ACK at the end of the retransmission */
        /* Don't do that if it risks mixing clear text and encrypted ack */
        if (is_cleartext_mode == 0 && packet->ptype != picoquic_packet_0rtt_protected) {
            if (picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                send_buffer_min_max - checksum_overhead - length, &data_bytes)
                == 0) {
                length += (uint32_t)data_bytes;
                packet->length = length;
            }
        }
        /* document the send time & overhead */
        packet->is_pure_ack = 0;
        packet->send_time = current_time;
        packet->checksum_overhead = checksum_overhead;
    }
    else if (ret == 0) {
        length = picoquic_predict_packet_header_length(
                cnx, packet_type, path_x);
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = path_x->pkt_ctx[pc].send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;

        if (((stream == NULL && tls_ready == 0 && cnx->first_misc_frame == NULL) ||
                path_x->cwin <= path_x->bytes_in_transit)
            && picoquic_is_ack_needed(cnx, current_time, pc, path_x) == 0
            && path_x->challenge_response_to_send == 0
            && (path_x->challenge_verified == 1 || current_time < path_x->challenge_time + path_x->retransmit_timer)
            && queue_peek(cnx->reserved_frames) == NULL
            && queue_peek(cnx->retry_frames) == NULL) {
            if (ret == 0 && send_buffer_max > path_x->send_mtu
                && path_x->cwin > path_x->bytes_in_transit && picoquic_is_mtu_probe_needed(cnx, path_x)) {
                length = picoquic_prepare_mtu_probe(cnx, path_x, header_length, checksum_overhead, bytes);
                packet->is_mtu_probe = 1;
                packet->length = length;
                packet->is_congestion_controlled = 1;
                path_x->mtu_probe_sent = 1;
                packet->is_pure_ack = 0;
            } else {
                length = 0;
                packet->offset = 0;
            }
        } else {
            if (path_x->challenge_verified == 0 &&
                current_time >= (path_x->challenge_time + path_x->retransmit_timer)) {
                if (picoquic_prepare_path_challenge_frame(cnx, &bytes[length],
                                                            send_buffer_min_max - checksum_overhead - length,
                                                            &data_bytes, path_x) == 0) {
                    length += (uint32_t) data_bytes;
                    path_x->challenge_time = current_time;
                    path_x->challenge_repeat_count++;
                    packet->is_congestion_controlled = 1;


                    if (path_x->challenge_repeat_count > PICOQUIC_CHALLENGE_REPEAT_MAX) {
                        DBG_PRINTF("%s\n", "Too many challenge retransmits, disconnect");
                        picoquic_set_cnx_state(cnx, picoquic_state_disconnected);
                        if (cnx->callback_fn) {
                            (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
                        }
                        length = 0;
                        packet->offset = 0;
                    }
                }
            }

            if (cnx->cnx_state != picoquic_state_disconnected) {
                size_t consumed = 0;
                unsigned int is_pure_ack = packet->is_pure_ack;
                ret = picoquic_scheduler_write_new_frames(cnx, &bytes[length],
                                                          send_buffer_min_max - checksum_overhead - length, packet,
                                                          &consumed, &is_pure_ack);
                packet->is_pure_ack = is_pure_ack;
                if (!ret && consumed > send_buffer_min_max - checksum_overhead - length) {
                    ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                } else if (!ret) {
                    length += consumed;
                    /* FIXME: Sorry, I'm lazy, this could be easily fixed by making this a PO.
                        * This is needed by the way the cwin is now handled. */
                    if (path_x == cnx->path[0] && (header_length != length || picoquic_is_ack_needed(cnx, current_time, pc, path_x))) {
                        if (picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length], send_buffer_min_max - checksum_overhead - length, &data_bytes) == 0) {
                            length += (uint32_t)data_bytes;
                        }
                    }

                    if (path_x->cwin > path_x->bytes_in_transit) {
                        /* if present, send tls data */
                        if (tls_ready) {
                            ret = picoquic_prepare_crypto_hs_frame(cnx, 3, &bytes[length],
                                                                    send_buffer_min_max - checksum_overhead - length, &data_bytes);

                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                if (data_bytes > 0)
                                {
                                    packet->is_pure_ack = 0;
                                    packet->contains_crypto = 1;
                                    packet->is_congestion_controlled = 1;
                                }
                            }
                        }
                        /* if present, send path response. This ensures we send it on the right path */
                        if (path_x->challenge_response_to_send && send_buffer_min_max - checksum_overhead - length >= PICOQUIC_CHALLENGE_LENGTH + 1) {
                            /* This is not really clean, but it will work */
                            bytes[length] = picoquic_frame_type_path_response;
                            memcpy(&bytes[length+1], path_x->challenge_response, PICOQUIC_CHALLENGE_LENGTH);
                            path_x->challenge_response_to_send = 0;
                            length += PICOQUIC_CHALLENGE_LENGTH + 1;
                            packet->is_congestion_controlled = 1;
                        }
                        /* If present, send misc frame */
                        while (cnx->first_misc_frame != NULL) {
                            ret = picoquic_prepare_first_misc_frame(cnx, &bytes[length],
                                                                    send_buffer_min_max - checksum_overhead - length, &data_bytes);
                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                packet->is_congestion_controlled = 1;
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
                            ret = picoquic_prepare_max_data_frame(cnx, 2 * cnx->data_received, &bytes[length],
                                                                    send_buffer_min_max - checksum_overhead - length, &data_bytes);

                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                if (data_bytes > 0)
                                {
                                    packet->is_pure_ack = 0;
                                    packet->is_congestion_controlled = 1;
                                }
                            }
                            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                ret = 0;
                            }
                        }
                        /* If necessary, encode the max stream data frames */
                        if (ret == 0) {
                            ret = picoquic_prepare_required_max_stream_data_frames(cnx, &bytes[length],
                                                                                    send_buffer_min_max - checksum_overhead - length, &data_bytes);
                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                if (data_bytes > 0)
                                {
                                    packet->is_pure_ack = 0;
                                    packet->is_congestion_controlled = 1;
                                }
                            }
                        }
                        /* If required, request for plugins */
                        if (ret == 0 && !cnx->plugin_requested) {
                            int is_retransmittable = 1;
                            for (int i = 0; ret == 0 && i < cnx->pids_to_request.size; i++) {
                                ret = picoquic_write_plugin_validate_frame(cnx, &bytes[length], &bytes[send_buffer_min_max - checksum_overhead],
                                    cnx->pids_to_request.elems[i].pid_id, cnx->pids_to_request.elems[i].plugin_name, &data_bytes, &is_retransmittable);
                                if (ret == 0) {
                                    length += (uint32_t)data_bytes;
                                    if (data_bytes > 0)
                                    {
                                        packet->is_pure_ack = 0;
                                        packet->is_congestion_controlled = 1;
                                        cnx->pids_to_request.elems[i].requested = 1;
                                    }
                                }
                                else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                    ret = 0;
                                }
                            }
                            cnx->plugin_requested = 1;
                        }

                        /* Encode the plugin frame, or frames */
                        while (plugin_stream != NULL) {
                            size_t stream_bytes_max = picoquic_stream_bytes_max(cnx, send_buffer_min_max - checksum_overhead - length, header_length, bytes);
                            ret = picoquic_prepare_plugin_frame(cnx, plugin_stream, &bytes[length],
                                                                stream_bytes_max, &data_bytes);
                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                if (data_bytes > 0)
                                {
                                    packet->is_pure_ack = 0;
                                    packet->is_congestion_controlled = 1;
                                }

                                if (stream_bytes_max > checksum_overhead + length + 8) {
                                    plugin_stream = picoquic_find_ready_plugin_stream(cnx);
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

                        size_t stream_bytes_max = picoquic_stream_bytes_max(cnx, send_buffer_min_max - checksum_overhead - length, header_length, bytes);
                        stream = picoquic_schedule_next_stream(cnx, stream_bytes_max, path_x);

                        /* Encode the stream frame, or frames */
                        while (stream != NULL) {
                            ret = picoquic_prepare_stream_frame(cnx, stream, &bytes[length],
                                                                stream_bytes_max, &data_bytes);
                            if (ret == 0) {
                                length += (uint32_t)data_bytes;
                                if (data_bytes > 0)
                                {
                                    packet->is_pure_ack = 0;
                                    packet->is_congestion_controlled = 1;
                                }

                                if (stream_bytes_max > checksum_overhead + length + 8) {
                                    stream_bytes_max = picoquic_stream_bytes_max(cnx, send_buffer_min_max - checksum_overhead - length, header_length, bytes);
                                    stream = picoquic_schedule_next_stream(cnx, stream_bytes_max, path_x);
                                } else {
                                    break;
                                }
                            } else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                ret = 0;
                                break;
                            }
                        }
                    }
                    if (length == 0 || length == header_length) {
                        /* Don't flood the network with packets! */
                        length = 0;
                        packet->offset = 0;
                    } else if (length > 0 && length != header_length && length + checksum_overhead <= PICOQUIC_RESET_PACKET_MIN_SIZE) {
                        uint32_t pad_size = PICOQUIC_RESET_PACKET_MIN_SIZE - checksum_overhead - length + 1;
                        for (uint32_t i = 0; i < pad_size; i++) {
                            bytes[length++] = 0;
                        }
                    }
                }
            }

        }
    }

    POP_LOG_CTX(cnx);
    protoop_save_outputs(cnx, path_x, length, header_length);
    return (protoop_arg_t) ret;
}


/* TODO FIXME packet should never be passed in this function, we should have a way to say send the retransmission now on the given path */
int picoquic_schedule_frames_on_path(picoquic_cnx_t *cnx, picoquic_packet_t *packet, size_t send_buffer_max, uint64_t current_time,
    picoquic_packet_t* retransmit_p, picoquic_path_t * from_path, char * reason, picoquic_path_t **path_x, uint32_t *length, uint32_t *header_length)
{
    
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_SCHEDULE_FRAMES_ON_PATH, outs,
        packet, send_buffer_max, current_time, retransmit_p, from_path, reason);
    *path_x = (picoquic_path_t*) outs[0];
    *length = (uint32_t) outs[1];
    *header_length = (uint32_t) outs[2];
    return ret;
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

    picoquic_packet_type_enum packet_type = picoquic_packet_1rtt_protected_phi0;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;
    int timer_based_retransmit = 0;
    char* reason = NULL;

    LOG_EVENT(cnx, "TRANSPORT", "PREPARE_PACKET", "", "{\"type\": \"%s\"}", picoquic_log_ptype_name(packet_type));
    PUSH_LOG_CTX(cnx, "\"packet_type\": \"%s\"", picoquic_log_ptype_name(packet_type));

    /* We should be able to get the retransmission, no matter the path we look at */
    picoquic_packet_t* retransmit_p = NULL;
    picoquic_path_t * from_path = NULL;
    for (int i = 0; !retransmit_p && i < cnx->nb_paths; i++) {
        picoquic_path_t* orig_path = cnx->path[i];
        picoquic_packet_t* p = orig_path->pkt_ctx[pc].retransmit_oldest;
        while (p != NULL) {
            picoquic_packet_t* p_next = p->next_packet;
            int should_retransmit = 0;
            timer_based_retransmit = 0;
            reason = NULL;
            /* Get the packet type */

            should_retransmit = picoquic_retransmit_needed_by_packet(cnx, p, current_time, &timer_based_retransmit, &reason);

            if (should_retransmit == 0) {
                break;
            }

            /* We might need to retransmit, but should we really? If it is a pure ACK, don't */
            if (p->is_pure_ack) {
                picoquic_dequeue_retransmit_packet(cnx, p, p->is_pure_ack);
                p = p_next;
            } else {
                /* Ok, we found one! */
                retransmit_p = p;
                from_path = p->send_path;
                break;
            }
        }
    }

    int ret = 0;
    int is_cleartext_mode = 0;
    packet->contains_crypto = 0;
    packet->is_pure_ack = 1;
    int contains_crypto = 0;
    uint32_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint32_t length = 0;
    uint32_t checksum_overhead = 0;
    uint32_t send_buffer_min_max = 0;

    /* Verify first that there is no need for retransmit or ack
     * on initial or handshake context. This does not deal with EOED packets,
     * as they are handled from within the general retransmission path */
    for (int i = 0; ret == 0 && length == 0 && i < cnx->nb_paths; i++) {
        path_x = cnx->path[i];
        checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);
        send_buffer_min_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : (uint32_t)send_buffer_max;
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
            path_x, packet, send_buffer_min_max, current_time, &header_length);

        if (length == 0) {
            length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_handshake,
                path_x, packet, send_buffer_min_max, current_time, &header_length);
        }
    }

    if (length == 0) {
        packet->pc = pc;
        ret = picoquic_schedule_frames_on_path(cnx, packet, send_buffer_max, current_time, retransmit_p,
                                      from_path, reason, &path_x, &length, &header_length);

        if (cnx->cnx_state != picoquic_state_disconnected) {
            /* If necessary, encode and send the keep alive packet!
             * We only send keep alive packets when no other data is sent!
             */
            if (packet->is_pure_ack == 0)
            {
                cnx->latest_progress_time = current_time;
            }
            else if (
                cnx->keep_alive_interval != 0
                && cnx->latest_progress_time + cnx->keep_alive_interval <= current_time && length == 0) {
                length = picoquic_predict_packet_header_length(
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

    packet->contains_crypto = contains_crypto;

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        &send_length, send_buffer, send_buffer_min_max, path_x, current_time);

    if (send_length > 0) {
        path_x->ping_received = 0;
    }

    if ((queue_peek(cnx->reserved_frames) != NULL || queue_peek(cnx->retry_frames) != NULL) && path_x->cwin > path_x->bytes_in_transit && send_length > 0) {
        picoquic_reinsert_by_wake_time(cnx->quic, cnx, current_time);
    } else {
        picoquic_cnx_set_next_wake_time(cnx, current_time, length);
    }

    POP_LOG_CTX(cnx);
    protoop_save_outputs(cnx, send_length, path_x);

    return (protoop_arg_t) ret;
}

/*  Prepare the next packet to send when in one the ready states */
int picoquic_prepare_packet_ready(picoquic_cnx_t* cnx, picoquic_path_t ** path, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREPARE_PACKET_READY, outs,
        *path, packet, current_time, send_buffer, send_buffer_max, *send_length);
    *send_length = (size_t) outs[0];
    *path = (picoquic_path_t*) outs[1];
    return ret;
}

/* Prepare next packet to send, or nothing.. */
int picoquic_prepare_segment(picoquic_cnx_t* cnx, picoquic_path_t ** path, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length)
{
    int ret = 0;
  
    /* Check that the connection is still alive -- the timer is asymmetric, so client will drop faster */
    if ((cnx->cnx_state < picoquic_state_disconnecting && 
        current_time >= cnx->latest_progress_time && (current_time - cnx->latest_progress_time) >= (PICOQUIC_MICROSEC_SILENCE_MAX*(2 - cnx->client_mode))) ||
        (cnx->cnx_state < picoquic_state_client_ready &&
            current_time >= cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX))
    {
        /* Too long silence, break it. */
        picoquic_set_cnx_state(cnx, picoquic_state_disconnected);
        ret = PICOQUIC_ERROR_DISCONNECTED;
        if (cnx->callback_fn) {
            (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
        }
    } else {
        /* Prepare header -- depend on connection state */
        /* TODO: 0-RTT work. */
        switch (cnx->cnx_state) {
        case picoquic_state_client_init:
        case picoquic_state_client_init_sent:
        case picoquic_state_client_init_resent:
        case picoquic_state_client_renegotiate:
        case picoquic_state_client_handshake_start:
        case picoquic_state_client_handshake_progress:
        case picoquic_state_client_almost_ready:
            ret = picoquic_prepare_packet_client_init(cnx, path, packet, current_time, send_buffer, send_buffer_max, send_length);
            break;
        case picoquic_state_server_almost_ready:
        case picoquic_state_server_init:
        case picoquic_state_server_handshake:
            ret = picoquic_prepare_packet_server_init(cnx, path, packet, current_time, send_buffer, send_buffer_max, send_length);
            break;
        case picoquic_state_client_ready:
        case picoquic_state_server_ready:
            ret = picoquic_prepare_packet_ready(cnx, path, packet, current_time, send_buffer, send_buffer_max, send_length);
            break;
        case picoquic_state_handshake_failure:
        case picoquic_state_disconnecting:
        case picoquic_state_closing_received:
        case picoquic_state_closing:
        case picoquic_state_draining:
            ret = picoquic_prepare_packet_closing(cnx, path, packet, current_time, send_buffer, send_buffer_max, send_length);
            break;
        case picoquic_state_disconnected:
            ret = PICOQUIC_ERROR_DISCONNECTED;
            break;
        case picoquic_state_client_retry_received:
            DBG_PRINTF("Unexpected connection state: %d\n", cnx->cnx_state);
            ret = PICOQUIC_ERROR_UNEXPECTED_STATE;
            break;
        default:
            DBG_PRINTF("Unexpected connection state: %d\n", cnx->cnx_state);
            ret = PICOQUIC_ERROR_UNEXPECTED_STATE;
            break;
        }
    }

    if (*send_length > 0 && *path) {
        (*path)->nb_pkt_sent++;
    }

    return ret;
}


/* Prepare next packet to send, or nothing.. */
int picoquic_prepare_packet(picoquic_cnx_t* cnx,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, picoquic_path_t **path)
{
    int ret = 0;
    picoquic_packet_t * packet = NULL;

    *send_length = 0;

    while (ret == 0)
    {
        size_t available = send_buffer_max;
        size_t segment_length = 0;

        /* TODO cope with different path mtus */
        picoquic_path_t* path_x = cnx->path[0];
        if (*send_length > 0) {
            send_buffer_max = path_x->send_mtu;

            if (send_buffer_max < *send_length + PICOQUIC_MIN_SEGMENT_SIZE) {
                break;
            }
            else {
                available = send_buffer_max - *send_length;
            }
        }

        packet = picoquic_create_packet(cnx);

        if (packet == NULL) {
            ret = PICOQUIC_ERROR_MEMORY;
            break;
        }
        else {
            ret = picoquic_prepare_segment(cnx, path, packet, current_time,
                send_buffer + *send_length, available, &segment_length);

            if (ret == 0) {
                *send_length += segment_length;
                if (packet->length == 0 ||
                    packet->ptype == picoquic_packet_1rtt_protected_phi0 ||
                    packet->ptype == picoquic_packet_1rtt_protected_phi1) {
                    if (packet->length == 0) {
                        picoquic_destroy_packet(packet);
                        packet = NULL;
                    }
                    break;
                } else {
                    LOG_EVENT(cnx, "TRANSPORT", "PACKET_PREPARED", "", "{\"type\": \"%s\", \"pn\": %lu, \"path\": \"%p\"}", picoquic_log_ptype_name(packet->ptype), packet->sequence_number, packet->send_path);
                }
            } else {
                picoquic_destroy_packet(packet);
                packet = NULL;

                if (*send_length != 0){
                    ret = 0;
                }
                break;
            }
        }
    }

    return ret;
}

int picoquic_close(picoquic_cnx_t* cnx, uint16_t reason_code)
{
    int ret = 0;

    if (cnx->cnx_state == picoquic_state_server_ready || cnx->cnx_state == picoquic_state_client_ready) {
        picoquic_set_cnx_state(cnx, picoquic_state_disconnecting);
        cnx->application_error = reason_code;
    } else if (cnx->cnx_state < picoquic_state_client_ready) {
        picoquic_set_cnx_state(cnx, picoquic_state_handshake_failure);
        cnx->application_error = reason_code;
    } else {
        ret = -1;
    }
    cnx->offending_frame_type = 0;

    picoquic_cnx_set_next_wake_time(cnx, picoquic_get_quic_time(cnx->quic), 1);

    return ret;
}

void sender_register_noparam_protoops(picoquic_cnx_t *cnx)
{
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_GET_DESTINATION_CONNECTION_ID, &get_destination_connection_id);

    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_SET_NEXT_WAKE_TIME, &set_next_wake_time);

    /** \todo Refactor API */
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREPARE_PACKET_READY, &prepare_packet_ready);

    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_SELECT_SENDING_PATH, &select_sending_path);

    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_SCHEDULE_FRAMES_ON_PATH, &schedule_frames_on_path);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_SCHEDULER_WRITE_NEW_FRAMES, &scheduler_write_new_frames);

    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_RETRANSMIT_NEEDED, &retransmit_needed);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_RETRANSMIT_NEEDED_BY_PACKET, &retransmit_needed_by_packet);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREDICT_PACKET_HEADER_LENGTH, &predict_packet_header_length);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_GET_CHECKSUM_LENGTH, &get_checksum_length);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_DEQUEUE_RETRANSMIT_PACKET, &dequeue_retransmit_packet);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_DEQUEUE_RETRANSMITTED_PACKET, &dequeue_retransmitted_packet);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREPARE_PACKET_OLD_CONTEXT, &prepare_packet_old_context);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREPARE_MTU_PROBE, &prepare_mtu_probe);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_FINALIZE_AND_PROTECT_PACKET, &finalize_and_protect_packet);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_HAS_CONGESTION_CONTROLLED_PLUGIN_FRAMEMS_TO_SEND, &has_congestion_controlled_plugin_frames_to_send);
}