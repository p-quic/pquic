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

/* Decoding of the various frames, and application to context */
#include "picoquic_internal.h"
#include <stdlib.h>
#include <string.h>
#include "plugin.h"
#include "memory.h"

/* ****************************************************
 * Frames private declarations
 * ****************************************************/


/**
 * Frame decoder function
 * Inputs:
 *   cnx       - [in/out] picoquic Context
 *   bytes     - [in]     pointer to the beginning of the frame (frame type)
 *   bytes_max - [in]     pointer to the end of the packet (one past the last byte)
 * Returns:
 *   Pointer to the data following the end of this frame, if the frame has been decoded successfully;
 *   or NULL if, decoding failed (in which case, picoquic_connection_error has been called).
 */
typedef uint8_t* (*decode_frame_fn)(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max);

/**
 * Frame skip function
 * Inputs:
 *   bytes     - [in]     pointer to the beginning of the frame (frame type)
 *   bytes_max - [in]     pointer to the end of the packet (one past the last byte)
 * Returns:
 *   Pointer to the data following the end of this frame, if the frame has been skipped successfully;
 *   or NULL if, skipping failed.
 */
typedef uint8_t* (*skip_frame_fn)(uint8_t* bytes, const uint8_t* bytes_max);


/* ****************************************************
 * Helper utilities
 * ****************************************************/

/* Skip and decode function.
 * These functions return NULL in case of a failure (insufficient buffer).
 */

#define VARINT_LEN(bytes) (1U << (((bytes)[0] & 0xC0) >> 6))


static uint8_t* picoquic_frames_fixed_skip(uint8_t* bytes, const uint8_t* bytes_max, size_t size)
{
    return (bytes += size) <= bytes_max ? bytes : NULL;
}


static uint8_t* picoquic_frames_varint_skip(uint8_t* bytes, const uint8_t* bytes_max)
{
    return bytes < bytes_max ? picoquic_frames_fixed_skip(bytes, bytes_max, (uint64_t)VARINT_LEN(bytes)) : NULL;
}


/* Parse a varint. In case of an error, *n64 is unchanged, and NULL is returned */
uint8_t* picoquic_frames_varint_decode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n64)
{
    uint8_t length;

    if (bytes < bytes_max && bytes + (length=VARINT_LEN(bytes)) <= bytes_max) {
        uint64_t v = *bytes++ & 0x3F;

        while (--length > 0) {
            v <<= 8;
            v += *bytes++;
        }

        *n64 = v;
    } else {
        bytes = NULL;
    }

    return bytes;
}


static uint8_t* picoquic_frames_uint8_decode(uint8_t* bytes, const uint8_t* bytes_max, uint8_t* n)
{
    if (bytes < bytes_max) {
        *n = *bytes++;
    } else {
        bytes = NULL;
    }
    return bytes;
}


static uint8_t* picoquic_frames_uint64_decode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n)
{
    if (bytes + sizeof(*n) <= bytes_max) {
        *n = PICOPARSE_64(bytes);
        bytes += sizeof(*n);
    } else {
        bytes = NULL;
    }
    return bytes;
}


static uint8_t* picoquic_frames_length_data_skip(uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t length;
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &length)) != NULL) {
        bytes = picoquic_frames_fixed_skip(bytes, bytes_max, (size_t)length);
    }
    return bytes;
}


/* ****************************************************** */

picoquic_stream_head* picoquic_create_stream(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    picoquic_stream_head* stream = (picoquic_stream_head*)malloc(sizeof(picoquic_stream_head));
    if (stream != NULL) {
        picoquic_stream_head* previous_stream = NULL;
        picoquic_stream_head* next_stream = cnx->first_stream;

        memset(stream, 0, sizeof(picoquic_stream_head));
        stream->stream_id = stream_id;

        if (IS_LOCAL_STREAM_ID(stream_id, cnx->client_mode)) {
            if (IS_BIDIR_STREAM_ID(stream_id)) {
                stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_bidi_local;
                stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_bidi_remote;
            }
            else {
                stream->maxdata_local = 0;
                stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_uni;
            }
        }
        else {
            if (IS_BIDIR_STREAM_ID(stream_id)) {
                stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_bidi_remote;
                stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_bidi_local;
            }
            else {
                stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_uni;
                stream->maxdata_remote = 0;
            }
        }

        /*
         * Make sure that the streams are open in order.
         */

        while (next_stream != NULL && next_stream->stream_id < stream_id) {
            previous_stream = next_stream;
            next_stream = next_stream->next_stream;
        }

        stream->next_stream = next_stream;

        if (previous_stream == NULL) {
            cnx->first_stream = stream;
        } else {
            previous_stream->next_stream = stream;
        }

        protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_STREAM_OPENED, NULL, stream, stream_id);
    }

    return stream;
}

/* if the initial remote has changed, update the existing streams.
 * By definition, this is only needed for streams locally created for 0-RTT traffic.
 */

void picoquic_update_stream_initial_remote(picoquic_cnx_t* cnx)
{
    picoquic_stream_head* stream = cnx->first_stream;

    while (stream) {
        if (IS_LOCAL_STREAM_ID(stream->stream_id, cnx->client_mode)) {
            if (IS_BIDIR_STREAM_ID(stream->stream_id)) {
                if (stream->maxdata_remote < cnx->remote_parameters.initial_max_stream_data_bidi_remote) {
                    stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_bidi_remote;
                }
            }
            else {
                if (stream->maxdata_remote < cnx->remote_parameters.initial_max_stream_data_uni) {
                    stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_uni;
                }
            }
        }
        stream = stream->next_stream;
    };
}

picoquic_stream_head* picoquic_find_stream(picoquic_cnx_t* cnx, uint64_t stream_id, int create)
{
    picoquic_stream_head* stream = cnx->first_stream;

    while (stream) {
        if (stream->stream_id == stream_id) {
            break;
        } else {
            stream = stream->next_stream;
        }
    };

    if (create != 0 && stream == NULL) {
        stream = picoquic_create_stream(cnx, stream_id);
    }

    return stream;
}

picoquic_stream_head* picoquic_find_or_create_stream(picoquic_cnx_t* cnx, uint64_t stream_id, int is_remote)
{
    picoquic_stream_head* stream = picoquic_find_stream(cnx, stream_id, 0);

    if (stream == NULL) {
        /* Verify the stream ID control conditions */
        unsigned int expect_client_stream = cnx->client_mode ^ is_remote;
        uint64_t max_stream = IS_BIDIR_STREAM_ID(stream_id) ? cnx->max_stream_id_bidir_local : cnx->max_stream_id_unidir_local;

        if (IS_CLIENT_STREAM_ID(stream_id) != expect_client_stream || stream_id > max_stream) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_STREAM_LIMIT_ERROR, 0);

        } else if ((stream = picoquic_create_stream(cnx, stream_id)) == NULL) {
            picoquic_connection_error(cnx, PICOQUIC_ERROR_MEMORY, 0);

        } else if (!IS_BIDIR_STREAM_ID(stream_id)) {
            /* Mark the stream as already finished in our direction */
            picoquic_add_stream_flags(cnx, stream, picoquic_stream_flag_fin_notified | picoquic_stream_flag_fin_sent);
        }
    }

    return stream;
}

picoquic_stream_head* picoquic_create_plugin_stream(picoquic_cnx_t* cnx, uint64_t pid_id)
{
    picoquic_stream_head* stream = (picoquic_stream_head*)malloc(sizeof(picoquic_stream_head));
    if (stream != NULL) {
        picoquic_stream_head* previous_stream = NULL;
        picoquic_stream_head* next_stream = cnx->first_plugin_stream;

        memset(stream, 0, sizeof(picoquic_stream_head));
        stream->stream_id = pid_id;

        /* FIXME currently, only server is allowed to send plugin frames */
        if (cnx->client_mode) {
            stream->maxdata_local = MAX_PLUGIN_DATA_LEN; /* Limit to MAX_PLUGIN_DATA_LEN */
            stream->maxdata_remote = 0;
        } else {
            stream->maxdata_local = 0;
            stream->maxdata_remote = MAX_PLUGIN_DATA_LEN; /* Limit to MAX_PLUGIN_DATA_LEN */
        }

        /*
         * Make sure that the streams are open in order.
         */
        while (next_stream != NULL && next_stream->stream_id < pid_id) {
            previous_stream = next_stream;
            next_stream = next_stream->next_stream;
        }

        stream->next_stream = next_stream;

        if (previous_stream == NULL) {
            cnx->first_plugin_stream = stream;
        } else {
            previous_stream->next_stream = stream;
        }

        protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PLUGIN_STREAM_OPENED, NULL, stream, pid_id);
    }

    return stream;
}

picoquic_stream_head* picoquic_find_plugin_stream(picoquic_cnx_t* cnx, uint64_t pid_id, int create)
{
    picoquic_stream_head* stream = cnx->first_plugin_stream;

    while (stream) {
        if (stream->stream_id == pid_id) {
            break;
        } else {
            stream = stream->next_stream;
        }
    };

    if (create != 0 && stream == NULL) {
        stream = picoquic_create_plugin_stream(cnx, pid_id);
    }

    return stream;
}

picoquic_stream_head* picoquic_find_or_create_plugin_stream(picoquic_cnx_t* cnx, uint64_t pid_id, int is_remote)
{
    picoquic_stream_head* stream = picoquic_find_plugin_stream(cnx, pid_id, 0);

    if (stream == NULL) {
        /* We expect being remote and being the client */
        if (!is_remote || !cnx->client_mode) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_STREAM_LIMIT_ERROR, 0);
        } else if ((stream = picoquic_create_plugin_stream(cnx, pid_id)) == NULL) {
            picoquic_connection_error(cnx, PICOQUIC_ERROR_MEMORY, 0);
        }
    }

    return stream;
}


void picoquic_add_stream_flags(picoquic_cnx_t* cnx, picoquic_stream_head* stream, uint32_t flags) {
    bool stream_closed = STREAM_CLOSED(stream);
    uint32_t old_flags = stream->stream_flags;
    stream->stream_flags |= flags;
    if ((old_flags & flags) != flags) {
        protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_STREAM_FLAGS_CHANGED, NULL, stream, stream->stream_id, stream->stream_flags);
    }
    if (!stream_closed && STREAM_CLOSED(stream)) {
        protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_STREAM_CLOSED, NULL, stream, stream->stream_id);
    }
}

/*
 * Check of the number of newly received bytes, or newly committed bytes
 * when a new max offset is learnt for a stream.
 */

int picoquic_flow_control_check_stream_offset(picoquic_cnx_t* cnx, picoquic_stream_head* stream,
    uint64_t new_fin_offset)
{
    int ret = 0;

    if (new_fin_offset > stream->maxdata_local) {
        /* protocol violation */
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FLOW_CONTROL_ERROR, 0);
    } else if (new_fin_offset > stream->fin_offset) {
        /* Checking the flow control limits. Need to pay attention
        * to possible integer overflow */

        uint64_t new_bytes = new_fin_offset - stream->fin_offset;

        if (new_bytes > cnx->maxdata_local || cnx->maxdata_local - new_bytes < cnx->data_received) {
            /* protocol violation */
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FLOW_CONTROL_ERROR, 0);
        } else {
            cnx->data_received += new_bytes;
            stream->fin_offset = new_fin_offset;
        }
    }

    return ret;
}

/*
 * RST_STREAM Frame
 *
 * An endpoint may use a RST_STREAM frame (type=0x01) to abruptly terminate a stream.
 */

int picoquic_prepare_stream_reset_frame(picoquic_cnx_t *cnx, picoquic_stream_head* stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;

    if ((stream->stream_flags & picoquic_stream_flag_reset_requested) == 0 || (stream->stream_flags & picoquic_stream_flag_reset_sent) != 0) {
        *consumed = 0;
    } else {
        size_t l1 = 0, l2 = 0, l3 = 0;
        if (bytes_max > 2) {
            bytes[byte_index++] = picoquic_frame_type_reset_stream;
            l1 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, stream->stream_id);
            byte_index += l1;
            l2 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, stream->local_error);
            byte_index += l2;
            l3 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, stream->sent_offset);
            byte_index += l3;
        }

        if (l1 == 0 || l2 == 0 || l3 == 0) {
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
            *consumed = 0;
        } else {
            *consumed = byte_index;
            picoquic_add_stream_flags(cnx, stream, picoquic_stream_flag_reset_sent | picoquic_stream_flag_fin_sent);

            /* Free the queued data */
            while (stream->send_queue != NULL) {
                picoquic_stream_data* next = stream->send_queue->next_stream_data;
                if (stream->send_queue->bytes != NULL) {
                    free(stream->send_queue->bytes);
                }
                free(stream->send_queue);
                stream->send_queue = next;
            }
        }
    }

    if (!ret) {
        LOG_EVENT(cnx, "FRAMES", "RST_STREAM_CREATED", "", "{\"data_ptr\": \"%p\", \"stream_ptr\": \"%p\", \"stream_id\": %" PRIu64 ", \"error\": %" PRIu64 ", \"offset\": %" PRIu64 "}", bytes, stream, stream->stream_id, stream->local_error, stream->sent_offset);
    }

    return ret;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_reset_stream_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    reset_stream_frame_t *frame = malloc(sizeof(reset_stream_frame_t));
    if (!frame) {
        printf("Failed to allocate memory for reset_stream_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->stream_id)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->app_error_code)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->final_offset)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_reset_stream);
        free(frame);
        frame = NULL;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_stream_reset_frame(picoquic_cnx_t* cnx)
{
    reset_stream_frame_t* frame = (reset_stream_frame_t *) cnx->protoop_inputv[0];

    picoquic_stream_head* stream;

    if ((stream = picoquic_find_or_create_stream(cnx, frame->stream_id, 1)) == NULL) {
        return 1; // error already signaled
    } else if ((stream->stream_flags & (picoquic_stream_flag_fin_received | picoquic_stream_flag_reset_received)) != 0 && frame->final_offset != stream->fin_offset) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FINAL_SIZE_ERROR,
            picoquic_frame_type_reset_stream);
        return 1;
    } else if (picoquic_flow_control_check_stream_offset(cnx, stream, frame->final_offset) != 0) {
        return 1; // error already signaled
    } else if ((stream->stream_flags & picoquic_stream_flag_reset_received) == 0) {
        stream->stream_flags |= picoquic_stream_flag_reset_received;
        stream->remote_error  = frame->app_error_code;

        if (cnx->callback_fn != NULL && (stream->stream_flags & picoquic_stream_flag_reset_signalled) == 0) {
            cnx->callback_fn(cnx, stream->stream_id, NULL, 0, picoquic_callback_stream_reset, cnx->callback_ctx);
            stream->stream_flags |= picoquic_stream_flag_reset_signalled;
        }
    }

    return 0;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_new_connection_id_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    new_connection_id_frame_t *frame = malloc(sizeof(new_connection_id_frame_t));
    if (!frame) {
        printf("Failed to allocate memory for new_connection_id_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->sequence)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->retire_prior_to)) == NULL ||
        (bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &frame->connection_id.id_len)) == NULL ||
        (frame->connection_id.id_len > PICOQUIC_CONNECTION_ID_MAX_SIZE) ||
        (bytes = (bytes + frame->connection_id.id_len + 16 <= bytes_max ? bytes : NULL)) == NULL)
    {
        bytes = NULL;
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_new_connection_id);
        free(frame);
        frame = NULL;
    }
    else
    {
        /* Memory bounds have been checked, so everything should be safe now */
        memcpy(&frame->connection_id.id, bytes, frame->connection_id.id_len);
        bytes += frame->connection_id.id_len;
        memcpy(&frame->stateless_reset_token, bytes, 16);
        bytes += 16;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

protoop_arg_t parse_retire_connection_id_frame(picoquic_cnx_t* cnx) {
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    retire_connection_id_frame_t *frame = malloc(sizeof(retire_connection_id_frame_t));
    if (!frame) {
        printf("Failed to allocate memory for retire_connection_id_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->sequence)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_retire_connection_id);
        free(frame);
        frame = NULL;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/*
 * New Retry Token frame
 */
uint8_t* picoquic_skip_new_token_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    return picoquic_frames_length_data_skip(bytes + picoquic_varint_skip(bytes), bytes_max);
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_new_token_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    new_token_frame_t *frame = malloc(sizeof(new_token_frame_t));
    if (!frame) {
        printf("Failed to allocate memory for new_token_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->token_length)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_new_token);
        free(frame);
        frame = NULL;
    }

    if (bytes_max - bytes < frame->token_length) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_new_token);
        bytes = NULL;
        free(frame);
        frame = NULL;
    } else {
        frame->token_ptr = bytes;
        bytes += frame->token_length;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/*
 * STOP SENDING Frame
 */

int picoquic_prepare_stop_sending_frame(picoquic_cnx_t* cnx, picoquic_stream_head* stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    const size_t min_length = 1 + 4 + 2;
    size_t byte_index = 0;

    if (bytes_max < min_length) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else if ((stream->stream_flags & picoquic_stream_flag_stop_sending_requested) == 0 || (stream->stream_flags & picoquic_stream_flag_stop_sending_sent) != 0 || (stream->stream_flags & picoquic_stream_flag_fin_received) != 0 || (stream->stream_flags & picoquic_stream_flag_reset_received) != 0) {
        *consumed = 0;
    } else {
        bytes[byte_index++] = picoquic_frame_type_stop_sending;
        byte_index += picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
            (uint64_t)stream->stream_id);
        picoformat_16(bytes + byte_index, (uint16_t)stream->local_stop_error);
        byte_index += 2;
        *consumed = byte_index;
        picoquic_add_stream_flags(cnx, stream, picoquic_stream_flag_stop_sending_sent);

        LOG_EVENT(cnx, "FRAMES", "STOP_SENDING_CREATED", "", "{\"data_ptr\": \"%p\", \"stream_id\": %" PRIu64 ", \"error\": %d}", bytes, stream->stream_id, stream->local_stop_error);
    }

    return ret;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_stop_sending_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    stop_sending_frame_t *frame = malloc(sizeof(stop_sending_frame_t));
    if (!frame) {
        printf("Failed to allocate memory for stop_sending_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->stream_id)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->application_error_code)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_new_connection_id);
        free(frame);
        frame = NULL;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_stop_sending_frame(picoquic_cnx_t* cnx)
{
    stop_sending_frame_t *frame = (stop_sending_frame_t *) cnx->protoop_inputv[0];

    picoquic_stream_head* stream;

    if ((stream = picoquic_find_or_create_stream(cnx, frame->stream_id, 1)) == NULL) {
        return 1;  // Error already signaled
    } else if ((stream->stream_flags & (picoquic_stream_flag_stop_sending_received | picoquic_stream_flag_reset_requested)) == 0) {
        stream->stream_flags |= picoquic_stream_flag_stop_sending_received;
        stream->remote_stop_error = frame->application_error_code;

        if (cnx->callback_fn != NULL && (stream->stream_flags & picoquic_stream_flag_stop_sending_signalled) == 0) {
            cnx->callback_fn(cnx, stream->stream_id, NULL, 0, picoquic_callback_stop_sending, cnx->callback_ctx);
            stream->stream_flags |= picoquic_stream_flag_stop_sending_signalled;
        }
    }

    return 0;
}

/*
 * Stream frame.
 * In our implementation, stream 0 is special, and feeds directly
 * into the SSL API.
 *
 * STREAM frames implicitly create a stream and carry stream data.
 */

int picoquic_is_stream_frame_unlimited(const uint8_t* bytes)
{
    return PICOQUIC_BITS_CLEAR_IN_RANGE(bytes[0], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max, 0x02);
}

int picoquic_parse_stream_header(const uint8_t* bytes, size_t bytes_max,
    uint64_t* stream_id, uint64_t* offset, size_t* data_length, int* fin,
    size_t* consumed)
{
    int ret = 0;
    int len = bytes[0] & 2;
    int off = bytes[0] & 4;
    uint64_t length = 0;
    size_t l_stream = 0;
    size_t l_len = 0;
    size_t l_off = 0;
    size_t byte_index = 1;

    *fin = bytes[0] & 1;

    if (bytes_max > byte_index) {
        l_stream = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, stream_id);
        byte_index += l_stream;
    }

    if (off == 0) {
        *offset = 0;
    } else if (bytes_max > byte_index) {
        l_off = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, offset);
        byte_index += l_off;
    }

    if (bytes_max < byte_index || l_stream == 0 || (off != 0 && l_off == 0)) {
        DBG_PRINTF("stream frame header too large: first_byte=0x%02x, bytes_max=%" PRIst,
            bytes[0], bytes_max);
        *data_length = 0;
        byte_index = bytes_max;
        ret = -1;
    } else if (len == 0) {
        *data_length = bytes_max - byte_index;
    } else {
        if (bytes_max > byte_index) {
            l_len = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &length);
            byte_index += l_len;
            *data_length = (size_t)length;
        }

        if (l_len == 0 || bytes_max < byte_index) {
            DBG_PRINTF("stream frame header too large: first_byte=0x%02x, bytes_max=%" PRIst,
                bytes[0], bytes_max);
            byte_index = bytes_max;
            ret = -1;
        } else if (byte_index + length > bytes_max) {
            DBG_PRINTF("stream data past the end of the packet: first_byte=0x%02x, data_length=%" PRIst ", max_bytes=%" PRIst,
                bytes[0], *data_length, bytes_max);
            ret = -1;
        }
    }

    *consumed = byte_index;
    return ret;
}

void picoquic_stream_data_callback(picoquic_cnx_t* cnx, picoquic_stream_head* stream)
{
    picoquic_stream_data* data = stream->stream_data;

    while (data != NULL && data->offset <= stream->consumed_offset) {
        size_t start = (size_t)(stream->consumed_offset - data->offset);
        size_t data_length = data->length - start;
        picoquic_call_back_event_t fin_now = picoquic_callback_no_event;

        stream->consumed_offset += data_length;

        if (stream->consumed_offset >= stream->fin_offset && (stream->stream_flags & (picoquic_stream_flag_fin_received | picoquic_stream_flag_fin_signalled)) == picoquic_stream_flag_fin_received) {
            fin_now = picoquic_callback_stream_fin;
            picoquic_add_stream_flags(cnx, stream, picoquic_stream_flag_fin_signalled);
        }

        LOG_EVENT(cnx, "APPLICATION", "CALLBACK", picoquic_log_fin_or_event_name(fin_now), "{\"stream_id\": %" PRIu64 ", \"data_length\": %" PRIu64 "}", stream->stream_id, data_length);
        cnx->callback_fn(cnx, stream->stream_id, data->bytes + start, data_length, fin_now,
            cnx->callback_ctx);

        free(data->bytes);
        stream->stream_data = data->next_stream_data;
        free(data);
        data = stream->stream_data;
    }

    /* handle the case where the fin frame does not carry any data */

    if (stream->consumed_offset >= stream->fin_offset && (stream->stream_flags & (picoquic_stream_flag_fin_received | picoquic_stream_flag_fin_signalled)) == picoquic_stream_flag_fin_received) {
        picoquic_add_stream_flags(cnx, stream, picoquic_stream_flag_fin_signalled);
        LOG_EVENT(cnx, "APPLICATION", "CALLBACK", picoquic_log_fin_or_event_name(picoquic_callback_stream_fin), "{\"stream_id\": %" PRIu64 ", \"data_length\": 0}", stream->stream_id);
        cnx->callback_fn(cnx, stream->stream_id, NULL, 0, picoquic_callback_stream_fin,
            cnx->callback_ctx);
    }
}

/* Common code to data stream and crypto hs stream */
static int picoquic_queue_network_input(picoquic_cnx_t* cnx, picoquic_stream_head* stream, size_t offset, uint8_t* bytes, size_t length, int * new_data_available)
{
    int ret = 0;
    picoquic_stream_data** pprevious = &stream->stream_data;
    picoquic_stream_data* next = stream->stream_data;
    size_t start = 0;

    if (offset <= stream->consumed_offset) {
        if (offset + length <= stream->consumed_offset) {
            /* already received */
            start = length;
        }
        else {
            start = (size_t)(stream->consumed_offset - offset);
        }
    }

    /* Queue of a block in the stream */

    while (next != NULL && start < length && next->offset <= offset + start) {
        if (offset + length <= next->offset + next->length) {
            start = length;
        } else if (offset < next->offset + next->length) {
            start = (size_t)(next->offset + next->length - offset);
        }
        pprevious = &next->next_stream_data;
        next = next->next_stream_data;
    }

    if (start < length) {
        size_t data_length = length - start;

        if (next != NULL && next->offset < offset + length) {
            data_length -= (size_t)(offset + length - next->offset);
        }

        if (data_length > 0) {
            picoquic_stream_data* data = (picoquic_stream_data*)malloc(sizeof(picoquic_stream_data));

            if (data == NULL) {
                ret = picoquic_connection_error(cnx, PICOQUIC_ERROR_MEMORY, 0);
            }
            else {
                data->length = data_length;
                data->bytes = (uint8_t*)malloc(data_length);
                if (data->bytes == NULL) {
                    ret = picoquic_connection_error(cnx, PICOQUIC_ERROR_MEMORY, 0);
                    free(data);
                }
                else {
                    data->offset = offset + start;
                    memcpy(data->bytes, bytes + start, data_length);
                    data->next_stream_data = next;
                    *pprevious = data;
                    *new_data_available = 1;
                }
            }
        }
    }

    return ret;
}

static int picoquic_stream_network_input(picoquic_cnx_t* cnx, uint64_t stream_id,
    uint64_t offset, int fin, uint8_t* bytes, size_t length, uint64_t current_time)
{
    int ret = 0;
    uint64_t should_notify = 0;
    /* Is there such a stream, is it still open? */
    picoquic_stream_head* stream;
    uint64_t new_fin_offset = offset + length;

    if ((stream = picoquic_find_or_create_stream(cnx, stream_id, 1)) == NULL) {
        ret = 1;  // Error already signaled

    } else if ((stream->stream_flags & picoquic_stream_flag_fin_received) != 0) {

        if (fin != 0 ? stream->fin_offset != new_fin_offset : new_fin_offset > stream->fin_offset) {
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FINAL_SIZE_ERROR, 0);
        }

    } else {
        if (fin) {
            picoquic_add_stream_flags(cnx, stream, picoquic_stream_flag_fin_received);
            should_notify = 1;
            cnx->latest_progress_time = current_time;
        }

        if (new_fin_offset > stream->fin_offset) {
            ret = picoquic_flow_control_check_stream_offset(cnx, stream, new_fin_offset);
        }
    }

    if (ret == 0) {
        int new_data_available = 0;

        ret = picoquic_queue_network_input(cnx, stream, (size_t)offset, bytes, length, &new_data_available);

        if (new_data_available) {
            should_notify = 1;
            cnx->latest_progress_time = current_time;
        }
    }

    if (ret == 0 && should_notify != 0 && cnx->callback_fn != NULL) {
        /* check how much data there is to send */
        picoquic_stream_data_callback(cnx, stream);
    }

    return ret;
}

protoop_arg_t parse_stream_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    stream_frame_t *frame = malloc(sizeof(stream_frame_t));
    if (!frame) {
        printf("Failed to allocate memory for stream_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    size_t hdr_consumed = 0;
    if (picoquic_parse_stream_header(bytes, bytes_max - bytes, &frame->stream_id, &frame->offset, &frame->data_length, &frame->fin, &hdr_consumed) != 0)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, *((uint8_t *) cnx->protoop_inputv[0]));
        free(frame);
        frame = NULL;
    } else {
        frame->data_ptr = bytes + hdr_consumed;
        bytes += hdr_consumed + frame->data_length;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_stream_frame(picoquic_cnx_t* cnx)
{
    stream_frame_t *frame = (stream_frame_t *) cnx->protoop_inputv[0];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[1];

    if (picoquic_stream_network_input(cnx, frame->stream_id, frame->offset, frame->fin, frame->data_ptr, frame->data_length, current_time) != 0) {
        return 1;
    }

    return 0;
}

/**
 * See PROTOOP_NOPARAM_FIND_READY_STREAM
 */
protoop_arg_t find_ready_stream(picoquic_cnx_t *cnx) {
    picoquic_stream_head *stream = cnx->first_stream;

    if (cnx->maxdata_remote > cnx->data_sent) {
        while (stream) {
            if ((stream->send_queue != NULL && stream->send_queue->length > stream->send_queue->offset &&
                 stream->sent_offset < stream->maxdata_remote) ||
                (STREAM_SEND_FIN(stream) && (stream->sent_offset < stream->maxdata_remote) && !STREAM_FIN_SENT(stream)) ||
                (STREAM_SEND_RESET(stream) && !STREAM_RESET_SENT(stream)) ||
                (STREAM_SEND_STOP_SENDING(stream) && !STREAM_STOP_SENDING_SENT(stream) && !STREAM_FIN_RCVD(stream) && !STREAM_RESET_RCVD(stream)))
            {
                /* if the stream is not active yet, verify that it fits under
                 * the max stream id limit */
                /* Check parity */
                if (IS_CLIENT_STREAM_ID(stream->stream_id) == cnx->client_mode) {
                    if (stream->stream_id <= cnx->max_stream_id_bidir_remote) {
                        break;
                    }
                } else {
                    break;
                }
            }

            stream = stream->next_stream;

        }
    } else {
        if ((stream->send_queue == NULL ||
             stream->send_queue->length <= stream->send_queue->offset) &&
            (!STREAM_FIN_NOTIFIED(stream) || STREAM_FIN_SENT(stream)) &&
            (!STREAM_RESET_REQUESTED(stream) || STREAM_RESET_SENT(stream)) &&
            (!STREAM_STOP_SENDING_REQUESTED(stream) || STREAM_STOP_SENDING_SENT(stream))) {
            stream = NULL;
        }
    }

    return (protoop_arg_t) stream;
}

picoquic_stream_head* picoquic_find_ready_stream(picoquic_cnx_t* cnx)
{
    protoop_params_t pp = { .pid = &PROTOOP_NOPARAM_FIND_READY_STREAM, .inputc = 0, .inputv = NULL, .outputv = NULL, .caller_is_intern = true};
    return (picoquic_stream_head *) plugin_run_protoop_internal(cnx, &pp);
}

picoquic_stream_head* picoquic_schedule_next_stream(picoquic_cnx_t* cnx, size_t max_size, picoquic_path_t *path)
{
    return (picoquic_stream_head *) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_SCHEDULE_NEXT_STREAM, NULL, max_size, path);
}

/**
 * See PROTOOP_NOPARAM_FIND_READY_PLUGIN_STREAM
 */
protoop_arg_t find_ready_plugin_stream(picoquic_cnx_t *cnx)
{
    picoquic_stream_head* stream = cnx->first_plugin_stream;

    if (cnx->maxdata_remote > cnx->data_sent) {
        while (stream) {
            if ((stream->send_queue != NULL && stream->send_queue->length > stream->send_queue->offset &&
                  stream->sent_offset < stream->maxdata_remote) ||
                 (STREAM_SEND_FIN(stream) && (stream->sent_offset < stream->maxdata_remote)) ||
                STREAM_SEND_RESET(stream) || STREAM_SEND_STOP_SENDING(stream)) {
                /* Consider it is always ok */
                break;
            }

            stream = stream->next_stream;

        } ;
    } else {
        if (stream &&
            (stream->send_queue == NULL || stream->send_queue->length <= stream->send_queue->offset) &&
            (!STREAM_FIN_NOTIFIED(stream) || STREAM_FIN_SENT(stream)) &&
            (!STREAM_RESET_REQUESTED(stream) || STREAM_RESET_SENT(stream)) &&
            (!STREAM_STOP_SENDING_REQUESTED(stream) || STREAM_STOP_SENDING_SENT(stream))) {
            stream = NULL;
        }
    }

    return (protoop_arg_t) stream;
}

picoquic_stream_head* picoquic_find_ready_plugin_stream(picoquic_cnx_t* cnx)
{
    protoop_params_t pp = { .pid = &PROTOOP_NOPARAM_FIND_READY_PLUGIN_STREAM, .inputc = 0, .inputv = NULL, .outputv = NULL, .caller_is_intern = true};
    return (picoquic_stream_head *) plugin_run_protoop_internal(cnx, &pp);
}

protoop_arg_t stream_bytes_max(picoquic_cnx_t* cnx) {
    size_t bytes_max = (size_t) cnx->protoop_inputv[0];
    protoop_save_outputs(cnx, bytes_max);
    return 0;
}

protoop_arg_t stream_always_encode_length(picoquic_cnx_t* cnx) {
    protoop_save_outputs(cnx, false);
    return 0;
}

bool picoquic_stream_always_encode_length(picoquic_cnx_t* cnx)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_STREAM_ALWAYS_ENCODE_LENGTH, outs, NULL);
    return (bool) outs[0];
}

/**
 * See PROTOOP_NOPARAM_PREPARE_STREAM_FRAME
 */
protoop_arg_t prepare_stream_frame(picoquic_cnx_t* cnx)
{
    picoquic_stream_head* stream = (picoquic_stream_head*) cnx->protoop_inputv[0];
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[1];
    size_t bytes_max = (size_t) cnx->protoop_inputv[2];

    size_t consumed = 0;

    int ret = 0;

    if (STREAM_SEND_RESET(stream)) {
        ret = picoquic_prepare_stream_reset_frame(cnx, stream, bytes, bytes_max, &consumed);
        protoop_save_outputs(cnx, consumed);
        return ret;
    }

    if (STREAM_SEND_STOP_SENDING(stream)) {
        ret = picoquic_prepare_stop_sending_frame(cnx, stream, bytes, bytes_max, &consumed);
        protoop_save_outputs(cnx, consumed);
        return ret;
    }

    if ((stream->send_queue == NULL || stream->send_queue->length <= stream->send_queue->offset) &&
        (!STREAM_FIN_NOTIFIED(stream) || STREAM_FIN_SENT(stream))) {
        consumed = 0;
    } else {
        size_t byte_index = 0;
        size_t l_stream = 0;
        size_t l_off = 0;
        size_t length = 0;

        bytes[byte_index++] = picoquic_frame_type_stream_range_min;

        if (bytes_max > byte_index) {
            l_stream = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, stream->stream_id);
            byte_index += l_stream;
        }

        if (stream->sent_offset > 0 && bytes_max > byte_index) {
            bytes[0] |= 4; /* Indicates presence of offset */
            l_off = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, stream->sent_offset);
            byte_index += l_off;
        }

        if (byte_index > bytes_max || l_stream == 0 || (stream->sent_offset > 0 && l_off == 0)) {
            consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        } else {
            /* Compute the length */
            size_t space = bytes_max - byte_index;

            if (space < 2 || (stream->send_queue == NULL && !STREAM_SEND_FIN(stream))) {
                length = 0;
            } else {
                size_t available = stream->send_queue ? (size_t)(stream->send_queue->length - stream->send_queue->offset) : 0;

                length = available;

                /* Enforce maxdata per stream on all streams, including stream 0 */
                if (length >(stream->maxdata_remote - stream->sent_offset)) {
                    length = (size_t)(stream->maxdata_remote - stream->sent_offset);
                }

                /* Abide by flow control restrictions, stream 0 is exempt */
                if (stream->stream_id != 0) {
                    if (length > (cnx->maxdata_remote - cnx->data_sent)) {
                        length = (size_t)(cnx->maxdata_remote - cnx->data_sent);
                    }
                }

                if (!picoquic_stream_always_encode_length(cnx) && length >= space) {
                    length = space;
                } else {
                    /* This is going to be a trial and error process */
                    size_t l_len = 0;

                    /* Try a simple encoding */
                    bytes[0] |= 2; /* Indicates presence of length */
                    l_len = picoquic_varint_encode(bytes + byte_index, space,
                        (uint64_t)length);
                    if (l_len == 0 || (l_len == space && length > 0)) {
                        /* Will not try a silly encoding */
                        consumed = 0;
                        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                    } else if (length + l_len > space) {
                        /* try a shorter packet */
                        length = space - l_len;
                        l_len = picoquic_varint_encode(bytes + byte_index, space,
                            (uint64_t)length);
                        byte_index += l_len;
                    } else {
                        /* This is good */
                        byte_index += l_len;
                    }
                }
            }

            if (ret == 0 && length > 0) {
                memcpy(&bytes[byte_index], stream->send_queue->bytes + stream->send_queue->offset, length);
                byte_index += length;

                stream->send_queue->offset += length;
                if (stream->send_queue->offset >= stream->send_queue->length) {
                    picoquic_stream_data* next = stream->send_queue->next_stream_data;
                    free(stream->send_queue->bytes);
                    free(stream->send_queue);
                    stream->send_queue = next;
                }

                LOG_EVENT(cnx, "FRAMES", "STREAM_FRAME_CREATED", "", "{\"data_ptr\": \"%p\", \"stream_id\": %" PRIu64 ", \"offset\": %" PRIu64 ", \"length\": %" PRIu64 ", \"fin\": %d, \"queued_size\": %" PRIu64 "}", bytes, stream->stream_id, stream->sent_offset, length, STREAM_FIN_NOTIFIED(stream) && stream->send_queue == 0, stream->sending_offset - stream->sent_offset);

                stream->sent_offset += length;
                /* The client does not handle this correctly, so fix this at client side... */
                // if (stream->stream_id != 0) {
                    cnx->data_sent += length;
                //}
                consumed = byte_index;
            }

            if (ret == 0 && STREAM_FIN_NOTIFIED(stream) && stream->send_queue == 0) {
                /* Set the fin bit */
                picoquic_add_stream_flags(cnx, stream, picoquic_stream_flag_fin_sent);
                bytes[0] |= 1;
                consumed = byte_index;
            } else if (ret == 0 && length == 0) {
                /* No point in sending a silly packet */
                consumed = 0;
                ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
            }
        }
    }

    protoop_save_outputs(cnx, consumed);

    return (protoop_arg_t) ret;
}

int picoquic_prepare_stream_frame(picoquic_cnx_t* cnx, picoquic_stream_head* stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREPARE_STREAM_FRAME, outs,
        stream, bytes, bytes_max);
    *consumed = (protoop_arg_t) outs[0];
    return ret;
}

/**
 * See PROTOOP_NOPARAM_PREPARE_STREAM_FRAME
 */
protoop_arg_t prepare_plugin_frame(picoquic_cnx_t* cnx)
{
    picoquic_stream_head* plugin_stream = (picoquic_stream_head*) cnx->protoop_inputv[0];
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[1];
    size_t bytes_max = (size_t) cnx->protoop_inputv[2];

    size_t consumed = 0;

    int ret = 0;

    if ((plugin_stream->send_queue == NULL || plugin_stream->send_queue->length <= plugin_stream->send_queue->offset) &&
        (!STREAM_FIN_NOTIFIED(plugin_stream) || STREAM_FIN_SENT(plugin_stream))) {
        consumed = 0;
    } else {
        size_t byte_index = 0;
        size_t l_pid = 0;
        size_t l_off = 0;
        size_t length = 0;

        bytes[byte_index++] = picoquic_frame_type_plugin;

        /* If the FIN bit is set, we will put it after */
        bytes[byte_index++] = 0;


        if (bytes_max > byte_index) {
            /* PID ID */
            l_pid = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, plugin_stream->stream_id);
            byte_index += l_pid;
        }

        if (bytes_max > byte_index) {
            /* Offset */
            l_off = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, plugin_stream->sent_offset);
            byte_index += l_off;
        }

        if (byte_index > bytes_max || l_pid == 0 || (plugin_stream->sent_offset > 0 && l_off == 0)) {
            consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        } else {
            /* Compute the length */
            size_t space = bytes_max - byte_index;

            if (space < 2 || plugin_stream->send_queue == NULL) {
                length = 0;
            } else {
                size_t available = (size_t)(plugin_stream->send_queue->length - plugin_stream->send_queue->offset);

                length = available;

                /* Enforce maxdata per stream on all streams, including stream 0 */
                if (length >(plugin_stream->maxdata_remote - plugin_stream->sent_offset)) {
                    length = (size_t)(plugin_stream->maxdata_remote - plugin_stream->sent_offset);
                }

                /* Flow control restrictions */
                if (length > (cnx->maxdata_remote - cnx->data_sent)) {
                    length = (size_t)(cnx->maxdata_remote - cnx->data_sent);
                }

                /* This is going to be a trial and error process */
                size_t l_len = 0;

                /* Try a simple encoding */
                l_len = picoquic_varint_encode(bytes + byte_index, space,
                    (uint64_t)length);
                if (l_len == 0 || (l_len == space && length > 0)) {
                    /* Will not try a silly encoding */
                    consumed = 0;
                    ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                } else if (length + l_len > space) {
                    /* try a shorter packet */
                    length = space - l_len;
                    l_len = picoquic_varint_encode(bytes + byte_index, space,
                        (uint64_t)length);
                    byte_index += l_len;
                } else {
                    /* This is good */
                    byte_index += l_len;
                }
            }

            if (ret == 0 && length > 0) {
                memcpy(&bytes[byte_index], plugin_stream->send_queue->bytes + plugin_stream->send_queue->offset, length);
                byte_index += length;

                plugin_stream->send_queue->offset += length;
                if (plugin_stream->send_queue->offset >= plugin_stream->send_queue->length) {
                    picoquic_stream_data* next = plugin_stream->send_queue->next_stream_data;
                    free(plugin_stream->send_queue->bytes);
                    free(plugin_stream->send_queue);
                    plugin_stream->send_queue = next;
                }

                LOG_EVENT(cnx, "FRAMES", "PLUGIN_FRAME_CREATED", "", "{\"data_ptr\": \"%p\", \"pid_id\": %" PRIu64 ", \"offset\": %" PRIu64 ", \"length\": %" PRIu64 ", \"fin\": %d}", bytes, plugin_stream->stream_id, plugin_stream->sent_offset, length, STREAM_FIN_NOTIFIED(plugin_stream) && plugin_stream->send_queue == 0);

                plugin_stream->sent_offset += length;
                /* The client does not handle this correctly, so fix this at client side... */
                // if (stream->stream_id != 0) {
                    cnx->data_sent += length;
                //}
                consumed = byte_index;
            }

            if (ret == 0 && STREAM_FIN_NOTIFIED(plugin_stream) && plugin_stream->send_queue == 0) {
                /* Set the fin bit */
                picoquic_add_stream_flags(cnx, plugin_stream, picoquic_stream_flag_fin_sent);
                bytes[1] = 1;
            } else if (ret == 0 && length == 0) {
                /* No point in sending a silly packet */
                consumed = 0;
                ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
            }
        }
    }

    protoop_save_outputs(cnx, consumed);

    return (protoop_arg_t) ret;
}

int picoquic_prepare_plugin_frame(picoquic_cnx_t* cnx, picoquic_stream_head* plugin_stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREPARE_PLUGIN_FRAME, outs,
        plugin_stream, bytes, bytes_max);
    *consumed = (protoop_arg_t) outs[0];
    return ret;
}

size_t picoquic_stream_bytes_max(picoquic_cnx_t* cnx, size_t bytes_max, size_t header_length, uint8_t* bytes)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_STREAM_BYTES_MAX, outs,
        bytes_max, header_length, bytes);
    return (size_t) outs[0];
}

/*
 * Crypto HS frames
 */

/**
 * See PROTOOP_NOPARAM_IS_TLS_STREAM_READY
 */
protoop_arg_t is_tls_stream_ready(picoquic_cnx_t *cnx)
{
    int ret = 0;

    for (int epoch = 0; epoch < 4; epoch++) {
        picoquic_stream_head* stream = &cnx->tls_stream[epoch];

        if (stream->send_queue != NULL &&
            stream->send_queue->length > stream->send_queue->offset &&
            cnx->crypto_context[epoch].aead_encrypt != NULL) {
            ret = 1;
            break;
        }
    }

    return (protoop_arg_t) ret;
}

int picoquic_is_tls_stream_ready(picoquic_cnx_t* cnx)
{
    protoop_params_t pp = { .pid = &PROTOOP_NOPARAM_IS_TLS_STREAM_READY, .inputc = 0, .inputv = NULL, .outputv = NULL, .caller_is_intern = true};
    return (int) plugin_run_protoop_internal(cnx, &pp);
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_crypto_hs_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    crypto_frame_t *frame = malloc(sizeof(crypto_frame_t));
    if (!frame) {
        printf("Failed to allocate memory for stop_sending_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->offset)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes,   bytes_max, &frame->length)) == NULL )
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_crypto_hs);
        free(frame);
        frame = NULL;
    } else if ((uint64_t)(bytes_max - bytes) < frame->length) {
        DBG_PRINTF("crypto hs data past the end of the packet: data_length=%" PRIst ", remaining_space=%" PRIst, frame->length, bytes_max - bytes);
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_crypto_hs);
        free(frame);
        frame = NULL;
        bytes = NULL;
    } else {
        frame->crypto_data_ptr = bytes;
        bytes += frame->length;
    }
    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_crypto_hs_frame(picoquic_cnx_t* cnx)
{
    crypto_frame_t *frame = (crypto_frame_t *) cnx->protoop_inputv[0];
    int epoch = (int) cnx->protoop_inputv[2];

    int new_data_available;  // Unused

    if (picoquic_queue_network_input(cnx, &cnx->tls_stream[epoch], (size_t)frame->offset, frame->crypto_data_ptr, (size_t)frame->length, &new_data_available) != 0) {
        return 1;  // Error signaled
    }

    return 0;
}

protoop_arg_t parse_handshake_done_frame(picoquic_cnx_t* cnx) {
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    hanshake_done_frame_t *frame = malloc(sizeof(hanshake_done_frame_t));
    if (!frame) {
        printf("Failed to allocate memory for hanshake_done_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes + picoquic_varint_skip(bytes);
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_handshake_done_frame(picoquic_cnx_t* cnx)
{
    uint64_t current_time = picoquic_current_time();
    if (cnx->client_mode) {
        cnx->handshake_done = 1;
        for (int i = 0; i < cnx->nb_paths; i++) {
            picoquic_path_t *path = cnx->path[i];
            picoquic_implicit_handshake_ack(cnx, path, picoquic_packet_context_initial, current_time);
            picoquic_implicit_handshake_ack(cnx, path, picoquic_packet_context_handshake, current_time);
        }
    }
    return 0;
}

/**
 * See PROTOOP_PARAM_DECODE_FRAME
 */
protoop_arg_t decode_crypto_hs_frame(picoquic_cnx_t *cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (const uint8_t *) cnx->protoop_inputv[1];
    int epoch = (int) cnx->protoop_inputv[3];
    int ack_needed = (int) cnx->protoop_inputv[4];

    uint64_t offset;
    uint64_t data_length;
    int      new_data_available;  // Unused

    ack_needed = 1;

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &offset)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes,   bytes_max, &data_length)) == NULL )
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_crypto_hs);

    } else if ((uint64_t)(bytes_max - bytes) < data_length) {
        DBG_PRINTF("crypto hs data past the end of the packet: data_length=%" PRIst ", remaining_space=%" PRIst, data_length, bytes_max - bytes);
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_crypto_hs);
        bytes = NULL;

    } else if (picoquic_queue_network_input(cnx, &cnx->tls_stream[epoch], (size_t)offset, bytes, (size_t)data_length, &new_data_available) != 0) {
        bytes = NULL;  // Error signaled

    } else {
        bytes += data_length;
    }

    protoop_save_outputs(cnx, ack_needed);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_NOPARAM_PREPARE_CRYPTO_HS_FRAME
 */
protoop_arg_t prepare_crypto_hs_frame(picoquic_cnx_t *cnx)
{
    int epoch = (int) cnx->protoop_inputv[0];
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[1];
    size_t bytes_max = (size_t) cnx->protoop_inputv[2];

    size_t consumed = 0;

    int ret = 0;
    picoquic_stream_head* stream = &cnx->tls_stream[epoch];

    if ((stream->send_queue == NULL || stream->send_queue->length <= stream->send_queue->offset) && ((stream->stream_flags & picoquic_stream_flag_fin_notified) == 0 || (stream->stream_flags & picoquic_stream_flag_fin_sent) != 0)) {
        consumed = 0;
    } else {
        size_t byte_index = 0;
        size_t l_off = 0;
        size_t length = 0;

        bytes[byte_index++] = picoquic_frame_type_crypto_hs;

        if (bytes_max > byte_index) {
            l_off = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, stream->sent_offset);
            byte_index += l_off;
        }

        if (byte_index > bytes_max || (stream->sent_offset > 0 && l_off == 0)) {
            consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        }
        else {
            /* Compute the length */
            size_t space = bytes_max - byte_index;

            /* TODO: check logic here -- I was tired when I wrote that */

            if (space < 2 || stream->send_queue == NULL) {
                length = 0;
            } else {
                /* This is going to be a trial and error process */
                size_t l_len = 0;
                size_t available = stream->send_queue->length - (size_t)stream->send_queue->offset;

                length = available;
                /* Trial encoding */
                l_len = picoquic_varint_encode(bytes + byte_index, space,
                    (uint64_t)length);

                if (length + l_len >= space) {
                    if (space < l_len) {
                        /* Will not try a silly encoding */
                        consumed = 0;
                        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                    }
                    else {
                        /* New encoding with appropriate length */
                        length = space - l_len;
                        l_len = picoquic_varint_encode(bytes + byte_index, space,
                            (uint64_t)length);
                    }
                }
                /* This is good */
                byte_index += l_len;
            }

            if (ret == 0 && length > 0) {
                memcpy(&bytes[byte_index], stream->send_queue->bytes + stream->send_queue->offset, length);
                byte_index += length;

                stream->send_queue->offset += length;
                if (stream->send_queue->offset >= stream->send_queue->length) {
                    picoquic_stream_data* next = stream->send_queue->next_stream_data;
                    free(stream->send_queue->bytes);
                    free(stream->send_queue);
                    stream->send_queue = next;
                }

                LOG_EVENT(cnx, "FRAMES", "CRYPTO_FRAME_CREATED", "", "{\"data_ptr\": \"%p\", \"offset\": %" PRIu64 ", \"length\": %" PRIu64 "}", bytes, stream->sent_offset, length);
                stream->sent_offset += length;
                consumed = byte_index;
            } else if (ret == 0 && length == 0) {
                /* No point in sending a silly packet */
                consumed = 0;
                ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
            }
        }
    }

    protoop_save_outputs(cnx, consumed);

    return (protoop_arg_t) ret;
}

int picoquic_prepare_crypto_hs_frame(picoquic_cnx_t* cnx, int epoch,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREPARE_CRYPTO_HS_FRAME, outs,
        epoch, bytes, bytes_max);
    *consumed = (size_t) outs[0];
    return ret;
}

protoop_arg_t prepare_handshake_done_frame(picoquic_cnx_t* cnx) {
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    size_t bytes_max = (size_t) cnx->protoop_inputv[1];
    size_t consumed = 0;

    if (bytes_max > 0) {
        *bytes = picoquic_frame_type_handshake_done;
        consumed++;
    }

    protoop_save_outputs(cnx, consumed);
    return 0;
}

int picoquic_prepare_handshake_done_frame(picoquic_cnx_t* cnx, uint8_t* bytes, size_t bytes_max, size_t* consumed) {
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREPARE_HANDSHAKE_DONE_FRAME, outs, bytes, bytes_max);
    *consumed = (size_t) outs[0];
    return ret;
}

/*
 * ACK Frames
 */

int picoquic_parse_ack_header(uint8_t const* bytes, size_t bytes_max,
    uint64_t* num_block, uint64_t* nb_ecnx3,
    uint64_t* largest, uint64_t* ack_delay, size_t* consumed,
    uint8_t ack_delay_exponent)
{
    int ret = 0;
    size_t byte_index = 1;
    size_t l_largest = 0;
    size_t l_delay = 0;
    size_t l_blocks = 0;

    if (bytes_max > byte_index) {
        l_largest = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, largest);
        byte_index += l_largest;
    }

    if (bytes_max > byte_index) {
        l_delay = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, ack_delay);
        *ack_delay <<= ack_delay_exponent;
        byte_index += l_delay;
    }

    if (nb_ecnx3 != NULL) {
        for (int ecnx = 0; ecnx < 3; ecnx++) {
            size_t l_ecnx = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &nb_ecnx3[ecnx]);

            if (l_ecnx == 0) {
                byte_index = bytes_max;
            }
            else {
                byte_index += l_ecnx;
            }
        }
    }

    if (bytes_max > byte_index) {
        l_blocks = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, num_block);
        byte_index += l_blocks;
    }

    if (l_largest == 0 || l_delay == 0 || l_blocks == 0 || bytes_max < byte_index) {
        DBG_PRINTF("ack frame fixed header too large: first_byte=0x%02x, bytes_max=%" PRIst,
            bytes[0], bytes_max);
        byte_index = bytes_max;
        ret = -1;
    }

    *consumed = byte_index;
    return ret;
}

/**
 * See PROTOOP_NOPARAM_CHECK_SPURIOUS_RETRANSMISSION
 */
protoop_arg_t check_spurious_retransmission(picoquic_cnx_t *cnx)
{
    uint64_t start_of_range = (uint64_t) cnx->protoop_inputv[0];
    uint64_t end_of_range = (uint64_t) cnx->protoop_inputv[1];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[2];
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) cnx->protoop_inputv[3];
    picoquic_path_t* path_x = (picoquic_path_t*) cnx->protoop_inputv[4];

    picoquic_packet_context_t * pkt_ctx = (picoquic_packet_context_t *) &path_x->pkt_ctx[pc];
    picoquic_packet_t* p = pkt_ctx->retransmitted_newest;

    while (p != NULL) {
        picoquic_packet_t* should_delete = NULL;

        if (p->sequence_number >= start_of_range && p->sequence_number <= end_of_range) {

            uint64_t max_spurious_rtt = current_time - p->send_time;
            uint64_t max_reorder_delay = pkt_ctx->latest_time_acknowledged - p->send_time;
            uint64_t max_reorder_gap = pkt_ctx->highest_acknowledged - p->sequence_number;
            picoquic_path_t * old_path = p->send_path;

            if (old_path != NULL) {
                if (p->length + p->checksum_overhead > old_path->send_mtu) {
                    old_path->send_mtu = (uint32_t)(p->length + p->checksum_overhead);
                    if (old_path->send_mtu > old_path->send_mtu_max_tried) {
                        old_path->send_mtu_max_tried = old_path->send_mtu;
                    }
                    old_path->mtu_probe_sent = 0;
                }

                if (max_spurious_rtt > old_path->max_spurious_rtt) {
                    old_path->max_spurious_rtt = max_spurious_rtt;
                }

                if (max_reorder_delay > old_path->max_reorder_delay) {
                    old_path->max_reorder_delay = max_reorder_delay;
                }

                if (max_reorder_gap > old_path->max_reorder_gap) {
                    old_path->max_reorder_gap = max_reorder_gap;
                }

                if (cnx->congestion_alg != NULL ) {
                    picoquic_congestion_algorithm_notify_func(cnx, old_path, picoquic_congestion_notification_spurious_repeat,
                        0, 0, p->sequence_number, current_time);
                }
            }

            cnx->nb_spurious++;
            should_delete = p;
        } else if (p->send_time + PICOQUIC_SPURIOUS_RETRANSMIT_DELAY_MAX < pkt_ctx->latest_time_acknowledged) {
            should_delete = p;
        }

        p = p->next_packet;

        if (should_delete != NULL) {
            picoquic_dequeue_retransmitted_packet(cnx, should_delete);
        }
    }

    return 0;
}


void picoquic_check_spurious_retransmission(picoquic_cnx_t* cnx,
    uint64_t start_of_range, uint64_t end_of_range, uint64_t current_time,
    picoquic_packet_context_enum pc, picoquic_path_t* path_x)
{
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_CHECK_SPURIOUS_RETRANSMISSION, NULL,
        start_of_range, end_of_range, current_time, pc, path_x);
}

protoop_arg_t update_ack_delay(picoquic_cnx_t* cnx) {
    picoquic_packet_context_t* pkt_ctx = (picoquic_packet_context_t *) cnx->protoop_inputv[0];
    picoquic_path_t* old_path = (picoquic_path_t *) cnx->protoop_inputv[1];
    int64_t rtt_estimate = (int64_t) cnx->protoop_inputv[2];
    bool first_estimate = (bool) cnx->protoop_inputv[3];
    pkt_ctx->ack_delay_local = old_path->rtt_min / 4;
    if (pkt_ctx->ack_delay_local < 1000) {
        pkt_ctx->ack_delay_local = 1000;
    } else if (!first_estimate && pkt_ctx->ack_delay_local > 10000) {
        pkt_ctx->ack_delay_local = 10000;
    }
    return 0;
}

static void picoquic_update_ack_delay(picoquic_cnx_t *cnx, picoquic_packet_context_t* pkt_ctx, picoquic_path_t* old_path, int64_t rtt_estimate, bool first_estimate) {
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_UPDATE_ACK_DELAY, NULL, pkt_ctx, old_path, rtt_estimate, first_estimate);
}

protoop_arg_t estimate_path_bandwidth(picoquic_cnx_t *cnx)
{
    picoquic_path_t *path_x = (picoquic_path_t *) cnx->protoop_inputv[0];
    uint64_t send_time = cnx->protoop_inputv[1];
    uint64_t delivered_prior = cnx->protoop_inputv[2];
    uint64_t delivered_time_prior = cnx->protoop_inputv[3];
    uint64_t delivered_sent_prior = cnx->protoop_inputv[4];
    uint64_t delivery_time = cnx->protoop_inputv[5];
    uint64_t current_time = cnx->protoop_inputv[6];
    int rs_is_path_limited = cnx->protoop_inputv[7];

    if (send_time >= path_x->delivered_sent_last) {
        if (path_x->delivered_time_last == 0) {
            /* No estimate yet, need to initialize the variables */
            path_x->delivered_last = current_time;
            path_x->delivered_time_last = path_x->delivered;
            path_x->delivered_sent_last = send_time;
        }
        else {
            uint64_t receive_interval = delivery_time - delivered_time_prior;

            if (receive_interval > PICOQUIC_BANDWIDTH_TIME_INTERVAL_MIN) {
                uint64_t delivered = path_x->delivered - delivered_prior;
                uint64_t send_interval = send_time - delivered_sent_prior;
                uint64_t bw_estimate;

                if (send_interval > receive_interval) {
                    receive_interval = send_interval;
                }

                if (receive_interval == 0) {
                    bw_estimate = PICOQUIC_BANDWIDTH_ESTIMATE_MAX;
                }
                else {
                    bw_estimate = delivered * 1000000;
                    bw_estimate /= receive_interval;
                }

                if (!rs_is_path_limited || bw_estimate > path_x->bandwidth_estimate) {
                    path_x->bandwidth_estimate = bw_estimate;
                }

                /* Bandwidth was estimated, update the references */
                path_x->delivered_last = path_x->delivered;
                path_x->delivered_time_last = delivery_time;
                path_x->delivered_sent_last = send_time;
                path_x->delivered_last_packet = delivered_prior;
                path_x->last_bw_estimate_path_limited = rs_is_path_limited;
                if (path_x->delivered > path_x->delivered_limited_index) {
                    path_x->delivered_limited_index = 0;
                }
            }
        }
    }

    return 0;
}

void picoquic_estimate_path_bandwidth(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t send_time,
    uint64_t delivered_prior, uint64_t delivered_time_prior, uint64_t delivered_sent_prior,
    uint64_t delivery_time, uint64_t current_time, int rs_is_path_limited) {
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_ESTIMATE_PATH_BANDWIDTH, NULL, path_x, send_time, delivered_prior, delivered_time_prior, delivered_sent_prior, delivery_time, current_time, rs_is_path_limited);
}

/**
 * See PROTOOP_NOPARAM_UPDATE_RTT
 */
protoop_arg_t update_rtt(picoquic_cnx_t *cnx)
{
    uint64_t largest = (uint64_t) cnx->protoop_inputv[0];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[1];
    uint64_t ack_delay = (uint64_t) cnx->protoop_inputv[2];
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) cnx->protoop_inputv[3];
    picoquic_path_t* path_x = (picoquic_path_t *) cnx->protoop_inputv[4];

    int is_new_ack = 0;

    picoquic_packet_context_t * pkt_ctx = &path_x->pkt_ctx[pc];
    picoquic_packet_t* packet = pkt_ctx->retransmit_newest;

    /* Check whether this is a new acknowledgement */
    if (largest > pkt_ctx->highest_acknowledged || pkt_ctx->first_sack_item.start_of_sack_range == (uint64_t)((int64_t)-1) ||
        pkt_ctx->highest_acknowledged == (uint64_t)((int64_t)-1)) { /* This last condition is for Multipath ! */
        pkt_ctx->highest_acknowledged = largest;
        is_new_ack = 1;

        if (ack_delay < PICOQUIC_ACK_DELAY_MAX) {
            /* if the ACK is reasonably recent, use it to update the RTT */
            /* find the stored copy of the largest acknowledged packet */

            while (packet != NULL && packet->sequence_number > largest) {
                packet = packet->next_packet;
            }

            if (packet == NULL || packet->sequence_number < largest) {
                /* There is no copy of this packet in store. It may have
                 * been deleted because too old, or maybe already
                 * retransmitted */
            } else {
                uint64_t acknowledged_time = current_time - ack_delay;
                int64_t rtt_estimate = acknowledged_time - packet->send_time;

                if (pkt_ctx->latest_time_acknowledged < packet->send_time) {
                    pkt_ctx->latest_time_acknowledged = packet->send_time;
                }
                cnx->latest_progress_time = current_time;

                if (rtt_estimate > 0) {
                    picoquic_path_t * old_path = packet->send_path;

                    if (ack_delay > old_path->max_ack_delay) {
                        old_path->max_ack_delay = ack_delay;
                    }

                    if (old_path->smoothed_rtt == PICOQUIC_INITIAL_RTT && old_path->rtt_variant == 0) {
                        old_path->smoothed_rtt = rtt_estimate;
                        old_path->rtt_variant = rtt_estimate / 2;
                        old_path->rtt_min = rtt_estimate;
                        old_path->retransmit_timer = 3 * rtt_estimate + old_path->max_ack_delay;
                        picoquic_update_ack_delay(cnx, pkt_ctx, old_path, rtt_estimate, true);
                    } else {
                        /* Computation per RFC 6298 */
                        int64_t delta_rtt = rtt_estimate - old_path->smoothed_rtt;
                        int64_t delta_rtt_average = 0;
                        old_path->smoothed_rtt += delta_rtt / 8;

                        if (delta_rtt < 0) {
                            delta_rtt_average = (-delta_rtt) - old_path->rtt_variant;
                        } else {
                            delta_rtt_average = delta_rtt - old_path->rtt_variant;
                        }
                        old_path->rtt_variant += delta_rtt_average / 4;

                        if (rtt_estimate < (int64_t)old_path->rtt_min) {
                            old_path->rtt_min = rtt_estimate;
                            picoquic_update_ack_delay(cnx, pkt_ctx, old_path, rtt_estimate, false);
                        }

                        if (4 * old_path->rtt_variant < old_path->rtt_min) {
                            old_path->rtt_variant = old_path->rtt_min / 4;
                        }

                        old_path->retransmit_timer = old_path->smoothed_rtt + 4 * old_path->rtt_variant + old_path->max_ack_delay;
                    }
                    old_path->rtt_sample = rtt_estimate;

                    if (PICOQUIC_MIN_RETRANSMIT_TIMER > old_path->retransmit_timer) {
                        old_path->retransmit_timer = PICOQUIC_MIN_RETRANSMIT_TIMER;
                    }

                    if (cnx->congestion_alg != NULL) {
                        picoquic_congestion_algorithm_notify_func(cnx, old_path,
                            picoquic_congestion_notification_rtt_measurement,
                            rtt_estimate, 0, 0, current_time);
                    }
                }
            }
        }
    }

    protoop_save_outputs(cnx, is_new_ack);
    return (protoop_arg_t) packet;
}

static picoquic_packet_t* picoquic_update_rtt(picoquic_cnx_t* cnx, uint64_t largest,
    uint64_t current_time, uint64_t ack_delay, picoquic_packet_context_enum pc, picoquic_path_t* path_x, int *is_new_ack)
{
    protoop_arg_t outs[1];
    picoquic_packet_t *p = (picoquic_packet_t *) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_UPDATE_RTT, outs,
        largest, current_time, ack_delay, pc, path_x);
    if (is_new_ack) {
        *is_new_ack = outs[0];
    }
    return p;
}

/**
 * See PROTOOP_NOPARAM_PROCESS_ACK_OF_ACK_RANGE
 */
static protoop_arg_t process_ack_of_ack_range(picoquic_cnx_t * cnx)
{
    picoquic_sack_item_t* first_sack = (picoquic_sack_item_t*) cnx->protoop_inputv[0];
    uint64_t start_of_range = (uint64_t) cnx->protoop_inputv[1];
    uint64_t end_of_range = (uint64_t) cnx->protoop_inputv[2];

    if (first_sack->start_of_sack_range == start_of_range) {
        if (end_of_range < first_sack->end_of_sack_range) {
            first_sack->start_of_sack_range = end_of_range + 1;
        } else {
            first_sack->start_of_sack_range = first_sack->end_of_sack_range;
        }
    } else {
        picoquic_sack_item_t* previous = first_sack;
        picoquic_sack_item_t* next = previous->next_sack;

        while (next != NULL) {
            if (next->end_of_sack_range == end_of_range && next->start_of_sack_range == start_of_range) {
                /* Matching range should be removed */
                previous->next_sack = next->next_sack;
                free(next);
                break;
            } else if (next->end_of_sack_range > end_of_range) {
                previous = next;
                next = next->next_sack;
            } else {
                break;
            }
        }
    }

    return 0;
}

static void picoquic_process_ack_of_ack_range(picoquic_cnx_t * cnx, picoquic_sack_item_t* first_sack,
    uint64_t start_of_range, uint64_t end_of_range)
{
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PROCESS_ACK_OF_ACK_RANGE, NULL,
        first_sack, start_of_range, end_of_range);
}

int picoquic_process_ack_of_ack_frame(
    picoquic_cnx_t* cnx,
    picoquic_sack_item_t* first_sack,
    uint8_t* bytes, size_t bytes_max, size_t* consumed, int is_ecn)
{
    int ret;
    uint64_t largest;
    uint64_t ack_delay;
    uint64_t num_block;
    uint64_t ecnx3[3];

    /* Find the oldest ACK range, in order to calibrate the
     * extension of the largest number to 64 bits */

    picoquic_sack_item_t* target_sack = first_sack;
    while (target_sack->next_sack != NULL) {
        target_sack = target_sack->next_sack;
    }

    ret = picoquic_parse_ack_header(bytes, bytes_max,
        &num_block, (is_ecn)? ecnx3 : NULL,
        &largest, &ack_delay, consumed, 0);

    if (ret == 0) {
        size_t byte_index = *consumed;

        /* Process each successive range */

        while (1) {
            uint64_t range;
            size_t l_range;
            uint64_t block_to_block;

            if (byte_index >= bytes_max) {
                ret = -1;
                break;
            }

            l_range = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &range);
            if (l_range == 0) {
                byte_index = bytes_max;
                ret = -1;
                break;
            } else {
                byte_index += l_range;
            }

            range++;
            if (largest + 1 < range) {
                DBG_PRINTF("ack range error: largest=%" PRIx64 ", range=%" PRIx64, largest, range);
                ret = -1;
                break;
            }

            if (range > 0) {
                picoquic_process_ack_of_ack_range(cnx, first_sack, largest + 1 - range, largest);
            }

            if (num_block-- == 0)
                break;

            /* Skip the gap */

            if (byte_index >= bytes_max) {
                ret = -1;
                break;
            } else {
                size_t l_gap = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &block_to_block);
                if (l_gap == 0) {
                    byte_index = bytes_max;
                    ret = -1;
                    break;
                } else {
                    byte_index += l_gap;
                    block_to_block += 1; /* Add 1, since there are never 0 gaps -- see spec. */
                    block_to_block += range;
                }
            }

            if (largest < block_to_block) {
                DBG_PRINTF("ack gap error: largest=%" PRIx64 ", range=%" PRIx64 ", gap=%" PRIu64,
                    largest, range, block_to_block - range);
                ret = -1;
                break;
            }

            largest -= block_to_block;
        }

        *consumed = byte_index;
    }

    return ret;
}

/**
 * See PROTOOP_NOPARAM_CHECK_STREAM_FRAME_ALREADY_ACKED
 */
protoop_arg_t check_stream_frame_already_acked(picoquic_cnx_t *cnx)
{
    uint8_t* bytes = (uint8_t*) cnx->protoop_inputv[0];
    size_t bytes_max = (size_t) cnx->protoop_inputv[1];
    int no_need_to_repeat = (int) cnx->protoop_inputv[2];

    int ret = 0;
    int fin;
    size_t data_length;
    uint64_t stream_id;
    uint64_t offset;
    picoquic_stream_head* stream = NULL;
    size_t consumed = 0;

    no_need_to_repeat = 0;

    if (PICOQUIC_IN_RANGE(bytes[0], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
        ret = picoquic_parse_stream_header(bytes, bytes_max,
            &stream_id, &offset, &data_length, &fin, &consumed);

        if (ret == 0) {
            stream = picoquic_find_stream(cnx, stream_id, 0);
            if (stream == NULL) {
                /* this is weird -- the stream was destroyed. */
                no_need_to_repeat = 1;
            } else {
                if ((stream->stream_flags & picoquic_stream_flag_reset_sent) != 0) {
                    no_need_to_repeat = 1;
                } else {
                    /* Check whether the ack was already received */
                    no_need_to_repeat = picoquic_check_sack_list(&stream->first_sack_item, offset, offset + data_length);
                }
            }
        }
    }

    protoop_save_outputs(cnx, no_need_to_repeat);
    return ret;
}

int picoquic_check_stream_frame_already_acked(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max, int* no_need_to_repeat)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_CHECK_STREAM_FRAME_ALREADY_ACKED, outs,
        bytes, bytes_max, *no_need_to_repeat);
    *no_need_to_repeat = (int) outs[0];
    return ret;
}

/**
 * See PROTOOP_NOPARAM_PROCESS_ACK_OF_STREAM_FRAME
 */
protoop_arg_t process_ack_of_stream_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t*) cnx->protoop_inputv[0];
    size_t bytes_max = (size_t) cnx->protoop_inputv[1];
    size_t consumed = (size_t) cnx->protoop_inputv[2];

    int ret;
    int fin;
    size_t data_length;
    uint64_t stream_id;
    uint64_t offset;
    picoquic_stream_head* stream = NULL;

    /* skip stream frame */
    ret = picoquic_parse_stream_header(bytes, bytes_max,
        &stream_id, &offset, &data_length, &fin, &consumed);

    if (ret == 0) {
        consumed += data_length;

        /* record the ack range for the stream */
        stream = picoquic_find_stream(cnx, stream_id, 0);
        if (stream != NULL) {
            (void)picoquic_update_sack_list(cnx, &stream->first_sack_item,
                offset, offset + data_length - 1);
        }
    }

    protoop_save_outputs(cnx, consumed);

    return (protoop_arg_t) ret;
}

static int picoquic_process_ack_of_stream_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PROCESS_ACK_OF_STREAM_FRAME, outs,
        bytes, bytes_max, *consumed);
    *consumed = (size_t) outs[0];
    return ret;
}

/**
 * See PROTOOP_NOPARAM_PROCESS_POSSIBLE_ACK_OF_ACK_FRAME
 */
protoop_arg_t process_possible_ack_of_ack_frame(picoquic_cnx_t* cnx)
{
    picoquic_packet_t* p = (picoquic_packet_t*) cnx->protoop_inputv[0];

    int ret = 0;
    size_t byte_index;
    int frame_is_pure_ack = 0;
    size_t frame_length = 0;

    if (ret == 0 && p->ptype == picoquic_packet_0rtt_protected) {
        cnx->nb_zero_rtt_acked++;
    }

    byte_index = p->offset;

    while (ret == 0 && byte_index < p->length) {
        if (p->bytes[byte_index] == picoquic_frame_type_ack) {
            ret = picoquic_process_ack_of_ack_frame(cnx, &p->send_path->pkt_ctx[p->pc].first_sack_item,
                &p->bytes[byte_index], p->length - byte_index, &frame_length, 0);
            byte_index += frame_length;
        } else if (p->bytes[byte_index] == picoquic_frame_type_ack_ecn) {
            ret = picoquic_process_ack_of_ack_frame(cnx, &p->send_path->pkt_ctx[p->pc].first_sack_item,
                &p->bytes[byte_index], p->length - byte_index, &frame_length, 1);
            byte_index += frame_length;
        } else if (PICOQUIC_IN_RANGE(p->bytes[byte_index], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            ret = picoquic_process_ack_of_stream_frame(cnx, &p->bytes[byte_index], p->length - byte_index, &frame_length);
            byte_index += frame_length;
        } else {
            ret = picoquic_skip_frame(cnx, &p->bytes[byte_index],
                p->length - byte_index, &frame_length, &frame_is_pure_ack);
            byte_index += frame_length;
        }
    }

    return 0;
}

void picoquic_process_possible_ack_of_ack_frame(picoquic_cnx_t* cnx, picoquic_packet_t* p)
{
    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PROCESS_POSSIBLE_ACK_OF_ACK_FRAME, NULL,
        p);
}

/**
 * See PROTOOP_NOPARAM_PROCESS_ACK_RANGE
 */
protoop_arg_t process_ack_range(picoquic_cnx_t *cnx)
{
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) cnx->protoop_inputv[0];
    uint64_t highest = (uint64_t) cnx->protoop_inputv[1];
    uint64_t range = (uint64_t) cnx->protoop_inputv[2];
    picoquic_packet_t* ppacket = (picoquic_packet_t*) cnx->protoop_inputv[3];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[4];

    picoquic_packet_t* p = ppacket;
    int ret = 0;
    /* Compare the range to the retransmit queue */
    while (p != NULL && range > 0) {
        if (p->sequence_number > highest) {
            p = p->next_packet;
        } else {
            if (p->sequence_number == highest) {
                /* TODO: RTT Estimate */
                picoquic_packet_t* next = p->next_packet;
                picoquic_path_t * old_path = p->send_path;

                old_path->delivered += p->length;
                if (cnx->congestion_alg != NULL) {
                    picoquic_congestion_algorithm_notify_func(cnx, old_path,
                        picoquic_congestion_notification_acknowledgement,
                        0, p->length, 0, current_time);
                }

                /* If the packet contained an ACK frame, perform the ACK of ACK pruning logic */
                picoquic_process_possible_ack_of_ack_frame(cnx, p);

                /* If packet is larger than the current MTU, update the MTU */
                if ((p->length + p->checksum_overhead) > old_path->send_mtu) {
                    old_path->send_mtu = (uint32_t)(p->length + p->checksum_overhead);
                    old_path->mtu_probe_sent = 0;
                }

                /* Any acknowledgement shows progress */
                p->send_path->pkt_ctx[pc].nb_retransmit = 0;
                p->send_path->pkt_ctx[pc].latest_progress_time = current_time;

                if (p->has_handshake_done) {
                    cnx->handshake_done_acked = 1;
                }

                picoquic_dequeue_retransmit_packet(cnx, p, 1);
                p = next;
            }

            range--;
            highest--;
        }
    }

    ppacket = p;

    protoop_save_outputs(cnx, ppacket);

    return (protoop_arg_t) ret;
}

static int picoquic_process_ack_range(
    picoquic_cnx_t* cnx, picoquic_packet_context_enum pc, uint64_t highest, uint64_t range, picoquic_packet_t** ppacket,
    uint64_t current_time)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PROCESS_ACK_RANGE, outs,
        pc, highest, range, *ppacket, current_time);
    *ppacket = (picoquic_packet_t*) outs[0];
    return ret;
}

protoop_arg_t parse_ack_frame_maybe_ecn(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 0;
    int is_retransmittable = 0;
    ack_frame_t *frame = malloc(sizeof(ack_frame_t));
    if (!frame) {
        printf("Failed to allocate memory for ack_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    uint64_t frame_type;
    bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_type);
    frame->is_ack_ecn = frame_type == picoquic_frame_type_ack_ecn ? 1 : 0;

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->largest_acknowledged)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack_delay)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            frame->is_ack_ecn ? picoquic_frame_type_ack_ecn : picoquic_frame_type_ack);
        free(frame);
        frame = NULL;
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack_block_count)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            frame->is_ack_ecn ? picoquic_frame_type_ack_ecn : picoquic_frame_type_ack);
        free(frame);
        frame = NULL;
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    /** \todo FIXME */
    if (frame->ack_block_count > 63) {
        printf("ACK frame parsing error: does not support ack_blocks > 63 elements\n");
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            frame->is_ack_ecn ? picoquic_frame_type_ack_ecn : picoquic_frame_type_ack);
        free(frame);
        frame = NULL;
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->first_ack_block)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            frame->is_ack_ecn ? picoquic_frame_type_ack_ecn : picoquic_frame_type_ack);
        free(frame);
        frame = NULL;
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    for (int i = 0; i < frame->ack_block_count; i++) {
        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack_blocks[i].gap)) == NULL ||
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ack_blocks[i].additional_ack_block)) == NULL)
        {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
                frame->is_ack_ecn ? picoquic_frame_type_ack_ecn : picoquic_frame_type_ack);
            free(frame);
            frame = NULL;
            protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
            return (protoop_arg_t) NULL;
        }
    }

    if (frame->is_ack_ecn) {
        for (int ecnx = 0; bytes && ecnx < 3; ecnx++) {
            bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->ecnx3[ecnx]);
        }
        if (bytes == NULL) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
                                      frame->is_ack_ecn ? picoquic_frame_type_ack_ecn : picoquic_frame_type_ack);
            free(frame);
            frame = NULL;
            protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
            return (protoop_arg_t) NULL;
        }
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

protoop_arg_t process_ack_frame_maybe_ecn(picoquic_cnx_t* cnx)
{
    ack_frame_t *frame = (ack_frame_t *) cnx->protoop_inputv[0];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[1];
    int epoch = (int) cnx->protoop_inputv[2];

    picoquic_path_t* path_x = cnx->path[0];
    picoquic_packet_context_enum pc = picoquic_context_from_epoch(epoch);
    uint8_t first_byte = (frame->is_ack_ecn) ? picoquic_frame_type_ack_ecn : picoquic_frame_type_ack;

    if (epoch == 1) {
        if (frame->is_ack_ecn) {
            DBG_PRINTF("Ack-ECN frame (0x%x) not expected in 0-RTT packet", first_byte);
        } else {
            DBG_PRINTF("Ack frame (0x%x) not expected in 0-RTT packet", first_byte);
        }
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, first_byte);
        return 1;
    } else if (frame->largest_acknowledged >= path_x->pkt_ctx[pc].send_sequence) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, first_byte);
        return 1;
    } else {
        if (frame->is_ack_ecn) {
            cnx->ecn_ect0_total_remote = frame->ecnx3[0];
            cnx->ecn_ect1_total_remote = frame->ecnx3[1];
            cnx->ecn_ce_total_remote = frame->ecnx3[2];
        }

        /* Attempt to update the RTT */
        int is_new_ack = 0;
        picoquic_packet_t* top_packet = picoquic_update_rtt(cnx, frame->largest_acknowledged, current_time, frame->ack_delay, pc, path_x, &is_new_ack);
        uint64_t largest_sent_time = 0;
        uint64_t delivered_prior = 0;
        uint64_t delivered_time_prior = 0;
        uint64_t delivered_sent_prior = 0;
        picoquic_path_t* old_path = NULL;
        int rs_is_path_limited = 0;

        if (top_packet != NULL) {
            old_path = top_packet->send_path;
            largest_sent_time = top_packet->send_time;
            delivered_prior = top_packet->delivered_prior;
            delivered_time_prior = top_packet->delivered_time_prior;
            delivered_sent_prior = top_packet->delivered_sent_prior;
            rs_is_path_limited = top_packet->delivered_app_limited;
        }

        uint64_t range = frame->first_ack_block;
        uint64_t block_to_block;

        range ++;

        if (frame->largest_acknowledged + 1 < range) {
            DBG_PRINTF("ack range error: largest=%" PRIx64 ", range=%" PRIx64, frame->largest_acknowledged, range);
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
            return 1;
        }

        if (picoquic_process_ack_range(cnx, pc, frame->largest_acknowledged, range, &top_packet, current_time) != 0) {
            return 1;
        }

        if (range > 0) {
            picoquic_check_spurious_retransmission(cnx, frame->largest_acknowledged + 1 - range, frame->largest_acknowledged, current_time, pc, path_x);
        }

        uint64_t largest = frame->largest_acknowledged;

        for (int i = 0; i < frame->ack_block_count; i++) {
            /* Skip the gap */
            block_to_block = frame->ack_blocks[i].gap;

            block_to_block += 1; /* add 1, since zero is ruled out by varint, see spec. */
            block_to_block += range;

            if (largest < block_to_block) {
                DBG_PRINTF("ack gap error: largest=%" PRIx64 ", range=%" PRIx64 ", gap=%" PRIu64,
                    largest, range, block_to_block - range);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                return 1;
            }

            largest -= block_to_block;
            range = frame->ack_blocks[i].additional_ack_block;
            range ++;
            if (largest + 1 < range) {
                DBG_PRINTF("ack range error: largest=%" PRIx64 ", range=%" PRIx64, largest, range);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                return 1;
            }

            if (picoquic_process_ack_range(cnx, pc, largest, range, &top_packet, current_time) != 0) {
                return 1;
            }

            if (range > 0) {
                picoquic_check_spurious_retransmission(cnx, largest + 1 - range, largest, current_time, pc, path_x);
            }
        }

        if (old_path != NULL && is_new_ack) {
            picoquic_estimate_path_bandwidth(cnx, old_path, largest_sent_time,
                                             delivered_prior, delivered_time_prior, delivered_sent_prior,
                                             current_time, current_time, rs_is_path_limited);

            picoquic_congestion_algorithm_notify_func(cnx, old_path, picoquic_congestion_notification_bw_measurement, old_path->rtt_sample, 0, 0, current_time);
        }
    }

    return 0;
}

int picoquic_prepare_ack_frame_maybe_ecn(picoquic_cnx_t* cnx, uint64_t current_time,
    picoquic_packet_context_enum pc,
    uint8_t* bytes, size_t bytes_max, size_t* consumed, int is_ecn)
{
    int ret = 0;
    size_t byte_index = 0;
    uint64_t num_block = 0;
    size_t l_largest = 0;
    size_t l_delay = 0;
    size_t l_first_range = 0;
    picoquic_path_t* path_x = cnx->path[0];
    picoquic_packet_context_t * pkt_ctx = &path_x->pkt_ctx[pc];
    picoquic_sack_item_t* next_sack = pkt_ctx->first_sack_item.next_sack;
    uint64_t ack_delay = 0;
    uint64_t ack_range = 0;
    uint64_t ack_gap = 0;
    uint64_t lowest_acknowledged = 0;
    size_t num_block_index = 0;
    uint8_t ack_type_byte = (is_ecn)?picoquic_frame_type_ack_ecn: picoquic_frame_type_ack;

    ack_frame_t frame;

    /* Check that there is enough room in the packet, and something to acknowledge */
    if (pkt_ctx->first_sack_item.start_of_sack_range == (uint64_t)((int64_t)-1)) {
        *consumed = 0;
    } else if (bytes_max < 13) {
        /* A valid ACK, with our encoding, uses at least 13 bytes.
        * If there is not enough space, don't attempt to encode it.
        */
        *consumed = 0;
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else {
        /* Encode the first byte */
        bytes[byte_index++] = ack_type_byte;
        /* Encode the largest seen */
        if (byte_index < bytes_max) {
            frame.largest_acknowledged = pkt_ctx->first_sack_item.end_of_sack_range;
            l_largest = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                pkt_ctx->first_sack_item.end_of_sack_range);
            byte_index += l_largest;
        }
        /* Encode the ack delay */
        if (byte_index < bytes_max) {
            if (current_time > pkt_ctx->time_stamp_largest_received) {
                ack_delay = current_time - pkt_ctx->time_stamp_largest_received;
                ack_delay >>= cnx->local_parameters.ack_delay_exponent;
            }
            l_delay = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                ack_delay);
            byte_index += l_delay;
        }

        if (ret == 0) {
            /* Reserve one byte for the number of blocks */
            num_block_index = byte_index;
            byte_index++;
            /* Encode the size of the first ack range */
            if (byte_index < bytes_max) {
                ack_range = pkt_ctx->first_sack_item.end_of_sack_range - pkt_ctx->first_sack_item.start_of_sack_range;
                frame.first_ack_block = ack_range;
                l_first_range = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                    ack_range);
                byte_index += l_first_range;
            }
        }

        if (l_delay == 0 || l_largest == 0 || l_first_range == 0 || byte_index > bytes_max) {
            /* not enough space */
            *consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        } else if (ret == 0) {
            /* Set the lowest acknowledged */
            lowest_acknowledged = pkt_ctx->first_sack_item.start_of_sack_range;
            /* Encode the ack blocks that fit in the allocated space */
            while (num_block < 63 && next_sack != NULL) {
                size_t l_gap = 0;
                size_t l_range = 0;

                if (byte_index < bytes_max) {
                    ack_gap = lowest_acknowledged - next_sack->end_of_sack_range - 2; /* per spec */
                    frame.ack_blocks[num_block].gap = ack_gap;
                    l_gap = picoquic_varint_encode(bytes + byte_index,
                        bytes_max - byte_index, ack_gap);
                }

                if (byte_index + l_gap < bytes_max) {
                    ack_range = next_sack->end_of_sack_range - next_sack->start_of_sack_range;
                    frame.ack_blocks[num_block].additional_ack_block = ack_range;
                    l_range = picoquic_varint_encode(bytes + byte_index + l_gap,
                        bytes_max - byte_index - l_gap, ack_range);
                }

                if (l_gap == 0 || l_range == 0) {
                    /* Not enough space to encode this gap. */
                    break;
                } else {
                    byte_index += l_gap + l_range;
                    lowest_acknowledged = next_sack->start_of_sack_range;
                    next_sack = next_sack->next_sack;
                    num_block++;
                }
            }

            if (is_ecn) {
                size_t l_ect0 = 0;
                size_t l_ect1 = 0;
                size_t l_ce = 0;

                l_ect0 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                                                cnx->ecn_ect0_total_local);
                byte_index += l_ect0;

                l_ect1 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                                                cnx->ecn_ect1_total_local);
                byte_index += l_ect0;

                l_ce = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                                              cnx->ecn_ce_total_local);
                byte_index += l_ce;

                if (l_ect0 == 0 || l_ect1 == 0 || l_ce == 0) {
                    *consumed = 0;
                    ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                }
            }

            frame.ack_block_count = num_block;

            LOG {
                char ack_str[800];
                size_t ack_ofs = 0;
                uint64_t largest = frame.largest_acknowledged;
                int ack_block_count = frame.ack_block_count;
                for (int num_block = -1; num_block < ack_block_count && ack_ofs < sizeof(ack_str); num_block++) {
                    uint64_t block_to_block;
                    uint64_t range;
                    if (num_block == -1) {
                        range = frame.first_ack_block + 1;
                    } else {
                        range = frame.ack_blocks[num_block].additional_ack_block + 1;
                    }

                    if (range <= 1)
                        ack_ofs += snprintf(ack_str + ack_ofs, sizeof(ack_str) - ack_ofs, "[%" PRIu64 "]%s", largest, num_block == ack_block_count - 1 ? "" : ", ");
                    else
                        ack_ofs += snprintf(ack_str + ack_ofs, sizeof(ack_str) - ack_ofs, "[%" PRIu64 ", %" PRIu64 "]%s", largest - range + 1, largest, num_block == ack_block_count - 1 ? "" : ", ");

                    if (num_block == ack_block_count - 1)
                        break;

                    block_to_block = frame.ack_blocks[num_block+1].gap + 1;
                    block_to_block += range;

                    largest -= block_to_block;
                }
                ack_str[ack_ofs] = 0;
                LOG_EVENT(cnx, "FRAMES", "ACK_FRAME_CREATED", "", "{\"data_ptr\": \"%p\", \"largest\": %" PRIu64 ", \"blocks\": [%s]}", bytes, frame.largest_acknowledged, ack_str);
            }

            /* When numbers are lower than 64, varint encoding fits on one byte */
            bytes[num_block_index] = (uint8_t)num_block;

            /* Remember the ACK value and time */
            pkt_ctx->highest_ack_sent = pkt_ctx->first_sack_item.end_of_sack_range;
            pkt_ctx->highest_ack_time = current_time;

            *consumed = byte_index;
        }
    }

    if (ret == 0) {
        pkt_ctx->ack_needed = 0;
    }

    return ret;
}

/**
 * See PROTOOP_NOPARAM_PREPARE_ACK_FRAME
 */
protoop_arg_t prepare_ack_frame(picoquic_cnx_t *cnx)
{
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[0];
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) cnx->protoop_inputv[1];
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[2];
    size_t bytes_max = (size_t) cnx->protoop_inputv[3];

    size_t consumed = 0;

    int ret = picoquic_prepare_ack_frame_maybe_ecn(cnx, current_time, pc, bytes, bytes_max, &consumed, 0);

    protoop_save_outputs(cnx, consumed);

    return (protoop_arg_t) ret;
}

int picoquic_prepare_ack_frame(picoquic_cnx_t* cnx, uint64_t current_time,
    picoquic_packet_context_enum pc,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREPARE_ACK_FRAME, outs,
        current_time, pc, bytes, bytes_max);
    *consumed = (size_t) outs[0];
    return ret;
}

/**
 * See PROTOOP_NOPARAM_PREPARE_ACK_ECN_FRAME
 */
protoop_arg_t prepare_ack_ecn_frame(picoquic_cnx_t *cnx)
{
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[0];
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) cnx->protoop_inputv[1];
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[2];
    size_t bytes_max = (size_t) cnx->protoop_inputv[3];

    size_t consumed = 0;

    int ret = picoquic_prepare_ack_frame_maybe_ecn(cnx, current_time, pc, bytes, bytes_max, &consumed, 1);

    protoop_save_outputs(cnx, consumed);

    return (protoop_arg_t) ret;
}

int picoquic_prepare_ack_ecn_frame(picoquic_cnx_t* cnx, uint64_t current_time,
    picoquic_packet_context_enum pc,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREPARE_ACK_ECN_FRAME, outs,
        current_time, pc, bytes, bytes_max, *consumed);
    *consumed = (size_t) outs[0];
    return ret;
}

/**
 * See PROTOOP_NOPARAM_IS_ACK_NEEDED
 */
protoop_arg_t is_ack_needed(picoquic_cnx_t *cnx)
{
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[0];
    picoquic_packet_context_enum pc = (picoquic_packet_context_enum) cnx->protoop_inputv[1];
    picoquic_path_t* path_x = (picoquic_path_t*) cnx->protoop_inputv[2];

    int ret = 0;
    picoquic_packet_context_t * pkt_ctx = &path_x->pkt_ctx[pc];

    if (pkt_ctx->ack_needed) {
        if (pkt_ctx->highest_ack_sent + 2 <= pkt_ctx->first_sack_item.end_of_sack_range ||
            pkt_ctx->highest_ack_time + pkt_ctx->ack_delay_local <= current_time) {
            ret = 1;
        }
    } else if (pkt_ctx->highest_ack_sent + 8 <= pkt_ctx->first_sack_item.end_of_sack_range &&
        pkt_ctx->highest_ack_time + pkt_ctx->ack_delay_local <= current_time) {
        /* Force sending an ack-of-ack from time to time, as a low priority action */
        if (pkt_ctx->first_sack_item.end_of_sack_range == (uint64_t)((int64_t)-1)) {
            ret = 0;
        }
        else {
            ret = 1;
        }
    }

    return (protoop_arg_t) ret;
}

int picoquic_is_ack_needed(picoquic_cnx_t* cnx, uint64_t current_time, picoquic_packet_context_enum pc,
    picoquic_path_t* path_x)
{
    return (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_IS_ACK_NEEDED, NULL,
        current_time, pc, path_x);
}

/*
 * Connection close frame
 */
int picoquic_prepare_connection_close_frame(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    size_t l1 = 0, l2 = 0, l3 = 0;

    if (bytes_max > 4) {
        bytes[byte_index++] = picoquic_frame_type_connection_close;
        l1 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, cnx->local_error);
        byte_index += l1;
        l2 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, cnx->offending_frame_type);
        byte_index += l2;
        l3 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, 0);
        byte_index += l3;
        *consumed = byte_index;

        if (l1 == 0 || l2 == 0 || l3 == 0) {
            *consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        } else {
            LOG_EVENT(cnx, "FRAMES", "CONNECTION_CLOSE_CREATED", "", "{\"data_ptr\": \"%p\", \"error\": %d, \"frame_type\": %" PRIu64 ", \"reason\": \"\"}", bytes, cnx->local_error, cnx->offending_frame_type);
        }
    }
    else {
        *consumed = 0;
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    }

    return ret;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_connection_close_frame(picoquic_cnx_t* cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    connection_close_frame_t* frame = malloc(sizeof(connection_close_frame_t));

    if (!frame) {
        printf("Failed to allocate memory for connection_close_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->error_code)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes,   bytes_max, &frame->frame_type)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->reason_phrase_length)) == NULL ||
        (bytes = (bytes + frame->reason_phrase_length <= bytes_max) ? bytes : NULL) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_connection_close);
        free(frame);
        frame = NULL;
    }
    else {
        /* The memory bound was already checked, so this is safe */
        memcpy(frame->reason_phrase, bytes,
        frame->reason_phrase_length <= REASONPHRASELENGTH_MAX ? frame->reason_phrase_length : REASONPHRASELENGTH_MAX);
        bytes += frame->reason_phrase_length;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_connection_close_frame(picoquic_cnx_t* cnx)
{
    connection_close_frame_t* frame = (connection_close_frame_t *) cnx->protoop_inputv[0];

    cnx->remote_error = frame->error_code;
    cnx->cnx_state = (cnx->cnx_state < picoquic_state_client_ready) ? picoquic_state_disconnected : picoquic_state_closing_received;
    if (cnx->callback_fn) {
        (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
    }

    return 0;
}

/*
 * Application close frame
 */

int picoquic_prepare_application_close_frame(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    size_t l1 = 0, l2 = 0;

    if (bytes_max > 2) {
        bytes[byte_index++] = picoquic_frame_type_application_close;
        l1 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, cnx->application_error);
        byte_index += l1;
        l2 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, 0);
        byte_index += l2;
        *consumed = byte_index;

        if (l1 == 0 || l2 == 0) {
            *consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        } else {
            LOG_EVENT(cnx, "FRAMES", "APPLICATION_CLOSE_CREATED", "", "{\"data_ptr\": \"%p\", \"error\": %d, \"reason\": \"\"}", bytes, cnx->application_error);
        }
    }
    else {
        *consumed = 0;
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    }

    return ret;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_application_close_frame(picoquic_cnx_t* cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    application_close_frame_t* frame = malloc(sizeof(application_close_frame_t));

    if (!frame) {
        printf("Failed to allocate memory for application_close_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->error_code)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->reason_phrase_length)) == NULL ||
        (bytes = (bytes + frame->reason_phrase_length <= bytes_max) ? bytes : NULL) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_application_close);
        free(frame);
        frame = NULL;
    }
    else {
        /* The memory bound was already checked, so this is safe */
        memcpy(frame->reason_phrase, bytes,
            frame->reason_phrase_length <= REASONPHRASELENGTH_MAX ? frame->reason_phrase_length : REASONPHRASELENGTH_MAX);

        bytes += frame->reason_phrase_length;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_application_close_frame(picoquic_cnx_t* cnx)
{
    application_close_frame_t* frame = (application_close_frame_t *) cnx->protoop_inputv[0];
    cnx->remote_application_error = frame->error_code;
    cnx->cnx_state = (cnx->cnx_state < picoquic_state_client_ready) ? picoquic_state_disconnected : picoquic_state_closing_received;
    if (cnx->callback_fn) {
        (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_application_close, cnx->callback_ctx);
    }

    return 0;
}

/*
 * Max data frame
 */

#define PICOQUIC_MAX_MAXDATA ((uint64_t)((int64_t)-1))
#define PICOQUIC_MAX_MAXDATA_1K (PICOQUIC_MAX_MAXDATA >> 10)
#define PICOQUIC_MAX_MAXDATA_1K_MASK (PICOQUIC_MAX_MAXDATA << 10)

/**
 * See PROTOOP_NOPARAM_PREPARE_MAX_DATA_FRAME
 */
protoop_arg_t prepare_max_data_frame(picoquic_cnx_t *cnx)
{
    uint64_t maxdata_increase = (uint64_t) cnx->protoop_inputv[0];
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[1];
    size_t bytes_max = (size_t) cnx->protoop_inputv[2];

    size_t consumed = 0;

    int ret = 0;
    size_t l1 = 0;

    if (bytes_max < 1) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else {
        bytes[0] = picoquic_frame_type_max_data;
        l1 = picoquic_varint_encode(bytes + 1, bytes_max - 1, cnx->maxdata_local + maxdata_increase);

        if (l1 == 0) {
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        } else {
            cnx->maxdata_local = (cnx->maxdata_local + maxdata_increase);
        }

        consumed = 1 + l1;
        LOG_EVENT(cnx, "FRAMES", "MAX_DATA_CREATED", "", "{\"data_ptr\": \"%p\", \"maximum_data\": %" PRIu64 "}", bytes, cnx->maxdata_local);
    }

    protoop_save_outputs(cnx, consumed);

    return (protoop_arg_t) ret;
}

int picoquic_prepare_max_data_frame(picoquic_cnx_t* cnx, uint64_t maxdata_increase,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREPARE_MAX_DATA_FRAME, outs,
        maxdata_increase, bytes, bytes_max, *consumed);
    *consumed = (size_t) outs[0];
    return ret;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_max_data_frame(picoquic_cnx_t* cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    max_data_frame_t* frame = malloc(sizeof(max_data_frame_t));

    if (!frame) {
        printf("Failed to allocate memory for max_data_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->maximum_data)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_max_data);
        free(frame);
        frame = NULL;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_max_data_frame(picoquic_cnx_t* cnx)
{
    max_data_frame_t* frame = (max_data_frame_t *) cnx->protoop_inputv[0];

    if (frame->maximum_data > cnx->maxdata_remote) {
        cnx->maxdata_remote = frame->maximum_data;
    }

    return 0;
}

/*
 * Max stream data frame
 */

int picoquic_prepare_max_stream_data_frame(picoquic_stream_head* stream,
    uint8_t* bytes, size_t bytes_max, uint64_t new_max_data, size_t* consumed)
{
    int ret = 0;
    size_t l1 = picoquic_varint_encode(bytes + 1, bytes_max - 1, stream->stream_id);
    size_t l2 = picoquic_varint_encode(bytes + 1 + l1, bytes_max - 1 - l1, new_max_data);

    if (l1 == 0 || l2 == 0) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        *consumed = 0;
    } else {
        bytes[0] = picoquic_frame_type_max_stream_data;
        *consumed = 1 + l1 + l2;
        stream->maxdata_local = new_max_data;
    }

    return ret;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_max_stream_data_frame(picoquic_cnx_t* cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    max_stream_data_frame_t* frame = malloc(sizeof(max_stream_data_frame_t));

    if (!frame) {
        printf("Failed to allocate memory for max_stream_data_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->stream_id)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->maximum_stream_data)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_max_stream_data);
        free(frame);
        frame = NULL;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_max_stream_data_frame(picoquic_cnx_t *cnx)
{
    max_stream_data_frame_t* frame = (max_stream_data_frame_t *) cnx->protoop_inputv[0];

    picoquic_stream_head* stream;

    if ((stream = picoquic_find_stream(cnx, frame->stream_id, 1)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_ERROR_MEMORY, picoquic_frame_type_max_stream_data);
        return 1;
    } else if (frame->maximum_stream_data > stream->maxdata_remote) {
        /* TODO: call back if the stream was blocked? */
        stream->maxdata_remote = frame->maximum_stream_data;
    }

    return 0;
}

/**
 * See PROTOOP_NOPARAM_PREPARE_REQUIRED_MAX_STREAM_DATA_FRAME
 */
protoop_arg_t prepare_required_max_stream_data_frames(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    size_t bytes_max = (size_t) cnx->protoop_inputv[1];

    size_t consumed = 0;

    int ret = 0;
    size_t byte_index = 0;
    picoquic_stream_head* stream = cnx->first_stream;

    while (stream != NULL && ret == 0 && byte_index < bytes_max) {
        if ((stream->stream_flags & (picoquic_stream_flag_fin_received | picoquic_stream_flag_reset_received)) == 0 && 2 * stream->consumed_offset > stream->maxdata_local) {
            size_t bytes_in_frame = 0;

            ret = picoquic_prepare_max_stream_data_frame(stream,
                bytes + byte_index, bytes_max - byte_index,
                stream->maxdata_local + 2 * stream->consumed_offset,
                &bytes_in_frame);
            if (ret == 0) {
                byte_index += bytes_in_frame;
                LOG_EVENT(cnx, "FRAMES", "MAX_STREAM_DATA_CREATED", "", "{\"data_ptr\": \"%p\", \"stream_id\": %" PRIu64 ", \"maximum_data\": %" PRIu64 "}", bytes, stream->stream_id, stream->maxdata_local);
            } else {
                break;
            }
        }
        stream = stream->next_stream;
    }

    if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
        ret = 0;
    }

    if (ret == 0) {
        consumed = byte_index;
    } else {
        consumed = 0;
    }

    protoop_save_outputs(cnx, consumed);

    return (protoop_arg_t) ret;
}

int picoquic_prepare_required_max_stream_data_frames(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREPARE_REQUIRED_MAX_STREAM_DATA_FRAME, outs,
        bytes, bytes_max);
    *consumed = (size_t)outs[0];
    return ret;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_max_streams_frame(picoquic_cnx_t *cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    max_streams_frame_t* frame = malloc(sizeof(max_streams_frame_t));

    if (!frame) {
        printf("Failed to allocate memory for max_streams_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    uint64_t frame_type;
    bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_type);
    frame->uni = frame_type == picoquic_frame_type_max_streams_uni;
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->maximum_streams)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
        free(frame);
        frame = NULL;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_max_stream_id_frame(picoquic_cnx_t* cnx)
{
    max_streams_frame_t* frame = (max_streams_frame_t *) cnx->protoop_inputv[0];
    uint64_t *max_id = !frame->uni ? &cnx->max_stream_id_bidir_remote : &cnx->max_stream_id_unidir_remote;
    uint64_t max_stream_id = STREAM_ID_FROM_RANK(frame->maximum_streams, !cnx->client_mode, frame->uni);
    if (max_stream_id > *max_id) {
        *max_id = max_stream_id;
    }

    return 0;
}

/*
 * Sending of miscellaneous frames
 */

/**
 * See PROTOOP_NOPARAM_PREPARE_FIRST_MISC_FRAME
 */
protoop_arg_t prepare_first_misc_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t*) cnx->protoop_inputv[0];
    size_t bytes_max = (size_t) cnx->protoop_inputv[1];

    size_t consumed = 0;

    int ret = picoquic_prepare_misc_frame(cnx, cnx->first_misc_frame, bytes, bytes_max, &consumed);

    if (ret == 0) {
        picoquic_misc_frame_header_t* misc_frame = cnx->first_misc_frame;
        cnx->first_misc_frame = misc_frame->next_misc_frame;
        free(misc_frame);
    }

    protoop_save_outputs(cnx, consumed);

    return (protoop_arg_t) ret;
}

int picoquic_prepare_first_misc_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
                                      size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREPARE_FIRST_MISC_FRAME, outs,
        bytes, bytes_max, *consumed);
    *consumed = (size_t) outs[0];
    return ret;
}

/**
 * See PROTOOP_NOPARAM_PREPARE_MISC_FRAME
 */
protoop_arg_t prepare_misc_frame(picoquic_cnx_t *cnx)
{
    picoquic_misc_frame_header_t* misc_frame = (picoquic_misc_frame_header_t *) cnx->protoop_inputv[0];
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[1];
    size_t bytes_max = (size_t) cnx->protoop_inputv[2];

    size_t consumed = 0;

    int ret = 0;

    if (misc_frame->length > bytes_max) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        consumed = 0;
    } else {
        uint8_t* frame = ((uint8_t*)misc_frame) + sizeof(picoquic_misc_frame_header_t);
        memcpy(bytes, frame, misc_frame->length);
        consumed = misc_frame->length;
    }

    protoop_save_outputs(cnx, consumed);

    return (protoop_arg_t) ret;
}

int picoquic_prepare_misc_frame(picoquic_cnx_t* cnx, picoquic_misc_frame_header_t* misc_frame, uint8_t* bytes,
                                size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREPARE_MISC_FRAME, outs,
        misc_frame, bytes, bytes_max, *consumed);
    *consumed = (size_t) outs[0];
    return ret;
}

/*
 * Path Challenge and Response frames
 */

/**
 * cnx->protoop_inputv[0] = uint8_t* bytes
 * cnx->protoop_inputv[1] = size_t bytes_max
 * cnx->protoop_inputv[2] = size_t consumed
 * cnx->protoop_inputv[3] = picoquic_path_t * path
 *
 * Output: error code (int)
 * cnx->protoop_outputv[0] = size_t consumed
 */
protoop_arg_t prepare_path_challenge_frame(picoquic_cnx_t *cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    size_t bytes_max = (size_t) cnx->protoop_inputv[1];
    picoquic_path_t * path = (picoquic_path_t *) cnx->protoop_inputv[2];

    size_t consumed = 0;

    int ret = 0;
    if (bytes_max < (1 + 8)) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        consumed = 0;
    } else {
        bytes[0] = picoquic_frame_type_path_challenge;
        picoformat_64(bytes + 1, path->challenge);
        consumed = 1 + 8;

        LOG_EVENT(cnx, "FRAMES", "PATH_CHALLENGE_CREATED", "", "{\"data_ptr\": \"%p\", \"data\": \"%" PRIx64 "\"}", bytes, path->challenge);
    }

    protoop_save_outputs(cnx, consumed);

    return (protoop_arg_t) ret;
}

int picoquic_prepare_path_challenge_frame(picoquic_cnx_t *cnx, uint8_t* bytes,
    size_t bytes_max, size_t* consumed, picoquic_path_t * path)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PREPARE_PATH_CHALLENGE_FRAME, outs,
        bytes, bytes_max, path);
    *consumed = (size_t) outs[0];
    return ret;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_path_challenge_frame(picoquic_cnx_t* cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 0;
    int is_retransmittable = 0;
    path_challenge_frame_t* frame = malloc(sizeof(path_challenge_frame_t));

    if (!frame) {
        printf("Failed to allocate memory for max_stream_id_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if (bytes_max - bytes <= (int) PICOQUIC_CHALLENGE_LENGTH) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_path_challenge);
        bytes = NULL;
        free(frame);
        frame = NULL;
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    memcpy(&frame->data, bytes + picoquic_varint_skip(bytes), PICOQUIC_CHALLENGE_LENGTH);
    bytes += PICOQUIC_CHALLENGE_LENGTH+1;

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_path_challenge_frame(picoquic_cnx_t* cnx)
{
    path_challenge_frame_t* frame = (path_challenge_frame_t *) cnx->protoop_inputv[0];
    picoquic_path_t *path_x = (picoquic_path_t *) cnx->protoop_inputv[3];
    /*
    * Queue a response frame as response to path challenge.
    * The response should be force-sent by the sender itself!
    */
    memcpy(path_x->challenge_response, &frame->data, PICOQUIC_CHALLENGE_LENGTH);
    path_x->challenge_response_to_send = 1;

    return 0;
}

/**
 * See PROTOOP_PARAM_DECODE_FRAME
 */
protoop_arg_t decode_path_challenge_frame(picoquic_cnx_t *cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (const uint8_t *) cnx->protoop_inputv[1];
    int ack_needed = (int) cnx->protoop_inputv[4];

    if (bytes_max - bytes <= (int) PICOQUIC_CHALLENGE_LENGTH) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_path_challenge);
        bytes = NULL;

    } else {
        /*
         * Queue a response frame as response to path challenge.
         * TODO: ensure it goes out on the same path as the incoming challenge.
         */
        uint8_t frame_buffer[258];

        frame_buffer[0] = picoquic_frame_type_path_response;
        memcpy(frame_buffer+1, bytes + picoquic_varint_skip(bytes), PICOQUIC_CHALLENGE_LENGTH);

        // Ignore return code. If cannot send the response, consider it "lost"
        picoquic_queue_misc_frame(cnx, frame_buffer, PICOQUIC_CHALLENGE_LENGTH+1);

        bytes += PICOQUIC_CHALLENGE_LENGTH+1;
    }

    protoop_save_outputs(cnx, ack_needed);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_path_response_frame(picoquic_cnx_t* cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 0;
    int is_retransmittable = 0;
    path_response_frame_t* frame = malloc(sizeof(path_response_frame_t));

    if (!frame) {
        printf("Failed to allocate memory for path_response_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_uint64_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->data)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_path_response);
        free(frame);
        frame = NULL;
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_path_response_frame(picoquic_cnx_t* cnx)
{
    path_response_frame_t* frame = (path_response_frame_t *) cnx->protoop_inputv[0];

    int found_challenge = 0;
    /*
        * Check that the challenge corresponds to something that was sent locally
        */
    for (int i = 0; i < cnx->nb_paths; i++) {
        if (frame->data == cnx->path[i]->challenge) {
            /* TODO: verify that the network addresses match the path */
            found_challenge = 1;
            cnx->path[i]->challenge_verified = 1;
        }
    }

    if (found_challenge == 0 && cnx->callback_fn != NULL) {
        uint8_t original_frame[9];
        original_frame[0] = picoquic_frame_type_path_response;
        uint64_t data_network_order = htobe64(frame->data);
        memcpy(&original_frame[1], &data_network_order, 8);
        cnx->callback_fn(cnx, 0, &original_frame[0], PICOQUIC_CHALLENGE_LENGTH+1,
                         picoquic_callback_challenge_response, cnx->callback_ctx);
    }

    return 0;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_blocked_frame(picoquic_cnx_t* cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    blocked_frame_t* frame = malloc(sizeof(blocked_frame_t));

    if (!frame) {
        printf("Failed to allocate memory for blocked_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->offset)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_data_blocked);
        free(frame);
        frame = NULL;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_stream_blocked_frame(picoquic_cnx_t* cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    stream_blocked_frame_t* frame = malloc(sizeof(stream_blocked_frame_t));

    if (!frame) {
        printf("Failed to allocate memory for stream_blocked_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->stream_id)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->offset)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_stream_data_blocked);
        free(frame);
        frame = NULL;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_DECODE_FRAME
 */
protoop_arg_t decode_stream_blocked_frame(picoquic_cnx_t* cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (const uint8_t *) cnx->protoop_inputv[1];
    int ack_needed = (int) cnx->protoop_inputv[4];

    ack_needed = 1;

    /* TODO: check that the stream number is valid */
    if ((bytes = picoquic_frames_varint_skip(bytes + picoquic_varint_skip(bytes), bytes_max)) == NULL ||
        (bytes = picoquic_frames_varint_skip(bytes,   bytes_max)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_stream_data_blocked);
    }

    protoop_save_outputs(cnx, ack_needed);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_streams_blocked_frame(picoquic_cnx_t *cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    streams_blocked_frame_t* frame = malloc(sizeof(streams_blocked_frame_t));

    if (!frame) {
        printf("Failed to allocate memory for streams_blocked_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    uint64_t frame_type;
    bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_type);
    frame->uni = frame_type == picoquic_frame_type_uni_streams_blocked;
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->stream_limit)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_type);
        free(frame);
        frame = NULL;
    }

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_DECODE_FRAME
 */
protoop_arg_t decode_stream_id_blocked_frame(picoquic_cnx_t* cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (const uint8_t *) cnx->protoop_inputv[1];
    int ack_needed = (int) cnx->protoop_inputv[4];

    ack_needed = 1;

    if ((bytes = picoquic_frames_varint_skip(bytes + picoquic_varint_skip(bytes), bytes_max)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_bidi_streams_blocked);
    }

    protoop_save_outputs(cnx, ack_needed);
    return (protoop_arg_t) bytes;
}

protoop_arg_t write_plugin_validate_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t*) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t*) cnx->protoop_inputv[1];
    plugin_validate_frame_t* frame_ctx = (plugin_validate_frame_t*) cnx->protoop_inputv[2];

    int ret = 0;
    int consumed = 0;
    int is_retransmittable = 1;
    size_t max_bytes = (size_t) (bytes_max - bytes);

    size_t l1 = picoquic_varint_encode(bytes + 1, max_bytes - 1, frame_ctx->pid_id);
    size_t l2 = picoquic_varint_encode(bytes + 1 + l1, max_bytes - 1 - l1, frame_ctx->pid_len);

    if (l1 == 0 || l2 == 0 || (bytes + 1 + l1 + l2 + frame_ctx->pid_len) > bytes_max) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else {
        bytes[0] = picoquic_frame_type_plugin_validate;
        memcpy(bytes + 1 + l1 + l2, frame_ctx->pid, frame_ctx->pid_len);
        consumed = 1 + l1 + l2 + frame_ctx->pid_len;
    }

    protoop_save_outputs(cnx, consumed, is_retransmittable);
    return ret;
}

int picoquic_write_plugin_validate_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t pid_id, char* pid, size_t* consumed, int* is_retransmittable)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    plugin_validate_frame_t frame_ctx;
    frame_ctx.pid_id = pid_id;
    frame_ctx.pid_len = strlen(pid) + 1; // To have '\0'
    frame_ctx.pid = pid;
    int ret = (int) protoop_prepare_and_run_param(cnx, &PROTOOP_PARAM_WRITE_FRAME, picoquic_frame_type_plugin_validate, outs,
        bytes, bytes_max, &frame_ctx);
    *consumed = (size_t) outs[0];
    *is_retransmittable = (int) outs[1];
    return ret;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_plugin_validate_frame(picoquic_cnx_t* cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    plugin_validate_frame_t* frame = malloc(sizeof(plugin_validate_frame_t));

    if (!frame) {
        printf("Failed to allocate memory for plugin_validate_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes + picoquic_varint_skip(bytes), bytes_max, &frame->pid_id)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_max_data);
        free(frame);
        frame = NULL;
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    /* Currently, the length includes the '\0' */
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->pid_len)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_max_data);
        free(frame);
        frame = NULL;
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if (frame->pid_len > 250) {
        /* Probably the length is not correctly formatted */
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_max_data);
        free(frame);
        frame = NULL;
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    frame->pid = malloc(sizeof(char) * frame->pid_len);
    if (!frame->pid) {
        printf("Failed to allocate memory for pid in plugin_validate_frame_t\n");
        free(frame);
        frame = NULL;
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }
    memcpy(frame->pid, bytes, frame->pid_len);
    bytes += frame->pid_len;

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_plugin_validate_frame(picoquic_cnx_t* cnx)
{
    plugin_validate_frame_t* frame = (plugin_validate_frame_t *) cnx->protoop_inputv[0];

    /* Find the corresponding plugin path */
    for (int i = 0; i < cnx->quic->plugins_to_inject.size; i++) {
        if (strcmp(frame->pid, cnx->quic->plugins_to_inject.elems[i].plugin_name) == 0) {
            uint8_t plugin_buffer[MAX_PLUGIN_DATA_LEN];
            size_t size_used = 0;
            int err = plugin_prepare_plugin_data_exchange(cnx, cnx->quic->plugins_to_inject.elems[i].plugin_path, plugin_buffer,
                MAX_PLUGIN_DATA_LEN, &size_used);
            if (err == 0) {
                picoquic_add_to_plugin_stream(cnx, frame->pid_id, plugin_buffer, size_used, 1);
            } else {
                printf("Failed to prepare plugin data exchanged\n");
            }
            return err;
        }
    }

    return 0;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_plugin_frame(picoquic_cnx_t* cnx)
{
    uint8_t *bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t *bytes_max = (uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    plugin_frame_t* frame = malloc(sizeof(plugin_frame_t));

    if (!frame) {
        printf("Failed to allocate memory for plugin_frame_t\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    memcpy(&frame->fin, bytes + 1, 1);

    if ((bytes = picoquic_frames_varint_decode(bytes + 2, bytes_max, &frame->pid_id)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_max_data);
        free(frame);
        frame = NULL;
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->offset)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_max_data);
        free(frame);
        frame = NULL;
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame->length)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_max_data);
        free(frame);
        frame = NULL;
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if (frame->length > bytes_max - bytes) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_max_data);
        free(frame);
        frame = NULL;
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    memcpy(frame->data, bytes, frame->length);
    bytes += frame->length;

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

void picoquic_plugin_data_callback(picoquic_cnx_t* cnx, picoquic_stream_head* plugin_stream)
{
    picoquic_stream_data* data = plugin_stream->stream_data;
    plugin_req_pid_t *preq = NULL;

    while (data != NULL && data->offset <= plugin_stream->consumed_offset) {
        size_t start = (size_t)(plugin_stream->consumed_offset - data->offset);
        size_t data_length = data->length - start;
        picoquic_call_back_event_t fin_now = picoquic_callback_no_event;

        plugin_stream->consumed_offset += data_length;

        if (plugin_stream->consumed_offset >= plugin_stream->fin_offset && (plugin_stream->stream_flags & (picoquic_stream_flag_fin_received | picoquic_stream_flag_fin_signalled)) == picoquic_stream_flag_fin_received) {
            fin_now = picoquic_callback_stream_fin;
            picoquic_add_stream_flags(cnx, plugin_stream, picoquic_stream_flag_fin_signalled);
        }

        LOG_EVENT(cnx, "APPLICATION", "CALLBACK", picoquic_log_fin_or_event_name(fin_now), "{\"plugin_id\": %" PRIu64 ", \"data_length\": %" PRIu64 "}", plugin_stream->stream_id, data_length);
        /* FIXME not efficient */
        for (int i = 0; i < cnx->pids_to_request.size; i++) {
            preq = &cnx->pids_to_request.elems[i];
            if (preq->pid_id == plugin_stream->stream_id) {
                memcpy(preq->data + preq->received_length, data->bytes, data_length);
                preq->received_length += data_length;
                break;
            }
        }

        free(data->bytes);
        plugin_stream->stream_data = data->next_stream_data;
        free(data);
        data = plugin_stream->stream_data;
    }

    /* Once all data have been received, process it! */

    if (plugin_stream->consumed_offset >= plugin_stream->fin_offset && (plugin_stream->stream_flags & picoquic_stream_flag_fin_received) == picoquic_stream_flag_fin_received) {
        picoquic_add_stream_flags(cnx, plugin_stream, picoquic_stream_flag_fin_signalled);
        for (int i = 0; i < cnx->pids_to_request.size; i++) {
            preq = &cnx->pids_to_request.elems[i];
            if (preq->pid_id == plugin_stream->stream_id) {
                plugin_process_plugin_data_exchange(cnx, preq->plugin_name, preq->data, preq->received_length);
                free(preq->data);
                preq->data = NULL;
                break;
            }
        }
        LOG_EVENT(cnx, "APPLICATION", "CALLBACK", picoquic_log_fin_or_event_name(picoquic_callback_stream_fin), "{\"plugin_id\": %" PRIu64 ", \"data_length\": 0}", plugin_stream->stream_id);
    }
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_plugin_frame(picoquic_cnx_t* cnx)
{
    plugin_frame_t* frame = (plugin_frame_t *) cnx->protoop_inputv[0];
    uint64_t current_time = (uint64_t) cnx->protoop_inputv[1];

    int ret = 0;
    uint64_t should_notify = 0;
    /* Is there such a stream, is it still open? */
    picoquic_stream_head* plugin_stream;
    uint64_t new_fin_offset = frame->offset + frame->length;

    if ((plugin_stream = picoquic_find_or_create_plugin_stream(cnx, frame->pid_id, 1)) == NULL) {
        ret = 1;  // Error already signaled
    } else if ((plugin_stream->stream_flags & picoquic_stream_flag_fin_received) != 0) {
        if (frame->fin != 0 ? plugin_stream->fin_offset != new_fin_offset : new_fin_offset > plugin_stream->fin_offset) {
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FINAL_SIZE_ERROR, 0);
        }
    } else {
        if (frame->fin) {
            picoquic_add_stream_flags(cnx, plugin_stream, picoquic_stream_flag_fin_received);
            should_notify = 1;
            cnx->latest_progress_time = current_time;
        }

        if (new_fin_offset > plugin_stream->fin_offset) {
            ret = picoquic_flow_control_check_stream_offset(cnx, plugin_stream, new_fin_offset);
        }
    }

    if (ret == 0) {
        int new_data_available = 0;

        ret = picoquic_queue_network_input(cnx, plugin_stream, (size_t)frame->offset, frame->data, frame->length, &new_data_available);

        if (new_data_available) {
            should_notify = 1;
            cnx->latest_progress_time = current_time;
        }
    }

    if (ret == 0 && should_notify != 0) {
        /* check how much data there is to send */
        picoquic_plugin_data_callback(cnx, plugin_stream);
    }

    return ret;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 * Default behaviour for unknown parameter
 */
static protoop_arg_t parse_unknown_frame(picoquic_cnx_t* cnx)
{
    void *frame = NULL;
    int ack_needed = 0;
    int is_retransmittable = 0;
    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) NULL;
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 * Default behaviour for unknown parameter
 */
static protoop_arg_t process_unknown_frame(picoquic_cnx_t* cnx)
{
    return 1;
}

/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 * If you don't want to do any processing with this frame, call me!
 */
static protoop_arg_t process_ignore_frame(picoquic_cnx_t* cnx)
{
    return 0;
}

static protoop_arg_t process_ping_frame(picoquic_cnx_t* cnx)
{
    picoquic_path_t* path_x = (picoquic_path_t*) cnx->protoop_inputv[3];
    path_x->ping_received = 1;
    return 0;
}

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
static protoop_arg_t parse_padding_or_ping_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t*) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t*) cnx->protoop_inputv[1];

    /* Frame is not allocated, so do it now */
    padding_or_ping_frame_t *frame = malloc(sizeof(padding_or_ping_frame_t));
    if (!frame) {
        int ack_needed = 0;
        int is_retransmittable = 0;
        printf("Failed to allocate memory for padding_or_ping_frame\n");
        protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    int ack_needed = bytes[0] ? 1 : 0;
    int is_retransmittable = bytes[0] ? 1 : 0;
    frame->is_ping = bytes[0] ? 1 : 0;
    frame->num_block = 0;
    uint8_t first_byte = bytes[0];

    do {
        bytes++;
        frame->num_block++;
    } while (bytes < bytes_max && *bytes == first_byte);

    protoop_save_outputs(cnx, frame, ack_needed, is_retransmittable);
    return (protoop_arg_t) bytes;
}

uint8_t* picoquic_decode_frame(picoquic_cnx_t* cnx, uint64_t frame_type, uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t current_time, int epoch, int* ack_needed, picoquic_path_t* path_x)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    bytes = (uint8_t*) protoop_prepare_and_run_param(cnx, &PROTOOP_PARAM_PARSE_FRAME, (uint16_t) frame_type, outs,
        bytes, bytes_max);
    void *frame = (void *) outs[0];
    *ack_needed |= (int) outs[1];
    protoop_plugin_t *previous_plugin = cnx->previous_plugin_in_replace;
    if (bytes && frame) {
        int err = (int) protoop_prepare_and_run_param(cnx, &PROTOOP_PARAM_PROCESS_FRAME, (uint16_t) frame_type, outs,
            frame, current_time, epoch, path_x);
        if (err) {
            bytes = NULL;
        }

        /* It is the responsibility of the caller to free frame */
        if (previous_plugin) {
            //printf("MY FREE decode_frame = %p\n", frame);
            my_free_in_core(cnx->previous_plugin_in_replace, frame);
        } else {
            free(frame);
        }
    }

    return bytes;
}

/*
 * Decoding of the received frames.
 *
 * In some cases, the expected frames are "restricted" to only ACK, STREAM 0 and PADDING.
 */

int picoquic_decode_frames(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max_size, int epoch, uint64_t current_time, picoquic_path_t* path_x)
{
    const uint8_t *bytes_max = bytes + bytes_max_size;
    int ack_needed = 0;
    picoquic_packet_context_enum pc = picoquic_context_from_epoch(epoch);
    picoquic_packet_context_t * pkt_ctx = &path_x->pkt_ctx[pc];

    typedef struct frame_queue {
        uint64_t frame_type;
        void *frame;
        protoop_plugin_t *originator;
        struct frame_queue *next;
    } frame_queue_t;

    frame_queue_t *frames = NULL;
    frame_queue_t *tail = NULL;

    while (bytes != NULL && bytes < bytes_max) {
        uint64_t frame_type;
        picoquic_varint_decode(bytes, bytes_max - bytes, &frame_type);

        if (epoch != 1 && epoch != 3 && frame_type != picoquic_frame_type_padding
                                     && frame_type != picoquic_frame_type_path_challenge
                                     && frame_type != picoquic_frame_type_path_response
                                     && frame_type != picoquic_frame_type_connection_close
                                     && frame_type != picoquic_frame_type_crypto_hs
                                     && frame_type != picoquic_frame_type_ack
                                     && frame_type != picoquic_frame_type_ack_ecn) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, frame_type);
            bytes = NULL;
            break;

        } else {
            protoop_arg_t outs[PROTOOPARGS_MAX];
            bytes = (uint8_t*) protoop_prepare_and_run_param(cnx, &PROTOOP_PARAM_PARSE_FRAME, (uint16_t) frame_type, outs, bytes, bytes_max);
            void *frame = (void *) outs[0];
            ack_needed |= (int) outs[1];
            protoop_plugin_t *previous_plugin = cnx->previous_plugin_in_replace;

            if (bytes && frame) {
                frame_queue_t **fq = tail ? &(tail->next) : &frames;
                *fq = malloc(sizeof(frame_queue_t));
                if (!*fq) {
                    bytes = NULL;
                    if (previous_plugin)
                        my_free_in_core(previous_plugin, frame);
                    else
                        free(frame);
                } else {
                    (*fq)->frame_type = frame_type;
                    (*fq)->frame = frame;
                    (*fq)->originator = previous_plugin;
                    (*fq)->next = NULL;
                    tail = *fq;
                }
            }
        }
    }

    picoquic_received_segment(cnx);

    while (frames && bytes) {
        frame_queue_t *fq = frames;

        protoop_arg_t outs[PROTOOPARGS_MAX];
        int err = (int) protoop_prepare_and_run_param(cnx, &PROTOOP_PARAM_PROCESS_FRAME, (uint16_t) fq->frame_type, outs, fq->frame, current_time, epoch, path_x);
        if (err) {
            bytes = NULL;
        }

        if (fq->originator) {
            //printf("MY FREE decode_frame = %p\n", frame);
            my_free_in_core(fq->originator, fq->frame);
        } else {
            free(fq->frame);
        }

        frames = frames->next;
        free(fq);
    }

    if (bytes != NULL && ack_needed != 0) {
        cnx->latest_progress_time = current_time;
        pkt_ctx->ack_needed = 1;
    }

    return bytes != NULL ? 0 : PICOQUIC_ERROR_DETECTED;
}

int picoquic_decode_frames_without_current_time(picoquic_cnx_t* cnx, uint8_t* bytes,
                                                size_t bytes_max_size, int epoch, picoquic_path_t* path_x) {
    const uint8_t *bytes_max = bytes + bytes_max_size;
    int ack_needed = 0;
    uint64_t current_time = picoquic_current_time();

    while (bytes != NULL && bytes < bytes_max) {
        uint64_t frame_type;
        picoquic_varint_decode(bytes, bytes_max - bytes, &frame_type);

        if (epoch != 1 && epoch != 3 && frame_type != picoquic_frame_type_padding
                                     && frame_type != picoquic_frame_type_path_challenge
                                     && frame_type != picoquic_frame_type_path_response
                                     && frame_type != picoquic_frame_type_connection_close
                                     && frame_type != picoquic_frame_type_crypto_hs
                                     && frame_type != picoquic_frame_type_ack
                                     && frame_type != picoquic_frame_type_ack_ecn) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, frame_type);
            bytes = NULL;
            break;

        } else {
            bytes = picoquic_decode_frame(cnx, frame_type, bytes, bytes_max, current_time, epoch, &ack_needed, path_x);
        }
    }

    return bytes != NULL ? 0 : PICOQUIC_ERROR_DETECTED;
}
/*
* The STREAM skipping function only supports the varint format.
* The old "fixed int" versions are supported by code in the skip_frame function
*/
static uint8_t* picoquic_skip_stream_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    uint8_t  len = bytes[0] & 2;
    uint8_t  off = bytes[0] & 4;

    if ((bytes = picoquic_frames_varint_skip(bytes + picoquic_varint_skip(bytes), bytes_max)) != NULL &&
        (off == 0 || (bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL))
    {
        bytes = (len == 0) ? (uint8_t*)bytes_max : picoquic_frames_length_data_skip(bytes, bytes_max);
    }

    return bytes;
}

/**
 * See PROTOOP_NOPARAM_SKIP_FRAME
 */
protoop_arg_t skip_frame(picoquic_cnx_t *cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    size_t bytes_max_size = (size_t) cnx->protoop_inputv[1];
    size_t consumed = (size_t) cnx->protoop_inputv[2];
    int pure_ack = (int) cnx->protoop_inputv[3];

    int is_retransmittable;

    const uint8_t *bytes_max = bytes + bytes_max_size;
    uint64_t frame_type;
    picoquic_varint_decode(bytes, bytes_max_size, &frame_type);

    protoop_arg_t outs[PROTOOPARGS_MAX];
    bytes = (uint8_t*) protoop_prepare_and_run_param(cnx, &PROTOOP_PARAM_PARSE_FRAME, (uint16_t) frame_type, outs,
        bytes, bytes_max);
    void *frame = (void *) outs[0];
    is_retransmittable = (int) outs[2];
    if (frame) {
        /* We don't need the frame data, so free it */
        if (cnx->previous_plugin_in_replace) {
            //printf("MY FREE skip_frame = %p\n", frame);
            my_free_in_core(cnx->previous_plugin_in_replace, frame);
        } else {
            free(frame);
        }
    }

    consumed = (bytes != NULL) ? bytes_max_size - (bytes_max - bytes) : bytes_max_size;

    pure_ack = is_retransmittable ? 0 : 1;

    protoop_save_outputs(cnx, consumed, pure_ack);

    return bytes == NULL;
}

int picoquic_skip_frame(picoquic_cnx_t *cnx, uint8_t* bytes, size_t bytes_max_size, size_t* consumed,
    int* pure_ack)
{
    protoop_arg_t outs[PROTOOPARGS_MAX];
    int ret = (int) protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_SKIP_FRAME, outs,
        bytes, bytes_max_size, *consumed, *pure_ack);
    *consumed = (size_t) outs[0];
    *pure_ack = (int) outs[1];
    return ret;
}

int picoquic_decode_closing_frames(picoquic_cnx_t *cnx, uint8_t* bytes, size_t bytes_max, int* closing_received)
{
    int ret = 0;
    size_t byte_index = 0;

    *closing_received = 0;
    while (ret == 0 && byte_index < bytes_max) {
        uint64_t frame_type;
        picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &frame_type);

        if (frame_type == picoquic_frame_type_connection_close || frame_type == picoquic_frame_type_application_close) {
            *closing_received = 1;
            break;
        } else {
            size_t consumed = 0;
            int pure_ack = 0;

            ret = picoquic_skip_frame(cnx, bytes + byte_index,
                bytes_max - byte_index, &consumed, &pure_ack);
            byte_index += consumed;
        }
    }

    return ret;
}

/* A simple no-op */
static protoop_arg_t protoop_noop(picoquic_cnx_t *cnx)
{
    /* Do nothing! */
    return 0;
}

void frames_register_noparam_protoops(picoquic_cnx_t *cnx)
{
    /* Decoding */
    register_param_protoop_default(cnx, &PROTOOP_PARAM_PARSE_FRAME, &parse_unknown_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_padding, &parse_padding_or_ping_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_reset_stream, &parse_reset_stream_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_connection_close, &parse_connection_close_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_application_close, &parse_application_close_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_max_data, &parse_max_data_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_max_stream_data, &parse_max_stream_data_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_max_streams_bidi,
                           &parse_max_streams_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_max_streams_uni,
                           &parse_max_streams_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_ping, &parse_padding_or_ping_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_data_blocked, &parse_blocked_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_stream_data_blocked, &parse_stream_blocked_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_bidi_streams_blocked, &parse_streams_blocked_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_uni_streams_blocked, &parse_streams_blocked_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_new_connection_id, &parse_new_connection_id_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_retire_connection_id, &parse_retire_connection_id_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_stop_sending, &parse_stop_sending_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_ack, &parse_ack_frame_maybe_ecn);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_path_challenge, &parse_path_challenge_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_path_response, &parse_path_response_frame);
    for (param_id_t p = picoquic_frame_type_stream_range_min; p <= picoquic_frame_type_stream_range_max; p++) {
        register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, p, &parse_stream_frame);
    }
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_crypto_hs, &parse_crypto_hs_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_new_token, &parse_new_token_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_ack_ecn, &parse_ack_frame_maybe_ecn);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_handshake_done, &parse_handshake_done_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_plugin_validate, &parse_plugin_validate_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PARSE_FRAME, picoquic_frame_type_plugin, &parse_plugin_frame);

    register_param_protoop_default(cnx, &PROTOOP_PARAM_PROCESS_FRAME, &process_unknown_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_padding, &process_ignore_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_reset_stream, &process_stream_reset_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_connection_close, &process_connection_close_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_application_close, &process_application_close_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_max_data, &process_max_data_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_max_stream_data, &process_max_stream_data_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_max_streams_bidi, &process_max_stream_id_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_ping, &process_ping_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_data_blocked, &process_ignore_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_stream_data_blocked, &process_ignore_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_bidi_streams_blocked, &process_ignore_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_uni_streams_blocked, &process_ignore_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_new_connection_id, &process_ignore_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_retire_connection_id, &process_ignore_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_stop_sending, &process_stop_sending_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_ack, &process_ack_frame_maybe_ecn);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_path_challenge, &process_path_challenge_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_path_response, &process_path_response_frame);
    for (param_id_t p = picoquic_frame_type_stream_range_min; p <= picoquic_frame_type_stream_range_max; p++) {
        register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, p, &process_stream_frame);
    }
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_crypto_hs, &process_crypto_hs_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_new_token, &process_ignore_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_ack_ecn, &process_ack_frame_maybe_ecn);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_handshake_done, &process_handshake_done_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_plugin_validate, &process_plugin_validate_frame);
    register_param_protoop(cnx, &PROTOOP_PARAM_PROCESS_FRAME, picoquic_frame_type_plugin, &process_plugin_frame);

    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_UPDATE_RTT, &update_rtt);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_UPDATE_ACK_DELAY, &update_ack_delay);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_ESTIMATE_PATH_BANDWIDTH, &estimate_path_bandwidth);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PROCESS_ACK_RANGE, &process_ack_range);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_CHECK_SPURIOUS_RETRANSMISSION, &check_spurious_retransmission);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PROCESS_POSSIBLE_ACK_OF_ACK_FRAME, &process_possible_ack_of_ack_frame);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PROCESS_ACK_OF_STREAM_FRAME, &process_ack_of_stream_frame);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PROCESS_ACK_OF_ACK_RANGE, &process_ack_of_ack_range);

    /* Preparing */
    /** \todo Refactor API */
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREPARE_ACK_FRAME, &prepare_ack_frame);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREPARE_ACK_ECN_FRAME, &prepare_ack_ecn_frame);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREPARE_PATH_CHALLENGE_FRAME, &prepare_path_challenge_frame);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREPARE_CRYPTO_HS_FRAME, &prepare_crypto_hs_frame);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREPARE_HANDSHAKE_DONE_FRAME, &prepare_handshake_done_frame);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREPARE_MISC_FRAME, &prepare_misc_frame);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREPARE_MAX_DATA_FRAME, &prepare_max_data_frame);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREPARE_FIRST_MISC_FRAME, &prepare_first_misc_frame);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREPARE_REQUIRED_MAX_STREAM_DATA_FRAME, &prepare_required_max_stream_data_frames);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREPARE_STREAM_FRAME, &prepare_stream_frame);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_PREPARE_PLUGIN_FRAME, &prepare_plugin_frame);

    register_param_protoop(cnx, &PROTOOP_PARAM_WRITE_FRAME, picoquic_frame_type_plugin_validate, &write_plugin_validate_frame);

    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_FIND_READY_STREAM, &find_ready_stream);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_SCHEDULE_NEXT_STREAM, &find_ready_stream);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_FIND_READY_PLUGIN_STREAM, &find_ready_plugin_stream);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_IS_ACK_NEEDED, &is_ack_needed);
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_IS_TLS_STREAM_READY, &is_tls_stream_ready);

    /* Skipping */
    /** \todo Refactor API, decode_frame split into parse and process param operations */
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_SKIP_FRAME, &skip_frame);

    /* Others */
    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_CHECK_STREAM_FRAME_ALREADY_ACKED, &check_stream_frame_already_acked);

    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_STREAM_BYTES_MAX, &stream_bytes_max);

    register_noparam_protoop(cnx, &PROTOOP_NOPARAM_STREAM_ALWAYS_ENCODE_LENGTH, &stream_always_encode_length);
}
