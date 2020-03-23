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

/*
 * Management of transport parameters for PicoQUIC.
 */

#include "picoquic_internal.h"
#include "util.h"
#include <string.h>

#define TP_PRESENT(flags, tp) ((flags & (1 << tp)) != 0)

uint32_t picoquic_decode_transport_param_stream_id(uint16_t rank, int extension_mode, int stream_type) {
    uint32_t stream_id = 0;
    
    if (rank > 0) {
        stream_type |= (extension_mode == 0) ? PICOQUIC_STREAM_ID_SERVER_INITIATED : PICOQUIC_STREAM_ID_CLIENT_INITIATED;

        if (stream_type == 0) {
            stream_id = 4 * rank;
        }
        else {
            stream_id = 4 * (rank - 1) + stream_type;
        }
    }

    return stream_id;
}

uint16_t picoquic_prepare_transport_param_stream_id(uint32_t stream_id, int extension_mode, int stream_type) {
    uint16_t rank = 0;

    if (stream_id > 0) {
        stream_type |= (extension_mode == 0) ? PICOQUIC_STREAM_ID_SERVER_INITIATED: PICOQUIC_STREAM_ID_CLIENT_INITIATED;

        if (stream_type == 0) {
            rank = (uint16_t) (stream_id/4);
        } else {
            rank = (uint16_t) ((stream_id / 4) + 1);
        }
    }

    return rank;
}

uint16_t picoquic_length_transport_param_preferred_address(picoquic_tp_preferred_address_t * preferred_address)
{
    return 4 + 2 + 16 + 2 + 1 + preferred_address->connection_id.id_len + 16;
}

uint16_t picoquic_prepare_transport_param_preferred_address(uint8_t * bytes, size_t bytes_max, 
    picoquic_tp_preferred_address_t * preferred_address)
{
    uint16_t byte_index = 0;
    size_t coded_length = picoquic_length_transport_param_preferred_address(preferred_address);

    if (bytes_max >= coded_length) {
        memcpy(bytes + byte_index, preferred_address->ipv4_address, sizeof(preferred_address->ipv4_address));
        byte_index += sizeof(preferred_address->ipv4_address);
        picoformat_16(bytes + byte_index, preferred_address->ipv4_port);
        byte_index += 2;
        memcpy(bytes + byte_index, preferred_address->ipv6_address, sizeof(preferred_address->ipv6_address));
        byte_index += sizeof(preferred_address->ipv6_address);
        picoformat_16(bytes + byte_index, preferred_address->ipv6_port);
        byte_index += 2;
        bytes[byte_index++] = preferred_address->connection_id.id_len;
        byte_index += (uint16_t) picoquic_format_connection_id(bytes + byte_index, bytes_max - byte_index, preferred_address->connection_id);
        memcpy(bytes + byte_index, preferred_address->stateless_reset_token, 16);
        byte_index += 16;
    }
    return byte_index;
}

size_t picoquic_decode_transport_param_preferred_address(uint8_t * bytes, size_t bytes_max,
    picoquic_tp_preferred_address_t * preferred_address)
{
    /* first compute the minimal length */
    size_t byte_index = 0;
    size_t minimal_length = 4 + 2 + 16 + 2 + 1 + 16;
    size_t ret = 0;

    if (bytes_max < minimal_length) {
        ret = 1;
    } else {
        memcpy(preferred_address->ipv4_address, bytes + byte_index, sizeof(preferred_address->ipv4_address));
        byte_index += sizeof(preferred_address->ipv4_address);
        preferred_address->ipv4_port = PICOPARSE_16(bytes + byte_index);
        byte_index += sizeof(preferred_address->ipv4_port);
        memcpy(preferred_address->ipv6_address, bytes + byte_index, sizeof(preferred_address->ipv6_address));
        byte_index += sizeof(preferred_address->ipv6_address);
        preferred_address->ipv6_port = PICOPARSE_16(bytes + byte_index);
        byte_index += sizeof(preferred_address->ipv6_port);
        preferred_address->connection_id.id_len = bytes[byte_index++];
        if (bytes_max < byte_index + preferred_address->connection_id.id_len + 16) {
            ret = -1;
        } else {
            memcpy(preferred_address->connection_id.id, bytes + byte_index, preferred_address->connection_id.id_len);
            byte_index += preferred_address->connection_id.id_len;
            memcpy(preferred_address->stateless_reset_token, bytes + byte_index, sizeof(preferred_address->stateless_reset_token));
            byte_index += sizeof(preferred_address->stateless_reset_token);
        }
    }

    if (byte_index < bytes_max) {
        ret = 1;
    }

    return ret;
}


uint16_t picoquic_get_list_transport_parameter(char* plugin_tp_list, plugin_list_t* list) {
    uint16_t length = 0;
    for (int i = 0; i < list->size; i++) {
        if (i > 0) {
            plugin_tp_list[length++] = ',';
        }
        strcpy(&plugin_tp_list[length], list->elems[i].plugin_name);
        length += strlen(list->elems[i].plugin_name);
    }
    if (length > 0) {
        plugin_tp_list[length++] = '\0';
    }
    return length;
}


uint16_t picoquic_get_supported_plugins_transport_parameter(picoquic_cnx_t* cnx) {
    if (cnx->quic == NULL || cnx->quic->supported_plugins.size == 0) {
        /* No supported plugins transport parameter */
        return 0;
    }

    cnx->local_parameters.supported_plugins = malloc(sizeof(char) * (
            cnx->quic->supported_plugins.name_num_bytes + cnx->quic->supported_plugins.size));
    if (cnx->local_parameters.supported_plugins == NULL) {
        DBG_PRINTF("Failed to allocate memory for local supported plugins transport param\n");
        return 0;
    }

    return picoquic_get_list_transport_parameter(cnx->local_parameters.supported_plugins, &cnx->quic->supported_plugins);
}


uint16_t picoquic_get_plugins_to_inject_transport_parameter(picoquic_cnx_t* cnx) {
    if (cnx->quic == NULL || cnx->quic->plugins_to_inject.size == 0) {
        /* No plugins to inject transport parameter */
        return 0;
    }

    cnx->local_parameters.plugins_to_inject = malloc(sizeof(char) * (
            cnx->quic->plugins_to_inject.name_num_bytes + cnx->quic->plugins_to_inject.size));
    if (cnx->local_parameters.plugins_to_inject == NULL) {
        DBG_PRINTF("Failed to allocate memory for local plugins to inject transport param\n");
        return 0;
    }

    return picoquic_get_list_transport_parameter(cnx->local_parameters.plugins_to_inject, &cnx->quic->plugins_to_inject);
}

static size_t tp_varint_encode(uint8_t *bytes, size_t bytes_max, uint64_t extension_type, uint64_t extension_value) {
    uint64_t val_len = picoquic_varint_len(extension_value);
    if (bytes_max < picoquic_varint_len(extension_type) + picoquic_varint_len(val_len) + val_len) {
        return -1;
    }
    size_t byte_index = picoquic_varint_encode(bytes, bytes_max, extension_type);
    byte_index += picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, val_len);
    byte_index += picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, extension_value);
    return byte_index;
}

static size_t tp_data_encode(uint8_t *bytes, size_t bytes_max, uint64_t extension_type, uint8_t *extension_value, size_t extension_len) {
    if (bytes_max < picoquic_varint_len(extension_type) + picoquic_varint_len(extension_len) + extension_len) {
        return -1;
    }
    size_t byte_index = picoquic_varint_encode(bytes, bytes_max, extension_type);
    byte_index += picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, extension_len);
    if (extension_len > 0 && extension_value) {
        memcpy(bytes + byte_index, extension_value, extension_len);
        byte_index += extension_len;
    }
    return byte_index;
}

int picoquic_prepare_transport_extensions(picoquic_cnx_t* cnx, int extension_mode,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    size_t min_size = 0;
    uint16_t param_size = 0;

    /* All parameters are now optional, but some are sent always */
    param_size =  (1 + 1 + 4) + (1 + 1 + 4) + (1 + 1 + 2) + (1 + 1 + 2);

    if (cnx->local_parameters.initial_max_streams_bidi != 0) {
        param_size += (1 + 1 + picoquic_varint_len(cnx->local_parameters.initial_max_streams_bidi));
    }

    if (extension_mode == 1) {
        param_size += 1 + 1 + PICOQUIC_RESET_SECRET_SIZE;
    }
    if (cnx->local_parameters.ack_delay_exponent != 3) {
        param_size += (1 + 1 + 1);
    }
    if (cnx->local_parameters.initial_max_streams_uni != 0) {
        param_size += (1 + 1 + 2);
    }
    if (cnx->local_parameters.disable_active_migration != 0) {
        param_size += (1 + 1);
    }
    if (cnx->local_parameters.initial_max_stream_data_bidi_remote > 0) {
        param_size += (1 + 1 + 4);
    }
    if (cnx->local_parameters.initial_max_stream_data_uni > 0) {
        param_size += (1 + 1 + 4);
    }
    if (cnx->local_parameters.max_packet_size >= 1200) {
        param_size += (1 + 1 + 2);
    }

    size_t supported_plugins_len = picoquic_get_supported_plugins_transport_parameter(cnx);
    if (supported_plugins_len > 0) {
        param_size += (1 + 2 + supported_plugins_len);
    }
    size_t plugins_to_insert_len = picoquic_get_plugins_to_inject_transport_parameter(cnx);
    if (plugins_to_insert_len > 0) {
        param_size += (1 + 2 + plugins_to_insert_len);
    }

    min_size += param_size;

    if (min_size > bytes_max) {
        ret = PICOQUIC_ERROR_EXTENSION_BUFFER_TOO_SMALL;
    } else {
        byte_index += tp_varint_encode(bytes + byte_index, bytes_max - byte_index,
                                       picoquic_tp_initial_max_stream_data_bidi_local,
                                       cnx->local_parameters.initial_max_stream_data_bidi_local);

        byte_index += tp_varint_encode(bytes + byte_index, bytes_max - byte_index,
                                       picoquic_tp_initial_max_data,
                                       cnx->local_parameters.initial_max_data);


        if (cnx->local_parameters.initial_max_streams_bidi > 0) {
            byte_index += tp_varint_encode(bytes + byte_index, bytes_max - byte_index,
                                           picoquic_tp_initial_max_streams_bidi,
                                           cnx->local_parameters.initial_max_streams_bidi);

        }

        byte_index += tp_varint_encode(bytes + byte_index, bytes_max - byte_index,
                                       picoquic_tp_max_idle_timeout,
                                       cnx->local_parameters.max_idle_timeout);

        if (cnx->local_parameters.max_packet_size >= 1200) {
            byte_index += tp_varint_encode(bytes + byte_index, bytes_max - byte_index,
                                           picoquic_tp_max_packet_size,
                                           cnx->local_parameters.max_packet_size);
        }

        if (extension_mode == 1) {
            byte_index += tp_data_encode(bytes + byte_index, bytes_max - byte_index, picoquic_tp_stateless_reset_secret,
                    cnx->path[0]->reset_secret, PICOQUIC_RESET_SECRET_SIZE);
        }

        if (cnx->local_parameters.ack_delay_exponent != 3) {
            byte_index += tp_varint_encode(bytes + byte_index, bytes_max - byte_index,
                                           picoquic_tp_ack_delay_exponent,
                                           cnx->local_parameters.ack_delay_exponent);
        }

        if (cnx->local_parameters.initial_max_streams_uni > 0) {
            byte_index += tp_varint_encode(bytes + byte_index, bytes_max - byte_index,
                                           picoquic_tp_initial_max_streams_uni,
                                           cnx->local_parameters.initial_max_streams_uni);
        }

        if (cnx->local_parameters.disable_active_migration != 0) {
            byte_index += tp_data_encode(bytes + byte_index, bytes_max - byte_index, picoquic_tp_disable_active_migration, NULL, 0);
        }

        if (cnx->local_parameters.initial_max_stream_data_bidi_remote > 0) {
            byte_index += tp_varint_encode(bytes + byte_index, bytes_max - byte_index,
                                           picoquic_tp_initial_max_stream_data_bidi_remote,
                                           cnx->local_parameters.initial_max_stream_data_bidi_remote);
        }

        if (cnx->local_parameters.initial_max_stream_data_uni > 0) {
            byte_index += tp_varint_encode(bytes + byte_index, bytes_max - byte_index,
                                           picoquic_tp_initial_max_stream_data_uni,
                                           cnx->local_parameters.initial_max_stream_data_uni);
        }

        if (supported_plugins_len > 0) {
            byte_index += tp_data_encode(bytes + byte_index, bytes_max - byte_index,
                                         picoquic_tp_supported_plugins,
                                         (uint8_t *) cnx->local_parameters.supported_plugins,
                                         supported_plugins_len);
        }

        if (plugins_to_insert_len > 0) {
            byte_index += tp_data_encode(bytes + byte_index, bytes_max - byte_index,
                                         picoquic_tp_plugins_to_inject,
                                         (uint8_t *) cnx->local_parameters.plugins_to_inject,
                                         plugins_to_insert_len);
        }
    }

    *consumed = byte_index;

    return ret;
}

int picoquic_receive_transport_extensions(picoquic_cnx_t* cnx, int extension_mode,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    uint64_t present_flag = 0; /* Provide support up to TP 63 */
    cnx->remote_parameters_received = 1;

    if (byte_index + 2 <= bytes_max) {
        /* Set the parameters to default value */
        memset(&cnx->remote_parameters, 0, sizeof(picoquic_tp_t));
        cnx->remote_parameters.ack_delay_exponent = 3;
        cnx->remote_parameters.max_packet_size = 65527;
        cnx->remote_parameters.max_ack_delay = 25;
        cnx->remote_parameters.active_connection_id_limit = 2;

        while (ret == 0 && byte_index < bytes_max) {
            if (byte_index + 2 > bytes_max) {
                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
            } else {
                uint64_t extension_type;
                byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &extension_type);
                uint64_t extension_length;
                byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &extension_length);

                if (byte_index + extension_length > bytes_max) {
                    ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                } else {
                    size_t extension_val_start = byte_index;

                    switch (extension_type) {  // TP with integer values are varint encoded
                        case picoquic_tp_initial_max_stream_data_bidi_local:
                        case picoquic_tp_initial_max_stream_data_bidi_remote:
                        case picoquic_tp_initial_max_stream_data_uni:
                        case picoquic_tp_initial_max_data:
                        case picoquic_tp_initial_max_streams_bidi:
                        case picoquic_tp_initial_max_streams_uni:
                        case picoquic_tp_ack_delay_exponent:
                        case picoquic_tp_max_idle_timeout:
                        case picoquic_tp_max_ack_delay:
                        case picoquic_tp_active_connection_id_limit:
                           if (extension_length != 1 && extension_length != 2 && extension_length != 4 && extension_length != 8) {
                               ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                               break;
                           }
                    }

                    if (ret == 0 && extension_type < 64) {
                        if ((present_flag & (1UL << extension_type)) != 0) {
                            /* Malformed, already present */
                            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        } else {
                            present_flag |= (1UL << extension_type);
                        }
                    } else {
                        break;
                    }

                    switch (extension_type) {
                    case picoquic_tp_initial_max_stream_data_bidi_local:
                        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &cnx->remote_parameters.initial_max_stream_data_bidi_local);
                        break;
                    case picoquic_tp_initial_max_stream_data_bidi_remote:
                        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &cnx->remote_parameters.initial_max_stream_data_bidi_remote);
                        break;
                    case picoquic_tp_initial_max_stream_data_uni:
                        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &cnx->remote_parameters.initial_max_stream_data_uni);
                        break;
                    case picoquic_tp_initial_max_data:
                        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &cnx->remote_parameters.initial_max_data);
                        cnx->maxdata_remote = cnx->remote_parameters.initial_max_data;
                        cnx->max_stream_id_bidir_remote = STREAM_ID_FROM_RANK(cnx->local_parameters.initial_max_streams_bidi, !cnx->client_mode, 0);
                        break;
                    case picoquic_tp_initial_max_streams_bidi:
                    {
                        uint64_t bidir;
                        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &bidir);

                        cnx->remote_parameters.initial_max_streams_bidi = bidir;
                        cnx->max_stream_id_bidir_remote = picoquic_decode_transport_param_stream_id(bidir, extension_mode, PICOQUIC_STREAM_ID_BIDIR);
                    }
                        break;
                    case picoquic_tp_max_idle_timeout:
                        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &cnx->remote_parameters.max_idle_timeout);
                        break;
                    case picoquic_tp_max_packet_size:
                        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &cnx->remote_parameters.max_packet_size);
                        if (cnx->remote_parameters.max_packet_size < 1200) {
                            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        }
                        break;
                    case picoquic_tp_stateless_reset_secret:
                        if (extension_length != PICOQUIC_RESET_SECRET_SIZE) {
                            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        } else {
                            memcpy(cnx->path[0]->reset_secret, bytes + byte_index, PICOQUIC_RESET_SECRET_SIZE);
                            byte_index += extension_length;
                        }
                        break;
                    case picoquic_tp_ack_delay_exponent:
                        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &cnx->remote_parameters.ack_delay_exponent);
                        if (cnx->remote_parameters.ack_delay_exponent > 20) {
                            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        }
                        break;
                    case picoquic_tp_max_ack_delay:
                        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &cnx->remote_parameters.max_ack_delay);
                        if (cnx->remote_parameters.max_ack_delay > (((uint64_t) 2) << 14)) {
                            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        }
                        break;
                    case picoquic_tp_initial_max_streams_uni:
                    {
                        uint64_t unidir;
                        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &unidir);
                        cnx->remote_parameters.initial_max_streams_uni = unidir;
                        cnx->max_stream_id_unidir_remote = picoquic_decode_transport_param_stream_id(unidir, extension_mode, PICOQUIC_STREAM_ID_UNIDIR);
                    }
                        break;
                    case picoquic_tp_preferred_address:
                        ret = picoquic_decode_transport_param_preferred_address(bytes + byte_index, extension_length, &cnx->remote_parameters.preferred_address);
                        if (ret != 0) {
                            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        }
                        byte_index += extension_length;
                        break;
                    case picoquic_tp_original_connection_id:
                        if (extension_length > PICOQUIC_CONNECTION_ID_MAX_SIZE) {
                            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        } else {
                            cnx->remote_parameters.original_connection_id.id_len = extension_length;
                            memcpy(&cnx->remote_parameters.original_connection_id.id, bytes + byte_index, extension_length);
                            byte_index += extension_length;
                        }
                        break;
                    case picoquic_tp_disable_active_migration:
                        if (extension_length != 0) {
                            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        } else {
                            cnx->remote_parameters.disable_active_migration = 1;
                        }
                        break;
                    case picoquic_tp_active_connection_id_limit:
                        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &cnx->remote_parameters.active_connection_id_limit);
                        if (cnx->remote_parameters.active_connection_id_limit < 2) {
                            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        }
                        break;
                    case picoquic_tp_supported_plugins:
                        if (extension_length > 0) {
                            cnx->remote_parameters.supported_plugins = malloc(sizeof(char) * extension_length);
                            if (cnx->remote_parameters.supported_plugins == NULL) {
                                fprintf(stderr, "Cannot allocate memory for remote supported plugins\n");
                            } else {
                                memcpy(cnx->remote_parameters.supported_plugins, bytes + byte_index, extension_length);
                                byte_index += extension_length;
                            }
                        }
                        break;
                    case picoquic_tp_plugins_to_inject:
                        if (extension_length > 0) {
                            cnx->remote_parameters.plugins_to_inject = malloc(sizeof(char) * extension_length);
                            if (cnx->remote_parameters.plugins_to_inject == NULL) {
                                fprintf(stderr, "Cannot allocate memory for remote plugins to inject\n");
                            } else {
                                memcpy(cnx->remote_parameters.plugins_to_inject, bytes + byte_index, extension_length);
                                byte_index += extension_length;
                            }
                        }
                        break;
                    default:
                        /* ignore unknown extensions */
                        protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_NOPARAM_UNKNOWN_TP_RECEIVED, NULL, extension_type, extension_length, bytes + byte_index);
                        byte_index += extension_length;
                        break;
                    }

                    if (ret == 0 && extension_val_start + extension_length > byte_index) { // There are bytes left over
                        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        break;
                    }

                    switch (extension_type) {
                        case picoquic_tp_initial_max_stream_data_bidi_local:
                        case picoquic_tp_initial_max_stream_data_bidi_remote:
                        case picoquic_tp_initial_max_stream_data_uni:
                            /* If we sent zero rtt data, the streams were created with the
                            * old value of the remote parameter. We need to update that.
                            */
                            picoquic_update_stream_initial_remote(cnx);
                            break;
                    }
                }
            }
        }
    }

    /* Check for TPs that can't be sent by a client */
    if (ret == 0 && extension_mode == 0 &&
        (TP_PRESENT(present_flag, picoquic_tp_original_connection_id) ||
         TP_PRESENT(present_flag, picoquic_tp_stateless_reset_secret) ||
         TP_PRESENT(present_flag, picoquic_tp_preferred_address))) {
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
    }

    *consumed = byte_index;

    return ret;
}
