#include "getset.h"
#include "picoquic_internal.h"

static inline protoop_arg_t get_cnx_transport_parameter(picoquic_tp_t *t, uint16_t value) {
    switch (value) {
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
        return t->initial_max_stream_data_bidi_local;
    case TRANSPORT_PARAMETER_INITIAL_MAX_DATA:
        return t->initial_max_data;
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAMS_BIDI:
        return t->initial_max_streams_bidi;
    case TRANSPORT_PARAMETER_MAX_IDLE_TIMEOUT:
        return t->max_idle_timeout;
    case TRANSPORT_PARAMETER_PREFERRED_ADDRESS:
        /** TODO this should be documented somewhere */
        return (protoop_arg_t) &(t->preferred_address);
    case TRANSPORT_PARAMETER_MAX_PACKET_SIZE:
        return t->max_packet_size;
    case TRANSPORT_PARAMETER_STATELESS_RESET_TOKEN:
        printf("ERROR: stateless reset token is not implemented!\n");
        return 0;
    case TRANSPORT_PARAMETER_ACK_DELAY_EXPONENT:
        return t->ack_delay_exponent;
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAMS_UNI:
        return t->initial_max_streams_uni;
    case TRANSPORT_PARAMETER_MIGRATION_DISABLED:
        return t->disable_active_migration;
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
        return t->initial_max_stream_data_bidi_remote;
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_UNIDIR:
        return t->initial_max_stream_data_uni;
    default:
        printf("ERROR: unknown transport parameter value %u\n", value);
        return 0;
    }
}

protoop_arg_t get_cnx(picoquic_cnx_t *cnx, access_key_t ak, uint16_t param)
{
    switch(ak) {
    case AK_CNX_PROPOSED_VERSION:
        return cnx->proposed_version;
    case AK_CNX_IS_0RTT_ACCEPTED:
        return cnx->is_0RTT_accepted;
    case AK_CNX_REMOTE_PARMETERS_RECEIVED:
        return cnx->remote_parameters_received;
    case AK_CNX_CURRENT_SPIN:
        return cnx->current_spin;
    case AK_CNX_CLIENT_MODE:
        return cnx->client_mode;
    case AK_CNX_PREV_SPIN:
        return cnx->prev_spin;
    case AK_CNX_SPIN_VEC:
        return cnx->spin_vec;
    case AK_CNX_SPIN_EDGE:
        return cnx->spin_edge;
    case AK_CNX_SPIN_LAST_TRIGGER:
        return cnx->spin_last_trigger;
    case AK_CNX_LOCAL_PARAMETER:
        return get_cnx_transport_parameter(&cnx->local_parameters, param);
    case AK_CNX_REMOTE_PARAMETER:
        return get_cnx_transport_parameter(&cnx->remote_parameters, param);
    case AK_CNX_MAX_EARLY_DATA_SIZE:
        return cnx->max_early_data_size;
    case AK_CNX_STATE:
        return cnx->cnx_state;
    case AK_CNX_INITIAL_CID:
        return (protoop_arg_t) &cnx->initial_cnxid;
    case AK_CNX_START_TIME:
        return cnx->start_time;
    case AK_CNX_APPLICATION_ERROR:
        return cnx->application_error;
    case AK_CNX_LOCAL_ERROR:
        return cnx->local_error;
    case AK_CNX_REMOTE_APPLICATION_ERROR:
        return cnx->remote_application_error;
    case AK_CNX_REMOTE_ERROR:
        return cnx->remote_error;
    case AK_CNX_OFFENDING_FRAME_TYPE:
        return cnx->offending_frame_type;
    case AK_CNX_NEXT_WAKE_TIME:
        return cnx->next_wake_time;
    case AK_CNX_LATEST_PROGRESS_TIME:
        return cnx->latest_progress_time;
    case AK_CNX_NB_PATH_CHALLENGE_SENT:
        return cnx->nb_path_challenge_sent;
    case AK_CNX_NB_PATH_RESPONSE_RECEIVED:
        return cnx->nb_path_response_received;
    case AK_CNX_NB_ZERO_RTT_SENT:
        return cnx->nb_zero_rtt_sent;
    case AK_CNX_NB_ZERO_RTT_ACKED:
        return cnx->nb_zero_rtt_acked;
    case AK_CNX_NB_RETRANSMISSION_TOTAL:
        return cnx->nb_retransmission_total;
    case AK_CNX_NB_SPURIOUS:
        return cnx->nb_spurious;
    case AK_CNX_ECN_ECT0_TOTAL_LOCAL:
        return cnx->ecn_ect0_total_local;
    case AK_CNX_ECN_ECT1_TOTAL_LOCAL:
        return cnx->ecn_ect1_total_local;
    case AK_CNX_ECN_CE_TOTAL_LOCAL:
        return cnx->ecn_ce_total_local;
    case AK_CNX_ECN_ECT0_TOTAL_REMOTE:
        return cnx->ecn_ect0_total_remote;
    case AK_CNX_ECN_ECT1_TOTAL_REMOTE:
        return cnx->ecn_ect1_total_remote;
    case AK_CNX_ECN_CE_TOTAL_REMOTE:
        return cnx->ecn_ce_total_remote;
    case AK_CNX_DATA_SENT:
        return cnx->data_sent;
    case AK_CNX_DATA_RECEIVED:
        return cnx->data_received;
    case AK_CNX_MAXDATA_LOCAL:
        return cnx->maxdata_local;
    case AK_CNX_MAXDATA_REMOTE:
        return cnx->maxdata_remote;
    case AK_CNX_MAX_STREAM_ID_BIDIR_LOCAL:
        return cnx->max_stream_id_bidir_local;
    case AK_CNX_MAX_STREAM_ID_UNIDIR_LOCAL:
        return cnx->max_stream_id_unidir_local;
    case AK_CNX_MAX_STREAM_ID_BIDIR_REMOTE:
        return cnx->max_stream_id_bidir_remote;
    case AK_CNX_MAX_STREAM_ID_UNIDIR_REMOTE:
        return cnx->max_stream_id_unidir_remote;
    case AK_CNX_KEEP_ALIVE_INTERVAL:
        return cnx->keep_alive_interval;
    case AK_CNX_NB_PATHS:
        return cnx->nb_paths;
    case AK_CNX_PATH:
        if (param >= cnx->nb_paths) {
            printf("ERROR: trying to get path with index %u, but only %d paths available\n", param, cnx->nb_paths);
            return 0;
        }
        return (protoop_arg_t) cnx->path[param];
    case AK_CNX_CONGESTION_CONTROL_ALGORITHM:
        return (protoop_arg_t) cnx->congestion_alg;
    case AK_CNX_TLS_STREAM:
        if (param >= PICOQUIC_NUMBER_OF_EPOCHS) {
            printf("ERROR: trying to get TLS stream with epoch %u, but only %d epoch available\n", param, PICOQUIC_NUMBER_OF_EPOCHS);
            return 0;
        }
        return (protoop_arg_t) &cnx->tls_stream[param];
    case AK_CNX_CRYPTO_CONTEXT:
        if (param >= PICOQUIC_NUMBER_OF_EPOCHS) {
            printf("ERROR: trying to get crypto context for epoch %u, but only %d epoch available\n", param, PICOQUIC_NUMBER_OF_EPOCHS);
            return 0;
        }
        return (protoop_arg_t) &cnx->crypto_context[param];
    case AK_CNX_INPUT:
        if (param >= cnx->protoop_inputc) {
            printf("ERROR: trying to get input %u, but there are only %d inputs available\n", param, cnx->protoop_inputc);
            return 0;
        }
        return cnx->protoop_inputv[param];
    case AK_CNX_OUTPUT:
        if (param >= cnx->protoop_outputc_callee) {
            printf("ERROR: trying to get output %u but only %d outputs so far...\n", param, cnx->protoop_outputc_callee);
            return 0;
        }
        return cnx->protoop_outputv[param];
    case AK_CNX_RETRY_TOKEN_LENGTH:
        return cnx->retry_token_length;
    case AK_CNX_WAKE_NOW:
        return cnx->wake_now;
    case AK_CNX_RETURN_VALUE:
        return cnx->protoop_output;
    case AK_CNX_RESERVED_FRAMES:
        return (protoop_arg_t) cnx->reserved_frames;
    case AK_CNX_FIRST_MISC_FRAME:
        return (protoop_arg_t) cnx->first_misc_frame;
    case AK_CNX_RETRY_FRAMES:
        return (protoop_arg_t) cnx->retry_frames;
    case AK_CNX_RTX_FRAMES:
        if (param >= picoquic_nb_packet_context) {
            printf("ERROR: trying to get rtx_frames queue for unknown pc %d\n", param);
            return 0;
        }
        return (protoop_arg_t) cnx->rtx_frames[param];
    case AK_CNX_HANDSHAKE_DONE:
        return cnx->handshake_done;
    case AK_CNX_HANDSHAKE_DONE_SENT:
        return cnx->handshake_done_sent;
    case AK_CNX_HANDSHAKE_DONE_ACKED:
        return cnx->handshake_done_acked;
    case AK_CNX_FIRST_STREAM:
        return (protoop_arg_t) cnx->first_stream;
    case AK_CNX_PLUGIN_REQUESTED:
        return cnx->plugin_requested;
    case AK_CNX_PIDS_TO_REQUEST_SIZE:
        return cnx->pids_to_request.size;
    case AK_CNX_PIDS_TO_REQUEST:
        if (param >= cnx->pids_to_request.size) {
            printf("ERROR: trying to get pid to request %u but only %d pid to requests...\n", param, cnx->pids_to_request.size);
            return 0;
        }
        return (protoop_arg_t) &cnx->pids_to_request.elems[param];
    default:
        printf("ERROR: unknown cnx access key %u\n", ak);
        return 0;
    }
}

static inline void set_cnx_transport_parameter(picoquic_tp_t *t, uint16_t value, protoop_arg_t val) {
    switch (value) {
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
        t->initial_max_stream_data_bidi_local = val;
        break;
    case TRANSPORT_PARAMETER_INITIAL_MAX_DATA:
        t->initial_max_data = val;
        break;
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAMS_BIDI:
        t->initial_max_streams_bidi = val;
        break;
    case TRANSPORT_PARAMETER_MAX_IDLE_TIMEOUT:
        t->max_idle_timeout = val;
        break;
    case TRANSPORT_PARAMETER_PREFERRED_ADDRESS:
        /** FIXME Don't touch this for now */
        printf("ERROR: setting preferred address is not implemented!\n");
        break;
    case TRANSPORT_PARAMETER_MAX_PACKET_SIZE:
        t->max_packet_size = val;
        break;
    case TRANSPORT_PARAMETER_STATELESS_RESET_TOKEN:
        printf("ERROR: stateless reset token is not implemented!\n");
        break;
    case TRANSPORT_PARAMETER_ACK_DELAY_EXPONENT:
        t->ack_delay_exponent = val;
        break;
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAMS_UNI:
        t->initial_max_streams_uni = val;
        break;
    case TRANSPORT_PARAMETER_MIGRATION_DISABLED:
        t->disable_active_migration = (unsigned int) val;
        break;
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
        t->initial_max_stream_data_bidi_remote = val;
        break;
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_UNIDIR:
        t->initial_max_stream_data_uni = val;
        break;
    default:
        printf("ERROR: unknown transport parameter value %u\n", value);
        break;
    }
}

void set_cnx(picoquic_cnx_t *cnx, access_key_t ak, uint16_t param, protoop_arg_t val)
{
    switch(ak) {
    case AK_CNX_PROPOSED_VERSION:
        cnx->proposed_version = (uint32_t) val;
        break;
    case AK_CNX_IS_0RTT_ACCEPTED:
        cnx->is_0RTT_accepted = (uint8_t) val;
        break;
    case AK_CNX_REMOTE_PARMETERS_RECEIVED:
        cnx->remote_parameters_received = (uint8_t) val;
        break;
    case AK_CNX_CURRENT_SPIN:
        cnx->current_spin = (uint8_t) val;
        break;
    case AK_CNX_CLIENT_MODE:
        cnx->client_mode = (uint8_t) val;
        break;
    case AK_CNX_PREV_SPIN:
        cnx->prev_spin = (uint8_t) val;
        break;
    case AK_CNX_SPIN_VEC:
        cnx->spin_vec = (uint8_t) val;
        break;
    case AK_CNX_SPIN_EDGE:
        cnx->spin_edge = (uint8_t) val;
        break;
    case AK_CNX_SPIN_LAST_TRIGGER:
        cnx->spin_last_trigger = (uint64_t) val;
        break;
    case AK_CNX_LOCAL_PARAMETER:
        set_cnx_transport_parameter(&cnx->local_parameters, param, val);
        break;
    case AK_CNX_REMOTE_PARAMETER:
        set_cnx_transport_parameter(&cnx->remote_parameters, param, val);
        break;
    case AK_CNX_MAX_EARLY_DATA_SIZE:
        cnx->max_early_data_size = (size_t) val;
        break;
    case AK_CNX_STATE:
        picoquic_set_cnx_state(cnx, (picoquic_state_enum) val);
        break;
    case AK_CNX_INITIAL_CID:
        printf("ERROR: setting initial CID is not implemented!\n");
        break;
    case AK_CNX_START_TIME:
        cnx->start_time = (uint64_t) val;
        break;
    case AK_CNX_APPLICATION_ERROR:
        cnx->application_error = (uint64_t) val;
        break;
    case AK_CNX_LOCAL_ERROR:
        cnx->local_error = val;
        break;
    case AK_CNX_REMOTE_APPLICATION_ERROR:
        cnx->remote_application_error = (uint64_t) val;
        break;
    case AK_CNX_REMOTE_ERROR:
        cnx->remote_error = (uint16_t) val;
        break;
    case AK_CNX_OFFENDING_FRAME_TYPE:
        cnx->offending_frame_type = (uint64_t) val;
        break;
    case AK_CNX_NEXT_WAKE_TIME:
        cnx->next_wake_time = (uint64_t) val;
        break;
    case AK_CNX_LATEST_PROGRESS_TIME:
        cnx->latest_progress_time = (uint64_t) val;
        break;
    case AK_CNX_NB_PATH_CHALLENGE_SENT:
        cnx->nb_path_challenge_sent = (uint32_t) val;
        break;
    case AK_CNX_NB_PATH_RESPONSE_RECEIVED:
        cnx->nb_path_response_received = (uint32_t) val;
        break;
    case AK_CNX_NB_ZERO_RTT_SENT:
        cnx->nb_zero_rtt_sent = (uint32_t) val;
        break;
    case AK_CNX_NB_ZERO_RTT_ACKED:
        cnx->nb_zero_rtt_acked = (uint32_t) val;
        break;
    case AK_CNX_NB_RETRANSMISSION_TOTAL:
        cnx->nb_retransmission_total = (uint64_t) val;
        break;
    case AK_CNX_NB_SPURIOUS:
        cnx->nb_spurious = (uint64_t) val;
        break;
    case AK_CNX_ECN_ECT0_TOTAL_LOCAL:
        cnx->ecn_ect0_total_local = (uint64_t) val;
        break;
    case AK_CNX_ECN_ECT1_TOTAL_LOCAL:
        cnx->ecn_ect1_total_local = (uint64_t) val;
        break;
    case AK_CNX_ECN_CE_TOTAL_LOCAL:
        cnx->ecn_ce_total_local = (uint64_t) val;
        break;
    case AK_CNX_ECN_ECT0_TOTAL_REMOTE:
        cnx->ecn_ect0_total_remote = (uint64_t) val;
        break;
    case AK_CNX_ECN_ECT1_TOTAL_REMOTE:
        cnx->ecn_ect1_total_remote = (uint64_t) val;
        break;
    case AK_CNX_ECN_CE_TOTAL_REMOTE:
        cnx->ecn_ce_total_remote = (uint64_t) val;
        break;
    case AK_CNX_DATA_SENT:
        cnx->data_sent = (uint64_t) val;
        break;
    case AK_CNX_DATA_RECEIVED:
        cnx->data_received = (uint64_t) val;
        break;
    case AK_CNX_MAXDATA_LOCAL:
        cnx->maxdata_local = (uint64_t) val;
        break;
    case AK_CNX_MAXDATA_REMOTE:
        cnx->maxdata_remote = (uint64_t) val;
        break;
    case AK_CNX_MAX_STREAM_ID_BIDIR_LOCAL:
        cnx->max_stream_id_bidir_local = (uint64_t) val;
        break;
    case AK_CNX_MAX_STREAM_ID_UNIDIR_LOCAL:
        cnx->max_stream_id_unidir_local = (uint64_t) val;
        break;
    case AK_CNX_MAX_STREAM_ID_BIDIR_REMOTE:
        cnx->max_stream_id_bidir_remote = (uint64_t) val;
        break;
    case AK_CNX_MAX_STREAM_ID_UNIDIR_REMOTE:
        cnx->max_stream_id_unidir_remote = (uint64_t) val;
        break;
    case AK_CNX_KEEP_ALIVE_INTERVAL:
        cnx->keep_alive_interval = (uint64_t) val;
        break;
    case AK_CNX_NB_PATHS:
        cnx->nb_paths = (int) val;
        break;
    case AK_CNX_PATH:
        if (param >= cnx->nb_paths) {
            printf("ERROR: trying to set path with index %u, but only %d paths available\n", param, cnx->nb_paths);
            return;
        }
        cnx->path[param] = (picoquic_path_t *) val;
        break;
    case AK_CNX_CONGESTION_CONTROL_ALGORITHM:
        printf("ERROR: setting the congestion control is not implemented!\n");
        break;
    case AK_CNX_TLS_STREAM:
        printf("ERROR: setting the TLS stream is not implemented!\n");
        break;
    case AK_CNX_CRYPTO_CONTEXT:
        printf("ERROR: setting the crypto context is not implemented!\n");
        break;
    case AK_CNX_INPUT:
        printf("ERROR: trying to set an input\n");
        break;
    case AK_CNX_OUTPUT:
        if (param > cnx->protoop_outputc_callee) {
            printf("ERROR: trying to set output %u but only %d outputs so far... You need to insert them sequentially!\n", param, cnx->protoop_outputc_callee);
            return;
        }
        cnx->protoop_outputv[param] = val;
        if (param == cnx->protoop_outputc_callee) {
            cnx->protoop_outputc_callee++;
        }
        break;
    case AK_CNX_RETRY_TOKEN_LENGTH:
        cnx->retry_token_length = (uint32_t) val;
        break;
    case AK_CNX_WAKE_NOW:
        cnx->wake_now = (uint8_t) val;
        break;
    case AK_CNX_RETURN_VALUE:
        printf("ERROR: trying to modify return value...\n");
        break;
    case AK_CNX_RESERVED_FRAMES:
        printf("ERROR: trying to modify reserved frames...\n");
        break;
    case AK_CNX_RETRY_FRAMES:
        printf("ERROR: trying to modify retry frames...\n");
        break;
    case AK_CNX_FIRST_MISC_FRAME:
        printf("ERROR: trying to modify first misc frame...\n");
        break;
    case AK_CNX_RTX_FRAMES:
        printf("ERROR: trying to modify rtx frames...\n");
        break;
    case AK_CNX_HANDSHAKE_DONE:
        printf("ERROR: trying to modify handshake_done...\n");
        break;
    case AK_CNX_HANDSHAKE_DONE_SENT:
        printf("ERROR: trying to modify handshake_done_sent...\n");
        break;
    case AK_CNX_HANDSHAKE_DONE_ACKED:
        printf("ERROR: trying to modify handshake_done_acked...\n");
    break;
    case AK_CNX_PLUGIN_REQUESTED:
        cnx->plugin_requested = (uint8_t) val;
        break;
    case AK_CNX_PIDS_TO_REQUEST_SIZE:
        cnx->pids_to_request.size = (uint16_t) val;
        break;
    case AK_CNX_PIDS_TO_REQUEST:
        printf("ERROR: trying to modify pids to request...\n");
        break;
    default:
        printf("ERROR: unknown cnx access key %u\n", ak);
        break;
    }
}

void set_cnx_metadata(picoquic_cnx_t *cnx, int idx, protoop_arg_t val) {
    if (!cnx->current_plugin) {
        printf("ERROR: %s called outside a plugin context\n", __func__);
        return;
    }
    if (set_plugin_metadata(cnx->current_plugin, &cnx->metadata, idx, val))
        printf("ERROR: %s returned a non-zero error code\n", __func__);
}


protoop_arg_t get_cnx_metadata(picoquic_cnx_t *cnx, int idx) {
    if (!cnx->current_plugin) {
        printf("ERROR: %s called outside a plugin context\n", __func__);
        return -1;
    }
    uint64_t out;
    int err = get_plugin_metadata(cnx->current_plugin, &cnx->metadata, idx, &out);
    if (err)
        printf("ERROR: %s returned a non-zero error code\n", __func__);
    return out;
}

protoop_arg_t get_path(picoquic_path_t *path, access_key_t ak, uint16_t param)
{
    switch(ak) {
    case AK_PATH_PEER_ADDR:
        return (protoop_arg_t) &path->peer_addr;
    case AK_PATH_PEER_ADDR_LEN:
        return path->peer_addr_len;
    case AK_PATH_LOCAL_ADDR:
        return (protoop_arg_t) &path->local_addr;
    case AK_PATH_LOCAL_ADDR_LEN:
        return path->local_addr_len;
    case AK_PATH_IF_INDEX_LOCAL:
        return path->if_index_local;
    case AK_PATH_CHALLENGE:
        return path->challenge;
    case AK_PATH_CHALLENGE_TIME:
        return path->challenge_time;
    case AK_PATH_CHALLENGE_RESPONSE:
        return (protoop_arg_t) path->challenge_response;
    case AK_PATH_CHALLENGE_REPEAT_COUNT:
        return path->challenge_repeat_count;
    case AK_PATH_MTU_PROBE_SENT:
        return path->mtu_probe_sent;
    case AK_PATH_CHALLENGE_VERIFIED:
        return path->challenge_verified;
    case AK_PATH_CHALLENGE_RESPONSE_TO_SEND:
        return path->challenge_response_to_send;
    case AK_PATH_PING_RECEIVED:
        return path->ping_received;
    case AK_PATH_MAX_ACK_DELAY:
        return path->max_ack_delay;
    case AK_PATH_SMOOTHED_RTT:
        return path->smoothed_rtt;
    case AK_PATH_RTT_VARIANT:
        return path->rtt_variant;
    case AK_PATH_RETRANSMIT_TIMER:
        return path->retransmit_timer;
    case AK_PATH_RTT_MIN:
        return path->rtt_min;
    case AK_PATH_MAX_SPURIOUS_RTT:
        return path->max_spurious_rtt;
    case AK_PATH_MAX_REORDER_DELAY:
        return path->max_reorder_delay;
    case AK_PATH_MAX_REORDER_GAP:
        return path->max_reorder_gap;
    case AK_PATH_SEND_MTU:
        return path->send_mtu;
    case AK_PATH_SEND_MTU_MAX_TRIED:
        return path->send_mtu_max_tried;
    case AK_PATH_CWIN:
        return path->cwin;
    case AK_PATH_BYTES_IN_TRANSIT:
        return path->bytes_in_transit;
    case AK_PATH_CONGESTION_ALGORITHM_STATE:
        return (protoop_arg_t) path->congestion_alg_state;
    case AK_PATH_PACKET_EVALUATION_TIME:
        return path->pacing_evaluation_time;
    case AK_PATH_PACING_BUCKET_NANO_SEC:
        return path->pacing_bucket_nanosec;
    case AK_PATH_PACING_BUCKET_MAX:
        return path->pacing_bucket_max;
    case AK_PATH_PACING_PACKET_TIME_NANOSEC:
        return path->pacing_packet_time_nanosec;
    case AK_PATH_PACING_PACKET_TIME_MICROSEC:
        return path->pacing_packet_time_nanosec;
    case AK_PATH_LOCAL_CID:
        return (protoop_arg_t) &path->local_cnxid;
    case AK_PATH_REMOTE_CID:
        return (protoop_arg_t) &path->remote_cnxid;
    case AK_PATH_RESET_SECRET:
        return (protoop_arg_t) &path->reset_secret;
    case AK_PATH_PKT_CTX:
        if (param >= picoquic_nb_packet_context) {
            printf("ERROR: accessing pc %u but max value is %u\n", param, picoquic_nb_packet_context);
            return 0;
        }
        return (protoop_arg_t) &path->pkt_ctx[param];
    case AK_PATH_NB_PKT_SENT:
        return path->nb_pkt_sent;
    case AK_PATH_DELIVERED:
        return path->delivered;
    case AK_PATH_DELIVERED_PRIOR:
        return path->delivered;
    case AK_PATH_DELIVERED_LIMITED_INDEX:
        return path->delivered_limited_index;
    case AK_PATH_RTT_SAMPLE:
        return path->rtt_sample;
    default:
        printf("ERROR: unknown path access key %u\n", ak);
        return 0;
    }
}

void set_path(picoquic_path_t *path, access_key_t ak, uint16_t param, protoop_arg_t val)
{
    switch(ak) {
    case AK_PATH_PEER_ADDR:
        printf("ERROR: setting the peer addr is not implemented!\n");
        break;
    case AK_PATH_PEER_ADDR_LEN:
        path->peer_addr_len = (int) val;
        break;
    case AK_PATH_LOCAL_ADDR:
        printf("ERROR: setting the local addr is not implemented!\n");
        break;
    case AK_PATH_LOCAL_ADDR_LEN:
        path->local_addr_len = (int) val;
        break;
    case AK_PATH_IF_INDEX_LOCAL:
        path->if_index_local = (int) val;
        break;
    case AK_PATH_CHALLENGE:
        path->challenge = val;
        break;
    case AK_PATH_CHALLENGE_TIME:
        path->challenge_time =val;
        break;
    case AK_PATH_CHALLENGE_RESPONSE:
        printf("ERROR: setting the challenge response is not implemented!\n");
        break;
    case AK_PATH_CHALLENGE_REPEAT_COUNT:
        path->challenge_repeat_count = (uint8_t) val;
        break;
    case AK_PATH_MTU_PROBE_SENT:
        path->mtu_probe_sent = val;
        break;
    case AK_PATH_CHALLENGE_VERIFIED:
        path->challenge_verified = val;
        break;
    case AK_PATH_CHALLENGE_RESPONSE_TO_SEND:
        path->challenge_response_to_send = val;
        break;
    case AK_PATH_PING_RECEIVED:
        path->ping_received = val;
        break;
    case AK_PATH_MAX_ACK_DELAY:
        path->max_ack_delay = val;
        break;
    case AK_PATH_SMOOTHED_RTT:
        path->smoothed_rtt = val;
        break;
    case AK_PATH_RTT_VARIANT:
        path->rtt_variant = val;
        break;
    case AK_PATH_RETRANSMIT_TIMER:
        path->retransmit_timer = val;
        break;
    case AK_PATH_RTT_MIN:
        path->rtt_min = val;
        break;
    case AK_PATH_MAX_SPURIOUS_RTT:
        path->max_spurious_rtt = val;
        break;
    case AK_PATH_MAX_REORDER_DELAY:
        path->max_reorder_delay = val;
        break;
    case AK_PATH_MAX_REORDER_GAP:
        path->max_reorder_gap = val;
        break;
    case AK_PATH_SEND_MTU:
        path->send_mtu = val;
        break;
    case AK_PATH_SEND_MTU_MAX_TRIED:
        path->send_mtu_max_tried = val;
        break;
    case AK_PATH_CWIN:
        path->cwin = val;
        break;
    case AK_PATH_BYTES_IN_TRANSIT:
        path->bytes_in_transit = val;
        break;
    case AK_PATH_CONGESTION_ALGORITHM_STATE:
        printf("ERROR: setting the congestion algorithm state is not implemented!\n");
        break;
    case AK_PATH_PACKET_EVALUATION_TIME:
        path->pacing_evaluation_time = val;
        break;
    case AK_PATH_PACING_BUCKET_NANO_SEC:
        path->pacing_bucket_nanosec = val;
        break;
    case AK_PATH_PACING_BUCKET_MAX:
        path->pacing_bucket_max = val;
        break;
    case AK_PATH_PACING_PACKET_TIME_NANOSEC:
        path->pacing_packet_time_nanosec = val;
        break;
    case AK_PATH_PACING_PACKET_TIME_MICROSEC:
        path->pacing_packet_time_nanosec = val;
        break;
    case AK_PATH_LOCAL_CID:
        printf("ERROR: setting the local CID is not implemented!\n");
        break;
    case AK_PATH_REMOTE_CID:
        printf("ERROR: setting the remote CID is not implemented!\n");
        break;
    case AK_PATH_RESET_SECRET:
        printf("ERROR: setting the reset secret is not implemented!\n");
        break;
    case AK_PATH_PKT_CTX:
        printf("ERROR: setting the pkt ctx is not implemented!\n");
        break;
    case AK_PATH_NB_PKT_SENT:
        path->nb_pkt_sent = val;
        break;
    case AK_PATH_DELIVERED_LIMITED_INDEX:
        path->delivered_limited_index = val;
        break;
    case AK_PATH_RTT_SAMPLE:
        path->rtt_sample = val;
        break;
    default:
        printf("ERROR: unknown path access key %u\n", ak);
        break;
    }
}

void set_path_metadata(picoquic_cnx_t *cnx, picoquic_path_t *path, int idx, protoop_arg_t val) {
    if (!cnx->current_plugin) {
        printf("ERROR: %s called outside a plugin context\n", __func__);
        return;
    }
    if (set_plugin_metadata(cnx->current_plugin, &path->metadata, idx, val))
        printf("ERROR: %s returned a non-zero error code\n", __func__);
}


protoop_arg_t get_path_metadata(picoquic_cnx_t *cnx, picoquic_path_t *path, int idx) {
    if (!cnx->current_plugin) {
        printf("ERROR: %s called outside a plugin context\n", __func__);
        return -1;
    }
    uint64_t out;
    int err = get_plugin_metadata(cnx->current_plugin, &path->metadata, idx, &out);
    if (err)
        printf("ERROR: %s returned a non-zero error code\n", __func__);
    return out;
}


protoop_arg_t get_pkt_ctx(picoquic_packet_context_t *pkt_ctx, access_key_t ak)
{
    switch(ak) {
    case AK_PKTCTX_SEND_SEQUENCE:
        return pkt_ctx->send_sequence;
    case AK_PKTCTX_FIRST_SACK_ITEM:
        return (protoop_arg_t) &pkt_ctx->first_sack_item;
    case AK_PKTCTX_TIME_STAMP_LARGEST_RECEIVED:
        return pkt_ctx->time_stamp_largest_received;
    case AK_PKTCTX_HIGHEST_ACK_SENT:
        return pkt_ctx->highest_ack_sent;
    case AK_PKTCTX_HIGHEST_ACK_TIME:
        return pkt_ctx->highest_ack_time;
    case AK_PKTCTX_ACK_DELAY_LOCAL:
        return pkt_ctx->ack_delay_local;
    case AK_PKTCTX_NB_RETRANSMIT:
        return pkt_ctx->nb_retransmit;
    case AK_PKTCTX_LATEST_RETRANSMIT_TIME:
        return pkt_ctx->latest_retransmit_time;
    case AK_PKTCTX_LATEST_RETRANSMIT_CC_NOTIFICATION_TIME:
        return pkt_ctx->latest_retransmit_cc_notification_time;
    case AK_PKTCTX_HIGHEST_ACKNOWLEDGED:
        return pkt_ctx->highest_acknowledged;
    case AK_PKTCTX_LATEST_TIME_ACKNOWLEDGED:
        return pkt_ctx->latest_time_acknowledged;
    case AK_PKTCTX_RETRANSMIT_NEWEST:
        return (protoop_arg_t) pkt_ctx->retransmit_newest;
    case AK_PKTCTX_RETRANSMIT_OLDEST:
        return (protoop_arg_t) pkt_ctx->retransmit_oldest;
    case AK_PKTCTX_RETRANSMITTED_NEWEST:
        return (protoop_arg_t) pkt_ctx->retransmitted_newest;
    case AK_PKTCTX_RETRANSMITTED_OLDEST:
        return (protoop_arg_t) pkt_ctx->retransmitted_oldest;
    case AK_PKTCTX_ACK_NEEDED:
        return pkt_ctx->ack_needed;
    case AK_PKTCTX_LATEST_PROGRESS_TIME:
        return pkt_ctx->latest_progress_time;
    default:
        printf("ERROR: unknown pkt ctx access key %u\n", ak);
        return 0;
    }
}

void set_pkt_ctx(picoquic_packet_context_t *pkt_ctx, access_key_t ak, protoop_arg_t val)
{
    switch(ak) {
    case AK_PKTCTX_SEND_SEQUENCE:
        pkt_ctx->send_sequence = val;
        break;
    case AK_PKTCTX_FIRST_SACK_ITEM:
        printf("ERROR: setting the first sack item is not implemented!\n");
        break;
    case AK_PKTCTX_TIME_STAMP_LARGEST_RECEIVED:
        pkt_ctx->time_stamp_largest_received = val;
        break;
    case AK_PKTCTX_HIGHEST_ACK_SENT:
        pkt_ctx->highest_ack_sent = val;
        break;
    case AK_PKTCTX_HIGHEST_ACK_TIME:
        pkt_ctx->highest_ack_time = val;
        break;
    case AK_PKTCTX_ACK_DELAY_LOCAL:
        pkt_ctx->ack_delay_local = val;
        break;
    case AK_PKTCTX_NB_RETRANSMIT:
        pkt_ctx->nb_retransmit = val;
        break;
    case AK_PKTCTX_LATEST_RETRANSMIT_TIME:
        pkt_ctx->latest_retransmit_time = val;
    case AK_PKTCTX_LATEST_RETRANSMIT_CC_NOTIFICATION_TIME:
        pkt_ctx->latest_retransmit_cc_notification_time = val;
        break;
    case AK_PKTCTX_HIGHEST_ACKNOWLEDGED:
        pkt_ctx->highest_acknowledged = val;
        break;
    case AK_PKTCTX_LATEST_TIME_ACKNOWLEDGED:
        pkt_ctx->latest_time_acknowledged = val;
        break;
    case AK_PKTCTX_RETRANSMIT_NEWEST:
        printf("ERROR: setting the retransmit newest is not implemented!\n");
        break;
    case AK_PKTCTX_RETRANSMIT_OLDEST:
        printf("ERROR: setting the retransmit oldest is not implemented!\n");
        break;
    case AK_PKTCTX_RETRANSMITTED_NEWEST:
        printf("ERROR: setting the retransmitted newest is not implemented!\n");
        break;
    case AK_PKTCTX_RETRANSMITTED_OLDEST:
        printf("ERROR: setting the retransmitted oldest is not implemented!\n");
        break;
    case AK_PKTCTX_ACK_NEEDED:
        pkt_ctx->ack_needed = val;
        break;
    default:
        printf("ERROR: unknown pkt ctx access key %u\n", ak);
        break;
    }
}

void set_pkt_metadata(picoquic_cnx_t *cnx, picoquic_packet_t *pkt, int idx, protoop_arg_t val) {
    if (!cnx->current_plugin) {
        printf("ERROR: %s called outside a plugin context\n", __func__);
        return;
    }
    if (set_plugin_metadata(cnx->current_plugin, &pkt->metadata, idx, val))
        printf("ERROR: %s returned a non-zero error code\n", __func__);
}


protoop_arg_t get_pkt_metadata(picoquic_cnx_t *cnx, picoquic_packet_t *pkt, int idx) {
    if (!cnx->current_plugin) {
        printf("ERROR: %s called outside a plugin context\n", __func__);
        return -1;
    }
    uint64_t out;
    int err = get_plugin_metadata(cnx->current_plugin, &pkt->metadata, idx, &out);
    if (err)
        printf("ERROR: %s returned a non-zero error code\n", __func__);
    return out;
}

protoop_arg_t get_pkt(picoquic_packet_t *pkt, access_key_t ak)
{
    switch(ak) {
    case AK_PKT_PREVIOUS_PACKET:
        return (protoop_arg_t) pkt->previous_packet;
    case AK_PKT_NEXT_PACKET:
        return (protoop_arg_t) pkt->next_packet;
    case AK_PKT_SEND_PATH:
        return (protoop_arg_t) pkt->send_path;
    case AK_PKT_SEQUENCE_NUMBER:
        return pkt->sequence_number;
    case AK_PKT_SEND_TIME:
        return pkt->send_time;
    case AK_PKT_LENGTH:
        return pkt->length;
    case AK_PKT_CHECKSUM_OVERHEAD:
        return pkt->checksum_overhead;
    case AK_PKT_OFFSET:
        return pkt->offset;
    case AK_PKT_TYPE:
        return pkt->ptype;
    case AK_PKT_CONTEXT:
        return pkt->pc;
    case AK_PKT_IS_PURE_ACK:
        return pkt->is_pure_ack;
    case AK_PKT_CONTAINS_CRYPTO:
        return pkt->contains_crypto;
    case AK_PKT_HAS_HANDSHAKE_DONE:
        return pkt->has_handshake_done;
    case AK_PKT_IS_CONGESTION_CONTROLLED:
        return pkt->is_congestion_controlled;
    case AK_PKT_BYTES:
        return (protoop_arg_t) pkt->bytes;
    case AK_PKT_IS_MTU_PROBE:
        return pkt->is_mtu_probe;
    case AK_PKT_DELIVERED_PRIOR:
        return pkt->delivered_prior;
    case AK_PKT_DELIVERED_TIME_PRIOR:
        return pkt->delivered_time_prior;
    case AK_PKT_DELIVERED_SENT_PRIOR:
        return pkt->delivered_sent_prior;
    case AK_PKT_DELIVERED_APP_LIMITED:
        return pkt->delivered_app_limited;
    default:
        printf("ERROR: unknown pkt access key %u\n", ak);
        return 0;
    }
}

void set_pkt(picoquic_packet_t *pkt, access_key_t ak, protoop_arg_t val)
{
    switch(ak) {
    case AK_PKT_PREVIOUS_PACKET:
        printf("ERROR: setting the previous packet is not implemented!\n");
        break;
    case AK_PKT_NEXT_PACKET:
        printf("ERROR: setting the next packet is not implemented!\n");
        break;
    case AK_PKT_SEND_PATH:
        /* TODO check the path is valid pointer */
        pkt->send_path = (picoquic_path_t *) val;
        break;
    case AK_PKT_SEQUENCE_NUMBER:
        pkt->sequence_number = val;
        break;
    case AK_PKT_SEND_TIME:
        pkt->send_time = val;
        break;
    case AK_PKT_LENGTH:
        pkt->length = val;
        break;
    case AK_PKT_CHECKSUM_OVERHEAD:
        pkt->checksum_overhead = val;
        break;
    case AK_PKT_OFFSET:
        pkt->offset = val;
        break;
    case AK_PKT_TYPE:
        if (val >= picoquic_packet_type_max) {
            printf("ERROR: setting type %" PRIu64 " but max value is %u\n", val, picoquic_packet_type_max);
            break;
        }
        pkt->ptype = (picoquic_packet_type_enum) val;
        break;
    case AK_PKT_CONTEXT:
        if (val >= picoquic_nb_packet_context) {
            printf("ERROR: setting context %" PRIu64 " but max value is %u\n", val, picoquic_nb_packet_context);
            break;
        }
        pkt->pc = (picoquic_packet_context_enum) val;
        break;
    case AK_PKT_IS_PURE_ACK:
        pkt->is_pure_ack = val;
        break;
    case AK_PKT_CONTAINS_CRYPTO:
        pkt->contains_crypto = val;
        break;
    case AK_PKT_HAS_HANDSHAKE_DONE:
        pkt->has_handshake_done = (unsigned int) val;
    case AK_PKT_IS_CONGESTION_CONTROLLED:
        pkt->is_congestion_controlled = val;
        break;
    case AK_PKT_BYTES:
        printf("ERROR: setting bytes is not implemented!\n");
        break;
    case AK_PKT_IS_MTU_PROBE:
        pkt->is_mtu_probe = val;
        break;
    default:
        printf("ERROR: unknown pkt access key %u\n", ak);
        break;
    }
}

protoop_arg_t get_sack_item(picoquic_sack_item_t *sack_item, access_key_t ak)
{
    switch(ak) {
    case AK_SACKITEM_NEXT_SACK:
        return (protoop_arg_t) sack_item->next_sack;
    case AK_SACKITEM_START_RANGE:
        return sack_item->start_of_sack_range;
    case AK_SACKITEM_END_RANGE:
        return sack_item->end_of_sack_range;
    default:
        printf("ERROR: unknown sack item access key %u\n", ak);
        return 0;
    }
}

void set_sack_item(picoquic_sack_item_t *sack_item, access_key_t ak, protoop_arg_t val)
{
    switch(ak) {
    case AK_SACKITEM_NEXT_SACK:
        printf("ERROR: setting next sack is not implemented!\n");
        break;
    case AK_SACKITEM_START_RANGE:
        sack_item->start_of_sack_range = val;
        break;
    case AK_SACKITEM_END_RANGE:
        sack_item->end_of_sack_range = val;
        break;
    default:
        printf("ERROR: unknown sack_item access key %u\n", ak);
        break;
    }
}

protoop_arg_t get_cnxid(picoquic_connection_id_t *cnxid, access_key_t ak)
{
    switch(ak) {
    case AK_CNXID_ID:
        return (protoop_arg_t) cnxid->id;
    case AK_CNXID_LEN:
        return cnxid->id_len;
    default:
        printf("ERROR: unknown connection id access key %u\n", ak);
        return 0;
    }
}

void set_cnxid(picoquic_connection_id_t *cnxid, access_key_t ak, protoop_arg_t val)
{
    switch(ak) {
    case AK_CNXID_ID:
        printf("ERROR: setting cnxid id is not implemented!\n");
        break;
    case AK_CNXID_LEN:
        cnxid->id_len = (uint8_t) val;
        break;
    default:
        printf("ERROR: unknown connection id access key %u\n", ak);
        break;
    }
}

protoop_arg_t get_stream_head(picoquic_stream_head *stream_head, access_key_t ak)
{
    switch(ak) {
    case AK_STREAMHEAD_SEND_QUEUE:
        return (protoop_arg_t) stream_head->send_queue;
    case AK_STREAMHEAD_CONSUMED_OFFSET:
        return stream_head->consumed_offset;
    case AK_STREAMHEAD_NEXT_STREAM:
        return (protoop_arg_t) stream_head->next_stream;
    case AK_STREAMHEAD_STREAM_ID:
        return stream_head->stream_id;
    case AK_STREAMHEAD_MAX_DATA_REMOTE:
        return stream_head->maxdata_remote;
    case AK_STREAMHEAD_SENT_OFFSET:
        return stream_head->sent_offset;
    case AK_STREAMHEAD_STREAM_FLAGS:
        return stream_head->stream_flags;
    case AK_STREAMHEAD_SENDING_OFFSET:
        return stream_head->sending_offset;
    default:
        printf("ERROR: unknown stream head access key %u\n", ak);
        return 0;
    }
}

void set_stream_head(picoquic_stream_head *stream_head, access_key_t ak, protoop_arg_t val)
{
    switch(ak) {
    case AK_STREAMHEAD_SEND_QUEUE:
        printf("ERROR: setting send queue is not implemented!\n");
        break;
    case AK_STREAMHEAD_CONSUMED_OFFSET:
        stream_head->consumed_offset = val;
        break;
    default:
        printf("ERROR: unknown stream head access key %u\n", ak);
        break;
    }
}

protoop_arg_t get_stream_data(picoquic_stream_data *stream_data, access_key_t ak)
{
    switch(ak) {
        case AK_STREAMDATA_LENGTH:
            return stream_data->length;
        case AK_STREAMDATA_OFFSET:
            return stream_data->offset;
        default:
            printf("ERROR: unknown stream head access key %u\n", ak);
            return 0;
    }
}

protoop_arg_t get_crypto_context(picoquic_crypto_context_t *crypto_context, access_key_t ak)
{
    switch(ak) {
    case AK_CRYPTOCONTEXT_AEAD_ENCRYPTION:
        return (protoop_arg_t) crypto_context->aead_encrypt;
    default:
        printf("ERROR: unknown stream head access key %u\n", ak);
        return 0;
    }
}

void set_crypto_context(picoquic_crypto_context_t *crypto_context, access_key_t ak, protoop_arg_t val)
{
    switch(ak) {
    case AK_CRYPTOCONTEXT_AEAD_ENCRYPTION:
        printf("ERROR: setting aead encryption is not implemented!\n");
        break;
    default:
        printf("ERROR: unknown stream head access key %u\n", ak);
        break;
    }
}

protoop_arg_t get_ph(picoquic_packet_header *ph, access_key_t ak)
{
    switch(ak) {
    case AK_PH_DESTINATION_CNXID:
        return (protoop_arg_t) &ph->dest_cnx_id;
    case AK_PH_OFFSET:
        return (protoop_arg_t) ph->offset;
    case AK_PH_PAYLOAD_LENGTH:
        return (protoop_arg_t) ph->payload_length;
    case AK_PH_SEQUENCE_NUMBER:
        return (protoop_arg_t) ph->pn64;
    case AK_PH_EPOCH:
        return (protoop_arg_t) ph->epoch;
    case AK_PH_PTYPE:
        return ph->ptype;
    default:
        printf("ERROR: unknown packet header access key %u\n", ak);
        return 0;
    }
}

void set_ph(picoquic_packet_header *ph, access_key_t ak, protoop_arg_t val)
{
    switch(ak) {
    case AK_PH_DESTINATION_CNXID:
        printf("ERROR: setting destination connection id is not implemented\n");
        break;
    default:
        printf("ERROR: unknown packet header access key %u\n", ak);
        break;
    }
}

protoop_arg_t get_preq(plugin_req_pid_t *preq, access_key_t ak)
{
    switch (ak) {
    case AK_PIDREQ_PID_ID:
        return preq->pid_id;
    case AK_PIDREQ_PLUGIN_NAME:
        return (protoop_arg_t) preq->plugin_name;
    case AK_PIDREQ_REQUESTED:
        return preq->requested;
    default:
        printf("ERROR: unknown pid req access key %u\n", ak);
        return 0;
    }
}

void set_preq(plugin_req_pid_t *preq, access_key_t ak, protoop_arg_t val)
{
    switch (ak) {
    case AK_PIDREQ_PID_ID:
        printf("ERROR: setting pid id is not implemented\n");
        break;
    case AK_PIDREQ_PLUGIN_NAME:
        printf("ERROR: setting plugin name is not implemented\n");
        break;
    case AK_PIDREQ_REQUESTED:
        preq->requested = val;
        break;
    default:
        printf("ERROR: unknown pid req access key %u\n", ak);
        break;
    }
}
