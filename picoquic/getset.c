#include "getset.h"

static inline protoop_arg_t get_cnx_transport_parameter(picoquic_tp_t *t, uint16_t value) {
    switch (value) {
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
        return t->initial_max_stream_data_bidi_local;
    case TRANSPORT_PARAMETER_INITIAL_MAX_DATA:
        return t->initial_max_data;
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_ID_BIDIR:
        return t->initial_max_stream_id_bidir;
    case TRANSPORT_PARAMETER_IDLE_TIMEOUT:
        return t->idle_timeout;
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
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_ID_UNIDIR:
        return t->initial_max_stream_id_unidir;
    case TRANSPORT_PARAMETER_MIGRATION_DISABLED:
        return t->migration_disabled;
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
    case CNX_AK_PROPOSED_VERSION:
        return cnx->proposed_version;
    case CNX_AK_IS_0RTT_ACCEPTED:
        return cnx->is_0RTT_accepted;
    case CNX_AK_REMOTE_PARMETERS_RECEIVED:
        return cnx->remote_parameters_received;
    case CNX_AK_CURRENT_SPIN:
        return cnx->current_spin;
    case CNX_AK_CLIENT_MODE:
        return cnx->client_mode;
    case CNX_AK_PREV_SPIN:
        return cnx->prev_spin;
    case CNX_AK_SPIN_VEC:
        return cnx->spin_vec;
    case CNX_AK_SPIN_EDGE:
        return cnx->spin_edge;
    case CNX_AK_SPIN_LAST_TRIGGER:
        return cnx->spin_last_trigger;
    case CNX_AK_LOCAL_PARAMETER:
        return get_cnx_transport_parameter(&cnx->local_parameters, param);
    case CNX_AK_REMOTE_PARAMETER:
        return get_cnx_transport_parameter(&cnx->remote_parameters, param);
    case CNX_AK_MAX_EARLY_DATA_SIZE:
        return cnx->max_early_data_size;
    case CNX_AK_STATE:
        return cnx->cnx_state;
    case CNX_AK_INITIAL_CID:
        return (protoop_arg_t) &cnx->initial_cnxid;
    case CNX_AK_LOCAL_CID:
        return (protoop_arg_t) &cnx->local_cnxid;
    case CNX_AK_REMOTE_CID:
        return (protoop_arg_t) &cnx->remote_cnxid;
    case CNX_AK_START_TIME:
        return cnx->start_time;
    case CNX_AK_APPLICATION_ERROR:
        return cnx->application_error;
    case CNX_AK_LOCAL_ERROR:
        return cnx->local_error;
    case CNX_AK_REMOTE_APPLICATION_ERROR:
        return cnx->remote_application_error;
    case CNX_AK_REMOTE_ERROR:
        return cnx->remote_error;
    case CNX_AK_OFFENDING_FRAME_TYPE:
        return cnx->offending_frame_type;
    case CNX_AK_NEXT_WAKE_TIME:
        return cnx->next_wake_time;
    case CNX_AK_LATEST_PROGRESS_TIME:
        return cnx->latest_progress_time;
    case CNX_AK_NB_PATH_CHALLENGE_SENT:
        return cnx->nb_path_challenge_sent;
    case CNX_AK_NB_PATH_RESPONSE_RECEIVED:
        return cnx->nb_path_response_received;
    case CNX_AK_NB_ZERO_RTT_SENT:
        return cnx->nb_zero_rtt_sent;
    case CNX_AK_NB_ZERO_RTT_ACKED:
        return cnx->nb_zero_rtt_acked;
    case CNX_AK_NB_RETRANSMISSION_TOTAL:
        return cnx->nb_retransmission_total;
    case CNX_AK_NB_SPURIOUS:
        return cnx->nb_spurious;
    case CNX_AK_ECN_ECT0_TOTAL_LOCAL:
        return cnx->ecn_ect0_total_local;
    case CNX_AK_ECN_ECT1_TOTAL_LOCAL:
        return cnx->ecn_ect1_total_local;
    case CNX_AK_ECN_CE_TOTAL_LOCAL:
        return cnx->ecn_ce_total_local;
    case CNX_AK_ECN_ECT0_TOTAL_REMOTE:
        return cnx->ecn_ect0_total_remote;
    case CNX_AK_ECN_ECT1_TOTAL_REMOTE:
        return cnx->ecn_ect1_total_remote;
    case CNX_AK_ECN_CE_TOTAL_REMOTE:
        return cnx->ecn_ce_total_remote;
    case CNX_AK_DATA_SENT:
        return cnx->data_sent;
    case CNX_AK_DATA_RECEIVED:
        return cnx->data_received;
    case CNX_AK_MAXDATA_LOCAL:
        return cnx->maxdata_local;
    case CNX_AK_MAXDATA_REMOTE:
        return cnx->maxdata_remote;
    case CNX_AK_MAX_STREAM_ID_BIDIR_LOCAL:
        return cnx->max_stream_id_bidir_local;
    case CNX_AK_MAX_STREAM_ID_UNIDIR_LOCAL:
        return cnx->max_stream_id_unidir_local;
    case CNX_AK_MAX_STREAM_ID_BIDIR_REMOTE:
        return cnx->max_stream_id_bidir_remote;
    case CNX_AK_MAX_STREAM_ID_UNIDIR_REMOTE:
        return cnx->max_stream_id_unidir_remote;
    case CNX_AK_KEEP_ALIVE_INTERVAL:
        return cnx->keep_alive_interval;
    case CNX_AK_NB_PATHS:
        return cnx->nb_paths;
    case CNX_AK_PATH:
        if (param >= cnx->nb_paths) {
            printf("ERROR: trying to get path with index %u, but only %d paths available\n", param, cnx->nb_paths);
            return 0;
        }
        return (protoop_arg_t) cnx->path[param];
    case CNX_AK_CONGESTION_CONTROL_ALGORITHM:
        return (protoop_arg_t) cnx->congestion_alg;
    case CNX_AK_TLS_STREAM:
        if (param >= PICOQUIC_NUMBER_OF_EPOCHS) {
            printf("ERROR: trying to get TLS stream with epoch %u, but only %d epoch available\n", param, PICOQUIC_NUMBER_OF_EPOCHS);
            return 0;
        }
        return (protoop_arg_t) &cnx->tls_stream[param];
    case CNX_AK_CRYPTO_CONTEXT:
        if (param >= PICOQUIC_NUMBER_OF_EPOCHS) {
            printf("ERROR: trying to get crypto context for epoch %u, but only %d epoch available\n", param, PICOQUIC_NUMBER_OF_EPOCHS);
            return 0;
        }
        return (protoop_arg_t) &cnx->crypto_context[param];
    case CNX_AK_INPUT:
        if (param >= cnx->protoop_inputc) {
            printf("ERROR: trying to get input %u, but there are only %d inputs available\n", param, cnx->protoop_inputc);
            return 0;
        }
        return cnx->protoop_inputv[param];
    case CNX_AK_OUTPUT:
        printf("ERROR: trying to get an output\n");
        return 0;
    case CNX_AK_RETRY_TOKEN_LENGTH:
        return cnx->retry_token_length;
    default:
        printf("ERROR: unknown cnx access key %u\n", ak);
        return 0;
    }
}

static inline void set_cnx_transport_parameter(picoquic_tp_t *t, uint16_t value, protoop_arg_t val) {
    switch (value) {
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
        t->initial_max_stream_data_bidi_local = (uint32_t) val;
        break;
    case TRANSPORT_PARAMETER_INITIAL_MAX_DATA:
        t->initial_max_data = (uint32_t) val;
        break;
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_ID_BIDIR:
        t->initial_max_stream_id_bidir = (uint32_t) val;
        break;
    case TRANSPORT_PARAMETER_IDLE_TIMEOUT:
        t->idle_timeout = (uint32_t) val;
        break;
    case TRANSPORT_PARAMETER_PREFERRED_ADDRESS:
        /** FIXME Don't touch this for now */
        printf("ERROR: setting preferred address is not implemented!\n");
        break;
    case TRANSPORT_PARAMETER_MAX_PACKET_SIZE:
        t->max_packet_size = (uint32_t) val;
        break;
    case TRANSPORT_PARAMETER_STATELESS_RESET_TOKEN:
        printf("ERROR: stateless reset token is not implemented!\n");
        break;
    case TRANSPORT_PARAMETER_ACK_DELAY_EXPONENT:
        t->ack_delay_exponent = (uint8_t) val;
        break;
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_ID_UNIDIR:
        t->initial_max_stream_id_unidir = (uint32_t) val;
        break;
    case TRANSPORT_PARAMETER_MIGRATION_DISABLED:
        t->migration_disabled = (uint8_t) val;
        break;
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
        t->initial_max_stream_data_bidi_remote = (uint32_t) val;
        break;
    case TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_UNIDIR:
        t->initial_max_stream_data_uni = (uint32_t) val;
        break;
    default:
        printf("ERROR: unknown transport parameter value %u\n", value);
        break;
    }
}

void set_cnx(picoquic_cnx_t *cnx, access_key_t ak, uint16_t param, protoop_arg_t val)
{
    switch(ak) {
    case CNX_AK_PROPOSED_VERSION:
        cnx->proposed_version = (uint32_t) val;
        break;
    case CNX_AK_IS_0RTT_ACCEPTED:
        cnx->is_0RTT_accepted = (uint8_t) val;
        break;
    case CNX_AK_REMOTE_PARMETERS_RECEIVED:
        cnx->remote_parameters_received = (uint8_t) val;
        break;
    case CNX_AK_CURRENT_SPIN:
        cnx->current_spin = (uint8_t) val;
        break;
    case CNX_AK_CLIENT_MODE:
        cnx->client_mode = (uint8_t) val;
        break;
    case CNX_AK_PREV_SPIN:
        cnx->prev_spin = (uint8_t) val;
        break;
    case CNX_AK_SPIN_VEC:
        cnx->spin_vec = (uint8_t) val;
        break;
    case CNX_AK_SPIN_EDGE:
        cnx->spin_edge = (uint8_t) val;
        break;
    case CNX_AK_SPIN_LAST_TRIGGER:
        cnx->spin_last_trigger = (uint64_t) val;
        break;
    case CNX_AK_LOCAL_PARAMETER:
        set_cnx_transport_parameter(&cnx->local_parameters, param, val);
        break;
    case CNX_AK_REMOTE_PARAMETER:
        set_cnx_transport_parameter(&cnx->remote_parameters, param, val);
        break;
    case CNX_AK_MAX_EARLY_DATA_SIZE:
        cnx->max_early_data_size = (size_t) val;
        break;
    case CNX_AK_STATE:
        cnx->cnx_state = (picoquic_state_enum) val;
        break;
    case CNX_AK_INITIAL_CID:
        printf("ERROR: setting initial CID is not implemented!\n");
        break;
    case CNX_AK_LOCAL_CID:
        printf("ERROR: setting local CID is not implemented!\n");
        break;
    case CNX_AK_REMOTE_CID:
        printf("ERROR: setting remote CID is not implemented!\n");
        break;
    case CNX_AK_START_TIME:
        cnx->start_time = (uint64_t) val;
        break;
    case CNX_AK_APPLICATION_ERROR:
        cnx->application_error = (uint16_t) val;
        break;
    case CNX_AK_LOCAL_ERROR:
        cnx->local_error = (uint16_t) val;
        break;
    case CNX_AK_REMOTE_APPLICATION_ERROR:
        cnx->remote_application_error = (uint16_t) val;
        break;
    case CNX_AK_REMOTE_ERROR:
        cnx->remote_error = (uint16_t) val;
        break;
    case CNX_AK_OFFENDING_FRAME_TYPE:
        cnx->offending_frame_type = (uint64_t) val;
        break;
    case CNX_AK_NEXT_WAKE_TIME:
        cnx->next_wake_time = (uint64_t) val;
        break;
    case CNX_AK_LATEST_PROGRESS_TIME:
        cnx->latest_progress_time = (uint64_t) val;
        break;
    case CNX_AK_NB_PATH_CHALLENGE_SENT:
        cnx->nb_path_challenge_sent = (uint32_t) val;
        break;
    case CNX_AK_NB_PATH_RESPONSE_RECEIVED:
        cnx->nb_path_response_received = (uint32_t) val;
        break;
    case CNX_AK_NB_ZERO_RTT_SENT:
        cnx->nb_zero_rtt_sent = (uint32_t) val;
        break;
    case CNX_AK_NB_ZERO_RTT_ACKED:
        cnx->nb_zero_rtt_acked = (uint32_t) val;
        break;
    case CNX_AK_NB_RETRANSMISSION_TOTAL:
        cnx->nb_retransmission_total = (uint64_t) val;
        break;
    case CNX_AK_NB_SPURIOUS:
        cnx->nb_spurious = (uint64_t) val;
        break;
    case CNX_AK_ECN_ECT0_TOTAL_LOCAL:
        cnx->ecn_ect0_total_local = (uint64_t) val;
        break;
    case CNX_AK_ECN_ECT1_TOTAL_LOCAL:
        cnx->ecn_ect1_total_local = (uint64_t) val;
        break;
    case CNX_AK_ECN_CE_TOTAL_LOCAL:
        cnx->ecn_ce_total_local = (uint64_t) val;
        break;
    case CNX_AK_ECN_ECT0_TOTAL_REMOTE:
        cnx->ecn_ect0_total_remote = (uint64_t) val;
        break;
    case CNX_AK_ECN_ECT1_TOTAL_REMOTE:
        cnx->ecn_ect1_total_remote = (uint64_t) val;
        break;
    case CNX_AK_ECN_CE_TOTAL_REMOTE:
        cnx->ecn_ce_total_remote = (uint64_t) val;
        break;
    case CNX_AK_DATA_SENT:
        cnx->data_sent = (uint64_t) val;
        break;
    case CNX_AK_DATA_RECEIVED:
        cnx->data_received = (uint64_t) val;
        break;
    case CNX_AK_MAXDATA_LOCAL:
        cnx->maxdata_local = (uint64_t) val;
        break;
    case CNX_AK_MAXDATA_REMOTE:
        cnx->maxdata_remote = (uint64_t) val;
        break;
    case CNX_AK_MAX_STREAM_ID_BIDIR_LOCAL:
        cnx->max_stream_id_bidir_local = (uint64_t) val;
        break;
    case CNX_AK_MAX_STREAM_ID_UNIDIR_LOCAL:
        cnx->max_stream_id_unidir_local = (uint64_t) val;
        break;
    case CNX_AK_MAX_STREAM_ID_BIDIR_REMOTE:
        cnx->max_stream_id_bidir_remote = (uint64_t) val;
        break;
    case CNX_AK_MAX_STREAM_ID_UNIDIR_REMOTE:
        cnx->max_stream_id_unidir_remote = (uint64_t) val;
        break;
    case CNX_AK_KEEP_ALIVE_INTERVAL:
        cnx->keep_alive_interval = (uint64_t) val;
        break;
    case CNX_AK_NB_PATHS:
        cnx->nb_paths = (int) val;
        break;
    case CNX_AK_PATH:
        if (param >= cnx->nb_paths) {
            printf("ERROR: trying to set path with index %u, but only %d paths available\n", param, cnx->nb_paths);
            return;
        }
        cnx->path[param] = (picoquic_path_t *) val;
        break;
    case CNX_AK_CONGESTION_CONTROL_ALGORITHM:
        printf("ERROR: setting the congestion control is not implemented!\n");
        break;
    case CNX_AK_TLS_STREAM:
        printf("ERROR: setting the TLS stream is not implemented!\n");
        break;
    case CNX_AK_CRYPTO_CONTEXT:
        printf("ERROR: setting the crypto context is not implemented!\n");
        break;
    case CNX_AK_INPUT:
        printf("ERROR: trying to set an input\n");
        break;
    case CNX_AK_OUTPUT:
        if (param > cnx->protoop_outputc_callee) {
            printf("ERROR: trying to set output %u but only %d outputs so far... You need to insert them sequentially!\n", param, cnx->protoop_outputc_callee);
            return;
        }
        cnx->protoop_outputv[param] = val;
        if (param == cnx->protoop_outputc_callee) {
            cnx->protoop_outputc_callee++;
        }
        break;
    case CNX_AK_RETRY_TOKEN_LENGTH:
        cnx->retry_token_length = (uint32_t) val;
    default:
        printf("ERROR: unknown cnx access key %u\n", ak);
        break;
    }
}