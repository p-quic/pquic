#include "getset.h"

static inline protoop_arg_t get_cnx_transport_parameter(picoquic_tp_t *t, uint16_t value) {
    switch (value) {
    case 0x00:
        return t->initial_max_stream_data_bidi_local;
    case 0x01:
        return t->initial_max_data;
    case 0x02:
        return t->initial_max_stream_id_bidir;
    case 0x03:
        return t->idle_timeout;
    case 0x04:
        /** TODO this should be documented somewhere */
        return (protoop_arg_t) &(t->prefered_address);
    case 0x05:
        return t->max_packet_size;
    case 0x06:
        printf("ERROR: stateless reset token is not implemented!\n");
        return 0;
    case 0x07:
        return t->ack_delay_exponent;
    case 0x08:
        return t->initial_max_stream_id_unidir;
    case 0x09:
        return t->migration_disabled;
    case 0x0a:
        return t->initial_max_stream_data_bidi_remote;
    case 0x0b:
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
    default:
        printf("ERROR: unknown cnx access key %u\n", ak);
        return 0;
    }
}