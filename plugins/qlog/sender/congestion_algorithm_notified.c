#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    picoquic_path_t* path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_congestion_notification_t notification = get_cnx(cnx, AK_CNX_INPUT, 1);
    uint64_t rtt_measurement = get_cnx(cnx, AK_CNX_INPUT, 2);
    uint64_t nb_bytes_acknowledged = get_cnx(cnx, AK_CNX_INPUT, 3);
    uint64_t lost_packet_number = get_cnx(cnx, AK_CNX_INPUT, 4);
    uint64_t current_time = get_cnx(cnx, AK_CNX_INPUT, 5);

    switch (notification) {
        case picoquic_congestion_notification_spurious_repeat:
            LOG_EVENT(cnx, "recovery", "metrics_updated", "congestion_notification_spurious_retransmit_detected", "{\"cc_path\": \"%p\", \"congestion_window\": \"%" PRIu64 "\", \"bytes_in_flight\": \"%" PRIu64 "\"}", (protoop_arg_t) path_x, get_path(path_x, AK_PATH_CWIN, 0), get_path(path_x, AK_PATH_BYTES_IN_TRANSIT, 0));
            break;
        case picoquic_congestion_notification_rtt_measurement:
            LOG_EVENT(cnx, "recovery", "metrics_updated", "congestion_notification_rtt_measurement", "{\"cc_path\": \"%p\", \"congestion_window\": \"%" PRIu64 "\", \"bytes_in_flight\": \"%" PRIu64 "\", \"min_rtt\": \"%" PRIu64 "\", \"latest_rtt\": \"%" PRIu64 "\", \"smoothed_rtt\": \"%" PRIu64 "\"}", (protoop_arg_t) path_x, get_path(path_x, AK_PATH_CWIN, 0), get_path(path_x, AK_PATH_BYTES_IN_TRANSIT, 0), get_path(path_x, AK_PATH_RTT_MIN, 0), rtt_measurement, get_path(path_x, AK_PATH_SMOOTHED_RTT, 0));
            break;
        case picoquic_congestion_notification_acknowledgement:
            LOG_EVENT(cnx, "recovery", "metrics_updated", "congestion_notification_acknowledgment", "{\"cc_path\": \"%p\", \"congestion_window\": \"%" PRIu64 "\", \"bytes_in_flight\": \"%" PRIu64 "\", \"bytes_acknowledged\": \"%" PRIu64 "\"}", (protoop_arg_t) path_x, get_path(path_x, AK_PATH_CWIN, 0), get_path(path_x, AK_PATH_BYTES_IN_TRANSIT, 0), nb_bytes_acknowledged);
            break;
        case picoquic_congestion_notification_repeat:
            LOG_EVENT(cnx, "recovery", "metrics_updated", "congestion_notification_repeat_acknowledgment", "{\"cc_path\": \"%p\", \"congestion_window\": \"%" PRIu64 "\", \"bytes_in_flight\": \"%" PRIu64 "\"}", (protoop_arg_t) path_x, get_path(path_x, AK_PATH_CWIN, 0), get_path(path_x, AK_PATH_BYTES_IN_TRANSIT, 0));
            break;
        case picoquic_congestion_notification_timeout:
            LOG_EVENT(cnx, "recovery", "metrics_updated", "congestion_notification_acknowledgment", "{\"cc_path\": \"%p\", \"congestion_window\": \"%" PRIu64 "\", \"bytes_in_flight\": \"%" PRIu64 "\"}", (protoop_arg_t) path_x, get_path(path_x, AK_PATH_CWIN, 0), get_path(path_x, AK_PATH_BYTES_IN_TRANSIT, 0));
            break;
        case picoquic_congestion_notification_cwin_blocked:
            LOG_EVENT(cnx, "recovery", "metrics_updated", "congestion_notification_cwin_blocked", "{\"cc_path\": \"%p\", \"congestion_window\": \"%" PRIu64 "\", \"bytes_in_flight\": \"%" PRIu64 "\"}", (protoop_arg_t) path_x, get_path(path_x, AK_PATH_CWIN, 0), get_path(path_x, AK_PATH_BYTES_IN_TRANSIT, 0));
            break;
        case picoquic_congestion_notification_bw_measurement:
            LOG_EVENT(cnx, "recovery", "metrics_updated", "congestion_notification_bw_measurement", "{\"cc_path\": \"%p\", \"congestion_window\": \"%" PRIu64 "\", \"bytes_in_flight\": \"%" PRIu64 "\"}", (protoop_arg_t) path_x, get_path(path_x, AK_PATH_CWIN, 0), get_path(path_x, AK_PATH_BYTES_IN_TRANSIT, 0));
            break;
        default:
            break;
    }
    return 0;
}