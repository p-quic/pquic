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
            LOG_EVENT(cnx, "RECOVERY", "SPURIOUS_RETRANSMIT_DETECTED", "", "{\"cc_path\": \"%p\"}", (protoop_arg_t) path_x);
            break;
        case picoquic_congestion_notification_rtt_measurement:
            LOG_EVENT(cnx, "RECOVERY", "RTT_ESTIMATE", "", "{\"cc_path\": \"%p\", \"rtt_estimate\": %lu, \"smoothed_rtt\": %lu}", (protoop_arg_t) path_x, rtt_measurement, get_path(path_x, AK_PATH_SMOOTHED_RTT, 0));
            break;
        case picoquic_congestion_notification_acknowledgement:
            LOG_EVENT(cnx, "CONGESTION_CONTROL", "CWIN_UPDATE", "ACKNOWLEDGMENT", "{\"cc_path\": \"%p\", \"cwin\": %lu, \"bytes_acknowledged\": %lu}", (protoop_arg_t) path_x, get_path(path_x, AK_PATH_CWIN, 0), nb_bytes_acknowledged);
            break;
        case picoquic_congestion_notification_repeat:
            LOG_EVENT(cnx, "CONGESTION_CONTROL", "CWIN_UPDATE", "REPEAT", "{\"cc_path\": \"%p\", \"cwin\": %lu, \"pn\": %lu}", (protoop_arg_t) path_x, get_path(path_x, AK_PATH_CWIN, 0), lost_packet_number);
            break;
        case picoquic_congestion_notification_timeout:
            LOG_EVENT(cnx, "CONGESTION_CONTROL", "CWIN_UPDATE", "TIMEOUT", "{\"cc_path\": \"%p\", \"cwin\": %lu, \"pn\": %lu}", (protoop_arg_t) path_x, get_path(path_x, AK_PATH_CWIN, 0), lost_packet_number);
            break;
        default:
            break;
    }
    return 0;
}