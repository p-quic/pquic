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
            LOG_EVENT(cnx, "RECOVERY", "SPURIOUS_RETRANSMIT_DETECTED", "", "{}");
            break;
        case picoquic_congestion_notification_rtt_measurement:
            LOG_EVENT(cnx, "RECOVERY", "RTT_ESTIMATE", "", "{\"rtt_estimate\": %lu, \"smoothed_rtt\": %lu}", rtt_measurement, get_path(path_x, AK_PATH_SMOOTHED_RTT, 0));
            break;
        case picoquic_congestion_notification_acknowledgement:
            LOG_EVENT(cnx, "CONGESTION_CONTROL", "CWIN_UPDATE", "ACKNOWLEDGMENT", "{\"cwin\": %lu, \"bytes_acknowledged\": %lu}", get_path(path_x, AK_PATH_CWIN, 0), nb_bytes_acknowledged);
        case picoquic_congestion_notification_repeat:
            LOG_EVENT(cnx, "CONGESTION_CONTROL", "CWIN_UPDATE", "REPEAT", "{\"cwin\": %lu, \"pn\": %lu}", get_path(path_x, AK_PATH_CWIN, 0), lost_packet_number);
        case picoquic_congestion_notification_timeout:
            LOG_EVENT(cnx, "CONGESTION_CONTROL", "CWIN_UPDATE", "TIMEOUT", "{\"cwin\": %lu, \"pn\": %lu}", get_path(path_x, AK_PATH_CWIN, 0), lost_packet_number);
            break;
        default:
            break;
    }

    PROTOOP_PRINTF(cnx, "CC NOTIF: %p, %d, %lu, %lu, %lu, %lu\n", (protoop_arg_t) path_x, notification, rtt_measurement, nb_bytes_acknowledged, lost_packet_number, current_time);
    return 0;
}