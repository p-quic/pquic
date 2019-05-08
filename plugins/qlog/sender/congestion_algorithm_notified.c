#include "../bpf.h"

protoop_arg_t protoop_log(picoquic_cnx_t *cnx) {
    picoquic_path_t* path_x = (picoquic_path_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_congestion_notification_t notification = get_cnx(cnx, AK_CNX_INPUT, 1);
    uint64_t rtt_measurement = get_cnx(cnx, AK_CNX_INPUT, 2);
    uint64_t nb_bytes_acknowledged = get_cnx(cnx, AK_CNX_INPUT, 3);
    uint64_t lost_packet_number = get_cnx(cnx, AK_CNX_INPUT, 4);
    uint64_t current_time = get_cnx(cnx, AK_CNX_INPUT, 5);

    PROTOOP_PRINTF(cnx, "CC NOTIF: %p, %d, %lu, %lu, %lu, %lu\n", (protoop_arg_t) path_x, notification, rtt_measurement, nb_bytes_acknowledged, lost_packet_number, current_time);
    return 0;
}