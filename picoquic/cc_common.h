#ifndef CC_COMMON_H
#define CC_COMMON_H

#define PICOQUIC_MIN_MAX_RTT_SCOPE 7

typedef struct st_picoquic_min_max_rtt_t {
    uint64_t last_rtt_sample_time;
    uint64_t rtt_filtered_min;
    int nb_rtt_excess;
    int sample_current;
    int is_init;
    int past_threshold;
    int threshold_count;
    uint64_t sample_min;
    uint64_t sample_max;
    uint64_t samples[PICOQUIC_MIN_MAX_RTT_SCOPE];
} picoquic_min_max_rtt_t;


uint64_t picoquic_cc_get_sequence_number(picoquic_path_t *path);

uint64_t picoquic_cc_get_ack_number(picoquic_path_t *path);

void picoquic_filter_rtt_min_max(picoquic_min_max_rtt_t* rtt_track, uint64_t rtt);

int picoquic_hystart_test(picoquic_min_max_rtt_t* rtt_track, uint64_t rtt_measurement, uint64_t packet_time, uint64_t current_time, int is_one_way_delay_enabled);

void picoquic_hystart_increase(picoquic_path_t* path_x, picoquic_min_max_rtt_t* rtt_filter, uint64_t nb_delivered);

int picoquic_cc_was_cwin_blocked(picoquic_path_t *path, uint64_t last_sequence_blocked);

#endif //CC_COMMON_H
