#ifndef CC_COMMON_H
#define CC_COMMON_H

uint64_t picoquic_cc_get_sequence_number(picoquic_path_t *path);

uint64_t picoquic_cc_get_ack_number(picoquic_path_t *path);

int picoquic_cc_was_cwin_blocked(picoquic_path_t *path, uint64_t last_sequence_blocked);

#endif //CC_COMMON_H
