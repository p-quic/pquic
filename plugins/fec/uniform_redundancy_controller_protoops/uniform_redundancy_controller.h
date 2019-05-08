#include "picoquic_internal.h"

typedef struct {
    uint64_t total_acknowledged_packets;
    uint64_t total_lost_packets;
} uniform_redundancy_controller_t;