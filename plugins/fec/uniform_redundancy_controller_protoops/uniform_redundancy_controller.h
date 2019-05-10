#include "picoquic.h"

#define DEFAULT_N 30
#define DEFAULT_K 25

typedef struct {
    uint64_t total_acknowledged_packets;
    uint64_t total_lost_packets;
} uniform_redundancy_controller_t;