#include "picoquic_internal.h"

#define ECN_OPAQUE_ID 0x01

typedef struct {
    /* ECN Data */
    uint32_t ecn_val;
    uint32_t ecn_sock_flags;
    uint64_t ecn_ect0_marked_pkts;
    uint64_t ecn_ect1_marked_pkts;
    uint64_t ecn_ect_ce_marked_pkts;
    uint64_t ecn_ect0_remote_pkts;
    uint64_t ecn_ect1_remote_pkts;
    uint64_t ecn_ect_ce_remote_pkts;
    uint64_t ecn_ack_ce_counter;
} bpf_data;