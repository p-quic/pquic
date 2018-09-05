#include "picoquic_internal.h"

#define ECN_OPAQUE_ID 0x01

typedef struct {
    /* ECN Data */
    uint32_t ecn_val;
    uint64_t ecn_ect0_marked_pkts;
    uint64_t ecn_ect1_marked_pkts;
    uint64_t ecn_ect_ce_marked_pkts;
    uint32_t ecn_sock_flags;
} bpf_data;