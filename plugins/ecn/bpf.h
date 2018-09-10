#include "picoquic_internal.h"

#define ECN_OPAQUE_ID 0x01

#define ECN_FRAME_TYPE 0x28

#define PROTOOPID_DECODE_ECN_FRAME (PROTOOPID_DECODE_FRAMES + 0x38)
#define PROTOOPID_PREPARE_ECN_FRAME (PROTOOPID_SENDER + 0x38)

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