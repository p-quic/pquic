#include "../helpers.h"

#define ECN_OPAQUE_ID 0x01

#define META_PKT_CTX_ECN_COUNTERS 0x01

typedef struct {
    uint32_t ecn_val; /* Latest value read from a socket */
    uint32_t ecn_sock_flags; /* A map of sockets correctly ECN-configured */
    bool in_skip_frame;
} bpf_data;

typedef struct {
    uint64_t ecn_ect0_marked_pkts;
    uint64_t ecn_ect1_marked_pkts;
    uint64_t ecn_ect_ce_marked_pkts;
    uint64_t ecn_ect0_remote_pkts;
    uint64_t ecn_ect1_remote_pkts;
    uint64_t ecn_ect_ce_remote_pkts;
    uint64_t ecn_ack_ce_counter;
} ecn_counters_t;

typedef struct {
    uint64_t ect0;
    uint64_t ect1;
    uint64_t ectce;
} ecn_block_t;

static bpf_data *initialize_bpf_data(picoquic_cnx_t *cnx)
{
    bpf_data *bpfd = (bpf_data *) my_malloc(cnx, sizeof(bpf_data));
    if (!bpfd) return NULL;
    my_memset(bpfd, 0, sizeof(bpf_data));
    return bpfd;
}

static bpf_data *get_bpf_data(picoquic_cnx_t *cnx)
{
    bpf_data *bpfd_ptr = (bpf_data *) get_cnx_metadata(cnx, ECN_OPAQUE_ID);
    if (!bpfd_ptr) {
        bpfd_ptr = initialize_bpf_data(cnx);
        // Save pointer for future use
        set_cnx_metadata(cnx, ECN_OPAQUE_ID, (protoop_arg_t) bpfd_ptr);
    }
    return bpfd_ptr;
}