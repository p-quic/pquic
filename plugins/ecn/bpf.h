#include "picoquic.h"
#include "memory.h"
#include "memcpy.h"
#include "getset.h"

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

typedef struct ecn_frame {
    uint64_t ect0;
    uint64_t ect1;
    uint64_t ectce;
} ecn_frame_t;

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
    return *bpfd_ptr;
}