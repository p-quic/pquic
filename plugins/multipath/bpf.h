#include "picoquic_internal.h"
#include "memory.h"
#include "memcpy.h"

#define MP_OPAQUE_ID 0x10

typedef struct {
    picoquic_path_t path;
    uint64_t path_id;
    uint8_t state; /* 0: proposed, 1: ready, 2: active, 3: unusable, 4: closed */
    picoquic_connection_id_t local_cnxid;
    picoquic_connection_id_t remote_cnxid;
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
    picoquic_packet_context_t pkt_ctx;
} path_data_t;

typedef struct {
    uint8_t num_paths;
    path_data_t paths[8];
} bpf_data;

static bpf_data *initialize_bpf_data(picoquic_cnx_t *cnx)
{
    bpf_data *bpfd = (bpf_data *) my_malloc(cnx, sizeof(bpf_data));
    if (!bpfd) return NULL;
    my_memset(bpfd, 0, sizeof(bpf_data));
    return bpfd;
}

static bpf_data *get_bpf_data(picoquic_cnx_t *cnx)
{
    int allocated = 0;
    bpf_data **bpfd_ptr = (bpf_data **) get_opaque_data(cnx, MP_OPAQUE_ID, sizeof(bpf_data *), &allocated);
    if (!bpfd_ptr) return NULL;
    if (allocated) {
        *bpfd_ptr = initialize_bpf_data(cnx);
    }
    return *bpfd_ptr;
}