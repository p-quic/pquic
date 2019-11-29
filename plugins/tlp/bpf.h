#include "picoquic.h"
#include "memory.h"
#include "memcpy.h"

#define TLP_OPAQUE_ID 0x00

typedef struct {
    /* TLP Data */
    uint8_t tlp_nb;
    uint64_t tlp_time;
    uint64_t tlp_packet_send_time; /* Detect if the TLP probe changed or not */
    uint64_t tlp_last_asked; /* Don't enter infinite loops... */
    uint8_t print;
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
    bpf_data *bpfd_ptr = (bpf_data *) get_cnx_metadata(cnx, TLP_OPAQUE_ID);
    if (!bpfd_ptr) {
        bpfd_ptr = initialize_bpf_data(cnx);
        set_cnx_metadata(cnx, TLP_OPAQUE_ID, (protoop_arg_t) bpfd_ptr);
    }
    return bpfd_ptr;
}