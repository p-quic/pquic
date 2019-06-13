#include "picoquic.h"
#include "../fec_protoops.h"


protoop_arg_t process_recovered_frame(picoquic_cnx_t *cnx)
{
    bpf_state *state = get_bpf_state(cnx);
    if (!state) return PICOQUIC_ERROR_MEMORY;
    uint8_t *size_and_packets = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    recovered_packets_t rp;
    rp.number_of_packets = *size_and_packets;
    rp.packets = (uint64_t *) (size_and_packets+1);

    enqueue_recovered_packets(&state->recovered_packets, &rp);
    return (protoop_arg_t) 0;
}