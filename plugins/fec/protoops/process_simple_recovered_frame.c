#include "picoquic_internal.h"
#include "../bpf.h"


protoop_arg_t process_recovered_frame(picoquic_cnx_t *cnx)
{
    uint8_t *size_and_packets = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    uint64_t current_time = get_cnx(cnx, AK_CNX_INPUT, 1);
    recovered_packets_t rp;
    rp.number_of_packets = *size_and_packets;
    rp.packets = (uint64_t *) (size_and_packets+1);
    PROTOOP_PRINTF(cnx, "PROCESS RECOVERED FRAME\n");
    peer_has_recovered_packets(cnx, &rp, current_time);
    return (protoop_arg_t) 0;
}