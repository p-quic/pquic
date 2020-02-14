#include "picoquic_internal.h"
#include <stdlib.h>
#include <string.h>
#include "cc_common.h"


uint64_t picoquic_cc_get_sequence_number(picoquic_path_t *path)
{
    return path->pkt_ctx[picoquic_packet_context_application].send_sequence;
}

uint64_t picoquic_cc_get_ack_number(picoquic_path_t *path)
{
    return path->pkt_ctx[picoquic_packet_context_application].highest_acknowledged;
}

int picoquic_cc_was_cwin_blocked(picoquic_path_t *path, uint64_t last_sequence_blocked)
{
    return (last_sequence_blocked == 0 || picoquic_cc_get_ack_number(path) <= last_sequence_blocked);
}