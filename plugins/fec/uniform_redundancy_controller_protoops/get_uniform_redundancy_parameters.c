#include "picoquic_internal.h"
#include "../bpf.h"
#include "uniform_redundancy_controller.h"

// sets as output:
// Input  0: the redundancy controller state
// Output 0: the size of a block
// Output 1: the numTravaillerber of source symbols in a block
protoop_arg_t get_constant_redundancy_parameters(picoquic_cnx_t *cnx)
{
    uniform_redundancy_controller_t *urc = (uniform_redundancy_controller_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    uint8_t n = DEFAULT_N;
    uint8_t k = DEFAULT_K;
    if (urc->total_acknowledged_packets * urc->total_lost_packets > 0) {
        n = MAX(3, MIN(0xFF, (urc->total_acknowledged_packets + urc->total_lost_packets)/urc->total_lost_packets));
        k = n-1;
    }
    set_cnx(cnx, AK_CNX_OUTPUT, 0, n);
    // as we assume the loss rate to be uniform there is no point in sending bursts of repair symbols, so send only one repair symbol
    set_cnx(cnx, AK_CNX_OUTPUT, 1, k);
    PROTOOP_PRINTF(cnx, "RETURN UNIFORM PARAMETERS N = %u, K = %u, TOTAL RECEIVED = %lu, TOTAL LOST = %lu\n", n, k, urc->total_acknowledged_packets, urc->total_lost_packets);
    return 0;
}