#include "../fec_protoops.h"
#include "uniform_redundancy_controller.h"

// sets as output:
// Input  0: the redundancy controller state
// Output 0: the size of a block
// Output 1: the numTravaillerber of source symbols in a block
protoop_arg_t get_constant_redundancy_parameters(picoquic_cnx_t *cnx)
{
    uniform_redundancy_controller_t *urc = (uniform_redundancy_controller_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    bool flush = (bool) get_cnx(cnx, AK_CNX_INPUT, 1);
    uint8_t n = 0;
    uint8_t k = 0;
    if (urc->total_acknowledged_packets * urc->total_lost_packets > 0) {
        n = MAX(3, MIN(MAX_SYMBOLS_PER_FEC_BLOCK, (urc->total_acknowledged_packets + urc->total_lost_packets)/urc->total_lost_packets));
        k = n-1;
    }
    // if we flush the window, ensure that there is redundancy to send
    set_cnx(cnx, AK_CNX_OUTPUT, 0, flush ? MAX(DEFAULT_N, n) : n);
    // as we assume the loss rate to be uniform there is no point in sending bursts of repair symbols, so send only one repair symbol
    set_cnx(cnx, AK_CNX_OUTPUT, 1, flush ? MAX(DEFAULT_K, k) : k);
    PROTOOP_PRINTF(cnx, "RETURN UNIFORM PARAMETERS N = %u, K = %u, TOTAL RECEIVED = %" PRIu64 ", TOTAL LOST = %" PRIu64 "\n", n, k, urc->total_acknowledged_packets, urc->total_lost_packets);
    return 0;
}