#ifndef WESTWOOD_H
#define WESTWOOD_H

#include <picoquic.h>

#include "../../picoquic/memcpy.h"
#include "../../picoquic/memory.h"
#include "../helpers.h"
#include "../../picoquic/picoquic.h"
#include "cc_common.h"

#define WESTWOOD_OPAQUE_ID 0x0F
#define NB_RTT_WESTWOOD 4

typedef enum {
    westwood_alg_slow_start = 0,
    westwood_alg_congestion_avoidance
} westwood_alg_state_t;

typedef struct {
    westwood_alg_state_t alg_state;
    uint64_t ssthresh;
    int64_t residual_ack;
    int64_t recovery_start;
    int64_t cwin_before_recovery_start;
    int64_t min_rtt;
    int64_t nb_rtt;
    uint64_t last_rtt[NB_RTT_WESTWOOD];
    int64_t bytes_acknowledged_since_last_rtt;
    int64_t bytes_acknowledged_during_previous_round;
    int64_t last_rtt_timestamp;
    int64_t last_rtt_value;
    uint64_t last_sequence_blocked;
} westwood_state_t;


static __attribute__((always_inline)) westwood_state_t *initialize_westwood_state_t(picoquic_cnx_t *cnx, uint64_t current_time)
{
    westwood_state_t *state = (westwood_state_t *) my_malloc(cnx, sizeof(westwood_state_t));
    if (!state) return NULL;
    my_memset(state, 0, sizeof(westwood_state_t));

    state->alg_state = westwood_alg_slow_start;
    state->ssthresh = (uint64_t) ((int64_t)-1);
    state->last_rtt_timestamp = current_time;
    state->last_rtt_value = -1;
    return state;
}

static __attribute__((always_inline)) westwood_state_t *get_westwood_state_t(picoquic_cnx_t *cnx, uint64_t current_time)
{
    westwood_state_t *state_ptr = (westwood_state_t *) get_cnx_metadata(cnx, WESTWOOD_OPAQUE_ID);
    if (!state_ptr) {
        state_ptr = initialize_westwood_state_t(cnx, current_time);
        set_cnx_metadata(cnx, WESTWOOD_OPAQUE_ID, (protoop_arg_t) state_ptr);
    }
    return state_ptr;
}

static __attribute__((always_inline)) void westwood_enter_recovery(picoquic_cnx_t *cnx, picoquic_path_t* path_x,
                                            picoquic_congestion_notification_t notification,
                                            westwood_state_t* westwood_state,
                                            uint64_t current_time, uint64_t *cwin)
{

    uint64_t newreno_behaviour = *cwin/2;
    westwood_state->ssthresh = 0;
    // westwood cwin reduction formula
    if (westwood_state->last_rtt_value != -1)
        westwood_state->ssthresh = westwood_state->bytes_acknowledged_during_previous_round*westwood_state->min_rtt/(uint64_t) westwood_state->last_rtt_value;
    westwood_state->ssthresh = MAX(westwood_state->ssthresh, newreno_behaviour);
    westwood_state->cwin_before_recovery_start = *cwin;
    if (westwood_state->ssthresh < PICOQUIC_CWIN_MINIMUM) {
        westwood_state->ssthresh = PICOQUIC_CWIN_MINIMUM;
    }

    if (notification == picoquic_congestion_notification_timeout) {
        *cwin = PICOQUIC_CWIN_MINIMUM;
        westwood_state->alg_state = westwood_alg_slow_start;
    } else {
        *cwin = westwood_state->ssthresh;
        westwood_state->alg_state = westwood_alg_congestion_avoidance;
    }

    westwood_state->recovery_start = current_time;

    westwood_state->residual_ack = 0;


}

#endif // WESTWOOD_H
