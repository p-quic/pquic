#include "picoquic_internal.h"
#include "getset.h"
#include "../helpers.h"
#include "bpf.h"

/** See PROTOOP_NOPARAM_NOPARAM_UNKNOWN_TP_RECEIVED */
protoop_arg_t unknown_tp_received(picoquic_cnx_t *cnx) {
    cop2_conn_metrics *metrics = get_cop2_metrics(cnx);

    uint16_t type = (uint16_t) get_cnx(cnx, CNX_AK_INPUT, 0);
    uint16_t length = (uint16_t) get_cnx(cnx, CNX_AK_INPUT, 1);
    uint8_t *value = (uint8_t *) get_cnx(cnx, CNX_AK_INPUT, 2);

    cop2_tp *tp = my_malloc(cnx, sizeof(cop2_tp));
    if (tp == NULL) {
        return -1;
    }
    tp->type = type;
    tp->length = length;
    tp->value = my_malloc(cnx, (unsigned int) length);
    if (tp->value == NULL) {
        return -1;
    }
    my_memcpy(tp->value, value, tp->length);
    if (metrics->unknown_tps_tail == NULL) {
        metrics->unknown_tps = tp;
        metrics->unknown_tps_tail = tp;
    } else {
        metrics->unknown_tps_tail->next = tp;
    }
    metrics->n_unknown_tps++;
    return 0;
}