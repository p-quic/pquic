#include "bpf.h"

/**
 * Input: None
 *
 * Output: None
 */
protoop_arg_t log_event(picoquic_cnx_t *cnx) {
    qlog_t *qlog = get_qlog_t(cnx);
    uint64_t now = picoquic_current_time();
    char *fields[QLOG_N_EVENT_FIELDS - 1];
    for (int i = 0; i < QLOG_N_EVENT_FIELDS - 1; i++) {
        fields[i] = (char *) get_cnx(cnx, AK_CNX_INPUT, i);
    }
    if (qlog->fd == -1 || !qlog->wrote_hdr) {
        qlog_event_t *e = my_malloc(cnx, sizeof(qlog_event_t));
        e->reference_time = now;
        for (int i = 0; i < QLOG_N_EVENT_FIELDS - 1; i++) {
            size_t str_len = strlen(fields[i]) + 1;
            e->fields[i] = my_malloc(cnx, str_len);
            my_memcpy(e->fields[i], fields[i], str_len);
        }
        if (!qlog->head) {
            qlog->head = e;
        }
        if (qlog->tail) {
            qlog->tail->next = e;
        }
        qlog->tail = e;
    } else {
        append_event(qlog, now, fields);
    }
    return 0;
}