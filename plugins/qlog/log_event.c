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
        if (!e)
            return 0;
        e->reference_time = now;
        for (int i = 0; i < QLOG_N_EVENT_FIELDS - 1; i++) {
            if (fields[i]) {
                size_t str_len = strlen(fields[i]) + 1;
                e->fields[i] = my_malloc(cnx, str_len);
                if (!e->fields[i])
                    return 0;
                my_memcpy(e->fields[i], fields[i], str_len);
            } else if (i == 3) {
                e->fields[i] = format_ctx(cnx, qlog);
            }
        }
        if (!qlog->head) {
            qlog->head = e;
        }
        if (qlog->tail) {
            qlog->tail->next = e;
        }
        qlog->tail = e;
    } else {
        bool generate_context = !fields[3];
        if (generate_context) {
            fields[3] = format_ctx(cnx, qlog);
        }
        append_event(qlog, now, fields);
        if (generate_context) {
            my_free(cnx, fields[3]);
        }
    }
    return 0;
}