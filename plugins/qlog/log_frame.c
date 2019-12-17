#include "bpf.h"

/**
 */
protoop_arg_t log_frame(picoquic_cnx_t *cnx) {
    char *frame = (char *) get_cnx(cnx, AK_CNX_INPUT, 0);
    size_t frame_len = strlen(frame) + 1;
    qlog_t *qlog = get_qlog_t(cnx);
    qlog_frames_t **qf = qlog->frames_tail ? &(qlog->frames_tail->next) : &qlog->frames_head;
    *qf = my_malloc(cnx, sizeof(qlog_frames_t));
    if (!*qf) {
        return 0;
    }
    (*qf)->frame = my_malloc(cnx, frame_len);
    if (!(*qf)->frame) {
        my_free(cnx, *qf);
        *qf = NULL;
        return 0;
    }
    (*qf)->frame_len = frame_len;
    (*qf)->next = NULL;
    my_memcpy((*qf)->frame, frame, frame_len);
    qlog->frames_tail = *qf;
    return 0;
}