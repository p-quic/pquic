#include "../bpf.h"

protoop_arg_t segment_aborted(picoquic_cnx_t *cnx)
{
    qlog_t *qlog = get_qlog_t(cnx);
    qlog_frames_t *f = qlog->frames_head;
    while(f) {
        qlog_frames_t *t = f;
        f = f->next;
        my_free(cnx, t->frame);
        my_free(cnx, t);
    }
    qlog->frames_head = NULL;
    qlog->frames_tail = NULL;
    return 0;
}