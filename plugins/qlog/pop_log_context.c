#include "bpf.h"

/**
 * Input: None
 *
 * Output: None
 */
protoop_arg_t pop_context(picoquic_cnx_t *cnx) {
    qlog_t *qlog = get_qlog_t(cnx);
    char *ctx = pop_ctx(cnx, qlog);
    if (ctx)
        my_free(cnx, ctx);
    return 0;
}