#include "bpf.h"

/**
 * Input: None
 *
 * Output: None
 */
protoop_arg_t push_context(picoquic_cnx_t *cnx) {
    qlog_t *qlog = get_qlog_t(cnx);
    char *core_ctx = (char *) get_cnx(cnx, AK_CNX_INPUT, 0);
    size_t core_ctx_len = strlen(core_ctx) + 1;
    char *ctx = (char *) my_malloc(cnx, core_ctx_len);
    if (ctx) {
        my_memcpy(ctx, core_ctx, core_ctx_len);
        push_ctx(cnx, qlog, ctx);
    }
    return 0;
}