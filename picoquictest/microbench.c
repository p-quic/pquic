#include "picoquic_internal.h"
#include "plugin.h"
#include "memory.h"
#include "getset.h"
#include "util.h"
#include "protoop.h"

uint64_t simple_for_loop(picoquic_cnx_t *mem) {
    uint64_t sum = 0;
    for (uint64_t i = 0; i < 1000000000; i++) {
        sum = i + sum * 3 / 2;
    }
    return sum;
}

uint64_t get_set_cnx_fields_loop(picoquic_cnx_t *cnx) {
    uint64_t sum = 0;
    for (uint64_t i = 0; i < 500000000; i++) {
        sum += cnx->start_time;
        sum += cnx->latest_progress_time;
        cnx->start_time = 2 * sum + 3 * i;
        cnx->latest_progress_time = 3 * sum / 4 + i;
    }
    return sum;
}

uint64_t get_set_api_cnx_fields_loop(picoquic_cnx_t *cnx) {
    uint64_t sum = 0;
    for (uint64_t i = 0; i < 500000000; i++) {
        sum += get_cnx(cnx, AK_CNX_START_TIME, 0);
        sum += get_cnx(cnx, AK_CNX_LATEST_PROGRESS_TIME, 0);
        set_cnx(cnx, AK_CNX_START_TIME, 0, 2 * sum + 3 * i);
        set_cnx(cnx, AK_CNX_LATEST_PROGRESS_TIME, 0, 3 * sum / 4 + i);
    }
    return sum;
}

#define SIMPLE_FOR_LOOP ((protoop_id_t) { .id = "simple_for_loop", .hash = hash_value_str("simple_for_loop") })
#define GET_SET_CNX_FIELDS_LOOP ((protoop_id_t) { .id = "get_set_cnx_fields_loop", .hash = hash_value_str("get_set_cnx_fields_loop") })

void register_microbench_protoops(picoquic_cnx_t *cnx)
{
    register_noparam_protoop(cnx, &SIMPLE_FOR_LOOP, &simple_for_loop);
    register_noparam_protoop(cnx, &GET_SET_CNX_FIELDS_LOOP, &get_set_cnx_fields_loop);
}

int microbench_plugin_run_test() {
    int ret = 0;
    picoquic_cnx_t cnx = { 0 };
    register_protocol_operations(&cnx);
    register_microbench_protoops(&cnx);
    
    /* TODO compare with non-direct calls! */

    struct timeval tv_sl_start;
    struct timeval tv_sl_end;

    uint64_t sum = 0;
    gettimeofday(&tv_sl_start, NULL);

    //for (uint64_t i = 0; i < 1000000; i++) {
        sum += simple_for_loop(&cnx);
        //protoop_prepare_and_run_noparam(&cnx, "simple_for_loop", NULL,
        //    cnx);
    //}

    gettimeofday(&tv_sl_end, NULL);

    uint64_t sl_native = (tv_sl_end.tv_sec - tv_sl_start.tv_sec) * 1000000 + (tv_sl_end.tv_usec - tv_sl_start.tv_usec);
    fprintf(stderr, "Native sl: %" PRIu64 " us, sum is %" PRIu64 "\n", sl_native, sum);

    struct timeval tv_gs_start;
    struct timeval tv_gs_end;

    sum = 0;
    gettimeofday(&tv_gs_start, NULL);

    //for (uint64_t i = 0; i < 1000000; i++) {
        sum += get_set_cnx_fields_loop(&cnx);
        //protoop_prepare_and_run_noparam(&cnx, "simple_for_loop", NULL,
        //    cnx);
    //}

    gettimeofday(&tv_gs_end, NULL);

    uint64_t gs_native = (tv_gs_end.tv_sec - tv_gs_start.tv_sec) * 1000000 + (tv_gs_end.tv_usec - tv_gs_start.tv_usec);
    fprintf(stderr, "Native gs: %" PRIu64 " us, sum is %" PRIu64 "\n", gs_native, sum);

    struct timeval tv_gs_api_start;
    struct timeval tv_gs_api_end;

    sum = 0;
    gettimeofday(&tv_gs_api_start, NULL);

    //for (uint64_t i = 0; i < 1000000; i++) {
        sum += get_set_api_cnx_fields_loop(&cnx);
        //protoop_prepare_and_run_noparam(&cnx, "simple_for_loop", NULL,
        //    cnx);
    //}

    gettimeofday(&tv_gs_api_end, NULL);

    uint64_t gs_api_native = (tv_gs_api_end.tv_sec - tv_gs_api_start.tv_sec) * 1000000 + (tv_gs_api_end.tv_usec - tv_gs_api_start.tv_usec);
    fprintf(stderr, "Native API gs: %" PRIu64 " us, sum is %" PRIu64 "\n", gs_api_native, sum);

    ret = plugin_insert_plugin(&cnx, "plugins/microbench/microbench.plugin");
    if (ret) {
        fprintf(stderr, "Failed to insert microbench plugin!\n");
        return ret;
    }

    /* Ok, this is ugly but if here we want to test only eBPF execution, we don't have the choice... */
    protocol_operation_struct_t *post;
    HASH_FIND_PID(cnx.ops, &SIMPLE_FOR_LOOP.hash, post);
    if (!post) {
        printf("FATAL ERROR: no protocol operation with id %s\n", "simple_for_loop");
        return 1;
    }
    protocol_operation_param_struct_t *popst = post->params;
    cnx.current_plugin = popst->replace->p;
    char *error_msg = NULL;

    struct timeval tv_sl_jit_start;
    struct timeval tv_sl_jit_end;

    sum = 0;
    gettimeofday(&tv_sl_jit_start, NULL);

    //for (uint64_t i = 0; i < 1000000; i++) {
        sum += _exec_loaded_code(popst->replace, (void *)&cnx, (void *)cnx.current_plugin->memory, sizeof(cnx.current_plugin->memory), &error_msg, true);
        //protoop_prepare_and_run_noparam(&cnx, "simple_for_loop", NULL,
        //    cnx);
    //}

    gettimeofday(&tv_sl_jit_end, NULL);
    uint64_t sl_jit = (tv_sl_jit_end.tv_sec - tv_sl_jit_start.tv_sec) * 1000000 + (tv_sl_jit_end.tv_usec - tv_sl_jit_start.tv_usec);
    fprintf(stderr, "JIT sl: %" PRIu64 " us, sum is %" PRIu64 "\n", sl_jit, sum);

    /* Second execution */
    HASH_FIND_PID(cnx.ops, &GET_SET_CNX_FIELDS_LOOP.hash, post);
    if (!post) {
        printf("FATAL ERROR: no protocol operation with id %s\n", "get_set_cnx_fields_loop");
        return 1;
    }
    popst = post->params;
    cnx.current_plugin = popst->replace->p;

    struct timeval tv_gs_jit_start;
    struct timeval tv_gs_jit_end;

    // Reset start_time and latest_progress_time
    cnx.start_time = 0;
    cnx.latest_progress_time = 0;

    sum = 0;
    gettimeofday(&tv_gs_jit_start, NULL);

    //for (uint64_t i = 0; i < 1000000; i++) {
        sum += _exec_loaded_code(popst->replace, (void *)&cnx, (void *)cnx.current_plugin->memory, sizeof(cnx.current_plugin->memory), &error_msg, true);
        //protoop_prepare_and_run_noparam(&cnx, "simple_for_loop", NULL,
        //    cnx);
    //}

    gettimeofday(&tv_gs_jit_end, NULL);
    uint64_t gs_jit = (tv_gs_jit_end.tv_sec - tv_gs_jit_start.tv_sec) * 1000000 + (tv_gs_jit_end.tv_usec - tv_gs_jit_start.tv_usec);
    fprintf(stderr, "JIT gs: %" PRIu64 " us, sum is %" PRIu64 "\n", gs_jit, sum);
    
    /* Interpreted */
    HASH_FIND_PID(cnx.ops, &SIMPLE_FOR_LOOP.hash, post);
    if (!post) {
        printf("FATAL ERROR: no protocol operation with id %s\n", "simple_for_loop");
        return 1;
    }
    popst = post->params;
    cnx.current_plugin = popst->replace->p;

    struct timeval tv_sl_int_start;
    struct timeval tv_sl_int_end;

    sum = 0;
    gettimeofday(&tv_sl_int_start, NULL);

    //for (uint64_t i = 0; i < 1000000; i++) {
        sum += _exec_loaded_code(popst->replace, (void *)&cnx, (void *)cnx.current_plugin->memory, sizeof(cnx.current_plugin->memory), &error_msg, false);
        //protoop_prepare_and_run_noparam(&cnx, "simple_for_loop", NULL,
        //    cnx);
    //}

    gettimeofday(&tv_sl_int_end, NULL);
    uint64_t sl_int = (tv_sl_int_end.tv_sec - tv_sl_int_start.tv_sec) * 1000000 + (tv_sl_int_end.tv_usec - tv_sl_int_start.tv_usec);
    fprintf(stderr, "Interpreted sl: %" PRIu64 " us, sum is %" PRIu64 "\n", sl_int, sum);

    /* Second execution */
    HASH_FIND_PID(cnx.ops, &GET_SET_CNX_FIELDS_LOOP.hash, post);
    if (!post) {
        printf("FATAL ERROR: no protocol operation with id %s\n", "get_set_cnx_fields_loop");
        return 1;
    }
    popst = post->params;
    cnx.current_plugin = popst->replace->p;

    struct timeval tv_gs_int_start;
    struct timeval tv_gs_int_end;

    // Reset start_time and latest_progress_time
    cnx.start_time = 0;
    cnx.latest_progress_time = 0;

    sum = 0;
    gettimeofday(&tv_gs_int_start, NULL);

    //for (uint64_t i = 0; i < 1000000; i++) {
        sum += _exec_loaded_code(popst->replace, (void *)&cnx, (void *)cnx.current_plugin->memory, sizeof(cnx.current_plugin->memory), &error_msg, false);
        //protoop_prepare_and_run_noparam(&cnx, "simple_for_loop", NULL,
        //    cnx);
    //}

    gettimeofday(&tv_gs_int_end, NULL);
    uint64_t gs_int = (tv_gs_int_end.tv_sec - tv_gs_int_start.tv_sec) * 1000000 + (tv_gs_int_end.tv_usec - tv_gs_int_start.tv_usec);
    fprintf(stderr, "Interpreted gs: %" PRIu64 " us, sum is %" PRIu64 "\n", gs_int, sum);

    /* TODO register functions as default ops */
    return ret;
}