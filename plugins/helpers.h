#ifndef HELPERS_H
#define HELPERS_H

#include "picoquic.h"
#include "plugin.h"
#include "memcpy.h"
#include "memory.h"
#include "getset.h"
#include "util.h"

#define PICOQUIC_MAX_PACKET_SIZE 1536
#define PICOQUIC_MIN_SEGMENT_SIZE 256
#define PICOQUIC_INITIAL_MTU_IPV4 1252
#define PICOQUIC_INITIAL_MTU_IPV6 1232
#define PICOQUIC_ENFORCED_INITIAL_MTU 1200
#define PICOQUIC_PRACTICAL_MAX_MTU 1440
#define PICOQUIC_RETRY_SECRET_SIZE 64
#define PICOQUIC_DEFAULT_0RTT_WINDOW 4096

#define PICOQUIC_NUMBER_OF_EPOCHS 4
#define PICOQUIC_NUMBER_OF_EPOCH_OFFSETS (PICOQUIC_NUMBER_OF_EPOCHS+1)

#define PICOQUIC_INITIAL_RTT 250000 /* 250 ms */
#define PICOQUIC_INITIAL_RETRANSMIT_TIMER 1000000 /* one second */
#define PICOQUIC_MIN_RETRANSMIT_TIMER 50000 /* 50 ms */
#define PICOQUIC_ACK_DELAY_MAX 25000 /* 25 ms */
#define PICOQUIC_RACK_DELAY 10000 /* 10 ms */

#define PICOQUIC_SPURIOUS_RETRANSMIT_DELAY_MAX 1000000 /* one second */

#define PICOQUIC_MICROSEC_SILENCE_MAX 120000000 /* 120 seconds for now */
#define PICOQUIC_MICROSEC_HANDSHAKE_MAX 15000000 /* 15 seconds for now */
#define PICOQUIC_MICROSEC_WAIT_MAX 10000000 /* 10 seconds for now */

#define PICOQUIC_CWIN_INITIAL (10 * PICOQUIC_MAX_PACKET_SIZE)
#define PICOQUIC_CWIN_MINIMUM (2 * PICOQUIC_MAX_PACKET_SIZE)

#define PICOQUIC_SPIN_VEC_LATE 1000 /* in microseconds : reaction time beyond which to mark a spin bit edge as 'late' */

#define PICOQUIC_CHALLENGE_REPEAT_MAX 4

#define PROTOOP_NUMARGS(...)  (sizeof((protoop_arg_t[]){__VA_ARGS__})/sizeof(protoop_arg_t))
#ifndef DISABLE_PROTOOP_PRINTF
#define PROTOOP_PRINTF(cnx, fmt, ...)   helper_protoop_printf(cnx, fmt, (protoop_arg_t[]){__VA_ARGS__}, PROTOOP_NUMARGS(__VA_ARGS__))
#else
#define PROTOOP_PRINTF(cnx, fmt, ...)
#endif

#define PSTREAM_RESET_SENT(stream) ((get_stream_head(stream, AK_STREAMHEAD_STREAM_FLAGS) & picoquic_stream_flag_reset_sent) != 0)
#define PSTREAM_RESET_REQUESTED(stream) ((get_stream_head(stream, AK_STREAMHEAD_STREAM_FLAGS) & picoquic_stream_flag_reset_requested) != 0)
#define PSTREAM_RESET_RCVD(stream) ((get_stream_head(stream, AK_STREAMHEAD_STREAM_FLAGS) & picoquic_stream_flag_reset_received) != 0)
#define PSTREAM_SEND_RESET(stream) (PSTREAM_RESET_REQUESTED(stream) && !PSTREAM_RESET_SENT(stream))
#define PSTREAM_STOP_SENDING_REQUESTED(stream) ((get_stream_head(stream, AK_STREAMHEAD_STREAM_FLAGS) & picoquic_stream_flag_stop_sending_requested) != 0)
#define PSTREAM_STOP_SENDING_SENT(stream) ((get_stream_head(stream, AK_STREAMHEAD_STREAM_FLAGS) & picoquic_stream_flag_stop_sending_sent) != 0)
#define PSTREAM_STOP_SENDING_RECEIVED(stream) ((get_stream_head(stream, AK_STREAMHEAD_STREAM_FLAGS) & picoquic_stream_flag_stop_sending_received) != 0)
#define PSTREAM_SEND_STOP_SENDING(stream) (PSTREAM_STOP_SENDING_REQUESTED(stream) && !PSTREAM_STOP_SENDING_SENT(stream))
#define PSTREAM_FIN_NOTIFIED(stream) ((get_stream_head(stream, AK_STREAMHEAD_STREAM_FLAGS) & picoquic_stream_flag_fin_notified) != 0)
#define PSTREAM_FIN_SENT(stream) ((get_stream_head(stream, AK_STREAMHEAD_STREAM_FLAGS) & picoquic_stream_flag_fin_sent) != 0)
#define PSTREAM_FIN_RCVD(stream) ((get_stream_head(stream, AK_STREAMHEAD_STREAM_FLAGS) & picoquic_stream_flag_fin_received) != 0)
#define PSTREAM_SEND_FIN(stream) (PSTREAM_FIN_NOTIFIED(stream) && !PSTREAM_FIN_SENT(stream))
#define PSTREAM_CLOSED(stream) ((PSTREAM_FIN_SENT(stream) || (get_stream_head(stream, AK_STREAMHEAD_STREAM_FLAGS) & picoquic_stream_flag_reset_received) != 0) && (PSTREAM_RESET_SENT(stream)) || (get_stream_head(stream, AK_STREAMHEAD_STREAM_FLAGS) & picoquic_stream_flag_fin_received) != 0)

#define PROTOOP_SNPRINTF(cnx, buf, buf_len, fmt, ...)   helper_protoop_snprintf(cnx, buf, buf_len, fmt, (protoop_arg_t[]){__VA_ARGS__}, PROTOOP_NUMARGS(__VA_ARGS__))

#ifndef DISABLE_QLOG
#define LOG
#define LOG_EVENT(cnx, cat, ev_type, trig, data_fmt, ...)   helper_log_event(cnx, (char *[]){cat, ev_type, trig, data_fmt}, (protoop_arg_t[]){__VA_ARGS__}, PROTOOP_NUMARGS(__VA_ARGS__))
#define PUSH_LOG_CTX(cnx, fmt, ...) helper_push_log_context(cnx, fmt, (protoop_arg_t[]){__VA_ARGS__}, PROTOOP_NUMARGS(__VA_ARGS__))
#define POP_LOG_CTX(cnx)    run_noparam(cnx, PROTOOPID_NOPARAM_POP_LOG_CONTEXT, 0, NULL, NULL)
#else
#define LOG if (0)
#define LOG_EVENT(cnx, cat, ev_type, trig, data_fmt, ...)
#define PUSH_LOG_CTX(cnx, fmt, ...)
#define POP_LOG_CTX(cnx)
#endif

void *my_malloc_ex(picoquic_cnx_t *cnx, unsigned int size);

#ifdef PLUGIN_MEMORY_DBG
#define my_malloc(cnx,size) my_malloc_dbg(cnx,size,__FILE__,__LINE__)
#define my_free(cnx,ptr) my_free_dbg(cnx,ptr,__FILE__,__LINE__)
#define my_memcpy(dst,src,size) my_memcpy_dbg(dst,src,size,__FILE__,__LINE__)
#define my_memset(dst,c,count) my_memset_dbg(dst,c,count,__FILE__,__LINE__)
#else
#define my_malloc(cnx,size) my_malloc(cnx,size)
#define my_free(cnx,ptr) my_free(cnx,ptr)
#define my_memcpy(dst,src,size) my_memcpy(dst,src,size)
#define my_memset(dst,c,count) my_memset(dst,c,count)
#endif


static inline protoop_arg_t run_noparam_with_pid(picoquic_cnx_t *cnx, char *pid_str, int inputc, protoop_arg_t *inputv, protoop_arg_t *outputv, protoop_id_t *pid) {
    protoop_params_t pp;
    pp.param = NO_PARAM;
    pp.caller_is_intern = true;
    pp.inputc = inputc;
    pp.inputv = inputv;
    pp.outputv = outputv;
    return plugin_run_protoop(cnx, &pp, pid_str, pid);
}
static inline protoop_arg_t run_noparam(picoquic_cnx_t *cnx, char *pid_str, int inputc, protoop_arg_t *inputv, protoop_arg_t *outputv) {
    return run_noparam_with_pid(cnx, pid_str, inputc, inputv, outputv, NULL);
}

static inline protoop_arg_t run_param_with_pid(picoquic_cnx_t *cnx, char *pid_str, param_id_t param, int inputc, protoop_arg_t *inputv, protoop_arg_t *outputv, protoop_id_t *pid) {
    protoop_params_t pp;
    pp.param = param;
    pp.caller_is_intern = true;
    pp.inputc = inputc;
    pp.inputv = inputv;
    pp.outputv = outputv;
    return plugin_run_protoop(cnx, &pp, pid_str, pid);
}

static inline protoop_arg_t run_param(picoquic_cnx_t *cnx, char *pid_str, param_id_t param, int inputc, protoop_arg_t *inputv, protoop_arg_t *outputv) {
    return run_param_with_pid(cnx, pid_str, param, inputc, inputv, outputv, NULL);
}

static __attribute__((always_inline)) void helper_protoop_snprintf(picoquic_cnx_t *cnx, const char *buf, size_t buf_len, const char *fmt, const protoop_arg_t *fmt_args, size_t args_len) {
    protoop_arg_t args[5];
    args[0] = (protoop_arg_t) buf;
    args[1] = buf_len;
    args[2] = (protoop_arg_t) fmt;
    args[3] = (protoop_arg_t) fmt_args;
    args[4] = args_len;
    run_noparam(cnx, PROTOOPID_NOPARAM_SNPRINTF, 5, args, NULL);
}

static uint32_t helper_get_checksum_length(picoquic_cnx_t* cnx, int is_cleartext_mode)
{
    protoop_arg_t args[1];
    args[0] = (protoop_arg_t) is_cleartext_mode;
    return (uint32_t) run_noparam(cnx, PROTOOPID_NOPARAM_GET_CHECKSUM_LENGTH, 1, args, NULL);
}

static __attribute__((always_inline)) void helper_protoop_printf(picoquic_cnx_t *cnx, const char *fmt, protoop_arg_t *fmt_args, size_t args_len)
{
    protoop_arg_t args[3];
    args[0] = (protoop_arg_t) fmt;
    args[1] = (protoop_arg_t) fmt_args;
    args[2] = (protoop_arg_t) args_len;
    run_noparam(cnx, PROTOOPID_NOPARAM_PRINTF, 3, args, NULL);
}

static __attribute__((always_inline)) void helper_log_event(picoquic_cnx_t *cnx, char *args[4], protoop_arg_t *fmt_args, size_t args_len) {
    char *data = my_malloc(cnx, 1024);
    if (!data) return;
    helper_protoop_snprintf(cnx, data, 1024, args[3], fmt_args, args_len);
    protoop_arg_t pargs[5];
    pargs[0] = (protoop_arg_t) args[0];
    pargs[1] = (protoop_arg_t) args[1];
    pargs[2] = (protoop_arg_t) args[2];
    pargs[3] = (protoop_arg_t) NULL;
    pargs[4] = (protoop_arg_t) data;
    run_noparam(cnx, PROTOOPID_NOPARAM_LOG_EVENT, 5, pargs, NULL);
    my_free(cnx, (void *) data);
}

static __attribute__((always_inline)) void helper_push_log_context(picoquic_cnx_t *cnx, char *fmt, protoop_arg_t *fmt_args, size_t args_len) {
    char *data = my_malloc(cnx, 256);
    if (!data) return;
    helper_protoop_snprintf(cnx, data, 256, fmt, fmt_args, args_len);
    protoop_arg_t args[1];
    args[0] = (protoop_arg_t) data;
    run_noparam(cnx, PROTOOPID_NOPARAM_PUSH_LOG_CONTEXT, 1, args, NULL);
    my_free(cnx, (void *) data);
}

static int helper_retransmit_needed_by_packet(picoquic_cnx_t *cnx, picoquic_packet_t *p, uint64_t current_time, int *timer_based_retransmit, char **reason, uint64_t *retransmit_time)
{
    protoop_arg_t outs[PROTOOPARGS_MAX], args[3];
    args[0] = (protoop_arg_t) p;
    args[1] = (protoop_arg_t) current_time;
    args[2] = (protoop_arg_t) *timer_based_retransmit;
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_RETRANSMIT_NEEDED_BY_PACKET, 3, args, outs);
    if (timer_based_retransmit) {
        *timer_based_retransmit = (int) outs[0];
    }
    if (reason != NULL) {
        *reason = (char *) outs[1];
    }
    if (retransmit_time != NULL) {
        *retransmit_time = (uint64_t) outs[2];
    }
    return ret;
}

static __attribute__((always_inline)) void helper_congestion_algorithm_notify(picoquic_cnx_t *cnx, picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification, uint64_t rtt_measurement, uint64_t nb_bytes_acknowledged,
    uint64_t lost_packet_number, uint64_t current_time)
{
    protoop_arg_t args[6];
    args[0] = (protoop_arg_t) path_x;
    args[1] = (protoop_arg_t) notification;
    args[2] = (protoop_arg_t) rtt_measurement;
    args[3] = (protoop_arg_t) nb_bytes_acknowledged;
    args[4] = (protoop_arg_t) lost_packet_number;
    args[5] = (protoop_arg_t) current_time;
    run_noparam(cnx, PROTOOPID_NOPARAM_CONGESTION_ALGORITHM_NOTIFY, 6, args, NULL);
}

static void helper_callback_function(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes,
    size_t length, picoquic_call_back_event_t fin_or_event)
{
    protoop_arg_t args[4];
    args[0] = (protoop_arg_t) stream_id;
    args[1] = (protoop_arg_t) bytes;
    args[2] = (protoop_arg_t) length;
    args[3] = (protoop_arg_t) fin_or_event;
    run_noparam(cnx, PROTOOPID_NOPARAM_CALLBACK_FUNCTION, 4, args, NULL);
}

static int helper_skip_frame(picoquic_cnx_t *cnx, uint8_t* bytes, size_t bytes_max, size_t* consumed, int* pure_ack)
{
    protoop_arg_t args[4], outs[PROTOOPARGS_MAX];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) bytes_max;
    args[2] = (protoop_arg_t) *consumed;
    args[3] = (protoop_arg_t) *pure_ack;
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_SKIP_FRAME, 4, args, outs);
    *consumed = (size_t) outs[0];
    *pure_ack = (int) outs[1];
    return ret;
}

static int helper_check_stream_frame_already_acked(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max, int* no_need_to_repeat)
{
    protoop_arg_t args[3], outs[PROTOOPARGS_MAX];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) bytes_max;
    args[2] = (protoop_arg_t) *no_need_to_repeat;
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_CHECK_STREAM_FRAME_ALREADY_ACKED, 3, args, outs);
    *no_need_to_repeat = (int) outs[0];
    return ret;
}

static uint32_t helper_predict_packet_header_length(picoquic_cnx_t *cnx, picoquic_packet_type_enum packet_type, picoquic_path_t* path_x)
{
    protoop_arg_t args[2];
    args[0] = (protoop_arg_t) packet_type;
    args[1] = (protoop_arg_t) path_x;
    return (uint32_t) run_noparam(cnx, PROTOOPID_NOPARAM_PREDICT_PACKET_HEADER_LENGTH, 2, args, NULL);
}

static int helper_is_stream_frame_unlimited(const uint8_t* bytes)
{
    uint8_t first_byte;
    my_memcpy(&first_byte, &bytes[0], 1);
    return PICOQUIC_BITS_CLEAR_IN_RANGE(first_byte, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max, 0x02);
}

static void helper_dequeue_retransmit_packet(picoquic_cnx_t* cnx, picoquic_packet_t* p, int should_free)
{
    protoop_arg_t args[2];
    args[0] = (protoop_arg_t) p;
    args[1] = (protoop_arg_t) should_free;
    run_noparam(cnx, PROTOOPID_NOPARAM_DEQUEUE_RETRANSMIT_PACKET, 2, args, NULL);
}

/* Decide whether MAX data need to be sent or not */
static int helper_should_send_max_data(picoquic_cnx_t* cnx)
{
    int ret = 0;

    uint64_t data_received = (uint64_t) get_cnx(cnx, AK_CNX_DATA_RECEIVED, 0);
    uint64_t maxdata_local = (uint64_t) get_cnx(cnx, AK_CNX_MAXDATA_LOCAL, 0);
    if (2 * data_received > maxdata_local)
        ret = 1;

    return ret;
}

/* Decide whether to send an MTU probe */
static __attribute__((always_inline)) int helper_is_mtu_probe_needed(picoquic_cnx_t* cnx, picoquic_path_t * path_x)
{
    int ret = 0;

    picoquic_state_enum cnx_state = (picoquic_state_enum) get_cnx(cnx, AK_CNX_STATE, 0);
    unsigned int mtu_probe_sent = (unsigned int) get_path(path_x, AK_PATH_MTU_PROBE_SENT, 0);
    uint32_t send_mtu_max_tried = (uint32_t) get_path(path_x, AK_PATH_SEND_MTU_MAX_TRIED, 0);
    uint32_t send_mtu = (uint32_t) get_path(path_x, AK_PATH_SEND_MTU, 0);
    if ((cnx_state == picoquic_state_client_ready || cnx_state == picoquic_state_server_ready) && mtu_probe_sent == 0 && (send_mtu_max_tried == 0 || (send_mtu + 10) < send_mtu_max_tried)) {
        ret = 1;
    }

    return ret;
}

static int helper_scheduler_write_new_frames(picoquic_cnx_t *cnx, uint8_t *bytes, size_t max_bytes, picoquic_packet_t* packet,
                                             size_t *consumed, unsigned int *is_pure_ack)
{
    protoop_arg_t outs[2];
    protoop_arg_t args[3];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) max_bytes;
    args[2] = (protoop_arg_t) packet;
    int ret = run_noparam(cnx, PROTOOPID_NOPARAM_SCHEDULER_WRITE_NEW_FRAMES, 3, args, outs);
    *consumed = (size_t) outs[0];
    *is_pure_ack &= (unsigned int) outs[1];
    return ret;
}

static picoquic_stream_head *helper_find_ready_stream(picoquic_cnx_t *cnx)
{
    return (picoquic_stream_head *) run_noparam(cnx, PROTOOPID_NOPARAM_FIND_READY_STREAM, 0, NULL, NULL);
}

static picoquic_stream_head *helper_schedule_next_stream(picoquic_cnx_t *cnx, size_t max_size, picoquic_path_t *path)
{
    protoop_arg_t args[2];
    args[0] = (protoop_arg_t) max_size;
    args[1] = (protoop_arg_t) path;
    return (picoquic_stream_head *) run_noparam(cnx, PROTOOPID_NOPARAM_SCHEDULE_NEXT_STREAM, 2, args, NULL);
}

static picoquic_stream_head *helper_find_ready_plugin_stream(picoquic_cnx_t *cnx)
{
    return (picoquic_stream_head *) run_noparam(cnx, PROTOOPID_NOPARAM_FIND_READY_PLUGIN_STREAM, 0, NULL, NULL);
}

static int helper_is_ack_needed(picoquic_cnx_t *cnx, uint64_t current_time, picoquic_packet_context_enum pc,
    picoquic_path_t* path_x)
{
    protoop_arg_t args[3];
    args[0] = (protoop_arg_t) current_time;
    args[1] = (protoop_arg_t) pc;
    args[2] = (protoop_arg_t) path_x;
    return (int) run_noparam(cnx, PROTOOPID_NOPARAM_IS_ACK_NEEDED, 3, args, NULL);
}

static int helper_is_tls_stream_ready(picoquic_cnx_t *cnx)
{
    return (int) run_noparam(cnx, PROTOOPID_NOPARAM_IS_TLS_STREAM_READY, 0, NULL, NULL);
}

static uint32_t helper_prepare_packet_old_context(picoquic_cnx_t *cnx, picoquic_packet_context_enum pc,
    picoquic_path_t * path_x, picoquic_packet_t* packet, size_t send_buffer_max,
    uint64_t current_time, uint32_t * header_length)
{
    protoop_arg_t outs[1];
    protoop_arg_t args[6];
    args[0] = (protoop_arg_t) pc;
    args[1] = (protoop_arg_t) path_x;
    args[2] = (protoop_arg_t) packet;
    args[3] = (protoop_arg_t) send_buffer_max;
    args[4] = (protoop_arg_t) current_time;
    args[5] = (protoop_arg_t) *header_length;
    uint32_t length = (uint32_t) run_noparam(cnx, PROTOOPID_NOPARAM_PREPARE_PACKET_OLD_CONTEXT, 6, args, outs);
    *header_length = (uint32_t) outs[0];
    return length;
}

static int helper_retransmit_needed(picoquic_cnx_t* cnx,
    picoquic_packet_context_enum pc,
    picoquic_path_t * path_x, uint64_t current_time,
    picoquic_packet_t* packet, size_t send_buffer_max, int* is_cleartext_mode, uint32_t* header_length, char **reason)
{
    protoop_arg_t outs[2];
    protoop_arg_t args[7];
    args[0] = (protoop_arg_t) pc;
    args[1] = (protoop_arg_t) path_x;
    args[2] = (protoop_arg_t) current_time;
    args[3] = (protoop_arg_t) packet;
    args[4] = (protoop_arg_t) send_buffer_max;
    args[5] = (protoop_arg_t) *is_cleartext_mode;
    args[6] = (protoop_arg_t) *header_length;
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_RETRANSMIT_NEEDED, 7, args, outs);
    *is_cleartext_mode = (int) outs[0];
    *header_length = (uint32_t) outs[1];
    if (reason) {
        *reason = (char *) outs[2];
    }
    return ret;
}

static uint32_t helper_prepare_mtu_probe(picoquic_cnx_t* cnx,
    picoquic_path_t * path_x,
    uint32_t header_length, uint32_t checksum_length,
    uint8_t* bytes)
{
    protoop_arg_t args[4];
    args[0] = (protoop_arg_t) path_x;
    args[1] = (protoop_arg_t) header_length;
    args[2] = (protoop_arg_t) checksum_length;
    args[3] = (protoop_arg_t) bytes;
    return (uint32_t) run_noparam(cnx, PROTOOPID_NOPARAM_PREPARE_MTU_PROBE, 4, args, NULL);
}

static int helper_prepare_path_challenge_frame(picoquic_cnx_t *cnx, uint8_t* bytes,
    size_t bytes_max, size_t* consumed, picoquic_path_t * path)
{
    protoop_arg_t outs[1];
    protoop_arg_t args[3];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) bytes_max;
    args[2] = (protoop_arg_t) path;
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_PREPARE_PATH_CHALLENGE_FRAME, 3, args, outs);
    *consumed = (size_t) outs[0];
    return ret;
}

static int helper_prepare_ack_frame(picoquic_cnx_t* cnx, uint64_t current_time,
    picoquic_packet_context_enum pc,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[1];
    protoop_arg_t args[5];
    args[0] = (protoop_arg_t) current_time;
    args[1] = (protoop_arg_t) pc;
    args[2] = (protoop_arg_t) bytes;
    args[3] = (protoop_arg_t) bytes_max;
    args[4] = (protoop_arg_t) *consumed;
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_PREPARE_ACK_FRAME, 5, args, outs);
    *consumed = (size_t) outs[0];
    return ret;
}

static int helper_prepare_crypto_hs_frame(picoquic_cnx_t* cnx, int epoch,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[1];
    protoop_arg_t args[4];
    args[0] = (protoop_arg_t) epoch;
    args[1] = (protoop_arg_t) bytes;
    args[2] = (protoop_arg_t) bytes_max;
    args[3] = (protoop_arg_t) *consumed;
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_PREPARE_CRYPTO_HS_FRAME, 4, args, outs);
    *consumed = (size_t) outs[0];
    return ret;
}

static int helper_prepare_first_misc_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
                                      size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[1];
    protoop_arg_t args[3];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) bytes_max;
    args[2] = (protoop_arg_t) *consumed;
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_PREPARE_FIRST_MISC_FRAME, 3, args, outs);
    *consumed = (size_t) outs[0];
    return ret;
}

static int helper_prepare_max_data_frame(picoquic_cnx_t* cnx, uint64_t maxdata_increase,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[1];
    protoop_arg_t args[4];
    args[0] = (protoop_arg_t) maxdata_increase;
    args[1] = (protoop_arg_t) bytes;
    args[2] = (protoop_arg_t) bytes_max;
    args[3] = (protoop_arg_t) *consumed;
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_PREPARE_MAX_DATA_FRAME, 4, args, outs);
    *consumed = (size_t) outs[0];
    return ret;
}

static int helper_prepare_required_max_stream_data_frames(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[1];
    protoop_arg_t args[3];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) bytes_max;
    args[2] = (protoop_arg_t) *consumed;
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_PREPARE_REQUIRED_MAX_STREAM_DATA_FRAME, 3, args, outs);
    *consumed = (size_t)outs[0];
    return ret;
}

static int helper_stream_bytes_max(picoquic_cnx_t* cnx, size_t bytes_max, size_t header_length, uint8_t* bytes)
{
    protoop_arg_t outs[1];
    protoop_arg_t args[3];
    args[0] = (protoop_arg_t) bytes_max;
    args[1] = (protoop_arg_t) header_length;
    args[2] = (protoop_arg_t) bytes;
    run_noparam(cnx, PROTOOPID_NOPARAM_STREAM_BYTES_MAX, 3, args, outs);
    return (size_t) outs[0];
}

static int helper_prepare_stream_frame(picoquic_cnx_t* cnx, picoquic_stream_head* stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[1];
    protoop_arg_t args[3];
    args[0] = (protoop_arg_t) stream;
    args[1] = (protoop_arg_t) bytes;
    args[2] = (protoop_arg_t) bytes_max;
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_PREPARE_STREAM_FRAME, 3, args, outs);
    *consumed = (size_t) outs[0];
    return ret;
}

static int helper_prepare_plugin_frame(picoquic_cnx_t* cnx, picoquic_stream_head* stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    protoop_arg_t outs[1];
    protoop_arg_t args[3];
    args[0] = (protoop_arg_t) stream;
    args[1] = (protoop_arg_t) bytes;
    args[2] = (protoop_arg_t) bytes_max;
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_PREPARE_PLUGIN_FRAME, 3, args, outs);
    *consumed = (size_t) outs[0];
    return ret;
}

static int helper_write_plugin_validate_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t pid_id, char* pid, size_t* consumed, int* is_retransmittable)
{
    protoop_arg_t outs[2];
    plugin_validate_frame_t frame_ctx;
    frame_ctx.pid_id = pid_id;
    frame_ctx.pid_len = strlen(pid) + 1; // To have '\0'
    frame_ctx.pid = pid;
    protoop_arg_t args[3];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) bytes_max;
    args[2] = (protoop_arg_t) &frame_ctx;
    int ret = (int) run_param(cnx, PROTOOPID_PARAM_WRITE_FRAME, picoquic_frame_type_plugin_validate, 3, args, outs);
    *consumed = (size_t) outs[0];
    *is_retransmittable = (int) outs[1];
    return ret;
}

static void helper_finalize_and_protect_packet(picoquic_cnx_t *cnx, picoquic_packet_t * packet, int ret, 
    uint32_t length, uint32_t header_length, uint32_t checksum_overhead,
    size_t * send_length, uint8_t * send_buffer, uint32_t send_buffer_max, 
    picoquic_path_t * path_x, uint64_t current_time)
{
    protoop_arg_t args[10];
    args[0] = (protoop_arg_t) packet;
    args[1] = (protoop_arg_t) ret;
    args[2] = (protoop_arg_t) length;
    args[3] = (protoop_arg_t) header_length;
    args[4] = (protoop_arg_t) checksum_overhead;
    args[5] = (protoop_arg_t) *send_length;
    args[6] = (protoop_arg_t) send_buffer;
    args[7] = (protoop_arg_t) send_buffer_max;
    args[8] = (protoop_arg_t) path_x;
    args[9] = (protoop_arg_t) current_time;
    *send_length = (size_t) run_noparam(cnx, PROTOOPID_NOPARAM_FINALIZE_AND_PROTECT_PACKET, 10, args, NULL);
}

/* TODO: tie with per path scheduling */
static void helper_cnx_set_next_wake_time(picoquic_cnx_t* cnx, uint64_t current_time, uint32_t last_pkt_length)
{
    protoop_arg_t args[2];
    args[0] = (protoop_arg_t) current_time;
    args[1] = (protoop_arg_t) last_pkt_length;
    run_noparam(cnx, PROTOOPID_NOPARAM_SET_NEXT_WAKE_TIME, 2, args, NULL);
}

static picoquic_packet_context_enum helper_context_from_epoch(int epoch)
{
    picoquic_packet_context_enum pc[4];
    pc[0] = picoquic_packet_context_initial;
    pc[1] = picoquic_packet_context_application;
    pc[2] = picoquic_packet_context_handshake;
    pc[3] = picoquic_packet_context_application;

    /* 5 to 4, bug in picoquic... */
    return (epoch >= 0 && epoch < 4) ? pc[epoch] : 0;
}

static int helper_connection_error(picoquic_cnx_t* cnx, uint16_t local_error, uint64_t frame_type)
{
    protoop_arg_t args[2];
    args[0] = (protoop_arg_t) local_error;
    args[1] = (protoop_arg_t) frame_type;
    return (int) run_noparam(cnx, PROTOOPID_NOPARAM_CONNECTION_ERROR, 2, args, NULL);
}

static uint8_t* helper_decode_stream_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max, uint64_t current_time)
{
    protoop_arg_t args[3];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) bytes_max;
    args[2] = (protoop_arg_t) current_time;
    return (uint8_t *) run_noparam(cnx, PROTOOPID_NOPARAM_DECODE_STREAM_FRAME, 3, args, NULL);
}

#define VARINT_LEN(bytes) (1U << (((bytes)[0] & 0xC0) >> 6))

/* Integer parsing macros */
#define PICOPARSE_16(b) ((((uint16_t)(b)[0]) << 8) | (b)[1])
#define PICOPARSE_24(b) ((((uint32_t)PICOPARSE_16(b)) << 16) | ((b)[2]))
#define PICOPARSE_32(b) ((((uint32_t)PICOPARSE_16(b)) << 16) | PICOPARSE_16((b) + 2))
#define PICOPARSE_64(b) ((((uint64_t)PICOPARSE_32(b)) << 32) | PICOPARSE_32((b) + 4))

static uint8_t* helper_frames_uint8_decode(uint8_t* bytes, const uint8_t* bytes_max, uint8_t* n)
{
    if (bytes < bytes_max) {
        my_memcpy(n, bytes, 1);
        bytes++;
    } else {
        bytes = NULL;
    }
    return bytes;
}

static uint8_t *helper_parse_frame(picoquic_cnx_t *cnx, uint8_t frame_type, uint8_t *bytes, const uint8_t *bytes_max,
    void **frame, int *ack_needed, int *is_retransmittable)
{
    protoop_arg_t args[2], outs[3];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) bytes_max;
    uint8_t *ret_bytes = (uint8_t *) run_param(cnx, PROTOOPID_PARAM_PARSE_FRAME, frame_type, 2, args, outs);
    *frame = (void *) outs[0];
    *ack_needed = (int) outs[1];
    *is_retransmittable = (int) outs[2];
    return ret_bytes;
}

static int helper_parse_ack_header(uint8_t const* bytes, size_t bytes_max,
    uint64_t* num_block, uint64_t* nb_ecnx3,
    uint64_t* largest, uint64_t* ack_delay, size_t* consumed,
    uint8_t ack_delay_exponent)
{
    int ret = 0;
    size_t byte_index = 1;
    size_t l_largest = 0;
    size_t l_delay = 0;
    size_t l_blocks = 0;

    if (bytes_max > byte_index) {
        l_largest = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, largest);
        byte_index += l_largest;
    }

    if (bytes_max > byte_index) {
        l_delay = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, ack_delay);
        *ack_delay <<= ack_delay_exponent;
        byte_index += l_delay;
    }

    if (nb_ecnx3 != NULL) {
        for (int ecnx = 0; ecnx < 3; ecnx++) {
            size_t l_ecnx = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &nb_ecnx3[ecnx]);

            if (l_ecnx == 0) {
                byte_index = bytes_max;
            }
            else {
                byte_index += l_ecnx;
            }
        }
    }

    if (bytes_max > byte_index) {
        l_blocks = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, num_block);
        byte_index += l_blocks;
    }

    if (l_largest == 0 || l_delay == 0 || l_blocks == 0 || bytes_max < byte_index) {
        // DBG_PRINTF("ack frame fixed header too large: first_byte=0x%02x, bytes_max=%" PRIst,
        //     bytes[0], bytes_max);
        byte_index = bytes_max;
        ret = -1;
    }

    *consumed = byte_index;
    return ret;
}

static picoquic_packet_t* helper_update_rtt(picoquic_cnx_t* cnx, uint64_t largest,
    uint64_t current_time, uint64_t ack_delay, picoquic_packet_context_enum pc,
    picoquic_path_t* path_x)
{
    protoop_arg_t args[5];
    args[0] = (protoop_arg_t) largest;
    args[1] = (protoop_arg_t) current_time;
    args[2] = (protoop_arg_t) ack_delay;
    args[3] = (protoop_arg_t) pc;
    args[4] = (protoop_arg_t) path_x;
    return (picoquic_packet_t *) run_noparam(cnx, PROTOOPID_NOPARAM_UPDATE_RTT, 5, args, NULL);
}

static int helper_process_ack_range(
    picoquic_cnx_t* cnx, picoquic_packet_context_enum pc, uint64_t highest, uint64_t range, picoquic_packet_t** ppacket,
    uint64_t current_time)
{
    protoop_arg_t args[5], outs[1];
    args[0] = (protoop_arg_t) pc;
    args[1] = (protoop_arg_t) highest;
    args[2] = (protoop_arg_t) range;
    args[3] = (protoop_arg_t) *ppacket;
    args[4] = (protoop_arg_t) current_time;
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_PROCESS_ACK_RANGE, 5, args, outs);
    *ppacket = (picoquic_packet_t*) outs[0];
    return ret;
}

static void helper_check_spurious_retransmission(picoquic_cnx_t* cnx,
    uint64_t start_of_range, uint64_t end_of_range, uint64_t current_time,
    picoquic_packet_context_enum pc, picoquic_path_t* path_x)
{
    protoop_arg_t args[5];
    args[0] = (protoop_arg_t) start_of_range;
    args[1] = (protoop_arg_t) end_of_range;
    args[2] = (protoop_arg_t) current_time;
    args[3] = (protoop_arg_t) pc;
    args[4] = (protoop_arg_t) path_x;
    run_noparam(cnx, PROTOOPID_NOPARAM_CHECK_SPURIOUS_RETRANSMISSION, 5, args, NULL);
}

static void helper_process_possible_ack_of_ack_frame(picoquic_cnx_t* cnx, picoquic_packet_t* p)
{
    protoop_arg_t args[1];
    args[0] = (protoop_arg_t) p;
    run_noparam(cnx, PROTOOPID_NOPARAM_PROCESS_POSSIBLE_ACK_OF_ACK_FRAME, 1, args, NULL);
}

static int helper_process_ack_of_stream_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max, size_t* consumed)
{
    protoop_arg_t args[3], outs[1];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) bytes_max;
    args[2] = (protoop_arg_t) *consumed;
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_PROCESS_ACK_OF_STREAM_FRAME, 3, args, outs);
    *consumed = (size_t) outs[0];
    return ret;
}

/**
 *  return_values must contain 5 pointers to:
 *
 *  uint64_t* stream_id
 *  uint64_t* offset
 *  size_t* data_length
 *  int* fin
    size_t* consumed
 */
static int helper_parse_stream_header(const uint8_t* bytes, size_t bytes_max, protoop_arg_t** return_values) {
    int ret = 0;
    uint8_t first_byte;
    my_memcpy(&first_byte, bytes, 1);
    int len = first_byte & 2;
    int off = first_byte & 4;
    uint64_t length = 0;
    size_t l_stream = 0;
    size_t l_len = 0;
    size_t l_off = 0;
    size_t byte_index = 1;

    uint64_t* stream_id = *(return_values);
    uint64_t* offset = *(return_values + 1);
    size_t* data_length = *(return_values + 2);
    int* fin = (int *) *(return_values + 3);
    size_t* consumed = *(return_values + 4);

    *fin = first_byte & 1;

    if (bytes_max > byte_index) {
        l_stream = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, stream_id);
        byte_index += l_stream;
    }

    if (off == 0) {
        *offset = 0;
    } else if (bytes_max > byte_index) {
        l_off = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, offset);
        byte_index += l_off;
    }

    if (bytes_max < byte_index || l_stream == 0 || (off != 0 && l_off == 0)) {
        //DBG_PRINTF("stream frame header too large: first_byte=0x%02x, bytes_max=%" PRIst, bytes[0], bytes_max);
        *data_length = 0;
        byte_index = bytes_max;
        ret = -1;
    } else if (len == 0) {
        *data_length = bytes_max - byte_index;
    } else {
        if (bytes_max > byte_index) {
            l_len = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &length);
            byte_index += l_len;
            *data_length = (size_t)length;
        }

        if (l_len == 0 || bytes_max < byte_index) {
            //DBG_PRINTF("stream frame header too large: first_byte=0x%02x, bytes_max=%" PRIst, bytes[0], bytes_max);
            byte_index = bytes_max;
            ret = -1;
        } else if (byte_index + length > bytes_max) {
            //DBG_PRINTF("stream data past the end of the packet: first_byte=0x%02x, data_length=%" PRIst ", max_bytes=%" PRIst, bytes[0], *data_length, bytes_max);
            ret = -1;
        }
    }

    *consumed = byte_index;
    return ret;
}

static int helper_packet_was_retransmitted(picoquic_cnx_t* cnx, char* reason, picoquic_packet_t *p)
{
    protoop_arg_t args[1], outs[0];
    args[0] = (protoop_arg_t) p;
    int ret = (int) run_noparam(cnx, reason, 1, args, outs);
    return ret;
}

static int helper_packet_was_lost(picoquic_cnx_t *cnx, picoquic_packet_t *packet, picoquic_path_t *path) {
    protoop_arg_t args[2];
    args[0] = (protoop_arg_t) packet;
    args[1] = (protoop_arg_t) path;
    return run_noparam(cnx, PROTOOPID_NOPARAM_PACKET_WAS_LOST, 2, args, NULL);
}

static __attribute__((always_inline)) void helper_process_ack_of_ack_range(picoquic_cnx_t *cnx, picoquic_sack_item_t *first_sack,
    uint64_t start_range, uint64_t end_range)
{
    protoop_arg_t args[3];
    args[0] = (protoop_arg_t) first_sack;
    args[1] = (protoop_arg_t) start_range;
    args[2] = (protoop_arg_t) end_range;
    run_noparam(cnx, PROTOOPID_NOPARAM_PROCESS_ACK_OF_ACK_RANGE, 3, args, NULL);
}

#define TMP_FRAME_BEGIN(cnx, parsed_frame, local_frame, frame_type)                                                     \
    frame_type *parsed_frame = (frame_type *) get_cnx(cnx, AK_CNX_OUTPUT, 0);                                           \
    if (parsed_frame) {                                                                                                 \
        frame_type local_frame;                                                                                         \
        my_memcpy(&local_frame, parsed_frame, sizeof(frame_type));                                                      \


#define TMP_FRAME_END }

#define TMP_FRAME_BEGIN_MALLOC(cnx, parsed_frame, local_frame, frame_type)                                                     \
    frame_type *parsed_frame = (frame_type *) get_cnx(cnx, AK_CNX_OUTPUT, 0);                                           \
    if (parsed_frame) {                                                                                                 \
        frame_type *local_frame = (frame_type *) my_malloc(cnx, sizeof(frame_type));                                    \
        if (!local_frame) return 0;                                                                                     \
        my_memcpy(local_frame, parsed_frame, sizeof(frame_type));                                                       \


#define TMP_FRAME_END_MALLOC(cnx, local_frame) \
        my_free(cnx, local_frame); \
    }

#endif