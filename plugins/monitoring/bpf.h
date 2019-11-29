#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "endianness.h"
#include "picoquic.h"
#include "memory.h"
#include "memcpy.h"
#include "util.h"
#include "getset.h"

#define MONITORING_OPAQUE_ID 0x02
#define BILLION ((unsigned int) 1000000)

#define CMP_SOCKADDR(a, b)  (picoquic_compare_addr((struct sockaddr *)&a, (struct sockaddr *)&b))
#define CMP_SOCKADDR_PTR(a, b)  (picoquic_compare_addr((struct sockaddr *)a, (struct sockaddr *)b))
#define TIME_SUBTRACT_MS(a, b)  (((b.tv_sec - a.tv_sec) * 1000) + (((unsigned long)(b.tv_nsec - a.tv_nsec)) / BILLION))

#define FLOW_STATE_NEW 1
#define FLOW_STATE_ESTABLISHED 2
#define FLOW_STATE_UPDATE 3
#define FLOW_STATE_FINISHED 4
#define FLOW_STATE_BROKEN 5
#define FLOW_STATE_UNREACHABLE 6

typedef struct {
    /* sum in bytes */
    uint64_t data_sent;
    uint64_t data_recv;
    uint64_t data_lost;
    uint64_t data_ooo;
    uint64_t data_dupl;

    /* sum in packets */
    uint64_t pkt_sent;
    uint64_t pkt_pure_ack_sent;
    uint64_t pkt_recv;
    uint64_t pkt_lost;
    uint64_t pkt_ooo;
    uint64_t pkt_dupl;

    /* event counts */
    uint64_t frt_fired;
    uint64_t ert_fired;
    uint64_t rto_fired;
    uint64_t tlp_fired;

    /* time in msec */
    uint64_t smoothed_rtt;
    uint64_t rtt_variance;

    /* time in µsec */
    uint64_t ack_delay;
    uint64_t max_ack_delay;
} __attribute__((packed, aligned(8))) monitoring_metrics;

typedef struct {
    /* QUIC streams */
    uint64_t streams_opened;
    uint64_t streams_closed;

    /* Flow control */
    uint64_t max_recv_buf;
    uint64_t peer_max_recv_buf;

    uint64_t app_data_sent;
} monitoring_quic_metrics;

typedef struct st_monitoring_path_metrics {
    struct timespec t_start;
    struct timespec t_end;

    picoquic_connection_id_t icid;
    picoquic_connection_id_t dcid;  /* We may want to add a kind of CID update message */
    picoquic_connection_id_t scid;  /* Or just send all the CIDs that were used on this path */

    int local_addr_len;
    struct sockaddr_storage local_addr;
    int peer_addr_len;
    struct sockaddr_storage peer_addr;

    monitoring_metrics metrics;
    struct st_monitoring_path_metrics *next;
} __attribute__((packed, aligned(8))) monitoring_path_metrics;

typedef struct st_monitoring_tp {
    uint16_t type;
    uint16_t length;
    uint8_t *value;
    struct st_monitoring_tp *next;
} monitoring_tp;

typedef struct {  // We might want to add CIDs to this
    monitoring_quic_metrics quic_metrics;
    int n_unknown_tps;
    monitoring_tp *unknown_tps;
    monitoring_tp *unknown_tps_tail;
    monitoring_path_metrics handshake_metrics;
    int n_established_paths;
    monitoring_path_metrics *established_metrics;
} monitoring_conn_metrics;

static __attribute__((always_inline)) monitoring_conn_metrics *initialize_metrics_data(picoquic_cnx_t *cnx)  // TODO: We need to free it as well
{
    monitoring_conn_metrics *metrics = (monitoring_conn_metrics *) my_malloc(cnx, sizeof(monitoring_conn_metrics));
    if (!metrics) return NULL;
    my_memset(metrics, 0, sizeof(monitoring_conn_metrics));
    return metrics;
}

static __attribute__((always_inline)) monitoring_conn_metrics *get_monitoring_metrics(picoquic_cnx_t *cnx)
{
    monitoring_conn_metrics *bpfd_ptr = (monitoring_conn_metrics *) get_cnx_metadata(cnx, MONITORING_OPAQUE_ID);
    if (!bpfd_ptr) {
        bpfd_ptr = initialize_metrics_data(cnx);
        my_memset(bpfd_ptr, 0, sizeof(monitoring_conn_metrics));
        clock_gettime(CLOCK_MONOTONIC, &((bpfd_ptr)->handshake_metrics.t_start));
        set_cnx_metadata(cnx, MONITORING_OPAQUE_ID, (protoop_arg_t) bpfd_ptr);
    }
    return bpfd_ptr;
}

static __attribute__((always_inline)) int copy_path(char *dst, monitoring_path_metrics *path) {
    int copied = 0;

    long elapsed = TIME_SUBTRACT_MS(path->t_start, path->t_end);
    my_memcpy(dst + copied, &elapsed, sizeof(long));
    copied += sizeof(long);
    *(dst + copied) = path->icid.id_len;
    copied += sizeof(uint8_t);
    my_memcpy(dst + copied, &path->icid.id, path->icid.id_len);
    copied += path->icid.id_len;
    *(dst + copied) = path->dcid.id_len;
    copied += sizeof(uint8_t);
    my_memcpy(dst + copied, &path->dcid.id, path->dcid.id_len);
    copied += path->dcid.id_len;
    *(dst + copied) = path->scid.id_len;
    copied += sizeof(uint8_t);
    my_memcpy(dst + copied, &path->scid.id, path->scid.id_len);
    copied += path->scid.id_len;
    my_memcpy(dst + copied, &path->local_addr_len, sizeof(int));
    copied += sizeof(int);
    my_memcpy(dst + copied, &path->local_addr, (size_t) path->local_addr_len);
    copied += path->local_addr_len;
    my_memcpy(dst + copied, &path->peer_addr_len, sizeof(int));
    copied += sizeof(int);
    my_memcpy(dst + copied, &path->peer_addr, (size_t) path->peer_addr_len);
    copied += path->peer_addr_len;
    my_memcpy(dst + copied, &path->metrics, sizeof(monitoring_metrics));
    copied += sizeof(monitoring_metrics);
    return copied;
}

static __attribute__((always_inline)) int unknown_tps_length(monitoring_conn_metrics *metrics) {
    int length = sizeof(int);
    monitoring_tp *tp = metrics->unknown_tps;
    while(tp != NULL) {
        length += 2 * sizeof(uint16_t);
        length += tp->length;
        tp = tp->next;
    }
    return length;
}

static __attribute__((always_inline)) monitoring_path_metrics *find_metrics_for_path(picoquic_cnx_t *cnx, monitoring_conn_metrics *metrics, picoquic_path_t *path)
{
    monitoring_path_metrics *prev_path = NULL;
    monitoring_path_metrics *path_metrics = metrics->established_metrics;
    struct sockaddr_storage *path_local_addr = (struct sockaddr_storage *) get_path(path, AK_PATH_LOCAL_ADDR, 0);
    struct sockaddr_storage *path_peer_addr = (struct sockaddr_storage *) get_path(path, AK_PATH_PEER_ADDR, 0);
    int limit = metrics->n_established_paths; // T2 oddity
    for(int i = 0; i < limit && CMP_SOCKADDR_PTR(&path_metrics->local_addr, path_local_addr) && CMP_SOCKADDR_PTR(&path_metrics->peer_addr, path_peer_addr); i++) {
        prev_path = path_metrics;
        path_metrics = path_metrics->next;
    }

    if (path_metrics == NULL) {
        if (prev_path == NULL) {
            metrics->established_metrics = (monitoring_path_metrics *) my_malloc(cnx, sizeof(monitoring_path_metrics));
            path_metrics = metrics->established_metrics;
        } else {
            prev_path->next = (monitoring_path_metrics *) my_malloc(cnx, sizeof(monitoring_path_metrics));
            path_metrics = prev_path->next;
        }

        metrics->n_established_paths++;
        my_memset(path_metrics, 0, sizeof(monitoring_path_metrics));
        picoquic_connection_id_t *initial_cnxid = (picoquic_connection_id_t *) get_cnx(cnx, AK_CNX_INITIAL_CID, 0);
        picoquic_connection_id_t *remote_cnxid = (picoquic_connection_id_t *) get_path(path, AK_PATH_REMOTE_CID, 0);
        picoquic_connection_id_t *local_cnxid = (picoquic_connection_id_t *) get_path(path, AK_PATH_LOCAL_CID, 0);
        my_memcpy(&path_metrics->icid, initial_cnxid, sizeof(picoquic_connection_id_t));
        my_memcpy(&path_metrics->dcid, remote_cnxid, sizeof(picoquic_connection_id_t));
        my_memcpy(&path_metrics->scid, local_cnxid, sizeof(picoquic_connection_id_t));
        int local_addr_len = (int) get_path(path, AK_PATH_LOCAL_ADDR_LEN, 0);
        my_memcpy(&path_metrics->local_addr, path_local_addr, local_addr_len);
        path_metrics->local_addr_len = local_addr_len;
        int peer_addr_len = (int) get_path(path, AK_PATH_PEER_ADDR_LEN, 0);
        my_memcpy(&path_metrics->peer_addr, path_peer_addr, peer_addr_len);
        path_metrics->peer_addr_len = peer_addr_len;
        clock_gettime(CLOCK_MONOTONIC, &path_metrics->t_start);

        if (CMP_SOCKADDR_PTR(&path_metrics->local_addr, &metrics->handshake_metrics.local_addr) && CMP_SOCKADDR_PTR(&path_metrics->peer_addr, &metrics->handshake_metrics.local_addr)) {
            path_metrics->metrics = metrics->handshake_metrics.metrics;
        }
    }

    return path_metrics;
}

static __attribute__((always_inline)) void complete_path(monitoring_path_metrics *path_metrics, picoquic_cnx_t *cnx, picoquic_path_t *path) {
    picoquic_connection_id_t *initial_cnxid = (picoquic_connection_id_t *) get_cnx(cnx, AK_CNX_INITIAL_CID, 0);
    picoquic_connection_id_t *remote_cnxid = (picoquic_connection_id_t *) get_path(path, AK_PATH_REMOTE_CID, 0);
    picoquic_connection_id_t *local_cnxid = (picoquic_connection_id_t *) get_path(path, AK_PATH_LOCAL_CID, 0);
    uint8_t initial_cnxid_len = (uint8_t) get_cnxid(initial_cnxid, AK_CNXID_LEN);
    uint8_t remote_cnxid_len = (uint8_t) get_cnxid(remote_cnxid, AK_CNXID_LEN);
    uint8_t local_cnxid_len = (uint8_t) get_cnxid(local_cnxid, AK_CNXID_LEN);
    if (path_metrics->icid.id_len == 0 && initial_cnxid_len > 0) {
        my_memcpy(&path_metrics->icid, initial_cnxid, sizeof(picoquic_connection_id_t));
    }
    if (path_metrics->dcid.id_len == 0 && remote_cnxid_len > 0) {
        my_memcpy(&path_metrics->dcid, remote_cnxid, sizeof(picoquic_connection_id_t));
    }
    if (path_metrics->scid.id_len == 0 && local_cnxid_len > 0) {
        my_memcpy(&path_metrics->scid, local_cnxid, sizeof(picoquic_connection_id_t));
    }
    struct sockaddr_storage *path_local_addr = (struct sockaddr_storage *) get_path(path, AK_PATH_LOCAL_ADDR, 0);
    int local_addr_len = (int) get_path(path, AK_PATH_LOCAL_ADDR_LEN, 0);
    struct sockaddr_storage *path_peer_addr = (struct sockaddr_storage *) get_path(path, AK_PATH_PEER_ADDR, 0);
    int peer_addr_len = (int) get_path(path, AK_PATH_PEER_ADDR_LEN, 0);
    my_memcpy(&path_metrics->local_addr, path_local_addr, local_addr_len);
    path_metrics->local_addr_len = local_addr_len;
    my_memcpy(&path_metrics->peer_addr, path_peer_addr, peer_addr_len);
    path_metrics->peer_addr_len = peer_addr_len;
    clock_gettime(CLOCK_MONOTONIC, &path_metrics->t_end);
}

static __attribute__((always_inline)) void dump_metrics(picoquic_cnx_t *cnx, monitoring_conn_metrics *metrics) {
    struct sockaddr_in si;
    memset(&si, 0, sizeof(struct sockaddr_in));
    si.sin_family = AF_INET;
    si.sin_port = my_htons(55555);
    inet_aton("127.0.0.1", &si.sin_addr);

    int n_paths = metrics->n_established_paths + 1;
    size_t len_path_metrics = sizeof(long) + 2 * (sizeof(int) + sizeof(struct sockaddr_storage)) + sizeof(monitoring_metrics);

    char *buf = (char *) my_malloc(cnx, (unsigned int) (n_paths * len_path_metrics));
    if (buf == NULL) {
        //PROTOOP_PRINTF(cnx, "FATAL: Failed to dump metrics: could not allocate buffer");
        return;
    }

    size_t copied = 0;
    copied += copy_path(buf + copied, &metrics->handshake_metrics);
    monitoring_path_metrics *path = metrics->established_metrics;
    for (int i = 1; i < n_paths; i++) {
        copied += copy_path(buf + copied, path);
        path = path->next;
    }

    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    connect(udp_socket, (struct sockaddr *) &si, sizeof(struct sockaddr_in));
    ssize_t sent = send(udp_socket, buf, copied, 0);
    if (sent > 0) {
        //PROTOOP_PRINTF(cnx, "Metrics dumped\n");
    }
    my_free(cnx, buf);
}


static __attribute__((always_inline)) void send_path_metrics_to_exporter(picoquic_cnx_t *cnx, monitoring_path_metrics *path_metrics, uint8_t flow_start_reason, uint8_t flow_end_reason) {
    struct sockaddr_in si;
    memset(&si, 0, sizeof(struct sockaddr_in));
    si.sin_family = AF_INET;
    si.sin_port = my_htons(55555);
    inet_aton("127.0.0.1", &si.sin_addr);

    monitoring_conn_metrics *metrics = get_monitoring_metrics(cnx);
    size_t len_path_metrics = sizeof(long) + 2 * (sizeof(int) + sizeof(struct sockaddr_storage)) + sizeof(monitoring_metrics) + sizeof(monitoring_quic_metrics) + unknown_tps_length(metrics);
    len_path_metrics += 2; // Accounts for flow states
    char *buf = (char *) my_malloc(cnx, (unsigned int) (len_path_metrics));
    if (buf == NULL) {
        PROTOOP_PRINTF(cnx, "Unable to allocate %d-byte buffer\n", len_path_metrics);
        return;
    }

    my_memcpy(buf, &get_monitoring_metrics(cnx)->quic_metrics, sizeof(monitoring_quic_metrics));
    size_t copied = sizeof(monitoring_quic_metrics);
    my_memcpy(buf + copied, &metrics->n_unknown_tps, sizeof(int));
    copied += sizeof(int);
    monitoring_tp *tp = metrics->unknown_tps;
    while(tp != NULL) {
        my_memcpy(buf + copied, &tp->type, sizeof(uint16_t));
        copied += sizeof(uint16_t);
        my_memcpy(buf + copied, &tp->length, sizeof(uint16_t));
        copied += sizeof(uint16_t);
        my_memcpy(buf + copied, tp->value, tp->length);
        copied += tp->length;
        tp = tp->next;
    }
    buf[copied] = flow_start_reason;
    buf[copied + 1] = flow_end_reason;
    copied += 2;
    copied += (size_t) copy_path(buf + copied, path_metrics);

    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    connect(udp_socket, (struct sockaddr *) &si, sizeof(struct sockaddr_in));
    ssize_t sent = send(udp_socket, buf, copied, 0);
    if (sent < copied) {
        PROTOOP_PRINTF(cnx, "Unable to send path metrics\n");
    }
    my_free(cnx, buf);
}