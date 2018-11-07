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

#define COP2_OPAQUE_ID 0x02
#define BILLION ((unsigned int) 1000000)


#define CMP_SOCKADDR(a, b)  (picoquic_compare_addr((struct sockaddr *)&a, (struct sockaddr *)&b))
#define CMP_SOCKADDR_PTR(a, b)  (picoquic_compare_addr((struct sockaddr *)a, (struct sockaddr *)b))
#define TIME_SUBTRACT_MS(a, b)  (((b.tv_sec - a.tv_sec) * 1000) + (((unsigned long)(b.tv_nsec - a.tv_nsec)) / BILLION))

typedef struct {
    /* sum in bytes */
    uint64_t data_sent;
    uint64_t data_recv;
    uint64_t data_lost;
    uint64_t data_ooo;
    uint64_t data_dupl;

    /* sum in packets */
    uint64_t pkt_sent;
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
} __attribute__((packed, aligned(8))) cop2_metrics;

typedef struct st_cop2_path_metrics {
    struct timespec t_start;
    struct timespec t_end;

    picoquic_connection_id_t icid;
    picoquic_connection_id_t dcid;  /* We may want to add a kind of CID update message */
    picoquic_connection_id_t scid;  /* Or just send all the CIDs that were used on this path */

    int local_addr_len;
    struct sockaddr_storage local_addr;
    int peer_addr_len;
    struct sockaddr_storage peer_addr;

    cop2_metrics metrics;
    struct st_cop2_path_metrics *next;
} __attribute__((packed, aligned(8))) cop2_path_metrics;

typedef struct {  // We might want to add CIDs to this
    cop2_path_metrics handshake_metrics;
    cop2_path_metrics *established_metrics;
} cop2_conn_metrics;

static __attribute__((always_inline)) cop2_conn_metrics *initialize_metrics_data(picoquic_cnx_t *cnx)  // TODO: We need to free it as well
{
    cop2_conn_metrics *metrics = (cop2_conn_metrics *) my_malloc(cnx, sizeof(cop2_conn_metrics));
    if (!metrics) return NULL;
    my_memset(metrics, 0, sizeof(cop2_conn_metrics));
    return metrics;
}

static __attribute__((always_inline)) cop2_conn_metrics *get_cop2_metrics(picoquic_cnx_t *cnx)
{
    int allocated = 0;
    cop2_conn_metrics **bpfd_ptr = (cop2_conn_metrics **) get_opaque_data(cnx, COP2_OPAQUE_ID, sizeof(cop2_conn_metrics *), &allocated);
    if (!bpfd_ptr) return NULL;
    if (allocated) {
        *bpfd_ptr = initialize_metrics_data(cnx);
        clock_gettime(CLOCK_MONOTONIC, &((*bpfd_ptr)->handshake_metrics.t_start));
    }
    return *bpfd_ptr;
}

static __attribute__((always_inline)) int count_paths(cop2_conn_metrics *metrics) {
    int n_paths = 1;  // There always exists the handshake path
    cop2_path_metrics *path = metrics->established_metrics;
    while (path != NULL) {
        n_paths++;
        path = path->next;
    }
    return n_paths;
}

static __attribute__((always_inline)) int copy_path(char *dst, cop2_path_metrics *path) {
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
    my_memcpy(dst + copied, &path->metrics, sizeof(cop2_metrics));
    copied += sizeof(cop2_metrics);
    return copied;
}

static __attribute__((always_inline)) cop2_path_metrics *find_metrics_for_path(picoquic_cnx_t *cnx, cop2_conn_metrics *metrics, picoquic_path_t *path)
{
    cop2_path_metrics *prev_path = NULL;
    cop2_path_metrics *path_metrics = metrics->established_metrics;
    struct sockaddr_storage *path_local_addr = (struct sockaddr_storage *) get_path(path, PATH_AK_LOCAL_ADDR, 0);
    struct sockaddr_storage *path_peer_addr = (struct sockaddr_storage *) get_path(path, PATH_AK_PEER_ADDR, 0);
    while(path_metrics != NULL && CMP_SOCKADDR_PTR(&path_metrics->local_addr, path_local_addr) && CMP_SOCKADDR_PTR(&path_metrics->peer_addr, path_peer_addr)) {
        prev_path = path_metrics;
        path_metrics = path_metrics->next;
    }

    if (path_metrics == NULL) {
        if (prev_path == NULL) {
            metrics->established_metrics = (cop2_path_metrics *) my_malloc(cnx, sizeof(cop2_path_metrics));
            path_metrics = metrics->established_metrics;
        } else {
            prev_path->next = (cop2_path_metrics *) my_malloc(cnx, sizeof(cop2_path_metrics));
            path_metrics = prev_path->next;
        }

        my_memset(path_metrics, 0, sizeof(cop2_path_metrics));
        picoquic_connection_id_t *initial_cnxid = (picoquic_connection_id_t *) get_cnx(cnx, CNX_AK_INITIAL_CID, 0);
        picoquic_connection_id_t *remote_cnxid = (picoquic_connection_id_t *) get_path(path, PATH_AK_REMOTE_CID, 0);
        picoquic_connection_id_t *local_cnxid = (picoquic_connection_id_t *) get_path(path, PATH_AK_LOCAL_CID, 0);
        my_memcpy(&path_metrics->icid, initial_cnxid, sizeof(picoquic_connection_id_t));
        my_memcpy(&path_metrics->dcid, remote_cnxid, sizeof(picoquic_connection_id_t));
        my_memcpy(&path_metrics->scid, local_cnxid, sizeof(picoquic_connection_id_t));
        int local_addr_len = (int) get_path(path, PATH_AK_LOCAL_ADDR_LEN, 0);
        my_memcpy(&path_metrics->local_addr, path_local_addr, local_addr_len);
        path_metrics->local_addr_len = local_addr_len;
        int peer_addr_len = (int) get_path(path, PATH_AK_PEER_ADDR_LEN, 0);
        my_memcpy(&path_metrics->peer_addr, path_peer_addr, peer_addr_len);
        path_metrics->peer_addr_len = peer_addr_len;
        clock_gettime(CLOCK_MONOTONIC, &path_metrics->t_start);
    }

    return path_metrics;
}

static __attribute__((always_inline)) void complete_path(cop2_path_metrics *path_metrics, picoquic_cnx_t *cnx, picoquic_path_t *path) {
    picoquic_connection_id_t *initial_cnxid = (picoquic_connection_id_t *) get_cnx(cnx, CNX_AK_INITIAL_CID, 0);
    picoquic_connection_id_t *remote_cnxid = (picoquic_connection_id_t *) get_path(path, PATH_AK_REMOTE_CID, 0);
    picoquic_connection_id_t *local_cnxid = (picoquic_connection_id_t *) get_path(path, PATH_AK_LOCAL_CID, 0);
    if (path_metrics->icid.id_len == 0 && initial_cnxid->id_len > 0) {
        my_memcpy(&path_metrics->icid, initial_cnxid, sizeof(picoquic_connection_id_t));
    }
    if (path_metrics->dcid.id_len == 0 && remote_cnxid->id_len > 0) {
        my_memcpy(&path_metrics->dcid, remote_cnxid, sizeof(picoquic_connection_id_t));
    }
    if (path_metrics->scid.id_len == 0 && local_cnxid->id_len > 0) {
        my_memcpy(&path_metrics->scid, local_cnxid, sizeof(picoquic_connection_id_t));
    }
    struct sockaddr_storage *path_local_addr = (struct sockaddr_storage *) get_path(path, PATH_AK_LOCAL_ADDR, 0);
    int local_addr_len = (int) get_path(path, PATH_AK_LOCAL_ADDR_LEN, 0);
    struct sockaddr_storage *path_peer_addr = (struct sockaddr_storage *) get_path(path, PATH_AK_PEER_ADDR, 0);
    int peer_addr_len = (int) get_path(path, PATH_AK_PEER_ADDR_LEN, 0);
    my_memcpy(&path_metrics->local_addr, path_local_addr, local_addr_len);
    path_metrics->local_addr_len = local_addr_len;
    my_memcpy(&path_metrics->peer_addr, path_peer_addr, peer_addr_len);
    path_metrics->peer_addr_len = peer_addr_len;
    clock_gettime(CLOCK_MONOTONIC, &path_metrics->t_end);
}

static __attribute__((always_inline)) void dump_metrics(picoquic_cnx_t *cnx, cop2_conn_metrics *metrics) {
    struct sockaddr_in si;
    memset(&si, 0, sizeof(struct sockaddr_in));
    si.sin_family = AF_INET;
    si.sin_port = my_htons(55555);
    inet_aton("127.0.0.1", &si.sin_addr);

    int n_paths = count_paths(metrics);
    size_t len_path_metrics = sizeof(long) + 2 * (sizeof(int) + sizeof(struct sockaddr_storage)) + sizeof(cop2_metrics);

    char *buf = (char *) my_malloc(cnx, (unsigned int) (n_paths * len_path_metrics));
    if (buf == NULL) {
        //PROTOOP_PRINTF(cnx, "FATAL: Failed to dump metrics: could not allocate buffer");
        return;
    }

    size_t copied = 0;
    copied += copy_path(buf + copied, &metrics->handshake_metrics);
    cop2_path_metrics *path = metrics->established_metrics;
    for (int i = 1; i < n_paths; ++i) {
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
