#include "picoquic_internal.h"
#include "memory.h"
#include "memcpy.h"
#include "util.h"
#include <string.h>

#define COP2_OPAQUE_ID 0x02

#define CMP_SOCKADDR(a, b)  (picoquic_compare_addr((struct sockaddr *)&a, (struct sockaddr *)&b))

typedef struct {
    /* sum in bytes */
    size_t data_sent;
    size_t data_recv;
    size_t data_lost;
    size_t data_ooo;

    /* time in msec */
    uint64_t mean_rtt;
    uint64_t rtt_variance;
} cop2_metrics;

typedef struct st_cop2_path_metrics{
    struct sockaddr_storage peer_addr;
    int peer_addr_len;
    struct sockaddr_storage local_addr;
    int local_addr_len;

    cop2_metrics metrics;
    struct st_cop2_path_metrics *next;
} cop2_path_metrics;

typedef struct {
    cop2_path_metrics handshake_metrics;
    cop2_path_metrics *established_metrics;
} cop2_conn_metrics;

static cop2_conn_metrics *initialize_metrics_data(picoquic_cnx_t *cnx)
{
    cop2_conn_metrics *metrics = (cop2_conn_metrics *) my_malloc(cnx, sizeof(cop2_conn_metrics));
    if (!metrics) return NULL;
    my_memset(metrics, 0, sizeof(cop2_conn_metrics));
    return metrics;
}

static cop2_conn_metrics *get_cop2_metrics(picoquic_cnx_t *cnx)
{
    int allocated = 0;
    cop2_conn_metrics **bpfd_ptr = (cop2_conn_metrics **) get_opaque_data(cnx, COP2_OPAQUE_ID, sizeof(cop2_conn_metrics *), &allocated);
    if (!bpfd_ptr) return NULL;
    if (allocated) {
        *bpfd_ptr = initialize_metrics_data(cnx);
    }
    return *bpfd_ptr;
}

static cop2_path_metrics *find_metrics_for_path(picoquic_cnx_t *cnx, cop2_conn_metrics *metrics, picoquic_path_t *path)
{
    cop2_path_metrics *prev_path = NULL;
    cop2_path_metrics *path_metrics = metrics->established_metrics;
    while(path_metrics != NULL && CMP_SOCKADDR(path_metrics->local_addr, path->local_addr) && CMP_SOCKADDR(path_metrics->peer_addr, path->peer_addr)) {
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

        my_memcpy(&path_metrics->local_addr, &path->local_addr, path->local_addr_len);
        path_metrics->local_addr_len = path->local_addr_len;
        my_memcpy(&path_metrics->peer_addr, &path->peer_addr, path->peer_addr_len);
        path_metrics->peer_addr_len = path->peer_addr_len;
    }

    return path_metrics;
}
