#include "memory.h"
#include "memcpy.h"

#define FRAME_TYPE_DATAGRAM 0x1c
#define FRAME_TYPE_DATAGRAM_WITH_LEN 0x1d

#define DATAGRAM_OPAQUE_ID 0x00

#define APP_SOCKET 1
#define PLUGIN_SOCKET 0

typedef struct st_datagram_memory_t {
    int socket_fds[2];  // TODO: When to free this socket ?
} datagram_memory_t;

typedef struct st_datagram_frame_t {
    uint64_t length;
    uint8_t * datagram_data_ptr;  /* Start of the data, not contained in the structure */
} datagram_frame_t;

static inline size_t varint_len(uint64_t val) {
    if (val <= 64) {
        return 1;
    } else if (val <= 16383) {
        return 2;
    } else if (val <= 1073741823) {
        return 4;
    } else if (val <= 4611686018427387903) {
        return 8;
    }
    return 0;
}

static __attribute__((always_inline)) datagram_memory_t *initialize_datagram_memory(picoquic_cnx_t *cnx)  // TODO: We need to free it as well
{
    datagram_memory_t *metrics = (datagram_memory_t *) my_malloc(cnx, sizeof(datagram_memory_t));
    if (!metrics) return NULL;
    my_memset(metrics, 0, sizeof(datagram_memory_t));
    return metrics;
}

static __attribute__((always_inline)) datagram_memory_t *get_datagram_memory(picoquic_cnx_t *cnx)
{
    int allocated = 0;
    datagram_memory_t **bpfd_ptr = (datagram_memory_t **) get_opaque_data(cnx, DATAGRAM_OPAQUE_ID, sizeof(datagram_memory_t *), &allocated);
    if (!bpfd_ptr) return NULL;
    if (allocated) {
        *bpfd_ptr = initialize_datagram_memory(cnx);
        (*bpfd_ptr)->socket_fds[0] = -1;
        (*bpfd_ptr)->socket_fds[1] = -1;
    }
    return *bpfd_ptr;
}