#include "memory.h"
#include "memcpy.h"
#include "getset.h"

#define FT_DATAGRAM 0x20
#define FT_DATAGRAM_LEN 0x01
#define FT_DATAGRAM_ID 0x02
#define IS_DATAGRAM(t) ((t & 0xFE) == FT_DATAGRAM)
#define HAS_LEN(t) ((t & FT_DATAGRAM_LEN) == FT_DATAGRAM_LEN)
#define HAS_ID(t) ((t & FT_DATAGRAM_ID) == FT_DATAGRAM_ID)

#define DATAGRAM_OPAQUE_ID 0x00

#define APP_SOCKET 1
#define PLUGIN_SOCKET 0

typedef struct st_datagram_memory_t {
    uint64_t next_datagram_id;
    int socket_fds[2];  // TODO: When to free this socket ?
} datagram_memory_t;

typedef struct st_datagram_frame_t {
    uint64_t datagram_id;
    uint64_t length;
    uint8_t * datagram_data_ptr;  /* Start of the data, not contained in the structure */
} datagram_frame_t;

static inline size_t varint_len(uint64_t val) {
    if (val <= 63) {
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

static __attribute__((always_inline)) uint32_t get_max_datagram_size(picoquic_cnx_t *cnx) {
    uint32_t max_message_size = 0;
    int nb_paths = (int) get_cnx(cnx, CNX_AK_NB_PATHS, 0);
    for (int i = 0; i < nb_paths; i++) {
        picoquic_path_t *path = (picoquic_path_t*) get_cnx(cnx, CNX_AK_PATH, i);
        uint32_t payload_mtu = (uint32_t) get_path(path, PATH_AK_SEND_MTU, 0) - 1 - (uint8_t) get_cnxid((picoquic_connection_id_t *)get_path(path, PATH_AK_REMOTE_CID, 0), CNXID_AK_LEN) - 4;  // Let's be conservative on the PN space used
        if (payload_mtu > max_message_size) {
            max_message_size = payload_mtu;
        }
    }
    return max_message_size - 1 - 2;
}