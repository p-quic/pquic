#include "memory.h"
#include "memcpy.h"
#include "getset.h"
#include "../helpers.h"

#define FT_DATAGRAM 0x2c
#define FT_DATAGRAM_LEN 0x01
#define FT_DATAGRAM_ID 0x02
#define IS_DATAGRAM(t) ((t & 0xFE) == FT_DATAGRAM)
#define HAS_LEN(t) ((t & FT_DATAGRAM_LEN) == FT_DATAGRAM_LEN)
#define HAS_ID(t) ((t & FT_DATAGRAM_ID) == FT_DATAGRAM_ID)

#define DATAGRAM_OPAQUE_ID 0x00

#define APP_SOCKET 1
#define PLUGIN_SOCKET 0

#define SEND_BUFFER 900000
#define RECV_BUFFER 500000

#ifdef DATAGRAM_CONGESTION_CONTROLLED
#define DCC true
#else
#define DCC false
#endif

typedef struct st_datagram_frame_t {
    uint64_t datagram_id;
    uint64_t length;
    uint8_t * datagram_data_ptr;  /* Start of the data, not contained in the structure */
} datagram_frame_t;

typedef struct st_received_datagram_t {
    datagram_frame_t *datagram;
    uint64_t delivery_deadline;
    struct st_received_datagram_t *next;
} received_datagram_t;

typedef struct st_datagram_memory_t {
    int socket_fds[2];  // TODO: When to free this socket ?
    uint64_t next_datagram_id;
    uint64_t expected_datagram_id;
    received_datagram_t *datagram_buffer;
    uint32_t send_buffer;
    uint32_t recv_buffer;
} datagram_memory_t;

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
    datagram_memory_t *bpfd_ptr = (datagram_memory_t *) get_cnx_metadata(cnx, DATAGRAM_OPAQUE_ID);
    if (!bpfd_ptr) {
        bpfd_ptr = initialize_datagram_memory(cnx);
        (bpfd_ptr)->socket_fds[0] = -1;
        (bpfd_ptr)->socket_fds[1] = -1;
        (bpfd_ptr)->expected_datagram_id = 1;
        /* Save the pointer for future use */
        set_cnx_metadata(cnx, DATAGRAM_OPAQUE_ID, (protoop_arg_t) bpfd_ptr);
    }
    return bpfd_ptr;
}

static __attribute__((always_inline)) uint32_t get_max_datagram_size(picoquic_cnx_t *cnx) {
    uint32_t max_message_size = 0;
    int nb_paths = (int) get_cnx(cnx, AK_CNX_NB_PATHS, 0);
    for (uint16_t i = 0; i < nb_paths; i++) {
        picoquic_path_t *path = (picoquic_path_t*) get_cnx(cnx, AK_CNX_PATH, i);
        uint32_t payload_mtu = (uint32_t) get_path(path, AK_PATH_SEND_MTU, 0) - 1 - (uint8_t) get_cnxid((picoquic_connection_id_t *)get_path(path, AK_PATH_REMOTE_CID, 0), AK_CNXID_LEN) - 4;  // Let's be conservative on the PN space used
        if (payload_mtu > max_message_size) {
            max_message_size = payload_mtu;
        }
    }
    return max_message_size - 1 - 2;
}

static __attribute__((always_inline)) uint64_t get_max_rtt_difference(picoquic_cnx_t *cnx, picoquic_path_t *path_x) {
    uint64_t highest_rtt = 0;
    int nb_paths = (int) get_cnx(cnx, AK_CNX_NB_PATHS, 0);
    for (uint16_t i = (uint16_t) (nb_paths > 1); i < nb_paths; i++) {
        picoquic_path_t *path = (picoquic_path_t*) get_cnx(cnx, AK_CNX_PATH, i);
        uint64_t path_rtt = get_path(path, AK_PATH_SMOOTHED_RTT, 0);
        if (path_rtt > highest_rtt) {
            highest_rtt = path_rtt;
        }
    }
    return highest_rtt - get_path(path_x, AK_PATH_SMOOTHED_RTT, 0);
}

static __attribute__((always_inline)) protoop_arg_t send_datagram_to_application(datagram_memory_t *m, picoquic_cnx_t *cnx, datagram_frame_t *frame) {
    ssize_t ret = write(m->socket_fds[PLUGIN_SOCKET], frame->datagram_data_ptr, frame->length);
    PROTOOP_PRINTF(cnx, "Wrote %d bytes to the message socket\n", ret);
    //picoquic_reinsert_cnx_by_wake_time(cnx, picoquic_current_time());
    reserve_frame_slot_t *slot = my_malloc(cnx, sizeof(reserve_frame_slot_t));
    my_memset(slot, 0, sizeof(reserve_frame_slot_t));
    slot->frame_type = 0x60;
    slot->nb_bytes = 1;
    slot->frame_ctx = NULL;
    reserve_frames(cnx, 1, slot);
    if (frame->datagram_id != 0) {
        m->expected_datagram_id = frame->datagram_id + 1;
    }
    return (protoop_arg_t) (ret > 0 ? 0 : ret);
}

static __attribute__((always_inline)) void dump_buffer(datagram_memory_t *m, picoquic_cnx_t *cnx) {
    received_datagram_t *r = m->datagram_buffer;
    uint64_t now = picoquic_current_time();
    while (r != NULL) {
        PROTOOP_PRINTF(cnx, "{%d, d=%lu, n=%p} ", r->datagram->datagram_id, r->delivery_deadline < now ? 0 : r->delivery_deadline - now, (protoop_arg_t) r->next);
        r = r->next;
    }
    PROTOOP_PRINTF(cnx, "\n");
}

static __attribute__((always_inline)) void insert_into_datagram_buffer(datagram_memory_t *m, received_datagram_t *r) {
    if (m->datagram_buffer == NULL) {
        m->datagram_buffer = r;
        r->next = NULL;
    } else {
        received_datagram_t **prev = &m->datagram_buffer;
        received_datagram_t *node = m->datagram_buffer;
        while(node != NULL && node->datagram->datagram_id < r->datagram->datagram_id) {
            prev = &(*prev)->next;
            node = node->next;
        }
        *prev = r;
        r->next = node;
    }
    m->recv_buffer += r->datagram->length;
}

static __attribute__((always_inline)) void process_datagram_buffer(datagram_memory_t *m, picoquic_cnx_t *cnx) {
    received_datagram_t *r = m->datagram_buffer;
    uint64_t now = picoquic_current_time();

    while (r != NULL) {
        if (r->delivery_deadline < now || m->expected_datagram_id >= r->datagram->datagram_id) {
            send_datagram_to_application(m, cnx, r->datagram);
            if (r->datagram->length <= m->recv_buffer) {
                m->recv_buffer -= r->datagram->length;
            } else {
                m->recv_buffer = 0;
            }
            my_free(cnx, r->datagram->datagram_data_ptr);
            my_free(cnx, r->datagram);
            m->datagram_buffer = r->next;
            received_datagram_t *t = r;
            r = r->next;
            my_free(cnx, t);
        } else {
            break;
        }
    }
    if (m->datagram_buffer != NULL && get_cnx(cnx, AK_CNX_NEXT_WAKE_TIME, 0) > m->datagram_buffer->delivery_deadline) {
        picoquic_reinsert_cnx_by_wake_time(cnx, m->datagram_buffer->delivery_deadline);
    }
}

static __attribute__((always_inline)) void send_head_datagram_buffer(datagram_memory_t *m, picoquic_cnx_t *cnx) {
    if (m->datagram_buffer != NULL) {
        received_datagram_t *head = m->datagram_buffer;
        send_datagram_to_application(m, cnx, head->datagram);
        if (head->datagram->length <= m->recv_buffer) {
            m->recv_buffer -= head->datagram->length;
        } else {
            m->recv_buffer = 0;
        }
        my_free(cnx, head->datagram->datagram_data_ptr);
        my_free(cnx, head->datagram);
        m->datagram_buffer = head->next;
        my_free(cnx, head);
    }
}

static __attribute__((always_inline)) void free_head_datagram_reserved(datagram_memory_t *m, picoquic_cnx_t *cnx) {
    uint8_t nb_frames;
    reserve_frame_slot_t *slots = cancel_head_reservation(cnx, &nb_frames, (int) DCC);
    if (slots == NULL) {
        m->send_buffer = 0;
        return;
    }
    for (int i = 0; i < nb_frames; i++) {
        reserve_frame_slot_t *slot = (slots+i);
        datagram_frame_t *frame = slot->frame_ctx;
        my_free(cnx, frame->datagram_data_ptr);
        if (frame->length <= m->send_buffer) {
            m->send_buffer -= frame->length;
        } else {
            m->send_buffer = 0;
        }
        my_free(cnx, frame);
        my_free(cnx, slot);
    }
}

static __attribute__((always_inline)) void *my_malloc_on_sending_buffer(datagram_memory_t *m, picoquic_cnx_t *cnx, unsigned int size) {
    void *p = my_malloc(cnx, size);
    while (p == NULL && m->send_buffer > 0) {
        free_head_datagram_reserved(m, cnx);
        p = my_malloc(cnx, size);
    }
    return p;
}