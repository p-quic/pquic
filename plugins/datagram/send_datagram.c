#include <picoquic_internal.h>
#include "picoquic.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

protoop_arg_t send_datagram_frame(picoquic_cnx_t* cnx)
{
    char *payload = (char *) get_cnx(cnx, CNX_AK_INPUT, 0);
    int len = (int) get_cnx(cnx, CNX_AK_INPUT, 1);
    uint64_t datagram_id = 0;
    datagram_memory_t *m = get_datagram_memory(cnx);

    uint32_t max_path_mtu = get_max_datagram_size(cnx);
    if (len > max_path_mtu) {
        PROTOOP_PRINTF(cnx, "Unable to send %d-byte long message, max known payload transmission unit is %d bytes\n", len, max_path_mtu);
        return 1;
    }

    void *chunk = my_malloc_on_sending_buffer(m, cnx, sizeof(reserve_frame_slot_t) + sizeof(datagram_frame_t) + (size_t) len);
    if (chunk == NULL) {
        PROTOOP_PRINTF(cnx, "Unable to allocate frame slot!\n");
        return 1;
    }
    reserve_frame_slot_t *slot = chunk;

#ifdef DATAGRAM_WITH_ID
    datagram_id = ++get_datagram_memory(cnx)->next_datagram_id;
    slot->frame_type = FT_DATAGRAM | FT_DATAGRAM_ID | FT_DATAGRAM_LEN;
    slot->nb_bytes = 1 + varint_len(datagram_id) + varint_len(len) + len;  // Unfortunately we are always forced to account for the length field
#else
    slot->frame_type = FT_DATAGRAM | FT_DATAGRAM_LEN;
    slot->nb_bytes = 1 + varint_len(len) + len;  // Unfortunately we are always forced to account for the length field
#endif

    datagram_frame_t* frame = chunk + sizeof(reserve_frame_slot_t);
    frame->datagram_data_ptr = (uint8_t *) (frame + sizeof(datagram_frame_t));

    frame->length = (uint64_t) len;
    if (frame->length > SEND_BUFFER) {
        PROTOOP_PRINTF(cnx, "%d-byte long frame cannot fit into %d-byte long send buffer", frame->length, SEND_BUFFER);
        my_free(cnx, frame->datagram_data_ptr);
        my_free(cnx, frame);
        my_free(cnx, slot);
        return 1;
    }

    int limit = (int) m->send_buffer;
    for (int i = 0; i < limit; i++) {
        if (m->send_buffer + frame->length > SEND_BUFFER) {
            free_head_datagram_reserved(m, cnx);
        } else {
            break;
        }
    }

    frame->datagram_id = datagram_id;
    my_memcpy(frame->datagram_data_ptr, payload, (size_t) len);
    slot->frame_ctx = frame;

    size_t reserved_size = reserve_frames(cnx, 1, slot);  // Apparently not provable
    if (reserved_size < slot->nb_bytes) {
        //PROTOOP_PRINTF(cnx, "Unable to reserve frame slot\n");
        my_free(cnx, frame->datagram_data_ptr);
        my_free(cnx, frame);
        my_free(cnx, slot);
        return 1;
    }
    m->send_buffer += frame->length;
    PROTOOP_PRINTF(cnx, "Send buffer size %d\n", m->send_buffer);
    picoquic_reinsert_cnx_by_wake_time(cnx, picoquic_current_time());
    return 0;
}