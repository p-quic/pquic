#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

protoop_arg_t send_datagram_frame(picoquic_cnx_t* cnx)
{
    char *payload = (char *) get_cnx(cnx, CNX_AK_INPUT, 0);
    size_t len = (size_t) get_cnx(cnx, CNX_AK_INPUT, 1);

    reserve_frame_slot_t *slot = (reserve_frame_slot_t *) my_malloc(cnx, sizeof(reserve_frame_slot_t));
    if (slot == NULL) {
        PROTOOP_PRINTF(cnx, "Unable to allocate frame slot!\n");
        return 1;
    }
    slot->frame_type = 0x1d;
    slot->nb_bytes = 1 + varint_len(len) + len;  // Unfortunately we are always forced to account for the length field

    struct iovec* message = my_malloc(cnx, sizeof(struct iovec));
    if (message == NULL) {
        PROTOOP_PRINTF(cnx, "Unable to allocate frame slot!\n");
        my_free(cnx, slot);
        return 1;
    }
    message->iov_base = my_malloc(cnx, (unsigned int) len);
    message->iov_len = len;
    if (message->iov_base == NULL) {
        PROTOOP_PRINTF(cnx, "Unable to allocate frame slot!\n");
        my_free(cnx, message);
        my_free(cnx, slot);
        return 1;
    }
    my_memcpy(message->iov_base, payload, len);
    slot->frame_ctx = message;
    size_t reserved_size = reserve_frames(cnx, 1, slot);
    if (reserved_size < slot->nb_bytes) {
        PROTOOP_PRINTF(cnx, "Unable to reserve frame slot\n");
        my_free(cnx, message->iov_base);
        my_free(cnx, message);
        my_free(cnx, slot);
        return 1;
    }
    return 0;
}