#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

protoop_arg_t send_datagram_frame(picoquic_cnx_t* cnx)
{
    PROTOOP_PRINTF(cnx, "send_datagram_frame called \n");
    char *payload = (char *) cnx->protoop_inputv[0];
    size_t len = (size_t) cnx->protoop_inputv[1];

    reserve_frame_slot_t *slot = (reserve_frame_slot_t *) my_malloc(cnx, sizeof(reserve_frame_slot_t));
    if (slot == NULL) {
        PROTOOP_PRINTF(cnx, "Unable to allocate frame slot!\n");
        return 1;
    }
    slot->frame_type = 0x1c;
    slot->frame_ctx = my_malloc(cnx, len);
    if (slot->frame_ctx == NULL) {
        PROTOOP_PRINTF(cnx, "Unable to allocate frame slot!\n");
        return 1;
    }
    slot->nb_bytes = 1 + varint_len(len) + len;  // Unfortunately we are always forced to account for the length field

    struct iovec* message = my_malloc(cnx, sizeof(struct iovec));
    if (message == NULL) {
        PROTOOP_PRINTF(cnx, "Unable to allocate frame slot!\n");
        my_free(cnx, slot);
        return 1;
    }
    message->iov_base = my_malloc(cnx, len);
    message->iov_len = len;
    if (message->iov_base == NULL) {
        PROTOOP_PRINTF(cnx, "Unable to allocate frame slot!\n");
        my_free(cnx, slot);
        return 1;
    }
    my_memcpy(message->iov_base, payload, slot->nb_bytes);
    slot->frame_ctx = message;
    size_t reserved_size = reserve_frames(cnx, 1, slot);
    if (reserved_size <= 0) {
        PROTOOP_PRINTF(cnx, "Unable to reserve frame slot\n");
        return 1;
    }
    return 0;
}