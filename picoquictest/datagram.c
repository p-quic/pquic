#include "picoquic_internal.h"
#include "plugin.h"
#include "memory.h"
#include "util.h"

#include "../plugins/datagram/bpf.h"

uint8_t* copy_to_cnx(picoquic_cnx_t *cnx, const void *src, size_t src_len) {
    uint8_t *ptr = (uint8_t *) malloc((unsigned int) src_len);
    if (ptr == NULL) {
        return ptr;
    }
    memcpy(ptr, src, src_len);
    return ptr;
}

static int datagram_parse_test()
{
    int ret = 0;

    picoquic_cnx_t cnx = { 0 };
    protoop_arg_t out[3] = {0, 0, 0};
    register_protocol_operations(&cnx);
    ret = plugin_insert_plugin(&cnx, "plugins/datagram/datagram.plugin");
    if (ret) {
        DBG_PRINTF("Unable to load datagram plugin\n");
        return ret;
    }

    uint8_t *bytes = copy_to_cnx(&cnx, (char[]){0x1c, 0xa, 0xb, 0xc, 0xd}, 5);
    if (bytes == NULL) {
        DBG_PRINTF("Unable to allocate memory in cnx\n");
        return -1;
    }
    uint8_t *pret = (uint8_t *) protoop_prepare_and_run_param(&cnx, &PROTOOP_PARAM_PARSE_FRAME, FRAME_TYPE_DATAGRAM, out, bytes, bytes + 5);
    if (pret != bytes + 5) {
        DBG_PRINTF("Unable to parse simple frame with no explicit length\n");
        free(bytes);
        return -1;
    }
    my_free_in_core(cnx.previous_plugin, (void *) out[0]);
    free(bytes);

    bytes = copy_to_cnx(&cnx, (char[]){0x1d, 0x40, 0x4, 0xa, 0xb, 0xc, 0xd}, 7);
    if (bytes == NULL) {
        DBG_PRINTF("Unable to allocate memory in cnx\n");
        return -1;
    }
    pret = (uint8_t *) protoop_prepare_and_run_param(&cnx, &PROTOOP_PARAM_PARSE_FRAME, FRAME_TYPE_DATAGRAM_WITH_LEN, out, bytes, bytes + 40); // Simulates that there are bytes after the frame
    if (pret != bytes + 1 + 2 + 4) {
        DBG_PRINTF("Unable to parse simple frame with explicit length\n");
        free(bytes);
        return -1;
    }
    my_free_in_core(cnx.previous_plugin, (void *) out[0]);
    free(bytes);

    bytes = copy_to_cnx(&cnx, (char[]){0x1d, 0x40, 0x12, 0xa, 0xb, 0xc, 0xd}, 7);
    if (bytes == NULL) {
        DBG_PRINTF("Unable to allocate memory in cnx\n");
        return -1;
    }
    pret = (uint8_t *) protoop_prepare_and_run_param(&cnx, &PROTOOP_PARAM_PARSE_FRAME, FRAME_TYPE_DATAGRAM_WITH_LEN, out, bytes, bytes + 7);
    if (pret != NULL) {
        DBG_PRINTF("A truncated frame was successfully parsed\n");
        my_free_in_core(cnx.previous_plugin, (void *) out[0]);
        free(bytes);
        return -1;
    }
    free(bytes);

    return ret;
}

static int datagram_write_test() {
    int ret = 0;

    picoquic_cnx_t cnx = { 0 };
    protoop_arg_t out[1] = {0};
    register_protocol_operations(&cnx);
    ret = plugin_insert_plugin(&cnx, "plugins/datagram/datagram.plugin");
    if (ret) {
        DBG_PRINTF("Unable to load datagram plugin\n");
        return ret;
    }

    uint8_t *bytes = copy_to_cnx(&cnx, (char[]){0xa, 0xb, 0xc, 0xd}, 4);
    if (bytes == NULL) {
        DBG_PRINTF("Unable to allocate memory in cnx\n");
        return -1;
    }

    /* Should be the only plugin */
    protoop_plugin_t *p = cnx.plugins;

    /* Cheating... */
    cnx.current_plugin = p;

    struct iovec *message = (struct iovec*) my_malloc(&cnx, sizeof(struct iovec));
    if (message == NULL) {
        DBG_PRINTF("Unable to allocate memory in cnx\n");
        return -1;
    }
    message->iov_base = bytes;
    message->iov_len = 4;

    reserve_frame_slot_t *slot = (reserve_frame_slot_t *) my_malloc(&cnx, sizeof(reserve_frame_slot_t));
    if (slot == NULL) {
        DBG_PRINTF("Unable to allocate memory in cnx\n");
        return -1;
    }

    slot->frame_type = FRAME_TYPE_DATAGRAM_WITH_LEN;
    slot->nb_bytes = 1 + varint_len(message->iov_len) + message->iov_len;
    slot->frame_ctx = message;

    uint8_t *buffer = my_malloc(&cnx, (unsigned int) slot->nb_bytes);
    if (buffer == NULL) {
        DBG_PRINTF("Unable to allocate memory in cnx\n");
        return -1;
    }
    /* Stop cheating */
    cnx.current_plugin = NULL;
    protoop_arg_t pret = protoop_prepare_and_run_param(&cnx, &PROTOOP_PARAM_WRITE_FRAME, FRAME_TYPE_DATAGRAM_WITH_LEN, out, buffer, buffer + slot->nb_bytes, message, 0);
    if (pret) {
        DBG_PRINTF("Protoop write frame failed with error code %d\n", ret);
        return -1;
    }
    if (out[0] != slot->nb_bytes) {
        DBG_PRINTF("write_frame consumed %d bytes, expected %d\n", out[0], slot->nb_bytes);
        return -1;
    }
    //debug_dump(buffer, slot->nb_bytes);

    memset(buffer, 0, slot->nb_bytes);
    slot->frame_type = FRAME_TYPE_DATAGRAM;
    slot->nb_bytes = 1 + 4;
    bytes = copy_to_cnx(&cnx, (char[]){0xa, 0xb, 0xc, 0xd}, 4);
    if (bytes == NULL) {
        DBG_PRINTF("Unable to allocate memory in cnx\n");
        return -1;
    }

    /* Cheating... */
    cnx.current_plugin = p;
    message = (struct iovec*) my_malloc(&cnx, sizeof(struct iovec));
    if (message == NULL) {
        DBG_PRINTF("Unable to allocate memory in cnx\n");
        return -1;
    }
    message->iov_base = bytes;
    message->iov_len = 4;

    /* Stop cheating */
    cnx.current_plugin = NULL;

    pret = protoop_prepare_and_run_param(&cnx, &PROTOOP_PARAM_WRITE_FRAME, FRAME_TYPE_DATAGRAM, out, buffer, buffer + slot->nb_bytes, message, 0);
    if (pret) {
        DBG_PRINTF("Protoop write frame failed with error code %d\n", ret);
        return -1;
    }
    if (out[0] != slot->nb_bytes) {
        DBG_PRINTF("write_frame consumed %d bytes, expected %d\n", out[0], slot->nb_bytes);
        return -1;
    }
    //debug_dump(buffer, 6);

    return ret;
}

int datagram_test() {
    int ret = datagram_parse_test();
    if (ret) {
        DBG_PRINTF("datagram_parse test failed\n");
        return ret;
    }
    ret = datagram_write_test();
    if (ret) {
        DBG_PRINTF("datagram_write test failed\n");
        return ret;
    }
    return 0;
}