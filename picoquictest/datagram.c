#include "picoquic_internal.h"
#include "plugin.h"
#include "memory.h"
#include "util.h"

#include "../plugins/datagram/bpf.h"

uint8_t* copy_to_cnx(picoquic_cnx_t *cnx, const void *src, size_t src_len) {
    uint8_t *ptr = (uint8_t *) my_malloc(cnx, (unsigned int) src_len);
    if (ptr == NULL) {
        return ptr;
    }
    memcpy(ptr, src, src_len);
    return ptr;
}

int datagram_test()
{
    int ret = 0;

    picoquic_cnx_t cnx = { 0 };
    protoop_arg_t out[3] = {0, 0, 0};
    init_memory_management(&cnx);
    register_protocol_operations(&cnx);
    ret = plugin_insert_transaction(&cnx, "plugins/datagram/datagram.plugin");
    if (ret) {
        DBG_PRINTF("Unable to load datagram plugin\n");
        return ret;
    }

    uint8_t *bytes = copy_to_cnx(&cnx, (char[]){0x1c, 0xa, 0xb, 0xc, 0xd}, 5);
    if (bytes == NULL) {
        DBG_PRINTF("Unable to allocate memory in cnx\n");
        return -1;
    }
    uint8_t *pret = (uint8_t *) protoop_prepare_and_run_param(&cnx, PROTOOP_PARAM_PARSE_FRAME, FRAME_TYPE_DATAGRAM, out, bytes, bytes + 5);
    if (pret != bytes + 5) {
        DBG_PRINTF("Unable to parse simple frame with no explicit length\n");
        my_free(&cnx, bytes);
        return -1;
    }
    my_free(&cnx, (void *) out[0]);
    my_free(&cnx, bytes);

    bytes = copy_to_cnx(&cnx, (char[]){0x1d, 0x40, 0x4, 0xa, 0xb, 0xc, 0xd}, 7);
    if (bytes == NULL) {
        DBG_PRINTF("Unable to allocate memory in cnx\n");
        return -1;
    }
    pret = (uint8_t *) protoop_prepare_and_run_param(&cnx, PROTOOP_PARAM_PARSE_FRAME, FRAME_TYPE_DATAGRAM_WITH_LEN, out, bytes, bytes + 40); // Simulates that there are bytes after the frame
    if (pret != bytes + 1 + 2 + 4) {
        DBG_PRINTF("Unable to parse simple frame with explicit length\n");
        my_free(&cnx, bytes);
        return -1;
    }
    my_free(&cnx, (void *) out[0]);
    my_free(&cnx, bytes);

    bytes = copy_to_cnx(&cnx, (char[]){0x1d, 0x40, 0x12, 0xa, 0xb, 0xc, 0xd}, 7);
    if (bytes == NULL) {
        DBG_PRINTF("Unable to allocate memory in cnx\n");
        return -1;
    }
    pret = (uint8_t *) protoop_prepare_and_run_param(&cnx, PROTOOP_PARAM_PARSE_FRAME, FRAME_TYPE_DATAGRAM_WITH_LEN, out, bytes, bytes + 7);
    if (pret != NULL) {
        DBG_PRINTF("A truncated frame was successfully parsed\n");
        my_free(&cnx, (void *) out[0]);
        my_free(&cnx, bytes);
        return -1;
    }
    my_free(&cnx, bytes);

    return ret;
}
