

#include <picoquic.h>
#include "block_framework.h"

static __attribute__((always_inline)) int write_fec_frame(picoquic_cnx_t *cnx) {
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, CNX_AK_INPUT, 1);
    fec_frame_t *ff = (fec_frame_t *) get_cnx(cnx, CNX_AK_INPUT, 2);
    if (bytes + sizeof(fec_frame_header_t) > bytes_max)
        return -1;
    uint8_t *header_buffer = my_malloc(cnx, sizeof(fec_frame_header_t));
    if (!header_buffer)
        return PICOQUIC_ERROR_MEMORY;
    write_fec_frame_header(&ff->header, header_buffer);
    // copy the frame header
    my_memcpy(bytes, header_buffer, sizeof(fec_frame_header_t));
    my_free(cnx, header_buffer);
    // copy the frame payload
    my_memcpy(bytes + sizeof(fec_frame_header_t), ff->data, bytes_max - (bytes + sizeof(fec_frame_header_t)));
    my_free(cnx, ff->data);
    my_free(cnx, ff);
    set_cnx(cnx, CNX_AK_OUTPUT, 0, (protoop_arg_t) (sizeof(fec_frame_header_t) + ff->header.data_length));
    return 0;
}