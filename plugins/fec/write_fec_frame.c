

#include <picoquic_internal.h>
#include "bpf.h"

protoop_arg_t write_fec_frame(picoquic_cnx_t *cnx) {
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, CNX_AK_INPUT, 1);
    fec_frame_t *ff = (fec_frame_t *) get_cnx(cnx, CNX_AK_INPUT, 2);
    PROTOOP_PRINTF(cnx, "WRITE FEC FRAME\n");
    if (bytes + sizeof(fec_frame_header_t) > bytes_max) {
        PROTOOP_PRINTF(cnx, "RETURN -1 FEC FRAME: %p > %p\n", (protoop_arg_t) bytes + sizeof(fec_frame_header_t),
                       (protoop_arg_t) bytes_max);
        return -1;
    }
    bpf_state *state = get_bpf_state(cnx);
    if (state->current_packet_contains_fpid_frame) {
        // TODO: re-reserve the frame
        set_cnx(cnx, CNX_AK_OUTPUT, 0, (protoop_arg_t) 0);
        my_free(cnx, ff->data);
        return 0;

    }
    uint8_t *header_buffer = my_malloc(cnx, 1 + sizeof(fec_frame_header_t));
    if (!header_buffer)
        return PICOQUIC_ERROR_MEMORY;

    write_fec_frame_header(&ff->header, header_buffer);
    state->current_packet_contains_fec_frame = true;
    // copy the frame header
    my_memcpy(bytes, header_buffer, 1 + sizeof(fec_frame_header_t));
    my_free(cnx, header_buffer);
    // copy the frame payload
    my_memcpy(bytes + 1 + sizeof(fec_frame_header_t), ff->data, bytes_max - (bytes + 1 + sizeof(fec_frame_header_t)));
    my_free(cnx, ff->data);
    set_cnx(cnx, CNX_AK_OUTPUT, 0, (protoop_arg_t) (sizeof(fec_frame_header_t) + ff->header.data_length));
    return 0;
}