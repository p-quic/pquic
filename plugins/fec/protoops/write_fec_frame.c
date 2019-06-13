

#include <picoquic.h>
#include "../fec_protoops.h"

protoop_arg_t write_fec_frame(picoquic_cnx_t *cnx) {
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    fec_frame_t *ff = (fec_frame_t *) get_cnx(cnx, AK_CNX_INPUT, 2);
    PROTOOP_PRINTF(cnx, "WRITE FEC FRAME FOR BLOCK %u\n", ff->header.repair_fec_payload_id.fec_block_number);
    if (bytes + sizeof(fec_frame_header_t) + 1 > bytes_max) {
        PROTOOP_PRINTF(cnx, "RETURN -1 FEC FRAME: %p > %p\n", (protoop_arg_t) bytes + sizeof(fec_frame_header_t),
                       (protoop_arg_t) bytes_max);
        return -1;
    }
    bpf_state *state = get_bpf_state(cnx);
    if (state->current_packet_contains_fpid_frame) {
        // TODO: re-reserve the frame
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) 0);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
        my_free(cnx, ff->data);
        PROTOOP_PRINTF(cnx, "DONT WRITE FEC FRAME: ALREADY CONTAINS SFPID FRAME\n");
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
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) (1 + sizeof(fec_frame_header_t) + ff->header.data_length));
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
    my_free(cnx, ff);
    PROTOOP_PRINTF(cnx, "WRITTEN FRAME OF LEN %u, TOTAL %u BYTES\n", ff->header.data_length, (1 + sizeof(fec_frame_header_t) + ff->header.data_length));
    return 0;
}