#include <picoquic.h>
#include "../fec_protoops.h"

protoop_arg_t write_fpid_frame(picoquic_cnx_t *cnx) {
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    source_fpid_frame_t *f = (source_fpid_frame_t *) get_cnx(cnx, AK_CNX_INPUT, 2);
    if (bytes + 1 + sizeof(source_fpid_frame_t) > bytes_max) {
        PROTOOP_PRINTF(cnx, "RETURN -1 FPID FRAME: BYTES = %p,  %p > %p\n", (protoop_arg_t) bytes, (protoop_arg_t) bytes + sizeof(fec_frame_header_t), (protoop_arg_t) bytes_max);
        return -1;
    }
    bpf_state *state = get_bpf_state(cnx);
    if (state->current_packet_contains_fec_frame || state->current_packet_contains_fpid_frame || state->cancel_sfpid_in_current_packet) {
        // no FPID frame in a packet containing a FEC Frame
        // FIXME: we loose a symbol number in the fec block...
        my_free(cnx, f);
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) 0);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
        state->sfpid_reserved = false;
        PROTOOP_PRINTF(cnx, "DONT WRITE SFPID FRAME: ALREADY CONTAINS FEC FRAME\n");
        return 0;//PICOQUIC_MISCCODE_RETRY_NXT_PKT;

    }
    uint8_t *fpid_buffer = my_malloc(cnx, 1 + sizeof(source_fpid_frame_t));
    if (!fpid_buffer)
        return PICOQUIC_ERROR_MEMORY;
    size_t consumed = 0;
    helper_write_source_fpid_frame(cnx, f, fpid_buffer, bytes_max - bytes, &consumed);
    if (state->current_sfpid_frame) {
        my_free(cnx, state->current_sfpid_frame);
    }
    state->current_sfpid_frame = f;
    state->current_packet_contains_fpid_frame = true;
    my_memcpy(bytes, fpid_buffer, consumed);
    state->sfpid_reserved = false;
    PROTOOP_PRINTF(cnx, "WRITE SFPID FRAME block %u, symbol number %u, consumed = %u\n", f->source_fpid.fec_block_number, f->source_fpid.symbol_number, consumed);
    my_free(cnx, fpid_buffer);
    state->written_sfpid_frame = bytes;
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) consumed);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
    return 0;
}