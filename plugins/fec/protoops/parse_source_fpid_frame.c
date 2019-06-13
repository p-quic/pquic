#include "picoquic.h"
#include "../fec_protoops.h"

/**
 * cnx->protoop_inputv[0] = uint8_t* bytes
 * cnx->protoop_inputv[1] = const uint8_t* bytes_max
 * cnx->protoop_inputv[2] = uint64_t current_time
 *
 * Output: uint8_t* bytes
 */
protoop_arg_t parse_source_fpid_frame(picoquic_cnx_t *cnx)
{
    PROTOOP_PRINTF(cnx, "Parse FPID FRAME\n");
    uint8_t* bytes_protected = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);


    if (get_bpf_state(cnx)->is_in_skip_frame) {
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) NULL);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, false);
        set_cnx(cnx, AK_CNX_OUTPUT, 2, false);
        return (protoop_arg_t) bytes_protected + 1 + sizeof(source_fpid_frame_t);
    }

    uint8_t *bytes = my_malloc(cnx, (unsigned int) (1 + sizeof(source_fpid_frame_t)));
    if (!bytes){
        return PICOQUIC_ERROR_MEMORY;
    }
    my_memcpy(bytes, bytes_protected, (1 + sizeof(source_fpid_frame_t)));
    if (bytes_max-bytes < sizeof(source_fpid_frame_t) + 1){
        my_free(cnx, bytes);
        return 0;
    }

    source_fpid_frame_t *frame = my_malloc(cnx, sizeof(source_fpid_frame_t));
    if (!frame)
        return PICOQUIC_ERROR_MEMORY;
    parse_sfpid_frame(frame, bytes + 1);
    my_free(cnx, bytes);
    PROTOOP_PRINTF(cnx, "Parse FEC-proteceted packet with FPID = %u (block = %u)\n", frame->source_fpid.raw, frame->source_fpid.fec_block_number);
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, false);
    set_cnx(cnx, AK_CNX_OUTPUT, 2, false);
    return (protoop_arg_t) bytes_protected + 1 + sizeof(source_fpid_frame_t);
}