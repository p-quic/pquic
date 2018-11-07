#include "picoquic.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t decode_ecn_frame(picoquic_cnx_t *cnx)
{
    uint8_t *bytes = (uint8_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, CNX_AK_INPUT, 1);

    int ack_needed = 0;
    int is_retransmittable = 0;
    ecn_frame_t *frame = my_malloc(cnx, sizeof(ecn_frame_t));
    if (!frame) {
        helper_protoop_printf(cnx, "Failed to allocate memory for ack_frame_t\n", NULL, 0);
        set_cnx(cnx, CNX_AK_OUTPUT, 0, (protoop_arg_t) frame);
        set_cnx(cnx, CNX_AK_OUTPUT, 1, (protoop_arg_t) ack_needed);
        set_cnx(cnx, CNX_AK_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    if ((bytes = helper_frames_uint64_decode(bytes + 1, bytes_max, &frame->ect0)) == NULL ||
        (bytes = helper_frames_uint64_decode(bytes, bytes_max, &frame->ect1))     == NULL ||
        (bytes = helper_frames_uint64_decode(bytes, bytes_max, &frame->ectce))    == NULL)
    {
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, ECN_FRAME_TYPE);
        bytes = NULL;
        my_free(cnx, frame);
        frame = NULL;
    }
    
    bpf_data *bpfd = get_bpf_data(cnx);

    uint8_t first_byte;
    my_memcpy(&first_byte, &bytes[0], 1);
    uint64_t ect0, ect1, ectce;

    if (first_byte != ECN_FRAME_TYPE || bytes_max - bytes < 25) {
        bytes = NULL;
        helper_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
    }

    set_cnx(cnx, CNX_AK_OUTPUT, 0, (protoop_arg_t) frame);
    set_cnx(cnx, CNX_AK_OUTPUT, 1, (protoop_arg_t) ack_needed);
    set_cnx(cnx, CNX_AK_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
    return (protoop_arg_t) bytes;
}