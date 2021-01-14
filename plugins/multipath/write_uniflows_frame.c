#include "bpf.h"

/**
 * See PROTOOP_PARAM_WRITE_FRAME
 */
protoop_arg_t write_uniflows_frame(picoquic_cnx_t *cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t *bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    bpf_data *bpfd = get_bpf_data(cnx);

    int ret = 0;
    int should_be_retransmitted = 1;
    size_t byte_index = 0;

    size_t uniflow_header_len = varint_len(bpfd->uniflows_sequence) + 1 + 1;
    size_t uniflow_info_min_len = 2;

    if (bytes_max - bytes < uniflow_header_len + (bpfd->nb_receiving_proposed * uniflow_info_min_len) + (bpfd->nb_sending_active * uniflow_info_min_len)) {
        byte_index = 0;
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else {
        size_t l_frame_id = picoquic_varint_encode(bytes + byte_index, (bytes_max - bytes) - byte_index, UNIFLOWS_TYPE);
        byte_index += l_frame_id;

        size_t l_sequence = picoquic_varint_encode(bytes + byte_index, (bytes_max - bytes) - byte_index, bpfd->uniflows_sequence);
        byte_index += l_sequence;

        size_t l_receiving = picoquic_varint_encode(bytes + byte_index, (bytes_max - bytes) - byte_index, bpfd->nb_receiving_proposed);
        byte_index += l_receiving;

        int nb_sending = 0;
        for (int i = 0; ret == 0 && i < bpfd->nb_sending_proposed; i++) {
            if (bpfd->sending_uniflows[i] && bpfd->sending_uniflows[i]->state == uniflow_active && get_path(bpfd->sending_uniflows[i]->path, AK_PATH_CHALLENGE_VERIFIED, 0)) {
                nb_sending++;
            }
        }

        size_t l_sending = picoquic_varint_encode(bytes + byte_index, (bytes_max - bytes) - byte_index, nb_sending);
        byte_index += l_sending;

        if (l_frame_id == 0 || l_sequence == 0 || l_receiving == 0 || l_sending == 0) {
            byte_index = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        }

        for (int i = 0; ret == 0 && i < bpfd->nb_receiving_proposed; i++) {
            if (bpfd->receiving_uniflows[i]) {
                size_t l_uniflow_id = picoquic_varint_encode(bytes + byte_index, (bytes_max - bytes) - byte_index,
                                                             bpfd->receiving_uniflows[i]->uniflow_id);
                byte_index += l_uniflow_id;

                if (l_uniflow_id == 0 || (bytes_max - bytes) <= byte_index) {
                    byte_index = 0;
                    ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                } else {
                    my_memcpy(bytes + byte_index, &bpfd->receiving_uniflows[i]->loc_addr_id, 1);
                    byte_index++;
                }
            }
        }

        for (int i = 0; ret == 0 && i < bpfd->nb_sending_proposed; i++) {
            if (bpfd->sending_uniflows[i] && bpfd->sending_uniflows[i]->state == uniflow_active && get_path(bpfd->sending_uniflows[i]->path, AK_PATH_CHALLENGE_VERIFIED, 0)) {
                size_t l_uniflow_id = picoquic_varint_encode(bytes + byte_index, (bytes_max - bytes) - byte_index,
                                                             bpfd->sending_uniflows[i]->uniflow_id);
                byte_index += l_uniflow_id;

                if (l_uniflow_id == 0 || (bytes_max - bytes) <= byte_index) {
                    byte_index = 0;
                    ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                } else {
                    my_memcpy(bytes + byte_index, &bpfd->sending_uniflows[i]->loc_addr_id, 1);
                    byte_index++;
                }
            }
        }
    }

    if (ret == 0 && byte_index > 0) {
        bpfd->uniflows_sequence++;
    }

    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) byte_index);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) should_be_retransmitted);
    return (protoop_arg_t) ret;
}