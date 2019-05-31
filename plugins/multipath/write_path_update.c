#include "bpf.h"

protoop_arg_t write_path_update(picoquic_cnx_t *cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    path_update_t *update = (path_update_t *) get_cnx(cnx, AK_CNX_INPUT, 2);
    int ret = 0;
    size_t consumed = 0;

    if ((bytes_max - bytes) < 1 + varint_len(update->closed_path_id) + varint_len(update->proposed_path_id)) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        goto exit;
    }

    my_memset(bytes, PATH_UPDATE_TYPE, 1);
    consumed++;
    consumed += picoquic_varint_encode(bytes + consumed, bytes_max - (bytes + consumed), update->closed_path_id);
    consumed += picoquic_varint_encode(bytes + consumed, bytes_max - (bytes + consumed), update->proposed_path_id);

exit:
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) consumed);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 1);
    return (protoop_arg_t) ret;
}