#include "bpf.h"

/**
 * Input: None
 *
 * Output: None
 */
protoop_arg_t state_changed(picoquic_cnx_t *cnx)
{
    qlog_t *qlog = get_qlog_t(cnx);
    picoquic_state_enum state = get_cnx(cnx, AK_CNX_STATE, 0);
    if (qlog->fd > 0) {
        picoquic_path_t *path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);
        if (path) {
            picoquic_connection_id_t *cid = (picoquic_connection_id_t *) get_path(path, AK_PATH_REMOTE_CID, 0);
            if (cid) {
                uint8_t cid_len = get_cnxid(cid, AK_CNXID_LEN);
                if (qlog->hdr.odcid.id_len == 0 && cid_len) {
                    qlog->hdr.odcid.id_len = cid_len;
                    my_memcpy(&qlog->hdr.odcid.id, (const void *) get_cnxid(cid, AK_CNXID_ID), qlog->hdr.odcid.id_len);
                }
                // TODO: Parameters set
            }
        }

        if (state == picoquic_state_disconnected) {
            write_trailer(cnx, qlog);
            close(qlog->fd);
        }
    }
    return 0;
}