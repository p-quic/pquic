#include "picoquic.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"

protoop_arg_t select_sending_path(picoquic_cnx_t *cnx)
{
    picoquic_path_t *path_x = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, 0);
    picoquic_path_t *path_0 = path_x;
    bpf_data *bpfd = get_bpf_data(cnx);
    path_data_t *pd = NULL;
    uint8_t selected_path_index = 255;
    start_using_path_if_possible(cnx);
    for (int i = 0; i < bpfd->nb_proposed; i++) {
        pd = &bpfd->paths[i];

        /* A (very) simple round-robin */
        if (pd->state == 2) {
            if (path_x == path_0) {
                path_x = pd->path;
                selected_path_index = i;
            } else if (bpfd->last_path_index_sent != i) {
                path_x = pd->path;
                selected_path_index = i;
            }
        }
    }
    bpfd->last_path_index_sent = selected_path_index;

    return (protoop_arg_t) path_x;
}