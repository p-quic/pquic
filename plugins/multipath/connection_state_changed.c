#include "bpf.h"

protoop_arg_t connection_state_changed(picoquic_cnx_t* cnx)
{
    picoquic_state_enum from_state = (picoquic_state_enum) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_state_enum to_state = (picoquic_state_enum) get_cnx(cnx, AK_CNX_INPUT, 1);

    /* Check that nothing nasty is done */
    if (from_state != to_state && (to_state == picoquic_state_client_ready ||
                                   to_state == picoquic_state_server_ready))
    {
        /* Again, still checking */
        /* Try to send two CIDs for 2 paths IDS */
        bpf_data *bpfd = get_bpf_data(cnx);
        if (bpfd->nb_receiving_proposed == 0) {
            /* TODO do something smarter than this... */
            /* Prepare MP_NEW_CONNECTION_IDs */
            for (uint64_t i = 1; i < N_RECEIVING_UNIFLOWS + 1; i++) {
                reserve_mp_new_connection_id_frame(cnx, i);
            }
            /* And also send add address */
            reserve_add_address_frame(cnx);
        }
    }

    return 0;
}