#include "picoquic_internal.h"
#include "memory.h"
#include "memcpy.h"
#include "../helpers.h"
#include "bpf.h"

protoop_arg_t connection_state_changed(picoquic_cnx_t* cnx)
{
    picoquic_state_enum from_state = (picoquic_state_enum) cnx->protoop_inputv[0];
    picoquic_state_enum to_state = (picoquic_state_enum) cnx->protoop_inputv[1];

    helper_protoop_printf(cnx, "Please call me!\n", NULL, 0);

    /* Check that nothing nasty is done */
    if (from_state != to_state && (to_state == picoquic_state_client_ready ||
                                   to_state == picoquic_state_server_ready))
    {
        /* Again, still checking */
        /* Try to send two CIDs for 2 paths IDS */
        bpf_data *bpfd = get_bpf_data(cnx);
        helper_protoop_printf(cnx, "Try to book?\n", NULL, 0);
        if (bpfd->nb_proposed_snt == 0) {
            /* Prepare first MP_NEW_CONNECTION_ID */
            reserve_mp_new_connection_id_frame(cnx, 2);
            /* Prepare second MP_NEW_CONNECTION_ID */
            reserve_mp_new_connection_id_frame(cnx, 4);
            /* And also send add address by the way */
            reserve_add_address_frame(cnx);
            helper_protoop_printf(cnx, "Should be booked\n", NULL, 0);
        }
    }

    return 0;
}