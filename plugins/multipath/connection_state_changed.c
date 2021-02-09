#include "bpf.h"

protoop_arg_t connection_state_changed(picoquic_cnx_t* cnx)
{
    picoquic_state_enum from_state = (picoquic_state_enum) get_cnx(cnx, AK_CNX_INPUT, 0);
    picoquic_state_enum to_state = (picoquic_state_enum) get_cnx(cnx, AK_CNX_INPUT, 1);

    /* Check that nothing nasty is done */
    if (from_state != to_state && (to_state == picoquic_state_client_almost_ready ||
                                   to_state == picoquic_state_server_ready))
    {
        /* Again, still checking */
        bpf_data *bpfd = get_bpf_data(cnx);
        if (bpfd->nb_receiving_proposed == 0) {
            /* Initialize initial uniflows */
            picoquic_path_t *path_0 = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);
            uniflow_data_t *ru0 = bpfd->receiving_uniflows[mp_get_uniflow_index(cnx, bpfd, false, 0, NULL)];
            uniflow_data_t *su0 = bpfd->sending_uniflows[mp_get_uniflow_index(cnx, bpfd, true, 0, NULL)];

            ru0->state = uniflow_active;
            ru0->path = path_0;
            ru0->proposed_cid = true;
            picoquic_connection_id_t *local_cnxid = (picoquic_connection_id_t *) get_path(path_0, AK_PATH_LOCAL_CID, 0);
            my_memcpy(&ru0->cnxid, local_cnxid, sizeof(picoquic_connection_id_t));
            uint8_t *reset_secret = (uint8_t *) get_path(path_0, AK_PATH_RESET_SECRET, 0);
            my_memcpy(ru0->reset_secret, reset_secret, 16);

            su0->state = uniflow_active;
            su0->path = path_0;
            su0->proposed_cid = true;
            picoquic_connection_id_t *remote_cnxid = (picoquic_connection_id_t *) get_path(path_0, AK_PATH_REMOTE_CID, 0);
            my_memcpy(&su0->cnxid, remote_cnxid, sizeof(picoquic_connection_id_t));
            reset_secret = (uint8_t *) get_path(path_0, AK_PATH_RESET_SECRET, 0);
            my_memcpy(su0->reset_secret, reset_secret, 16);
            bpfd->nb_sending_active = 1;

            /* Initialize initial addresses */
            bpfd->nb_loc_addrs = 1;
            struct sockaddr_storage *sal = (struct sockaddr_storage *) my_malloc_ex(cnx, sizeof(struct sockaddr_storage));
            my_memcpy(sal, (const void *) get_path(path_0, AK_PATH_LOCAL_ADDR, 0), get_path(path_0, AK_PATH_LOCAL_ADDR_LEN, 0));
            bpfd->loc_addrs[0].id = 0;
            bpfd->loc_addrs[0].sa = (struct sockaddr *) sal;
            bpfd->loc_addrs[0].is_v6 = sal->ss_family == AF_INET6;
            bpfd->loc_addrs[0].is_v4_mapped_in_v6 = is_v4_mapped_in_v6((struct sockaddr *) sal);
            bpfd->loc_addrs[0].if_index = get_path(path_0, AK_PATH_IF_INDEX_LOCAL, 0);
            bpfd->nb_rem_addrs = 1;
            struct sockaddr_storage *sar = (struct sockaddr_storage *) my_malloc_ex(cnx, sizeof(struct sockaddr_storage));
            my_memcpy(sar, (const void *) get_path(path_0, AK_PATH_PEER_ADDR, 0), get_path(path_0, AK_PATH_PEER_ADDR_LEN, 0));
            bpfd->rem_addrs[0].id = 0;
            bpfd->rem_addrs[0].sa = (struct sockaddr *) sar;
            bpfd->rem_addrs[0].is_v6 = sar->ss_family == AF_INET6;
            bpfd->rem_addrs[0].is_v4_mapped_in_v6 = is_v4_mapped_in_v6((struct sockaddr *) sar);

            /* Prepare MP_NEW_CONNECTION_IDs */
            uint64_t max_sending_uniflow_id = N_RECEIVING_UNIFLOWS - 1;
            /* If we negotiate the option, let's bound to the peer provided value */
            if (bpfd->tp_sent) {
                if (bpfd->received_max_sending_uniflow < max_sending_uniflow_id) {
                    max_sending_uniflow_id = bpfd->received_max_sending_uniflow;
                }
            }

            for (uint64_t i = 1; i <= max_sending_uniflow_id; i++) {
                reserve_mp_new_connection_id_frame(cnx, i);
            }
            /* And also send add address */
            reserve_add_address_frame(cnx);
        }
    }

    return 0;
}