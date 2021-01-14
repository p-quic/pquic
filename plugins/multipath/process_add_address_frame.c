#include "bpf.h"


/**
 * See PROTOOP_PARAM_PROCESS_FRAME
 */
protoop_arg_t process_add_address_frame(picoquic_cnx_t *cnx)
{ 
    add_address_frame_t *frame = (add_address_frame_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    bpf_data *bpfd = get_bpf_data(cnx);

    int addr_index = 0;

    for (addr_index = 0; addr_index < bpfd->nb_rem_addrs; addr_index++) {
        if (bpfd->rem_addrs[addr_index].id == frame->address_id) {
            // Already processed. Or should we raise an error?
            return 0;
        }
    }

    if (addr_index >= sizeof(bpfd->rem_addrs) / sizeof(addr_data_t)) {
        /* No more place to store the address*/
        return 0;
    }

    /* Create a copy of the sockaddr for the rem_addrs array, as the frame will be freed */
    bpfd->rem_addrs[addr_index].id = frame->address_id;
    if (frame->ip_vers == 4) {
        bpfd->rem_addrs[addr_index].is_v6 = false;
        struct sockaddr_in *sai = (struct sockaddr_in *) my_malloc_ex(cnx, sizeof(struct sockaddr_in));
        if (!sai) {
            return 1;
        }
        my_memcpy(sai, &frame->addr, sizeof(struct sockaddr_in));
        bpfd->rem_addrs[addr_index].sa = (struct sockaddr *) sai;
    } else { /* v6 */
        bpfd->rem_addrs[addr_index].is_v6 = true;
        struct sockaddr_in6 *sai6 = (struct sockaddr_in6 *) my_malloc_ex(cnx, sizeof(struct sockaddr_in6));
        if (!sai6) {
            return 1;
        }
        my_memcpy(sai6, &frame->addr, sizeof(struct sockaddr_in6));
        bpfd->rem_addrs[addr_index].sa = (struct sockaddr *) sai6;
    }
    bpfd->nb_rem_addrs++;

    return 0;
}