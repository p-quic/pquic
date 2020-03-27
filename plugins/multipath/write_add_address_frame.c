#include "bpf.h"

/**
 * See PROTOOP_PARAM_WRITE_FRAME
 */
protoop_arg_t write_add_address_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t *bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    add_address_ctx_t *aac = (add_address_ctx_t *) get_cnx(cnx, AK_CNX_INPUT, 2);
    
    size_t consumed = 0;
    picoquic_path_t *path_0 = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);
    uint16_t port;
    int local_addr_len_0 = (int) get_path(path_0, AK_PATH_LOCAL_ADDR_LEN, 0);

    if (local_addr_len_0 == sizeof(struct sockaddr_in)) {
        struct sockaddr_in *si = (struct sockaddr_in *) get_path(path_0, AK_PATH_LOCAL_ADDR, 0);
        my_memcpy(&port, &si->sin_port, 2);
    } else {
        /* v6 */
        struct sockaddr_in6 *si6 = (struct sockaddr_in6 *) get_path(path_0, AK_PATH_LOCAL_ADDR, 0);
        my_memcpy(&port, &si6->sin6_port, 2);
    }

    int ret = 0;
    int frame_size_v4 = 9;
    bpf_data *bpfd = get_bpf_data(cnx);

    if (bytes_max - bytes < aac->nb_addrs * frame_size_v4) {
        /* A valid frame, with our encoding, uses at least 13 bytes.
         * If there is not enough space, don't attempt to encode it.
         */
        consumed = 0;
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    }
    else {
        /* Create local address IDs. */
        size_t byte_index = 0;
        size_t l_frame_id = 0;
        int addr_index = 0;
        int addr_id = 0;
        struct sockaddr_storage *sa;

        for (int i = 0; i < aac->nb_addrs; i++) {
            /* First record the address */

            if (!aac->is_rtx) {
                addr_index = bpfd->nb_loc_addrs;
                addr_id = addr_index + 1;
                sa = (struct sockaddr_storage *) my_malloc_ex(cnx, sizeof(struct sockaddr_storage));
                if (!sa) {
                    ret = PICOQUIC_ERROR_MEMORY;
                    break;
                }
                my_memcpy(sa, &aac->sas[i], sizeof(struct sockaddr_storage));
                /* Take the port from the current path 0 */
                if (sa->ss_family == AF_INET) {
                    my_memcpy(&((struct sockaddr_in *) sa)->sin_port, &port, 2);
                } else if (sa->ss_family == AF_INET6) {
                    my_memcpy(&((struct sockaddr_in6 *) sa)->sin6_port, &port, 2);
                }
                bpfd->loc_addrs[addr_index].id = addr_id;
                bpfd->loc_addrs[addr_index].sa = (struct sockaddr *) sa;
                bpfd->loc_addrs[addr_index].is_v6 = sa->ss_family == AF_INET6;
                bpfd->loc_addrs[addr_index].if_index = aac->if_indexes[i];
                bpfd->nb_loc_addrs++;
            } else {
                addr_index = i;
                addr_id = addr_index + 1;
                sa = (struct sockaddr_storage *) bpfd->loc_addrs[addr_index].sa;
            }

            /* Encode the frame ID */
            l_frame_id = picoquic_varint_encode(bytes + byte_index, (size_t) (bytes_max - bytes) - byte_index,
                ADD_ADDRESS_TYPE);
            byte_index += l_frame_id;
            my_memset(&bytes[byte_index++], (port ? 0x10 : 0x00) | ((sa->ss_family == AF_INET6) ? 0x06 : 0x04), 1);
            /* Encode address ID */
            my_memset(&bytes[byte_index++], addr_id, 1);
            /* Encode IP address */
            if (sa->ss_family == AF_INET) {
                my_memcpy(&bytes[byte_index], &((struct sockaddr_in*)sa)->sin_addr.s_addr, sizeof(in_addr_t));
                byte_index += sizeof(in_addr_t);
            } else if (sa->ss_family == AF_INET6) {
                my_memcpy(&bytes[byte_index], &((struct sockaddr_in6*)sa)->sin6_addr, sizeof(struct in6_addr));
                byte_index += sizeof(struct in6_addr);
            }

            if (port != 0) {
                /* Encode port */
                my_memcpy(&bytes[byte_index], &port, 2);
                byte_index += 2;
            }
        }

        consumed = byte_index;
    }

    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) consumed);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 1);

    return (protoop_arg_t) ret;
}