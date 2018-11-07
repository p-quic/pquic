#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"

/**
 * See PROTOOP_PARAM_WRITE_FRAME
 */
protoop_arg_t write_add_address_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, CNX_AK_INPUT, 0);
    const uint8_t *bytes_max = (const uint8_t *) get_cnx(cnx, CNX_AK_INPUT, 1);
    add_address_ctx_t *aac = (add_address_ctx_t *) get_cnx(cnx, CNX_AK_INPUT, 2);
    
    size_t consumed = 0;
    picoquic_path_t *path_0 = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, 0);
    uint16_t port;
    int local_addr_len_0 = (int) get_path(path_0, PATH_AK_LOCAL_ADDR_LEN, 0);

    if (local_addr_len_0 == sizeof(struct sockaddr_in)) {
        struct sockaddr_in *si = (struct sockaddr_in *) get_path(path_0, PATH_AK_LOCAL_ADDR, 0);
        my_memcpy(&port, &si->sin_port, 2);
    } else {
        /* v6 */
        struct sockaddr_in6 *si6 = (struct sockaddr_in6 *) get_path(path_0, PATH_AK_LOCAL_ADDR, 0);
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
        int addr_index = 0;
        int addr_id = 0;
        struct sockaddr_in *sa;

        for (int i = 0; i < aac->nb_addrs; i++) {
            /* First record the address */
            addr_index = bpfd->nb_loc_addrs;
            addr_id = addr_index + 1;
            sa = (struct sockaddr_in *) my_malloc(cnx, sizeof(struct sockaddr_in));
            if (!sa) {
                ret = PICOQUIC_ERROR_MEMORY;
                break;
            }
            my_memcpy(sa, &aac->sas[i], sizeof(struct sockaddr_in));
            /* Take the port from the current path 0 */
            my_memcpy(&sa->sin_port, &port, 2);
            bpfd->loc_addrs[addr_index].id = addr_id;
            bpfd->loc_addrs[addr_index].sa = (struct sockaddr *) sa;
            bpfd->loc_addrs[addr_index].is_v6 = false;
            bpfd->loc_addrs[addr_index].if_index = aac->if_indexes[i];

            /* Encode the first byte */
            bytes[byte_index++] = ADD_ADDRESS_TYPE;
            if (port != 0) {
                /* Encode port flag with v4 */
                bytes[byte_index++] = 0x14;
            } else {
                /* Otherwisen only v4 value */
                bytes[byte_index++] = 0x04;
            }
            /* Encode address ID */
            bytes[byte_index++] = addr_id;
            /* Encode IP address */
            my_memcpy(&bytes[byte_index], &sa->sin_addr.s_addr, 4);
            byte_index += 4;
            if (port != 0) {
                /* Encode port */
                my_memcpy(&bytes[byte_index], &sa->sin_port, 2);
                byte_index += 2;
            }
            
            bpfd->nb_loc_addrs++;
        }

        consumed = byte_index;
    }

    my_free(cnx, aac);

    set_cnx(cnx, CNX_AK_OUTPUT, 0, (protoop_arg_t) consumed);

    return (protoop_arg_t) ret;
}