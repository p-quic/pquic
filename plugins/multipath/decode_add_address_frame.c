#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"


/**
 * cnx->protoop_inputv[0] = uint8_t* bytes
 * cnx->protoop_inputv[1] = const uint8_t* bytes_max
 *
 * Output: uint8_t* bytes
 */
protoop_arg_t decode_add_address_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];

    size_t byte_index = 1;
    uint8_t flags_and_ip_ver;
    uint8_t ip_ver;
    uint8_t addr_id;
    uint16_t port;
    bpf_data *bpfd = get_bpf_data(cnx);
    int addr_index = 0;

    if (bytes_max - bytes > byte_index) {
        flags_and_ip_ver = bytes[byte_index++];
    }

    if (bytes_max - bytes > byte_index) {
        addr_id = bytes[byte_index++];
    }

    for (addr_index = 0; addr_index < bpfd->nb_rem_addrs; addr_index++) {
        if (bpfd->rem_addrs[addr_index].id == addr_id) {
            // Or should we raise an error?
            break;
        }
    }

    ip_ver = flags_and_ip_ver & 0x0f;

    if (ip_ver == 4) {
        struct sockaddr_in *sai = my_malloc(cnx, sizeof(struct sockaddr_in));
        if (!sai) {
            // Raise error...
        }
        if (bytes_max - bytes > byte_index) {
            my_memcpy(&sai->sin_addr.s_addr, &bytes[byte_index], 4);
            byte_index += 4;
        }
        if (flags_and_ip_ver & 0x10 && bytes_max - bytes > byte_index) {
            my_memcpy(&sai->sin_port, &bytes[byte_index], 2);
            byte_index += 2;
        }
        bpfd->rem_addrs[addr_index].sa = (struct sockaddr *) sai;
        bpfd->rem_addrs[addr_index].id = addr_id;
        bpfd->rem_addrs[addr_index].is_v6 = false;
        bpfd->nb_rem_addrs++;
    } else if (ip_ver == 6) {
        struct sockaddr_in6 *sai6 = my_malloc(cnx, sizeof(struct sockaddr_in6));
        if (!sai6) {
            // Raise error...
        }
        if (bytes_max - bytes > byte_index) {
            my_memcpy(&sai6->sin6_addr, &bytes[byte_index], 16);
            byte_index += 16;
        }
        if (flags_and_ip_ver & 0x10 && bytes_max - bytes > byte_index) {
            my_memcpy(&sai6->sin6_port, &bytes[byte_index], 2);
            byte_index += 2;
        }
        bpfd->rem_addrs[addr_index].sa = (struct sockaddr *) sai6;
        bpfd->rem_addrs[addr_index].id = addr_id;
        bpfd->rem_addrs[addr_index].is_v6 = true;
        bpfd->nb_rem_addrs++;
    } else {
        // Error: unknown ip version
    }


    return (protoop_arg_t) bytes + byte_index;
}