#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"


/**
 * The interface for the decode_frame protocol operation is the same for all:
 * uint8_t* bytes = cnx->protoop_inputv[0]
 * const uint8_t* bytes_max = cnx->protoop_inputv[1]
 * uint64_t current_time = cnx->protoop_inputv[2]
 * int epoch = cnx->protoop_inputv[3]
 * int ack_needed = cnx->protoop_inputv[4]
 *
 * Output: uint8_t* bytes
 * cnx->protoop_outputv[0] = ack_needed
 */
protoop_arg_t decode_add_address_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];
    int ack_needed = (int) cnx->protoop_outputv[4];

    ack_needed = 1;

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

    /* Get the default port, if needed */
    struct sockaddr_storage *sa_def = &cnx->path[0]->peer_addr;
    int sa_def_length = cnx->path[0]->peer_addr_len;
    uint16_t port_def = 0;

    if (sa_def_length == sizeof(struct sockaddr_in)) {
        struct sockaddr_in *sai_def = (struct sockaddr_in *) sa_def;
        port_def = (uint16_t) sai_def->sin_port;
    } else { /* IPv6 */
        struct sockaddr_in6 *sai6_def = (struct sockaddr_in6 *) sa_def;
        port_def = (uint16_t) sai6_def->sin6_port;
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
        } else {
            /* It is the same port as the initial path */
            my_memcpy(&sai->sin_port, &port_def, 2);
        }
        /* Ensure sai is a AF_INET address */
        sai->sin_family = AF_INET;
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
        } else {
            /* It is the same port as the initial path */
            my_memcpy(&sai6->sin6_port, &port_def, 2);
        }
        /* Ensure sai6 is a AF_INET6 address */
        sai6->sin6_family = AF_INET6;
        bpfd->rem_addrs[addr_index].sa = (struct sockaddr *) sai6;
        bpfd->rem_addrs[addr_index].id = addr_id;
        bpfd->rem_addrs[addr_index].is_v6 = true;
        bpfd->nb_rem_addrs++;
    } else {
        // Error: unknown ip version
    }

    cnx->protoop_outputc_callee = 1;
    cnx->protoop_outputv[0] = ack_needed;
    return (protoop_arg_t) bytes + byte_index;
}