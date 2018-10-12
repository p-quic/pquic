#include "picoquic_internal.h"
#include "plugin.h"
#include "../helpers.h"
#include "bpf.h"
#include "memory.h"


/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_add_address_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
    const uint8_t* bytes_max = (const uint8_t *) cnx->protoop_inputv[1];

    int ack_needed = 1;
    int is_retransmittable = 1;
    add_address_frame_t *frame = (add_address_frame_t *) my_malloc(cnx, sizeof(add_address_frame_t));

    if (!frame) {
        helper_protoop_printf(cnx, "Failed to allocate memory for add_address_frame_t\n", NULL, 0);
        cnx->protoop_outputc_callee = 3;
        cnx->protoop_outputv[0] = (protoop_arg_t) frame;
        cnx->protoop_outputv[1] = (protoop_arg_t) ack_needed;
        cnx->protoop_outputv[2] = (protoop_arg_t) is_retransmittable;
        return (protoop_arg_t) NULL;
    }

    size_t byte_index = 1;
    uint8_t flags_and_ip_ver;

    if (bytes_max - bytes <= 3) {
        /* No enough space for the ADD_ADDRESS header, won't work */
        my_free(cnx, frame);
        frame = NULL;
        cnx->protoop_outputc_callee = 3;
        cnx->protoop_outputv[0] = (protoop_arg_t) frame;
        cnx->protoop_outputv[1] = (protoop_arg_t) ack_needed;
        cnx->protoop_outputv[2] = (protoop_arg_t) is_retransmittable;
        return (protoop_arg_t) NULL;
    }

    flags_and_ip_ver = bytes[byte_index++];
    frame->address_id = bytes[byte_index++];
    frame->has_port = (flags_and_ip_ver & 0x10) != 0;
    frame->ip_vers = flags_and_ip_ver & 0x0F;

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

    if (frame->ip_vers == 4 && (bytes_max - (bytes + byte_index) >= 4 + 2 * frame->has_port)) {
        struct sockaddr_in *sai = (struct sockaddr_in *) &frame->addr;
        my_memcpy(&sai->sin_addr.s_addr, &bytes[byte_index], 4);
        byte_index += 4;
        if (frame->has_port) {
            my_memcpy(&sai->sin_port, &bytes[byte_index], 2);
            byte_index += 2;
        } else {
            /* It is the same port as the initial path */
            my_memcpy(&sai->sin_port, &port_def, 2);
        }
        /* Ensure sai is a AF_INET address */
        sai->sin_family = AF_INET;
        bytes += byte_index;
    } else if (frame->ip_vers == 6 && (bytes_max - (bytes + byte_index) >= 16 + 2 * frame->has_port)) {
        struct sockaddr_in6 *sai6 = &frame->addr;
        my_memcpy(&sai6->sin6_addr, &bytes[byte_index], 16);
        byte_index += 16;
        if (frame->has_port) {
            my_memcpy(&sai6->sin6_port, &bytes[byte_index], 2);
            byte_index += 2;
        } else {
            /* It is the same port as the initial path */
            my_memcpy(&sai6->sin6_port, &port_def, 2);
        }
        /* Ensure sai6 is a AF_INET6 address */
        sai6->sin6_family = AF_INET6;
        bytes += byte_index;
    } else {
        // Error: unknown ip version
        my_free(cnx, frame);
        frame = NULL;
        bytes = NULL;
    }

    cnx->protoop_outputc_callee = 3;
    cnx->protoop_outputv[0] = (protoop_arg_t) frame;
    cnx->protoop_outputv[1] = (protoop_arg_t) ack_needed;
    cnx->protoop_outputv[2] = (protoop_arg_t) is_retransmittable;
    return (protoop_arg_t) bytes;
}

