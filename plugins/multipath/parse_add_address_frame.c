#include "bpf.h"


/**
 * See PROTOOP_PARAM_PARSE_FRAME
 */
protoop_arg_t parse_add_address_frame(picoquic_cnx_t* cnx)
{
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);

    int ack_needed = 1;
    int is_retransmittable = 1;
    add_address_frame_t *frame = (add_address_frame_t *) my_malloc(cnx, sizeof(add_address_frame_t));

    if (!frame) {
        helper_protoop_printf(cnx, "Failed to allocate memory for add_address_frame_t\n", NULL, 0);
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
        set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    size_t byte_index = picoquic_varint_skip(bytes);
    uint8_t flags_and_ip_ver;

    if (bytes_max - bytes <= 3) {
        /* No enough space for the ADD_ADDRESS header, won't work */
        my_free(cnx, frame);
        frame = NULL;
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
        set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
        return (protoop_arg_t) NULL;
    }

    my_memcpy(&flags_and_ip_ver, &bytes[byte_index++], 1);
    my_memcpy(&frame->address_id, &bytes[byte_index++], 1);
    frame->has_port = (flags_and_ip_ver & 0x10) != 0;
    frame->ip_vers = flags_and_ip_ver & 0x0F;

    /* Get the default port, if needed */
    picoquic_path_t *path_0 = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);
    struct sockaddr_storage *sa_def = (struct sockaddr_storage *) get_path(path_0, AK_PATH_PEER_ADDR, 0);
    int sa_def_length = (int) get_path(path_0, AK_PATH_PEER_ADDR_LEN, 0);
    uint16_t port_def = 0;

    if (sa_def_length == sizeof(struct sockaddr_in)) {
        struct sockaddr_in sai_def;
        my_memcpy(&sai_def, sa_def, sizeof(struct sockaddr_in));
        port_def = (uint16_t) sai_def.sin_port;
    } else { /* IPv6 */
        struct sockaddr_in6 sai6_def; 
        my_memcpy(&sai6_def, sa_def, sizeof(struct sockaddr_in6));
        port_def = (uint16_t) sai6_def.sin6_port;
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

    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) frame);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) ack_needed);
    set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) is_retransmittable);
    return (protoop_arg_t) bytes;
}

