#include "picoquic_internal.h"
#include "memory.h"
#include "memcpy.h"
#include "../helpers.h"

#define MP_OPAQUE_ID 0x10
#define MAX_PATHS 8
#define MAX_ADDRS 8

#define PREPARE_NEW_CONNECTION_ID_FRAME (PROTOOPID_SENDER + 0x48)
#define PREPARE_MP_ACK_FRAME (PROTOOPID_SENDER + 0x49)
#define PREPARE_ADD_ADDRESS_FRAME (PROTOOPID_SENDER + 0x4a)

#define ADD_ADDRESS_TYPE 0x22
#define MP_NEW_CONNECTION_ID_TYPE 0x26
#define MP_ACK_TYPE 0x27

typedef struct {
    picoquic_path_t *path;
    uint64_t path_id;
    uint8_t state; /* 0: proposed, 1: ready, 2: active, 3: unusable, 4: closed */
    uint8_t loc_addr_id;
    uint8_t rem_addr_id;
    picoquic_connection_id_t local_cnxid;
    picoquic_connection_id_t remote_cnxid;
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
} path_data_t;

typedef struct {
    uint8_t id;
    uint32_t if_index;
    struct sockaddr *sa;
    bool is_v6;
} addr_data_t;

typedef struct {
    uint8_t nb_proposed;
    uint8_t nb_proposed_snt;
    uint8_t nb_proposed_rcv;
    uint8_t nb_loc_addrs;
    uint8_t nb_rem_addrs;

    /* Just for simple rr scheduling */
    uint8_t last_path_index_sent;

    path_data_t paths[MAX_PATHS];
    addr_data_t loc_addrs[MAX_ADDRS];
    addr_data_t rem_addrs[MAX_ADDRS];
} bpf_data;

typedef struct add_address_frame {
    uint8_t has_port;
    uint8_t ip_vers;
    uint8_t address_id;
    /* This is an hack... An ipv4 address will fit inside */
    struct sockaddr_in6 addr;
} add_address_frame_t;

typedef struct mp_new_connection_id_frame {
    uint64_t path_id;
    new_connection_id_frame_t ncidf;
} mp_new_connection_id_frame_t;

typedef struct mp_ack_frame {
    uint64_t path_id;
    ack_frame_t ack;
} mp_ack_frame_t;

static bpf_data *initialize_bpf_data(picoquic_cnx_t *cnx)
{
    bpf_data *bpfd = (bpf_data *) my_malloc(cnx, sizeof(bpf_data));
    if (!bpfd) return NULL;
    my_memset(bpfd, 0, sizeof(bpf_data));
    return bpfd;
}

static bpf_data *get_bpf_data(picoquic_cnx_t *cnx)
{
    int allocated = 0;
    bpf_data **bpfd_ptr = (bpf_data **) get_opaque_data(cnx, MP_OPAQUE_ID, sizeof(bpf_data *), &allocated);
    if (!bpfd_ptr) return NULL;
    if (allocated) {
        *bpfd_ptr = initialize_bpf_data(cnx);
    }
    return *bpfd_ptr;
}

static int mp_get_path_index(bpf_data *bpfd, uint64_t path_id, int *new_path_index) {
    int path_index;
    if (new_path_index) {
        *new_path_index = 0;
    }
    for (path_index = 0; path_index < bpfd->nb_proposed; path_index++) {
        if (bpfd->paths[path_index].path_id == path_id) {
            break;
        }
    }
    if (path_index == bpfd->nb_proposed && bpfd->nb_proposed >= MAX_PATHS) {
        path_index = -1;
    } else if (path_index == bpfd->nb_proposed) {
        bpfd->paths[path_index].path_id = path_id;
        bpfd->nb_proposed++;
        if (new_path_index) {
            *new_path_index = 1;
        }
    }
    return path_index;
}

static path_data_t *mp_get_path_data(bpf_data *bpfd, picoquic_path_t *path_x) {
    path_data_t *pd = NULL;
    for (int path_index = 0; path_index < bpfd->nb_proposed; path_index++) {
        if (bpfd->paths[path_index].path == path_x) {
            pd = &bpfd->paths[path_index];
            break;
        }
    }
    return pd;
}

static void mp_path_ready(picoquic_cnx_t *cnx, path_data_t *pd, uint64_t current_time)
{
    pd->state = 1;
    /* By default, create the path with the current peer address of path 0 */
    int cnx_path_index = picoquic_create_path(cnx, current_time, (struct sockaddr *) &cnx->path[0]->peer_addr);
    /* TODO cope with possible errors */
    pd->path = cnx->path[cnx_path_index];
}

/* Other multipath functions */

static int parse_mp_ack_header(uint8_t const* bytes, size_t bytes_max,
    uint64_t* num_block, uint64_t* nb_ecnx3, uint64_t *path_id,
    uint64_t* largest, uint64_t* ack_delay, size_t* consumed,
    uint8_t ack_delay_exponent)
{
    int ret = 0;
    size_t byte_index = 1;
    size_t l_largest = 0;
    size_t l_delay = 0;
    size_t l_blocks = 0;
    size_t l_path_id = 0;

    if (bytes_max > byte_index) {
        l_path_id = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, path_id);
        byte_index += l_path_id;
    }

    if (bytes_max > byte_index) {
        l_largest = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, largest);
        byte_index += l_largest;
    }

    if (bytes_max > byte_index) {
        l_delay = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, ack_delay);
        *ack_delay <<= ack_delay_exponent;
        byte_index += l_delay;
    }

    if (nb_ecnx3 != NULL) {
        for (int ecnx = 0; ecnx < 3; ecnx++) {
            size_t l_ecnx = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &nb_ecnx3[ecnx]);

            if (l_ecnx == 0) {
                byte_index = bytes_max;
            }
            else {
                byte_index += l_ecnx;
            }
        }
    }

    if (bytes_max > byte_index) {
        l_blocks = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, num_block);
        byte_index += l_blocks;
    }

    if (l_path_id == 0 || l_largest == 0 || l_delay == 0 || l_blocks == 0 || bytes_max < byte_index) {
        // DBG_PRINTF("ack frame fixed header too large: first_byte=0x%02x, bytes_max=%" PRIst,
        //     bytes[0], bytes_max);
        byte_index = bytes_max;
        ret = -1;
    }

    *consumed = byte_index;
    return ret;
}

static int helper_process_mp_ack_range(
    picoquic_cnx_t* cnx, picoquic_packet_context_enum pc, uint64_t highest, uint64_t range, picoquic_packet_t** ppacket,
    uint64_t current_time)
{
    protoop_arg_t args[5], outs[1];
    args[0] = (protoop_arg_t) pc;
    args[1] = (protoop_arg_t) highest;
    args[2] = (protoop_arg_t) range;
    args[3] = (protoop_arg_t) *ppacket;
    args[4] = (protoop_arg_t) current_time;
    protoop_params_t pp = get_pp_noparam(PROTOOP_NOPARAM_PROCESS_ACK_RANGE, 5, args, outs);
    int ret = (int) plugin_run_protoop(cnx, &pp);
    *ppacket = (picoquic_packet_t*) outs[0];
    return ret;
}

static int helper_prepare_mp_ack_frame(
    picoquic_cnx_t* cnx, uint64_t current_time, picoquic_packet_context_enum pc, uint8_t* bytes,
    size_t bytes_max, size_t* consumed, picoquic_path_t* path_x)
{
    protoop_arg_t args[6], outs[1];
    args[0] = (protoop_arg_t) current_time;
    args[1] = (protoop_arg_t) pc;
    args[2] = (protoop_arg_t) bytes;
    args[3] = (protoop_arg_t) bytes_max;
    args[4] = (protoop_arg_t) *consumed;
    args[5] = (protoop_arg_t) path_x;
    protoop_params_t pp = get_pp_noparam("prepare_mp_ack_frame", 6, args, outs);
    int ret = (int) plugin_run_protoop(cnx, &pp);
    *consumed = (size_t) outs[0];
    return ret;
}

/* Multipath functions */

static int helper_prepare_mp_new_connection_id_frame(picoquic_cnx_t* cnx, uint8_t* bytes, size_t bytes_max,
    size_t *consumed, uint64_t path_id, uint64_t current_time)
{
    protoop_arg_t args[5], outs[1];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) bytes_max;
    args[2] = (protoop_arg_t) *consumed;
    args[3] = (protoop_arg_t) path_id;
    args[4] = (protoop_arg_t) current_time;
    protoop_params_t pp = get_pp_noparam("prepare_mp_new_connection_id_frame", 5, args, outs);
    int ret = (int) plugin_run_protoop(cnx, &pp);
    *consumed = (size_t) outs[0];
    return ret;
}

static int helper_prepare_add_address_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max, size_t *consumed)
{
    protoop_arg_t args[3], outs[1];
    args[0] = (protoop_arg_t) bytes;
    args[1] = (protoop_arg_t) bytes_max;
    args[2] = (protoop_arg_t) *consumed;
    protoop_params_t pp = get_pp_noparam("prepare_add_address_frame", 3, args, outs);
    int ret = (int) plugin_run_protoop(cnx, &pp);
    *consumed = (size_t) outs[0];
    return ret;
}