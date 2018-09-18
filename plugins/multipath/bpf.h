#include "picoquic_internal.h"
#include "memory.h"
#include "memcpy.h"

#define MP_OPAQUE_ID 0x10
#define MAX_PATHS 8

#define DECODE_MP_ACK_FRAME (PROTOOPID_DECODE_FRAMES + 0x27)

#define PREPARE_NEW_CONNECTION_ID_FRAME (PROTOOPID_SENDER + 0x48)
#define PREPARE_MP_ACK_FRAME (PROTOOPID_SENDER + 0x49)

#define MP_NEW_CONNECTION_ID_TYPE 0x26
#define MP_ACK_TYPE 0x27

typedef struct {
    picoquic_path_t *path;
    uint64_t path_id;
    uint8_t state; /* 0: proposed, 1: ready, 2: active, 3: unusable, 4: closed */
    picoquic_connection_id_t local_cnxid;
    picoquic_connection_id_t remote_cnxid;
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
} path_data_t;

typedef struct {
    uint8_t nb_proposed;
    uint8_t nb_proposed_snt;
    uint8_t nb_proposed_rcv;
    path_data_t paths[MAX_PATHS];
} bpf_data;

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
        l_largest = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, path_id);
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
    int ret = (int) plugin_run_protoop(cnx, PROTOOPID_PROCESS_ACK_RANGE, 5, args, outs);
    *ppacket = (picoquic_packet_t*) outs[0];
    return ret;
}
