#include "picoquic.h"
#include "memory.h"
#include "memcpy.h"
#include "../helpers.h"
#include "getset.h"

#define MP_OPAQUE_ID 0x00
#define MAX_PATHS 8
#define MAX_ADDRS 8

#define PREPARE_NEW_CONNECTION_ID_FRAME (PROTOOPID_SENDER + 0x48)
#define PREPARE_MP_ACK_FRAME (PROTOOPID_SENDER + 0x49)
#define PREPARE_ADD_ADDRESS_FRAME (PROTOOPID_SENDER + 0x4a)

#define ADD_ADDRESS_TYPE 0x22
#define MP_NEW_CONNECTION_ID_TYPE 0x26
#define MP_ACK_TYPE 0x27

typedef struct {
    uint64_t path_id;
} mp_new_connection_id_ctx_t;

typedef struct {
    size_t nb_addrs;
    struct sockaddr_in sas[4];
    uint32_t if_indexes[4];
} add_address_ctx_t;

typedef struct {
    picoquic_path_t *path_x;
    picoquic_packet_context_enum pc;
} mp_ack_ctx_t;

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

    picoquic_path_t *ack_ok_paths[MAX_PATHS]; /* TODO cleaner support and support for more */
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

static __attribute__((always_inline)) void mp_path_ready(picoquic_cnx_t *cnx, path_data_t *pd, uint64_t current_time)
{
    pd->state = 1;
    picoquic_path_t *path_0 = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, 0);
    /* By default, create the path with the current peer address of path 0 */
    struct sockaddr *peer_addr_0 = (struct sockaddr *) get_path(path_0, PATH_AK_PEER_ADDR, 0);
    int cnx_path_index = picoquic_create_path(cnx, current_time, peer_addr_0);
    /* TODO cope with possible errors */
    pd->path = (picoquic_path_t *) get_cnx(cnx, CNX_AK_PATH, cnx_path_index);
    /* Also insert CIDs */
    picoquic_connection_id_t *local_cnxid = (picoquic_connection_id_t *) get_path(pd->path, PATH_AK_LOCAL_CID, 0);
    my_memcpy(local_cnxid, &pd->local_cnxid, sizeof(picoquic_connection_id_t));
    picoquic_connection_id_t *remote_cnxid = (picoquic_connection_id_t *) get_path(pd->path, PATH_AK_REMOTE_CID, 0);
    my_memcpy(remote_cnxid, &pd->remote_cnxid, sizeof(picoquic_connection_id_t));
    uint8_t *reset_secret = (uint8_t *) get_path(pd->path, PATH_AK_RESET_SECRET, 0);
    my_memcpy(reset_secret, pd->reset_secret, 16);
}

static void reserve_mp_new_connection_id_frame(picoquic_cnx_t *cnx, uint64_t path_id)
{
    mp_new_connection_id_ctx_t *mncic = (mp_new_connection_id_ctx_t *) my_malloc(cnx, sizeof(mp_new_connection_id_ctx_t));
    if (!mncic) {
        return;
    }
    mncic->path_id = path_id;
    reserve_frame_slot_t *rfs = (reserve_frame_slot_t *) my_malloc(cnx, sizeof(reserve_frame_slot_t));
    if (!rfs) {
        my_free(cnx, mncic);
        return;
    }
    rfs->frame_type = MP_NEW_CONNECTION_ID_TYPE;
    rfs->frame_ctx = mncic;
    rfs->nb_bytes = 52; /* This is the max value, in practice it won't be so much, but spare the estimation process here */
    reserve_frames(cnx, 1, rfs);
}

static void reserve_add_address_frame(picoquic_cnx_t *cnx)
{
    add_address_ctx_t *aac = (add_address_ctx_t *) my_malloc(cnx, sizeof(add_address_ctx_t));
    if (!aac) {
        return;
    }
    aac->nb_addrs = picoquic_getaddrs_v4(aac->sas, aac->if_indexes, 4);
    if (aac->nb_addrs == 0) {
        my_free(cnx, aac);
        return;
    }
    int frame_size_v4 = 9;
    reserve_frame_slot_t *rfs = (reserve_frame_slot_t *) my_malloc(cnx, sizeof(reserve_frame_slot_t));
    if (!rfs) {
        my_free(cnx, aac);
        return;
    }
    rfs->frame_type = ADD_ADDRESS_TYPE;
    rfs->frame_ctx = aac;
    rfs->nb_bytes = frame_size_v4 * aac->nb_addrs;
    reserve_frames(cnx, 1, rfs);
}

static void reserve_mp_ack_frame(picoquic_cnx_t *cnx, picoquic_path_t *path_x, picoquic_packet_context_enum pc)
{
    mp_ack_ctx_t *mac = (mp_ack_ctx_t *) my_malloc(cnx, sizeof(mp_ack_ctx_t));
    if (!mac) {
        return;
    }
    mac->path_x = path_x;
    mac->pc = pc;
    reserve_frame_slot_t *rfs = (reserve_frame_slot_t *) my_malloc(cnx, sizeof(reserve_frame_slot_t));
    if (!rfs) {
        my_free(cnx, mac);
        return;
    }
    rfs->frame_type = MP_ACK_TYPE;
    rfs->frame_ctx = mac;
    rfs->nb_bytes = 14; /* This might probably change... */
    reserve_frames(cnx, 1, rfs);
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
    int ret = (int) run_noparam(cnx, PROTOOPID_NOPARAM_PROCESS_ACK_RANGE, 5, args, outs);
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
    int ret = (int) run_noparam(cnx, "prepare_mp_ack_frame", 6, args, outs);
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
    int ret = (int) run_noparam(cnx, "prepare_mp_new_connection_id_frame", 5, args, outs);
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
    int ret = (int) run_noparam(cnx, "prepare_mp_add_address_frame", 3, args, outs);
    *consumed = (size_t) outs[0];
    return ret;
}

static void start_using_path_if_possible(picoquic_cnx_t* cnx) {
    int client_mode = (int) get_cnx(cnx, CNX_AK_CLIENT_MODE, 0);
    /* Prevent the server from starting using new paths */
    if (!client_mode) {
        return;
    }
    bpf_data *bpfd = get_bpf_data(cnx);
    path_data_t *pd = NULL;

    /* Don't go further if the address exchange is not complete! */
    if (bpfd->nb_loc_addrs < 2 && bpfd->nb_rem_addrs < 1) {
        return;
    }

    for (int i = 0; i < bpfd->nb_proposed; i++) {
        pd = &bpfd->paths[i];
        /* If we are the client, activate the path */
        /* FIXME hardcoded */
        if (pd->state == 1 && pd->path_id % 2 == 0) {
            pd->state = 2;
            addr_data_t *adl = NULL;
            addr_data_t *adr = NULL;
            /* Path 2 on the first local address, only if it exists! */
            if (pd->path_id == 2 && bpfd->loc_addrs[0].sa != NULL && bpfd->rem_addrs[0].sa) {
                pd->loc_addr_id = 1;
                adl = &bpfd->loc_addrs[0];
                set_path(pd->path, PATH_AK_LOCAL_ADDR_LEN, 0, (adl->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
                struct sockaddr_storage *path_local_addr = (struct sockaddr_storage *) get_path(pd->path, PATH_AK_LOCAL_ADDR, 0);
                my_memcpy(path_local_addr, adl->sa, (adl->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
                set_path(pd->path, PATH_AK_IF_INDEX_LOCAL, 0, (unsigned long) adl->if_index);
                pd->rem_addr_id = 1;
                adr = &bpfd->rem_addrs[0];
                set_path(pd->path, PATH_AK_PEER_ADDR_LEN, 0, (adr->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
                struct sockaddr_storage *path_peer_addr = (struct sockaddr_storage *) get_path(pd->path, PATH_AK_PEER_ADDR, 0);
                my_memcpy(path_peer_addr, adr->sa,(adr->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
            } else if (pd->path_id == 4 && bpfd->loc_addrs[1].sa != NULL && bpfd->rem_addrs[0].sa) {
                // Path id is 4
                pd->loc_addr_id = 2;
                adl = &bpfd->loc_addrs[1];
                set_path(pd->path, PATH_AK_LOCAL_ADDR_LEN, 0, (adl->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
                struct sockaddr_storage *path_local_addr = (struct sockaddr_storage *) get_path(pd->path, PATH_AK_LOCAL_ADDR, 0);
                my_memcpy(path_local_addr, adl->sa, (adl->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
                set_path(pd->path, PATH_AK_IF_INDEX_LOCAL, 0, (unsigned long) adl->if_index);
                pd->rem_addr_id = 1;
                adr = &bpfd->rem_addrs[0];
                set_path(pd->path, PATH_AK_PEER_ADDR_LEN, 0, (adr->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
                struct sockaddr_storage *path_peer_addr = (struct sockaddr_storage *) get_path(pd->path, PATH_AK_PEER_ADDR, 0);
                my_memcpy(path_peer_addr, adr->sa,(adr->is_v6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
            }
        }
    }
}