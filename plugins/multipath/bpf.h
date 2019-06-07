#include "../helpers.h"
#include "getset.h"
#include "util.h"

#define MP_OPAQUE_ID 0x00
#define MP_DUPLICATE_ID 0x01

#ifndef N_PATHS
#define N_PATHS 2
#endif
#ifndef MAX_PATHS
#define MAX_PATHS 8
#endif
#ifndef MAX_ADDRS
#define MAX_ADDRS 8
#endif

#define PREPARE_NEW_CONNECTION_ID_FRAME (PROTOOPID_SENDER + 0x48)
#define PREPARE_MP_ACK_FRAME (PROTOOPID_SENDER + 0x49)
#define PREPARE_ADD_ADDRESS_FRAME (PROTOOPID_SENDER + 0x4a)

#define PATH_UPDATE_TYPE 0x21
#define ADD_ADDRESS_TYPE 0x22
#define MP_NEW_CONNECTION_ID_TYPE 0x26
#define MP_ACK_TYPE 0x27

#define RTT_PROBE_TYPE 0x42
#define RTT_PROBE_INTERVAL 100000

typedef enum mp_path_state_e {
    path_proposed = 0,
    path_ready = 1,
    path_active = 2,
    path_unusable = 3,
    path_closed = 4,
} mp_path_state;

typedef struct {
    uint64_t path_id;
} mp_new_connection_id_ctx_t;

typedef struct {
    size_t nb_addrs;
    struct sockaddr_storage sas[MAX_ADDRS];
    uint32_t if_indexes[MAX_ADDRS];
} add_address_ctx_t;

typedef struct {
    picoquic_path_t *path_x;
    picoquic_packet_context_enum pc;
} mp_ack_ctx_t;

typedef struct {
    picoquic_path_t *path;
    uint64_t path_id;
    mp_path_state state; /* 0: proposed, 1: ready, 2: active, 3: unusable, 4: closed */
    uint8_t loc_addr_id;
    uint8_t rem_addr_id;
    picoquic_connection_id_t local_cnxid;
    picoquic_connection_id_t remote_cnxid;
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
    uint64_t last_rtt_probe;
    uint8_t rtt_probe_tries;
    bool rtt_probe_ready;
    bool proposed_cid;
    // bool doing_ack;

    uint64_t failure_count;
    uint64_t cooldown_time;
} path_data_t;

typedef struct {
    uint8_t id;
    uint32_t if_index;
    struct sockaddr *sa;
    bool is_v6;
} addr_data_t;

typedef struct {
    uint8_t nb_proposed;
    uint8_t nb_active;
    uint8_t nb_proposed_snt;
    uint8_t nb_proposed_rcv;
    uint8_t nb_loc_addrs;
    uint8_t nb_rem_addrs;

    /* Just for simple rr scheduling */
    uint8_t last_path_index_sent;

    path_data_t *paths[MAX_PATHS];
    addr_data_t loc_addrs[MAX_ADDRS];
    addr_data_t rem_addrs[MAX_ADDRS];

    // uint8_t pkt_seen_non_ack;
} bpf_data;

typedef struct {
    uint8_t requires_duplication;
    uint16_t data_length;
    uint8_t data[1250];
} bpf_duplicate_data;

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

typedef struct path_update {
    uint64_t closed_path_id;
    uint64_t proposed_path_id;
} path_update_t;

static bpf_data *initialize_bpf_data(picoquic_cnx_t *cnx)
{
    bpf_data *bpfd = (bpf_data *) my_malloc_ex(cnx, sizeof(bpf_data));
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

static bpf_duplicate_data *initialize_bpf_duplicate_data(picoquic_cnx_t *cnx)
{
    bpf_duplicate_data *bpfdd = (bpf_duplicate_data *) my_malloc_ex(cnx, sizeof(bpf_duplicate_data));
    if (!bpfdd) return NULL;
    my_memset(bpfdd, 0, sizeof(bpf_duplicate_data));
    return bpfdd;
}

static bpf_duplicate_data *get_bpf_duplicate_data(picoquic_cnx_t *cnx)
{
    int allocated = 0;
    bpf_duplicate_data **bpfdd_ptr = (bpf_duplicate_data **) get_opaque_data(cnx, MP_DUPLICATE_ID, sizeof(bpf_duplicate_data), &allocated);
    if (!bpfdd_ptr) return NULL;
    if (allocated) {
        *bpfdd_ptr = initialize_bpf_duplicate_data(cnx);
    }
    return *bpfdd_ptr;
}

static int mp_get_path_index(picoquic_cnx_t *cnx, bpf_data *bpfd, uint64_t path_id, int *new_path_index) {
    int path_index;
    if (new_path_index) {
        *new_path_index = false;
    }
    path_data_t *pd = NULL;
    for (path_index = 0; path_index < bpfd->nb_proposed; path_index++) {
        pd = bpfd->paths[path_index];
        if (!pd || pd->path_id == path_id) {
            break;
        }
    }
    if (path_index == bpfd->nb_proposed || !pd) {
        if (bpfd->nb_proposed >= MAX_PATHS) {
            path_index = -1;
        } else {
            bpfd->paths[path_index] = my_malloc_ex(cnx, sizeof(path_data_t));
            if (!bpfd->paths[path_index]) {
                return -1;
            }
            my_memset(bpfd->paths[path_index], 0, sizeof(path_data_t));
            bpfd->paths[path_index]->path_id = path_id;
            bpfd->nb_proposed++;
            if (new_path_index) {
                *new_path_index = true;
            }
        }
    }
    return path_index;
}

static path_data_t *mp_get_path_data(bpf_data *bpfd, picoquic_path_t *path_x) {
    path_data_t *pd = NULL;
    for (int path_index = 0; path_index < bpfd->nb_proposed; path_index++) {
        pd = bpfd->paths[path_index];
        if (pd && pd->path == path_x) {
            return pd;
        }
    }
    return NULL;
}

static __attribute__((always_inline)) void mp_path_ready(picoquic_cnx_t *cnx, path_data_t *pd, uint64_t current_time)
{
    pd->state = path_ready;
    picoquic_path_t *path_0 = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);
    /* By default, create the path with the current peer address of path 0 */
    struct sockaddr *peer_addr_0 = (struct sockaddr *) get_path(path_0, AK_PATH_PEER_ADDR, 0);
    int cnx_path_index = picoquic_create_path(cnx, current_time, peer_addr_0);
    /* TODO cope with possible errors */
    pd->path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, cnx_path_index);
    /* Also insert CIDs */
    picoquic_connection_id_t *local_cnxid = (picoquic_connection_id_t *) get_path(pd->path, AK_PATH_LOCAL_CID, 0);
    my_memcpy(local_cnxid, &pd->local_cnxid, sizeof(picoquic_connection_id_t));
    picoquic_connection_id_t *remote_cnxid = (picoquic_connection_id_t *) get_path(pd->path, AK_PATH_REMOTE_CID, 0);
    my_memcpy(remote_cnxid, &pd->remote_cnxid, sizeof(picoquic_connection_id_t));
    uint8_t *reset_secret = (uint8_t *) get_path(pd->path, AK_PATH_RESET_SECRET, 0);
    my_memcpy(reset_secret, pd->reset_secret, 16);
    LOG_EVENT(cnx, "MULTIPATH", "PATH_READY", "", "{\"path_id\": %lu, \"path\": \"%p\"}", pd->path_id, (protoop_arg_t) pd->path);
}

static __attribute__((always_inline)) size_t varint_len(uint64_t val) {
    if (val <= 63) {
        return 1;
    } else if (val <= 16383) {
        return 2;
    } else if (val <= 1073741823) {
        return 4;
    } else if (val <= 4611686018427387903) {
        return 8;
    }
    return 0;
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
    my_memset(rfs, 0, sizeof(reserve_frame_slot_t));
    rfs->frame_type = MP_NEW_CONNECTION_ID_TYPE;
    rfs->frame_ctx = mncic;
    rfs->nb_bytes = 52; /* This is the max value, in practice it won't be so much, but spare the estimation process here */
    reserve_frames(cnx, 1, rfs);
}

static bool accept_addr(picoquic_cnx_t *cnx, struct sockaddr_storage *sa, uint32_t if_index) {
    protoop_id_t pid;
    pid.id = "accept_addr";
    pid.hash = hash_value_str(pid.id);
    if (!plugin_pluglet_exists(cnx, &pid, NO_PARAM, pluglet_replace)) {
        return true;
    }
    protoop_arg_t args[2];
    args[0] = (protoop_arg_t) sa;
    args[1] = (protoop_arg_t) if_index;
    return (bool) run_noparam(cnx, pid.id, 2, args, NULL);
}

static size_t filter_addrs(picoquic_cnx_t *cnx, struct sockaddr_storage *sas, uint32_t *if_indexes, int addrs) {
    int i = 0;
    while (i < addrs) {
        struct sockaddr_storage *sa = sas + i;
        char dst[INET_ADDRSTRLEN];
        PROTOOP_PRINTF(cnx, "Address %s ", (protoop_arg_t) inet_ntop(AF_INET, &((struct sockaddr_in *) sa)->sin_addr, dst, sizeof(dst)));
        if (!accept_addr(cnx, sa, *(if_indexes + i))) {
            struct sockaddr_storage *end = sas + (addrs - 1);
            if (end != sa) {
                my_memcpy(sa, end, sizeof(struct sockaddr_storage));
                *(if_indexes + i) = *(if_indexes + (addrs - 1));
            }
            addrs--;
            PROTOOP_PRINTF(cnx, "was rejected\n");
        } else {
            i++;
            PROTOOP_PRINTF(cnx, "was accepted\n");
        }
    }
    return addrs;
}

static void reserve_add_address_frame(picoquic_cnx_t *cnx)
{
    add_address_ctx_t *aac = (add_address_ctx_t *) my_malloc(cnx, sizeof(add_address_ctx_t));
    my_memset(aac, 0, sizeof(add_address_ctx_t));
    if (!aac) {
        return;
    }
    aac->nb_addrs = (size_t) picoquic_getaddrs(aac->sas, aac->if_indexes, MAX_ADDRS);
    if (aac->nb_addrs == 0) {
        my_free(cnx, aac);
        return;
    }
    aac->nb_addrs = filter_addrs(cnx, aac->sas, aac->if_indexes, aac->nb_addrs);
    if (aac->nb_addrs == 0) {
        my_free(cnx, aac);
        return;
    }
    int frame_size_v6 = 21;
    reserve_frame_slot_t *rfs = (reserve_frame_slot_t *) my_malloc(cnx, sizeof(reserve_frame_slot_t));
    if (!rfs) {
        my_free(cnx, aac);
        return;
    }
    my_memset(rfs, 0, sizeof(reserve_frame_slot_t));
    rfs->frame_type = ADD_ADDRESS_TYPE;
    rfs->frame_ctx = aac;
    rfs->nb_bytes = frame_size_v6 * aac->nb_addrs;
    reserve_frames(cnx, 1, rfs);
}

static __attribute__((always_inline)) void reserve_mp_ack_frame(picoquic_cnx_t *cnx, picoquic_path_t *path_x, picoquic_packet_context_enum pc)
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
    my_memset(rfs, 0, sizeof(reserve_frame_slot_t));
    rfs->frame_type = MP_ACK_TYPE;
    rfs->frame_ctx = mac;
    rfs->nb_bytes = 200; /* FIXME dynamic count */
    reserve_frames(cnx, 1, rfs);
    /* Reserved now, so ack_needed is not true anymore. This is an important fix! */
    picoquic_packet_context_t *pkt_ctx = (picoquic_packet_context_t *) get_path(path_x, AK_PATH_PKT_CTX, pc);
    set_pkt_ctx(pkt_ctx, AK_PKTCTX_ACK_NEEDED, 0);
}

static __attribute__((always_inline)) void reserve_path_update(picoquic_cnx_t *cnx, uint64_t closed_path_id, uint64_t proposed_path_id) {
    path_update_t *update = (path_update_t *) my_malloc(cnx, sizeof(path_update_t));
    update->closed_path_id = closed_path_id;
    update->proposed_path_id = proposed_path_id;

    reserve_frame_slot_t *rfs = (reserve_frame_slot_t *) my_malloc(cnx, sizeof(reserve_frame_slot_t));
    if (!rfs) {
        my_free(cnx, update);
        return;
    }
    my_memset(rfs, 0, sizeof(reserve_frame_slot_t));
    rfs->frame_type = PATH_UPDATE_TYPE;
    rfs->frame_ctx = update;
    rfs->nb_bytes = 1 + varint_len(update->closed_path_id) + varint_len(update->proposed_path_id);
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


static picoquic_path_t *schedule_path(picoquic_cnx_t *cnx, picoquic_packet_t *retransmit_p, picoquic_path_t *from_path, char *reason, int change_path) {
    protoop_arg_t args[4];
    args[0] = (protoop_arg_t) retransmit_p;
    args[1] = (protoop_arg_t) from_path;
    args[2] = (protoop_arg_t) reason;
    args[3] = change_path;
    return (picoquic_path_t *) run_noparam(cnx, "schedule_path", 4, args, NULL);
}

static void manage_paths(picoquic_cnx_t *cnx) {
    run_noparam(cnx, "manage_paths", 0, NULL, NULL);
}
