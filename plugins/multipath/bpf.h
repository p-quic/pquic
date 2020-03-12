#include "../helpers.h"
#include "getset.h"
#include "util.h"

#define MP_OPAQUE_ID 0x00
#define MP_DUPLICATE_ID 0x01
#define MP_TUPLE_ID 0x02

#ifndef N_PATHS
#define N_PATHS 2
#endif
#ifndef MAX_PATHS
#define MAX_PATHS 4
#endif
#ifndef MAX_ADDRS
#define MAX_ADDRS 4
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
    path_ready = 0,
    path_active = 1,
    path_unusable = 2, /* XXX: (QDC) Not sure this is needed anymore */
    path_closed = 3,
} mp_path_state;

typedef struct {
    uint64_t path_id;
} mp_new_connection_id_ctx_t;

typedef struct {
    size_t nb_addrs;
    struct sockaddr_storage sas[MAX_ADDRS];
    uint32_t if_indexes[MAX_ADDRS];
    bool is_rtx;
} add_address_ctx_t;

typedef struct {
    picoquic_path_t *path_x;
    picoquic_packet_context_enum pc;
} mp_ack_ctx_t;

typedef struct {
    picoquic_path_t *path;
    /* FIXME find a proper way to distinguish sending vs. receive path */
    bool is_sending_path;
    uint64_t path_id;
    mp_path_state state; /* 0: ready, 1: active, 2: closed */
    uint8_t loc_addr_id;
    uint8_t rem_addr_id;
    /* For receive paths, it is local cnxid / reset secret, for sending paths it is remote */
    picoquic_connection_id_t cnxid;
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
    uint64_t max_ack_delay;
    uint64_t smoothed_rtt;
    uint64_t rtt_variant;
    uint64_t rtt_min;
    uint64_t nb_updates;
} stats_t;

typedef struct {
    uint8_t nb_sending_active;
    uint8_t nb_sending_proposed;
    uint8_t nb_receive_proposed;
    uint8_t nb_loc_addrs;
    uint8_t nb_rem_addrs;

    /* Just for simple rr scheduling */
    uint8_t last_path_index_sent;

    path_data_t *sending_paths[MAX_PATHS];
    path_data_t *receive_paths[MAX_PATHS];
    addr_data_t loc_addrs[MAX_ADDRS];
    addr_data_t rem_addrs[MAX_ADDRS];

    // uint8_t pkt_seen_non_ack;
} bpf_data;

typedef struct {
    stats_t tuple_stats[MAX_PATHS][MAX_PATHS]; /* [receive index][sending index] */
} bpf_tuple_data;

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
    bpf_data *bpfd_ptr = (bpf_data *) get_cnx_metadata(cnx, MP_OPAQUE_ID);
    if (!bpfd_ptr) {
        bpfd_ptr = initialize_bpf_data(cnx);
        set_cnx_metadata(cnx, MP_OPAQUE_ID, (protoop_arg_t) bpfd_ptr);
    }
    return bpfd_ptr;
}

static bpf_tuple_data *initialize_bpf_tuple_data(picoquic_cnx_t *cnx)
{
    bpf_tuple_data *bpftd = (bpf_tuple_data *) my_malloc(cnx, sizeof(bpf_tuple_data));
    if (!bpftd) return NULL;
    my_memset(bpftd, 0, sizeof(bpf_tuple_data));
    return bpftd;
}

static bpf_tuple_data *get_bpf_tuple_data(picoquic_cnx_t *cnx)
{
    bpf_tuple_data *bpftd_ptr = (bpf_tuple_data *) get_cnx_metadata(cnx, MP_TUPLE_ID);
    if (!bpftd_ptr) {
        bpftd_ptr = initialize_bpf_tuple_data(cnx);
        set_cnx_metadata(cnx, MP_TUPLE_ID, (protoop_arg_t) bpftd_ptr);
    }
    return bpftd_ptr;
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
    bpf_duplicate_data *bpfdd_ptr = (bpf_duplicate_data *) get_cnx_metadata(cnx, MP_DUPLICATE_ID);
    if (!bpfdd_ptr) {
        bpfdd_ptr = initialize_bpf_duplicate_data(cnx);
        set_cnx_metadata(cnx, MP_DUPLICATE_ID, (protoop_arg_t) bpfdd_ptr);
    }
    return bpfdd_ptr;
}

/* Returns -1 if not found */
static int mp_find_path_index_internal(picoquic_cnx_t *cnx, uint8_t max_count, path_data_t **paths, uint64_t path_id) {
    int path_index;
    path_data_t *pd = NULL;
    for (path_index = 0; path_index < max_count; path_index++) {
        pd = paths[path_index];
        if (!pd || pd->path_id == path_id) {
            break;
        }
    }
    if (path_index == max_count || !pd) {
        path_index = -1;
    }
    return path_index;
}

static int mp_get_path_index(picoquic_cnx_t *cnx, bpf_data *bpfd, bool for_sending_path, uint64_t path_id, int *new_path_index) {
    path_data_t **paths = for_sending_path ? bpfd->sending_paths : bpfd->receive_paths;
    uint8_t max_count = for_sending_path ? bpfd->nb_sending_proposed : bpfd->nb_receive_proposed;
    int path_index = mp_find_path_index_internal(cnx, max_count, paths, path_id);
    if (new_path_index) {
        *new_path_index = false;
    }

    if (path_index < 0 && max_count < MAX_PATHS) {
        path_index = max_count;
        paths[path_index] = my_malloc(cnx, sizeof(path_data_t));
        if (!paths[path_index]) {
            helper_protoop_printf(cnx, "Cannot allocate path_data...\n", NULL, 0);
            return -1;
        }
        my_memset(paths[path_index], 0, sizeof(path_data_t));
        paths[path_index]->path_id = path_id;
        if (for_sending_path) {
            bpfd->nb_sending_proposed++;
        } else {
            bpfd->nb_receive_proposed++;
        }
        if (new_path_index) {
            *new_path_index = true;
        }
    }

    return path_index;
}

static path_data_t *mp_get_path_data(bpf_data *bpfd, bool for_sending_path, picoquic_path_t *path_x) {
    path_data_t **paths = for_sending_path ? bpfd->sending_paths : bpfd->receive_paths;
    uint8_t max_count = for_sending_path ? bpfd->nb_sending_proposed : bpfd->nb_receive_proposed;
    path_data_t *pd = NULL;
    for (int path_index = 0; path_index < max_count; path_index++) {
        pd = paths[path_index];
        if (pd && pd->path == path_x) {
            return pd;
        }
    }
    return NULL;
}

static path_data_t *mp_get_sending_path_data(bpf_data *bpfd, picoquic_path_t *path_x) {
    return mp_get_path_data(bpfd, true, path_x);
}

static path_data_t *mp_get_receive_path_data(bpf_data *bpfd, picoquic_path_t *path_x) {
    return mp_get_path_data(bpfd, false, path_x);
}

static int mp_get_path_index_from_path(bpf_data *bpfd, bool for_sending_path, picoquic_path_t *path_x) {
    path_data_t **paths = for_sending_path ? bpfd->sending_paths : bpfd->receive_paths;
    uint8_t max_count = for_sending_path ? bpfd->nb_sending_proposed : bpfd->nb_receive_proposed;
    path_data_t *pd = NULL;
    for (int path_index = 0; path_index < max_count; path_index++) {
        pd = paths[path_index];
        if (pd && pd->path == path_x) {
            return path_index;
        }
    }
    return -1;
}

static __attribute__((always_inline)) void mp_sending_path_ready(picoquic_cnx_t *cnx, path_data_t *pd, uint64_t current_time)
{
    pd->state = path_ready;
    pd->is_sending_path = true;
    /* By default, create the path with the current peer address of path 0 */
    picoquic_path_t *path_0 = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);
    struct sockaddr *peer_addr_0 = (struct sockaddr *) get_path(path_0, AK_PATH_PEER_ADDR, 0);
    int cnx_path_index = picoquic_create_path(cnx, current_time, peer_addr_0);
    /* TODO cope with possible errors */
    pd->path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, cnx_path_index);
    /* Also insert the remote CID */
    picoquic_connection_id_t *remote_cnxid = (picoquic_connection_id_t *) get_path(pd->path, AK_PATH_REMOTE_CID, 0);
    my_memcpy(remote_cnxid, &pd->cnxid, sizeof(picoquic_connection_id_t));
    uint8_t *reset_secret = (uint8_t *) get_path(pd->path, AK_PATH_RESET_SECRET, 0);
    my_memcpy(reset_secret, pd->reset_secret, 16);
    LOG_EVENT(cnx, "multipath", "sending_path_ready", "", "{\"path_id\": %" PRIu64 ", \"path\": \"%p\"}", pd->path_id, (protoop_arg_t) pd->path);
}

static __attribute__((always_inline)) void mp_receive_path_active(picoquic_cnx_t *cnx, path_data_t *pd, uint64_t current_time)
{
    pd->state = path_active;
    pd->is_sending_path = false;
    /* By default, create the path with the current peer address of path 0 */
    picoquic_path_t *path_0 = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, 0);
    struct sockaddr *peer_addr_0 = (struct sockaddr *) get_path(path_0, AK_PATH_PEER_ADDR, 0);
    int cnx_path_index = picoquic_create_path(cnx, current_time, peer_addr_0);
    /* TODO cope with possible errors */
    pd->path = (picoquic_path_t *) get_cnx(cnx, AK_CNX_PATH, cnx_path_index);
    set_path(pd->path, AK_PATH_CHALLENGE_VERIFIED, 0, 1);  // Don't validate receive path
    /* Also insert the local CID */
    picoquic_connection_id_t *local_cnxid = (picoquic_connection_id_t *) get_path(pd->path, AK_PATH_LOCAL_CID, 0);
    my_memcpy(local_cnxid, &pd->cnxid, sizeof(picoquic_connection_id_t));
    uint8_t *reset_secret = (uint8_t *) get_path(pd->path, AK_PATH_RESET_SECRET, 0);
    my_memcpy(reset_secret, pd->reset_secret, 16);
    LOG_EVENT(cnx, "multipath", "receive_path_ready", "", "{\"path_id\": %" PRIu64 ", \"path\": \"%p\"}", pd->path_id, (protoop_arg_t) pd->path);
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

static __attribute__((always_inline)) picoquic_packet_t* mp_update_rtt(picoquic_cnx_t* cnx, uint64_t largest,
    uint64_t current_time, uint64_t ack_delay, picoquic_packet_context_enum pc,
    picoquic_path_t* sending_path, picoquic_path_t* receive_path, int *is_new_ack)
{
    protoop_arg_t args[6];
    args[0] = (protoop_arg_t) largest;
    args[1] = (protoop_arg_t) current_time;
    args[2] = (protoop_arg_t) ack_delay;
    args[3] = (protoop_arg_t) pc;
    args[4] = (protoop_arg_t) sending_path;
    args[5] = (protoop_arg_t) receive_path;
    protoop_arg_t outs[1];
    picoquic_packet_t *p = (picoquic_packet_t *) run_noparam(cnx, PROTOOPID_NOPARAM_UPDATE_RTT, 6, args, outs);
    if (is_new_ack) {
        *is_new_ack = outs[0];
    }
    return p;
}