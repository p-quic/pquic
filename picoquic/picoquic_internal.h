/*
* \file picoquic_internal.h
* \brief Header file with all internal structures of picoquic
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef PICOQUIC_INTERNAL_H
#define PICOQUIC_INTERNAL_H

#include "picohash.h"
#include "picoquic.h"
#include "picotlsapi.h"
#include "util.h"
#include "ubpf.h"
#include "picosocks.h"
#include "uthash.h"
#include "plugin.h"

#ifdef __APPLE__
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#else
#include <endian.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PICOQUIC_MAX_PACKET_SIZE 1536
#define PICOQUIC_MIN_SEGMENT_SIZE 256
#define PICOQUIC_INITIAL_MTU_IPV4 1252
#define PICOQUIC_INITIAL_MTU_IPV6 1232
#define PICOQUIC_ENFORCED_INITIAL_MTU 1200
#define PICOQUIC_PRACTICAL_MAX_MTU 1440
#define PICOQUIC_RETRY_SECRET_SIZE 64
#define PICOQUIC_DEFAULT_0RTT_WINDOW 4096

#define PICOQUIC_NUMBER_OF_EPOCHS 4
#define PICOQUIC_NUMBER_OF_EPOCH_OFFSETS (PICOQUIC_NUMBER_OF_EPOCHS+1)

#define PICOQUIC_INITIAL_RTT 250000 /* 250 ms */
#define PICOQUIC_TARGET_RENO_RTT 100000 /* 100 ms */
#define PICOQUIC_INITIAL_RETRANSMIT_TIMER 1000000 /* one second */
#define PICOQUIC_MIN_RETRANSMIT_TIMER 50000 /* 50 ms */
#define PICOQUIC_ACK_DELAY_MAX 25000 /* 25 ms */
#define PICOQUIC_RACK_DELAY 10000 /* 10 ms */

#define PICOQUIC_BANDWIDTH_ESTIMATE_MAX 10000000000ull /* 10 GB per second */
#define PICOQUIC_BANDWIDTH_TIME_INTERVAL_MIN 1000

#define PICOQUIC_SPURIOUS_RETRANSMIT_DELAY_MAX 1000000 /* one second */

#define PICOQUIC_MICROSEC_SILENCE_MAX 120000000 /* 120 seconds for now */
#define PICOQUIC_MICROSEC_HANDSHAKE_MAX 15000000 /* 15 seconds for now */
#define PICOQUIC_MICROSEC_WAIT_MAX 10000000 /* 10 seconds for now */

#define PICOQUIC_CWIN_INITIAL (10 * PICOQUIC_MAX_PACKET_SIZE)
#define PICOQUIC_CWIN_MINIMUM (2 * PICOQUIC_MAX_PACKET_SIZE)

#define PICOQUIC_SPIN_VEC_LATE 1000 /* in microseconds : reaction time beyond which to mark a spin bit edge as 'late' */


/*
 * Supported versions
 */
#define PICOQUIC_INTEROP_VERSION 0xff00001b
#define PICOQUIC_INTERNAL_TEST_VERSION_1 0x50435130

#define PICOQUIC_INTEROP_VERSION_INDEX 1

/*
 * Flags used to describe the capabilities of different versions.
 */

typedef enum {
    picoquic_version_no_flag = 0
} picoquic_version_feature_flags;

/*
 * Codes used for representing the various types of packet encodings
 */
typedef enum {
    picoquic_version_header_27
} picoquic_version_header_encoding;

typedef struct st_picoquic_version_parameters_t {
    uint32_t version;
    uint32_t version_flags;
    picoquic_version_header_encoding version_header_encoding;
    size_t version_aead_key_length;
    uint8_t* version_aead_key;
} picoquic_version_parameters_t;

extern const picoquic_version_parameters_t picoquic_supported_versions[];
extern const size_t picoquic_nb_supported_versions;
int picoquic_get_version_index(uint32_t proposed_version);

/*
     * Definition of the session ticket store that can be associated with a
     * client context.
     */
typedef struct st_picoquic_stored_ticket_t {
    struct st_picoquic_stored_ticket_t* next_ticket;
    char* sni;
    char* alpn;
    uint8_t* ticket;
    uint64_t time_valid_until;
    uint16_t sni_length;
    uint16_t alpn_length;
    uint16_t ticket_length;
} picoquic_stored_ticket_t;

int picoquic_store_ticket(picoquic_stored_ticket_t** pp_first_ticket,
    uint64_t current_time,
    char const* sni, uint16_t sni_length, char const* alpn, uint16_t alpn_length,
    uint8_t* ticket, uint16_t ticket_length);
int picoquic_get_ticket(picoquic_stored_ticket_t* p_first_ticket,
    uint64_t current_time,
    char const* sni, uint16_t sni_length, char const* alpn, uint16_t alpn_length,
    uint8_t** ticket, uint16_t* ticket_length);

int picoquic_save_tickets(const picoquic_stored_ticket_t* first_ticket,
    uint64_t current_time, char const* ticket_file_name);
int picoquic_load_tickets(picoquic_stored_ticket_t** pp_first_ticket,
    uint64_t current_time, char const* ticket_file_name);
void picoquic_free_tickets(picoquic_stored_ticket_t** pp_first_ticket);


#define MAX_PLUGIN 64
#define PROTOOPPLUGINNAME_MAX 100
/**
 * XXX: For now, we assume we always request the same plugin.
 * If not, we would require an hash map with linked list, but the current behaviour
 * of the client and the server does not require it now. Currently, a queue does
 * well the job.
 */
typedef struct st_cached_plugins_t {
    protocol_operation_struct_t* ops; /* A hash map to the protocol operations */
    protoop_plugin_t* plugins; /* A hash map to the plugins referenced by ops */
    char plugin_names[MAX_PLUGIN][PROTOOPPLUGINNAME_MAX]; /* The names of the plugins */
    uint8_t nb_plugins;
} cached_plugins_t;

typedef struct st_plugin_list_t {
    uint16_t size;
    uint16_t name_num_bytes; // Count the number of bytes in the plugin names
    plugin_fname_t elems[MAX_PLUGIN];
} plugin_list_t;

typedef struct st_plugin_req_pid_t {
    char* plugin_name;
    int requested:1;
    uint64_t pid_id;
    uint64_t received_length;
    uint8_t *data;
} plugin_req_pid_t;

typedef struct st_plugin_request_t {
    uint16_t size;
    plugin_req_pid_t elems[MAX_PLUGIN];
} plugin_request_t;

/*
	 * QUIC context, defining the tables of connections,
	 * open sockets, etc.
	 */
typedef struct st_picoquic_quic_t {
    void * F_log;
    void * F_tls_secrets;
    void* tls_master_ctx;
    picoquic_stream_data_cb_fn default_callback_fn;
    void* default_callback_ctx;
    char const* default_alpn;
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE];
    uint8_t retry_seed[PICOQUIC_RETRY_SECRET_SIZE];
    uint64_t* p_simulated_time;
    char const* ticket_file_name;
    picoquic_stored_ticket_t* p_first_ticket;
    uint32_t mtu_max;

    uint32_t flags;

    picoquic_stateless_packet_t* pending_stateless_packet;

    picoquic_congestion_algorithm_t const* default_congestion_alg;

    struct st_picoquic_cnx_t* cnx_list;
    struct st_picoquic_cnx_t* cnx_last;

    struct st_picoquic_cnx_t* cnx_wake_first;
    struct st_picoquic_cnx_t* cnx_wake_last;

    picohash_table* table_cnx_by_id;
    picohash_table* table_cnx_by_net;

    cnx_id_cb_fn cnx_id_callback_fn;
    void* cnx_id_callback_ctx;

    void* aead_encrypt_ticket_ctx;
    void* aead_decrypt_ticket_ctx;

    picoquic_verify_certificate_cb_fn verify_certificate_callback_fn;
    picoquic_free_verify_certificate_ctx free_verify_certificate_callback_fn;
    void* verify_certificate_ctx;
    uint8_t local_ctx_length;

    /* Which was the socket used to receive the last packet? */
    SOCKET_TYPE rcv_socket;

    picoquic_tp_t * default_tp;

    picoquic_fuzz_fn fuzz_fn;
    void* fuzz_ctx;

    /* Queue of cached plugins */
    queue_t* cached_plugins_queue;
    /* Path to the plugin cache store */
    char* plugin_store_path;
    /* List of supported plugins in plugin cache store */
    plugin_list_t supported_plugins;
    /* List of plugins we want to inject both locally and remotely */
    plugin_list_t plugins_to_inject;
    /* List of local plugins to forcefully inject */
    plugin_list_t local_plugins;
} picoquic_quic_t;

picoquic_packet_context_enum picoquic_context_from_epoch(int epoch);

/*
 * Transport parameters, as defined by the QUIC transport specification
 */

typedef enum {
    picoquic_tp_original_connection_id = 0x00,
    picoquic_tp_max_idle_timeout = 0x01,
    picoquic_tp_stateless_reset_secret = 0x02,
    picoquic_tp_max_packet_size = 0x03,
    picoquic_tp_initial_max_data = 0x04,
    picoquic_tp_initial_max_stream_data_bidi_local = 0x05,
    picoquic_tp_initial_max_stream_data_bidi_remote = 0x06,
    picoquic_tp_initial_max_stream_data_uni = 0x07,
    picoquic_tp_initial_max_streams_bidi = 0x08,
    picoquic_tp_initial_max_streams_uni = 0x09,
    picoquic_tp_ack_delay_exponent = 0x0a,
    picoquic_tp_max_ack_delay = 0x0b,  // TODO draft-27
    picoquic_tp_disable_active_migration = 0x0c,
    picoquic_tp_preferred_address = 0x0d,
    picoquic_tp_active_connection_id_limit = 0x0e, // TODO draft-27
    picoquic_tp_supported_plugins = 0x20,
    picoquic_tp_plugins_to_inject = 0x21,
} picoquic_tp_enum;

typedef struct st_picoquic_tp_preferred_address_t {
    uint8_t ipv4_address[4];
    uint16_t ipv4_port;
    uint8_t ipv6_address[16];
    uint16_t ipv6_port;
    picoquic_connection_id_t connection_id;
    uint8_t stateless_reset_token[16];
} picoquic_tp_preferred_address_t;

typedef struct st_picoquic_tp_t {
    picoquic_connection_id_t original_connection_id;  // TODO use TP
    uint64_t max_idle_timeout;  // TODO use TP
    uint64_t max_packet_size;
    uint64_t initial_max_data;
    uint64_t initial_max_stream_data_bidi_local;
    uint64_t initial_max_stream_data_bidi_remote;
    uint64_t initial_max_stream_data_uni;
    uint64_t initial_max_streams_bidi;
    uint64_t initial_max_streams_uni;
    uint64_t ack_delay_exponent;
    uint64_t max_ack_delay;  // TODO use TP
    unsigned int disable_active_migration;
    picoquic_tp_preferred_address_t preferred_address;  // TODO use TP
    uint64_t active_connection_id_limit;
    char* supported_plugins;
    char* plugins_to_inject;
} picoquic_tp_t;

/*
 * SACK dashboard item, part of connection context.
 */

typedef struct st_picoquic_sack_item_t {
    struct st_picoquic_sack_item_t* next_sack;
    uint64_t start_of_sack_range;
    uint64_t end_of_sack_range;
} picoquic_sack_item_t;

/*
 * Stream head.
 * Stream contains bytes of data, which are not always delivered in order.
 * When in order data is available, the application can read it,
 * or a callback can be set.
 */

typedef struct _picoquic_stream_data {
    struct _picoquic_stream_data* next_stream_data;
    uint64_t offset;  /* Stream offset of the first octet in "bytes" */
    size_t length;    /* Number of octets in "bytes" */
    uint8_t* bytes;
} picoquic_stream_data;

typedef struct _picoquic_stream_head {
    struct _picoquic_stream_head* next_stream;
    uint64_t stream_id;
    uint64_t consumed_offset;
    uint64_t fin_offset;
    uint64_t maxdata_local;
    uint64_t maxdata_remote;
    uint64_t local_error;
    uint64_t remote_error;
    uint64_t local_stop_error;
    uint64_t remote_stop_error;
    picoquic_stream_data* stream_data;
    uint64_t sent_offset;
    uint64_t sending_offset;
    picoquic_stream_data* send_queue;
    picoquic_sack_item_t first_sack_item;
    /* Flags describing the state of the stream */
    unsigned int is_active : 1; /* The application is actively managing data sending through callbacks */
    unsigned int fin_requested : 1; /* Application has requested Fin of sending stream */
    unsigned int fin_sent : 1; /* Fin sent to peer */
    unsigned int fin_received : 1; /* Fin received from peer */
    unsigned int fin_signalled : 1; /* After Fin was received from peer, Fin was signalled to the application */
    unsigned int reset_requested : 1; /* Application has requested to reset the stream */
    unsigned int reset_sent : 1; /* Reset stream sent to peer */
    unsigned int reset_received : 1; /* Reset stream received from peer */
    unsigned int reset_signalled : 1; /* After Reset stream received from peer, application was notified */
    unsigned int stop_sending_requested : 1; /* Application has requested to stop sending */
    unsigned int stop_sending_sent : 1; /* Stop sending was sent to peer */
    unsigned int stop_sending_received : 1; /* Stop sending received from peer */
    unsigned int stop_sending_signalled : 1; /* After stop sending received from peer, application was notified */
    unsigned int max_stream_updated : 1; /* After stream was closed in both directions, the max stream id number was updated */
} picoquic_stream_head;

#define IS_CLIENT_STREAM_ID(id) (unsigned int)(((id) & 1) == 0)
#define IS_BIDIR_STREAM_ID(id)  (unsigned int)(((id) & 2) == 0)
#define IS_LOCAL_STREAM_ID(id, client_mode)  (unsigned int)(((id)^(client_mode)) & 1)
#define STREAM_ID_FROM_RANK(rank, is_server_stream, is_unidir) ((((uint64_t)(rank)-(uint64_t)1)<<2)|(((uint64_t)is_unidir)<<1)|((uint64_t)(is_server_stream)))

/* Per epoch crypto context. There are four such contexts:
 * 0: Initial context, with encryption based on a version dependent key,
 * 1: 0-RTT context
 * 2: Handshake context
 * 3: Application data
 */
typedef struct st_picoquic_crypto_context_t {
    void* aead_encrypt;
    void* aead_decrypt;
    void* hp_enc; /* Used for PN encryption */
    void* hp_dec; /* Used for PN decryption */
} picoquic_crypto_context_t;

/* Per epoch sequence/packet context.
 * There are three such contexts:
 * 0: Application (0-RTT and 1-RTT)
 * 1: Handshake
 * 2: Initial
 */

typedef struct st_picoquic_packet_context_t {
    uint64_t send_sequence;

    picoquic_sack_item_t first_sack_item;
    uint64_t time_stamp_largest_received;
    uint64_t highest_ack_sent;
    uint64_t highest_ack_time;
    uint64_t ack_delay_local;
    uint64_t latest_progress_time;

    uint64_t nb_retransmit;
    uint64_t latest_retransmit_time;
    uint64_t latest_retransmit_cc_notification_time;
    uint64_t highest_acknowledged;
    uint64_t latest_time_acknowledged; /* time at which the highest acknowledged was sent */
    picoquic_packet_t* retransmit_newest;
    picoquic_packet_t* retransmit_oldest;
    picoquic_packet_t* retransmitted_newest;
    picoquic_packet_t* retransmitted_oldest;

    unsigned int ack_needed : 1;
} picoquic_packet_context_t;

/*
* Per path context
*/
typedef struct st_picoquic_path_t {
    /* Peer address. To do: allow for multiple addresses */
    struct sockaddr_storage peer_addr;
    int peer_addr_len;
    struct sockaddr_storage local_addr;
    int local_addr_len;
    unsigned long if_index_local;

#define PICOQUIC_CHALLENGE_LENGTH 8
    /* Challenge used for this path */
    uint64_t challenge;
    uint64_t challenge_time;
    uint8_t challenge_response[PICOQUIC_CHALLENGE_LENGTH];
    uint8_t challenge_repeat_count;
#define PICOQUIC_CHALLENGE_REPEAT_MAX 4
    /* flags */
    unsigned int mtu_probe_sent : 1;
    unsigned int challenge_verified : 1;
    unsigned int challenge_response_to_send : 1;
    unsigned int ping_received : 1;
    unsigned int last_bw_estimate_path_limited : 1;

    /* Time measurement */
    uint64_t max_ack_delay;
    uint64_t rtt_sample;
    uint64_t smoothed_rtt;
    uint64_t rtt_variant;
    uint64_t retransmit_timer;
    uint64_t rtt_min;
    uint64_t max_spurious_rtt;
    uint64_t max_reorder_delay;
    uint64_t max_reorder_gap;

    /* MTU */
    uint32_t send_mtu;
    uint32_t send_mtu_max_tried;

    /* Congestion control state */
    uint64_t cwin;
    uint64_t bytes_in_transit;
    void* congestion_alg_state;

    /*
     * Pacing uses a set of per path variables:
     * - pacing_evaluation_time: last time the path was evaluated.
     * - pacing_bucket_nanosec: number of nanoseconds of transmission time that are allowed.
     * - pacing_bucket_max: maximum value (capacity) of the leaky bucket.
     * - pacing_packet_time_nanosec: number of nanoseconds required to send a full size packet.
     * - pacing_packet_time_microsec: max of (packet_time_nano_sec/1024, 1) microsec.
     */
    uint64_t pacing_evaluation_time;
    uint64_t pacing_bucket_nanosec;
    uint64_t pacing_bucket_max;
    uint64_t pacing_packet_time_nanosec;
    uint64_t pacing_packet_time_microsec;

    /* Statistics */
    uint64_t nb_pkt_sent;

    /* Bandwidth measurement */
    uint64_t delivered; /* The total amount of data delivered so far on the path */
    uint64_t delivered_last;
    uint64_t delivered_time_last;
    uint64_t delivered_sent_last;
    uint64_t delivered_limited_index;
    uint64_t delivered_last_packet;
    uint64_t bandwidth_estimate; /* In bytes per second */

    uint64_t received; /* Total amount of bytes received from the path */
    uint64_t receive_rate_epoch; /* Time of last receive rate measurement */
    uint64_t received_prior; /* Total amount received at start of epoch */
    uint64_t receive_rate_estimate; /* In bytes per second */
    uint64_t receive_rate_max; /* In bytes per second */

    /* QDC: Moved from the ctx */
    /* Connection IDs */
    picoquic_connection_id_t local_cnxid;
    picoquic_connection_id_t remote_cnxid;
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
    /* Sequence and retransmission state */
    picoquic_packet_context_t pkt_ctx[picoquic_nb_packet_context];

    plugin_struct_metadata_t *metadata;
} picoquic_path_t;

/* Typedef for plugins */

typedef char* plugin_id_t;

#define PLUGIN_MEMORY (16 * 1024 * 1024) /* In bytes, at least needed by tests */

typedef enum {
    plugin_memory_manager_fixed_blocks,
    plugin_memory_manager_dynamic,
} plugin_memory_manager_type_t;

typedef struct plugin_memory_manager {
    void *(*my_malloc)(protoop_plugin_t *p, unsigned int size);
    void (*my_free)(protoop_plugin_t *p, void *ptr);
    void *(*my_realloc)(protoop_plugin_t *p, void *ptr, unsigned int size);
    void *ctx;
} plugin_memory_manager_t;


typedef struct memory_pool {
    uint64_t num_of_blocks;
    uint64_t size_of_each_block;
    uint64_t num_free_blocks;
    uint64_t num_initialized;
    uint8_t *mem_start;
    uint8_t *next;
} memory_pool_t;

typedef struct plugin_parameters {
    // set to true when the frames generated by the plugin should be considered as "rate-unlimited"
    // the frames will be sent regardless of the fact that STREAM frames must be sent
    bool rate_unlimited;

    // determines the memory manager used for this plugin
    plugin_memory_manager_type_t plugin_memory_manager_type;
} plugin_parameters_t;

typedef struct protoop_plugin {
    UT_hash_handle hh; /* Make the structure hashable */
    char name[PROTOOPPLUGINNAME_MAX];
    queue_t *block_queue_cc; /* Send reservation queue for congestion controlled frames */
    queue_t *block_queue_non_cc; /* Send reservation queue for non-congestion controlled frames */
    uint64_t bytes_in_flight; /* Number of bytes in flight due to generated frames */
    uint64_t bytes_total; /* Number of total bytes by generated frames, for monitoring */
    uint64_t frames_total; /* Number of total generated frames, for monitoring */
    uint64_t hash;         /* Hash of the plugin name */
    plugin_parameters_t params;
    /* With uBPF, we don't want the VM it corrupts the memory of another context.
     * Therefore, each plugin has its own memory space that should contain everything
     * needed for the given connection.
     */
    plugin_memory_manager_t memory_manager;
    char memory[PLUGIN_MEMORY]; /* Memory that can be used for malloc, free,... */
} protoop_plugin_t;

#define PROTOOPNAME_MAX 100
#define STRUCT_METADATA_MAX 10

typedef protoop_arg_t (*protocol_operation)(picoquic_cnx_t *);

typedef struct observer_node {
    pluglet_t *observer; /* An observer, either pre or post */
    struct observer_node *next;
} observer_node_t;

typedef struct {
    param_id_t param; /* Key of the parameter. If its value is -1, it has no parameter */
    protocol_operation core; /* The default operation, kept for unplugging feature */
    pluglet_t *replace; /* Exclusive pluglet replacing the code operation */
    bool intern;  /* intern operations can only be called by pluglets and have observers,
                   * extern operations can only be called by the application and have no observers */
    bool running; /* Indicates if the protocol operation is in the current call stack or not.
                   * Efficient way to figure out if there are loops in protocol operation calls */
    observer_node_t *pre; /* List of observers, probing just before function invocation */
    observer_node_t *post; /* List of observers, probing just after function returns */
    UT_hash_handle hh; /* Make the structure hashable */
} protocol_operation_param_struct_t;

protocol_operation_param_struct_t *create_protocol_operation_param(param_id_t param, protocol_operation op);

typedef struct st_protocol_operation_struct_t {
    protoop_id_t pid; /* Key, the hash is the primary one */
    char name[PROTOOPNAME_MAX];
    bool is_parametrable;
    /* This pointer is special. Depending on the value of is_parametrable, it is
     * either directly the protocol_operation_param_struct_t, or an hash map containing
     * such elements
     */
    protocol_operation_param_struct_t *params; /* This is a hash map */
    UT_hash_handle hh; /* Make the structure hashable */
} protocol_operation_struct_t;

typedef struct st_plugin_struct_metadata {
    uint64_t plugin_hash;   /* primary key (we will store the plugin hash inside, so we assume it won't collide) */
    uint64_t metadata[STRUCT_METADATA_MAX];

    UT_hash_handle hh; /* Make the structure hashable */
} plugin_struct_metadata_t;

/* Register functions */
int register_noparam_protoop(picoquic_cnx_t* cnx, protoop_id_t *pid, protocol_operation op);
int register_param_protoop(picoquic_cnx_t* cnx, protoop_id_t *pid, param_id_t param, protocol_operation op);
int register_param_protoop_default(picoquic_cnx_t* cnx, protoop_id_t *pid, protocol_operation op);
void register_protocol_operations(picoquic_cnx_t *cnx);

void packet_register_noparam_protoops(picoquic_cnx_t *cnx);
void frames_register_noparam_protoops(picoquic_cnx_t *cnx);
void sender_register_noparam_protoops(picoquic_cnx_t *cnx);
void quicctx_register_noparam_protoops(picoquic_cnx_t *cnx);

#define CONTEXT_MEMORY (2 * 1024 * 1024) /* In bytes, at least needed by tests */

#define MAX_PLUGIN_DATA_LEN (1024 * 1000) /* In bytes */

/*
 * Per connection context.
 * This is the structure that will be passed to pluglets.
 */
typedef struct st_picoquic_cnx_t {
    picoquic_quic_t* quic;

    /* Management of context retrieval tables */
    struct st_picoquic_cnx_t* next_in_table;
    struct st_picoquic_cnx_t* previous_in_table;
    struct st_picoquic_cnx_id_t* first_cnx_id;
    struct st_picoquic_net_id_t* first_net_id;

    /* Proposed and negotiated version. Feature flags denote version dependent features */
    uint32_t proposed_version;
    int version_index;

    /* Series of flags showing the state or choices of the connection */
    unsigned int is_0RTT_accepted : 1; /* whether 0-RTT is accepted */
    unsigned int remote_parameters_received : 1; /* whether remote parameters where received */
    unsigned int current_spin : 1; /* Current value of the spin bit */
    unsigned int client_mode : 1; /* Is this connection the client side? */
    unsigned int prev_spin : 1;  /* previous Spin bit */
    unsigned int spin_vec : 2;   /* Valid Edge Counter, makes spin bit RTT measurements more reliable */
    unsigned int spin_edge : 1;  /* internal signalling from incoming to outgoing: we just spinned it */
    uint64_t spin_last_trigger;  /* timestamp of the incoming packet that triggered the spinning */
    unsigned int key_phase_enc : 1; /* Key phase used in outgoing packets */
    unsigned int key_phase_dec : 1; /* Key phase expected in incoming packets */
    unsigned int zero_rtt_data_accepted : 1; /* Peer confirmed acceptance of zero rtt data */
    unsigned int one_rtt_data_acknowledged : 1; /* 1RTT data acknowledged by peer */
    unsigned int processed_transport_parameter: 1; /* Indicate if transport parameters are processed or not */


    /* Local and remote parameters */
    picoquic_tp_t local_parameters;
    picoquic_tp_t remote_parameters;
    /* On clients, document the SNI and ALPN expected from the server */
    /* TODO: there may be a need to propose multiple ALPN */
    char const* sni;
    char const* alpn;
    /* On clients, receives the maximum 0RTT size accepted by server */
    size_t max_early_data_size;
    /* Call back function and context */
    picoquic_stream_data_cb_fn callback_fn;
    void* callback_ctx;

    /* connection state, ID, etc. Todo: allow for multiple cnxid */
    picoquic_state_enum cnx_state;
    picoquic_connection_id_t initial_cnxid;
    uint64_t start_time;
    uint64_t application_error;
    uint64_t local_error;
    uint64_t remote_application_error;
    uint64_t remote_error;
    uint64_t offending_frame_type;
    uint32_t retry_token_length;
    uint8_t * retry_token;
    unsigned int handshake_done : 1;
    unsigned int handshake_done_sent : 1;
    unsigned int handshake_done_acked : 1;
    unsigned int ready_notified : 1;


    /* Next time sending data is expected */
    uint64_t next_wake_time;
    struct st_picoquic_cnx_t* next_by_wake_time;
    struct st_picoquic_cnx_t* previous_by_wake_time;

    /* TLS context, TLS Send Buffer, streams, epochs */
    void* tls_ctx;
    struct st_ptls_buffer_t* tls_sendbuf;
    uint16_t psk_cipher_suite_id;

    picoquic_stream_head tls_stream[PICOQUIC_NUMBER_OF_EPOCHS]; /* Separate input/output from each epoch */
    picoquic_crypto_context_t crypto_context[PICOQUIC_NUMBER_OF_EPOCHS]; /* Encryption and decryption objects */

    /* Liveness detection */
    uint64_t latest_progress_time; /* last local time at which the connection progressed */

    /* Statistics */
    uint64_t nb_bytes_queued;
    uint32_t nb_path_challenge_sent;
    uint32_t nb_path_response_received;
    uint32_t nb_zero_rtt_sent;
    uint32_t nb_zero_rtt_acked;
    uint64_t nb_retransmission_total;
    uint64_t nb_spurious;
    /* ECN Counters */
    uint64_t ecn_ect0_total_local;
    uint64_t ecn_ect1_total_local;
    uint64_t ecn_ce_total_local;
    uint64_t ecn_ect0_total_remote;
    uint64_t ecn_ect1_total_remote;
    uint64_t ecn_ce_total_remote;

    /* Congestion algorithm */
    picoquic_congestion_algorithm_t const* congestion_alg;

    /* Flow control information */
    uint64_t data_sent;
    uint64_t data_received;
    uint64_t maxdata_local;
    uint64_t maxdata_remote;
    uint64_t max_stream_id_bidir_local;
    uint64_t max_stream_id_bidir_local_computed;
    uint64_t max_stream_id_unidir_local;
    uint64_t max_stream_id_unidir_local_computed;
    uint64_t max_stream_id_bidir_remote;
    uint64_t max_stream_id_unidir_remote;

    /* Management of streams */
    picoquic_stream_head * first_stream;
    uint64_t last_visited_stream_id;
    uint64_t last_visited_plugin_stream_id;

    /* If not `0`, the connection will send keep alive messages in the given interval. */
    uint64_t keep_alive_interval;

    /* Management of paths */
    picoquic_path_t ** path;
    int nb_paths;
    int nb_path_alloc;

    /* Management of pending frames to be sent due to reservations */
    queue_t *reserved_frames;
    /* Queue of frames to retry sending */
    queue_t *retry_frames;
    /* Queues of frames to be retransmitted */
    queue_t *rtx_frames[picoquic_nb_packet_context];
    /* Keep a pointer to the next plugin to look at first */
    protoop_plugin_t *first_drr;
    /* Core guaranteed rate (fraction over 1000) */
    uint16_t core_rate;
    /* Should we wake directly the stack due to a reserved frame? */
    uint8_t wake_now:1;
    uint8_t plugin_requested:1;

    /* List of plugins that should be requested on this connection */
    plugin_request_t pids_to_request;

    /* Management of plugin streams */
    picoquic_stream_head * first_plugin_stream;

    /* Management of default protocol operations and plugins */
    protocol_operation_struct_t *ops;

    protoop_plugin_t *plugins;

    plugin_struct_metadata_t *metadata;

    /* Due to uBPF constraints, all needed info must be contained in the context.
     * Furthermore, the arguments might have different types...
     * Fortunately, if arguments are either integers or pointers, this is simple.
     */
    int protoop_inputc;
    protoop_arg_t protoop_inputv[PROTOOPARGS_MAX];
    protoop_arg_t protoop_outputv[PROTOOPARGS_MAX];

    int protoop_outputc_callee; /* Modified by the callee */
    protoop_arg_t protoop_output; /* Only available for post calls */

    protocol_operation_struct_t *current_protoop; /* This should not be modified by the plugins... */
    pluglet_type_enum current_anchor;
    protoop_plugin_t *current_plugin; /* This should not be modified by the plugins... */
    protoop_plugin_t *previous_plugin_in_replace; /* To free memory, we might be interested to know if it is in plugin or core memory */;
} picoquic_cnx_t;

/* Init of transport parameters */
int picoquic_set_default_tp(picoquic_quic_t* quic, picoquic_tp_t * tp);
void picoquic_init_transport_parameters(picoquic_tp_t* tp, int client_mode);

/* Helper macros */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)

/* C99-style: anonymous argument referenced by __VA_ARGS__, empty arg not OK */

# define N_ARGS(...) N_ARGS_HELPER1(__VA_ARGS__, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
# define N_ARGS_HELPER1(...) N_ARGS_HELPER2(__VA_ARGS__)
# define N_ARGS_HELPER2(x1, x2, x3, x4, x5, x6, x7, x8, x9, n, ...) n

# define protoop_prepare_and_run_noparam(cnx, pid, outputv, ...) protoop_prepare_and_run_helper(cnx, pid, NO_PARAM, true, outputv, N_ARGS(__VA_ARGS__), __VA_ARGS__)
# define protoop_prepare_and_run_param(cnx, pid, param, outputv, ...) protoop_prepare_and_run_helper(cnx, pid, param, true, outputv, N_ARGS(__VA_ARGS__), __VA_ARGS__)
# define protoop_prepare_and_run_extern_noparam(cnx, pid, outputv, ...) protoop_prepare_and_run_helper(cnx, pid, NO_PARAM, false, outputv, N_ARGS(__VA_ARGS__), __VA_ARGS__)
# define protoop_prepare_and_run_extern_param(cnx, pid, param, outputv, ...) protoop_prepare_and_run_helper(cnx, pid, param, false, outputv, N_ARGS(__VA_ARGS__), __VA_ARGS__)
# define protoop_save_outputs(cnx, ...) protoop_save_outputs_helper(cnx, N_ARGS(__VA_ARGS__), __VA_ARGS__)

#ifndef LOG
#ifndef DISABLE_QLOG
#define LOG
#else
#define LOG if (0)
#endif
#endif

#ifndef LOG_EVENT
#ifndef DISABLE_QLOG
#define LOG_EVENT(cnx, cat, ev_type, trig, data_fmt, ...)                                                                                                                    \
    do {                                                                                                                                                                     \
        char ___data[1024];                                                                                                                                                  \
        snprintf(___data, 1024, data_fmt, __VA_ARGS__);                                                                                                                      \
        protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_LOG_EVENT, NULL, (protoop_arg_t) cat, (protoop_arg_t) ev_type, (protoop_arg_t) trig, (protoop_arg_t) NULL, (protoop_arg_t) ___data); \
    } while (0)
#else
#define LOG_EVENT(cnx, cat, ev_type, trig, data_fmt, ...)
#endif
#endif

#ifndef PUSH_LOG_CTX
#ifndef DISABLE_QLOG
#define PUSH_LOG_CTX(cnx, ctx_fmt, ...) \
    do {                                                                                                                                                                     \
        char ___data[1024];                                                                                                                                                  \
        snprintf(___data, 1024, ctx_fmt, __VA_ARGS__);                                                                                                                      \
        protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_PUSH_LOG_CONTEXT, NULL, (protoop_arg_t) ___data); \
    } while (0)
#else
#define PUSH_LOG_CTX(cnx, ctx_fmt, ...)
#endif
#endif

#ifndef POP_LOG_CTX
#ifndef DISABLE_QLOG
#define POP_LOG_CTX(cnx)    protoop_prepare_and_run_noparam(cnx, &PROTOOP_NOPARAM_POP_LOG_CONTEXT, NULL, NULL)
#else
#define POP_LOG_CTX(cnx)
#endif
#endif

#elif defined(__GNUC__)

/* GCC-style: named argument, empty arg is OK */

# define N_ARGS(args...) N_ARGS_HELPER1(args, 9, 8, 7, 6, 5, 4, 3, 2, 1)
# define N_ARGS_HELPER1(args...) N_ARGS_HELPER2(args)
# define N_ARGS_HELPER2(x1, x2, x3, x4, x5, x6, x7, x8, x9, n, x...) n


# define protoop_prepare_and_run_noparam(cnx, pid, outputv, ...) protoop_prepare_and_run_noparam_helper(cnx, pid, NO_PARAM, outputv, N_ARGS(args), args)
# define protoop_prepare_and_run_param(cnx, pid, param, outputv, ...) protoop_prepare_and_run_noparam_helper(cnx, pid, param, outputv, N_ARGS(args), args)
# define protoop_save_outputs(cnx, ...) protoop_save_outputs_helper(cnx, N_ARGS(args), args)

#else

#error variadic macros for your compiler here

#endif

static inline protoop_arg_t protoop_prepare_and_run_helper(picoquic_cnx_t *cnx, protoop_id_t *pid, param_id_t param, bool caller, protoop_arg_t *outputv, unsigned int n_args, ...)
{
  int i;
  va_list ap;

  va_start(ap, n_args);
  protoop_arg_t args[n_args];
  DBG_PLUGIN_PRINTF("%u argument(s):", n_args);
  for (i = 0; i < n_args; i++) {
    args[i] = va_arg(ap, protoop_arg_t);
    DBG_PLUGIN_PRINTF("  %" PRIu64, args[i]);
  }
  va_end(ap);
  protoop_params_t pp = { .pid = pid, .param = param, .inputc = n_args, .inputv = args, .outputv = outputv, .caller_is_intern = caller };
  return plugin_run_protoop_internal(cnx, &pp);
}

static inline void protoop_save_outputs_helper(picoquic_cnx_t *cnx, unsigned int n_args, ...)
{
  int i;
  va_list ap;

  va_start(ap, n_args);
  DBG_PLUGIN_PRINTF("%u saved:", n_args);
  for (i = 0; i < n_args; i++) {
    cnx->protoop_outputv[i] = va_arg(ap, protoop_arg_t);
    DBG_PLUGIN_PRINTF("  %" PRIu64, cnx->protoop_outputv[i]);
  }
  cnx->protoop_outputc_callee = n_args;
  va_end(ap);
}

/* End of plugins helper functions */

/* Init of transport parameters */
void picoquic_init_transport_parameters(picoquic_tp_t* tp, int client_mode);

/* Handling of stateless packets */
picoquic_stateless_packet_t* picoquic_create_stateless_packet(picoquic_quic_t* quic);
void picoquic_queue_stateless_packet(picoquic_quic_t* quic, picoquic_stateless_packet_t* sp);

/* Registration of connection ID in server context */
int picoquic_register_cnx_id(picoquic_quic_t* quic, picoquic_cnx_t* cnx, const picoquic_connection_id_t* cnx_id);
int picoquic_register_cnx_id_for_cnx(picoquic_cnx_t* cnx, const picoquic_connection_id_t* cnx_id);

/* handling of retransmission queue */
void picoquic_dequeue_retransmit_packet(picoquic_cnx_t* cnx, picoquic_packet_t* p, int should_free);
void picoquic_dequeue_retransmitted_packet(picoquic_cnx_t* cnx, picoquic_packet_t* p);
void picoquic_implicit_handshake_ack(picoquic_cnx_t* cnx, picoquic_path_t *path, picoquic_packet_context_enum pc, uint64_t current_time);

/* Reset connection after receiving version negotiation */
int picoquic_reset_cnx_version(picoquic_cnx_t* cnx, uint8_t* bytes, size_t length, uint64_t current_time);

/* Reset the connection context, e.g. after retry */
int picoquic_reset_cnx(picoquic_cnx_t* cnx, uint64_t current_time);

/* Reset packet context */
void picoquic_reset_packet_context(picoquic_cnx_t* cnx,
    picoquic_packet_context_enum pc, picoquic_path_t* path_x);

/* Notify error on connection */
int picoquic_connection_error(picoquic_cnx_t* cnx, uint64_t local_error, uint64_t frame_type);

/* Set the transport parameters */
void picoquic_set_transport_parameters(picoquic_cnx_t * cnx, picoquic_tp_t * tp);

/* Connection context retrieval functions */
picoquic_cnx_t* picoquic_cnx_by_id(picoquic_quic_t* quic, picoquic_connection_id_t cnx_id);
picoquic_cnx_t* picoquic_cnx_by_net(picoquic_quic_t* quic, struct sockaddr* addr);

/* Next time is used to order the list of available connections,
     * so ready connections are polled first */
void picoquic_reinsert_by_wake_time(picoquic_quic_t* quic, picoquic_cnx_t* cnx, uint64_t next_time);

void picoquic_cnx_set_next_wake_time(picoquic_cnx_t* cnx, uint64_t current_time, uint32_t last_pkt_length);

void picoquic_create_random_cnx_id(picoquic_quic_t* quic, picoquic_connection_id_t * cnx_id, uint8_t id_length);
void picoquic_create_random_cnx_id_for_cnx(picoquic_cnx_t* cnx, picoquic_connection_id_t *cnx_id, uint8_t id_length);

/* Integer parsing macros */
#define PICOPARSE_16(b) ((((uint16_t)(b)[0]) << 8) | (b)[1])
#define PICOPARSE_24(b) ((((uint32_t)PICOPARSE_16(b)) << 16) | ((b)[2]))
#define PICOPARSE_32(b) ((((uint32_t)PICOPARSE_16(b)) << 16) | PICOPARSE_16((b) + 2))
#define PICOPARSE_64(b) ((((uint64_t)PICOPARSE_32(b)) << 32) | PICOPARSE_32((b) + 4))

/* Integer formatting functions */
void picoformat_16(uint8_t* bytes, uint16_t n16);
void picoformat_32(uint8_t* bytes, uint32_t n32);
void picoformat_64(uint8_t* bytes, uint64_t n64);

void picoquic_varint_encode_16(uint8_t* bytes, uint16_t n16);
size_t picoquic_varint_len(uint64_t val);


/* utilities */
char* picoquic_string_create(const char* original, size_t len);
char* picoquic_string_duplicate(const char* original);

/* Packet parsing */

typedef struct _picoquic_packet_header {
    picoquic_connection_id_t dest_cnx_id;
    picoquic_connection_id_t srce_cnx_id;
    uint32_t pn;
    uint32_t vn;
    uint32_t offset;
    uint32_t pn_offset;
    picoquic_packet_type_enum ptype;
    uint64_t pnmask;
    uint64_t pn64;
    uint16_t payload_length;
    int version_index;
    int epoch;
    picoquic_packet_context_enum pc;
    unsigned int spin : 1;
    unsigned int spin_vec : 2;
    unsigned int has_spin_bit : 1;
    uint32_t token_length;
    uint32_t token_offset;
} picoquic_packet_header;

int picoquic_parse_packet_header(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    uint32_t length,
    struct sockaddr* addr_from,
    picoquic_packet_header* ph,
    picoquic_cnx_t** pcnx,
    int receiving);

picoquic_path_t *picoquic_get_incoming_path(
    picoquic_cnx_t* cnx,
    picoquic_packet_header* ph);

uint32_t picoquic_create_packet_header(
    picoquic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type,
    picoquic_path_t* path_x,
    uint64_t sequence_number,
    uint8_t* bytes,
    uint32_t * pn_offset,
    uint32_t * pn_length);

uint32_t  picoquic_predict_packet_header_length(
    picoquic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type,
    picoquic_path_t* path_x);

void picoquic_update_payload_length(
    uint8_t* bytes, size_t pnum_index, size_t header_length, size_t packet_length);

uint32_t picoquic_get_checksum_length(picoquic_cnx_t* cnx, int is_cleartext_mode);

int picoquic_is_stream_frame_unlimited(const uint8_t* bytes);
int picoquic_check_stream_frame_already_acked(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max, int* no_need_to_repeat);

int picoquic_parse_stream_header(
    const uint8_t* bytes, size_t bytes_max,
    uint64_t* stream_id, uint64_t* offset, size_t* data_length, int* fin,
    size_t* consumed);

int picoquic_parse_ack_header(
    uint8_t const* bytes, size_t bytes_max,
    uint64_t* num_block, uint64_t* nb_ecnx3, uint64_t* largest,
    uint64_t* ack_delay, size_t* consumed,
    uint8_t ack_delay_exponent);

uint64_t picoquic_get_packet_number64(uint64_t highest, uint64_t mask, uint32_t pn);

size_t  picoquic_decrypt_packet(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t packet_length, picoquic_packet_header* ph,
    void * hp_enc, void* aead_context, int * already_received,
    picoquic_path_t* path_from);

uint32_t picoquic_protect_packet(picoquic_cnx_t* cnx,
    picoquic_packet_type_enum ptype,
    uint8_t * bytes,
    picoquic_path_t* path_x,
    uint64_t sequence_number,
    uint32_t length, uint32_t header_length,
    uint8_t* send_buffer, uint32_t send_buffer_max,
    picoquic_packet_header *ph,
    void * aead_context, void* pn_enc);

void picoquic_finalize_and_protect_packet(picoquic_cnx_t *cnx, picoquic_packet_t * packet, int ret,
    uint32_t length, uint32_t header_length, uint32_t checksum_overhead,
    size_t * send_length, uint8_t * send_buffer, uint32_t send_buffer_max,
    picoquic_path_t * path_x, uint64_t current_time);

int picoquic_parse_header_and_decrypt(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    uint32_t length,
    uint32_t packet_length,
    struct sockaddr* addr_from,
    uint64_t current_time,
    picoquic_packet_header* ph,
    picoquic_cnx_t** pcnx,
    uint32_t * consumed,
    int * new_context_created);

/* Handling of packet logging */
void picoquic_log_decrypted_segment(void* F_log, int log_cnxid, picoquic_cnx_t* cnx,
    int receiving, picoquic_packet_header * ph, uint8_t* bytes, size_t length, int ret);

void picoquic_log_outgoing_segment(void* F_log, int log_cnxid, picoquic_cnx_t* cnx,
    uint8_t * bytes,
    uint64_t sequence_number,
    uint32_t length,
    uint8_t* send_buffer, uint32_t send_length);

void picoquic_log_packet_address(FILE* F, uint64_t log_cnxid64, picoquic_cnx_t* cnx,
    struct sockaddr* addr_peer, int receiving, size_t length, uint64_t current_time);

void picoquic_log_transport_extension(FILE* F, picoquic_cnx_t* cnx, int log_cnxid);

void picoquic_log_error_packet(FILE* F, uint8_t* bytes, size_t bytes_max, int ret);
void picoquic_log_processing(FILE* F, picoquic_cnx_t* cnx, size_t length, int ret);
void picoquic_log_transport_extension(FILE* F, picoquic_cnx_t* cnx, int log_cnxid);
void picoquic_log_congestion_state(FILE* F, picoquic_cnx_t* cnx, uint64_t current_time);
void picoquic_log_picotls_ticket(FILE* F, picoquic_connection_id_t cnx_id,
    uint8_t* ticket, uint16_t ticket_length);
const char * picoquic_log_fin_or_event_name(picoquic_call_back_event_t ev);
void picoquic_log_time(FILE* F, picoquic_cnx_t* cnx, uint64_t current_time,
    const char* label1, const char* label2);
char const* picoquic_log_state_name(picoquic_state_enum state);

#define PICOQUIC_SET_LOG(quic, F) (quic)->F_log = (void*)(F)

#define PICOQUIC_SET_TLS_SECRETS_LOG(quic, F) (quic)->F_tls_secrets = (void*)(F)

/* handling of ACK logic */
int picoquic_is_ack_needed(picoquic_cnx_t* cnx, uint64_t current_time, picoquic_packet_context_enum pc,
    picoquic_path_t* path_x);

int picoquic_is_pn_already_received(picoquic_path_t* path_x,
    picoquic_packet_context_enum pc, uint64_t pn64);
int picoquic_record_pn_received(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_packet_context_enum pc, uint64_t pn64, uint64_t current_microsec);
uint16_t picoquic_deltat_to_float16(uint64_t delta_t);
uint64_t picoquic_float16_to_deltat(uint16_t float16);

int picoquic_update_sack_list(picoquic_cnx_t* cnx, picoquic_sack_item_t* sack,
    uint64_t pn64_min, uint64_t pn64_max);
/*
     * Check whether the data fills a hole. returns 0 if it does, -1 otherwise.
     */
int picoquic_check_sack_list(picoquic_sack_item_t* sack,
    uint64_t pn64_min, uint64_t pn64_max);

/*
     * Process ack of ack
     */
int picoquic_process_ack_of_ack_frame(
    picoquic_cnx_t* cnx,
    picoquic_sack_item_t* first_sack,
    uint8_t* bytes, size_t bytes_max, size_t* consumed, int is_ecn);

/* stream management */
picoquic_stream_head* picoquic_create_stream(picoquic_cnx_t* cnx, uint64_t stream_id);
void picoquic_update_stream_initial_remote(picoquic_cnx_t* cnx);
picoquic_stream_head* picoquic_find_ready_stream(picoquic_cnx_t* cnx);
picoquic_stream_head* picoquic_schedule_next_stream(picoquic_cnx_t* cnx, size_t max_size, picoquic_path_t *path);
int picoquic_is_tls_stream_ready(picoquic_cnx_t* cnx);
uint8_t* picoquic_decode_stream_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max, uint64_t current_time, picoquic_path_t* path_x);
int picoquic_prepare_stream_frame(picoquic_cnx_t* cnx, picoquic_stream_head* stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
size_t picoquic_stream_bytes_max(picoquic_cnx_t* cnx, size_t bytes_max, size_t header_length, uint8_t* bytes);
bool picoquic_stream_always_encode_length(picoquic_cnx_t* cnx);
uint8_t* picoquic_decode_crypto_hs_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    const uint8_t* bytes_max, int epoch);
int picoquic_prepare_crypto_hs_frame(picoquic_cnx_t* cnx, int epoch,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
int picoquic_prepare_handshake_done_frame(picoquic_cnx_t *cnx, uint8_t* bytes, size_t bytes_max, size_t* consumed);
int picoquic_prepare_ack_frame(picoquic_cnx_t* cnx, uint64_t current_time,
    picoquic_packet_context_enum pc,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
int picoquic_prepare_connection_close_frame(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
int picoquic_prepare_application_close_frame(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
int picoquic_prepare_required_max_stream_data_frames(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
int picoquic_prepare_max_data_frame(picoquic_cnx_t* cnx, uint64_t maxdata_increase,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
void picoquic_update_max_stream_ID_local(picoquic_cnx_t* cnx, picoquic_stream_head* stream);
int picoquic_prepare_max_stream_ID_frame_if_needed(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
void picoquic_clear_stream(picoquic_stream_head* stream);
int picoquic_prepare_path_challenge_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max, size_t* consumed, picoquic_path_t * path);

int picoquic_write_plugin_validate_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max,
                                         uint64_t pid_id, char* pid, size_t* consumed, int* is_retransmittable);

/* plugin stream management */
picoquic_stream_head* picoquic_create_plugin_stream(picoquic_cnx_t* cnx, uint64_t pid_id);
picoquic_stream_head* picoquic_find_ready_plugin_stream(picoquic_cnx_t* cnx);
int picoquic_prepare_plugin_frame(picoquic_cnx_t* cnx, picoquic_stream_head* plugin_stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);


/* send/receive */

int picoquic_decode_frames(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max_size, int epoch, uint64_t current_time, picoquic_path_t* path_x);

int picoquic_skip_frame(picoquic_cnx_t *cnx, uint8_t* bytes, size_t bytes_max_size, size_t* consumed, int* pure_ack);

int picoquic_decode_closing_frames(picoquic_cnx_t *cnx, uint8_t* bytes,
    size_t bytes_max, int* closing_received);

uint32_t picoquic_decode_transport_param_stream_id(uint16_t rank, int extension_mode, int stream_type);
uint16_t picoquic_prepare_transport_param_stream_id(uint32_t stream_id, int extension_mode, int stream_type);

int picoquic_prepare_transport_extensions(picoquic_cnx_t* cnx, int extension_mode,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);

int picoquic_receive_transport_extensions(picoquic_cnx_t* cnx, int extension_mode,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);

/* Hooks for reception and sending of packets */
void picoquic_received_packet(picoquic_cnx_t *cnx, SOCKET_TYPE socket);
void picoquic_before_sending_packet(picoquic_cnx_t *cnx, SOCKET_TYPE socket);
void picoquic_received_segment(picoquic_cnx_t *cnx);
void picoquic_segment_prepared(picoquic_cnx_t *cnx, picoquic_packet_t *pkt);
void picoquic_segment_aborted(picoquic_cnx_t *cnx);
/* Hooks for reception and sending of QUIC packets before encryption */  // TODO: Maybe the two above and below should be merged
void picoquic_header_parsed(picoquic_cnx_t *cnx, picoquic_packet_header *ph, picoquic_path_t *path, size_t length);
void picoquic_header_prepared(picoquic_cnx_t *cnx, picoquic_packet_header *ph, picoquic_path_t *path, picoquic_packet_t *packet, size_t length);

/* Queue stateless reset */
void picoquic_queue_stateless_reset(picoquic_cnx_t* cnx,
    picoquic_packet_header* ph, struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    unsigned long if_index_to,
    uint64_t current_time);

protoop_arg_t protoop_noop(picoquic_cnx_t *cnx);
protoop_arg_t protoop_true(picoquic_cnx_t *cnx);
protoop_arg_t protoop_false(picoquic_cnx_t *cnx);

#define STREAM_RESET_SENT(stream) (stream->reset_sent)
#define STREAM_RESET_REQUESTED(stream) (stream->reset_requested)
#define STREAM_RESET_RCVD(stream) (stream->reset_received)
#define STREAM_SEND_RESET(stream) (STREAM_RESET_REQUESTED(stream) && !STREAM_RESET_SENT(stream))
#define STREAM_STOP_SENDING_REQUESTED(stream) (stream->stop_sending_requested)
#define STREAM_STOP_SENDING_SENT(stream) (stream->stop_sending_sent)
#define STREAM_STOP_SENDING_RECEIVED(stream) (stream->stop_sending_received)
#define STREAM_SEND_STOP_SENDING(stream) (STREAM_STOP_SENDING_REQUESTED(stream) && !STREAM_STOP_SENDING_SENT(stream))
#define STREAM_FIN_REQUESTED(stream) (stream->fin_requested)
#define STREAM_FIN_SENT(stream) (stream->fin_sent)
#define STREAM_FIN_RCVD(stream) (stream->fin_received)
#define STREAM_SEND_FIN(stream) (STREAM_FIN_REQUESTED(stream) && !STREAM_FIN_SENT(stream))
#define STREAM_CLOSED(stream) ((STREAM_FIN_SENT(stream) || STREAM_RESET_RCVD(stream)) && (STREAM_RESET_SENT(stream) || STREAM_FIN_RCVD(stream)))

#ifdef __cplusplus
}
#endif
#endif /* PICOQUIC_INTERNAL_H */
