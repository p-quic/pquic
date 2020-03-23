/**
 * \file getset.h
 * \brief Here are the fields accessible to plugins.
 */

#ifndef GETSET_H
#define GETSET_H

#include "picoquic.h"

typedef uint16_t access_key_t;

/**
 * @defgroup GETSET_FUNCTIONS Get/Set Functions
 * 
 * @{
 */

/**
 * Get a specific field belonging to the connection context \p cnx
 *
 * \param cnx The connection context
 * \param ak The key of the field to get
 * \param param A parameter for the key. Its meaning depends on the accessed field
 * 
 * \return The value of the field with the corresponding key
 */
protoop_arg_t get_cnx(picoquic_cnx_t *cnx, access_key_t ak, uint16_t param);

/**
 * Set a specific field belonging to the connection context \p cnx to the value \p val
 *
 * \param cnx The connection context
 * \param ak The key of the field to set
 * \param param A parameter for the key. Its meaning depends on the accessed field
 * \param val The value to set
 */
void set_cnx(picoquic_cnx_t *cnx, access_key_t ak, uint16_t param, protoop_arg_t val);

/**
 * Set the plugin-specific metadata of this connection context \p cnx at index \p idx` to \p val
 *
 * \param cnx The connection pointer
 * \param idx The index of the plugin-specific metadata
 * \param val The value of the metadata to set
 */
void set_cnx_metadata(picoquic_cnx_t *cnx, int idx, protoop_arg_t val);

/**
 * Get and return the value of the plugin-specific metadata of this connection context
 * \p cnx at index \p idx
 * If the metadata have never been set before, zero is returned
 * 
 * \param cnx The connection pointer
 * \param idx The index of the plugin-specific metadata to get
 *
 * \return \p protoop_arg_t The value of the plugin metadata, zero is never set before
 */
protoop_arg_t get_cnx_metadata(picoquic_cnx_t *cnx, int idx);

/**
 * Get a specific field belonging to the path \p path
 * 
 * \param path The path structure pointer
 * \param ak The key of the field to get
 * \param param A parameter for the key. Its meaning depends on the accessed field
 * 
 * \return The value of the field with the corresponding key
 */
protoop_arg_t get_path(picoquic_path_t *path, access_key_t ak, uint16_t param);

/**
 * Set a specific field belonging to the path context \p path to the value \p val
 *
 * \param path The path structure pointer
 * \param ak The key of the field to set
 * \param param A parameter for the key. Its meaning depends on the accessed field
 * \param val The value to set
 */
void set_path(picoquic_path_t *path, access_key_t ak, uint16_t param, protoop_arg_t val);

/**
 * Set the plugin-specific metadata of this path at index \p idx to \p val
 * 
 * \param cnx The connection pointer
 * \param path The path pointer
 * \param idx The index of the plugin-specific metadata
 * \param val The value of the metadata to set
 */
void set_path_metadata(picoquic_cnx_t *cnx, picoquic_path_t *path, int idx, protoop_arg_t val);

/**
 * Get and return the value of the plugin-specific metadata of this path at index \p idx
 * If the metadata have never been set before, zero is returned
 * 
 * \param cnx The connection pointer
 * \param path The path pointer
 * \param idx The index of the plugin-specific metadata to get
 *
 */
protoop_arg_t get_path_metadata(picoquic_cnx_t *cnx, picoquic_path_t *path, int idx);

/**
 * Get a specific field beloging to the packet context \p pkt_ctx
 * 
 * \param pkt_ctx The packet context pointer
 * \param ak The key of the field to get
 * 
 * \return The value of the field with the corresponding key
 */
protoop_arg_t get_pkt_ctx(picoquic_packet_context_t *pkt_ctx, access_key_t ak);

/**
 * Set a specific field belonging to the packet context \p pkt_ctx to the value \p val
 * 
 * \param pkt_ctx The packet context pointer
 * \param ak The key of the field to get
 * \param val The value to set
 */
void set_pkt_ctx(picoquic_packet_context_t *pkt_ctx, access_key_t ak, protoop_arg_t val);

/**
 * Get a specific field belonging to the packet \p pkt
 * 
 * \param pkt The packet pointer
 * \param ak The key of the field to get
 * 
 * \return The value of the field with the corresponding key
 */
protoop_arg_t get_pkt(picoquic_packet_t *pkt, access_key_t ak);

/**
 * Set a specific field belonging to the packet \p pkt to the value \p val
 * 
 * \param pkt The packet pointer
 * \param ak The key of the field to get
 * \param val The value to set
 */
void set_pkt(picoquic_packet_t *pkt, access_key_t ak, protoop_arg_t val);

/**
 * Sets the plugin-specific metadata of this packet at index `idx` to `val`
 * @param cnx The connection pointer
 * @param pkt The packet pointer
 * @param idx The index of the plugin-specific metadata
 * @param val The value of the metadata to set
 */
void set_pkt_metadata(picoquic_cnx_t *cnx, picoquic_packet_t *pkt, int idx, protoop_arg_t val);


/**
 * Gets and returns the value of the plugin-specific metadata of this packet at index `idx`
 * If the metadata have never been set before, zero is returned
 * @param cnx The connection pointer
 * @param pkt The packet pointer
 * @param idx The index of the plugin-specific metadata to get
 *
 */
protoop_arg_t get_pkt_metadata(picoquic_cnx_t *cnx, picoquic_packet_t *pkt, int idx);

/**
 * Get a specific field belonging to the sack item \p sack_item
 * 
 * \param sack_item The sack_item pointer
 * \param ak The key of the field to get
 * 
 * \return The value of the field with the corresponding key
 */
protoop_arg_t get_sack_item(picoquic_sack_item_t *sack_item, access_key_t ak);

/**
 * Set a specific field belonging to the sack item \p sack_item to the value \p val
 * 
 * \param sack_item The sack_item pointer
 * \param ak The key of the field to get
 * \param val The value to set
 */
void set_sack_item(picoquic_sack_item_t *sack_item, access_key_t ak, protoop_arg_t val);

/**
 * Get a specific field belonging to the connection id \p cnxid
 * 
 * \param cnxid The connection id pointer
 * \param ak The key of the field to get
 * 
 * \return The value of the field with the corresponding key
 */
protoop_arg_t get_cnxid(picoquic_connection_id_t *cnxid, access_key_t ak);

/**
 * Set a specific field belonging to the connection id \p cnxid to the value \p val
 * 
 * \param cnxid The connection id pointer
 * \param ak The key of the field to get
 * \param val The value to set
 */
void set_cnxid(picoquic_connection_id_t *cnxid, access_key_t ak, protoop_arg_t val);

/**
 * Get a specific field belonging to the stream_head \p stream_head
 * 
 * \param stream_head The stream head pointer
 * \param ak The key of the field to get
 * 
 * \return The value of the field with the corresponding key
 */
protoop_arg_t get_stream_head(picoquic_stream_head *stream_head, access_key_t ak);

/**
 * Set a specific field belonging to the stream_head \p stream_head to the value \p val
 * 
 * \param cnxid The stream head pointer
 * \param ak The key of the field to get
 * \param val The value to set
 */
void set_stream_head(picoquic_stream_head *stream_head, access_key_t ak, protoop_arg_t val);

/**
 * Get a specific field belonging to the stream_data \p stream_data
 *
 * \param stream_data The stream data pointer
 * \param ak The key of the field to get
 *
 * \return The value of the field with the corresponding key
 */
protoop_arg_t get_stream_data(picoquic_stream_data *stream_data, access_key_t ak);

/**
 * Get a specific field belonging to the crypto context \p crypto_context
 * 
 * \param crypto_context The crypto context pointer
 * \param ak The key of the field to get
 * 
 * \return The value of the field with the corresponding key
 */
protoop_arg_t get_crypto_context(picoquic_crypto_context_t *crypto_context, access_key_t ak);

/**
 * Set a specific field belonging to the crypto context \p crypto_context to the value \p val
 * 
 * \param cnxid The crypto context pointer
 * \param ak The key of the field to get
 * \param val The value to set
 */
void set_crypto_context(picoquic_crypto_context_t *crypto_context, access_key_t ak, protoop_arg_t val);

/**
 * Get a specific field belonging to the packet header \p ph
 * 
 * \param ph The packet header pointer
 * \param ak The key of the field to get
 * 
 * \return The value of the field with the corresponding key
 */
protoop_arg_t get_ph(picoquic_packet_header *ph, access_key_t ak);

/**
 * Set a specific field belonging to the packet header \p ph to the value \p val
 * 
 * \param cnxid The packet header pointer
 * \param ak The key of the field to get
 * \param val The value to set
 */
void set_ph(picoquic_packet_header *ph, access_key_t ak, protoop_arg_t val);

/**
 * Get a specific field belonging to the pid request \p preq
 * \warning This API is not stable, do not use it!
 * 
 * \param preq The pid request pointer
 * \param ak The key of the field to get
 * 
 * \return The value of the field with the corresponding key
 */
protoop_arg_t get_preq(plugin_req_pid_t *preq, access_key_t ak);

/**
 * Set a specific field belonging to the pid request \p preq to the value \p val
 * \warning This API is not stable, do not use it!
 * 
 * \param preq The pid request pointer
 * \param ak The key of the field to get
 * \param val The value to set
 */
void set_preq(plugin_req_pid_t *preq, access_key_t ak, protoop_arg_t val);


/**
 * @}
 */

/**
 * @defgroup GETSET_PARAMETERS_PARAM Transport parameters values for \p param
 */
#define TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL 0x00
#define TRANSPORT_PARAMETER_INITIAL_MAX_DATA 0x01
#define TRANSPORT_PARAMETER_INITIAL_MAX_STREAMS_BIDI 0x02
#define TRANSPORT_PARAMETER_MAX_IDLE_TIMEOUT 0x03
#define TRANSPORT_PARAMETER_PREFERRED_ADDRESS 0x04
#define TRANSPORT_PARAMETER_MAX_PACKET_SIZE 0x05
#define TRANSPORT_PARAMETER_STATELESS_RESET_TOKEN 0x06
#define TRANSPORT_PARAMETER_ACK_DELAY_EXPONENT 0x07
#define TRANSPORT_PARAMETER_INITIAL_MAX_STREAMS_UNI 0x08
#define TRANSPORT_PARAMETER_MIGRATION_DISABLED 0x09
#define TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 0x0a
#define TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_UNIDIR 0x0b
/**
 * @}
 * 
 * @defgroup GETSET_CNX_AK Connection Access Keys
 * 
 * \brief Those access keys are dedicated to the \p get_cnx and \p set_cnx calls.
 * 
 * @{
 */

/** The input of the protocol operation number \p param */
#define AK_CNX_INPUT 0x00
/** The output of the protocol operation number \p param */
#define AK_CNX_OUTPUT 0x01
/** The proposed QUIC version, as a uint32_t */
#define AK_CNX_PROPOSED_VERSION 0x02
/** Whether 0-RTT is accepted */
#define AK_CNX_IS_0RTT_ACCEPTED 0x03
/** Whether remote parameters were received */
#define AK_CNX_REMOTE_PARMETERS_RECEIVED 0x04
/** Current value of the spin bit */
#define AK_CNX_CURRENT_SPIN 0x05
/** Is this connection the client side? */
#define AK_CNX_CLIENT_MODE 0x06
/** Previous spin bit */
#define AK_CNX_PREV_SPIN 0x07
/** Valid Edge Counter, makes spin bit RTT measurements more reliable */
#define AK_CNX_SPIN_VEC 0x08
/** Internal signalling from incoming to outgoing: we just spinned it */
#define AK_CNX_SPIN_EDGE 0x09
/** Timestamp of the incoming packet that triggered the spinning, in uint64_t */
#define AK_CNX_SPIN_LAST_TRIGGER 0x0a
/** The local parameter with the value provided by \p param */
#define AK_CNX_LOCAL_PARAMETER 0x0b
/** The remote parameter with the value provided by \p param */
#define AK_CNX_REMOTE_PARAMETER 0x0c
/** On clients, maximum 0RTT size accepted by server */
#define AK_CNX_MAX_EARLY_DATA_SIZE 0x0d
/** The connection state, as defined by \p picoquic_state_enum */
#define AK_CNX_STATE 0x0e
/** The pointer to the initial connection ID */
#define AK_CNX_INITIAL_CID 0x0f
/** The start time of the connection, as uint64_t */
#define AK_CNX_START_TIME 0x10
/** The application error code, as uint64_t */
#define AK_CNX_APPLICATION_ERROR 0x11
/** The local error code, as uint64_t */
#define AK_CNX_LOCAL_ERROR 0x12
/** The remote application error code, as uint64_t */
#define AK_CNX_REMOTE_APPLICATION_ERROR 0x13
/** The remote error code, as uint64_t */
#define AK_CNX_REMOTE_ERROR 0x14
/** The offending frame type causing the error, as uint64_t */
#define AK_CNX_OFFENDING_FRAME_TYPE 0x15
/** Next time sending data is expected, as uint64_t */
#define AK_CNX_NEXT_WAKE_TIME 0x16
/** Last local time at which the connection progressed, as uint64_t */
#define AK_CNX_LATEST_PROGRESS_TIME 0x17
/** Number of path challenges sent, as uint32_t */
#define AK_CNX_NB_PATH_CHALLENGE_SENT 0x18
/** Number of path responses received, as uint32_t */
#define AK_CNX_NB_PATH_RESPONSE_RECEIVED 0x19
/** Number of zero rtt packets sent, as uint32_t */
#define AK_CNX_NB_ZERO_RTT_SENT 0x1a
/** Number of zero rtt packets acked, as uint32_t */
#define AK_CNX_NB_ZERO_RTT_ACKED 0x1b
/** Number of total packet retransmissions, as uint64_t */
#define AK_CNX_NB_RETRANSMISSION_TOTAL 0x1c
/** Number of spurious packet retransmissions, as uint64_t */
#define AK_CNX_NB_SPURIOUS 0x1d
/** Total number of local ECN ECT0 packets, as uint64_t */
#define AK_CNX_ECN_ECT0_TOTAL_LOCAL 0x1e
/** Total number of local ECN ECT1 packets, as uint64_t */
#define AK_CNX_ECN_ECT1_TOTAL_LOCAL 0x1f
/** Total number of local ECN CE packets, as uint64_t */
#define AK_CNX_ECN_CE_TOTAL_LOCAL 0x20
/** Total number of remote ECN ECT0 packets, as uint64_t */
#define AK_CNX_ECN_ECT0_TOTAL_REMOTE 0x21
/** Total number of remote ECN ECT1 packets, as uint64_t */
#define AK_CNX_ECN_ECT1_TOTAL_REMOTE 0x22
/** Total number of remote ECN CE packets, as uint64_t */
#define AK_CNX_ECN_CE_TOTAL_REMOTE 0x23
/** Total data sent, as uint64_t */
#define AK_CNX_DATA_SENT 0x24
/** Total data received, as uint64_t */
#define AK_CNX_DATA_RECEIVED 0x25
/** Maxdata local, as uint64_t */
#define AK_CNX_MAXDATA_LOCAL 0x26
/** Maxdata remote, as uint64_t */
#define AK_CNX_MAXDATA_REMOTE 0x27
/** Max stream ID bidirectional local, as uint64_t */
#define AK_CNX_MAX_STREAM_ID_BIDIR_LOCAL 0x28
/** Max stream ID unidirectional local, as uint64_t */
#define AK_CNX_MAX_STREAM_ID_UNIDIR_LOCAL 0x29
/** Max stream ID bidirectional remote, as uint64_t */
#define AK_CNX_MAX_STREAM_ID_BIDIR_REMOTE 0x2a
/** Max stream ID unidirectional remote, as uint64_t */
#define AK_CNX_MAX_STREAM_ID_UNIDIR_REMOTE 0x2b
/** Keep alive interval used (0 disable it) */
#define AK_CNX_KEEP_ALIVE_INTERVAL 0x2c
/** The number of paths currently available */
#define AK_CNX_NB_PATHS 0x2d
/** The pointer to the path with its index provided by \p param */
#define AK_CNX_PATH 0x2e
/** The pointer to the congestion control algorithm */
#define AK_CNX_CONGESTION_CONTROL_ALGORITHM 0x2f
/** The pointer to the TLS stream with the epoch \p param */
#define AK_CNX_TLS_STREAM 0x30
/** The pointer to the encryption/decryption objects for the epoch \p param */
#define AK_CNX_CRYPTO_CONTEXT 0x31
/** The retry token length */
#define AK_CNX_RETRY_TOKEN_LENGTH 0x32
/** Should we wake the implementation right now? */
#define AK_CNX_WAKE_NOW 0x33
/** The return value of the protocol operation, only meaningful in post operations */
#define AK_CNX_RETURN_VALUE 0x34
/** The reserved frames queue */
#define AK_CNX_RESERVED_FRAMES 0x35
/** The retry frames queue */
#define AK_CNX_RETRY_FRAMES 0x36
/** The first misc frame to be sent */
#define AK_CNX_FIRST_MISC_FRAME 0x37
/** The first stream in the queue */
#define AK_CNX_FIRST_STREAM 0x38
/** Are plugins requested? */
#define AK_CNX_PLUGIN_REQUESTED 0x39
/** The number of plugin ids to request, as uint16_t */
#define AK_CNX_PIDS_TO_REQUEST_SIZE 0x3A
/** The pids to request structure pointer */
#define AK_CNX_PIDS_TO_REQUEST 0x3B
/** The queues of frames to be retransmitted */
#define AK_CNX_RTX_FRAMES 0x3C
/** Whether the handshake is done */
#define AK_CNX_HANDSHAKE_DONE 0x3D
/** Whether a HANDSHAKE_DONE frame was sent */
#define AK_CNX_HANDSHAKE_DONE_SENT 0x3E
/** Whether a HANDSHAKE_DONE frame was acked */
#define AK_CNX_HANDSHAKE_DONE_ACKED 0x3F

/**
 * @}
 * 
 * @defgroup GETSET_PATH_AK Path Access Keys
 * 
 * \brief Those access keys are dedicated to the \p get_path and \p set_path calls.
 * 
 * @{
 */

/** The pointer to the struct sockaddr of the peer */
#define AK_PATH_PEER_ADDR 0x00
/** The length of the peer addr structure */
#define AK_PATH_PEER_ADDR_LEN 0x01
/** The pointer to the local struct sockaddr */
#define AK_PATH_LOCAL_ADDR 0x02
/** The length of the local addr structure */
#define AK_PATH_LOCAL_ADDR_LEN 0x03
/** The local interface index */
#define AK_PATH_IF_INDEX_LOCAL 0x04
/** The challenge value */
#define AK_PATH_CHALLENGE 0x05
/** The last challenge time */
#define AK_PATH_CHALLENGE_TIME 0x06
/** The challenge response value pointer */
#define AK_PATH_CHALLENGE_RESPONSE 0x07
/** The number of time the challenge was repeated */
#define AK_PATH_CHALLENGE_REPEAT_COUNT 0x08
/** Flag for a MTU probe sent */
#define AK_PATH_MTU_PROBE_SENT 0x09
/** Flag indicating that the challenge was verified */
#define AK_PATH_CHALLENGE_VERIFIED 0x0a
/** Flag indicating that there is a challenge response to send */
#define AK_PATH_CHALLENGE_RESPONSE_TO_SEND 0x0b
/** Flag indicating that a ping was received */
#define AK_PATH_PING_RECEIVED 0x0c
/** The max ack delay, as uint64_t */
#define AK_PATH_MAX_ACK_DELAY 0x0d
/** The smoothed RTT, as uint64_t */
#define AK_PATH_SMOOTHED_RTT 0x0e
/** The RTT variance, as uint64_t */
#define AK_PATH_RTT_VARIANT 0x0f
/** The retransmit timer, as uint64_t */
#define AK_PATH_RETRANSMIT_TIMER 0x10
/** The min RTT, as uint64_t */
#define AK_PATH_RTT_MIN 0x11
/** The max spurious RTT, as uint64_t */
#define AK_PATH_MAX_SPURIOUS_RTT 0x12
/** The max reordering delay */
#define AK_PATH_MAX_REORDER_DELAY 0x13
/** The max reordering gap */
#define AK_PATH_MAX_REORDER_GAP 0x14
/** The send MTU */
#define AK_PATH_SEND_MTU 0x15
/** The maximum MTU that was tried */
#define AK_PATH_SEND_MTU_MAX_TRIED 0x16
/** The congestion window */
#define AK_PATH_CWIN 0x17
/** The number of bytes in flight */
#define AK_PATH_BYTES_IN_TRANSIT 0x18
/** The pointer to the congestion control algorithm state */
#define AK_PATH_CONGESTION_ALGORITHM_STATE 0x19
/** last time the path was evaluated */
#define AK_PATH_PACKET_EVALUATION_TIME 0x1a
/** number of nanoseconds of transmission time that are allowed */
#define AK_PATH_PACING_BUCKET_NANO_SEC 0x1b
/** maximum value (capacity) of the leaky bucket */
#define AK_PATH_PACING_BUCKET_MAX 0x1c
/** number of nanoseconds required to send a full size packet. */
#define AK_PATH_PACING_PACKET_TIME_NANOSEC 0x1d
/** The pointer to the local connection ID */
#define AK_PATH_LOCAL_CID 0x1e
/** The pointer to the remote connection ID */
#define AK_PATH_REMOTE_CID 0x1f
/** The pointer to the reset secret */
#define AK_PATH_RESET_SECRET 0x20
/** The pointer to the packet context with the picoquic_packet_context_enum \p param */
#define AK_PATH_PKT_CTX 0x21
/** The number of packets sent on the path, in uint64_t */
#define AK_PATH_NB_PKT_SENT 0x22
#define AK_PATH_DELIVERED 0x23
#define AK_PATH_DELIVERED_LIMITED_INDEX 0x24
#define AK_PATH_PACING_PACKET_TIME_MICROSEC 0x25
#define AK_PATH_RTT_SAMPLE 0x26
#define AK_PATH_DELIVERED_PRIOR 0x27
/**
 * @}
 * 
 * @defgroup GETSET_PKT_CTX_AK Packet context Access Keys
 * 
 * \brief Those access keys are dedicated to the \p get_pkt_ctx and \p set_pkt_ctx calls.
 * 
 * @{
 */

/** The send sequence */
#define AK_PKTCTX_SEND_SEQUENCE 0x00
/** Pointer to the first sack item */
#define AK_PKTCTX_FIRST_SACK_ITEM 0x01
/** The largest timestamp received */
#define AK_PKTCTX_TIME_STAMP_LARGEST_RECEIVED 0x02
/** The highest ack number sent */
#define AK_PKTCTX_HIGHEST_ACK_SENT 0x03
/** The highest ack sent time */
#define AK_PKTCTX_HIGHEST_ACK_TIME 0x04
/** The local ack delay */
#define AK_PKTCTX_ACK_DELAY_LOCAL 0x05
/** The number of retransmitted packets */
#define AK_PKTCTX_NB_RETRANSMIT 0x06
/** The latest retransmitted time */
#define AK_PKTCTX_LATEST_RETRANSMIT_TIME 0x07
/** The highest packet number acknowledged */
#define AK_PKTCTX_HIGHEST_ACKNOWLEDGED 0x08
/** The time at which the hisghest acknowledged was sent */
#define AK_PKTCTX_LATEST_TIME_ACKNOWLEDGED 0x09
/** The pointer to the newest retransmit packet */
#define AK_PKTCTX_RETRANSMIT_NEWEST 0x0a
/** The pointer to the oldest retransmit packet */
#define AK_PKTCTX_RETRANSMIT_OLDEST 0x0b
/** The pointer to the newest retransmitted packet */
#define AK_PKTCTX_RETRANSMITTED_NEWEST 0x0c
/** The pointer to the oldest retransmitted packet */
#define AK_PKTCTX_RETRANSMITTED_OLDEST 0x0d
/** Indicate if a ack is needed */
#define AK_PKTCTX_ACK_NEEDED 0x0e
/** The latest congestion notification time */
#define AK_PKTCTX_LATEST_RETRANSMIT_CC_NOTIFICATION_TIME 0x0f
/** The latest time at which progress was observed (e.g. an ack was received) */
#define AK_PKTCTX_LATEST_PROGRESS_TIME 0x10

/**
 * @}
 * 
 * @defgroup GETSET_PKT_AK Packet Access Keys
 * 
 * \brief Those access keys are dedicated to the \p get_pkt and \p set_pkt calls.
 * 
 * @{
 */

/** The pointer to the previous packet */
#define AK_PKT_PREVIOUS_PACKET 0x00
/** The pointer to the next packet */
#define AK_PKT_NEXT_PACKET 0x01
/** The pointer of the path on which this packet is sent */
#define AK_PKT_SEND_PATH 0x02
/** The sequence number */
#define AK_PKT_SEQUENCE_NUMBER 0x03
/** The send time */
#define AK_PKT_SEND_TIME 0x04
/** The length of the packet,as uint32_t */
#define AK_PKT_LENGTH 0x05
/** The length difference between encrypted and unencrypted */
#define AK_PKT_CHECKSUM_OVERHEAD 0x06
/** The offset of the packet */
#define AK_PKT_OFFSET 0x07
/** The packet type, as picoquic_packet_type_enum */
#define AK_PKT_TYPE 0x08
/** The packet context, as picoquic_packet_context_enum */
#define AK_PKT_CONTEXT 0x09
/** Flag stating that the packet is a pure ACK */
#define AK_PKT_IS_PURE_ACK 0x0b
/** Flag stating that the packet contains crypto material */
#define AK_PKT_CONTAINS_CRYPTO 0x0c
/** Flag stating that the packet is under congestion control */
#define AK_PKT_IS_CONGESTION_CONTROLLED 0x0d
/** Pointer to the content of the packet */
#define AK_PKT_BYTES 0x0e
/** Flag stating that the packet is a MTU probe */
#define AK_PKT_IS_MTU_PROBE 0x10
#define AK_PKT_DELIVERED_PRIOR 0x11
#define AK_PKT_DELIVERED_TIME_PRIOR 0x12
#define AK_PKT_DELIVERED_SENT_PRIOR 0x13
#define AK_PKT_DELIVERED_APP_LIMITED 0x14
#define AK_PKT_HAS_HANDSHAKE_DONE 0x15

/**
 * @}
 * 
 * @defgroup GETSET_SACK_ITEM_AK SACK item Access Keys
 * 
 * \brief Those access keys are dedicated to the \p get_sack_item and \p set_sack_item calls.
 * 
 * @{
 */

/** The next sack item */
#define AK_SACKITEM_NEXT_SACK 0x00
/** The start of the SACK range */
#define AK_SACKITEM_START_RANGE 0x01
/** The end of the SACK range */
#define AK_SACKITEM_END_RANGE 0x02

/**
 * @}
 * 
 * @defgroup GETSET_CNXID_AK Connection ID Access Keys
 * 
 * \brief Those access keys are dedicated to the \p get_cnxid and \p set_cnxid calls.
 * 
 * @{
 */

/** The pointer to the connection ID */
#define AK_CNXID_ID 0x00
/** The length of the connection ID */
#define AK_CNXID_LEN 0x01

/**
 * @}
 * 
 * @defgroup GETSET_STREAM_HEAD_AK Stream head Access Keys
 * 
 * \brief Those access keys are dedicated to the \p get_stream_head and \p set_stream_head calls.
 * 
 * @{
 */

/** The pointer to the sending queue */
#define AK_STREAMHEAD_SEND_QUEUE 0x00
/** The offset of consumed data */
#define AK_STREAMHEAD_CONSUMED_OFFSET 0x01
/** The next stream */
#define AK_STREAMHEAD_NEXT_STREAM 0x02
/** The stream ID*/
#define AK_STREAMHEAD_STREAM_ID 0x03
/** The maximum offset allowed by the peer */
#define AK_STREAMHEAD_MAX_DATA_REMOTE 0x04
/** The maximum offset sent on the stream */
#define AK_STREAMHEAD_SENT_OFFSET 0x05
/** The stream flags */
#define AK_STREAMHEAD_STREAM_FLAGS 0x06
/** The offset at which new app data will be queued for sending */
#define AK_STREAMHEAD_SENDING_OFFSET 0x07

/**
 * @}
 *
 * @defgroup GETSET_STREAM_DATA_AK Stream data Access Keys
 *
 * \brief Those access keys are dedicated to the \p get_stream_data call.
 *
 * @{
 */

#define AK_STREAMDATA_LENGTH 0x00
#define AK_STREAMDATA_OFFSET 0x01

/**
 * @}
 * 
 * @defgroup GETSET_CRYPTO_CONTEXT_AK Crypto context Access Keys
 * 
 * \brief Those access keys are dedicated to the \p get_crypto_context and \p set_crypto_context calls.
 * 
 * @{
 */

/** The pointer to the aead encryption scheme */
#define AK_CRYPTOCONTEXT_AEAD_ENCRYPTION 0x00

/**
 * @}
 * 
 * @defgroup GETSET_PH_AK Packet header Access Keys
 * 
 * \brief Those access keys are dedicated to the \p get_ph and \p set_ph calls.
 * 
 * @{
 */

/** The pointer to the destination connection ID */
#define AK_PH_DESTINATION_CNXID 0x00
/** The pointer to the destination connection ID */
#define AK_PH_OFFSET 0x01
/** The pointer to the payload length field */
#define AK_PH_PAYLOAD_LENGTH 0x02
/** The pointer to the pn64 field */
#define AK_PH_SEQUENCE_NUMBER 0x03
/** The corresponding epoch */
#define AK_PH_EPOCH 0x04
/** The packet type */
#define AK_PH_PTYPE 0x05

/**
 * @}
 * 
 * @defgroup GETSET_PIDREQ_AK PIDs to Request Access Keys
 * 
 * \brief Those access keys are dedicated to the \p get_pidred and \p get_pidred calls.
 * \warning This API is not stable, please do not use it!
 * 
 * @{
 */

/** The pointer to the PID ID */
#define AK_PIDREQ_PID_ID 0x00
/** The plugin name */
#define AK_PIDREQ_PLUGIN_NAME 0x01
/** Was the plugin requested? */
#define AK_PIDREQ_REQUESTED 0x02


/**
 * @}
 */

#endif /* GETSET_H */