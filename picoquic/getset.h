/**
 * \file getset.h
 * \brief Here are the fields accessible to plugins.
 */

#ifndef GETSET_H
#define GETSET_H

#include "picoquic_internal.h"

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
 * @}
 */

/**
 * @defgroup GETSET_PARAMETERS_PARAM Transport parameters values for \p param
 */
#define TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL 0x00
#define TRANSPORT_PARAMETER_INITIAL_MAX_DATA 0x01
#define TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_ID_BIDIR 0x02
#define TRANSPORT_PARAMETER_IDLE_TIMEOUT 0x03
#define TRANSPORT_PARAMETER_PREFERRED_ADDRESS 0x04
#define TRANSPORT_PARAMETER_MAX_PACKET_SIZE 0x05
#define TRANSPORT_PARAMETER_STATELESS_RESET_TOKEN 0x06
#define TRANSPORT_PARAMETER_ACK_DELAY_EXPONENT 0x07
#define TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_ID_UNIDIR 0x08
#define TRANSPORT_PARAMETER_MIGRATION_DISABLED 0x09
#define TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 0x0a
#define TRANSPORT_PARAMETER_INITIAL_MAX_STREAM_DATA_UNIDIR 0x0b
/**
 * @defgroup GETSET_CNX_AK Connection Access Keys
 * 
 * \brief Those access keys are dedicated to the \p get_cnx call.
 * 
 * @{
 */

/** The proposed QUIC version, as a uint32_t */
#define CNX_AK_PROPOSED_VERSION 0x00
/** Whether 0-RTT is accepted */
#define CNX_AK_IS_0RTT_ACCEPTED 0x01
/** Whether remote parameters were received */
#define CNX_AK_REMOTE_PARMETERS_RECEIVED 0x02
/** Current value of the spin bit */
#define CNX_AK_CURRENT_SPIN 0x03
/** Is this connection the client side? */
#define CNX_AK_CLIENT_MODE 0x04
/** Previous spin bit */
#define CNX_AK_PREV_SPIN 0x05
/** Valid Edge Counter, makes spin bit RTT measurements more reliable */
#define CNX_AK_SPIN_VEC 0x06
/** Internal signalling from incoming to outgoing: we just spinned it */
#define CNX_AK_SPIN_EDGE 0x07
/** Timestamp of the incoming packet that triggered the spinning, in uint64_t */
#define CNX_AK_SPIN_LAST_TRIGGER 0x08
/** The local parameter with the value provided by \p param */
#define CNX_AK_LOCAL_PARAMETER 0x09
/** The remote parameter with the value provided by \p param */
#define CNX_AK_REMOTE_PARAMETER 0x0a
/** On clients, maximum 0RTT size accepted by server */
#define CNX_AK_MAX_EARLY_DATA_SIZE 0x0b
/** The connection state, as defined by \p picoquic_state_enum */
#define CNX_AK_STATE 0x0c
/** The pointer to the initial connection ID */
#define CNX_AK_INITIAL_CID 0x0d
/** The start time of the connection, as uint64_t */
#define CNX_AK_START_TIME 0x10
/** The application error code, as uint16_t */
#define CNX_AK_APPLICATION_ERROR 0x11
/** The local error code, as uint16_t */
#define CNX_AK_LOCAL_ERROR 0x12
/** The remote application error code, as uint16_t */
#define CNX_AK_REMOTE_APPLICATION_ERROR 0x13
/** The remote error code, as uint16_t */
#define CNX_AK_REMOTE_ERROR 0x14
/** The offending frame type causing the error, as uint64_t */
#define CNX_AK_OFFENDING_FRAME_TYPE 0x15
/** Next time sending data is expected, as uint64_t */
#define CNX_AK_NEXT_WAKE_TIME 0x16
/** Last local time at which the connection progressed, as uint64_t */
#define CNX_AK_LATEST_PROGRESS_TIME 0x17
/** Number of path challenges sent, as uint32_t */
#define CNX_AK_NB_PATH_CHALLENGE_SENT 0x18
/** Number of path responses received, as uint32_t */
#define CNX_AK_NB_PATH_RESPONSE_RECEIVED 0x19
/** Number of zero rtt packets sent, as uint32_t */
#define CNX_AK_NB_ZERO_RTT_SENT 0x1a
/** Number of zero rtt packets acked, as uint32_t */
#define CNX_AK_NB_ZERO_RTT_ACKED 0x1b
/** Number of total packet retransmissions, as uint64_t */
#define CNX_AK_NB_RETRANSMISSION_TOTAL 0x1c
/** Number of spurious packet retransmissions, as uint64_t */
#define CNX_AK_NB_SPURIOUS 0x1d
/** Total number of local ECN ECT0 packets, as uint64_t */
#define CNX_AK_ECN_ECT0_TOTAL_LOCAL 0x1e
/** Total number of local ECN ECT1 packets, as uint64_t */
#define CNX_AK_ECN_ECT1_TOTAL_LOCAL 0x1f
/** Total number of local ECN CE packets, as uint64_t */
#define CNX_AK_ECN_CE_TOTAL_LOCAL 0x20
/** Total number of remote ECN ECT0 packets, as uint64_t */
#define CNX_AK_ECN_ECT0_TOTAL_REMOTE 0x21
/** Total number of remote ECN ECT1 packets, as uint64_t */
#define CNX_AK_ECN_ECT1_TOTAL_REMOTE 0x22
/** Total number of remote ECN CE packets, as uint64_t */
#define CNX_AK_ECN_CE_TOTAL_REMOTE 0x23
/** Total data sent, as uint64_t */
#define CNX_AK_DATA_SENT 0x24
/** Total data received, as uint64_t */
#define CNX_AK_DATA_RECEIVED 0x25
/** Maxdata local, as uint64_t */
#define CNX_AK_MAXDATA_LOCAL 0x26
/** Maxdata remote, as uint64_t */
#define CNX_AK_MAXDATA_REMOTE 0x27
/** Max stream ID bidirectional local, as uint64_t */
#define CNX_AK_MAX_STREAM_ID_BIDIR_LOCAL 0x28
/** Max stream ID unidirectional local, as uint64_t */
#define CNX_AK_MAX_STREAM_ID_UNIDIR_LOCAL 0x29
/** Max stream ID bidirectional remote, as uint64_t */
#define CNX_AK_MAX_STREAM_ID_BIDIR_REMOTE 0x2a
/** Max stream ID unidirectional remote, as uint64_t */
#define CNX_AK_MAX_STREAM_ID_UNIDIR_REMOTE 0x2b
/** Keep alive interval used (0 disable it) */
#define CNX_AK_KEEP_ALIVE_INTERVAL 0x2c
/** The number of paths currently available */
#define CNX_AK_NB_PATHS 0x2d
/** The pointer to the path with its index provided by \p param */
#define CNX_AK_PATH 0x2e
/** The pointer to the congestion control algorithm */
#define CNX_AK_CONGESTION_CONTROL_ALGORITHM 0x2f
/** The pointer to the TLS stream with the epoch \p param */
#define CNX_AK_TLS_STREAM 0x30
/** The pointer to the encryption/decryption objects for the epoch \p param */
#define CNX_AK_CRYPTO_CONTEXT 0x31
/** The input of the protocol operation number \p param */
#define CNX_AK_INPUT 0x32
/** The output of the protocol operation number \p param */
#define CNX_AK_OUTPUT 0x33
/** The retry token length */
#define CNX_AK_RETRY_TOKEN_LENGTH 0x34

/**
 * @}
 */

#endif /* GETSET_H */