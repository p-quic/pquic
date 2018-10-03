/**
 * \mainpage Protocol Plugins
 * 
 * \section readme ReadMe
 * 
 * The first thing you would do is to read the README.md.
 * 
 * \section avail_protoop Available Protocol Operations
 * 
 * All the protocol operations are defined in the protoop.h file.
 */

/**
 * \file protoop.h
 * \brief Here are the protocol operations that are currently available.
 * 
 * Each protocol operation takes a given number of **ensured** inputs and
 * provides a given number of **ensured** outputs. Inputs are denoted with
 * a [in], outputs by a [out]. They are provided in the described order.
 * Both inputs and outputs are actually provided by arrays of protoop_arg_t.
 */

#ifndef PROTOOP_H
#define PROTOOP_H

#include <stdint.h>

/* Typedef for plugins */
typedef struct state plugin_state_t;
typedef char* protoop_id_t;
typedef uint16_t param_id_t;
typedef uint16_t opaque_id_t;
typedef uint64_t protoop_arg_t;


/**
 * @defgroup parametrableProtoop Parametrable Protocol Operations
 * 
 * The following are protocol operations that takes a numerical argument.
 * A particular operation is attached to each different parameter value.
 */

/* @{ */ 

/**
 * Decode and process the frame whose the type is provided as parameter.
 * \param[in] bytes \b uint8_t* Pointer to the start of the frame in binary format to decode
 * \param[in] bytes_max <b> const uint8_t* </b> Pointer to the end of the packet to decode
 * \param[in] current_time \b uint64_t Time of reception of the packet
 * \param[in] epoch \b int Epoch of the received packet
 * \param[in] ack_needed \b int Current value indicating if the reception of previous frames requires replying with an ACK frame
 * 
 * \return \b uint8_t* Pointer to the first byte after the decoded frame in the packet, or NULL if an error occurred
 * \param[out] ack_needed \b int Set to 1 if the decoded frame requires replying with an ACK frame 
 */
static const protoop_id_t PROTOOP_PARAM_DECODE_FRAME = "decode_frame";

/* @} */ 

/**
 * @defgroup noparametrableProtoop Non-parametrable Protocol Operations
 * 
 * The following are protocol operations that does not take any argument.
 * Therefore, the operation is directly attached to the protocol operation ID.
 */

/* @{ */

/**
 * Decode the STREAM frame and process its content.
 * \param[in] bytes \b uint8_t* Pointer to the start of the frame in binary format to decode
 * \param[in] bytes_max <b> const uint8_t* </b> Pointer to the end of the packet to decode
 * \param[in] current_time \b uint64_t Time of reception of the frame
 * 
 * \return \b uint8_t* Pointer to the first byte after the decoded frame in the packet, or NULL if an error occurred
 */
static const protoop_id_t PROTOOP_NOPARAM_DECODE_STREAM_FRAME = "decode_stream_frame";

/**
 * Update the estimation of the perceived latency on the path \p path_x with the received packet.
 * \param[in] largest \b uint64_t The "largest" field of the received ACK frame
 * \param[in] current_time \b uint64_t Time of reception of the ACK frame
 * \param[in] ack_delay \b uint64_t The "ack_delay" field of the received ACK frame
 * \param[in] pc \b picoquic_packet_context_enum The packet context acked by the ACK frame
 * \param[in] path_x \b picoquic_path_t* The path acked by the ACK frame
 *
 * \return \b picoquic_packet_t* Pointer to the packet that updated the latency estimation, or NULL if none was used.
 */
static const protoop_id_t PROTOOP_NOPARAM_UPDATE_RTT = "update_rtt";

/**
 * Process "ack_range" blocks contained in an ACK frame and release acknowledged packets in the retransmit queue.
 * \param[in] pc \b picoquic_packet_context_enum The packet context acked by the ack range
 * \param[in] highest \b uint64_t The highest packet number acknowledged in the range
 * \param[in] range \b uint64_t The number of ranges to process
 * \param[in] ppacket \b picoquic_packet_t* The current first sent packet that can be acknowledged
 * \param[in] current_time \b uint64_t Time of reception of the ACK frame
 * 
 * \return \b int 0 if eveything is ok
 * \param[out] ppacket \b picoquic_packet_t* The first sent packet that could not be acknowledged by the range, or NULL if there is not.
 */
static const protoop_id_t PROTOOP_NOPARAM_PROCESS_ACK_RANGE = "process_ack_range";

/**
 * Check if packet that were retransmitted (in the retransmitted queue) were spurious, and release them if needed.
 * \param[in] start_of_range \b uint64_t The lowest packet number included in the range
 * \param[in] end_of_range \b uint64_t The largest packet number included in the range
 * \param[in] current_time \b uint64_t Time of reception of the ACK frame
 * \param[in] pc \b picoquic_packet_context_enum The packet context acked by the ACK frame
 * \param[in] path_x \b picoquic_path_t* The path acked by the ACK frame
 */
static const protoop_id_t PROTOOP_NOPARAM_CHECK_SPURIOUS_RETRANSMISSION = "check_spurious_retransmission";

/**
 * Update the sent packets and the ack status with the reception of the ACK frame.
 * \param[in] p \b picoquic_packet_t* The largest packet acknowledged by the ACK frame
 */
static const protoop_id_t PROTOOP_NOPARAM_PROCESS_POSSIBLE_ACK_OF_ACK_FRAME = "process_possible_ack_of_ack_frame";

/**
 * Update the ack status if the packet that was acknowledged contained a STREAM frame.
 * \param[in] bytes \b uint8_t* Pointer to the beginning of the STREAM frame in the packet
 * \param[in] bytes_max \b size_t Maximum size that can be read
 * \param[in] consumed \b size_t Current value of bytes consumed
 * 
 * \return \b int 0 if everything was fine
 * \param[out] consumed \b size_t Number of bytes in the STREAM frame processed
 */
static const protoop_id_t PROTOOP_NOPARAM_PROCESS_ACK_OF_STREAM_FRAME = "process_ack_of_stream_frame";

/**
 * Get a stream that is ready to send.
 * 
 * \return \b picoquic_stream_head* Pointer to a stream ready to be sent
 */
static const protoop_id_t PROTOOP_NOPARAM_FIND_READY_STREAM = "find_ready_stream";

/**
 * Check if it is needed to send back an ACK frame for the given path \p path_x
 * \param[in] current_time \b uint64_t The current time
 * \param[in] pc \b picoquic_packet_context_enum The packet context that would be acked
 * \param[in] path_x \b picoquic_path_t* The path that would be acked
 * 
 * \return \b int Iff non-zero, indicates that an ACK frame is needed
 */
static const protoop_id_t PROTOOP_NOPARAM_IS_ACK_NEEDED = "is_ack_needed";

/**
 * Chec if the TLS stream is ready to send.
 * 
 * \return \b int Iff non-zero, indicates that the TLS stream is ready
 */
static const protoop_id_t PROTOOP_NOPARAM_IS_TLS_STREAM_READY = "is_tls_stream_ready";

/**
 * Check if the STREAM frame pointer by \p bytes was already acked or not
 * \param[in] bytes \p uint8_t* Pointer to the beginning of the STREAM frame
 * \param[in] bytes_max \b size_t Maximum size that can be read
 * \param[in] no_need_to_repeat \b int Current value indicating if the STREAM frame should not be repeated
 * 
 * \return \b int Error code (0 means everything was fine)
 * \param[out] no_need_to_repeat \b int Indicates if the STREAM frame should not be repeated
 */
static const protoop_id_t PROTOOP_NOPARAM_CHECK_STREAM_FRAME_ALREADY_ACKED = "check_stream_frame_already_acked";

/* @} */

#endif