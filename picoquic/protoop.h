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
typedef char* protoop_id_t;


/**
 * @defgroup parametrableProtoop Parametrable Protocol Operations
 * 
 * The following are protocol operations that takes a numerical argument.
 * A particular operation is attached to each different parameter value.
 */

/* @{ */ 

/**
 * Parse the frame on the wire pointed by \p bytes whose the type is provided as parameter and provides the structure \p frame containing the frame information.
 * \param[in] bytes \b uint8_t* Pointer to the start of the in binary format to parse
 * \param[in] bytes_max <b> const uint8_t* </b> Pointer to the end of the packet to parse
 * 
 * \return \b uint8_t* Pointer to the first byte after the decoded frame in the packet, or NULL if an error occurred
 * \param[out] frame \b void* Pointer to the structure malloc'ed in the context memory containing the frame information
 * \param[out] ack_needed \b int Indicates if the parsed frame requires replying with an ACK frame
 * \param[out] is_retransmittable \b int Indicates if the parsed frame should be retransmitted if the packet carrying it is lost
 */
static const protoop_id_t PROTOOP_PARAM_PARSE_FRAME = "parse_frame";

/**
 * Process the parsed frame \p frame whose the type is provided as parameter.
 * \param[in] frame \b void* Pointer to the structure malloc'ed in the context memory containing the frame information. Don't free it.
 * \param[in] current_time \b uint64_t Time of reception of the packet containing that frame
 * \param[in] epoch \b int Epoch of the received packet containing the frame
 * 
 * \return \b int Error code, 0 iff everything is fine.
 */
static const protoop_id_t PROTOOP_PARAM_PROCESS_FRAME = "process_frame";

/**
 * Write the frame whose the type is provided as parameter.
 * \param[in] bytes \b uint8_t* Pointer to the start of the buffer to write
 * \param[in] bytes_max <b> const uint8_t* </b> Pointer to the end of the buffer to write
 * \param[in] frame_ctx \b void* The context of the frame to write. If no NULL, it has to be allocated in context memory and has to be free'd.
 * 
 * \return \b int Error code, 0 iff everything was fine
 * \param[out] consumed \b int The number of bytes written in \p bytes
 */
static const protoop_id_t PROTOOP_PARAM_WRITE_FRAME = "write_frame";

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
 * \param[in] path \b picoquic_path_t* The path on which the frame was received
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

// MP: Do we really want the RTT computation to be pluggable ?
// This a metric that is used in many places and often part of more complex mechanisms.
// I certainly wouldn't want a plugin to modify the RTT computation without being in charge of every other mechanisms
// that is using it.
// I would rather be in favor of plugins to define a separate metrics accessible via the cnx.

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

/**
 * uint8_t* bytes = (uint8_t *) cnx->protoop_inputv[0];
 * picoquic_packet_header* ph = (picoquic_packet_header *) cnx->protoop_inputv[1];
 * struct sockaddr* addr_from = (struct sockaddr *) cnx->protoop_inputv[2];
 * uint64_t current_time = (uint64_t) cnx->protoop_inputv[3];
 *
 * Output: return code (int)
 */

/**
 * Process an incoming packet which is 1-RTT protected.
 * \param[in] bytes \b uint8_t* Pointer to the start of the received packet
 * \param[in] ph \b picoquic_packet_header* Packet header information structure
 * \param[in] addr_from <b> struct sockaddr* </b> Source address of the incoming packet
 * \param[in] current_time \b uint64_t Time of reception of the packet
 * 
 * \return \b int Error code as described by ..., 0 is everything is fine \todo link to picoquic error codes
 */
static const protoop_id_t PROTOOP_NOPARAM_INCOMING_ENCRYPTED = "incoming_encrypted";

/** 
 * Get the path structure on which the packet with the header \p pc relates to.
 * \param[in] ph \b picoquic_packet_header* The header of the incoming packet
 *
 * \return \b picoquic_path_t* The path related to the packet header
 */
static const protoop_id_t PROTOOP_NOPARAM_GET_INCOMING_PATH = "get_incoming_path";

/**
 * Notify an event to the congestion control algorithm.
 * \param[in] path_x \b picoquic_path_t* Path concerned by the event
 * \param[in] notification \b picoquic_congestion_notification_t Notification event type
 * \param[in] rtt_measurement \b uint64_t Latency measurement to notify
 * \param[in] nb_bytes_acknowledged \b uint64_t Number of bytes acknowledged to notify
 * \param[in] lost_packet_number \b uint64_t Number of lost packets to notify
 * \param[in] current_time \b uint64_t Time of the notification
 * 
 * \todo link to congestion notification events
 */
static const protoop_id_t PROTOOP_NOPARAM_CONGESTION_ALGORITHM_NOTIFY = "congestion_algorithm_notify";

/**
 * Call back a function registered in the connection context to process incoming data.
 * \param[in] stream_id \b uint64_t The ID of the stream on which data arrived
 * \param[in] bytes \b uint8_t* Pointer to the received data
 * \param[in] length \b size_t Length of the received data
 * \param[in] fin_or_event \b picoquic_call_back_event_t Event type
 * \param[in] callback_ctx \b void* The context provided to the callback
 * 
 * \todo link to callback events
 */
static const protoop_id_t PROTOOP_NOPARAM_CALLBACK_FUNCTION = "callback_function";

/**
 * Print the formatted string \p fmt with the arguments \p fmt_args to the standard output.
 * \param[in] fmt <b> const char* </b> The formatting string
 * \param[in] fmt_args <b> const protoop_arg_t* </b> Array of values to format
 * \param[in] args_len \b size_t Number of values in \p fmt_args
 *
 * \warning Only up to 10 arguments can be printed in one single call
 */
static const protoop_id_t PROTOOP_NOPARAM_PRINTF = "printf";

/**
 * Trigger a connection error.
 * \param[in] local_error \b uint16_t QUIC error code
 * \param[in] frame_type \b uint64_t Type of the offending frame
 * 
 * \todo Link \p local_error to the param space related
 */
static const protoop_id_t PROTOOP_NOPARAM_CONNECTION_ERROR = "connection_error";

/**
 * Get the destination connection ID for \p path_x
 * \param[in] packet_type \b picoquic_packet_type_enum Type of the packet
 * \param[in] path_x \b picoquic_path_t* Path to get the destination connection ID
 * 
 * \return \b picoquic_connection_id_t* The destination connection ID
 */
static const protoop_id_t PROTOOP_NOPARAM_GET_DESTINATION_CONNECTION_ID = "get_destination_connection_id";

/**
 * Set the timer for the select, i.e., specify the next wake time of the implementation
 * \param[in] current_time \b uint64_t The current time
 */
static const protoop_id_t PROTOOP_NOPARAM_SET_NEXT_WAKE_TIME = "set_next_wake_time";

/**
 * Detect if a retransmission is needed.
 * \param[in] pc \b picoquic_packet_context_enum The packet context to retransmit
 * \param[in] path_x \b picoquic_path_t* The path on which the retransmission should be sent
 * \param[in] current_time \b uint64_t The current time
 * \param[in] packet \b picoquic_packet_t* The first packet candidate for retransmission
 * \param[in] send_buffer_max \b size_t The maximum size that could be used to retransmit packets
 * \param[in] is_cleartext_mode \b int Current value of the cleartext mode
 * \param[in] header_length \b uint32_t Current value of the header length
 * 
 * \return \b int The length of the retransmission
 * \param[out] is_cleartext_mode \b int Indicates if the retransmission is a cleartext one
 * \param[out] header_length \b uint32_t The length of the header of the retransmitted packet
 * \param[out] reason \b protoop_id_t Iff the return value is greater than zero, this indicates which mechanism triggered the retransmission
 */
static const protoop_id_t PROTOOP_NOPARAM_RETRANSMIT_NEEDED = "retransmit_needed";

/**
 * Indicates if \p p should be retransmitted or not.
 * \param[in] p \b picoquic_packet* The candidate packet for retransmission
 * \param[in] current_time \b uint64_t The current time of the evaluation
 * \param[in] timer_based \b int Current value of timer_based
 * 
 * \return \int Iff non-zero, the packet should be retransmitted
 * \param[out] timer_based \b int Iff non-zero, indicates that the retransmission is due to RTO
 * \param[out] reason \b protoop_id_t Iff the return value is non-zero, this indicates which mechanism triggered the retransmission
 */
static const protoop_id_t PROTOOP_NOPARAM_RETRANSMIT_NEEDED_BY_PACKET = "retransmit_needed_by_packet";

/**
 * Predict the length of the packet header to send.
 * \param[in] packet_type \b picoquic_packet_type_enum The type of the packet
 * \param[in] path_x \b picoquic_path_t* The path on which the packet would be sent
 * 
 * \return \b uint32_t The predicted length of the header
 */
static const protoop_id_t PROTOOP_NOPARAM_PREDICT_PACKET_HEADER_LENGTH = "predict_packet_header_length";

/**
 * Get the length of the checksum.
 * \param[in] is_cleartext_mode \b int Indicates if the checksum is contained in a cleartext packet
 * 
 * \return \b uint32_t The length of the checksum
 */
static const protoop_id_t PROTOOP_NOPARAM_GET_CHECKSUM_LENGTH = "get_checksum_length";

/**
 * Dequeue the packet from the retransmit queue.
 * \param[in] p \b picoquic_packet_t* The packet to be dequeued
 * \param[in] should_free \b If set, indicates that the packet should release its memory
 */
static const protoop_id_t PROTOOP_NOPARAM_DEQUEUE_RETRANSMIT_PACKET = "dequeue_retransmit_packet";

/**
 * Dequeue the packet from the retransmitted queue and release its memory.
 * \param[in] p \b picoquic_packet_t* The packet to be dequeued and freed
 */
static const protoop_id_t PROTOOP_NOPARAM_DEQUEUE_RETRANSMITTED_PACKET = "dequeue_retransmitted_packet";

/**
 * Prepare a required repetition or ack in a previous context.
 * \param[in] pc \b picoquic_packet_context_enum The packet context of the previous context
 * \param[in] path_x \b picoquic_path_t* The path on which packet will be sent
 * \param[in] packet \b picoquic_packet_t* The next packet to be sent
 * \param[in] send_buffer_max \b size_t The maximum size of the buffer to send
 * \param[in] current_time \b uint64_t The current time
 * \param[in] header_length \b uint32_t The current value of header_length
 * 
 * \return \b uint32_t The length of data coming from the old context
 * \param[out] header_length \b uint32_t The length of the header of the packet
 */
static const protoop_id_t PROTOOP_NOPARAM_PREPARE_PACKET_OLD_CONTEXT = "prepare_packet_old_context";

/**
 * Prepare a MTU probe.
 * \param[in] path_x \b picoquic_path_t* The path on which a MTU probe will be sent
 * \param[in] header_length \b uint32_t The size of the packet header
 * \param[in] checksum_length \b uint32_t The size of the checksum
 * \param[in] bytes \b uint8_t* Pointer to the packet buffer to send
 * 
 * \return \b uint32_t Size of the probe created (without the checksum)
 */
static const protoop_id_t PROTOOP_NOPARAM_PREPARE_MTU_PROBE = "prepare_mtu_probe";

/**
 * Finalize the packet and encrypt it.
 * \param[in] packet \b picoquic_packet_t* The packet to protect
 * \param[in] length \b uint32_t The size of the packet
 * \param[in] header_length \b uint32_t The size of the header of the packet
 * \param[in] checksum_overhead \b uint32_t The length of the checksum
 * \param[in] send_length \b size_t The length to send
 * \param[in] send_buffer \b uint8_t* The sending buffer
 * \param[in] send_buffer_max \b uint32_t The maximum size of the sending buffer
 * \param[in] path_x \b picoquic_path_t* The path on which the packet will be sent
 * \param[in] current_time \b uint64_t The current time
 * 
 * \return \b size_t The length of the buffer that will be sent
 */
static const protoop_id_t PROTOOP_NOPARAM_FINALIZE_AND_PROTECT_PACKET = "finalize_and_protect_packet";


/**
 * Observer-only anchor that must be triggered by all mechanisms that declare packets as lost
 * and trigger retransmissions.
 *
 * \param[in] packet \b picoquic_packet_t* The packet that was lost
 * \param[in] path_x \b picoquic_path_t* The path on which the packet was lost
 */
static const protoop_id_t PROTOOP_NOPARAM_PACKET_WAS_LOST = "packet_was_lost";


/**
 * Observer-only anchor that must be triggered whenever the connection state has changed.
 * Using the setter \b picoquic_set_cnx_state() ensures this requirement.
 *
 * No parameters are given to this protoop as the connection state already holds this information.
 */
static const protoop_id_t PROTOOP_NOPARAM_CONNECTION_STATE_CHANGED = "connection_state_changed";


/*
    MP: We may want to merge the two ops below into one a define a separate set of enums to describe the stream states
    as defined in the QUIC specs, e.g. https://tools.ietf.org/html/draft-ietf-quic-transport-15#section-9.2.
*/

/**
 * Observer-only anchor that must be triggered whenever a stream is opened.
 */
static const protoop_id_t PROTOOP_NOPARAM_STREAM_OPENED = "stream_opened";


/**
 * Observer-only anchor that must be triggered whenever a stream is closed.
 */
static const protoop_id_t PROTOOP_NOPARAM_STREAM_CLOSED = "stream_closed";

/**/

/**
 * Observer-only anchor that must be triggered when the Fast Retransmit mechanism is triggered
 *
 * \param[in] packet \b picoquic_packet_t* The packet candidate for retransmission
 */
static const protoop_id_t PROTOOP_NOPARAM_FAST_RETRANSMIT = "fast_retransmit";


/**
 * Observer-only anchor that must be triggered when the Retransmission Timeout mechanism is triggered
 *
 * \param[in] packet \b picoquic_packet_t* The packet candidate for retransmission
 */
static const protoop_id_t PROTOOP_NOPARAM_RETRANSMISSION_TIMEOUT = "retransmission_timeout";


/**
 * Observer-only anchor that must be triggered when the Tail Loss Probe mechanism is triggered
 *
 * \param[in] packet \b picoquic_packet_t* The packet candidate for retransmission
 */
static const protoop_id_t PROTOOP_NOPARAM_TAIL_LOSS_PROBE = "tail_loss_probe";


/**
 * Select the path on which the next packet will be sent.
 *
 * \return \b picoquic_path_t* The path on which the next packet will be sent.
 */
static const protoop_id_t PROTOOP_NOPARAM_SELECT_SENDING_PATH = "select_sending_path";

/* @} */

#endif