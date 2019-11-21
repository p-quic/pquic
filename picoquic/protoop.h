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
#include "uthash.h"

/* Typedef for plugins */
typedef char* protoop_str_id_t;
typedef struct protoop_id {
    uint64_t hash;
    char* id;
} protoop_id_t;

static inline uint64_t hash_value_str(char *str_pid)
{
    uint64_t ret;
    HASH_VALUE_STR(str_pid, ret);
    return ret;
}

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
#define PROTOOPID_PARAM_PARSE_FRAME "parse_frame"
extern protoop_id_t PROTOOP_PARAM_PARSE_FRAME;

/**
 * Process the parsed frame \p frame whose the type is provided as parameter.
 * \param[in] frame \b void* Pointer to the structure malloc'ed in the context memory containing the frame information. Don't free it.
 * \param[in] current_time \b uint64_t Time of reception of the packet containing that frame
 * \param[in] epoch \b int Epoch of the received packet containing the frame
 * \param[in] path_x \b picoquic_path_t* The path on which the frame was received
 * 
 * \return \b int Error code, 0 iff everything is fine.
 */
#define PROTOOPID_PARAM_PROCESS_FRAME "process_frame"
extern protoop_id_t PROTOOP_PARAM_PROCESS_FRAME;

/**
 * Write the frame whose the type is provided as parameter.
 * \param[in] bytes \b uint8_t* Pointer to the start of the buffer to write
 * \param[in] bytes_max <b> const uint8_t* </b> Pointer to the end of the buffer to write
 * \param[in] frame_ctx \b void* The context of the frame to write. If not NULL, it has to be allocated in context memory and has to be free'd by the plugin at some point.
 * 
 * \return \b int Error code, 0 iff everything was fine
 * \param[out] consumed \b int The number of bytes written in \p bytes
 * \param[out] is_retransmittable \b int Indicates if the parsed frame should be retransmitted if the packet carrying it is lost
 */
#define PROTOOPID_PARAM_WRITE_FRAME "write_frame"
extern protoop_id_t PROTOOP_PARAM_WRITE_FRAME;

/**
 * Notifies the reception (or not) of the frame by the peer and enables reservation frame slot cleaning.
 * \param[in] rfs \b reserve_frame_slot_t* The reserved frame. Should be free'd to avoid memory leak in the plugin.
 * \param[in] received \b int Indicates if the frame was received or not.
 * 
 */
#define PROTOOPID_PARAM_NOTIFY_FRAME "notify_frame"
extern protoop_id_t PROTOOP_PARAM_NOTIFY_FRAME;

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
#define PROTOOPID_NOPARAM_DECODE_STREAM_FRAME "decode_stream_frame"
extern protoop_id_t PROTOOP_NOPARAM_DECODE_STREAM_FRAME;
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
#define PROTOOPID_NOPARAM_UPDATE_RTT "update_rtt"
extern protoop_id_t PROTOOP_NOPARAM_UPDATE_RTT;

// MP: Do we really want the RTT computation to be pluggable ?
// This a metric that is used in many places and often part of more complex mechanisms.
// I certainly wouldn't want a plugin to modify the RTT computation without being in charge of every other mechanisms
// that is using it.
// I would rather be in favor of plugins to define a separate metrics accessible via the cnx.

/**
 * Schedule frames and provide a packet with the path it should be sent on when connection is ready
 * \param[in] packet \b picoquic_packet_t* The packet to be sent
 * \param[in] send_buffer_max \b size_t The maximum amount of bytes that can be written on the packet
 * \param[in] current_time \b uint64_t Time of the scheduling
 * \param[in] retransmit_p \b picoquic_packet_t* A candidate packet for retransmission
 * \param[in] from_path \b picoquic_path_t* The path on which the candidate packet was sent
 * \param[in] reason \b char* A description of the reason for which the candidate packet is proposed
 * 
 * \return \b int 0 if everything is ok
 * \param[out] path_x \b picoquic_path_t* The path on which the packet should be sent
 * \param[out] length \b uint32_t The length of the packet to be sent
 * \param[out] header_length \b uint32_t The length of the header of the packet to be sent
 */
#define PROTOOPID_NOPARAM_SCHEDULE_FRAMES_ON_PATH "schedule_frames_on_path"
extern protoop_id_t PROTOOP_NOPARAM_SCHEDULE_FRAMES_ON_PATH;

/**
 * Write frames that were previously scheduled in the packet
 * \param[in] bytes \b uint8_t* The array of bytes forming the packet content
 * \param[in] max_bytes \b size_t The maximum amount of bytes that can be written on the packet
 * \param[in] packet \b picoquic_packet_t* The packet to be sent
 * 
 * \return \b int 0 if everything is ok
 * \param[out] consumed \b size_t The number of bytes written
 * \param[out] is_pure_ack <b> unsigned int </b> Is this packet non retransmittable?
 */
#define PROTOOPID_NOPARAM_SCHEDULER_WRITE_NEW_FRAMES "scheduler_write_new_frames"
extern protoop_id_t PROTOOP_NOPARAM_SCHEDULER_WRITE_NEW_FRAMES;

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
#define PROTOOPID_NOPARAM_PROCESS_ACK_RANGE "process_ack_range"
extern protoop_id_t PROTOOP_NOPARAM_PROCESS_ACK_RANGE;
/**
 * Check if packet that were retransmitted (in the retransmitted queue) were spurious, and release them if needed.
 * \param[in] start_of_range \b uint64_t The lowest packet number included in the range
 * \param[in] end_of_range \b uint64_t The largest packet number included in the range
 * \param[in] current_time \b uint64_t Time of reception of the ACK frame
 * \param[in] pc \b picoquic_packet_context_enum The packet context acked by the ACK frame
 * \param[in] path_x \b picoquic_path_t* The path acked by the ACK frame
 */
#define PROTOOPID_NOPARAM_CHECK_SPURIOUS_RETRANSMISSION "check_spurious_retransmission"
extern protoop_id_t PROTOOP_NOPARAM_CHECK_SPURIOUS_RETRANSMISSION;

/**
 * Update the sent packets and the ack status with the reception of the ACK frame.
 * \param[in] p \b picoquic_packet_t* The largest packet acknowledged by the ACK frame
 */
#define PROTOOPID_NOPARAM_PROCESS_POSSIBLE_ACK_OF_ACK_FRAME "process_possible_ack_of_ack_frame"
extern protoop_id_t PROTOOP_NOPARAM_PROCESS_POSSIBLE_ACK_OF_ACK_FRAME;

/**
 * Process possible ACK of ACK range, and clean the associated SACK_ITEM
 * \param[in] first_sack \b picoquic_sack_item_t* The pointer to the first SACK item
 * \param[in] start_range \b uint64_t The start of the ACKed range
 * \param[in] end_range \b uint64_t The end of the ACKed range
 * 
 * \warning This protocol operation CANNOT be pluginized so far!
 */
#define PROTOOPID_NOPARAM_PROCESS_ACK_OF_ACK_RANGE "process_ack_of_ack_range"
extern protoop_id_t PROTOOP_NOPARAM_PROCESS_ACK_OF_ACK_RANGE;

/**
 * Update the ack status if the packet that was acknowledged contained a STREAM frame.
 * \param[in] bytes \b uint8_t* Pointer to the beginning of the STREAM frame in the packet
 * \param[in] bytes_max \b size_t Maximum size that can be read
 * \param[in] consumed \b size_t Current value of bytes consumed
 * 
 * \return \b int 0 if everything was fine
 * \param[out] consumed \b size_t Number of bytes in the STREAM frame processed
 */
#define PROTOOPID_NOPARAM_PROCESS_ACK_OF_STREAM_FRAME "process_ack_of_stream_frame"
extern protoop_id_t PROTOOP_NOPARAM_PROCESS_ACK_OF_STREAM_FRAME;

/**
 * Get a stream that is ready to send.
 * 
 * \return \b picoquic_stream_head* Pointer to a stream ready to be sent
 */
#define PROTOOPID_NOPARAM_FIND_READY_STREAM "find_ready_stream"
extern protoop_id_t PROTOOP_NOPARAM_FIND_READY_STREAM;

/**
 * Get the next stream to send given the buffer size left.
 * The stream returned will effectively be used to fill a packet.
 * \param[in] bytes_max \b size_t The buffer size made available to the stream
 *
 * \return \b picoquic_stream_head* Pointer to a stream to sent
 */
#define PROTOOPID_NOPARAM_SCHEDULE_NEXT_STREAM "schedule_next_stream"
extern protoop_id_t PROTOOP_NOPARAM_SCHEDULE_NEXT_STREAM;

/**
 * Get a plugin stream that is ready to send.
 *
 * \return \b picoquic_stream_head* Pointer to a plugin stream ready to be sent
 */
#define PROTOOPID_NOPARAM_FIND_READY_PLUGIN_STREAM "find_ready_plugin_stream"
extern protoop_id_t PROTOOP_NOPARAM_FIND_READY_PLUGIN_STREAM;

/**
 * Check if it is needed to send back an ACK frame for the given path \p path_x
 * \param[in] current_time \b uint64_t The current time
 * \param[in] pc \b picoquic_packet_context_enum The packet context that would be acked
 * \param[in] path_x \b picoquic_path_t* The path that would be acked
 *
 * \return \b int Iff non-zero, indicates that an ACK frame is needed
 */
#define PROTOOPID_NOPARAM_IS_ACK_NEEDED "is_ack_needed"
extern protoop_id_t PROTOOP_NOPARAM_IS_ACK_NEEDED;

/**
 * Check if the TLS stream is ready to send.
 * 
 * \return \b int Iff non-zero, indicates that the TLS stream is ready
 */
#define PROTOOPID_NOPARAM_IS_TLS_STREAM_READY "is_tls_stream_ready"
extern protoop_id_t PROTOOP_NOPARAM_IS_TLS_STREAM_READY;

/**
 * Check if the STREAM frame pointer by \p bytes was already acked or not
 * \param[in] bytes \p uint8_t* Pointer to the beginning of the STREAM frame
 * \param[in] bytes_max \b size_t Maximum size that can be read
 * \param[in] no_need_to_repeat \b int Current value indicating if the STREAM frame should not be repeated
 * 
 * \return \b int Error code (0 means everything was fine)
 * \param[out] no_need_to_repeat \b int Indicates if the STREAM frame should not be repeated
 */
#define PROTOOPID_NOPARAM_CHECK_STREAM_FRAME_ALREADY_ACKED "check_stream_frame_already_acked"
extern protoop_id_t PROTOOP_NOPARAM_CHECK_STREAM_FRAME_ALREADY_ACKED;

/**
 * Process an incoming packet which is 1-RTT protected.
 * \param[in] bytes \b uint8_t* Pointer to the start of the received packet
 * \param[in] ph \b picoquic_packet_header* Packet header information structure
 * \param[in] addr_from <b> struct sockaddr* </b> Source address of the incoming packet
 * \param[in] current_time \b uint64_t Time of reception of the packet
 * 
 * \return \b int Error code as described by ..., 0 is everything is fine \todo link to picoquic error codes
 */
#define PROTOOPID_NOPARAM_INCOMING_ENCRYPTED "incoming_encrypted"
extern protoop_id_t PROTOOP_NOPARAM_INCOMING_ENCRYPTED;

/** 
 * Get the path structure on which the packet with the header \p pc relates to.
 * \param[in] ph \b picoquic_packet_header* The header of the incoming packet
 *
 * \return \b picoquic_path_t* The path related to the packet header
 */
#define PROTOOPID_NOPARAM_GET_INCOMING_PATH "get_incoming_path"
extern protoop_id_t PROTOOP_NOPARAM_GET_INCOMING_PATH;

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
#define PROTOOPID_NOPARAM_CONGESTION_ALGORITHM_NOTIFY "congestion_algorithm_notify"
extern protoop_id_t PROTOOP_NOPARAM_CONGESTION_ALGORITHM_NOTIFY;

/**
 * Call back a function registered in the connection context to process incoming data.
 * \param[in] stream_id \b uint64_t The ID of the stream on which data arrived
 * \param[in] bytes \b uint8_t* Pointer to the received data
 * \param[in] length \b size_t Length of the received data
 * \param[in] fin_or_event \b picoquic_call_back_event_t Event type
 * 
 * \todo link to callback events
 */
#define PROTOOPID_NOPARAM_CALLBACK_FUNCTION "callback_function"
extern protoop_id_t PROTOOP_NOPARAM_CALLBACK_FUNCTION;

/**
 * Print the formatted string \p fmt with the arguments \p fmt_args to the standard output.
 * \param[in] fmt <b> const char* </b> The formatting string
 * \param[in] fmt_args <b> const protoop_arg_t* </b> Array of values to format
 * \param[in] args_len \b size_t Number of values in \p fmt_args
 *
 * \warning Only up to 10 arguments can be printed in one single call
 */
#define PROTOOPID_NOPARAM_PRINTF "printf"
extern protoop_id_t PROTOOP_NOPARAM_PRINTF;

/**
 * Print the formatted string \p fmt with the arguments \p fmt_args to the supplied buffer
 * \param[in] buf <b> const char* </b> The output buffer
 * \param[in] buf_len \b size_t The output buffer length
 * \param[in] fmt <b> const char* </b> The formatting string
 * \param[in] fmt_args <b> const protoop_arg_t* </b> Array of values to format
 * \param[in] args_len \b size_t Number of values in \p fmt_args
 *
 * \warning Only up to 10 arguments can be printed in one single call
 */
#define PROTOOPID_NOPARAM_SNPRINTF "snprintf"
extern protoop_id_t PROTOOP_NOPARAM_SNPRINTF;

/**
 * Trigger a connection error.
 * \param[in] local_error \b uint16_t QUIC error code
 * \param[in] frame_type \b uint64_t Type of the offending frame
 * 
 * \todo Link \p local_error to the param space related
 */
#define PROTOOPID_NOPARAM_CONNECTION_ERROR "connection_error"
extern protoop_id_t PROTOOP_NOPARAM_CONNECTION_ERROR;

/**
 * Get the destination connection ID for \p path_x
 * \param[in] packet_type \b picoquic_packet_type_enum Type of the packet
 * \param[in] path_x \b picoquic_path_t* Path to get the destination connection ID
 * 
 * \return \b picoquic_connection_id_t* The destination connection ID
 */
#define PROTOOPID_NOPARAM_GET_DESTINATION_CONNECTION_ID "get_destination_connection_id"
extern protoop_id_t PROTOOP_NOPARAM_GET_DESTINATION_CONNECTION_ID;

/**
 * Set the timer for the select, i.e., specify the next wake time of the implementation
 * \param[in] current_time \b uint64_t The current time
 * \param[in] last_pkt_length \b uint32_t Size of last packet sent
 */
#define PROTOOPID_NOPARAM_SET_NEXT_WAKE_TIME "set_next_wake_time"
extern protoop_id_t PROTOOP_NOPARAM_SET_NEXT_WAKE_TIME;

/**
 * sets the return code to true when there are congestion-controlled plugin frames in the sending queue
 */
#define PROTOOPID_NOPARAM_HAS_CONGESTION_CONTROLLED_PLUGIN_FRAMEMS_TO_SEND "has_congestion_controlled_plugin_frames_to_send"
extern protoop_id_t PROTOOP_NOPARAM_HAS_CONGESTION_CONTROLLED_PLUGIN_FRAMEMS_TO_SEND;

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
 * \param[out] reason \b extern protoop_id_t Iff the return value is greater than zero, this indicates which mechanism triggered the retransmission
 */
#define PROTOOPID_NOPARAM_RETRANSMIT_NEEDED "retransmit_needed"
extern protoop_id_t PROTOOP_NOPARAM_RETRANSMIT_NEEDED;

/**
 * Indicates if \p p should be retransmitted or not.
 * \param[in] p \b picoquic_packet* The candidate packet for retransmission
 * \param[in] current_time \b uint64_t The current time of the evaluation
 * \param[in] timer_based \b int Current value of timer_based
 * 
 * \return \int Iff non-zero, the packet should be retransmitted
 * \param[out] timer_based \b int Iff non-zero, indicates that the retransmission is due to RTO
 * \param[out] reason \b extern protoop_id_t Iff the return value is non-zero, this indicates which mechanism triggered the retransmission
 * \param[out] retransmit_time \b uint64_t The time computed for retransmission of the packet
 */
#define PROTOOPID_NOPARAM_RETRANSMIT_NEEDED_BY_PACKET "retransmit_needed_by_packet"
extern protoop_id_t PROTOOP_NOPARAM_RETRANSMIT_NEEDED_BY_PACKET;
/**
 * Predict the length of the packet header to send.
 * \param[in] packet_type \b picoquic_packet_type_enum The type of the packet
 * \param[in] path_x \b picoquic_path_t* The path on which the packet would be sent
 * 
 * \return \b uint32_t The predicted length of the header
 */
#define PROTOOPID_NOPARAM_PREDICT_PACKET_HEADER_LENGTH "predict_packet_header_length"
extern protoop_id_t PROTOOP_NOPARAM_PREDICT_PACKET_HEADER_LENGTH;
/**
 * Get the length of the checksum.
 * \param[in] is_cleartext_mode \b int Indicates if the checksum is contained in a cleartext packet
 * 
 * \return \b uint32_t The length of the checksum
 */
#define PROTOOPID_NOPARAM_GET_CHECKSUM_LENGTH "get_checksum_length"
extern protoop_id_t PROTOOP_NOPARAM_GET_CHECKSUM_LENGTH;
/**
 * Dequeue the packet from the retransmit queue.
 * \param[in] p \b picoquic_packet_t* The packet to be dequeued
 * \param[in] should_free \b If set, indicates that the packet should release its memory
 */
#define PROTOOPID_NOPARAM_DEQUEUE_RETRANSMIT_PACKET "dequeue_retransmit_packet"
extern protoop_id_t PROTOOP_NOPARAM_DEQUEUE_RETRANSMIT_PACKET;
/**
 * Dequeue the packet from the retransmitted queue and release its memory.
 * \param[in] p \b picoquic_packet_t* The packet to be dequeued and freed
 */
#define PROTOOPID_NOPARAM_DEQUEUE_RETRANSMITTED_PACKET "dequeue_retransmitted_packet"
extern protoop_id_t PROTOOP_NOPARAM_DEQUEUE_RETRANSMITTED_PACKET;
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
#define PROTOOPID_NOPARAM_PREPARE_PACKET_OLD_CONTEXT "prepare_packet_old_context"
extern protoop_id_t PROTOOP_NOPARAM_PREPARE_PACKET_OLD_CONTEXT;
/**
 * Prepare a MTU probe.
 * \param[in] path_x \b picoquic_path_t* The path on which a MTU probe will be sent
 * \param[in] header_length \b uint32_t The size of the packet header
 * \param[in] checksum_length \b uint32_t The size of the checksum
 * \param[in] bytes \b uint8_t* Pointer to the packet buffer to send
 * 
 * \return \b uint32_t Size of the probe created (without the checksum)
 */
#define PROTOOPID_NOPARAM_PREPARE_MTU_PROBE "prepare_mtu_probe"
extern protoop_id_t PROTOOP_NOPARAM_PREPARE_MTU_PROBE;
/**
 * Prepare a STREAM frame.
 * \param[in] stream \b picoquic_stream_head* The stream from which data to write originate
 * \param[in] bytes \b uint8_t* Pointer to the buffer to write the frame 
 * \param[in] bytes_max \b size_t Max size that can be written
 * 
 * \return \b int Error code, 0 means it's ok
 * \param[out] consumed \b size_t Number of bytes written
 */
#define PROTOOPID_NOPARAM_PREPARE_STREAM_FRAME "prepare_stream_frame"
extern protoop_id_t PROTOOP_NOPARAM_PREPARE_STREAM_FRAME;

/**
 * Prepare a PLUGIN frame.
 * \param[in] plugin_stream \b picoquic_stream_head* The plugin stream from which data to write originate
 * \param[in] bytes \b uint8_t* Pointer to the buffer to write the frame
 * \param[in] bytes_max \b size_t Max size that can be written
 *
 * \return \b int Error code, 0 means it's ok
 * \param[out] consumed \b size_t Number of bytes written
 */
#define PROTOOPID_NOPARAM_PREPARE_PLUGIN_FRAME "prepare_plugin_frame"
extern protoop_id_t PROTOOP_NOPARAM_PREPARE_PLUGIN_FRAME;

/**
 * Returns the maximal address writable for a stream in a packet.
 * \param[in] bytes_max \b size_t Current max size that can be written
 * \param[in] bytes \b uint8_t* Pointer to the buffer to write the frame
 *
 * \return \b int Error code, 0 means it's ok
 * \param[out] bytes_max \b size_t Current max size that can be written
 */
#define PROTOOPID_NOPARAM_STREAM_BYTES_MAX "stream_bytes_max"
extern protoop_id_t PROTOOP_NOPARAM_STREAM_BYTES_MAX;


/**
 * Returns true if the streams must always encode the payload length.
 */
#define PROTOOPID_NOPARAM_STREAM_ALWAYS_ENCODE_LENGTH "stream_always_encode_length"
extern protoop_id_t PROTOOP_NOPARAM_STREAM_ALWAYS_ENCODE_LENGTH;


/**
 * Prepare a CRYPTO HS frame.
 * \param[in] epoch \b int The current epoch
 * \param[in] bytes \b uint8_t* Pointer to the buffer to write the frame 
 * \param[in] bytes_max \b size_t Max size that can be written
 *  
 * \return \b int Error code, 0 means it's ok
 * \param[out] consumed \b size_t Number of bytes written
 */
#define PROTOOPID_NOPARAM_PREPARE_CRYPTO_HS_FRAME "prepare_crypto_hs_frame"
extern protoop_id_t PROTOOP_NOPARAM_PREPARE_CRYPTO_HS_FRAME;
/**
 * Prepare a ACK frame.
 * \param[in] current_time \b uint64_t The current time
 * \param[in] pc \b picoquic_packet_context_enum The packet context to ack
 * \param[in] bytes \b uint8_t* Pointer to the buffer to write the frame 
 * \param[in] bytes_max \b size_t Max size that can be written
 *
 * \return \b int Error code, 0 means it's ok
 * \param[out] consumed \b size_t Number of bytes written
 */
#define PROTOOPID_NOPARAM_PREPARE_ACK_FRAME "prepare_ack_frame"
extern protoop_id_t PROTOOP_NOPARAM_PREPARE_ACK_FRAME;
/**
 * Prepare a ACK ECN frame.
 * \param[in] current_time \b uint64_t The current time
 * \param[in] pc \b picoquic_packet_context_enum The packet context to ack
 * \param[in] bytes \b uint8_t* Pointer to the buffer to write the frame 
 * \param[in] bytes_max \b size_t Max size that can be written
 *
 * \return \b int Error code, 0 means it's ok
 * \param[out] consumed \b size_t Number of bytes written
 */
#define PROTOOPID_NOPARAM_PREPARE_ACK_ECN_FRAME "prepare_ack_ecn_frame"
extern protoop_id_t PROTOOP_NOPARAM_PREPARE_ACK_ECN_FRAME;
/**
 * Prepare a MAX DATA frame.
 * \param[in] maxdata_increase \b uint64_t The max data to advertise
 * \param[in] bytes \b uint8_t* Pointer to the buffer to write the frame 
 * \param[in] bytes_max \b size_t Max size that can be written
 *
 * \return \b int Error code, 0 means it's ok
 * \param[out] consumed \b size_t Number of bytes written
 */
#define PROTOOPID_NOPARAM_PREPARE_MAX_DATA_FRAME "prepare_max_data_frame"
extern protoop_id_t PROTOOP_NOPARAM_PREPARE_MAX_DATA_FRAME;
/**
 * Prepare the required MAX STREAM DATA frames.
 * \param[in] bytes \b uint8_t* Pointer to the buffer to write the frame 
 * \param[in] bytes_max \b size_t Max size that can be written
 *
 * \return \b int Error code, 0 means it's ok
 * \param[out] consumed \b size_t Number of bytes written
 */
#define PROTOOPID_NOPARAM_PREPARE_REQUIRED_MAX_STREAM_DATA_FRAME "prepare_required_max_stream_data_frames"
extern protoop_id_t PROTOOP_NOPARAM_PREPARE_REQUIRED_MAX_STREAM_DATA_FRAME;
/**
 * Prepare the first miscellanious frame.
 * \param[in] bytes \b uint8_t* Pointer to the buffer to write the frame 
 * \param[in] bytes_max \b size_t Max size that can be written
 *
 * \return \b int Error code, 0 means it's ok
 * \param[out] consumed \b size_t Number of bytes written
 */
#define PROTOOPID_NOPARAM_PREPARE_FIRST_MISC_FRAME "prepare_first_misc_frame"
extern protoop_id_t PROTOOP_NOPARAM_PREPARE_FIRST_MISC_FRAME;
/**
 * Prepare a miscellanious frame.
 * \param[in] misc_frame \b picoquic_misc_frame_header_t* Pointer of the misc frame structure
 * \param[in] bytes \b uint8_t* Pointer to the buffer to write the frame 
 * \param[in] bytes_max \b size_t Max size that can be written
 *
 * \return \b int Error code, 0 means it's ok
 * \param[out] consumed \b size_t Number of bytes written
 */
#define PROTOOPID_NOPARAM_PREPARE_MISC_FRAME "prepare_misc_frame"
extern protoop_id_t PROTOOP_NOPARAM_PREPARE_MISC_FRAME;
/**
 * Prepare a path challenge frame.
 * \param[in] bytes \b uint8_t* Pointer to the buffer to write the frame 
 * \param[in] bytes_max \b size_t Max size that can be written
 * \param[in] path \b picoquic_path_t* Pointer of the path on which we want to write the challenge
 *
 * \return \b int Error code, 0 means it's ok
 * \param[out] consumed \b size_t Number of bytes written
 */
#define PROTOOPID_NOPARAM_PREPARE_PATH_CHALLENGE_FRAME "prepare_path_challenge_frame"
extern protoop_id_t PROTOOP_NOPARAM_PREPARE_PATH_CHALLENGE_FRAME;
/**
 * Parse the frame on the wire pointed by \p bytes and skip it.
 * \param[in] bytes \b uint8_t* Pointer to the start of the in binary format to skip
 * \param[in] bytes_max_size \b size_t Max length of the buffer
 * \param[in] consumed \b size_t Current value of the number of bytes skipped
 * \param[in] pure_ack \b int Current value that indicates if the skipped frame is an ACK one
 * 
 * \return \b uint8_t* Pointer to the first byte after the decoded frame in the packet, or NULL if an error occurred
 * \param[out] consumed \b size_t Number of bytes skipped
 * \param[out] pure_ack \b int Indicates if the skipped frame is an ACK one
 */
#define PROTOOPID_NOPARAM_SKIP_FRAME "skip_frame"
extern protoop_id_t PROTOOP_NOPARAM_SKIP_FRAME;
/**
 * Prepare a packet when the connection is in ready state.
 * \todo Write doc
 * picoquic_path_t ** path
 * picoquic_packet_t* packet,
 * uint64_t current_time,
 * uint8_t* send_buffer,
 * size_t send_buffer_max,
 * size_t* send_length
 */
#define PROTOOPID_NOPARAM_PREPARE_PACKET_READY "prepare_packet_ready"
extern protoop_id_t PROTOOP_NOPARAM_PREPARE_PACKET_READY;
/**
 * \todo
 */
#define PROTOOPID_NOPARAM_RECEIVED_PACKET "received_packet"
extern protoop_id_t PROTOOP_NOPARAM_RECEIVED_PACKET;
/**
 * \todo
 */
#define PROTOOPID_NOPARAM_BEFORE_SENDING_PACKET "before_sending_packet"
extern protoop_id_t PROTOOP_NOPARAM_BEFORE_SENDING_PACKET;
/**
 * \todo
 */
#define PROTOOPID_NOPARAM_RECEIVED_SEGMENT "received_segment"
extern protoop_id_t PROTOOP_NOPARAM_RECEIVED_SEGMENT;
/**
 * \todo
 */
#define PROTOOPID_NOPARAM_BEFORE_SENDING_SEGMENT "before_sending_segment"
extern protoop_id_t PROTOOP_NOPARAM_BEFORE_SENDING_SEGMENT;
/**
 * \todo
 */
#define PROTOOPID_NOPARAM_AFTER_DECODING_FRAMES "after_decoding_frames"
extern protoop_id_t PROTOOP_NOPARAM_AFTER_DECODING_FRAMES;
/**
 * Finalize the packet and encrypt it.
 * \param[in] packet \b picoquic_packet_t* The packet to protect
 * \param[in] TODO: What is this param?
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
#define PROTOOPID_NOPARAM_FINALIZE_AND_PROTECT_PACKET "finalize_and_protect_packet"
extern protoop_id_t PROTOOP_NOPARAM_FINALIZE_AND_PROTECT_PACKET;

/**
 * Observer-only anchor that must be triggered by all mechanisms that declare packets as lost
 * and trigger retransmissions.
 *
 * \param[in] packet \b picoquic_packet_t* The packet that was lost
 * \param[in] path_x \b picoquic_path_t* The path on which the packet was lost
 */
#define PROTOOPID_NOPARAM_PACKET_WAS_LOST "packet_was_lost"
extern protoop_id_t PROTOOP_NOPARAM_PACKET_WAS_LOST;

/**
 * Observer-only anchor that must be triggered whenever the connection state has changed.
 * Using the setter \b picoquic_set_cnx_state() ensures this requirement.
 *
 * No parameters are given to this protoop as the connection state already holds this information.
 */
#define PROTOOPID_NOPARAM_CONNECTION_STATE_CHANGED "connection_state_changed"
extern protoop_id_t PROTOOP_NOPARAM_CONNECTION_STATE_CHANGED;

/*
    MP: We may want to merge the two ops below into one a define a separate set of enums to describe the stream states
    as defined in the QUIC specs, e.g. https://tools.ietf.org/html/draft-ietf-quic-transport-15#section-9.2.
*/

/**
 * Observer-only anchor that must be triggered whenever a stream is opened.
 */
#define PROTOOPID_NOPARAM_STREAM_OPENED "stream_opened"
extern protoop_id_t PROTOOP_NOPARAM_STREAM_OPENED;

/**
 * Observer-only anchor that must be triggered whenever a plugin stream is opened.
 */
#define PROTOOPID_NOPARAM_PLUGIN_STREAM_OPENED "plugin_stream_opened"
extern protoop_id_t PROTOOP_NOPARAM_PLUGIN_STREAM_OPENED;

/**
 * Observer-only anchor that must be triggered whenever the stream flags changed.
 */
#define PROTOOPID_NOPARAM_STREAM_FLAGS_CHANGED "stream_flags_changed"
extern protoop_id_t PROTOOP_NOPARAM_STREAM_FLAGS_CHANGED;

/**
 * Observer-only anchor that must be triggered whenever a stream is closed.
 */
#define PROTOOPID_NOPARAM_STREAM_CLOSED "stream_closed"
extern protoop_id_t PROTOOP_NOPARAM_STREAM_CLOSED;
/**/

/**
 * Observer-only anchor that must be triggered when the Fast Retransmit mechanism is triggered
 *
 * \param[in] packet \b picoquic_packet_t* The packet candidate for retransmission
 */
#define PROTOOPID_NOPARAM_FAST_RETRANSMIT "fast_retransmit"
extern protoop_id_t PROTOOP_NOPARAM_FAST_RETRANSMIT;

/**
 * Observer-only anchor that must be triggered when the Retransmission Timeout mechanism is triggered
 *
 * \param[in] packet \b picoquic_packet_t* The packet candidate for retransmission
 */
#define PROTOOPID_NOPARAM_RETRANSMISSION_TIMEOUT "retransmission_timeout"
extern protoop_id_t PROTOOP_NOPARAM_RETRANSMISSION_TIMEOUT;

/**
 * Observer-only anchor that must be triggered when the Tail Loss Probe mechanism is triggered
 *
 * \param[in] packet \b picoquic_packet_t* The packet candidate for retransmission
 */
#define PROTOOPID_NOPARAM_TAIL_LOSS_PROBE "tail_loss_probe"
extern protoop_id_t PROTOOP_NOPARAM_TAIL_LOSS_PROBE;

/**
 * Select the path on which the next packet will be sent.
 *
 * \param[in] retransmit_p \b picoquic_packet_t* The packet to be retransmitted, or NULL if none
 * \param[in] from_path \b picoquic_path_t* The path from which the packet originates, or NULL if none
 * \param[in] reason \b char* The reason why packet should be retransmitted, or NULL if none
 *
 * \return \b picoquic_path_t* The path on which the next packet will be sent.
 */
#define PROTOOPID_NOPARAM_SELECT_SENDING_PATH "select_sending_path"
extern protoop_id_t PROTOOP_NOPARAM_SELECT_SENDING_PATH;

/**
 * Observer-only anchor that is triggered when an unknown transport parameter is received.
 *
 * \param[in] parameter_id \b uint16_t The id of the received parameter
 * \param[in] length \b uint16_t The length of the value of the received extension
 * \param[in] value \b uint8_t* A pointer to the value of the received extension
 */
#define PROTOOPID_NOPARAM_UNKNOWN_TP_RECEIVED "unknown_tp_received"
extern protoop_id_t PROTOOP_NOPARAM_NOPARAM_UNKNOWN_TP_RECEIVED;

/**
 * Update the ack delay used locally based on the latest rtt estimate
 * \param[in] pkt_ctx \b picoquic_packet_context_t* The packet context to update
 * \param[in] old_path \b picoquic_path_t* The path on which the RTT estimate was computed
 * \param[in] rtt_estimate \b int64_t The RTT estimate computed on the given path
 * \param[in] first_estimate \b bool Indicates whether the RTT estimate was the first one for the given path
 */
#define PROTOOPID_NOPARAM_UPDATE_ACK_DELAY "update_ack_delay"
extern protoop_id_t PROTOOP_NOPARAM_UPDATE_ACK_DELAY;

/**
 * Log an event in the qlog format
 * \param[in] category \b char* The high-level category grouping the event
 * \param[in] event_type \b char* The low-level type of the event
 * \param[in] trigger \b char* The type of event that triggered the this event
 * \param[in] data \b char* Associated data with the event
 */
#define PROTOOPID_NOPARAM_LOG_EVENT "log_event"
extern protoop_id_t PROTOOP_NOPARAM_LOG_EVENT;

/**
 * Push context information to qlog
 * \param[in] data \b char* Context data
 */
#define PROTOOPID_NOPARAM_PUSH_LOG_CONTEXT "push_log_context"
extern protoop_id_t PROTOOP_NOPARAM_PUSH_LOG_CONTEXT;

/**
 * Pop context information to qlog
 */
#define PROTOOPID_NOPARAM_POP_LOG_CONTEXT "pop_log_context"
extern protoop_id_t PROTOOP_NOPARAM_POP_LOG_CONTEXT;

/* @} */

#endif