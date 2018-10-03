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
 * @defgroup parametrableProtoop Parametrable protocol operations
 * 
 * The following are protocol operations that takes a numerical argument.
 * A particular operation is attached to each different parameter value.
 */

/* @{ */ 

/**
 * Decode the frame whose the type is provided as parameter.
 * \param[in] bytes \b uint8_t* Pointer to the start of the frame in binary format to decode
 * \param[in] bytes_max <b> const uint8_t* </b> Pointer to the end of the packet to decode
 * \param[in] current_time \b uint64_t Time of reception of the packet
 * \param[in] epoch \b int Epoch of the received packet
 * \param[in] ack_needed \b int Current value indicating if the reception of previous frames requires replying with an ACK frame
 * 
 * \return Pointer to the first byte after the decoded frame in the packet, or NULL if an error occurred
 * \param[out] ack_needed \b int Set to 1 if the decoded frame requires replying with an ACK frame 
 */
static const protoop_id_t PROTOP_PARAM_DECODE_FRAME = "decode_frame";

/* @} */ 

/**
 * \section Non-parametrable protocol operations
 */

#endif