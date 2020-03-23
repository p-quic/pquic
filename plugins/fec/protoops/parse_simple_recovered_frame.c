#include <picoquic.h>
#include "../fec_protoops.h"

/*
 * The format of a RECOVERED frame is:
 *
 * 1. type byte (8bits)
 * 2. number of recovered packets (8bits)
 * 3. first recovered packet full-size packet number (64bits)
 * 4. recovered packets range (recovered packets with consecutive packet number compared to the first packet or the last gap). 0 indicates that there is only one packet in this range
 * 5. recovered packets gap (non-recovered packets with consecutive packet number compared to the last recovered range). 0 indicates that there is only one packet in this gap
 *   (repeat (4,5) as many times as needed)
 * [6. last recovered range if there are more than one recovered packet after the last gap]
 */


protoop_arg_t parse_recovered_frame(picoquic_cnx_t *cnx) {
    PROTOOP_PRINTF(cnx, "Parse RECOVERED FRAME\n");
    uint8_t *bytes_protected = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    if (bytes_max - bytes_protected < 2*sizeof(uint8_t) + sizeof(uint64_t)) {
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) NULL);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
        return (protoop_arg_t) NULL;
    }
    bytes_protected += sizeof(uint8_t);  // skip the type byte
    uint8_t number_of_packets;
    uint64_t first_recovered_packet;
    my_memcpy(&number_of_packets, bytes_protected, sizeof(uint8_t));
    bytes_protected += sizeof(uint8_t);
    my_memcpy(&first_recovered_packet, bytes_protected, sizeof(uint64_t));
    bytes_protected += sizeof(uint64_t);
    uint8_t *size_and_packets = my_malloc(cnx, sizeof(uint8_t) + number_of_packets*sizeof(uint64_t)); // sadly, we must place everything in one single malloc, because skip_frame will free our output
    my_memset(size_and_packets, 0, sizeof(uint8_t) + number_of_packets*sizeof(uint64_t));
    size_and_packets[0] = number_of_packets;
    uint64_t *packets =(uint64_t *) (size_and_packets+1);
    packets[0] = first_recovered_packet;
    int currently_parsed_recovered_packets = 1;
    uint64_t last_recovered_packet = first_recovered_packet;
    PROTOOP_PRINTF(cnx, "PACKET %" PRIx64 " HAS BEEN RECOVERED BY THE PEER\n", last_recovered_packet);
    bool range_is_gap = false;
    while(currently_parsed_recovered_packets < number_of_packets && bytes_protected < bytes_max) {
        uint8_t range;
        my_memcpy(&range, bytes_protected, sizeof(uint8_t));
        bytes_protected += sizeof(uint8_t);
        if (!range_is_gap) {
            // this is a range of recovered packets
            if (currently_parsed_recovered_packets + range > number_of_packets) {
                // error
                my_free(cnx, size_and_packets);
                set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) NULL);
                set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
                set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
                return (protoop_arg_t) NULL;
            }
            for (int j = 0 ; j < range ; j++) { // we add each packet of the range in the recovered packets
                last_recovered_packet++;    // the last recovered packet is now this one
                packets[currently_parsed_recovered_packets] = last_recovered_packet;
                PROTOOP_PRINTF(cnx, "PACKET %" PRIx64 " HAS BEEN RECOVERED BY THE PEER\n", last_recovered_packet);
                currently_parsed_recovered_packets++;
            }
            range_is_gap = true; // after a range of recovered packets, there must be a gap or nothing
        } else {
            // this range is a gap of recovered packets
            uint8_t n_packets_to_skip = range + 1;
            // it implicitly announces the recovery of the packet just after this gap
            last_recovered_packet += n_packets_to_skip + 1;
            packets[currently_parsed_recovered_packets] = last_recovered_packet;
            currently_parsed_recovered_packets++;
            range_is_gap = false; // after a gap of recovered packets, there must be a range or nothing
            PROTOOP_PRINTF(cnx, "PACKET %" PRIx64 " HAS BEEN RECOVERED BY THE PEER\n", last_recovered_packet);
        }
    }
    if (currently_parsed_recovered_packets != number_of_packets) {
        // error
        my_free(cnx, size_and_packets);
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) NULL);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
        PROTOOP_PRINTF(cnx, "DID NOT PARSE THE CORRECT NUMBER OF RECOVERED PACKETS (%u < %u)\n", currently_parsed_recovered_packets, number_of_packets);
        return (protoop_arg_t) NULL;
    }
    PROTOOP_PRINTF(cnx, "%u PACKETS HAVE BEEN RECOVERED\n", currently_parsed_recovered_packets);
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) size_and_packets);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) true);
    set_cnx(cnx, AK_CNX_OUTPUT, 2, (protoop_arg_t) false);
    return (protoop_arg_t) bytes_protected;
}