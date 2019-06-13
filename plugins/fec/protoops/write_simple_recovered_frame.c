#include <picoquic.h>
#include "../fec_protoops.h"

static __attribute__((always_inline)) void free_rp(picoquic_cnx_t *cnx, recovered_packets_t *rp) {
    my_free(cnx, rp->packets);
    my_free(cnx, rp);
}


/*
 * The format of a RECOVERED frame is:
 *
 * 1. type byte (8bits)
 * 2. number of recovered packets (8bits)
 * 3. first recovered packet full-size packet number (64bits)
 * 4. recovered packets range (recovered packets with consecutive packet number comapred to the first packet or the last gap)
 * 5. recovered packets gap (non-recovered packets with consecutive packet number comapred to the last recovered range)
 *   (repeat (4,5) as many times as needed)
 * [6. last recovered range if there are more than one recovered packet after the last gap]
 */


protoop_arg_t write_fpid_frame(picoquic_cnx_t *cnx) {
    uint8_t* bytes = (uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 0);
    const uint8_t* bytes_max = (const uint8_t *) get_cnx(cnx, AK_CNX_INPUT, 1);
    recovered_packets_t *rp = (recovered_packets_t *) get_cnx(cnx, AK_CNX_INPUT, 2);
    int consumed = 0;
    if (rp->number_of_packets == 0 || bytes_max - bytes < 2*sizeof(uint8_t) + sizeof(uint64_t)) {
        set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) consumed);
        set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
        free_rp(cnx, rp);
        return -1;
    }
    // the packets in rp must be sorted according to their packet number
    my_memset(bytes, RECOVERED_TYPE, sizeof(uint8_t));
    bytes += sizeof(uint8_t);
    consumed += sizeof(uint8_t);
    my_memcpy(bytes, &rp->number_of_packets, sizeof(uint8_t));
    bytes += sizeof(uint8_t);
    consumed += sizeof(uint8_t);
    my_memcpy(bytes, &rp->packets[0], sizeof(uint64_t));
    bytes += sizeof(uint64_t);
    consumed += sizeof(uint64_t);

    uint8_t range_length = 0;
    for (int i = 1 ; i < rp->number_of_packets ; i++) {
        if (rp->packets[i] <= rp->packets[i-1] || rp->packets[i] - rp->packets[i-1] > 0xFF) {
            // error
            set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) 0);
            set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
            free_rp(cnx, rp);
            return -1;
        }
        if (rp->packets[i] == rp->packets[i-1]) {
            range_length++;
        } else {
            if (bytes_max - bytes < 2*sizeof(uint8_t)) {
                set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) 0);
                set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
                free_rp(cnx, rp);
                return -1;
            }
            // write range
            my_memcpy(bytes, &range_length, sizeof(uint8_t));
            bytes += sizeof(uint8_t);
            consumed += sizeof(uint8_t);
            // write gap
            my_memset(bytes, (uint8_t) (rp->packets[i] - rp->packets[i-1]), sizeof(uint8_t));
            bytes += sizeof(uint8_t);
            consumed += sizeof(uint8_t);
            range_length = 0;
        }
    }
    // write last range if needed
    if (range_length > 0) {
        if (bytes_max - bytes < 2*sizeof(uint8_t)) {
            set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) 0);
            set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
            free_rp(cnx, rp);
            return -1;
        }
        my_memcpy(bytes, &range_length, sizeof(uint8_t));
        bytes += sizeof(uint8_t);
        consumed += sizeof(uint8_t);
    }
    set_cnx(cnx, AK_CNX_OUTPUT, 0, (protoop_arg_t) consumed);
    set_cnx(cnx, AK_CNX_OUTPUT, 1, (protoop_arg_t) 0);
    free_rp(cnx, rp);
    return 0;
}