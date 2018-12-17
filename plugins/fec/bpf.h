#include <picoquic_logger.h>
#include "picoquic_internal.h"
#include "block_framework.h"
#include "memory.h"
#include "memcpy.h"


typedef struct {
    bool has_sent_stream_data;
    bool should_check_block_flush;
    char underlying_fec_scheme[8];
    uint32_t oldest_fec_block_number : 24;
    uint8_t *current_packet;
    uint16_t current_packet_length;
    block_fec_framework_t *block_fec_framework;
    fec_block_t *fec_blocks[MAX_FEC_BLOCKS]; // ring buffer
} bpf_state;

static __attribute__((always_inline)) bpf_state *initialize_bpf_state(picoquic_cnx_t *cnx)
{
    bpf_state *state = (bpf_state *) my_malloc(cnx, sizeof(bpf_state));
    if (!state) return NULL;
    my_memset(state, 0, sizeof(bpf_state));
    state->block_fec_framework = new_block_fec_framework(cnx);
    if (!state->block_fec_framework) {
        my_free(cnx, state);
        return NULL;
    }
    return state;
}

static __attribute__((always_inline)) bpf_state *get_bpf_state(picoquic_cnx_t *cnx)
{
    int allocated = 0;
    bpf_state **state_ptr = (bpf_state **) get_opaque_data(cnx, FEC_OPAQUE_ID, sizeof(bpf_state *), &allocated);
    if (!state_ptr) return NULL;
    if (allocated) {
        *state_ptr = initialize_bpf_state(cnx);
    }
    return *state_ptr;
}


static __attribute__((always_inline)) uint32_t my_parse_connection_id(const uint8_t * bytes, uint8_t len, picoquic_connection_id_t * cnx_id)
{
    if (len <= PICOQUIC_CONNECTION_ID_MAX_SIZE) {
        cnx_id->id_len = len;
        my_memcpy(cnx_id->id, bytes, len);
    } else {
        len = 0;
        cnx_id->id_len = 0;
    }
    return len;
}


/* The packet number logic */
static __attribute__((always_inline)) uint64_t my_get_packet_number64(uint64_t highest, uint64_t mask, uint32_t pn)
{
    uint64_t expected = highest + 1;
    uint64_t not_mask_plus_one = (~mask) + 1;
    uint64_t pn64 = (expected & mask) | pn;

    if (pn64 < expected) {
        uint64_t delta1 = expected - pn64;
        uint64_t delta2 = not_mask_plus_one - delta1;
        if (delta2 < delta1) {
            pn64 += not_mask_plus_one;
        }
    } else {
        uint64_t delta1 = pn64 - expected;
        uint64_t delta2 = not_mask_plus_one - delta1;

        if (delta2 <= delta1 && (pn64 & mask) > 0) {
            /* Out of sequence packet from previous roll */
            pn64 -= not_mask_plus_one;
        }
    }

    return pn64;
}


static __attribute__((always_inline)) int my_is_pn_already_received(picoquic_path_t* path_x,
                                    picoquic_packet_context_enum pc, uint64_t pn64)
{
    int is_received = 0;
    picoquic_sack_item_t* sack = &path_x->pkt_ctx[pc].first_sack_item;

    if (sack->start_of_sack_range != (uint64_t)((int64_t)-1)) {
        do {
            if (pn64 > sack->end_of_sack_range)
                break;
            else if (pn64 >= sack->start_of_sack_range) {
                is_received = 1;
                break;
            }
            else {
                sack = sack->next_sack;
            }
        } while (sack != NULL);
    }

    return is_received;
}


static uint8_t picoquic_cleartext_internal_test_1_salt[] = {
        0x30, 0x67, 0x16, 0xd7, 0x63, 0x75, 0xd5, 0x55,
        0x4b, 0x2f, 0x60, 0x5e, 0xef, 0x78, 0xd8, 0x33,
        0x3d, 0xc1, 0xca, 0x36
};

static uint8_t picoquic_cleartext_draft_10_salt[] = {
        0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c,
        0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f,
        0xe0, 0x6d, 0x6c, 0x38
};

/* Support for draft 13! */
const picoquic_version_parameters_t picoquic_supported_versions[] = {
        { PICOQUIC_INTERNAL_TEST_VERSION_1, 0,
                picoquic_version_header_13,
                sizeof(picoquic_cleartext_internal_test_1_salt),
                picoquic_cleartext_internal_test_1_salt },
        { PICOQUIC_EIGHT_INTEROP_VERSION, 0,
                picoquic_version_header_13,
                sizeof(picoquic_cleartext_draft_10_salt),
                picoquic_cleartext_draft_10_salt },
        { PICOQUIC_SEVENTH_INTEROP_VERSION, 0,
                picoquic_version_header_13,
                sizeof(picoquic_cleartext_draft_10_salt),
                picoquic_cleartext_draft_10_salt }
};

//FIXME: cnx_id length changes ?
static __attribute__((always_inline)) int parse_packet_header(picoquic_cnx_t *cnx, picoquic_packet_header *ph, uint8_t *bytes, uint16_t length, int *already_received) {
    /* If this is a short header, it should be possible to retrieve the connection
         * context. This depends on whether the quic context requires cnx_id or not.
         */
    uint8_t cnxid_length = cnx->remote_cnxid.id_len;
    ph->pc = picoquic_packet_context_application;
    int ret = 0;

    if ((int)length >= 1 + cnxid_length) {
        /* We can identify the connection by its ID */
        ph->offset = (uint32_t)( 1 + my_parse_connection_id(bytes + 1, cnxid_length, &ph->dest_cnx_id));
        /* TODO: should consider using combination of CNX ID and ADDR_FROM */
    } else {
        ph->ptype = picoquic_packet_error;
        ph->offset = length;
        ph->payload_length = 0;
    }

    ph->epoch = 3;
    ph->version_index = cnx->version_index;
    /* If the connection is identified, decode the short header per version ID */
    switch (picoquic_supported_versions[ph->version_index].version_header_encoding) {
        case picoquic_version_header_13:
            if ((bytes[0] & 0x40) == 0) {
                ph->ptype = picoquic_packet_1rtt_protected_phi0;
            }
            else {
                ph->ptype = picoquic_packet_1rtt_protected_phi1;
            }
            ph->has_spin_bit = 1;
            ph->spin = (bytes[0] >> 2) & 1;
            ph->spin_vec = bytes[0] & 0x03 ;

            ph->pn_offset = ph->offset;
            ph->pn = 0;
            ph->pnmask = 0;
            break;
    }
    if (length < ph->offset) {
        ret = -1;
        ph->payload_length = 0;
    } else {
        ph->payload_length = (uint16_t)(length - ph->offset);
    }




    // parse pn



    if (already_received != NULL) {
        *already_received = 0;
    }


    size_t decoded;
    length = ph->offset + ph->payload_length; /* this may change after decrypting the PN */
    picoquic_path_t* path_from = cnx->path[0];
    /* Might happen if the CID is not the one expected */


    /* The header length is not yet known, will only be known after the sequence number is decrypted */
    size_t encrypted_length = 4;
    size_t sample_offset = ph->pn_offset + encrypted_length;
    uint8_t *decoded_pn_bytes;

    if (sample_offset > length)
    {
        encrypted_length = 0;
    }
    if (encrypted_length > 0)
    {
        /* Packet encoding is varint, specialized for sequence number */
        decoded_pn_bytes = bytes + ph->pn_offset;
        switch (decoded_pn_bytes[0] & 0xC0) {
            case 0x00:
            case 0x40: /* single byte encoding */
                ph->pn = decoded_pn_bytes[0] & 0x7F;
                ph->pnmask = 0xFFFFFFFFFFFFFF80ull;
                ph->offset = ph->pn_offset + 1;
                ph->payload_length -= 1;
                break;
            case 0x80: /* two byte encoding */
                ph->pn = (PICOPARSE_16(decoded_pn_bytes)) & 0x3FFF;
                ph->pnmask = 0xFFFFFFFFFFFFC000ull;
                ph->offset = ph->pn_offset + 2;
                ph->payload_length -= 2;
                break;
            case 0xC0:
                ph->pn = (PICOPARSE_32(decoded_pn_bytes)) & 0x3FFFFFFF;
                ph->pnmask = 0xFFFFFFFFC0000000ull;
                ph->offset = ph->pn_offset + 4;
                ph->payload_length -= 4;
                break;
        }

    }
    else {
        /* Invalid packet format. Avoid crash! */
        ph->pn = 0xFFFFFFFF;
        ph->pnmask = 0xFFFFFFFF00000000ull;
        ph->offset = ph->pn_offset;

//        PROTOOP_PRINTF(cnx, "Invalid packet format, type: %d, epoch: %d, pc: %d, pn: %d\n",
//                   ph->ptype, ph->epoch, ph->pc, (int)ph->pn);
    }

    /* Build a packet number to 64 bits */
    ph->pn64 = my_get_packet_number64(
            (already_received==NULL)?path_from->pkt_ctx[ph->pc].send_sequence:
            path_from->pkt_ctx[ph->pc].first_sack_item.end_of_sack_range, ph->pnmask, ph->pn);

    /* verify that the packet is new */
    if (already_received != NULL && my_is_pn_already_received(path_from, ph->pc, ph->pn64) != 0) {
        /* Set error type: already received */
        *already_received = 1;
    }





    return ret;
}







static __attribute__((always_inline)) int helper_write_source_fpid_frame(picoquic_cnx_t *cnx, source_fpid_frame_t *f, uint8_t *bytes, size_t bytes_max, size_t *consumed) {
    if (bytes_max <  (1 + sizeof(source_fpid_t)))
        return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    *bytes = SOURCE_FPID_TYPE;
    bytes++;
    encode_u32(f->source_fpid.raw, bytes);
    *consumed = (1 + sizeof(source_fpid_t));
    return 0;
}

static __attribute__((always_inline)) int helper_write_fec_frame(picoquic_cnx_t *cnx, bpf_state *state, uint8_t *bytes, size_t bytes_max, size_t *consumed) {
    if (bytes_max <= (1 + sizeof(fec_frame_header_t)))
        return PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    *bytes = FEC_TYPE;
    bytes++;
    *consumed = 0;
    block_fec_framework_t *bff = state->block_fec_framework;
    int ret = write_fec_frame(cnx, bff, bytes_max-1, consumed, bytes);
    if (*consumed)
        (*consumed)++;  // add the type byte

    return ret;
}

static __attribute__((always_inline)) fec_block_t *get_fec_block(bpf_state *state, uint32_t fbn){
    return state->fec_blocks[fbn % MAX_FEC_BLOCKS];
}

static __attribute__((always_inline)) void add_fec_block(bpf_state *state, fec_block_t *fb){
    state->fec_blocks[fb->fec_block_number % MAX_FEC_BLOCKS] = fb;
}

static __attribute__((always_inline)) void remove_and_free_fec_block(picoquic_cnx_t *cnx, bpf_state *state, fec_block_t *fb){
    free_fec_block(cnx, fb, false);
    state->fec_blocks[fb->fec_block_number % MAX_FEC_BLOCKS] = NULL;
}

static __attribute__((always_inline)) int sent_source_symbol_helper(picoquic_cnx_t *cnx, source_symbol_t *ss) {
    bpf_state *state = get_bpf_state(cnx);
    return protect_source_symbol(cnx, state->block_fec_framework, ss);
}

// protects the packet and writes the source_fpid
static __attribute__((always_inline)) int protect_packet(picoquic_cnx_t *cnx, source_fpid_t *source_fpid, uint8_t *data, uint16_t length){
    bpf_state *state = get_bpf_state(cnx);
    // write the source fpid
    source_fpid->fec_block_number = state->block_fec_framework->current_block_number;
    source_fpid->symbol_number = state->block_fec_framework->current_block->current_source_symbols;

    source_symbol_t *ss = malloc_source_symbol_with_data(cnx, *source_fpid, data, length);
    if (!ss)
        return -1;
    PROTOOP_PRINTF(cnx, "PROTECT PACKET OF SIZE %u, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x\n",
            (unsigned long) length,
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
    int ret = protect_source_symbol(cnx, state->block_fec_framework, ss);
    if (ret) {
        free_source_symbol(cnx, ss);
        return ret;
    }
    return 0;
}

#define MAX_RECOVERED_IN_ONE_ROW 20

static __attribute__((always_inline)) int recover_block(picoquic_cnx_t *cnx, bpf_state *state, fec_block_t *fb){

    protoop_arg_t args[5], outs[1];
    args[0] = (protoop_arg_t) fb;
    uint8_t to_recover[MAX_RECOVERED_IN_ONE_ROW];
    uint8_t n_to_recover = 0;
    picoquic_packet_header ph;
    for (uint8_t i = 0; i < fb->total_source_symbols && n_to_recover < MAX_RECOVERED_IN_ONE_ROW; i++) {
        if (fb->source_symbols[i] == NULL) {
            to_recover[n_to_recover++] = i;
        }
    }
    protoop_params_t pp = get_pp_noparam("fec_recover", 1, args, outs);
    int ret = (int) plugin_run_protoop(cnx, &pp);
    for (int idx = 0 ; idx < n_to_recover ; idx++) {
        int i = to_recover[idx];
        if (!fb->source_symbols[i])
            continue;
        int already_received = 0;
        ret = parse_packet_header(cnx, &ph, fb->source_symbols[i]->data, fb->source_symbols[i]->data_length, &already_received);
        if (!ret) {
            picoquic_record_pn_received(cnx, cnx->path[0],
                                            ph.pc, ph.pn64,
                                            picoquic_current_time());
            PROTOOP_PRINTF(cnx, "DECODING FRAMES OF RECOVERED SYMBOL (offset %d): pn = %x (%llx), ph.offset = %u, len_frames = %u, pl = %u\n", (protoop_arg_t) i, ph.pn, ph.pn64, ph.offset, fb->source_symbols[i]->data_length - ph.offset, ph.payload_length);
            args[0] = (protoop_arg_t) fb->source_symbols[i]->data + ph.offset;
            args[1] = ph.payload_length;
            args[2] = (protoop_arg_t) ph.epoch;
            args[3] = picoquic_current_time();
            args[4] = (protoop_arg_t) cnx->path[0];
            picoquic_log_frames_cnx(NULL, cnx, 1, fb->source_symbols[i]->data + ph.offset, ph.payload_length);
            pp = get_pp_noparam("decode_frames", 5, args, outs);
            // TODO: trigger ack for packet
            ret = (int) plugin_run_protoop(cnx, &pp);
            if (!ret) {
                PROTOOP_PRINTF(cnx, "DECODED ! \n");
            } else {
                PROTOOP_PRINTF(cnx, "ERROR WHILE DECODING: %u ! \n", (uint32_t) ret);
            }
        }
    }
    state->fec_blocks[fb->fec_block_number] = NULL;
    remove_and_free_fec_block(cnx, state, fb);

    return ret;

}

// returns true if the symbol has been successfully processed
// returns false otherwise: the symbol can be destroyed
static __attribute__((always_inline)) int received_repair_symbol_helper(picoquic_cnx_t *cnx, repair_symbol_t *rs, uint8_t nss, uint8_t nrs){
    bpf_state *state = get_bpf_state(cnx);
    uint32_t fbn = rs->fec_block_number;
    fec_block_t *fb = get_fec_block(state, fbn);
    // there exists an older FEC block
    // TODO: disambiguate block numbers: watch for possible wrapping or delayed packets
    if (fb && fb->fec_block_number < rs->fec_block_number) {
        remove_and_free_fec_block(cnx, state, fb);
        fb = NULL;
    }
    if (!fb)
        fb = malloc_fec_block(cnx, rs->fec_block_number);
    fb->total_source_symbols = nss;
    fb->total_repair_symbols = nrs;
    add_fec_block(state, fb);
    if (!add_repair_symbol_to_fec_block(rs, fb)) {
        return false;
    }
    PROTOOP_PRINTF(cnx, "RECEIVED RS: CURRENT_SS = %u, CURRENT_RS = %u, TOTAL_SS = %u\n", fb->current_source_symbols, fb->current_repair_symbols, fb->total_source_symbols);
    if (fb->current_source_symbols + fb->current_repair_symbols >= fb->total_source_symbols) {
        recover_block(cnx, state, fb);
    }
    return true;
}

// returns true if the symbol has been successfully processed
// returns false otherwise: the symbol can be destroyed
//FIXME: we pass the state in the parameters because the call to get_bpf_state leads to an error when loading the code
static __attribute__((always_inline)) bool received_source_symbol_helper(picoquic_cnx_t *cnx, bpf_state *state, source_symbol_t *ss){
    uint32_t fbn = ss->fec_block_number;
    fec_block_t *fb = get_fec_block(state, fbn);
    // there exists an older FEC block
    if (fb && fb->fec_block_number != ss->fec_block_number) {
        remove_and_free_fec_block(cnx, state, fb);
        fb = NULL;
    }
    if (!fb)
        fb = malloc_fec_block(cnx, ss->fec_block_number);
    add_fec_block(state, fb);
    if (!add_source_symbol_to_fec_block(ss, fb)) {
        return false;
    }
    PROTOOP_PRINTF(cnx, "RECEIVED SS: BLOCK = %u, CURRENT_SS = %u, CURRENT_RS = %u, TOTAL_SS = %u, TOTAL_RS = %u\n", fb->fec_block_number, fb->current_source_symbols, fb->current_repair_symbols, fb->total_source_symbols, fb->total_repair_symbols);
    if (fb->current_repair_symbols > 0 && fb->current_source_symbols + fb->current_repair_symbols >= fb->total_source_symbols) {
        recover_block(cnx, state, fb);
    }
    return true;
}

static __attribute__((always_inline)) int process_fec_protected_packet(picoquic_cnx_t *cnx, source_fpid_t source_fpid, uint8_t *data, uint16_t length){
    source_symbol_t *ss = malloc_source_symbol_with_data(cnx, source_fpid, data, length);
    bpf_state *state = get_bpf_state(cnx);
    received_source_symbol_helper(cnx, state, ss);
    return 0;
}

// assumes that the data_length field of the frame is safe
static __attribute__((always_inline)) int process_fec_frame_helper(picoquic_cnx_t *cnx, fec_frame_t *frame) {
    // TODO: here, we don't handle the case where repair symbols are split into several frames. We should do it.
    repair_symbol_t *rs = malloc_repair_symbol_with_data(cnx, frame->header.repair_fec_payload_id, frame->data,
                                                         frame->header.data_length);
    return received_repair_symbol_helper(cnx, rs, frame->header.nss, frame->header.nrs);
}
