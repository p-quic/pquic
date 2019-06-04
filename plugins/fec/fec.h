#ifndef FEC_H
#define FEC_H
#include "../helpers.h"

#define FEC_MAGIC_NUMBER 0x10
#define FEC_OPAQUE_ID 0x02
#define MAX_FEC_BLOCKS 3   // maximum number of idle source blocks handled concurrently
#define MAX_SYMBOLS_PER_FEC_BLOCK 100    // maximum number of idle source blocks handled concurrently

#define DECODE_FEC_FRAME (PROTOOPID_DECODE_FRAMES + 0x30)

#define PREPARE_NEW_CONNECTION_ID_FRAME (PROTOOPID_SENDER + 0x48)
#define PREPARE_MP_ACK_FRAME (PROTOOPID_SENDER + 0x49)
#define PREPARE_ADD_ADDRESS_FRAME (PROTOOPID_SENDER + 0x4a)

#define SOURCE_FPID_TYPE 0x29
#define FEC_TYPE 0x2a
#define RECOVERED_TYPE 0x2b

protoop_id_t PROTOOP_ID_FEC_GENERATE_REPAIR_SYMBOLS = { .id = "fec_generate_repair_symbols" };

#define DEFAULT_FEC_SCHEME "xor"

#define for_each_source_symbol(fb, ____ss) \
    for (int ____i = 0, ____keep = 1, n = fb->total_source_symbols; ____keep && ____i < n; ____i++, ____keep = 1-____keep ) \
        for (____ss = fb->source_symbols[____i] ; ____keep ; ____keep = 1-____keep)

#define for_each_repair_symbol(fb, ____ss) \
    for (int ____i = 0, ____keep = 1, n = fb->total_repair_symbols; ____keep && ____i < n; ____i++, ____keep = 1-____keep ) \
        for (____ss = fb->repair_symbols[____i] ; ____keep ; ____keep = 1-____keep)


#define for_each_source_symbol_nobreak(fb, ____ss) \
    for (int ____i = 0, n = fb->total_source_symbols; ____i < n; ____i++) \
        if ((____ss = fb->source_symbols[____i]) || 1)

#define for_each_repair_symbol_nobreak(fb, ____ss) \
    for (int ____i = 0, n = fb->total_repair_symbols; ____i < n; ____i++) \
        if (____ss = fb->repair_symbols[____i] || 1)

typedef void * fec_scheme_t;
typedef void * fec_redundancy_controller_t;

typedef union {
    uint32_t raw;
    struct __attribute__((__packed__)) {
        uint8_t symbol_number;
        uint32_t fec_block_number : 24;
    };
} source_fpid_t;

// type byte 0x1c
typedef struct __attribute__((__packed__)) {
    source_fpid_t source_fpid;
} source_fpid_frame_t;

typedef struct {
    uint64_t *packets;
    uint8_t number_of_packets;
} recovered_packets_t;

// TODO: maybe a bit complex structure but quite handy, think if we can/should simplify it
typedef union {
    uint64_t raw;
    struct __attribute__((__packed__)) {
        union {
            struct __attribute__((__packed__)) {
                uint8_t symbol_number;
                uint32_t fec_block_number : 24;
            };
            source_fpid_t source_fpid;
        };
        uint32_t fec_scheme_specific;
    };
} repair_fpid_t;

// type byte 0x1b
typedef struct __attribute__((__packed__)) {
    bool fin_bit : 1;
    uint16_t data_length : 15;
    uint8_t offset;
    repair_fpid_t repair_fec_payload_id;
    uint8_t nss;
    uint8_t nrs;
} fec_frame_header_t;


// TODO: handle cases when my_malloc returns NULL

// TODO: to save memory with a block FEC Scheme, remove the block number from the FPIDs and place it in the source block itself
typedef struct {
    union {
        repair_fpid_t repair_fec_payload_id;
        struct __attribute__((__packed__)) {
            uint8_t symbol_number;
            uint32_t fec_block_number : 24;
            uint32_t fec_scheme_specific;
        };
    };
    uint16_t data_length : 15;
    uint8_t *data;
} repair_symbol_t;

typedef struct {
    union {
    source_fpid_t source_fec_payload_id;
        struct __attribute__((__packed__)) {
            uint8_t fec_block_offset;
            uint32_t fec_block_number : 24;
        };
    };
    uint16_t data_length: 15;
    uint8_t *data;
} source_symbol_t;

typedef struct __attribute__((__packed__)) {
    fec_frame_header_t header;
    uint8_t *data;
} fec_frame_t;

typedef struct __attribute__((__packed__)) {
    uint32_t fec_block_number;
    uint8_t total_source_symbols;
    uint8_t total_repair_symbols;
    uint8_t current_source_symbols;
    uint8_t current_repair_symbols;
    // TODO: change this. Easy to use now, but eats a lot of memory at the receiver side
    source_symbol_t *source_symbols[MAX_SYMBOLS_PER_FEC_BLOCK];
    repair_symbol_t *repair_symbols[MAX_SYMBOLS_PER_FEC_BLOCK];
} fec_block_t;


static __attribute__((always_inline)) uint64_t decode_un(uint8_t *bytes, int n) {
    uint64_t retval = 0;
    int i;
    for (i = 0; i < n ; i++) {
        retval <<= 8;
        retval += bytes[i];
    }
    return retval;
}

static __attribute__((always_inline)) void encode_un(uint64_t to_encode, uint8_t *bytes, int n) {
    int i;
    for (i = 0; i < n ; i++) {
        bytes[i] = (uint8_t) (to_encode >> 8*(n-i-1));
    }
}

static __attribute__((always_inline)) uint16_t decode_u16(uint8_t *bytes) {
    return (uint16_t) decode_un(bytes, 2);
}

static __attribute__((always_inline)) uint32_t decode_u32(uint8_t *bytes) {
    return (uint32_t) decode_un(bytes, 4);
}

static __attribute__((always_inline)) uint64_t decode_u64(uint8_t *bytes) {
    return decode_un(bytes, 8);
}

static __attribute__((always_inline)) void encode_u16(uint16_t to_encode, uint8_t *bytes) {
    encode_un(to_encode, bytes, 2);
}

static __attribute__((always_inline)) void encode_u32(uint32_t to_encode, uint8_t *bytes) {
    encode_un(to_encode, bytes, 4);
}

static __attribute__((always_inline)) void encode_u64(uint64_t to_encode, uint8_t *bytes) {
    encode_un(to_encode, bytes, 8);
}


static __attribute__((always_inline)) void parse_fec_frame_header(fec_frame_header_t *header_to_parse, uint8_t *bytes) {
    *((uint16_t *) header_to_parse) = decode_u16(bytes);
    bytes += 2;
    header_to_parse->offset = *bytes++;
    header_to_parse->repair_fec_payload_id.raw = decode_u64(bytes);
    bytes += 8;
    header_to_parse->nss = *bytes++;
    header_to_parse->nrs = *bytes;
}

static __attribute__((always_inline)) void write_fec_frame_header(fec_frame_header_t *header_to_write, uint8_t *bytes) {
    *(bytes++) = FEC_TYPE;
    encode_u16(*((uint16_t *) header_to_write), bytes);
    bytes+=2;
    *bytes++ = header_to_write->offset;
    encode_u64(header_to_write->repair_fec_payload_id.raw, bytes);
    bytes+=8;
    *(bytes++) = header_to_write->nss;
    *bytes = header_to_write->nrs;
}

static __attribute__((always_inline)) void parse_sfpid_frame(source_fpid_frame_t *frame_to_parse, uint8_t *bytes) {
    frame_to_parse->source_fpid.raw = decode_u32(bytes);
}

// assumes that size if safe
static __attribute__((always_inline)) source_symbol_t *malloc_source_symbol(picoquic_cnx_t *cnx, source_fpid_t source_fpid, uint16_t size) {
    source_symbol_t *s = (source_symbol_t *) my_malloc(cnx, sizeof(source_symbol_t));
    uint8_t *data_cpy = (uint8_t *) my_malloc(cnx, size);
    if (!s || !data_cpy)
        return NULL;
    my_memset(s, 0, sizeof(source_symbol_t));
    my_memset(data_cpy, 0, size);
    s->source_fec_payload_id = source_fpid;
    s->data = data_cpy;
    s->data_length = size;
    return s;
}

// assumes that size is safe
static __attribute__((always_inline)) source_symbol_t *malloc_source_symbol_with_data(picoquic_cnx_t *cnx, source_fpid_t source_fpid,
                                                              uint8_t *data, uint16_t size) {
    source_symbol_t *s = malloc_source_symbol(cnx, source_fpid, size);
    if (!s)
        return NULL;
    my_memcpy(s->data, data, size);
    return s;
}

// assumes that size if safe
static __attribute__((always_inline)) repair_symbol_t *malloc_repair_symbol(picoquic_cnx_t *cnx, repair_fpid_t repair_fpid,
                                                    uint16_t size) {
    repair_symbol_t *s = (repair_symbol_t *) my_malloc(cnx, sizeof(repair_symbol_t));
    uint8_t *data_cpy = (uint8_t *) my_malloc(cnx, size);
    if (!s || !data_cpy)
        return NULL;

    my_memset(s, 0, sizeof(repair_symbol_t));
    my_memset(data_cpy, 0, size);
    s->repair_fec_payload_id = repair_fpid;
    s->data = data_cpy;
    s->data_length = size;
    return s;
}

// assumes that size if safe
static __attribute__((always_inline)) repair_symbol_t *malloc_repair_symbol_with_data(picoquic_cnx_t *cnx, repair_fpid_t repair_fpid,
                                                              uint8_t *data, uint16_t size) {
    repair_symbol_t *s = malloc_repair_symbol(cnx, repair_fpid, size);
    if (!s)
        return NULL;
    s->data_length = size;
    my_memcpy(s->data, data, size);
    return s;
}

static __attribute__((always_inline)) fec_block_t *malloc_fec_block(picoquic_cnx_t *cnx, uint32_t fbn){
    fec_block_t *fb = (fec_block_t *) my_malloc(cnx, sizeof(fec_block_t));
    my_memset(fb, 0, sizeof(fec_block_t));
    fb->fec_block_number = fbn;
    return fb;
}

static __attribute__((always_inline)) void free_source_symbol(picoquic_cnx_t *cnx, source_symbol_t *s) {
    my_free(cnx, s->data);
    my_free(cnx, s);
}

static __attribute__((always_inline)) void free_repair_symbol(picoquic_cnx_t *cnx, repair_symbol_t *s) {
    my_free(cnx, s->data);
    my_free(cnx, s);
}

static __attribute__((always_inline)) void free_fec_block(picoquic_cnx_t *cnx, fec_block_t *b, bool keep_repair_symbols) {
    int i = 0;
    for (i = 0 ; i < MAX_SYMBOLS_PER_FEC_BLOCK && b->current_source_symbols > 0; i++) {
        if (b->source_symbols[i]) {
            free_source_symbol(cnx, b->source_symbols[i]);
            if (!(--b->current_source_symbols)) // we freed everything
                break;
        }
    }

    if (!keep_repair_symbols) {
        for (i = 0 ; i < MAX_SYMBOLS_PER_FEC_BLOCK && b->current_repair_symbols > 0; i++) {
            if (b->repair_symbols[i]) {
                free_repair_symbol(cnx, b->repair_symbols[i]);
                b->repair_symbols[i] = NULL;
                if (!(--b->current_repair_symbols)) // we freed everything
                    break;
            }
        }
    }
    my_free(cnx, b);
}


static __attribute__((always_inline)) bool add_repair_symbol_to_fec_block(repair_symbol_t *rs, fec_block_t *fb){
    if (!fb->repair_symbols[rs->symbol_number]) {
        fb->repair_symbols[rs->symbol_number] = rs;
        fb->current_repair_symbols++;
        return true;
    }
    return false;
}

static __attribute__((always_inline)) bool add_source_symbol_to_fec_block(source_symbol_t *ss, fec_block_t *fb){
    if (!fb->source_symbols[ss->fec_block_offset]) {
        fb->source_symbols[ss->fec_block_offset] = ss;
        fb->current_source_symbols++;
        return true;
    }
    return false;
}
#endif