#define FRAME_TYPE_DATAGRAM 0x1c
#define FRAME_TYPE_DATAGRAM_WITH_LEN 0x1d

typedef struct st_datagram_frame_t {
    uint64_t length;
    uint8_t * datagram_data_ptr;  /* Start of the data, not contained in the structure */
} datagram_frame_t;

static inline size_t varint_len(uint64_t val) {
    if (val <= 64) {
        return 1;
    } else if (val <= 16383) {
        return 2;
    } else if (val <= 1073741823) {
        return 4;
    } else if (val <= 4611686018427387903) {
        return 8;
    }
    return 0;
}