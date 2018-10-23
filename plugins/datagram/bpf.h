#define FRAME_TYPE_DATAGRAM 0x1c
#define FRAME_TYPE_DATAGRAM_WITH_LEN 0x1d

typedef struct st_datagram_frame_t {
    uint64_t length;
    uint8_t * datagram_data_ptr;  /* Start of the data, not contained in the structure */
} datagram_frame_t;
