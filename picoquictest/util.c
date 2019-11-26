#include <stdint.h>
#include <picoquic_internal.h>
#include <glob.h>

int split_stream_frame_test() {
    int ret = 0;

    uint8_t small_frame[] = {0x11, 0x2A, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA};

    uint8_t buf1[10] = {0};
    uint8_t buf2[10] = {0};

    size_t buf1_size = sizeof(buf1);
    size_t buf2_size = sizeof(buf2);

    ret = picoquic_split_stream_frame(small_frame, sizeof(small_frame), buf1, &buf1_size, buf2, &buf2_size);
    if (ret != sizeof(small_frame))
        return 1;

    {
        uint64_t stream_id = 0;
        uint64_t offset = 0;
        uint64_t data_length = 0;
        int fin = 0;
        size_t consumed = 0;
        ret = picoquic_parse_stream_header(buf1, buf1_size, &stream_id, &offset, &data_length, &fin, &consumed);
        if (ret != 0)
            return 2;

        if (stream_id != 42)
            return 3;

        if (offset != 0)
            return 4;

        if (data_length != 7)
            return 5;

        if (fin != 0)
            return 6;

        if (consumed != 3)
            return 7;

        if (memcmp(small_frame + 2, buf1 + consumed, data_length) != 0)
            return 8;
    }

    {
        uint64_t stream_id = 0;
        uint64_t offset = 0;
        uint64_t data_length = 0;
        int fin = 0;
        size_t consumed = 0;
        ret = picoquic_parse_stream_header(buf2, buf2_size, &stream_id, &offset, &data_length, &fin, &consumed);
        if (ret != 0)
            return 9;

        if (stream_id != 42)
            return 10;

        if (offset != 7)
            return 11;

        if (data_length != 3)
            return 12;

        if (fin != 1)
            return 13;

        if (consumed != 4)
            return 14;

        if (memcmp(small_frame + 2 + offset, buf2 + consumed, data_length) != 0)
            return 15;
    }

    uint8_t smallest_frame[] = {0x11, 0x40, 0x2A};

    buf1_size = sizeof(buf1);
    buf2_size = sizeof(buf2);

    memset(buf1, 0, buf1_size);
    memset(buf2, 0, buf2_size);

    ret = picoquic_split_stream_frame(smallest_frame, sizeof(smallest_frame), buf1, &buf1_size, buf2, &buf2_size);
    if (ret != sizeof(smallest_frame))
        return 16;

    if (buf2_size != 0)
        return 17;

    {
        uint64_t stream_id = 0;
        uint64_t offset = 0;
        uint64_t data_length = 0;
        int fin = 0;
        size_t consumed = 0;
        ret = picoquic_parse_stream_header(buf1, buf1_size, &stream_id, &offset, &data_length, &fin, &consumed);
        if (ret != 0)
            return 18;

        if (stream_id != 42)
            return 19;

        if (offset != 0)
            return 20;

        if (data_length != 0)
            return 21;

        if (fin != 1)
            return 22;

        if (consumed != 3)
            return 23;

        if (memcmp(smallest_frame + 3, buf1 + consumed, data_length) != 0)
            return 24;
    }

    uint8_t three_frames[] = {0x12, 0x40, 0x2A, 0x03, 0xAB, 0xCD, 0xEF, 0x1, 0x0};  // A STREAM frame, a PING, and a PADDING frame

    buf1_size = sizeof(buf1);
    buf2_size = sizeof(buf2);

    memset(buf1, 0, buf1_size);
    memset(buf2, 0, buf2_size);

    ret = picoquic_split_stream_frame(three_frames, sizeof(three_frames), buf1, &buf1_size, buf2, &buf2_size);
    if (ret != 7)
        return 25;

    if (buf2_size != 0)
        return 26;

    {
        uint64_t stream_id = 0;
        uint64_t offset = 0;
        uint64_t data_length = 0;
        int fin = 0;
        size_t consumed = 0;
        ret = picoquic_parse_stream_header(buf1, buf1_size, &stream_id, &offset, &data_length, &fin, &consumed);
        if (ret != 0)
            return 27;

        if (stream_id != 42)
            return 28;

        if (offset != 0)
            return 29;

        if (data_length != 3)
            return 30;

        if (fin != 0)
            return 31;

        if (consumed != 3)
            return 32;

        if (memcmp(three_frames + 4, buf1 + consumed, data_length) != 0)
            return 33;
    }

    return 0;
}